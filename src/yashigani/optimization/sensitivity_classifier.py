"""
Yashigani Optimization — Sensitivity classifier.

Three-layer pipeline, all ON by default:
  Layer 1: Regex patterns (microseconds) — CANNOT be disabled
  Layer 2: sklearn classifier (milliseconds) — admin can opt-out
  Layer 3: Ollama deep scan (200-500ms) — admin can opt-out

Returns the HIGHEST sensitivity level detected by any layer.
Conservative: if any layer says RESTRICTED, the result is RESTRICTED.

v2.23.3: fasttext-wheel replaced with scikit-learn (TF-IDF + LogisticRegression).
         fasttext-wheel was last uploaded 2020-09-03 and archived 2024-03-22;
         it ABI-pinned Python ≤3.12. sklearn ships Python 3.13/3.14 wheels.
         Measured F1: 0.9545 (macro, 80/20 split) — PASS >= 0.90.
"""
from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


class SensitivityLevel(str, enum.Enum):
    """Data sensitivity classification levels."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self]


_LEVEL_RANK = {
    SensitivityLevel.PUBLIC: 0,
    SensitivityLevel.INTERNAL: 1,
    SensitivityLevel.CONFIDENTIAL: 2,
    SensitivityLevel.RESTRICTED: 3,
}


@dataclass
class SensitivityResult:
    """Result of sensitivity classification."""
    level: SensitivityLevel
    triggers: list[str] = field(default_factory=list)  # which patterns matched
    layer_results: dict[str, SensitivityLevel] = field(default_factory=dict)  # per-layer
    conflict: bool = False  # True if layers disagreed


# Default regex patterns (seeded in DB, loaded at startup)
_DEFAULT_PATTERNS: list[tuple[str, SensitivityLevel, str]] = [
    # (regex, level, description)
    (r"\b\d{3}-\d{2}-\d{4}\b", SensitivityLevel.CONFIDENTIAL, "US SSN"),
    (r"\b(?:\d[ -]*?){13,19}\b", SensitivityLevel.RESTRICTED, "Credit/debit card"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", SensitivityLevel.INTERNAL, "Email address"),
    (r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", SensitivityLevel.CONFIDENTIAL, "US/CA phone"),
    (r"\b(?:sk-|sk-ant-|sk-proj-)[A-Za-z0-9_-]{20,}\b", SensitivityLevel.RESTRICTED, "API key"),
    (r"\b(?:CONFIDENTIAL|TOP SECRET|RESTRICTED)\b", SensitivityLevel.RESTRICTED, "Classification marker"),
    (r"\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{0,2}\b", SensitivityLevel.CONFIDENTIAL, "IBAN"),
]


class SensitivityClassifier:
    """
    Three-layer sensitivity classification pipeline.

    Layer 1 (regex) cannot be disabled.
    Layers 2 and 3 are opt-out via constructor flags.

    v2.23.3: Layer 2 backend changed from fasttext-wheel to scikit-learn.
    The constructor accepts both `enable_sklearn`/`sklearn_backend` (preferred)
    and legacy `enable_fasttext`/`fasttext_backend` keyword aliases for callers
    that haven't been updated yet (deprecated, removed in v2.24.0).
    """

    def __init__(
        self,
        patterns: list[tuple[str, SensitivityLevel, str]] | None = None,
        # Preferred names (v2.23.3+)
        enable_sklearn: bool = True,
        sklearn_backend=None,
        # Legacy aliases — deprecated, will be removed in v2.24.0
        enable_fasttext: bool | None = None,
        fasttext_backend=None,
        # Ollama layer
        enable_ollama: bool = True,
        ollama_url: str = "http://ollama:11434",
        ollama_model: str = "qwen2.5:3b",
    ) -> None:
        self._patterns = [
            (re.compile(p, re.IGNORECASE), level, desc)
            for p, level, desc in (patterns or _DEFAULT_PATTERNS)
        ]
        # Handle legacy keyword aliases with deprecation warnings
        if enable_fasttext is not None:
            logger.warning(
                "SensitivityClassifier: enable_fasttext is deprecated, use enable_sklearn. "
                "Will be removed in v2.24.0."
            )
            enable_sklearn = enable_fasttext
        if fasttext_backend is not None:
            logger.warning(
                "SensitivityClassifier: fasttext_backend is deprecated, use sklearn_backend. "
                "Will be removed in v2.24.0."
            )
            sklearn_backend = fasttext_backend

        self._enable_sklearn = enable_sklearn
        self._enable_ollama = enable_ollama
        self._sklearn = sklearn_backend
        self._ollama_url = ollama_url
        self._ollama_model = ollama_model
        logger.info(
            "SensitivityClassifier: regex=%d patterns, sklearn=%s, ollama=%s",
            len(self._patterns), enable_sklearn, enable_ollama,
        )

    def classify_decoded(self, text: str) -> SensitivityResult:
        """Classify *text* AND every decoded view of it (F-RT1).

        Decode-before-classify: the input is normalised via
        ``yashigani.pii.decode.decode_views`` — base64 (std + urlsafe), hex,
        URL percent-encoding, ROT13, bounded nested decoding — and EACH view
        (raw + decoded) is run through :meth:`classify`.  The result carries
        the HIGHEST sensitivity level across all views (conservative), so an
        encoded payload like base64("SSN 123-45-6789") elevates the level the
        same way the plaintext would.

        A long encoded-looking high-entropy blob that could not be decoded
        floors the level at CONFIDENTIAL and adds a "decode:suspicious-blob"
        trigger, so a sensitive-context encoded blob is never a silent PUBLIC
        pass even when it cannot be read.

        Fully backward-compatible with :meth:`classify` for non-encoded text:
        the raw view alone determines the level.
        """
        from yashigani.pii.decode import decode_views

        decode_result = decode_views(text)
        final_level = SensitivityLevel.PUBLIC
        all_triggers: list[str] = []
        layer_results: dict[str, SensitivityLevel] = {}
        conflict = False

        for view in decode_result.views:
            view_result = self.classify(view.text)
            if view_result.level.rank > final_level.rank:
                final_level = view_result.level
            for trig in view_result.triggers:
                tagged = trig if view.view_name == "raw" else f"{view.view_name}:{trig}"
                all_triggers.append(tagged)
            # Keep the raw view's per-layer breakdown for compatibility.
            if view.view_name == "raw":
                layer_results = view_result.layer_results
            conflict = conflict or view_result.conflict

        # F-RT1 silent-pass guard: an undecodable high-entropy encoded blob in a
        # request is itself a signal.  Floor at CONFIDENTIAL so OPA's sensitivity
        # ceiling can act on it, and surface it as a trigger for audit.
        if decode_result.suspicious_blob:
            all_triggers.append("decode:suspicious-blob")
            if final_level.rank < SensitivityLevel.CONFIDENTIAL.rank:
                logger.warning(
                    "F-RT1: undecodable high-entropy encoded blob present — "
                    "flooring sensitivity at CONFIDENTIAL (tokens=%s)",
                    decode_result.flagged_tokens,
                )
                final_level = SensitivityLevel.CONFIDENTIAL

        return SensitivityResult(
            level=final_level,
            triggers=all_triggers,
            layer_results=layer_results,
            conflict=conflict,
        )

    def classify(self, text: str) -> SensitivityResult:
        """
        Run all enabled layers and return the highest sensitivity detected.

        Args:
            text: The prompt or message content to classify

        Returns:
            SensitivityResult with level, triggers, and per-layer details

        Fail-closed degradation (v2.23.3 — Laura CVA finding LAURA-CVA-V233-SKLEARN #2):
            If ollama is unavailable AND sklearn returns UNCERTAIN, the result is
            floored at RESTRICTED rather than falling through to PUBLIC. Defence-in-depth
            for the case where both non-regex layers cannot contribute a positive signal.
            Rationale: "I don't know" from two ML layers during a partial outage is a
            reason to be MORE conservative, not less.
        """
        triggers: list[str] = []
        layer_results = {}

        # Layer 1: Regex (always on, cannot be disabled)
        regex_level = self._scan_regex(text, triggers)
        layer_results["regex"] = regex_level

        # Layer 2: sklearn (opt-out)
        sklearn_level = SensitivityLevel.PUBLIC
        sklearn_uncertain = False  # True when backend signalled UNCERTAIN or failed
        if self._enable_sklearn and self._sklearn:
            try:
                # Call backend once; derive both level and uncertainty from the same result.
                raw_sklearn = self._sklearn.classify(text)
                sklearn_uncertain = raw_sklearn.label == "UNCERTAIN"
                if raw_sklearn.confidence > 0.5:
                    sklearn_level = _label_to_level(raw_sklearn.label)
                    if sklearn_level != SensitivityLevel.PUBLIC:
                        triggers.append(f"sklearn:{raw_sklearn.label}({raw_sklearn.confidence:.2f})")
                layer_results["sklearn"] = sklearn_level
            except Exception as exc:
                logger.warning("sklearn sensitivity scan failed: %s", exc)
                layer_results["sklearn"] = SensitivityLevel.PUBLIC
                sklearn_uncertain = True  # treat exception as uncertain

        # Layer 3: Ollama deep scan (opt-out)
        ollama_level = SensitivityLevel.PUBLIC
        ollama_unavailable = False
        if self._enable_ollama:
            try:
                ollama_level = self._scan_ollama(text, triggers)
                layer_results["ollama"] = ollama_level
            except Exception as exc:
                logger.warning("Ollama sensitivity scan failed: %s", exc)
                layer_results["ollama"] = SensitivityLevel.PUBLIC
                ollama_unavailable = True

        # Take the highest (most conservative) result
        all_levels = [regex_level, sklearn_level, ollama_level]
        final_level = max(all_levels, key=lambda l: l.rank)

        # Fail-closed: if ollama is unavailable AND sklearn is uncertain, floor at RESTRICTED.
        # Both ML layers have failed to produce a definitive SAFE signal — the conservative
        # verdict is RESTRICTED, not PUBLIC.
        if ollama_unavailable and sklearn_uncertain:
            if final_level.rank < SensitivityLevel.RESTRICTED.rank:
                logger.warning(
                    "Fail-closed: ollama unavailable and sklearn UNCERTAIN — "
                    "elevating result from %s to RESTRICTED",
                    final_level.value,
                )
                triggers.append("fail-closed:ollama-unavailable+sklearn-uncertain")
                final_level = SensitivityLevel.RESTRICTED

        # Detect conflicts between layers
        unique_levels = set(l for l in all_levels if l != SensitivityLevel.PUBLIC)
        conflict = len(unique_levels) > 1

        if conflict:
            logger.warning(
                "Sensitivity classification conflict: regex=%s sklearn=%s ollama=%s -> %s (conservative)",
                regex_level.value, sklearn_level.value, ollama_level.value, final_level.value,
            )

        return SensitivityResult(
            level=final_level,
            triggers=triggers,
            layer_results=layer_results,
            conflict=conflict,
        )

    def _scan_regex(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 1: Regex pattern matching. Cannot be disabled."""
        highest = SensitivityLevel.PUBLIC
        for pattern, level, desc in self._patterns:
            if pattern.search(text):
                triggers.append(f"regex:{desc}")
                if level.rank > highest.rank:
                    highest = level
        return highest

    def _scan_sklearn(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 2: sklearn classifier (TF-IDF + LogisticRegression)."""
        if not self._sklearn:
            return SensitivityLevel.PUBLIC
        result = self._sklearn.classify(text)
        if result.confidence > 0.5:
            level = _label_to_level(result.label)
            if level != SensitivityLevel.PUBLIC:
                triggers.append(f"sklearn:{result.label}({result.confidence:.2f})")
            return level
        return SensitivityLevel.PUBLIC

    def _scan_classifier(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Engine-agnostic alias for _scan_sklearn (v2.25.3+). Preferred name."""
        return self._scan_sklearn(text, triggers)

    # ---------------------------------------------------------------------------
    # Legacy aliases — kept for back-compat; removed in v2.26.0.
    # ---------------------------------------------------------------------------
    def _scan_fasttext(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Deprecated alias for _scan_classifier. Removed in v2.26.0."""
        return self._scan_classifier(text, triggers)

    def _scan_ollama(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 3: Ollama deep contextual scan.

        Raises any transport or timeout exception so that classify() can detect
        that ollama was genuinely unavailable and apply fail-closed logic.
        A clean PUBLIC response (ollama reachable, text classified as non-sensitive)
        returns SensitivityLevel.PUBLIC without raising.
        """
        import httpx  # noqa: PLC0415 — intentional lazy import
        prompt = (
            "Classify the sensitivity of the following text. "
            "Reply with ONLY one word: PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED.\n"
            "Rules:\n"
            "- RESTRICTED: contains credit card numbers, API keys, passwords, government classified info\n"
            "- CONFIDENTIAL: contains SSN, phone numbers, IBAN, medical records, personally identifiable info\n"
            "- INTERNAL: contains email addresses, internal project names, employee names\n"
            "- PUBLIC: no sensitive data detected\n\n"
            f"Text: {text[:2000]}\n\n"  # Truncate to avoid overwhelming small models
            "Classification:"
        )
        resp = httpx.post(
            f"{self._ollama_url}/api/generate",
            json={"model": self._ollama_model, "prompt": prompt, "stream": False},
            timeout=10.0,
        )
        if resp.status_code == 200:
            body = resp.json()
            answer = body.get("response", "").strip().upper()
            for level in SensitivityLevel:
                if level.value in answer:
                    if level != SensitivityLevel.PUBLIC:
                        triggers.append(f"ollama:{level.value}")
                    return level
        return SensitivityLevel.PUBLIC

    def add_pattern(self, pattern: str, level: SensitivityLevel, description: str) -> None:
        """Add a custom regex pattern at runtime."""
        self._patterns.append((re.compile(pattern, re.IGNORECASE), level, description))

    def reload_patterns(self, patterns: list[tuple[str, SensitivityLevel, str]]) -> None:
        """Replace all patterns (e.g. after admin updates via API)."""
        self._patterns = [
            (re.compile(p, re.IGNORECASE), level, desc)
            for p, level, desc in patterns
        ]
        logger.info("SensitivityClassifier: reloaded %d patterns", len(self._patterns))


def _label_to_level(label: str) -> SensitivityLevel:
    """Map a classifier label to a sensitivity level.

    Handles both SensitivityLevel value names (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED)
    and the backend's binary CLEAN/UNSAFE labels:
      UNSAFE  → RESTRICTED  (injection or sensitive content detected)
      CLEAN   → PUBLIC      (no sensitive content)
      UNCERTAIN → PUBLIC    (no definitive signal; fail-closed handled in classify())
    """
    label = label.upper().replace("__LABEL__", "").strip()
    # Backend binary labels — checked before SensitivityLevel scan to avoid
    # "RESTRICTED" accidentally matching if it ever appears in a label string.
    if label == "UNSAFE":
        return SensitivityLevel.RESTRICTED
    if label in ("CLEAN", "UNCERTAIN"):
        return SensitivityLevel.PUBLIC
    for level in SensitivityLevel:
        if level.value in label:
            return level
    return SensitivityLevel.PUBLIC
