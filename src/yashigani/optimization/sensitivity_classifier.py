"""
Yashigani Optimization — Sensitivity classifier.

Three-layer pipeline, all ON by default:
  Layer 1: Regex patterns (microseconds) — CANNOT be disabled
  Layer 2: sklearn classifier (milliseconds) — admin can opt-out
  Layer 3: Ollama deep scan (200-500ms) — admin can opt-out

Returns the HIGHEST sensitivity level detected by any layer.
Conservative: if any layer says level 5 (Sensitive), the result is 5.

R14/R15 (v2.25.5): internal value is now the canonical integer level (1–5).

New canonical model:
  1 = PUBLIC     (lowest — maps to "Info" label in default taxonomy)
  2 = INTERNAL   (maps to "Public" label in default taxonomy)
  3 = CONFIDENTIAL (maps to "Internal" label in default taxonomy)
  4 = RESTRICTED (maps to "Confidential" label in default taxonomy)
  5 = SENSITIVE  (new top level — maps to "Sensitive" label)

The named members keep OLD enum names as backward-compat aliases.
_STRING_TO_LEVEL maps the old string names → new int levels.
_LEVEL_TO_LEGACY_STRING maps int levels → old string names for OPA/external consumers.

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

logger = logging.getLogger(__name__)


class SensitivityLevel(int, enum.Enum):
    """Data sensitivity classification levels.

    Internal value IS the canonical numeric rank (1 = lowest, 5 = highest).
    Named members use the old string names as backward-compat aliases
    (R14/R15, v2.25.5).

    OLD → NEW level mapping (backward-compat shim):
      PUBLIC       = 1  (old: rank 0 → new: lowest level)
      INTERNAL     = 2  (old: rank 1 → new: level 2)
      CONFIDENTIAL = 3  (old: rank 2 → new: level 3)
      RESTRICTED   = 4  (old: rank 3 → new: level 4)
      SENSITIVE    = 5  (new: top level; credit cards, API keys, classified)

    The .rank property returns the integer value for numeric comparisons.
    Use _LEVEL_TO_LEGACY_STRING[level.value] to get the OPA-compatible string.
    """
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    SENSITIVE = 5

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (same as .value for int enum)."""
        return self.value

    @classmethod
    def _missing_(cls, value: object) -> "SensitivityLevel | None":
        """Allow construction from int or string.

        SensitivityLevel(4) → RESTRICTED
        SensitivityLevel("RESTRICTED") → RESTRICTED
        SensitivityLevel("5") → SENSITIVE
        """
        if isinstance(value, int):
            for member in cls:
                if member.value == value:
                    return member
        if isinstance(value, str):
            level_num = _STRING_TO_LEVEL.get(value.upper())
            if level_num is not None:
                for member in cls:
                    if member.value == level_num:
                        return member
        return None


# ---------------------------------------------------------------------------
# Backward-compat shim: old/new string names → canonical numeric level (R14/R15).
# Used by _missing_, _label_to_level, and the admin API pattern validator.
#
# OLD rank map: PUBLIC=0, INTERNAL=1, CONFIDENTIAL=2, RESTRICTED=3.
# NEW level map: PUBLIC=1, INTERNAL=2, CONFIDENTIAL=3, RESTRICTED=4, SENSITIVE=5.
# ---------------------------------------------------------------------------
_STRING_TO_LEVEL: dict[str, int] = {
    # Old string names → new int levels
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "RESTRICTED": 4,
    # New canonical label (level 5)
    "SENSITIVE": 5,
    # Accept plain numeric strings
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    # Accept new default taxonomy labels (case-insensitive after .upper())
    "INFO": 1,
}

# For OPA / external string serialisation: map level number back to the legacy
# OPA string. OPA v1_routing.rego and agents.rego accept both these strings
# AND numeric levels (R14/R15 shim in v2.25.5).
_LEVEL_TO_LEGACY_STRING: dict[int, str] = {
    1: "PUBLIC",
    2: "INTERNAL",
    3: "CONFIDENTIAL",
    4: "RESTRICTED",
    5: "RESTRICTED",   # Level 5 maps to "RESTRICTED" for legacy OPA callers
                       # (OPA shim now also accepts int 5 directly — R14/R15).
}

# Backward-compat _LEVEL_RANK — maps SensitivityLevel to its int rank.
# Consumed by any code doing `_LEVEL_RANK[level]`.
_LEVEL_RANK: dict[SensitivityLevel, int] = {
    m: m.value for m in SensitivityLevel
}


@dataclass
class SensitivityResult:
    """Result of sensitivity classification."""
    level: int  # canonical numeric level (1–5); SensitivityLevel int enum value
    triggers: list[str] = field(default_factory=list)  # which patterns matched
    layer_results: dict[str, int] = field(default_factory=dict)  # per-layer levels
    conflict: bool = False  # True if layers disagreed


# Default regex patterns (seeded in DB, loaded at startup).
# Levels use SensitivityLevel int enum members.
# R14/R15 (v2.25.5) level assignments:
#   Credit/debit card → 5 (SENSITIVE/top)
#   API key → 5
#   Classification marker (CONFIDENTIAL|TOP SECRET|RESTRICTED) → 5
#   OFFICIAL-SENSITIVE → 5
#   US SSN → 4 (RESTRICTED/Confidential)
#   IBAN → 4
#   US/CA phone → 4
#   Email address → 3 (CONFIDENTIAL/Internal)
_DEFAULT_PATTERNS: list[tuple[str, SensitivityLevel, str]] = [
    # (regex, level, description)
    (r"\b\d{3}-\d{2}-\d{4}\b",                              SensitivityLevel.RESTRICTED,  "US SSN"),
    (r"\b(?:\d[ -]*?){13,19}\b",                             SensitivityLevel.SENSITIVE,   "Credit/debit card"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", SensitivityLevel.CONFIDENTIAL, "Email address"),
    (r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b",                      SensitivityLevel.RESTRICTED,  "US/CA phone"),
    (r"\b(?:sk-|sk-ant-|sk-proj-)[A-Za-z0-9_-]{20,}\b",     SensitivityLevel.SENSITIVE,   "API key"),
    (r"\b(?:CONFIDENTIAL|TOP SECRET|RESTRICTED)\b",           SensitivityLevel.SENSITIVE,   "Classification marker"),
    (r"\bOFFICIAL[\s_-]+SENSITIVE\b",                         SensitivityLevel.SENSITIVE,   "UK Gov OFFICIAL-SENSITIVE marking"),
    (r"\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{0,2}\b", SensitivityLevel.RESTRICTED, "IBAN"),
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

    R14/R15 (v2.25.5): all levels are now integers 1–5. The SensitivityLevel
    int-enum members work as before for comparisons and named access.
    Fail-closed path elevates to 5 (SENSITIVE) on dual-ML-layer failure.
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
        self._patterns: list[tuple[re.Pattern[str], int, str]] = [
            (re.compile(p, re.IGNORECASE), int(level), desc)
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
        floors the level at RESTRICTED (level 4) and adds a "decode:suspicious-blob"
        trigger, so a sensitive-context encoded blob is never a silent level-1
        pass even when it cannot be read.

        Fully backward-compatible with :meth:`classify` for non-encoded text:
        the raw view alone determines the level.
        """
        from yashigani.pii.decode import decode_views

        decode_result = decode_views(text)
        final_level: int = SensitivityLevel.PUBLIC
        all_triggers: list[str] = []
        layer_results: dict[str, int] = {}
        conflict = False

        for view in decode_result.views:
            view_result = self.classify(view.text)
            if view_result.level > final_level:
                final_level = view_result.level
            for trig in view_result.triggers:
                tagged = trig if view.view_name == "raw" else f"{view.view_name}:{trig}"
                all_triggers.append(tagged)
            # Keep the raw view's per-layer breakdown for compatibility.
            if view.view_name == "raw":
                layer_results = view_result.layer_results
            conflict = conflict or view_result.conflict

        # F-RT1 silent-pass guard: an undecodable high-entropy encoded blob in a
        # request is itself a signal.  Floor at RESTRICTED (level 4) so OPA's
        # sensitivity ceiling can act on it, and surface it as a trigger for audit.
        if decode_result.suspicious_blob:
            all_triggers.append("decode:suspicious-blob")
            if final_level < SensitivityLevel.RESTRICTED:
                # CodeQL py/clear-text-logging (#1869) — WON'T FIX (operational):
                # the flagged high-entropy tokens are required in the logs for
                # security forensics (which blob floored sensitivity to RESTRICTED).
                # Logs are the access-controlled / tamper-evident audit channel, not
                # a public surface. Keep logging the tokens by design.
                logger.warning(
                    "F-RT1: undecodable high-entropy encoded blob present — "
                    "flooring sensitivity at RESTRICTED/level-4 (tokens=%s)",
                    decode_result.flagged_tokens,
                )
                final_level = SensitivityLevel.RESTRICTED

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
            SensitivityResult with level (int 1–5), triggers, and per-layer details

        Fail-closed degradation (v2.23.3 — Laura CVA finding LAURA-CVA-V233-SKLEARN #2;
        updated R14/R15 v2.25.5):
            If ollama is unavailable AND sklearn returns UNCERTAIN, the result is
            floored at level 5 (SENSITIVE/highest) rather than falling through to
            level 1 (PUBLIC). Defence-in-depth for the case where both non-regex
            layers cannot contribute a positive signal.
            Rationale: "I don't know" from two ML layers during a partial outage is a
            reason to be MORE conservative, not less.
        """
        triggers: list[str] = []
        layer_results: dict[str, int] = {}

        # Layer 1: Regex (always on, cannot be disabled)
        regex_level: int = self._scan_regex(text, triggers)
        layer_results["regex"] = regex_level

        # Layer 2: sklearn (opt-out)
        sklearn_level: int = SensitivityLevel.PUBLIC
        sklearn_uncertain = False  # True when backend signalled UNCERTAIN or failed
        if self._enable_sklearn and self._sklearn:
            try:
                # Call backend once; derive both level and uncertainty from the same result.
                raw_sklearn = self._sklearn.classify(text)
                sklearn_uncertain = raw_sklearn.label == "UNCERTAIN"
                if raw_sklearn.confidence > 0.5:
                    sklearn_level = _label_to_level(raw_sklearn.label)
                    if sklearn_level > SensitivityLevel.PUBLIC:
                        triggers.append(f"sklearn:{raw_sklearn.label}({raw_sklearn.confidence:.2f})")
                layer_results["sklearn"] = sklearn_level
            except Exception as exc:
                logger.warning("sklearn sensitivity scan failed: %s", exc)
                layer_results["sklearn"] = SensitivityLevel.PUBLIC
                sklearn_uncertain = True  # treat exception as uncertain

        # Layer 3: Ollama deep scan (opt-out)
        ollama_level: int = SensitivityLevel.PUBLIC
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
        final_level: int = max(all_levels)

        # Fail-closed: if ollama is unavailable AND sklearn is uncertain, floor at level 5.
        # Both ML layers have failed to produce a definitive SAFE signal — the conservative
        # verdict is SENSITIVE (5), not PUBLIC (1).
        if ollama_unavailable and sklearn_uncertain:
            if final_level < SensitivityLevel.SENSITIVE:
                logger.warning(
                    "Fail-closed: ollama unavailable and sklearn UNCERTAIN — "
                    "elevating result from %d to SENSITIVE (5)",
                    final_level,
                )
                triggers.append("fail-closed:ollama-unavailable+sklearn-uncertain")
                final_level = SensitivityLevel.SENSITIVE

        # Detect conflicts between layers
        unique_levels = {lvl for lvl in all_levels if lvl > SensitivityLevel.PUBLIC}
        conflict = len(unique_levels) > 1

        if conflict:
            logger.warning(
                "Sensitivity classification conflict: regex=%d sklearn=%d ollama=%d -> %d (conservative)",
                regex_level, sklearn_level, ollama_level, final_level,
            )

        return SensitivityResult(
            level=final_level,
            triggers=triggers,
            layer_results=layer_results,
            conflict=conflict,
        )

    def _scan_regex(self, text: str, triggers: list[str]) -> int:
        """Layer 1: Regex pattern matching. Cannot be disabled. Returns int level."""
        highest: int = SensitivityLevel.PUBLIC
        for pattern, level, desc in self._patterns:
            if pattern.search(text):
                triggers.append(f"regex:{desc}")
                if int(level) > highest:
                    highest = int(level)
        return highest

    def _scan_sklearn(self, text: str, triggers: list[str]) -> int:
        """Layer 2: sklearn classifier (TF-IDF + LogisticRegression). Returns int level."""
        if not self._sklearn:
            return SensitivityLevel.PUBLIC
        result = self._sklearn.classify(text)
        if result.confidence > 0.5:
            level = _label_to_level(result.label)
            if level > SensitivityLevel.PUBLIC:
                triggers.append(f"sklearn:{result.label}({result.confidence:.2f})")
            return level
        return SensitivityLevel.PUBLIC

    def _scan_classifier(self, text: str, triggers: list[str]) -> int:
        """Engine-agnostic alias for _scan_sklearn (v2.25.3+). Preferred name."""
        return self._scan_sklearn(text, triggers)

    # ---------------------------------------------------------------------------
    # Legacy aliases — kept for back-compat; removed in v2.26.0.
    # ---------------------------------------------------------------------------
    def _scan_fasttext(self, text: str, triggers: list[str]) -> int:
        """Deprecated alias for _scan_classifier. Removed in v2.26.0."""
        return self._scan_classifier(text, triggers)

    def _scan_ollama(self, text: str, triggers: list[str]) -> int:
        """Layer 3: Ollama deep contextual scan. Returns int level.

        Raises any transport or timeout exception so that classify() can detect
        that ollama was genuinely unavailable and apply fail-closed logic.
        A clean PUBLIC response (ollama reachable, text classified as non-sensitive)
        returns SensitivityLevel.PUBLIC without raising.
        """
        import httpx  # noqa: PLC0415 — intentional lazy import
        prompt = (
            "Classify the sensitivity of the following text. "
            "Reply with ONLY one word: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, or SENSITIVE.\n"
            "Rules:\n"
            "- SENSITIVE (level 5): contains credit card numbers, API keys, passwords, "
            "government classified info (TOP SECRET, OFFICIAL-SENSITIVE)\n"
            "- RESTRICTED (level 4): contains SSN, phone numbers, IBAN, medical records, "
            "personally identifiable info\n"
            "- CONFIDENTIAL (level 3): contains email addresses, internal project names, "
            "employee names\n"
            "- INTERNAL (level 2): general business information, meeting notes\n"
            "- PUBLIC (level 1): no sensitive data detected\n\n"
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
            # Check canonical labels in descending order (highest match first)
            for label in ("SENSITIVE", "RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"):
                if label in answer:
                    lvl = _STRING_TO_LEVEL[label]
                    if lvl > SensitivityLevel.PUBLIC:
                        triggers.append(f"ollama:{label}")
                    return lvl
        return SensitivityLevel.PUBLIC

    def add_pattern(self, pattern: str, level: "SensitivityLevel | int", description: str) -> None:
        """Add a custom regex pattern at runtime."""
        self._patterns.append((re.compile(pattern, re.IGNORECASE), int(level), description))

    def reload_patterns(self, patterns: list[tuple[str, "SensitivityLevel | int", str]]) -> None:
        """Replace all patterns (e.g. after admin updates via API)."""
        self._patterns = [
            (re.compile(p, re.IGNORECASE), int(level), desc)
            for p, level, desc in patterns
        ]
        logger.info("SensitivityClassifier: reloaded %d patterns", len(self._patterns))


def _label_to_level(label: str) -> int:
    """Map a classifier label to a numeric sensitivity level (1–5).

    Handles both SensitivityLevel names (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED/SENSITIVE)
    and the backend's binary CLEAN/UNSAFE labels:
      UNSAFE    → 5 (SENSITIVE — injection or highly sensitive content)
      CLEAN     → 1 (PUBLIC — no sensitive content)
      UNCERTAIN → 1 (no definitive signal; fail-closed handled in classify())

    R14/R15 (v2.25.5): returns int level instead of SensitivityLevel enum member.
    """
    label = label.upper().replace("__LABEL__", "").strip()
    # Backend binary labels — checked before table scan.
    if label == "UNSAFE":
        return SensitivityLevel.SENSITIVE  # 5
    if label in ("CLEAN", "UNCERTAIN"):
        return SensitivityLevel.PUBLIC  # 1
    # Named label lookup via shim table
    level = _STRING_TO_LEVEL.get(label)
    if level is not None:
        return level
    return SensitivityLevel.PUBLIC  # default: lowest
