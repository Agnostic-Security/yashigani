"""
Yashigani PII Detection — core detector.

Design principles:
- Zero external dependencies: stdlib only (re, dataclasses, enum).
- Standalone: does NOT depend on the sensitivity classifier.
- Bidirectional: safe to call on both request and response payloads.
- Audit-safe: raw PII is never stored — only masked_value is kept.
  Mask rule: first 2 chars + '****' + last 2 chars of the matched span.
  Single-char or two-char matches are fully masked.

Modes:
  LOG     — detect, record findings, return original text unchanged.
  REDACT  — detect, replace each match inline with [REDACTED:<TYPE>].
  BLOCK   — detect, return original text; action_taken="blocked". Caller
            decides whether to drop the payload based on detected=True.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from yashigani.pii.patterns import PATTERN_REGISTRY


# ---------------------------------------------------------------------------
# Public enumerations
# ---------------------------------------------------------------------------

class PiiMode(str, Enum):
    PASS         = "pass"           # allow through; no scan (explicit opt-out)
    LOG          = "log"            # detect and record; return original text
    REDACT       = "redact"         # detect and replace with [REDACTED:<TYPE>]
    PSEUDONYMIZE = "pseudonymize"   # detect and replace with [PSEUDONYMIZED:<TYPE>]
                                    # (non-reversible at this layer; reversible
                                    # pseudonymisation via pointer is at the
                                    # doc-OPA pipeline layer)
    BLOCK        = "block"          # detect; caller decides to drop payload


class PiiType(str, Enum):
    SSN                  = "SSN"
    CREDIT_CARD          = "CREDIT_CARD"
    EMAIL                = "EMAIL"
    PHONE                = "PHONE"
    IBAN                 = "IBAN"
    PASSPORT             = "PASSPORT"
    NHS_NUMBER           = "NHS_NUMBER"
    DRIVERS_LICENCE      = "DRIVERS_LICENCE"
    IP_ADDRESS           = "IP_ADDRESS"
    DATE_OF_BIRTH        = "DATE_OF_BIRTH"
    # Identifying / quasi-identifying classes broadened for document
    # enforcement (L-01 / red-team F2): a small structured record set is
    # re-identifiable when these survive in the clear, so PSEUDONYMIZE must
    # tokenize them and the small-set gate must see them as quasi-identifiers.
    NATIONAL_INSURANCE   = "NATIONAL_INSURANCE"   # UK NINO (AA 10 10 10 A)
    POSTAL_ADDRESS       = "POSTAL_ADDRESS"       # UK postcode / postal address
    # FINDING-V412-RESTART-013 gap #2: a person's name is PII in its own
    # right (direct identifier), but was NEVER a detected class — a document
    # under a "PII" data-class REDACT/PSEUDONYMIZE rule left "Name: Alice
    # Zhang" in cleartext even though SSN + EMAIL on the same document were
    # correctly caught. Context-sensitive (label-anchored) — see
    # patterns.PERSON_NAME_PATTERNS.
    PERSON_NAME          = "PERSON_NAME"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PiiFinding:
    """A single PII match within the scanned text."""
    pii_type: PiiType
    start: int
    end: int
    masked_value: str   # first 2 + '****' + last 2 chars; safe for audit logs
    # F-RT1: which normalised view the match came from.  "raw" for matches on
    # the original prompt text; "base64"/"hex"/"url"/"rot13"/... for matches
    # found only after decoding an encoded segment.  Audit-safe (no raw PII).
    view: str = "raw"


@dataclass
class PiiResult:
    """Aggregated outcome of a PII scan."""
    detected: bool
    findings: list[PiiFinding]
    mode: PiiMode
    action_taken: str   # "logged" | "redacted" | "blocked"
    # F-RT1: distinct views in which PII was found (e.g. {"raw", "base64"}).
    # Lets the caller record that a payload was caught only after decoding.
    matched_views: set = None  # type: ignore[assignment]
    # F-RT1: a long, encoded-looking, high-entropy blob that could NOT be
    # decoded to plaintext was present.  Even with detected=False this MUST
    # be audited — the silent pass is the worst part of F-RT1.
    suspicious_blob: bool = False
    suspicious_tokens: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.matched_views is None:
            self.matched_views = set()
        if self.suspicious_tokens is None:
            self.suspicious_tokens = []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _mask(value: str) -> str:
    """Return a masked representation safe for audit logging.

    Rule: first 2 chars + '****' + last 2 chars.
    Lengths < 5 are fully masked with '****'.
    """
    if len(value) < 5:
        return "****"
    return value[:2] + "****" + value[-2:]


def _luhn_valid(number: str) -> bool:
    """Validate a credit card number string using the Luhn algorithm.

    Non-digit characters are stripped before validation.
    """
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# F4 (CRITICAL — Laura, FINDING-V412-DOCKER-CLEANROUND-BATCH): inserting a
# Unicode "format" character (category Cf — U+200B ZERO WIDTH SPACE,
# U+200C ZERO WIDTH NON-JOINER, U+200D ZERO WIDTH JOINER, U+FEFF
# ZERO-WIDTH-NO-BREAK-SPACE/BOM, and others) INSIDE an SSN/credit-card/etc.
# token splits the contiguous digit run so every pattern in patterns.py
# (all plain `\d`/literal-anchored regexes, no format-char tolerance)
# finds ZERO matches — the value passed through completely unredacted.
# These characters render with zero visual width, so an operator/reviewer
# staring at the rendered text sees the exact same SSN/card number a human
# would recognise as sensitive, while the detector sees nothing.
#
# Fix: normalize text BEFORE matching —
#   1. Drop every category-"Cf" (format) character entirely (they carry no
#      visual width and no semantic content of their own).
#   2. Apply NFKC per-character (never across characters, so the mapping
#      stays simple and order-preserving) to also close compatibility-form
#      evasions (e.g. FULLWIDTH DIGIT ZERO U+FF10 -> ASCII "0").
# The index_map lets a match span in the NORMALIZED text be translated
# back to the correct span in the ORIGINAL text, so redaction/
# pseudonymisation still splices the right characters out of the real
# payload (never the normalized copy).
def _normalize_with_span_map(text: str) -> tuple[str, list[int]]:
    """
    Build a normalized view of ``text`` for PII pattern matching, plus a
    parallel index map so a match span found in the NORMALIZED text can be
    translated back to the corresponding span in the ORIGINAL text.

    Returns:
        (normalized_text, index_map) where index_map[i] is the original-text
        index that normalized_text[i] was derived from.  A normalized span
        [ns, ne) maps back to the original span
        [index_map[ns], index_map[ne - 1] + 1) via
        :func:`_map_normalized_span_to_original`.
    """
    out_chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if unicodedata.category(ch) == "Cf":
            # Zero-width / format character — drop entirely.  No output
            # emitted, so it contributes nothing to the matched span and
            # cannot be used to split an otherwise-contiguous PII token.
            continue
        for out_ch in unicodedata.normalize("NFKC", ch):
            out_chars.append(out_ch)
            index_map.append(i)
    return "".join(out_chars), index_map


def _map_normalized_span_to_original(
    norm_start: int, norm_end: int, index_map: list[int], orig_len: int,
) -> tuple[int, int]:
    """Translate a [norm_start, norm_end) span in normalized text back to
    the corresponding [orig_start, orig_end) span in the original text."""
    if norm_end <= norm_start:
        pos = index_map[norm_start] if norm_start < len(index_map) else orig_len
        return pos, pos
    orig_start = index_map[norm_start]
    orig_end = index_map[norm_end - 1] + 1
    return orig_start, orig_end


def _deduplicate_findings(findings: list[PiiFinding]) -> list[PiiFinding]:
    """Remove overlapping findings, keeping the one with the wider span.

    When two findings overlap we prefer the longer match to avoid tagging
    sub-sequences of a single PII value twice.
    """
    if not findings:
        return findings

    # Sort by start position, then by descending span length.
    sorted_f = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    result: list[PiiFinding] = []
    last_end = -1
    for f in sorted_f:
        if f.start >= last_end:
            result.append(f)
            last_end = f.end
    return result


# ---------------------------------------------------------------------------
# PiiDetector
# ---------------------------------------------------------------------------

class PiiDetector:
    """Regex-based PII detector.

    Parameters
    ----------
    mode:
        Controls what action is taken when PII is found.
    enabled_types:
        Set of PiiType values to scan for. ``None`` enables all types.
    """

    def __init__(
        self,
        mode: PiiMode = PiiMode.LOG,
        enabled_types: Optional[set[PiiType]] = None,
    ) -> None:
        self.mode = mode
        self.enabled_types: set[PiiType] = (
            set(PiiType) if enabled_types is None else set(enabled_types)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> PiiResult:
        """Scan *text* for all enabled PII types.

        Returns a :class:`PiiResult` with action_taken="logged" regardless
        of mode — this is a read-only scan.  Use :meth:`process` for the
        mode-appropriate action.
        """
        findings = self._scan(text)
        return PiiResult(
            detected=bool(findings),
            findings=findings,
            mode=self.mode,
            action_taken="logged",
        )

    def detect_decoded(self, text: str) -> PiiResult:
        """Scan *text* AND every decoded view of it for PII (F-RT1).

        The decode-before-classify stage (``yashigani.pii.decode``) normalises
        plausibly-encoded segments — base64 (std + urlsafe), hex, URL
        percent-encoding, ROT13, bounded nested decoding — back to plaintext
        BEFORE the regex scan runs.  A hit in ANY view sets ``detected``; each
        :class:`PiiFinding` records the ``view`` it came from.

        Even when no PII matches, a long encoded-looking high-entropy blob that
        could not be decoded sets ``suspicious_blob=True`` so the caller can
        still emit an audit event (closing the F-RT1 silent-pass).

        This is a read-only scan (action_taken="logged").  For mode-aware
        request handling use :meth:`process_decoded`.
        """
        # Lazy import keeps the detector importable even if decode is stubbed.
        from yashigani.pii.decode import decode_views

        decode_result = decode_views(text)
        all_findings: list[PiiFinding] = []
        matched_views: set[str] = set()

        for view in decode_result.views:
            view_findings = self._scan(view.text)
            for f in view_findings:
                f.view = view.view_name
                all_findings.append(f)
                matched_views.add(view.view_name)

        return PiiResult(
            detected=bool(all_findings),
            findings=all_findings,
            mode=self.mode,
            action_taken="logged",
            matched_views=matched_views,
            suspicious_blob=decode_result.suspicious_blob,
            suspicious_tokens=list(decode_result.flagged_tokens),
        )

    def process_decoded(self, text: str) -> tuple[str, PiiResult]:
        """Mode-aware dispatcher that decodes before classifying (F-RT1).

        Mirrors :meth:`process` but classifies across raw + decoded views:

        - LOG / BLOCK: returns the ORIGINAL text unchanged.  ``action_taken``
          is "blocked" in BLOCK mode (caller drops on ``detected``), else
          "logged".  Encoded payloads are NOT silently rewritten.
        - REDACT: redacts matches found in the *raw* view in-place (offsets are
          only meaningful against the raw text).  Matches found only inside an
          encoded segment cannot be safely spliced back, so REDACT mode escalates
          ``action_taken`` to "blocked" for encoded-only hits — the caller MUST
          drop or refuse the payload rather than forward an un-redactable
          encoded secret.  ``detected`` is always set when any view matched.

        F4 (CRITICAL — Laura): ``action_taken`` is "redacted"/"pseudonymized"
        ONLY when at least one raw-view finding was actually spliced out of
        the text.  A genuinely clean payload (``raw_findings`` empty and not
        ``encoded_only``) reports action_taken="logged" — never falsely
        claims a transform that never happened (false compliance).
        """
        result = self.detect_decoded(text)

        if self.mode == PiiMode.PASS:
            return text, PiiResult(
                detected=False, findings=[], mode=self.mode, action_taken="passed",
            )

        if self.mode == PiiMode.REDACT:
            raw_findings = [f for f in result.findings if f.view == "raw"]
            redacted = self._apply_redactions(text, raw_findings)
            encoded_only = result.detected and not raw_findings
            # If PII was found only in a decoded view, we cannot redact it in
            # place — escalate to blocked so the caller refuses the payload.
            # F4: only claim "redacted" when a raw-view finding was actually
            # spliced out — never on a payload with nothing to redact.
            if encoded_only:
                action = "blocked"
            elif raw_findings:
                action = "redacted"
            else:
                action = "logged"
            return redacted, PiiResult(
                detected=result.detected,
                findings=result.findings,
                mode=self.mode,
                action_taken=action,
                matched_views=result.matched_views,
                suspicious_blob=result.suspicious_blob,
                suspicious_tokens=result.suspicious_tokens,
            )

        if self.mode == PiiMode.PSEUDONYMIZE:
            raw_findings = [f for f in result.findings if f.view == "raw"]
            pseudonymized = self._apply_pseudonymization(text, raw_findings)
            encoded_only = result.detected and not raw_findings
            # Same escalation as REDACT: encoded-only PII cannot be pseudonymised
            # in-place — caller must block the payload.
            # F4: only claim "pseudonymized" when something was actually applied.
            if encoded_only:
                action = "blocked"
            elif raw_findings:
                action = "pseudonymized"
            else:
                action = "logged"
            return pseudonymized, PiiResult(
                detected=result.detected,
                findings=result.findings,
                mode=self.mode,
                action_taken=action,
                matched_views=result.matched_views,
                suspicious_blob=result.suspicious_blob,
                suspicious_tokens=result.suspicious_tokens,
            )

        action = "blocked" if self.mode == PiiMode.BLOCK else "logged"
        return text, PiiResult(
            detected=result.detected,
            findings=result.findings,
            mode=self.mode,
            action_taken=action,
            matched_views=result.matched_views,
            suspicious_blob=result.suspicious_blob,
            suspicious_tokens=result.suspicious_tokens,
        )

    def redact(self, text: str) -> tuple[str, PiiResult]:
        """Detect PII and replace each match with ``[REDACTED:<TYPE>]``.

        Returns the redacted text and a :class:`PiiResult` describing the
        replacements.  Replacements are applied right-to-left so that
        start/end offsets of earlier findings stay valid.

        F4 (CRITICAL — Laura): ``action_taken`` is "redacted" only when a
        finding was actually spliced out; a clean payload (no findings)
        reports "logged" — never a false "redacted" claim on unchanged text.
        """
        findings = self._scan(text)
        redacted = self._apply_redactions(text, findings)
        result = PiiResult(
            detected=bool(findings),
            findings=findings,
            mode=self.mode,
            action_taken="redacted" if findings else "logged",
        )
        return redacted, result

    def process(self, text: str) -> tuple[str, PiiResult]:
        """Mode-aware dispatcher.

        - PASS:         no scan; return original text, action_taken="passed".
        - LOG:          detect only; return original text unchanged, action_taken="logged".
        - REDACT:       replace matches with [REDACTED:<TYPE>], action_taken="redacted".
        - PSEUDONYMIZE: replace matches with [PSEUDONYMIZED:<TYPE>] (non-reversible at
                        this layer; reversible pseudonymisation via pointer is handled
                        at the doc-OPA pipeline layer), action_taken="pseudonymized".
        - BLOCK:        detect only; return original text unchanged, action_taken="blocked".
                        Caller inspects result.detected to decide whether to drop payload.
        """
        if self.mode == PiiMode.PASS:
            return text, PiiResult(
                detected=False, findings=[], mode=self.mode, action_taken="passed",
            )
        if self.mode == PiiMode.REDACT:
            return self.redact(text)
        if self.mode == PiiMode.PSEUDONYMIZE:
            return self._pseudonymize(text)

        findings = self._scan(text)
        action = "blocked" if self.mode == PiiMode.BLOCK else "logged"
        result = PiiResult(
            detected=bool(findings),
            findings=findings,
            mode=self.mode,
            action_taken=action,
        )
        return text, result

    # ------------------------------------------------------------------
    # Internal scanning logic
    # ------------------------------------------------------------------

    def _scan(self, text: str) -> list[PiiFinding]:
        """Run all enabled patterns and return deduplicated findings.

        F4 (CRITICAL — Laura): patterns are matched against a NORMALIZED
        view of ``text`` (Cf/zero-width chars stripped + per-character
        NFKC) so a zero-width Unicode character inserted mid-token cannot
        split an otherwise-contiguous SSN/credit-card/etc. run and evade
        every pattern.  Match spans are translated back to the ORIGINAL
        text via the index map before being stored, so redaction /
        pseudonymisation still splices the correct span out of the real
        payload (including any zero-width characters embedded within it).
        """
        raw_findings: list[PiiFinding] = []
        norm_text, index_map = _normalize_with_span_map(text)

        for pii_type in self.enabled_types:
            patterns = PATTERN_REGISTRY.get(pii_type.value, [])
            for pattern in patterns:
                for match in pattern.finditer(norm_text):
                    # RESTART-013 gap #2: context-sensitive patterns (e.g.
                    # PERSON_NAME's "Name: <value>") wrap the SENSITIVE VALUE
                    # in capture group 1 so the finding span covers only the
                    # value — never the label ("Name:" stays cleartext,
                    # matching the existing SSN/EMAIL redaction shape). Every
                    # PRE-EXISTING pattern has zero capture groups (all use
                    # non-capturing `(?:...)` groups), so `pattern.groups == 0`
                    # for them and this falls through to the original
                    # whole-match behaviour unchanged.
                    if pattern.groups > 0 and match.group(1) is not None:
                        norm_start, norm_end = match.start(1), match.end(1)
                        matched_text = match.group(1)
                    else:
                        norm_start, norm_end = match.start(), match.end()
                        matched_text = match.group(0)

                    # Credit card: post-filter with Luhn check (against the
                    # NORMALIZED — clean, zero-width-free — matched text).
                    if pii_type == PiiType.CREDIT_CARD:
                        if not _luhn_valid(matched_text):
                            continue

                    # F4: map the span back to the ORIGINAL text so
                    # redaction/pseudonymisation excises the full original
                    # span (including any embedded zero-width characters).
                    span_start, span_end = _map_normalized_span_to_original(
                        norm_start, norm_end, index_map, len(text),
                    )

                    raw_findings.append(PiiFinding(
                        pii_type=pii_type,
                        start=span_start,
                        end=span_end,
                        masked_value=_mask(matched_text),
                    ))

        return _deduplicate_findings(raw_findings)

    def _pseudonymize(self, text: str) -> tuple[str, PiiResult]:
        """Detect PII and replace each match with ``[PSEUDONYMIZED:<TYPE>]``.

        Non-reversible at this layer.  Full reversible pseudonymisation
        (reversible via pointer file) is at the doc-OPA document pipeline.
        Returns the pseudonymised text and a PiiResult.

        F4 (CRITICAL — Laura): ``action_taken`` is "pseudonymized" only when
        a finding was actually applied; a clean payload reports "logged".
        """
        findings = self._scan(text)
        pseudonymized = self._apply_pseudonymization(text, findings)
        return pseudonymized, PiiResult(
            detected=bool(findings),
            findings=findings,
            mode=self.mode,
            action_taken="pseudonymized" if findings else "logged",
        )

    def _apply_redactions(self, text: str, findings: list[PiiFinding]) -> str:
        """Replace each finding span with ``[REDACTED:<TYPE>]``.

        Applied in reverse order so indices remain valid.
        """
        if not findings:
            return text

        # Sort descending by start so we replace from the end.
        ordered = sorted(findings, key=lambda f: f.start, reverse=True)
        result = text
        for finding in ordered:
            placeholder = f"[REDACTED:{finding.pii_type.value}]"
            result = result[: finding.start] + placeholder + result[finding.end :]

        return result

    def _apply_pseudonymization(self, text: str, findings: list[PiiFinding]) -> str:
        """Replace each finding span with ``[PSEUDONYMIZED:<TYPE>]``.

        Applied in reverse order so indices remain valid.
        """
        if not findings:
            return text

        ordered = sorted(findings, key=lambda f: f.start, reverse=True)
        result = text
        for finding in ordered:
            placeholder = f"[PSEUDONYMIZED:{finding.pii_type.value}]"
            result = result[: finding.start] + placeholder + result[finding.end :]

        return result


# ---------------------------------------------------------------------------
# FIND-PCI-EGRESS-CEILING-BYPASS (2026-08-07) — always-on, config-independent
# PAN detector for the absolute PCI egress block (POL-009 pci_data_block).
#
# This is a THIN wrapper around the existing Luhn-validated CREDIT_CARD
# pattern set — it does not invent new regex/validation logic. It exists so
# that "does this response contain a Luhn-valid card number" can be answered
# WITHOUT depending on whether an operator has ``PiiDetector``
# (``_state.pii_detector``) or the optional ``ResponseInspectionPipeline``
# (``_state.response_inspection_pipeline`` — a performance toggle, see
# YSG-RISK-057) configured/enabled. "Absolute" per the PCI DSS control means
# this check cannot be turned off by an unrelated admin config toggle.
# Decode-before-scan (``detect_decoded``) so an encoded PAN is caught too.
# ---------------------------------------------------------------------------
_PCI_PAN_SCANNER = PiiDetector(mode=PiiMode.LOG, enabled_types={PiiType.CREDIT_CARD})


def contains_pci_pan(text: str) -> bool:
    """Return True if *text* contains a Luhn-valid card number (any view).

    Always-on: does not depend on any ``PiiDetector``/``ResponseInspectionPipeline``
    instance being configured or enabled. Used by the gateway's absolute PCI
    egress block (POL-009) so a caller's sensitivity ceiling can never permit
    a cardholder data number to reach a human response body.
    """
    if not text:
        return False
    return _PCI_PAN_SCANNER.detect_decoded(text).detected
