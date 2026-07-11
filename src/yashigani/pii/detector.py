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
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from yashigani.pii.patterns import PATTERN_REGISTRY


# ---------------------------------------------------------------------------
# Public enumerations
# ---------------------------------------------------------------------------

class PiiMode(str, Enum):
    LOG    = "log"
    REDACT = "redact"
    BLOCK  = "block"


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
        """
        result = self.detect_decoded(text)

        if self.mode == PiiMode.REDACT:
            raw_findings = [f for f in result.findings if f.view == "raw"]
            redacted = self._apply_redactions(text, raw_findings)
            encoded_only = result.detected and not raw_findings
            # If PII was found only in a decoded view, we cannot redact it in
            # place — escalate to blocked so the caller refuses the payload.
            action = "blocked" if encoded_only else "redacted"
            return redacted, PiiResult(
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
        """
        findings = self._scan(text)
        redacted = self._apply_redactions(text, findings)
        result = PiiResult(
            detected=bool(findings),
            findings=findings,
            mode=self.mode,
            action_taken="redacted",
        )
        return redacted, result

    def process(self, text: str) -> tuple[str, PiiResult]:
        """Mode-aware dispatcher.

        - LOG:    detect only; return original text unchanged, action_taken="logged".
        - REDACT: replace matches; return redacted text, action_taken="redacted".
        - BLOCK:  detect only; return original text unchanged, action_taken="blocked".
                  Caller inspects result.detected to decide whether to drop the payload.
        """
        if self.mode == PiiMode.REDACT:
            return self.redact(text)

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
        """Run all enabled patterns and return deduplicated findings."""
        raw_findings: list[PiiFinding] = []

        for pii_type in self.enabled_types:
            patterns = PATTERN_REGISTRY.get(pii_type.value, [])
            for pattern in patterns:
                for match in pattern.finditer(text):
                    matched_text = match.group(0)

                    # Credit card: post-filter with Luhn check.
                    if pii_type == PiiType.CREDIT_CARD:
                        if not _luhn_valid(matched_text):
                            continue

                    raw_findings.append(PiiFinding(
                        pii_type=pii_type,
                        start=match.start(),
                        end=match.end(),
                        masked_value=_mask(matched_text),
                    ))

        return _deduplicate_findings(raw_findings)

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
