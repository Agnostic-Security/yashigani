"""
Regression tests — FIND-LAURA-412-CRIT-001 (CRITICAL, PCI PAN ingress DLP
bypass via zero-width-space, independently confirmed live 2026-08-08).

## Root cause

Two un-synced PAN detectors:

  - EGRESS absolute-PCI block (``yashigani.pii.detector.contains_pci_pan``,
    added in the prior FIND-PCI-EGRESS-CEILING-BYPASS session) already
    normalized text via ``_normalize_with_span_map`` (NFKC per-character +
    Unicode category-Cf/format-char strip) before matching + Luhn-validating.
  - INGRESS regex layer that gates POL-009 ``pci_data_present``
    (``yashigani.optimization.sensitivity_classifier.SensitivityClassifier
    ._scan_regex``, the card pattern in ``_DEFAULT_PATTERNS``) ran the SAME
    class of digit-run regex directly on the RAW, unnormalized text.

A Luhn-valid PAN with a zero-width character (U+200B ZERO WIDTH SPACE, and
category-Cf siblings U+200C/U+200D/U+FEFF) inserted between every digit
splits the digit run for the ingress regex — every `\\d` in the pattern
matches a single visible digit, but the zero-width character breaks
contiguity, so the pattern finds nothing. Plain, base64, and fullwidth-digit
PANs still tripped the (unnormalized) pattern or the egress path; only the
zero-width variant sailed through the ingress classifier untouched, so a
request carrying a card number in the clear reached the model with no
POL-009 deny at all.

## The fix

``_scan_regex`` (src/yashigani/optimization/sensitivity_classifier.py) now:

  1. Normalizes the input via the SAME
     ``yashigani.pii.detector.normalize_for_pattern_matching`` (NFKC +
     Cf-strip) routine egress uses, before running every non-card pattern.
  2. Delegates credit-card detection entirely to
     ``yashigani.pii.detector.contains_pci_pan`` (Luhn-validated, network-
     prefix-matched) instead of the old bare ``\\b(?:\\d[ -]*?){13,19}\\b``
     regex — unifying ingress and egress onto ONE hardened PAN detector.

These tests exercise the classifier directly (unit-level proof the
detection logic is fixed) — the brief's live re-verification against the
running podman stack (zero-width/plain/base64/fullwidth PAN on /v1 and
/user, both stream modes, plus a benign-text no-over-block check) is
reported separately in the session's live-trial log, not re-implemented
here as a network test.
"""
from __future__ import annotations

from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)

_VISA_TEST_PAN = "4111111111111111"  # Luhn-valid Visa test PAN
_ZERO_WIDTH = "​"  # ZERO WIDTH SPACE — the exact evasion character Laura used


def _classifier() -> SensitivityClassifier:
    # Layer 1 (regex) only — disable sklearn/ollama so the assertions are
    # about the deterministic regex layer this finding is scoped to.
    return SensitivityClassifier(enable_sklearn=False, enable_ollama=False)


def _zero_width_pan(pan: str) -> str:
    return _ZERO_WIDTH.join(list(pan))


class TestFindLaura412Crit001PanZeroWidth:
    def test_zero_width_pan_is_now_detected_as_sensitive(self):
        """The exact bypass: a Luhn-valid PAN with U+200B between every
        digit must now be classified SENSITIVE (level 5), not PUBLIC."""
        clf = _classifier()
        text = f"My card number is {_zero_width_pan(_VISA_TEST_PAN)} please charge it"
        result = clf.classify(text)
        assert result.level == int(SensitivityLevel.SENSITIVE)
        assert any("Credit/debit card" in t for t in result.triggers)

    def test_zero_width_pan_detected_via_classify_decoded(self):
        """Ingress calls classify_decoded() (decode-before-classify); the
        raw view alone must trip the fix even without any encoding layer."""
        clf = _classifier()
        text = _zero_width_pan(_VISA_TEST_PAN)
        result = clf.classify_decoded(text)
        assert result.level == int(SensitivityLevel.SENSITIVE)

    def test_other_zero_width_format_chars_also_evade_no_more(self):
        """U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM/ZWNBSP — all category-Cf,
        all stripped by the shared normalizer."""
        clf = _classifier()
        for zw in ("‌", "‍", "﻿"):
            text = zw.join(list(_VISA_TEST_PAN))
            result = clf.classify(text)
            assert result.level == int(SensitivityLevel.SENSITIVE), (
                f"format char {zw!r} still evades detection"
            )

    def test_plain_pan_still_detected_no_regression(self):
        clf = _classifier()
        result = clf.classify(f"Card: {_VISA_TEST_PAN}")
        assert result.level == int(SensitivityLevel.SENSITIVE)

    def test_fullwidth_digit_pan_still_detected_no_regression(self):
        """Fullwidth digits (U+FF10-U+FF19) NFKC-fold to ASCII digits —
        already closed by contains_pci_pan; confirm ingress inherits it."""
        fullwidth = "".join(chr(0xFF10 + int(d)) for d in _VISA_TEST_PAN)
        clf = _classifier()
        result = clf.classify(f"Card: {fullwidth}")
        assert result.level == int(SensitivityLevel.SENSITIVE)

    def test_luhn_invalid_digit_run_not_flagged_as_card(self):
        """Unifying onto contains_pci_pan (Luhn-validated) means a
        Luhn-invalid 16-digit run is no longer misclassified as a card —
        this is a false-positive REDUCTION versus the old bare digit-run
        regex, not a new gap (SSN/other patterns are unaffected)."""
        clf = _classifier()
        result = clf.classify("Reference number: 1234 5678 9012 3456")
        assert not any("Credit/debit card" in t for t in result.triggers)

    def test_benign_text_still_public_no_over_block(self):
        clf = _classifier()
        result = clf.classify("hello, how are you today?")
        assert result.level == int(SensitivityLevel.PUBLIC)

    def test_zero_width_ssn_also_normalized(self):
        """The normalization is applied to ALL Layer-1 patterns, not just
        credit card — a zero-width-split SSN must be caught too."""
        clf = _classifier()
        ssn = _zero_width_pan("123-45-6789")
        result = clf.classify(f"SSN: {ssn}")
        assert result.level == int(SensitivityLevel.RESTRICTED)
