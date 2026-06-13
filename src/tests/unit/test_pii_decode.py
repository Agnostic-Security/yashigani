"""
Unit tests for the F-RT1 decode-before-classify stage.

F-RT1 (Medium, red-team verified 2026-05-30): the PII/sensitivity classifier
matched literal patterns on RAW prompt text only, so base64("SSN 123-45-6789")
produced NO PII_DETECTED event and was delivered silently.  These tests prove:

  - base64 (std + urlsafe), hex, URL-encoded, ROT13 payloads carrying an SSN or
    credit card are now decoded and detected, with the matching view recorded.
  - The original red-team cases (esp. #6 base64) behave correctly.
  - Non-encoded text still classifies exactly as before.
  - A non-decodable / huge / high-entropy blob neither crashes nor hangs, and is
    flagged as suspicious so the caller can audit it (no silent pass).
  - Bounds (MAX_INPUT_CHARS, MAX_DECODE_PASSES) hold.

Covers: yashigani.pii.decode + PiiDetector.detect_decoded/process_decoded +
SensitivityClassifier.classify_decoded.
"""
from __future__ import annotations

import base64

import pytest

from yashigani.pii import decode as decode_mod
from yashigani.pii.decode import decode_views, DecodeResult
from yashigani.pii.detector import PiiDetector, PiiMode, PiiType
from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)

# Deterministic, high-entropy, NON-UTF8-decodable bytes (an LCG sequence over the
# full byte range).  Used instead of os.urandom so the "undecodable high-entropy
# blob" assertions are stable across runs (no flakiness).  base64 of these bytes
# has entropy >4.0 bits/char and decodes to invalid UTF-8 → always suspicious.
HIGH_ENTROPY_BLOB = base64.b64encode(
    bytes((i * 37 + 11) % 256 for i in range(48))
).decode()

SSN = "123-45-6789"
SSN_TEXT = f"My SSN is {SSN}"
CC = "4111 1111 1111 1111"  # valid Luhn Visa test number
CC_TEXT = f"card {CC}"


def _regex_only_classifier() -> SensitivityClassifier:
    """Layer-1-only classifier (no sklearn/ollama) for deterministic tests."""
    return SensitivityClassifier(enable_sklearn=False, enable_ollama=False)


# ---------------------------------------------------------------------------
# decode_views — codec coverage
# ---------------------------------------------------------------------------

class TestDecodeViews:
    def test_raw_view_always_present(self):
        r = decode_views("plain text")
        assert r.views[0].view_name == "raw"
        assert r.views[0].text == "plain text"

    def test_empty_input(self):
        r = decode_views("")
        assert len(r.views) == 1
        assert r.views[0].view_name == "raw"
        assert r.suspicious_blob is False

    def test_base64_std_decoded(self):
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        r = decode_views(f"remember: {enc}")
        decoded_texts = [v.text for v in r.views if v.view_name == "base64"]
        assert any(SSN in t for t in decoded_texts)

    def test_base64_urlsafe_decoded(self):
        enc = base64.urlsafe_b64encode(SSN_TEXT.encode()).decode().rstrip("=")
        r = decode_views(f"token {enc}")
        views = {v.view_name for v in r.views}
        # urlsafe alphabet may also satisfy std b64 when no -/_ present; accept either.
        assert "base64url" in views or "base64" in views
        assert any(SSN in v.text for v in r.views if v.view_name != "raw")

    def test_hex_decoded(self):
        hx = SSN_TEXT.encode().hex()
        r = decode_views(f"data {hx}")
        decoded = [v.text for v in r.views if v.view_name == "hex"]
        assert any(SSN in t for t in decoded)

    def test_url_decoded(self):
        # percent-encode the SSN text
        enc = "My%20SSN%20is%20123-45-6789"
        r = decode_views(enc)
        decoded = [v.text for v in r.views if v.view_name == "url"]
        assert any(SSN in t for t in decoded)

    def test_rot13_decoded(self):
        import codecs
        enc = codecs.encode("secret password leak", "rot_13")
        r = decode_views(enc)
        assert any(v.view_name == "rot13" for v in r.views)

    def test_nested_base64_within_max_passes(self):
        inner = base64.b64encode(SSN_TEXT.encode()).decode()
        outer = base64.b64encode(inner.encode()).decode()
        r = decode_views(f"x {outer}")
        # double-base64 should reach the SSN within MAX_DECODE_PASSES.
        assert any(SSN in v.text for v in r.views)

    def test_clean_text_no_suspicious(self):
        r = decode_views("how is the weather in London today")
        assert r.suspicious_blob is False
        assert r.high_entropy is False


# ---------------------------------------------------------------------------
# DoS / robustness bounds
# ---------------------------------------------------------------------------

class TestBounds:
    def test_huge_input_not_decoded_but_flagged(self):
        big = "A" * (decode_mod.MAX_INPUT_CHARS + 10)
        r = decode_views(big)
        assert r.oversize is True
        assert r.suspicious_blob is True
        # Only the raw view — no decode work attempted on oversize input.
        assert len(r.views) == 1

    def test_high_entropy_undecodable_blob_flagged(self):
        blob = HIGH_ENTROPY_BLOB
        r = decode_views(f"payload {blob}")
        assert r.suspicious_blob is True
        assert r.high_entropy is True
        assert r.flagged_tokens  # masked, not raw
        assert all("..." in t or t.startswith("****") for t in r.flagged_tokens)

    def test_non_decodable_garbage_does_not_crash(self):
        # Mixed garbage that matches no codec shape cleanly.
        r = decode_views("!!!@@@###$$$%%%^^^&&&***((()))")
        assert isinstance(r, DecodeResult)
        assert r.views[0].view_name == "raw"

    def test_does_not_hang_on_many_tokens(self):
        # Many candidate tokens — bounded by MAX_SEGMENTS, must return promptly.
        tokens = " ".join("QUJDREVGR0hJSktMTU5PUA==" for _ in range(500))
        r = decode_views(tokens)
        assert isinstance(r, DecodeResult)


# ---------------------------------------------------------------------------
# PiiDetector.detect_decoded — the F-RT1 detection contract
# ---------------------------------------------------------------------------

class TestDetectDecoded:
    def setup_method(self):
        self.det = PiiDetector(mode=PiiMode.LOG)

    def test_attack6_base64_ssn_now_detected(self):
        """Red-team attack #6: base64('SSN 123-45-6789')."""
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        res = self.det.detect_decoded(f"please store {enc}")
        assert res.detected is True
        assert PiiType.SSN in {f.pii_type for f in res.findings}
        assert "base64" in res.matched_views

    def test_hex_credit_card_detected(self):
        hx = CC_TEXT.encode().hex()
        res = self.det.detect_decoded(f"value {hx}")
        assert res.detected is True
        assert PiiType.CREDIT_CARD in {f.pii_type for f in res.findings}
        assert "hex" in res.matched_views

    def test_url_encoded_ssn_detected(self):
        res = self.det.detect_decoded("My%20SSN%20is%20123-45-6789")
        assert res.detected is True
        assert "url" in res.matched_views

    def test_findings_carry_view(self):
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        res = self.det.detect_decoded(enc)
        assert all(hasattr(f, "view") for f in res.findings)
        assert any(f.view == "base64" for f in res.findings)

    def test_plaintext_ssn_still_detected_view_raw(self):
        res = self.det.detect_decoded(SSN_TEXT)
        assert res.detected is True
        assert "raw" in res.matched_views

    def test_clean_text_not_detected(self):
        res = self.det.detect_decoded("the quick brown fox jumps")
        assert res.detected is False
        assert res.suspicious_blob is False

    def test_undecodable_blob_sets_suspicious_without_pii(self):
        blob = HIGH_ENTROPY_BLOB
        res = self.det.detect_decoded(f"here {blob}")
        assert res.detected is False
        assert res.suspicious_blob is True  # silent-pass guard
        assert res.suspicious_tokens


# ---------------------------------------------------------------------------
# PiiDetector.process_decoded — mode-aware dispatch
# ---------------------------------------------------------------------------

class TestProcessDecoded:
    def test_log_mode_returns_original_text(self):
        det = PiiDetector(mode=PiiMode.LOG)
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        text_in = f"x {enc}"
        out, res = det.process_decoded(text_in)
        assert out == text_in
        assert res.action_taken == "logged"
        assert res.detected is True

    def test_block_mode_sets_blocked(self):
        det = PiiDetector(mode=PiiMode.BLOCK)
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        out, res = det.process_decoded(enc)
        assert res.action_taken == "blocked"
        assert res.detected is True

    def test_redact_raw_pii_redacted_in_place(self):
        det = PiiDetector(mode=PiiMode.REDACT)
        out, res = det.process_decoded(SSN_TEXT)
        assert "[REDACTED:SSN]" in out
        assert res.action_taken == "redacted"

    def test_redact_encoded_only_escalates_to_blocked(self):
        """An encoded SSN cannot be redacted in place — escalate to blocked."""
        det = PiiDetector(mode=PiiMode.REDACT)
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        out, res = det.process_decoded(f"keep {enc}")
        assert res.detected is True
        assert res.action_taken == "blocked"


# ---------------------------------------------------------------------------
# SensitivityClassifier.classify_decoded — feeds the OPA sensitivity input
# ---------------------------------------------------------------------------

class TestClassifyDecoded:
    def test_base64_ssn_elevates_sensitivity(self):
        sc = _regex_only_classifier()
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        res = sc.classify_decoded(f"note {enc}")
        # R14/R15 (v2.25.5): SSN regex maps to RESTRICTED (level 4).
        assert res.level == SensitivityLevel.RESTRICTED

    def test_hex_credit_card_elevates_to_sensitive(self):
        sc = _regex_only_classifier()
        hx = CC_TEXT.encode().hex()
        res = sc.classify_decoded(f"data {hx}")
        # R14/R15 (v2.25.5): credit-card regex maps to SENSITIVE (level 5).
        assert res.level == SensitivityLevel.SENSITIVE
        assert res.level >= SensitivityLevel.RESTRICTED

    def test_plaintext_unchanged_behaviour(self):
        sc = _regex_only_classifier()
        res = sc.classify_decoded(SSN_TEXT)
        # R14/R15 (v2.25.5): SSN maps to RESTRICTED (level 4).
        assert res.level == SensitivityLevel.RESTRICTED

    def test_clean_text_no_match(self):
        sc = _regex_only_classifier()
        res = sc.classify_decoded("good morning everyone")
        # R14/R15 (v2.25.5): no patterns matched → PUBLIC (level 1, lowest).
        assert res.level == SensitivityLevel.PUBLIC

    def test_undecodable_blob_floors_at_confidential(self):
        sc = _regex_only_classifier()
        blob = HIGH_ENTROPY_BLOB
        res = sc.classify_decoded(f"payload {blob}")
        assert res.level.rank >= SensitivityLevel.CONFIDENTIAL.rank
        assert "decode:suspicious-blob" in res.triggers

    def test_decoded_trigger_tagged_with_view(self):
        sc = _regex_only_classifier()
        enc = base64.b64encode(SSN_TEXT.encode()).decode()
        res = sc.classify_decoded(enc)
        assert any(t.startswith("base64:") for t in res.triggers)


# ---------------------------------------------------------------------------
# Red-team table — the 7 cases (encoded variants of attack #6 family)
# ---------------------------------------------------------------------------

class TestRedTeamCases:
    @pytest.mark.parametrize(
        "encoder",
        [
            lambda s: base64.b64encode(s.encode()).decode(),                       # #6 base64
            lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="),   # urlsafe b64
            lambda s: s.encode().hex(),                                            # hex
        ],
    )
    def test_encoded_ssn_detected(self, encoder):
        det = PiiDetector(mode=PiiMode.LOG)
        res = det.detect_decoded(f"context {encoder(SSN_TEXT)}")
        assert res.detected is True
        assert PiiType.SSN in {f.pii_type for f in res.findings}

    def test_plain_ssn_baseline_still_works(self):
        det = PiiDetector(mode=PiiMode.LOG)
        res = det.detect_decoded(SSN_TEXT)
        assert res.detected is True

    def test_no_pii_no_event(self):
        det = PiiDetector(mode=PiiMode.LOG)
        res = det.detect_decoded("just a normal question about cooking")
        assert res.detected is False
        assert res.suspicious_blob is False
