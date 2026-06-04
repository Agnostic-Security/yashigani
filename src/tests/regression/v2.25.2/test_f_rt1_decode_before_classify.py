"""
Regression test for F-RT1 (Medium, red-team verified 2026-05-30).

Original bug: the PII/sensitivity classifier matched literal patterns on RAW
prompt text only.  base64("SSN 123-45-6789") in a /v1/chat/completions prompt
produced NO PII_DETECTED event and was delivered 200 OK — the bypass was
invisible in every audit sink (no event emitted at all).

This test would FAIL against the pre-fix code (raw-only process()/classify())
and PASS against the decode-before-classify fix (process_decoded() /
classify_decoded()).  It pins the three load-bearing guarantees of the fix:

  1. An encoded SSN is now DETECTED (no silent pass).
  2. The encoded payload elevates the SENSITIVITY level (feeds OPA ceiling).
  3. An undecodable high-entropy blob still produces a SUSPICIOUS signal so the
     caller emits an audit event (the worst part of F-RT1 was the silent pass).

Fix-in-branch: F-RT1 surfaced in 2.25.x e2e red-team and is fixed in 2.25.2.
Relationship: sibling-but-distinct from YSG-RISK-057 (tool-description encoded
injection, v2.26 LLM-classifier sidecar) — different surface, same class.
"""
from __future__ import annotations

import base64

from yashigani.pii.detector import PiiDetector, PiiMode, PiiType
from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)

_SSN_TEXT = "patient SSN 123-45-6789 on file"

# Deterministic high-entropy, non-UTF8-decodable blob (LCG over the byte range).
# Used instead of os.urandom so the suspicious-blob assertion is stable.
_HIGH_ENTROPY_BLOB = base64.b64encode(
    bytes((i * 37 + 11) % 256 for i in range(48))
).decode()


def test_f_rt1_base64_ssn_no_longer_silent():
    """Attack #6: base64('...SSN 123-45-6789...') must now be detected."""
    det = PiiDetector(mode=PiiMode.LOG)
    enc = base64.b64encode(_SSN_TEXT.encode()).decode()

    # Pre-fix: process() on the raw blob => detected=False (silent pass).
    raw_only = det.detect(enc)
    assert raw_only.detected is False, "sanity: raw-only scan misses the encoded SSN"

    # Post-fix: detect_decoded() catches it via the base64 view.
    decoded = det.detect_decoded(enc)
    assert decoded.detected is True
    assert PiiType.SSN in {f.pii_type for f in decoded.findings}
    assert "base64" in decoded.matched_views


def test_f_rt1_encoded_payload_elevates_sensitivity():
    """The encoded SSN must elevate sensitivity so OPA's ceiling can act."""
    sc = SensitivityClassifier(enable_sklearn=False, enable_ollama=False)
    enc = base64.b64encode(_SSN_TEXT.encode()).decode()

    # Pre-fix behaviour: classify() on the raw blob => PUBLIC.
    assert sc.classify(enc).level == SensitivityLevel.PUBLIC

    # Post-fix: classify_decoded() sees the SSN => CONFIDENTIAL.
    assert sc.classify_decoded(enc).level == SensitivityLevel.CONFIDENTIAL


def test_f_rt1_undecodable_blob_is_not_a_silent_pass():
    """A high-entropy encoded blob with no plaintext PII must still be flagged."""
    det = PiiDetector(mode=PiiMode.LOG)
    blob = _HIGH_ENTROPY_BLOB
    res = det.detect_decoded(f"exfil {blob}")
    # No plaintext PII, but the suspicious-blob signal forces an audit.
    assert res.detected is False
    assert res.suspicious_blob is True
    assert res.suspicious_tokens


def test_f_rt1_non_encoded_traffic_unchanged():
    """Non-encoded text must behave exactly as before the fix."""
    det = PiiDetector(mode=PiiMode.LOG)
    assert det.detect_decoded("how do I bake bread").detected is False
    assert det.detect_decoded(_SSN_TEXT).detected is True
