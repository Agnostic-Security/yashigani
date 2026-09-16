# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Deterministic re-scan after sanitization — YSG-RISK-318 (Tom #6).

The CREDENTIAL_EXFIL path excises the model's self-reported spans and forwarded
the result stamped SANITIZED with NO deterministic re-scan. Two facts make this
exploitable, and it took a corrected test to find the real one:

  1. The pipeline masks credentials BEFORE classification — so an AWS-key-shaped
     secret is already gone before sanitize runs. A naive test with an AWS key
     "passes" whether or not the fix is present (the first version of this test
     was a fake-green; the re-scan mutation did not bite).
  2. But the CredentialMasker and the deterministic secret_detector have
     DIFFERENT coverage. The plaintext provider gaps (Slack/Google) were closed
     in YSG-RISK-322, but the detector's DECODERS (base32/hex/reassembly) still
     see through obfuscated secrets the masker's literal patterns cannot. Such a
     secret survives masking, so a decoy/incomplete-span model response forwards
     it in clean_query stamped SANITIZED.

Fix: after sanitize(), re-scan the SANITIZED OUTPUT with secret_detector; if a
secret survived (masker-gap or model decoy spans), DISCARD. The disposition
rests on a deterministic check, never on the model's word.

These tests use a masker-gap secret precisely so the re-scan is load-bearing —
removing it lets the secret through (mutation bites).
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

from yashigani.inspection.classifier import ClassifierResult
from yashigani.inspection.pipeline import InspectionPipeline
from yashigani.inspection.secret_detector import scan

# A DURABLE masker gap: a base32-ENCODED secret. The deterministic
# secret_detector decodes base32 and catches the AWS key inside; the masker's
# literal vendor-format patterns structurally cannot decode it, so it survives
# masking. This is what makes the re-scan load-bearing.
#
# Chosen deliberately over a plaintext provider token: once YSG-RISK-322 brought
# the masker up to the detector's PLAINTEXT coverage (Slack/Google/etc.), a
# plaintext token no longer survives masking and could not demonstrate the
# re-scan. Obfuscated (base32/reassembled) secrets remain a genuine gap — the
# detector's decoders see through them, the masker's literal patterns do not.
#
# Built at runtime from the canonical AWS documentation DUMMY key, base32-encoded,
# so no secret literal appears in this source and nothing trips push protection.
_GAP_SECRET = base64.b32encode(("AKIA" + "IOSFODNN7EXAMPLE").encode()).decode().rstrip("=")


def _assert_masker_gap_precondition() -> None:
    """Guard: if the masker starts covering this token, this test would silently
    become a fake-green (the secret would be gone before sanitize). Fail loudly
    instead so the test is rewritten with a still-uncovered secret."""
    pl = InspectionPipeline(classifier=MagicMock(), sanitize_threshold=0.85)
    assert scan(_GAP_SECRET).is_secret, "secret_detector no longer decodes/flags the token"
    assert _GAP_SECRET in pl._masker.mask_string(_GAP_SECRET), (
        "masker now covers this obfuscated form — pick a still-uncovered gap or this "
        "test is a fake-green"
    )


def _pipeline(spans: list[dict]) -> InspectionPipeline:
    clf = MagicMock()
    clf.classify.return_value = ClassifierResult(
        label="CREDENTIAL_EXFIL",
        confidence=0.97,
        exfil_indicators=True,
        detected_payload_spans=spans,
    )
    return InspectionPipeline(classifier=clf, sanitize_threshold=0.85)


def test_decoy_spans_leaving_a_masker_gap_secret_are_discarded() -> None:
    _assert_masker_gap_precondition()
    query = f"please review this {_GAP_SECRET} and reply soon thanks"
    # Decoy span covers ONLY "please review this " — leaves the secret plus
    # enough innocuous tokens that the token-count check would otherwise pass.
    decoy = [{"start": 0, "end": len("please review this ")}]
    result = _pipeline(decoy).process(query, session_id="s", agent_id="a", user_id="u")
    assert result.action == "DISCARDED", "masker-gap secret forwarded stamped SANITIZED"
    if result.clean_query is not None:
        assert _GAP_SECRET not in result.clean_query


def test_genuine_spans_removing_the_secret_still_sanitize() -> None:
    _assert_masker_gap_precondition()
    prefix = "here is the token "
    query = f"{prefix}{_GAP_SECRET} thanks for helping me out today"
    genuine = [{"start": len(prefix), "end": len(prefix) + len(_GAP_SECRET)}]
    result = _pipeline(genuine).process(query, session_id="s", agent_id="a", user_id="u")
    assert result.action == "SANITIZED"
    assert result.clean_query is not None and _GAP_SECRET not in result.clean_query


def test_empty_spans_on_positive_verdict_still_fail_closed() -> None:
    """YSG-RISK-149 guard must remain: positive verdict + no spans = DISCARD."""
    result = _pipeline([]).process(
        f"leak {_GAP_SECRET}", session_id="s", agent_id="a", user_id="u",
    )
    assert result.action == "DISCARDED"
