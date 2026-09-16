# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""secret_detector sees codepoint-smuggled secrets — YSG-RISK-319 egress parity.

The 319 ingress fix decoded codepoint smuggling in the content filter, but the
EGRESS leg (ResponseInspectionPipeline) has no suspicion gate and no filter
decode-prepass — it relies on the LLM classifier (blind to smuggling) and
`secret_detector.scan`. Measured: scan() did NOT decode tag/VS/PUA codepoints, so
an agent could exfiltrate a secret in a response by smuggling it in those
codepoints ("both legs" parity gap).

Note it also cannot be fixed with normalize_for_detection: that path's LEET step
mangles secret tokens (a '7' in an AWS key becomes a letter). The secret view
decodes + NFKC + folds confusables + strips zero-width, but NOT leet.

Fix: a `codepoint_decode` view in scan(), using the SAME decoder as the content
filter so the ranges cannot diverge between the two detectors.
"""

from __future__ import annotations

import pytest

from yashigani.inspection.secret_detector import scan

# Assembled from the canonical AWS docs DUMMY key so no secret literal is in
# source (push-protection safe); split so the plaintext literal never appears.
_SECRET = "AKIA" + "IOSFODNN7EXAMPLE"


def _tag(t: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) if 0x20 <= ord(c) < 0x7F else c for c in t)


def _supp_vs(t: str) -> str:
    return "".join(chr(0xE0100 + ord(c)) if ord(c) < 0x80 else c for c in t)


def _pua(t: str) -> str:
    return "".join(chr(0xF0000 + ord(c)) if ord(c) < 0x80 else c for c in t)


def test_plaintext_secret_still_detected() -> None:
    assert scan(_SECRET).is_secret


@pytest.mark.parametrize("enc", [_tag, _supp_vs, _pua], ids=["tag", "supp-vs", "pua"])
def test_codepoint_smuggled_secret_is_detected(enc) -> None:
    v = scan(enc(_SECRET))
    assert v.is_secret, "codepoint-smuggled secret slipped past egress scanning"
    assert "codepoint_decode" in v.views_hit


@pytest.mark.parametrize(
    "text",
    [
        "Great work team, shipping today!",
        "Here is the summary you asked for done",
        "I love this ❤️ thanks for the help ☀️",
        "Meeting notes: Q3 revenue up 12 percent, hiring two engineers.",
    ],
)
def test_legitimate_response_text_is_not_a_false_positive(text: str) -> None:
    assert not scan(text).is_secret, f"false positive on: {text!r}"


def test_smuggled_secret_survives_a_surrounding_response() -> None:
    """Realistic egress shape: the smuggled key embedded in a normal reply."""
    reply = f"Sure, here is the config value you wanted: {_tag(_SECRET)} — let me know."
    assert scan(reply).is_secret
