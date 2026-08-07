"""YSG-RISK-200 regression — egress inspector must scan CONTENT, not the envelope.

The bug: `scan_secrets()` was handed the whole transport envelope, and
`entropy_blob` fired on the random `chatcmpl-<hex>` correlation id every
OpenAI-compatible response carries. Measured FP rate on synthetic ids: 10.2% at
12 hex, 30.8% at 17, 79.8% at uuid length -> a per-request coin flip that denied
the agent's own LLM call with `pii_detected_in_result` and surfaced as
502 agent_unreachable. It read as flaky networking for three campaigns.

These tests PIN the ids rather than generating them -- a generated id reproduces
the bug only 10-80% of the time, which is precisely how it survived so long.
"""
from __future__ import annotations

import json

import pytest

_SRC = "src/yashigani/gateway/egress_proxy.py"


def _load():
    """Load the helper without importing the gateway package (which requires a
    live internal-bearer secret at import time)."""
    src = open(_SRC).read()
    i = src.find("_ENVELOPE_STRUCTURAL_KEYS")
    j = src.find("@router.api_route", i)
    ns: dict = {}
    exec(src[i:j], ns)  # noqa: S102 - test-only, reads our own source
    return ns["_inspectable_payload"]


# Ids PINNED from the live failure, not generated.
_FP_ID = "chatcmpl-720ba6e310e9"          # entropy 4.011 -> was flagged
_FP_ID_LONG = "chatcmpl-52c053b4817248929"  # entropy 4.027 -> was flagged
_CLEAN_ID = "chatcmpl-fcb443233c9e"        # same length as _FP_ID, was NOT flagged


def _envelope(content: str, cid: str = _FP_ID) -> str:
    return json.dumps({
        "id": cid, "object": "chat.completion", "created": 1785974400,
        "model": "qwen2.5:3b",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 27, "completion_tokens": 3, "total_tokens": 30},
    })


@pytest.mark.parametrize("cid", [_FP_ID, _FP_ID_LONG, _CLEAN_ID])
def test_envelope_identifiers_are_not_inspected(cid):
    """The correlation id must never reach the secret detector."""
    out = _load()(_envelope("Hello there", cid))
    assert cid not in out, f"correlation id {cid} still reaches the inspector"
    assert "1785974400" not in out, "created timestamp still reaches the inspector"
    assert "Hello there" in out, "message content was dropped — inspection would be blind"


def test_a_real_secret_in_content_is_still_inspected():
    """The control must not be weakened: a genuine key in message content
    still reaches the detector."""
    out = _load()(_envelope("my key is AKIAIOSFODNN7EXAMPLE plus sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAABBBB"))
    assert "AKIAIOSFODNN7EXAMPLE" in out
    assert "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAABBBB" in out


def test_unrecognised_shape_is_inspected_whole_fail_closed():
    """Anything not envelope-shaped must be scanned in full, never less."""
    f = _load()
    assert f("not json at all") == "not json at all"
    assert f("") == ""
    assert "AKIAIOSFODNN7EXAMPLE" in f(json.dumps(["AKIAIOSFODNN7EXAMPLE"]))
