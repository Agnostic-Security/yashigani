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
    i = src.find("_OPENAI_TOP_STRUCTURAL")
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
    out = _load()(_envelope("Hello there", cid), "llm")
    assert cid not in out, f"correlation id {cid} still reaches the inspector"
    assert "1785974400" not in out, "created timestamp still reaches the inspector"
    assert "Hello there" in out, "message content was dropped — inspection would be blind"


def test_a_real_secret_in_content_is_still_inspected():
    """The control must not be weakened: a genuine key in message content
    still reaches the detector."""
    out = _load()(_envelope("my key is AKIAIOSFODNN7EXAMPLE plus sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAABBBB"), "llm")
    assert "AKIAIOSFODNN7EXAMPLE" in out
    assert "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAABBBB" in out


def test_unrecognised_shape_is_inspected_whole_fail_closed():
    """Anything not envelope-shaped must be scanned in full, never less."""
    f = _load()
    assert f("not json at all", "llm") == "not json at all"
    assert f("", "llm") == ""
    assert "AKIAIOSFODNN7EXAMPLE" in f(json.dumps(["AKIAIOSFODNN7EXAMPLE"]), "llm")


# ---------------------------------------------------------------------------
# Bypass regressions — added 2026-08-07 after the pre-push review BLOCKED the
# first version of this fix.
#
# The first `_inspectable_payload()` excluded a set of key NAMES at ANY depth,
# for EVERY egress prefix. Both reviewers independently produced the same
# bypass class: a secret nested under a key literally named `id`/`model`/`type`
# skipped the DLP scan while the untouched original body was still forwarded
# verbatim on ALLOW — a silent, deterministic false-NEGATIVE traded for a noisy
# false-positive. These pin every shape they demonstrated.
# ---------------------------------------------------------------------------

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _envelope_with(extra: dict) -> str:
    base = {
        "id": _FP_ID,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
    }
    base.update(extra)
    return json.dumps(base)


@pytest.mark.parametrize("label,body", [
    ("nested id",
     _envelope_with({"metadata": {"id": _SECRET}})),
    ("nested model inside tool-call arguments",
     json.dumps({"id": _FP_ID, "choices": [{"index": 0, "message": {
         "role": "assistant",
         "tool_calls": [{"function": {"arguments": {"model": _SECRET}}}]}}]})),
    ("nested type in an Anthropic-style content block",
     json.dumps({"id": _FP_ID, "choices": [{"index": 0, "message": {
         "role": "assistant", "content": [{"type": _SECRET}]}}]})),
])
def test_secret_nested_under_a_structural_key_name_is_still_scanned(label, body):
    """A key NAME collision must not exempt content from the DLP scan."""
    out = _load()(body, "llm")
    assert _SECRET in out, f"DLP bypass via {label}: secret never reached the scanner"


@pytest.mark.parametrize("prefix", ["slack", "slack-hooks", "telegram", "", "unknown"])
def test_non_llm_prefixes_are_scanned_verbatim(prefix):
    """Stripping is scoped to the `llm` self-call class. Every genuinely
    external destination is inspected exactly as it was before this change."""
    body = _envelope_with({"metadata": {"id": _SECRET}})
    assert _load()(body, prefix) == body


def test_non_openai_shape_on_llm_prefix_is_scanned_whole():
    """Fail-closed: no `choices` array -> not a recognised envelope -> full scan."""
    body = json.dumps({"id": _FP_ID, "payload": {"id": _SECRET}})
    assert _load()(body, "llm") == body
