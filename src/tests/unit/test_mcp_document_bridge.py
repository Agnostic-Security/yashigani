"""
RESTART-013 gap #1 — documents/mcp_document_bridge.py unit tests.

Mode: DETERMINISTIC GATE, fully mocked egress_decide()/pipeline (isolates the
payload-walking + candidate-detection + block/transform-propagation seam under
test from the engine mechanics already covered elsewhere).

Coverage:
  MDB-01  a base64 document blob nested anywhere in an arbitrary JSON payload
          is found and enforced (payload-schema-agnostic — no hardcoded field
          name, proven with a field name the mirror-mcp tool does NOT use)
  MDB-02  a short / non-base64 / non-document string is left untouched (no
          OPA call at all — proven via a call counter)
  MDB-03  REDACT: the candidate's value is rewritten in place with the
          transformed base64
  MDB-04  BLOCK on ANY candidate blocks the WHOLE payload — no partial-allow
  MDB-05  multiple candidates: all are found (candidate_count), only the
          document-shaped ones are enforced
  MDB-06  an unexpected exception in egress_decide degrades to fail-closed
          BLOCK for the whole call (never silently forwards)
  MDB-07  candidate cap (_MAX_CANDIDATES_PER_CALL) bounds the work done

Author: Tom. Last updated: 2026-07-20.
"""
from __future__ import annotations

import base64

import pytest

from yashigani.documents import mcp_document_bridge as bridge
from yashigani.documents.proxy_modeb import EgressOutcome


class _FakePipeline:
    """Never actually reached — egress_decide is monkeypatched directly in
    every test below, so this is just a type-shaped placeholder."""


def _txt_bytes(marker: str = "hello world, this is a plain text document\n") -> bytes:
    # Padded so the base64 form clears _MIN_CANDIDATE_LEN even for short markers.
    return (marker + ("padding " * 4)).encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@pytest.mark.asyncio
async def test_mdb_01_finds_document_blob_at_arbitrary_field_name(monkeypatch):
    """No hardcoded field name — 'weird_custom_field_name' is not anything
    the mirror-mcp tool or any built-in schema uses."""
    calls: list = []

    async def _fake_egress_decide(pipeline, *, opa_url, body, content_type, request_id, **kw):
        calls.append(body)
        return EgressOutcome(action="LOG")

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {"weird_custom_field_name": _b64(_txt_bytes()), "other": "x"}
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r1",
    )
    assert outcome.candidate_count == 1
    assert calls and calls[0] == _txt_bytes()
    assert not outcome.blocked


@pytest.mark.asyncio
async def test_mdb_02_short_non_document_string_never_calls_opa(monkeypatch):
    calls: list = []

    async def _fake_egress_decide(*a, **k):
        calls.append(1)
        return EgressOutcome(action="LOG")

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {
        "filename": "salary.txt",           # short, not base64-document-shaped
        "session_token": "abc123-def456-token-not-a-document-blob-at-all-1234",
        "count": "42",
    }
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r2",
    )
    assert outcome.candidate_count == 0
    assert not calls
    assert not outcome.blocked


@pytest.mark.asyncio
async def test_mdb_03_redact_rewrites_value_in_place(monkeypatch):
    redacted = b"hello [REDACTED], this is a plain text document\n"

    async def _fake_egress_decide(pipeline, *, opa_url, body, content_type, request_id, **kw):
        return EgressOutcome(action="REDACT", transformed=True, forward_bytes=redacted)

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {"content_b64": _b64(_txt_bytes())}
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r3",
    )
    assert outcome.transformed
    assert base64.b64decode(payload["content_b64"]) == redacted


@pytest.mark.asyncio
async def test_mdb_04_block_on_any_candidate_blocks_whole_payload(monkeypatch):
    seen_bodies: list = []

    async def _fake_egress_decide(pipeline, *, opa_url, body, content_type, request_id, **kw):
        seen_bodies.append(body)
        if len(seen_bodies) == 1:
            return EgressOutcome(action="LOG")
        return EgressOutcome(action="BLOCK", blocked=True, block_reason="unpoliced_sensitive_class")

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {
        "a": _b64(_txt_bytes("first document content here padded out\n")),
        "b": _b64(_txt_bytes("second document content here padded too\n")),
    }
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r4",
    )
    assert outcome.blocked is True
    assert outcome.block_reason == "unpoliced_sensitive_class"
    # The whole call is denied — the caller must not forward candidate "a"
    # just because it individually cleared before "b" blocked.


@pytest.mark.asyncio
async def test_mdb_05_multiple_candidates_all_found(monkeypatch):
    async def _fake_egress_decide(pipeline, *, opa_url, body, content_type, request_id, **kw):
        return EgressOutcome(action="LOG")

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {
        "files": [
            {"content": _b64(_txt_bytes("doc one padded content here\n"))},
            {"content": _b64(_txt_bytes("doc two padded content here\n"))},
        ],
        "note": "short",
    }
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r5",
    )
    assert outcome.candidate_count == 2
    assert not outcome.blocked


@pytest.mark.asyncio
async def test_mdb_06_unexpected_exception_fails_closed(monkeypatch):
    async def _boom(*a, **k):
        raise RuntimeError("opa unreachable in a way egress_decide itself didn't catch")

    monkeypatch.setattr(bridge, "egress_decide", _boom)
    payload = {"content_b64": _b64(_txt_bytes())}
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r6",
    )
    assert outcome.blocked is True
    assert outcome.block_reason == "mcp_document_enforcement_error"


@pytest.mark.asyncio
async def test_mdb_07_candidate_cap_bounds_work(monkeypatch):
    calls: list = []

    async def _fake_egress_decide(pipeline, *, opa_url, body, content_type, request_id, **kw):
        calls.append(1)
        return EgressOutcome(action="LOG")

    monkeypatch.setattr(bridge, "egress_decide", _fake_egress_decide)
    payload = {
        f"field_{i}": _b64(_txt_bytes(f"document number {i} padded content here\n"))
        for i in range(40)
    }
    outcome = await bridge.enforce_mcp_document_payload(
        _FakePipeline(), opa_url="https://policy:8181", payload=payload, request_id="r7",
    )
    assert outcome.candidate_count <= bridge._MAX_CANDIDATES_PER_CALL
    assert len(calls) <= bridge._MAX_CANDIDATES_PER_CALL


def test_candidate_document_bytes_rejects_plain_short_uuid():
    assert bridge.candidate_document_bytes("not-base64-!!!-short") is None


def test_candidate_document_bytes_rejects_non_document_base64_blob():
    # Valid base64, long enough, but decodes to random-looking binary that
    # does not sniff to any committed document format.
    import os
    blob = base64.b64encode(os.urandom(64)).decode("ascii")
    assert bridge.candidate_document_bytes(blob) is None


def test_candidate_document_bytes_accepts_real_document():
    data = _txt_bytes()
    decoded = bridge.candidate_document_bytes(_b64(data))
    assert decoded == data
