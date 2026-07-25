"""
RESTART-013 gap #1 — MCP tool-call traffic wired into document enforcement.

Before this fix: gateway/proxy.py dispatched /mcp/<agent_name> at step 4c and
RETURNED before step 4d (the only document_pipeline call site);
gateway/mcp_router_runtime.py had ZERO references to
DocumentInspectionPipeline. A file inside an MCP tool-call argument, or a file
an MCP tool returned in its result, was never inspected.

Mode: DETERMINISTIC GATE. FastAPI TestClient over create_mcp_call_router(),
McpHttpTransport.forward mocked (no live MCP upstream needed),
documents.mcp_document_bridge.enforce_mcp_document_payload mocked (isolates
the WIRING under test — the bridge's own logic is covered by
test_mcp_document_bridge.py).

Coverage:
  GAP1-01  document_pipeline=None (default/dark) → the bridge is never even
           called — zero behaviour change for every pre-existing MCP test.
  GAP1-02  OUTBOUND BLOCK: a document in tool-call arguments blocks the WHOLE
           call BEFORE it reaches the upstream MCP server (transport.forward
           never called) — 403 MCP_DOCUMENT_BLOCKED.
  GAP1-03  OUTBOUND TRANSFORM: a REDACT/PSEUDONYMIZE decision on tool-call
           arguments rewrites the actual JSON-RPC body forwarded upstream —
           the raw document never reaches the upstream MCP server.
  GAP1-04  INBOUND BLOCK: a document in the tool's RESULT blocks delivery to
           the caller (upstream WAS called; the raw result is withheld).
  GAP1-05  INBOUND TRANSFORM: a REDACT/PSEUDONYMIZE decision on the tool's
           result rewrites what is actually delivered to the caller.
  GAP1-06  An unexpected exception in the document bridge fails closed (403),
           never silently forwards.

Author: Tom. Last updated: 2026-07-20.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.documents.mcp_document_bridge import McpDocumentOutcome


# ---------------------------------------------------------------------------
# Helpers (mirrors test_gorchopa1_ceiling_lookup.py's factories)
# ---------------------------------------------------------------------------

def _make_jsonrpc_request(method: str, params=None, req_id="1") -> str:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _make_broker_with_egress(egress_allow: bool = True):
    from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

    broker = MagicMock()
    opa_dec = OpaDecision(
        allow=True, deny_reason="ok", redact_args=set(),
        audit_capture=False, rate_limit_key=None,
    )
    ingress_decision = BrokerDecision(
        call_id="test-call-id", allow=True, deny_reason="ok",
        opa_decision=opa_dec, issued_jwt="test-jwt",
    )
    broker.enforce = AsyncMock(return_value=ingress_decision)
    broker.enforce_result = AsyncMock(return_value=EgressDecision(
        allow=egress_allow,
        deny_reason="ok" if egress_allow else "blocked",
        policy_id="mcp.response_decision",
        code="MCP_RESULT_OK",
        user_message="ok",
        elapsed_ms=1,
    ))
    broker._issuer = MagicMock()
    broker._issuer.issue = MagicMock(return_value="session-jwt-value")
    return broker


def _make_registry_with_egress(agent_name: str = "filesystem-mcp", egress_allow: bool = True):
    from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

    reg = McpBrokerRegistry()
    broker = _make_broker_with_egress(egress_allow=egress_allow)
    cfg = McpBrokerServerConfig(
        upstream_url="http://fs-mcp:8000", is_filesystem_agent=True,
        tenant_id="acme", agent_name=agent_name,
    )
    reg.register(agent_name, broker, cfg)
    return reg, broker


def _fake_upstream_response(tool_result: str = "file content") -> str:
    return json.dumps({
        "jsonrpc": "2.0", "id": "t1",
        "result": {"content": [{"type": "text", "text": tool_result}]},
    })


def _patch_transport_forward(fake_response: str):
    """Context manager: patch McpHttpTransport.forward, capturing every call's
    mcp_request_json so outbound-transform assertions can inspect it."""
    from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

    captured_calls: list = []

    async def fake_aenter(self):
        async def _forward(mcp_request_json, gateway_jwt):
            captured_calls.append(mcp_request_json)
            return fake_response
        self.forward = _forward
        return self

    async def fake_aexit(self, *a):
        pass

    return (
        patch.object(RealTransport, "__aenter__", fake_aenter),
        patch.object(RealTransport, "__aexit__", fake_aexit),
        captured_calls,
    )


def _build_app(broker_registry, *, document_pipeline=None, opa_url=""):
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
    app = FastAPI()
    app.include_router(
        create_mcp_call_router(
            broker_registry, document_pipeline=document_pipeline, opa_url=opa_url,
        )
    )
    return app


# ---------------------------------------------------------------------------
# GAP1-01 — document_pipeline=None: zero behaviour change
# ---------------------------------------------------------------------------

def test_gap1_01_no_pipeline_bridge_never_called(monkeypatch):
    bridge_calls: list = []

    async def _spy(*a, **k):
        bridge_calls.append(1)
        return McpDocumentOutcome()

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _spy
    )
    reg, broker = _make_registry_with_egress()
    app = _build_app(reg, document_pipeline=None)  # default / dark

    fake_resp = _fake_upstream_response("plain content")
    p1, p2, _calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "mirror", "arguments": {"content_b64": "x" * 100}}, "t1"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 200, resp.text
    assert not bridge_calls


# ---------------------------------------------------------------------------
# GAP1-02 — OUTBOUND BLOCK
# ---------------------------------------------------------------------------

def test_gap1_02_outbound_block_denies_before_upstream_call(monkeypatch):
    call_log: list = []

    async def _fake_enforce(pipeline, *, opa_url, payload, request_id, **kw):
        call_log.append(("call", payload))
        return McpDocumentOutcome(blocked=True, block_reason="document_blocked", payload=payload)

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _fake_enforce
    )
    reg, broker = _make_registry_with_egress()
    app = _build_app(reg, document_pipeline=object(), opa_url="https://policy:8181")

    fake_resp = _fake_upstream_response("should never be reached")
    p1, p2, transport_calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "mirror", "arguments": {"content_b64": "y" * 100}}, "t2"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"] == "MCP_DOCUMENT_BLOCKED"
    assert len(call_log) == 1  # outbound leg only — never reached the inbound leg
    assert not transport_calls  # upstream never called


# ---------------------------------------------------------------------------
# GAP1-03 — OUTBOUND TRANSFORM: raw document never reaches upstream
# ---------------------------------------------------------------------------

def test_gap1_03_outbound_transform_rewrites_forwarded_body(monkeypatch):
    async def _fake_enforce(pipeline, *, opa_url, payload, request_id, **kw):
        # Mutate in place exactly as the real bridge does (redact the content).
        if "content_b64" in payload:
            payload["content_b64"] = "REDACTED_BASE64=="
            return McpDocumentOutcome(transformed=True, payload=payload)
        return McpDocumentOutcome(payload=payload)

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _fake_enforce
    )
    reg, broker = _make_registry_with_egress()
    app = _build_app(reg, document_pipeline=object(), opa_url="https://policy:8181")

    fake_resp = _fake_upstream_response("mirrored back")
    p1, p2, transport_calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call",
            {"name": "mirror", "arguments": {"content_b64": "originalcleartextbytes=="}},
            "t3",
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 200, resp.text
    assert transport_calls, "expected the upstream call to have been made"
    forwarded = json.loads(transport_calls[0])
    assert forwarded["params"]["arguments"]["content_b64"] == "REDACTED_BASE64=="
    assert "originalcleartextbytes" not in transport_calls[0]


# ---------------------------------------------------------------------------
# GAP1-04 — INBOUND BLOCK: upstream WAS called; result withheld
# ---------------------------------------------------------------------------

def test_gap1_04_inbound_block_withholds_result(monkeypatch):
    call_count = {"n": 0}

    async def _fake_enforce(pipeline, *, opa_url, payload, request_id, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Outbound leg — clear.
            return McpDocumentOutcome(payload=payload)
        # Inbound leg (the tool's result) — block.
        return McpDocumentOutcome(blocked=True, block_reason="document_blocked", payload=payload)

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _fake_enforce
    )
    reg, broker = _make_registry_with_egress()
    app = _build_app(reg, document_pipeline=object(), opa_url="https://policy:8181")

    fake_resp = _fake_upstream_response("sensitive file content")
    p1, p2, transport_calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "read_file", "arguments": {"path": "/f"}}, "t4"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"] == "MCP_DOCUMENT_BLOCKED"
    assert transport_calls, "upstream WAS called for the inbound-block case"
    assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# GAP1-05 — INBOUND TRANSFORM: the delivered response reflects the transform
# ---------------------------------------------------------------------------

def test_gap1_05_inbound_transform_delivers_transformed_result(monkeypatch):
    call_count = {"n": 0}

    async def _fake_enforce(pipeline, *, opa_url, payload, request_id, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return McpDocumentOutcome(payload=payload)
        # Inbound: redact the text field of the tool's result.
        payload["result"]["content"][0]["text"] = "[REDACTED]"
        return McpDocumentOutcome(transformed=True, payload=payload)

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _fake_enforce
    )
    reg, broker = _make_registry_with_egress(egress_allow=True)
    app = _build_app(reg, document_pipeline=object(), opa_url="https://policy:8181")

    fake_resp = _fake_upstream_response("jordan.whitfield@example.com")
    p1, p2, transport_calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "read_file", "arguments": {"path": "/f"}}, "t5"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 200, resp.text
    assert "jordan.whitfield@example.com" not in resp.text
    assert "[REDACTED]" in resp.text


# ---------------------------------------------------------------------------
# GAP1-06 — unexpected bridge exception fails closed
# ---------------------------------------------------------------------------

def test_gap1_06_unexpected_bridge_exception_fails_closed(monkeypatch):
    async def _boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "yashigani.documents.mcp_document_bridge.enforce_mcp_document_payload", _boom
    )
    reg, broker = _make_registry_with_egress()
    app = _build_app(reg, document_pipeline=object(), opa_url="https://policy:8181")

    fake_resp = _fake_upstream_response("should never be reached")
    p1, p2, transport_calls = _patch_transport_forward(fake_resp)
    with p1, p2:
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "mirror", "arguments": {"content_b64": "z" * 100}}, "t6"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"] == "MCP_DOCUMENT_ENFORCEMENT_ERROR"
    assert not transport_calls
