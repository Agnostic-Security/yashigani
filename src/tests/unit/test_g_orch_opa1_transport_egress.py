"""
G-ORCH-OPA-1 — transport-layer egress wiring tests
====================================================

Tests proving that mcp_router_runtime._handle_mcp_call_inner calls
broker.enforce_result() after obtaining the upstream tool result, and that
the egress decision is correctly enforced end-to-end.

Test cases:
  C1. Result above caller ceiling → withheld (403 MCP_EGRESS_DENIED).
  C2. Allowed result → passes through (200 with upstream body unchanged).
  C3. OPA error in enforce_result → fail-closed withhold (403 OPA error code).
  C4. Inspection pipeline BLOCKED verdict → withheld before OPA (403 MCP_EGRESS_BLOCKED).
  C5. enforce_result raises unexpectedly → fail-closed withhold (403 MCP_EGRESS_ERROR).
  C6. No inspection pipeline wired → defaults to PUBLIC / pii=False; egress still runs.
  C7. enforce_result is called with correct result_sensitivity from inspection pipeline.

Mock strategy:
  - McpHttpTransport.__aenter__ is patched on the REAL class so that
    derive_posture() (called on the first McpHttpTransport instance before the
    context manager) still works (it is a pure in-memory computation).
    The patched __aenter__ injects a forward() AsyncMock returning a fixed
    upstream result — matching the pattern in test_p3_mcp_broker_wiring.py.
  - broker.enforce (ingress) → always allow.
  - broker.enforce_result (egress) → parametrised per test case.
  - ResponseInspectionPipeline.inspect → parametrised per test case.

G-ORCH-OPA-1 / 3.1 transport egress wiring.
"""
from __future__ import annotations

import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.mcp._types import (
    BrokerDecision,
    EgressDecision,
    OpaDecision,
)
from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
from yashigani.mcp._transport_http import McpHttpTransport as _RealTransport


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_UPSTREAM_RESULT = json.dumps({
    "jsonrpc": "2.0",
    "id": "1",
    "result": {"content": [{"type": "text", "text": "hello from upstream"}]},
})

_TOOLS_CALL_BODY = json.dumps({
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tools/call",
    "params": {"name": "web_search", "arguments": {"query": "test"}},
})


def _make_allow_ingress_decision(jwt: str = "test-jwt") -> BrokerDecision:
    return BrokerDecision(
        call_id="test-call",
        allow=True,
        deny_reason="ok",
        opa_decision=OpaDecision(
            allow=True,
            deny_reason="ok",
            redact_args=set(),
            audit_capture=False,
            rate_limit_key=None,
        ),
        issued_jwt=jwt,
        chain_depth=1,
        elapsed_ms=5,
    )


def _make_egress_allow() -> EgressDecision:
    return EgressDecision(
        allow=True,
        deny_reason="ok",
        policy_id="mcp.response_decision",
        code="MCP_RESULT_OK",
        user_message="Tool result approved for delivery.",
        elapsed_ms=4,
    )


def _make_egress_deny(reason: str, code: str, message: str) -> EgressDecision:
    return EgressDecision(
        allow=False,
        deny_reason=reason,
        policy_id="mcp.response_decision",
        code=code,
        user_message=message,
        elapsed_ms=4,
    )


def _make_mock_broker(
    egress_decision: Optional[EgressDecision] = None,
) -> MagicMock:
    """Build a mock broker that always allows ingress, with configurable egress."""
    broker = MagicMock()
    broker.enforce = AsyncMock(return_value=_make_allow_ingress_decision())
    broker.enforce_result = AsyncMock(
        return_value=egress_decision if egress_decision is not None else _make_egress_allow()
    )
    broker._issuer = MagicMock()
    broker._issuer.issue = MagicMock(return_value="session-jwt-value")
    return broker


def _make_clean_inspection(sensitivity: str = "PUBLIC") -> MagicMock:
    """Return a mock ResponseInspectionResult with CLEAN verdict."""
    r = MagicMock()
    r.verdict = "CLEAN"
    r.response_sensitivity = sensitivity
    r.confidence = 0.99
    r.skipped = False
    return r


def _make_blocked_inspection() -> MagicMock:
    """Return a mock ResponseInspectionResult with BLOCKED verdict."""
    r = MagicMock()
    r.verdict = "BLOCKED"
    r.response_sensitivity = "PUBLIC"
    r.confidence = 0.95
    r.skipped = False
    return r


def _make_flagged_inspection(sensitivity: str = "INTERNAL") -> MagicMock:
    """Return a mock ResponseInspectionResult with FLAGGED verdict."""
    r = MagicMock()
    r.verdict = "FLAGGED"
    r.response_sensitivity = sensitivity
    r.confidence = 0.80
    r.skipped = False
    return r


def _build_test_app(
    broker: MagicMock,
    inspection_pipeline: Optional[MagicMock] = None,
) -> TestClient:
    """
    Build a minimal FastAPI app with create_mcp_call_router for testing.

    The broker mock handles both enforce() and enforce_result().
    """
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router

    registry = McpBrokerRegistry()
    server_cfg = McpBrokerServerConfig(
        upstream_url="http://test-mcp:8000",
        is_filesystem_agent=False,
        tenant_id="test-tenant",
        agent_name="test-agent",
    )
    registry.register("test-agent", broker, server_cfg)

    app = FastAPI()
    router = create_mcp_call_router(
        registry=registry,
        response_inspection_pipeline=inspection_pipeline,
    )
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def _patch_transport_forward(fake_response: str = _UPSTREAM_RESULT):
    """
    Context-manager: patches McpHttpTransport.__aenter__ to inject forward() mock.

    The real __aenter__ is replaced so that derive_posture() (called on the first
    McpHttpTransport instance WITHOUT entering the context manager) is unaffected —
    derive_posture() uses self._is_relay etc. which are set at __init__ time.

    Only the async-context-manager path (used for forward()) gets the mock.
    """
    async def fake_aenter(self: _RealTransport) -> _RealTransport:
        self.forward = AsyncMock(return_value=fake_response)
        return self

    return patch.object(_RealTransport, "__aenter__", fake_aenter)


# ---------------------------------------------------------------------------
# C1: result above caller ceiling → withheld (deny contract returned)
# ---------------------------------------------------------------------------

class TestEgressDeniedWithheld:
    """C1: OPA egress deny → 403, raw upstream result NOT in response body."""

    def test_c1_result_above_ceiling_withheld(self):
        broker = _make_mock_broker(egress_decision=_make_egress_deny(
            reason="result_sensitivity_exceeds_caller_ceiling",
            code="MCP_RESULT_SENSITIVITY_EXCEEDED",
            message="The tool result contains information above your authorisation level.",
        ))

        with _patch_transport_forward():
            client = _build_test_app(broker)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "MCP_EGRESS_DENIED"
        assert body["deny_reason"] == "result_sensitivity_exceeds_caller_ceiling"
        assert body["code"] == "MCP_RESULT_SENSITIVITY_EXCEEDED"
        assert body["policy_id"] == "mcp.response_decision"
        # The raw upstream result MUST NOT be returned to the caller
        assert "hello from upstream" not in resp.text
        broker.enforce_result.assert_called_once()

    def test_c1_pii_blocked_withheld(self):
        """PII-detected egress deny → 403, result withheld."""
        broker = _make_mock_broker(egress_decision=_make_egress_deny(
            reason="pii_detected_in_result",
            code="MCP_RESULT_PII_BLOCKED",
            message="The tool result was blocked because personal information was detected.",
        ))

        with _patch_transport_forward():
            client = _build_test_app(broker)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body["deny_reason"] == "pii_detected_in_result"
        assert "hello from upstream" not in resp.text


# ---------------------------------------------------------------------------
# C2: allowed result passes through unchanged
# ---------------------------------------------------------------------------

class TestEgressAllowedPassthrough:
    """C2: OPA egress allow → 200, upstream body returned unchanged."""

    def test_c2_allowed_result_returned_unchanged(self):
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        with _patch_transport_forward():
            client = _build_test_app(broker)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 200
        # Upstream body returned verbatim
        assert "hello from upstream" in resp.text
        broker.enforce_result.assert_called_once()

    def test_c2_enforce_result_called_with_ctx_fields(self):
        """C2b: enforce_result receives McpCallContext with correct agent/tool."""
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        with _patch_transport_forward():
            client = _build_test_app(broker)
            client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        broker.enforce_result.assert_called_once()
        call_kwargs = broker.enforce_result.call_args[1]
        ctx = call_kwargs["ctx"]
        assert ctx.tool_name == "web_search"
        assert ctx.agent_name == "test-agent"


# ---------------------------------------------------------------------------
# C3: OPA error in enforce_result → fail-closed withhold
# ---------------------------------------------------------------------------

class TestEgressOpaErrorFailClosed:
    """C3: enforce_result returns OPA error / raises → fail-closed 403."""

    def test_c3_opa_unreachable_withholds_result(self):
        """OPA error response → withheld with the deny contract."""
        broker = _make_mock_broker(egress_decision=_make_egress_deny(
            reason="opa_unreachable",
            code="MCP_RESPONSE_OPA_UNREACHABLE",
            message="The security policy service is unreachable.",
        ))

        with _patch_transport_forward():
            client = _build_test_app(broker)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body["deny_reason"] == "opa_unreachable"
        assert "hello from upstream" not in resp.text

    def test_c3_enforce_result_raises_fail_closed(self):
        """C3b: enforce_result RAISES → fail-closed 403 MCP_EGRESS_ERROR."""
        broker = _make_mock_broker()
        broker.enforce_result = AsyncMock(side_effect=RuntimeError("unexpected crash"))

        with _patch_transport_forward():
            client = _build_test_app(broker)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "MCP_EGRESS_ERROR"
        assert "hello from upstream" not in resp.text


# ---------------------------------------------------------------------------
# C4: inspection BLOCKED verdict → withheld before OPA
# ---------------------------------------------------------------------------

class TestEgressInspectionBlocked:
    """C4: ResponseInspectionPipeline BLOCKED verdict → 403 before OPA query."""

    def test_c4_blocked_inspection_withholds_result(self):
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        mock_pipeline = MagicMock()
        mock_pipeline.inspect = MagicMock(return_value=_make_blocked_inspection())

        with _patch_transport_forward():
            client = _build_test_app(broker, inspection_pipeline=mock_pipeline)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "MCP_EGRESS_BLOCKED"
        assert body["deny_reason"] == "response_inspection_blocked"
        assert "hello from upstream" not in resp.text
        # enforce_result NOT called — short-circuited at inspection BLOCKED
        broker.enforce_result.assert_not_called()

    def test_c4_flagged_verdict_still_calls_enforce_result(self):
        """FLAGGED (not BLOCKED) → pii_detected=True; enforce_result still runs."""
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        mock_pipeline = MagicMock()
        mock_pipeline.inspect = MagicMock(
            return_value=_make_flagged_inspection(sensitivity="INTERNAL")
        )

        with _patch_transport_forward():
            client = _build_test_app(broker, inspection_pipeline=mock_pipeline)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        # FLAGGED passes to OPA; OPA allows → 200
        assert resp.status_code == 200
        broker.enforce_result.assert_called_once()
        call_kwargs = broker.enforce_result.call_args[1]
        # pii_detected=True because verdict was FLAGGED
        assert call_kwargs["pii_detected"] is True
        # result_sensitivity comes from the inspection pipeline
        assert call_kwargs["result_sensitivity"] == "INTERNAL"


# ---------------------------------------------------------------------------
# C7: result_sensitivity forwarded from inspection pipeline to enforce_result
# ---------------------------------------------------------------------------

class TestEgressSensitivityFromInspection:
    """C7: result_sensitivity from inspection pipeline passed to enforce_result."""

    def test_c7_sensitivity_passed_from_inspection_to_opa(self):
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        mock_pipeline = MagicMock()
        mock_pipeline.inspect = MagicMock(
            return_value=_make_clean_inspection(sensitivity="CONFIDENTIAL")
        )

        with _patch_transport_forward():
            client = _build_test_app(broker, inspection_pipeline=mock_pipeline)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 200
        call_kwargs = broker.enforce_result.call_args[1]
        assert call_kwargs["result_sensitivity"] == "CONFIDENTIAL"
        assert call_kwargs["pii_detected"] is False


# ---------------------------------------------------------------------------
# C6: no inspection pipeline → defaults PUBLIC/False, OPA gate still runs
# ---------------------------------------------------------------------------

class TestEgressNoInspectionPipeline:
    """C6: no inspection pipeline → defaults to PUBLIC/False; OPA gate always fires."""

    def test_c6_no_pipeline_defaults_public_opa_still_runs(self):
        broker = _make_mock_broker(egress_decision=_make_egress_allow())

        with _patch_transport_forward():
            # No inspection pipeline passed
            client = _build_test_app(broker, inspection_pipeline=None)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 200
        broker.enforce_result.assert_called_once()
        call_kwargs = broker.enforce_result.call_args[1]
        # Defaults when no pipeline
        assert call_kwargs["result_sensitivity"] == "PUBLIC"
        assert call_kwargs["pii_detected"] is False

    def test_c6_no_pipeline_egress_deny_withholds(self):
        """C6b: no pipeline, OPA denies → result still withheld."""
        broker = _make_mock_broker(egress_decision=_make_egress_deny(
            reason="result_sensitivity_exceeds_caller_ceiling",
            code="MCP_RESULT_SENSITIVITY_EXCEEDED",
            message="Blocked.",
        ))

        with _patch_transport_forward():
            client = _build_test_app(broker, inspection_pipeline=None)
            resp = client.post(
                "/mcp/test-agent",
                content=_TOOLS_CALL_BODY,
                headers={"Content-Type": "application/json"},
            )

        assert resp.status_code == 403
        assert "hello from upstream" not in resp.text
        body = resp.json()
        assert body["error"] == "MCP_EGRESS_DENIED"
