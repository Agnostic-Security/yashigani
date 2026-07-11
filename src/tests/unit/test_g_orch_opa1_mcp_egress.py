"""
G-ORCH-OPA-1 — MCP egress OPA decision tests
=============================================

Tests for the MCP tool-result egress OPA gate:
  A. query_mcp_response_decision (_opa.py) — OPA query fn
     A1. allow path: OPA returns allow=True
     A2. deny path: result sensitivity above ceiling
     A3. deny path: PII detected
     A4. fail-closed: OPA timeout → deny
     A5. fail-closed: OPA unreachable → deny
     A6. fail-closed: OPA HTTP error → deny
     A7. fail-closed: OPA returns undefined result ({}) → deny
     A8. input document shape: all fields present

  B. McpBroker.enforce_result() (broker.py) — broker method
     B1. OPA allow → EgressDecision.allow=True
     B2. OPA deny → EgressDecision.allow=False, no result leak
     B3. OPA error → fail-closed EgressDecision.allow=False
     B4. Audit event emitted on egress deny
     B5. No audit event emitted on egress allow (no double-audit)
     B6. EgressDecision fields: policy_id, code, user_message populated
     B7. None caller_sensitivity_ceiling → fail-closed deny

G-ORCH-OPA-1 / 3.1 egress hardening.
"""
from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from yashigani.mcp._opa import (
    query_mcp_response_decision,
    OpaResponseDecisionResult,
    MCP_RESPONSE_OPA_PATH,
)
from yashigani.mcp._types import (
    McpCallContext,
    McpPosture,
    PostureBinding,
)
from yashigani.mcp.broker import McpBroker, McpBrokerConfig


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

OPA_URL = "http://opa-test:8181"
SPIFFE = "spiffe://cluster.local/ns/default/sa/agent"


def _make_ctx(
    ceiling: Optional[str] = "RESTRICTED",
    tool_name: str = "web_search",
) -> McpCallContext:
    return McpCallContext(
        tenant_id="test-tenant",
        agent_name="test-agent",
        user_id="user-1",
        posture=McpPosture.MCP_B,
        posture_binding=PostureBinding(
            derived_from="tls_channel",
            channel_type="network-streamable-http",
        ),
        action="mcp.tools.call",
        tool_name=tool_name,
        tool_args_redacted={"query": "hello"},
        caller_sensitivity_ceiling=ceiling,
    )


def _make_broker(audit_writer=None) -> McpBroker:
    cfg = McpBrokerConfig(
        opa_url=OPA_URL,
        tenant_id="test-tenant",
        audit_writer=audit_writer,
    )
    return McpBroker(cfg)


def _opa_allow_response() -> dict:
    return {
        "result": {
            "allow": True,
            "deny_reason": "ok",
            "policy_id": "mcp.response_decision",
            "code": "MCP_RESULT_OK",
            "user_message": "Tool result approved for delivery.",
        }
    }


def _opa_deny_response(reason: str, code: str, message: str) -> dict:
    return {
        "result": {
            "allow": False,
            "deny_reason": reason,
            "policy_id": "mcp.response_decision",
            "code": code,
            "user_message": message,
        }
    }


# ---------------------------------------------------------------------------
# A. query_mcp_response_decision tests
# ---------------------------------------------------------------------------

class TestQueryMcpResponseDecision:
    """Tests for the _opa.py query_mcp_response_decision function."""

    @pytest.mark.asyncio
    async def test_a1_allow_path_returns_allow_true(self):
        """A1: OPA returns allow=True → result.allow is True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _opa_allow_response()
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=["mcp_users"],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            tool_name="web_search",
            http_client=mock_client,
        )

        assert result.allow is True
        assert result.deny_reason == "ok"
        assert result.policy_id == "mcp.response_decision"
        assert result.code == "MCP_RESULT_OK"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_a2_deny_when_sensitivity_exceeds_ceiling(self):
        """A2: OPA denies when result sensitivity exceeds caller ceiling."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _opa_deny_response(
            reason="result_sensitivity_exceeds_caller_ceiling",
            code="MCP_RESULT_SENSITIVITY_EXCEEDED",
            message="The tool result contains information above your authorisation level.",
        )
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="INTERNAL",
            caller_groups=[],
            result_sensitivity="RESTRICTED",
            pii_detected=False,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "result_sensitivity_exceeds_caller_ceiling"
        assert result.code == "MCP_RESULT_SENSITIVITY_EXCEEDED"
        assert "authorisation level" in result.user_message

    @pytest.mark.asyncio
    async def test_a3_deny_when_pii_detected(self):
        """A3: OPA denies when PII is detected in the result."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _opa_deny_response(
            reason="pii_detected_in_result",
            code="MCP_RESULT_PII_BLOCKED",
            message="The tool result was blocked because personal information was detected.",
        )
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=True,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "pii_detected_in_result"
        assert result.code == "MCP_RESULT_PII_BLOCKED"

    @pytest.mark.asyncio
    async def test_a4_timeout_returns_fail_closed_deny(self):
        """A4: OPA timeout → fail-closed deny (never raises)."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.TimeoutException("timed out")
        )

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "opa_timeout"
        assert result.error is not None
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_a5_unreachable_returns_fail_closed_deny(self):
        """A5: OPA unreachable (generic Exception) → fail-closed deny."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=ConnectionRefusedError("Connection refused")
        )

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "opa_unreachable"
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_a6_http_error_returns_fail_closed_deny(self):
        """A6: OPA HTTP 500 → fail-closed deny."""
        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "500", request=mock_request, response=mock_response
            )
        )

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "opa_http_error"
        assert "500" in result.error

    @pytest.mark.asyncio
    async def test_a7_undefined_result_returns_fail_closed_deny(self):
        """A7: OPA returns {'result': null} (undefined rule) → fail-closed deny."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": None}
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            http_client=mock_client,
        )

        assert result.allow is False
        assert result.deny_reason == "opa_undefined_result"
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_a8_input_document_shape(self):
        """A8: verify the OPA input document sent contains all expected fields."""
        captured_json = {}

        async def _capture_post(url, json=None, **kwargs):
            captured_json.update(json or {})
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _opa_allow_response()
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_client = AsyncMock()
        mock_client.post = _capture_post

        await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="CONFIDENTIAL",
            caller_groups=["group-a"],
            result_sensitivity="INTERNAL",
            pii_detected=False,
            tool_name="my_tool",
            agent_name="my_agent",
            http_client=mock_client,
        )

        assert "input" in captured_json
        inp = captured_json["input"]
        assert inp["caller"]["spiffe"] == SPIFFE
        assert inp["caller"]["sensitivity_ceiling"] == "CONFIDENTIAL"
        assert inp["caller"]["groups"] == ["group-a"]
        assert inp["result"]["sensitivity"] == "INTERNAL"
        assert inp["result"]["pii_detected"] is False
        assert inp["tool"]["name"] == "my_tool"
        assert inp["agent"]["name"] == "my_agent"

    @pytest.mark.asyncio
    async def test_a8b_opa_url_uses_correct_path(self):
        """A8b: the OPA POST targets MCP_RESPONSE_OPA_PATH."""
        captured_url = {}

        async def _capture_post(url, json=None, **kwargs):
            captured_url["url"] = url
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _opa_allow_response()
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_client = AsyncMock()
        mock_client.post = _capture_post

        await query_mcp_response_decision(
            opa_url=OPA_URL,
            caller_spiffe=SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            http_client=mock_client,
        )

        expected_url = OPA_URL.rstrip("/") + MCP_RESPONSE_OPA_PATH
        assert captured_url["url"] == expected_url


# ---------------------------------------------------------------------------
# B. McpBroker.enforce_result() tests
# ---------------------------------------------------------------------------

class TestEnforceResult:
    """Tests for McpBroker.enforce_result()."""

    @pytest.mark.asyncio
    async def test_b1_allow_returns_egress_decision_allow(self):
        """B1: OPA allow → EgressDecision.allow=True, no error."""
        broker = _make_broker()
        ctx = _make_ctx(ceiling="RESTRICTED")

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=True,
                deny_reason="ok",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_OK",
                user_message="Tool result approved for delivery.",
                elapsed_ms=10,
            )

            decision = await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="PUBLIC",
                pii_detected=False,
            )

        assert decision.allow is True
        assert decision.deny_reason == "ok"
        assert decision.code == "MCP_RESULT_OK"
        assert decision.error is None

    @pytest.mark.asyncio
    async def test_b2_deny_returns_egress_decision_deny_no_leak(self):
        """B2: OPA deny → EgressDecision.allow=False; result must not be leaked."""
        broker = _make_broker()
        ctx = _make_ctx(ceiling="INTERNAL")

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=False,
                deny_reason="result_sensitivity_exceeds_caller_ceiling",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_SENSITIVITY_EXCEEDED",
                user_message="The tool result contains information above your authorisation level.",
                elapsed_ms=8,
            )

            decision = await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="RESTRICTED",
                pii_detected=False,
            )

        assert decision.allow is False
        assert decision.deny_reason == "result_sensitivity_exceeds_caller_ceiling"
        assert decision.code == "MCP_RESULT_SENSITIVITY_EXCEEDED"
        # The EgressDecision does NOT contain the result content — it is the
        # caller's responsibility not to return the result when allow=False.
        # Verify the EgressDecision carries only safe deny fields.
        assert "result" not in vars(decision)

    @pytest.mark.asyncio
    async def test_b3_opa_error_fail_closed(self):
        """B3: OPA error → EgressDecision.allow=False (fail-closed)."""
        broker = _make_broker()
        ctx = _make_ctx()

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=False,
                deny_reason="opa_unreachable",
                policy_id="mcp.response_decision",
                code="MCP_RESPONSE_OPA_UNREACHABLE",
                user_message="Security policy service unreachable.",
                elapsed_ms=501,
                error="Connection refused",
            )

            decision = await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="PUBLIC",
                pii_detected=False,
            )

        assert decision.allow is False
        assert decision.deny_reason == "opa_unreachable"
        assert decision.error == "Connection refused"

    @pytest.mark.asyncio
    async def test_b4_audit_emitted_on_egress_deny(self):
        """B4: audit event emitted on egress denial."""
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()

        broker = _make_broker(audit_writer=mock_writer)
        ctx = _make_ctx()

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=False,
                deny_reason="pii_detected_in_result",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_PII_BLOCKED",
                user_message="PII blocked.",
                elapsed_ms=5,
            )

            await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="PUBLIC",
                pii_detected=True,
            )

        # The audit writer should have been called for the egress deny.
        assert mock_writer.write.called

    @pytest.mark.asyncio
    async def test_b5_no_extra_audit_on_allow(self):
        """B5: no extra audit event emitted on egress allow (clean path)."""
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()

        broker = _make_broker(audit_writer=mock_writer)
        ctx = _make_ctx()

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=True,
                deny_reason="ok",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_OK",
                user_message="Approved.",
                elapsed_ms=5,
            )

            await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="PUBLIC",
                pii_detected=False,
            )

        # On allow, enforce_result does NOT emit an additional audit event.
        assert not mock_writer.write.called

    @pytest.mark.asyncio
    async def test_b6_egress_decision_fields_populated(self):
        """B6: EgressDecision carries policy_id, code, user_message."""
        broker = _make_broker()
        ctx = _make_ctx()

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            mock_query.return_value = OpaResponseDecisionResult(
                allow=False,
                deny_reason="result_sensitivity_exceeds_caller_ceiling",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_SENSITIVITY_EXCEEDED",
                user_message="Blocked: result above your clearance.",
                elapsed_ms=7,
            )

            decision = await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="RESTRICTED",
                pii_detected=False,
            )

        assert decision.policy_id == "mcp.response_decision"
        assert decision.code == "MCP_RESULT_SENSITIVITY_EXCEEDED"
        assert decision.user_message != ""
        # elapsed_ms may be 0 in fast unit tests (sub-ms wall time, int truncation)
        assert decision.elapsed_ms >= 0

    @pytest.mark.asyncio
    async def test_b7_none_ceiling_produces_fail_closed_deny(self):
        """B7: ctx.caller_sensitivity_ceiling=None → OPA can't rank ceiling → fail-closed deny."""
        broker = _make_broker()
        ctx = _make_ctx(ceiling=None)  # No ceiling set

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            new_callable=AsyncMock,
        ) as mock_query:
            # When ceiling is None, OPA's _result_ceiling_rank is undefined → deny.
            mock_query.return_value = OpaResponseDecisionResult(
                allow=False,
                deny_reason="invalid_or_missing_caller_ceiling",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_CEILING_INVALID",
                user_message="Caller ceiling not recognised.",
                elapsed_ms=4,
            )

            decision = await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="PUBLIC",
                pii_detected=False,
            )

        # Verify None ceiling was passed to the OPA query
        call_kwargs = mock_query.call_args[1]
        assert call_kwargs["caller_sensitivity_ceiling"] is None

        # Decision is deny (fail-closed)
        assert decision.allow is False
        assert decision.deny_reason == "invalid_or_missing_caller_ceiling"

    @pytest.mark.asyncio
    async def test_b8_enforce_result_passes_sensitivity_to_opa(self):
        """B8: result_sensitivity and pii_detected are forwarded to the OPA query."""
        broker = _make_broker()
        ctx = _make_ctx(ceiling="CONFIDENTIAL")

        captured_kwargs = {}

        async def _capture(**kwargs):
            captured_kwargs.update(kwargs)
            return OpaResponseDecisionResult(
                allow=True,
                deny_reason="ok",
                policy_id="mcp.response_decision",
                code="MCP_RESULT_OK",
                user_message="ok",
                elapsed_ms=3,
            )

        with patch(
            "yashigani.mcp.broker.query_mcp_response_decision",
            side_effect=_capture,
        ):
            await broker.enforce_result(
                ctx=ctx,
                result_sensitivity="CONFIDENTIAL",
                pii_detected=True,
            )

        assert captured_kwargs["result_sensitivity"] == "CONFIDENTIAL"
        assert captured_kwargs["pii_detected"] is True
        assert captured_kwargs["caller_sensitivity_ceiling"] == "CONFIDENTIAL"
        assert captured_kwargs["tool_name"] == ctx.tool_name
        assert captured_kwargs["agent_name"] == ctx.agent_name
