"""
3.1.2 FIND-A-AUD — caller identity must reach the audit chain, not just OPA.

Before the fix: McpCallEvent and OpaDecisionOnMcpEvent had no agent_id field;
the audit_events.agent_id DB column was NULL for all GATEWAY_REQUEST / MCP-call
events.  The acting identity was visible to OPA (Phase 1 wired caller_agent_id)
but invisible in the tamper-evident audit chain — violating the "compliance/
security events must carry the acting identity" rule.

After the fix:
  - McpCallEvent.agent_id     = ctx.caller_agent_id  (or None when unauthenticated)
  - OpaDecisionOnMcpEvent.agent_id = ctx.caller_agent_id
  - Both events' to_dict() expose the "agent_id" key, which the PostgresSink
    writes to the audit_events.agent_id DB column ($5 in INSERT_AUDIT_EVENT).
  - McpBroker._emit_audit populates the field from McpCallContext.caller_agent_id.
  - McpBroker._emit_egress_audit populates it on the egress-deny OPA event too.

Tests:
  AUD-S1  McpCallEvent has agent_id field, defaults to None
  AUD-S2  OpaDecisionOnMcpEvent has agent_id field, defaults to None
  AUD-S3  McpCallEvent.to_dict() exposes "agent_id" key → PostgresSink DB mapping
  AUD-S4  OpaDecisionOnMcpEvent.to_dict() exposes "agent_id" key
  AUD-B1  broker._emit_audit → McpCallEvent.agent_id == ctx.caller_agent_id
  AUD-B2  broker._emit_audit → OpaDecisionOnMcpEvent.agent_id == ctx.caller_agent_id
  AUD-B3  caller_agent_id=None → agent_id is None in both events (not key-absent)
  AUD-B4  Denied call (OPA deny) → agent_id still propagated in audit events
  AUD-E1  egress-deny OpaDecisionOnMcpEvent.agent_id == ctx.caller_agent_id

Run:
  PYTHONPATH=src pytest src/tests/unit/test_v312_find_a_aud_mcp_audit_agent_id.py -q

Last updated: 2026-07-01T00:00:00+01:00
"""
from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(caller_agent_id: Optional[str] = "agent-X", tool_name: str = "search"):
    from yashigani.mcp._types import McpCallContext
    posture, binding = _make_posture_b()
    return McpCallContext(
        tenant_id="t1",
        agent_name="mcp-server-1",
        user_id="user-1",
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name=tool_name,
        caller_agent_id=caller_agent_id,
    )


def _opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True, deny_reason="ok", redact_args=set(),
        audit_capture=False, rate_limit_key=None, elapsed_ms=5,
    )


def _opa_deny():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=False, deny_reason="not_in_allowlist", redact_args=set(),
        audit_capture=True, rate_limit_key=None, elapsed_ms=5,
    )


def _make_broker(audit_writer=None):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    issuer = McpJwtIssuer(tenant_id="t1")
    config = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id="t1",
        issuer=issuer,
        audit_writer=audit_writer,
    )
    return McpBroker(config)


# ─────────────────────────────────────────────────────────────────────────────
# AUD-S: Schema field tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaAgentIdField:
    """McpCallEvent and OpaDecisionOnMcpEvent must both carry agent_id."""

    def test_s1_mcp_call_event_has_agent_id_field(self):
        """AUD-S1: McpCallEvent has agent_id field, defaults to None."""
        from yashigani.audit.schema import McpCallEvent

        evt = McpCallEvent()
        assert hasattr(evt, "agent_id"), (
            "McpCallEvent must have an agent_id field (FIND-A-AUD 3.1.2). "
            "Field missing — PostgresSink cannot populate audit_events.agent_id column."
        )
        assert evt.agent_id is None, (
            f"McpCallEvent.agent_id must default to None, got {evt.agent_id!r}"
        )

    def test_s2_opa_decision_on_mcp_event_has_agent_id_field(self):
        """AUD-S2: OpaDecisionOnMcpEvent has agent_id field, defaults to None."""
        from yashigani.audit.schema import OpaDecisionOnMcpEvent

        evt = OpaDecisionOnMcpEvent()
        assert hasattr(evt, "agent_id"), (
            "OpaDecisionOnMcpEvent must have an agent_id field (FIND-A-AUD 3.1.2)."
        )
        assert evt.agent_id is None, (
            f"OpaDecisionOnMcpEvent.agent_id must default to None, got {evt.agent_id!r}"
        )

    def test_s3_mcp_call_event_to_dict_has_agent_id_key(self):
        """AUD-S3: McpCallEvent.to_dict() exposes 'agent_id' key → PostgresSink DB mapping."""
        from yashigani.audit.schema import McpCallEvent

        evt = McpCallEvent(
            tenant_id="t1",
            agent_name="mcp-server",
            tool_name="search",
            opa_decision="allow",
            agent_id="agent-X",
        )
        d = evt.to_dict()
        assert "agent_id" in d, (
            "McpCallEvent.to_dict() must expose 'agent_id' key. "
            "The PostgresSink reads event.get('agent_id') for the audit_events.agent_id column ($5)."
        )
        assert d["agent_id"] == "agent-X", (
            f"Expected agent_id='agent-X' in to_dict(), got {d['agent_id']!r}"
        )

    def test_s4_opa_decision_on_mcp_event_to_dict_has_agent_id_key(self):
        """AUD-S4: OpaDecisionOnMcpEvent.to_dict() exposes 'agent_id' key."""
        from yashigani.audit.schema import OpaDecisionOnMcpEvent

        evt = OpaDecisionOnMcpEvent(
            tenant_id="t1",
            agent_name="mcp-server",
            tool_name="search",
            decision="allow",
            agent_id="agent-X",
        )
        d = evt.to_dict()
        assert "agent_id" in d, (
            "OpaDecisionOnMcpEvent.to_dict() must expose 'agent_id' key."
        )
        assert d["agent_id"] == "agent-X", (
            f"Expected agent_id='agent-X' in to_dict(), got {d['agent_id']!r}"
        )

    def test_s5_agent_id_null_when_none_in_dict(self):
        """agent_id=None in dataclass → to_dict() has key 'agent_id' with value None."""
        from yashigani.audit.schema import McpCallEvent
        evt = McpCallEvent(agent_id=None)
        d = evt.to_dict()
        # Key must exist (even when None) so PostgresSink reads None and the DB
        # column gets NULL rather than the previous case where the key was absent
        # and event.get("agent_id") also returned None (same result, but now
        # the serialisation is explicit and testable).
        assert "agent_id" in d
        assert d["agent_id"] is None


# ─────────────────────────────────────────────────────────────────────────────
# AUD-B: Broker _emit_audit propagation tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBrokerAuditAgentId:
    """broker._emit_audit must populate agent_id from ctx.caller_agent_id."""

    @pytest.mark.asyncio
    async def test_b1_mcp_call_event_agent_id_set_from_ctx(self):
        """AUD-B1: McpCallEvent written by broker has agent_id=ctx.caller_agent_id."""
        audit_writer = MagicMock()
        broker = _make_broker(audit_writer)
        ctx = _make_ctx(caller_agent_id="agent-X")

        with patch("yashigani.mcp.broker.query_mcp_decision", new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        from yashigani.audit.schema import McpCallEvent
        # broker writes: write(mcp_call_event), write(opa_event)
        assert audit_writer.write.call_count == 2, (
            f"Expected 2 audit writes (McpCallEvent + OpaDecisionOnMcpEvent), "
            f"got {audit_writer.write.call_count}"
        )
        mcp_call_evt = audit_writer.write.call_args_list[0][0][0]
        assert isinstance(mcp_call_evt, McpCallEvent), (
            f"First write must be McpCallEvent, got {type(mcp_call_evt)}"
        )
        assert mcp_call_evt.agent_id == "agent-X", (
            f"McpCallEvent.agent_id must be 'agent-X' (from ctx.caller_agent_id), "
            f"got {mcp_call_evt.agent_id!r}. FIND-A-AUD: audit chain was missing caller identity."
        )

    @pytest.mark.asyncio
    async def test_b2_opa_event_agent_id_set_from_ctx(self):
        """AUD-B2: OpaDecisionOnMcpEvent written by broker has agent_id=ctx.caller_agent_id."""
        audit_writer = MagicMock()
        broker = _make_broker(audit_writer)
        ctx = _make_ctx(caller_agent_id="agent-X")

        with patch("yashigani.mcp.broker.query_mcp_decision", new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        from yashigani.audit.schema import OpaDecisionOnMcpEvent
        opa_evt = audit_writer.write.call_args_list[1][0][0]
        assert isinstance(opa_evt, OpaDecisionOnMcpEvent), (
            f"Second write must be OpaDecisionOnMcpEvent, got {type(opa_evt)}"
        )
        assert opa_evt.agent_id == "agent-X", (
            f"OpaDecisionOnMcpEvent.agent_id must be 'agent-X', got {opa_evt.agent_id!r}."
        )

    @pytest.mark.asyncio
    async def test_b3_none_caller_agent_id_gives_none_agent_id(self):
        """AUD-B3: caller_agent_id=None (unauthenticated) → agent_id is None in audit events."""
        audit_writer = MagicMock()
        broker = _make_broker(audit_writer)
        ctx = _make_ctx(caller_agent_id=None)

        with patch("yashigani.mcp.broker.query_mcp_decision", new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        mcp_call_evt = audit_writer.write.call_args_list[0][0][0]
        opa_evt = audit_writer.write.call_args_list[1][0][0]
        # None is expected (caller not identified); the DB column gets NULL
        # which is correct for unauthenticated callers.
        assert mcp_call_evt.agent_id is None, (
            f"McpCallEvent.agent_id must be None for unauthenticated caller, "
            f"got {mcp_call_evt.agent_id!r}"
        )
        assert opa_evt.agent_id is None, (
            f"OpaDecisionOnMcpEvent.agent_id must be None for unauthenticated caller."
        )

    @pytest.mark.asyncio
    async def test_b4_denied_call_agent_id_propagated(self):
        """AUD-B4: OPA deny still emits audit events with agent_id populated."""
        audit_writer = MagicMock()
        broker = _make_broker(audit_writer)
        ctx = _make_ctx(caller_agent_id="agent-denied")

        with patch("yashigani.mcp.broker.query_mcp_decision", new=AsyncMock(return_value=_opa_deny())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow, "Expected OPA deny"
        # Events must still be written with agent_id on a deny path
        assert audit_writer.write.call_count >= 2, (
            "Deny path must still emit both audit events"
        )
        mcp_call_evt = audit_writer.write.call_args_list[0][0][0]
        opa_evt = audit_writer.write.call_args_list[1][0][0]

        from yashigani.audit.schema import McpCallEvent, OpaDecisionOnMcpEvent
        assert isinstance(mcp_call_evt, McpCallEvent)
        assert isinstance(opa_evt, OpaDecisionOnMcpEvent)
        assert mcp_call_evt.agent_id == "agent-denied", (
            f"Denied call: McpCallEvent.agent_id must be 'agent-denied', "
            f"got {mcp_call_evt.agent_id!r}"
        )
        assert opa_evt.agent_id == "agent-denied", (
            f"Denied call: OpaDecisionOnMcpEvent.agent_id must be 'agent-denied'."
        )

    @pytest.mark.asyncio
    async def test_b5_orchestrator_caller_id_in_audit(self):
        """AUD-B5: Reserved 'gateway:orchestrator' identity propagates to audit events."""
        audit_writer = MagicMock()
        broker = _make_broker(audit_writer)
        ctx = _make_ctx(caller_agent_id="gateway:orchestrator")

        with patch("yashigani.mcp.broker.query_mcp_decision", new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        mcp_call_evt = audit_writer.write.call_args_list[0][0][0]
        assert mcp_call_evt.agent_id == "gateway:orchestrator", (
            "Reserved gateway:orchestrator caller identity must appear in the audit chain."
        )


# ─────────────────────────────────────────────────────────────────────────────
# AUD-E: Egress audit event propagation test
# ─────────────────────────────────────────────────────────────────────────────

class TestEgressAuditAgentId:
    """broker._emit_egress_audit must also carry agent_id from ctx.caller_agent_id."""

    @pytest.mark.asyncio
    async def test_e1_egress_opa_event_has_agent_id(self):
        """AUD-E1: Egress-deny OpaDecisionOnMcpEvent.agent_id == ctx.caller_agent_id."""
        from yashigani.mcp.broker import McpBroker, McpBrokerConfig
        from yashigani.mcp._jwt import McpJwtIssuer
        from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
        from yashigani.mcp._opa import OpaResponseDecisionResult

        issuer = McpJwtIssuer(tenant_id="t1")
        audit_writer = MagicMock()
        config = McpBrokerConfig(
            opa_url="http://opa:8181",
            tenant_id="t1",
            issuer=issuer,
            audit_writer=audit_writer,
        )
        broker = McpBroker(config)

        posture = McpPosture.MCP_B
        ctx = McpCallContext(
            tenant_id="t1",
            agent_name="mcp-server-1",
            user_id="user-1",
            posture=posture,
            posture_binding=PostureBinding.for_posture(posture),
            action="mcp.tools.call",
            tool_name="read_secret",
            caller_agent_id="egress-caller",
            caller_sensitivity_ceiling="PUBLIC",
        )

        # OPA egress deny (result sensitivity exceeds ceiling)
        egress_deny = OpaResponseDecisionResult(
            allow=False,
            deny_reason="result_sensitivity_exceeds_caller_ceiling",
            policy_id="mcp.response_decision",
            code="MCP_RESULT_CEILING_EXCEEDED",
            user_message="Result blocked.",
            elapsed_ms=3,
            error=None,
        )

        with patch("yashigani.mcp._opa.query_mcp_response_decision",
                   new=AsyncMock(return_value=egress_deny)):
            await broker.enforce_result(ctx, "RESTRICTED", False)

        from yashigani.audit.schema import OpaDecisionOnMcpEvent
        assert audit_writer.write.call_count == 1, (
            "Egress deny must emit one OpaDecisionOnMcpEvent"
        )
        egress_evt = audit_writer.write.call_args_list[0][0][0]
        assert isinstance(egress_evt, OpaDecisionOnMcpEvent), (
            f"Egress deny event must be OpaDecisionOnMcpEvent, got {type(egress_evt)}"
        )
        assert egress_evt.agent_id == "egress-caller", (
            f"Egress OpaDecisionOnMcpEvent.agent_id must be 'egress-caller', "
            f"got {egress_evt.agent_id!r}. FIND-A-AUD: egress-deny audit was also missing caller identity."
        )


# ─────────────────────────────────────────────────────────────────────────────
# AUD-DB: PostgresSink DB-column mapping verification (integration-lite)
# ─────────────────────────────────────────────────────────────────────────────

class TestPostgresSinkAgentIdMapping:
    """Verify the event dict's agent_id key flows into the PostgresSink INSERT parameter."""

    def test_db1_mcp_call_event_agent_id_reaches_sink_parameter(self):
        """
        AUD-DB1: McpCallEvent with agent_id='agent-X' produces a to_dict() where
        event.get('agent_id') == 'agent-X' — matching what PostgresSink._flush_batch
        reads as $5 in INSERT_AUDIT_EVENT.

        This is a structural invariant test: we verify the dict key, not a live DB.
        The live DB path is covered by the install integration test suite.
        """
        from yashigani.audit.schema import McpCallEvent

        evt = McpCallEvent(
            tenant_id="t1",
            agent_name="mcp-server",
            tool_name="search",
            opa_decision="allow",
            agent_id="agent-X",
        )
        event_dict = evt.to_dict()

        # This is exactly what PostgresSink._flush_batch reads for the $5 parameter:
        sink_agent_id = event_dict.get("agent_id")
        assert sink_agent_id == "agent-X", (
            f"PostgresSink reads event.get('agent_id') as $5 in INSERT_AUDIT_EVENT. "
            f"Expected 'agent-X', got {sink_agent_id!r}. "
            f"FIND-A-AUD: audit_events.agent_id column was NULL before this fix."
        )

    def test_db2_previous_null_behaviour_was_missing_field(self):
        """
        AUD-DB2: Regression proof — before FIND-A-AUD fix, McpCallEvent had NO
        agent_id field, so event.get('agent_id') returned None → DB column NULL.
        After the fix, the field exists and is populated from caller_agent_id.
        """
        from yashigani.audit.schema import McpCallEvent
        import dataclasses

        field_names = {f.name for f in dataclasses.fields(McpCallEvent)}
        assert "agent_id" in field_names, (
            "REGRESSION: McpCallEvent.agent_id field is absent. "
            "This field was added in FIND-A-AUD (3.1.2) to populate "
            "audit_events.agent_id from McpCallContext.caller_agent_id. "
            "Do not remove it — the DB column will revert to NULL."
        )
