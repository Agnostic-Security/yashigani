"""
v3.1 Phase 1 — MCP caller identity plumbing tests.

Verifies that the calling agent's identity flows from the request context into
McpCallContext and reaches the OPA input document in broker.enforce().

Two paths tested end-to-end:
  (a) Agent-originated MCP call:
        request.state.agent_id = "agent-foo"
        → ctx.caller_agent_id == "agent-foo"
        → OPA input["caller"]["agent_id"] == "agent-foo"

  (b) Orchestrator self-call (gateway-mediated):
        X-Yashigani-Orchestration-Depth header present
        → ctx.caller_agent_id == "gateway:orchestrator"
        → OPA input["caller"]["agent_id"] == "gateway:orchestrator"

Phase 1 is ADDITIVE PLUMBING ONLY: no enforcement, no default-deny, no
behavior change.  Unbound OPA policies that do not reference input.caller
remain no-ops after this change.

Coverage:
  A. McpCallContext.caller_agent_id field — existence and defaults
  B. _build_opa_input: caller field in OPA document when provided
  C. broker.enforce: caller_agent_id reaches query_mcp_decision (mcp_decision input)
  D. broker.enforce: caller_agent_id reaches evaluate_client_policies base_input
  E. mcp_router_runtime: caller_agent_id populated from request.state.agent_id
  F. mcp_router_runtime: caller_agent_id = "gateway:orchestrator" from orch header
"""
from __future__ import annotations

import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    posture = McpPosture.MCP_B
    return posture, PostureBinding.for_posture(posture)


def _make_ctx(caller_agent_id: Optional[str] = None, user_id: str = "user-1"):
    from yashigani.mcp._types import McpCallContext
    posture, binding = _make_posture_b()
    return McpCallContext(
        tenant_id="t1",
        agent_name="mcp-server-1",
        user_id=user_id,
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name="search",
        caller_agent_id=caller_agent_id,
    )


def _opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True,
        deny_reason="ok",
        redact_args=set(),
        audit_capture=False,
        rate_limit_key=None,
        elapsed_ms=5,
    )


def _make_broker_config(opa_url: str = "http://opa:8181"):
    from yashigani.mcp.broker import McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    issuer = McpJwtIssuer(tenant_id="t1")
    return McpBrokerConfig(opa_url=opa_url, tenant_id="t1", issuer=issuer)


# ─────────────────────────────────────────────────────────────────────────────
# A. McpCallContext.caller_agent_id — field existence and defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestCallerAgentIdField:
    """McpCallContext.caller_agent_id field: defaults and values."""

    def test_field_defaults_to_none(self):
        """caller_agent_id defaults to None when not supplied."""
        ctx = _make_ctx()
        assert ctx.caller_agent_id is None, (
            "McpCallContext.caller_agent_id must default to None. "
            "v3.1 Phase 1 additive field."
        )

    def test_field_accepts_agent_id_string(self):
        """caller_agent_id stores an arbitrary agent-id string."""
        ctx = _make_ctx(caller_agent_id="agent-foo")
        assert ctx.caller_agent_id == "agent-foo"

    def test_field_accepts_orchestrator_reserved_identity(self):
        """Reserved identity 'gateway:orchestrator' is stored correctly."""
        ctx = _make_ctx(caller_agent_id="gateway:orchestrator")
        assert ctx.caller_agent_id == "gateway:orchestrator"

    def test_existing_fields_unaffected(self):
        """Adding caller_agent_id must not disturb existing McpCallContext fields."""
        ctx = _make_ctx(caller_agent_id="a", user_id="u1")
        assert ctx.tenant_id == "t1"
        assert ctx.agent_name == "mcp-server-1"
        assert ctx.user_id == "u1"
        assert ctx.action == "mcp.tools.call"
        assert ctx.tool_name == "search"


# ─────────────────────────────────────────────────────────────────────────────
# B. _build_opa_input: caller field in OPA document
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildOpaInputCallerField:
    """_build_opa_input includes input.caller when caller kwarg is provided."""

    def _build(self, caller: Optional[dict] = None) -> dict:
        from yashigani.mcp._opa import _build_opa_input
        return _build_opa_input(
            posture="mcp-b",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/t1/mcp-server-1",
            chain=[],
            tool_name="search",
            caller=caller,
        )

    def test_caller_absent_when_not_provided(self):
        """OPA input must NOT contain 'caller' key when caller=None (additive, no-op)."""
        doc = self._build(caller=None)
        assert "caller" not in doc["input"], (
            "input.caller must be absent when caller=None. "
            "Unbound policies must not see a new key that breaks their logic."
        )

    def test_caller_present_when_provided(self):
        """OPA input contains input.caller when caller dict is supplied."""
        caller = {"agent_id": "agent-foo", "user_id": "user-1"}
        doc = self._build(caller=caller)
        assert "caller" in doc["input"], "input.caller must be present when caller kwarg is supplied."
        assert doc["input"]["caller"]["agent_id"] == "agent-foo"
        assert doc["input"]["caller"]["user_id"] == "user-1"

    def test_caller_agent_id_empty_string_when_ctx_none(self):
        """Broker passes caller_agent_id or '' — empty string is safe for OPA."""
        caller = {"agent_id": "", "user_id": "user-1"}
        doc = self._build(caller=caller)
        assert doc["input"]["caller"]["agent_id"] == ""

    def test_existing_input_keys_unaffected(self):
        """Adding caller must not remove or alter posture/action/identity/tool."""
        caller = {"agent_id": "a", "user_id": "u"}
        doc = self._build(caller=caller)
        inp = doc["input"]
        assert inp["posture"] == "mcp-b"
        assert inp["action"] == "mcp.tools.call"
        assert "identity" in inp
        assert "tool" in inp


# ─────────────────────────────────────────────────────────────────────────────
# C. broker.enforce: caller_agent_id reaches query_mcp_decision (mcp_decision)
# ─────────────────────────────────────────────────────────────────────────────

class TestBrokerEnforceCallerInMcpDecision:
    """
    Path (a): agent-originated MCP call.
    Path (b): orchestrator self-call (caller_agent_id = "gateway:orchestrator").

    Both verify that ctx.caller_agent_id is forwarded as the 'caller' kwarg to
    query_mcp_decision, so the OPA mcp_decision query sees input.caller.
    """

    @pytest.mark.asyncio
    async def test_agent_caller_id_reaches_opa_input_agent_call(self):
        """
        (a) Agent-originated: caller_agent_id="agent-foo" → OPA mcp_decision
        receives caller={"agent_id": "agent-foo", "user_id": "user-1"}.
        """
        from yashigani.mcp.broker import McpBroker

        config = _make_broker_config()
        broker = McpBroker(config)
        ctx = _make_ctx(caller_agent_id="agent-foo", user_id="user-1")

        captured_caller = {}

        async def fake_query_mcp_decision(**kwargs):
            captured_caller.update(kwargs.get("caller") or {})
            return _opa_allow()

        # evaluate_client_policies is a local import inside broker.enforce(); patch at source.
        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_query_mcp_decision), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        assert captured_caller.get("agent_id") == "agent-foo", (
            "OPA mcp_decision input must carry caller.agent_id = 'agent-foo' "
            "for an agent-originated MCP call. v3.1 Phase 1."
        )
        assert captured_caller.get("user_id") == "user-1"

    @pytest.mark.asyncio
    async def test_orchestrator_caller_id_reaches_opa_input(self):
        """
        (b) Orchestrator self-call: caller_agent_id="gateway:orchestrator" → OPA
        mcp_decision receives caller={"agent_id": "gateway:orchestrator", "user_id": ""}.
        """
        from yashigani.mcp.broker import McpBroker

        config = _make_broker_config()
        broker = McpBroker(config)
        # Simulate orchestrator self-call: caller_agent_id is the reserved identity.
        ctx = _make_ctx(caller_agent_id="gateway:orchestrator", user_id="")

        captured_caller = {}

        async def fake_query_mcp_decision(**kwargs):
            captured_caller.update(kwargs.get("caller") or {})
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_query_mcp_decision), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        assert captured_caller.get("agent_id") == "gateway:orchestrator", (
            "OPA mcp_decision input must carry caller.agent_id = 'gateway:orchestrator' "
            "for an orchestrator self-call. v3.1 Phase 1."
        )

    @pytest.mark.asyncio
    async def test_none_caller_sends_empty_agent_id(self):
        """
        When caller_agent_id is None (unauthenticated), OPA receives
        caller={"agent_id": "", "user_id": ""} — never a missing key.
        """
        from yashigani.mcp.broker import McpBroker

        config = _make_broker_config()
        broker = McpBroker(config)
        ctx = _make_ctx(caller_agent_id=None, user_id="")

        captured_caller = {}

        async def fake_query_mcp_decision(**kwargs):
            captured_caller.update(kwargs.get("caller") or {})
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_query_mcp_decision), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        # "" is the safe coalesced value for None caller_agent_id
        assert captured_caller.get("agent_id") == ""


# ─────────────────────────────────────────────────────────────────────────────
# D. broker.enforce: caller reaches evaluate_client_policies base_input
# ─────────────────────────────────────────────────────────────────────────────

class TestBrokerEnforceCallerInClientPolicies:
    """Caller identity reaches the evaluate_client_policies base_input (step 2d)."""

    @pytest.mark.asyncio
    async def test_caller_agent_id_in_client_policy_base_input(self):
        """
        evaluate_client_policies receives base_input["caller"]["agent_id"]
        from McpCallContext.caller_agent_id.
        """
        from yashigani.mcp.broker import McpBroker

        config = _make_broker_config()
        broker = McpBroker(config)
        ctx = _make_ctx(caller_agent_id="agent-bar", user_id="u2")

        captured_base_input: dict = {}

        async def fake_eval_client_policies(cfg, scope_kind, scope_id, direction, base_input):
            captured_base_input.update(base_input)
            return {"allow": True}

        # evaluate_client_policies is a local import inside broker.enforce(); patch at source.
        with patch("yashigani.mcp.broker.query_mcp_decision",
                   new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=fake_eval_client_policies):
            await broker.enforce(ctx)

        caller_in_input = captured_base_input.get("caller", {})
        assert caller_in_input.get("agent_id") == "agent-bar", (
            "evaluate_client_policies base_input must carry caller.agent_id. "
            "Mirrors agent_router.py:326 caller+target pattern for MCP. v3.1 Phase 1."
        )
        assert caller_in_input.get("user_id") == "u2"

    @pytest.mark.asyncio
    async def test_orchestrator_caller_in_client_policy_base_input(self):
        """
        Orchestrator self-call: evaluate_client_policies base_input carries
        caller.agent_id = "gateway:orchestrator".
        """
        from yashigani.mcp.broker import McpBroker

        config = _make_broker_config()
        broker = McpBroker(config)
        ctx = _make_ctx(caller_agent_id="gateway:orchestrator", user_id="")

        captured_base_input: dict = {}

        async def fake_eval_client_policies(cfg, scope_kind, scope_id, direction, base_input):
            captured_base_input.update(base_input)
            return {"allow": True}

        with patch("yashigani.mcp.broker.query_mcp_decision",
                   new=AsyncMock(return_value=_opa_allow())), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=fake_eval_client_policies):
            await broker.enforce(ctx)

        caller_in_input = captured_base_input.get("caller", {})
        assert caller_in_input.get("agent_id") == "gateway:orchestrator"


# ─────────────────────────────────────────────────────────────────────────────
# E. mcp_router_runtime: caller_agent_id from request.state.agent_id
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpRuntimeCallerFromRequestState:
    """
    _handle_mcp_call_inner populates ctx.caller_agent_id from
    request.state.agent_id (set by AgentAuthMiddleware for authenticated agents).
    """

    def _make_jsonrpc(self, method: str = "tools/call", tool: str = "search") -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": "1",
            "method": method,
            "params": {"name": tool, "arguments": {}},
        }).encode()

    def _registry_with_broker(self, agent_name: str = "srv1"):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

        broker_mock = MagicMock()
        opa_dec = OpaDecision(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None,
        )
        broker_mock.enforce = AsyncMock(return_value=BrokerDecision(
            call_id="c1", allow=True, deny_reason="ok",
            opa_decision=opa_dec, issued_jwt="jwt",
        ))
        egress_dec = EgressDecision(
            allow=True, deny_reason="ok", policy_id="mcp.response_decision",
            code="MCP_RESULT_OK", user_message="ok", elapsed_ms=1,
        )
        broker_mock.enforce_result = AsyncMock(return_value=egress_dec)
        broker_mock._issuer = MagicMock()
        broker_mock._issuer.issue = MagicMock(return_value="session-jwt")

        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://srv1:8000",
            is_filesystem_agent=False,
            tenant_id="t1",
            agent_name=agent_name,
        )
        reg.register(agent_name, broker_mock, cfg)
        return reg, broker_mock

    @pytest.mark.asyncio
    async def test_caller_agent_id_from_request_state_agent_id(self):
        """
        When request.state.agent_id = "agent-foo", the McpCallContext
        passed to broker.enforce() must have caller_agent_id = "agent-foo".
        """
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        # Build a minimal mock request with state.agent_id set.
        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "agent-foo"
        req.headers = {"x-forwarded-user": "alice"}
        req.body = AsyncMock(return_value=self._make_jsonrpc())

        fake_upstream = json.dumps({
            "jsonrpc": "2.0", "id": "1",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        })

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=fake_upstream)
            return self_

        async def fake_aexit(self_, *a):
            pass

        with patch.object(McpHttpTransport, "__aenter__", fake_aenter), \
             patch.object(McpHttpTransport, "__aexit__", fake_aexit):
            await _handle_mcp_call_inner(
                agent_name="srv1",
                request=req,
                registry=reg,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed: "McpCallContext" = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_agent_id == "agent-foo", (
            "McpCallContext.caller_agent_id must be populated from "
            "request.state.agent_id for authenticated agent calls. v3.1 Phase 1."
        )

    @pytest.mark.asyncio
    async def test_no_agent_id_on_state_gives_none_caller(self):
        """
        When request.state has no agent_id attribute and no orchestration header,
        caller_agent_id must be None (unauthenticated/unidentified caller path).
        """
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        req = MagicMock()
        req.state = MagicMock(spec=[])  # no agent_id attribute
        req.headers = {}
        req.body = AsyncMock(return_value=self._make_jsonrpc())

        fake_upstream = json.dumps({
            "jsonrpc": "2.0", "id": "1",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        })

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=fake_upstream)
            return self_

        async def fake_aexit(self_, *a):
            pass

        with patch.object(McpHttpTransport, "__aenter__", fake_aenter), \
             patch.object(McpHttpTransport, "__aexit__", fake_aexit):
            await _handle_mcp_call_inner(
                agent_name="srv1",
                request=req,
                registry=reg,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_agent_id is None


# ─────────────────────────────────────────────────────────────────────────────
# F. mcp_router_runtime: orchestrator self-call via orch-depth header
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpRuntimeCallerFromOrchestrationHeader:
    """
    When X-Yashigani-Orchestration-Depth header is present AND request.state
    has no agent_id, caller_agent_id must be "gateway:orchestrator".

    This tests the gateway-mediated orchestrator self-call path: the orchestrator
    sets the depth header (via _self_call_headers) to identify itself when its
    MCP calls route through the gateway's /mcp/<agent_name> endpoint.
    """

    def _make_jsonrpc(self) -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}},
        }).encode()

    def _registry_with_broker(self, agent_name: str = "srv1"):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

        broker_mock = MagicMock()
        opa_dec = OpaDecision(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None,
        )
        broker_mock.enforce = AsyncMock(return_value=BrokerDecision(
            call_id="c1", allow=True, deny_reason="ok",
            opa_decision=opa_dec, issued_jwt="jwt",
        ))
        egress_dec = EgressDecision(
            allow=True, deny_reason="ok", policy_id="mcp.response_decision",
            code="MCP_RESULT_OK", user_message="ok", elapsed_ms=1,
        )
        broker_mock.enforce_result = AsyncMock(return_value=egress_dec)
        broker_mock._issuer = MagicMock()
        broker_mock._issuer.issue = MagicMock(return_value="session-jwt")

        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://srv1:8000",
            is_filesystem_agent=False,
            tenant_id="t1",
            agent_name=agent_name,
        )
        reg.register(agent_name, broker_mock, cfg)
        return reg, broker_mock

    @pytest.mark.asyncio
    async def test_orch_depth_header_sets_gateway_orchestrator_caller(self):
        """
        X-Yashigani-Orchestration-Depth header → ctx.caller_agent_id = "gateway:orchestrator".

        This is the gateway-mediated orchestrator self-call path detection.
        Phase 1 additive plumbing only — no enforcement on this field yet.
        """
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        req = MagicMock()
        req.state = MagicMock(spec=[])  # no agent_id
        # Simulate orchestrator self-call: the depth header is present.
        req.headers = {"x-yashigani-orchestration-depth": "1"}
        req.body = AsyncMock(return_value=self._make_jsonrpc())

        fake_upstream = json.dumps({
            "jsonrpc": "2.0", "id": "1",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        })

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=fake_upstream)
            return self_

        async def fake_aexit(self_, *a):
            pass

        with patch.object(McpHttpTransport, "__aenter__", fake_aenter), \
             patch.object(McpHttpTransport, "__aexit__", fake_aexit):
            await _handle_mcp_call_inner(
                agent_name="srv1",
                request=req,
                registry=reg,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_agent_id == "gateway:orchestrator", (
            "When X-Yashigani-Orchestration-Depth header is present, "
            "ctx.caller_agent_id must be 'gateway:orchestrator'. "
            "This is the reserved service identity for gateway-mediated "
            "orchestrator self-calls. v3.1 Phase 1."
        )

    @pytest.mark.asyncio
    async def test_agent_id_takes_priority_over_orch_header(self):
        """
        request.state.agent_id takes priority over the orchestration header.
        When both are present, the authenticated agent identity wins.
        """
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "real-agent"
        # Orchestration header also present (unusual, but we test priority).
        req.headers = {"x-yashigani-orchestration-depth": "2"}
        req.body = AsyncMock(return_value=self._make_jsonrpc())

        fake_upstream = json.dumps({
            "jsonrpc": "2.0", "id": "1",
            "result": {"content": [{"type": "text", "text": "ok"}]},
        })

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=fake_upstream)
            return self_

        async def fake_aexit(self_, *a):
            pass

        with patch.object(McpHttpTransport, "__aenter__", fake_aenter), \
             patch.object(McpHttpTransport, "__aexit__", fake_aexit):
            await _handle_mcp_call_inner(
                agent_name="srv1",
                request=req,
                registry=reg,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_agent_id == "real-agent", (
            "request.state.agent_id must take priority over the "
            "orchestration depth header."
        )
