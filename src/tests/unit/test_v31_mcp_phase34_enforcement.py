"""
v3.1 Phase 3+4 — MCP per-agent authorization enforcement tests.

Phase 4 — connection allow-list:
  McpBroker._check_connection_permit() uses resolve_boolean_grant(MCP_SERVER,
  server_id, org_id, group_ids=[], user_email=None) before forwarding.
  Deny-by-default: servers with no org grant are denied.

Phase 3 — tool allow-list:
  McpBroker._check_tool_permit() enforces McpCallContext.caller_allowed_tools.
  "gateway:orchestrator" is exempt.  None/empty list = no restriction.

Seeder:
  seed_mcp_grants() writes org-level MCP_SERVER grants idempotently.

Coverage:
  A. Phase 4 — connection allow-list
     A1. No permission_store → no-op (None)
     A2. Server with org grant → allowed
     A3. Server with no org grant → denied (deny-by-default)
     A4. gateway:orchestrator caller → allowed when org grant exists
     A5. enforce() integration: Phase 4 fires before OPA

  B. Phase 3 — tool allow-list
     B1. caller_allowed_tools=None → no restriction
     B2. caller_allowed_tools=[] → no restriction
     B3. caller_allowed_tools=["search"] AND tool="search" → allowed
     B4. caller_allowed_tools=["search"] AND tool="delete" → denied
     B5. gateway:orchestrator exempt (allowed regardless of tool)
     B6. caller_agent_id=None exempt (unauthenticated path)
     B7. tool_name=None exempt (non-tools/call action)
     B8. enforce() integration: Phase 3 fires after Phase 4 allow

  C. McpCallContext.caller_allowed_tools field
     C1. Field defaults to None
     C2. Field accepts a list

  D. Seeder
     D1. seed_mcp_grants writes org-level grants for all server_ids
     D2. seed_mcp_grants is idempotent (second call no-ops cleanly)
     D3. Empty server_ids list is a no-op
     D4. resolve_boolean_grant returns True after seeding

  E. mcp_router_runtime caller_allowed_tools resolution
     E1. identity_registry lookup populates caller_allowed_tools
     E2. No identity_registry → caller_allowed_tools stays None
     E3. gateway:orchestrator skips identity lookup
     E4. Caller not found in registry → caller_allowed_tools stays None
"""
from __future__ import annotations

import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _perm_store():
    """Build a PermissionStore backed by fakeredis."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(fakeredis.FakeRedis(decode_responses=False))


def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(
    server_id: str = "my-server",
    tool_name: Optional[str] = "search",
    caller_agent_id: Optional[str] = None,
    caller_allowed_tools: Optional[list[str]] = None,
):
    from yashigani.mcp._types import McpCallContext
    posture, binding = _make_posture_b()
    return McpCallContext(
        tenant_id="t1",
        agent_name=server_id,
        user_id="user-1",
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name=tool_name,
        server_id=server_id,
        caller_agent_id=caller_agent_id,
        caller_allowed_tools=caller_allowed_tools,
    )


def _make_broker(permission_store=None, org_id: str = "default"):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    issuer = McpJwtIssuer(tenant_id="t1")
    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id="t1",
        issuer=issuer,
        permission_store=permission_store,
        org_id=org_id,
    )
    return McpBroker(config=cfg)


def _opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True, deny_reason="ok", redact_args=set(),
        audit_capture=False, rate_limit_key=None, elapsed_ms=5,
    )


# ─────────────────────────────────────────────────────────────────────────────
# A. Phase 4 — connection allow-list
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase4ConnectionPermit:
    """McpBroker._check_connection_permit — Phase 4 allow-list enforcement."""

    def test_a1_no_permission_store_is_noop(self):
        """A1: No permission_store → _check_connection_permit returns None (no-op)."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx(server_id="my-server")
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            "When permission_store is None, _check_connection_permit must return "
            "None (no-op, backwards compatible). 3.1 Phase 4."
        )

    def test_a2_server_with_org_grant_allowed(self):
        """A2: Server with org-level allow grant → None (permitted)."""
        store = _perm_store()
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "my-server",
            BooleanGrantValue(allow=True),
        )
        broker = _make_broker(permission_store=store, org_id="default")
        ctx = _make_ctx(server_id="my-server")
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            "Server with org-level allow grant must be permitted. "
            "_check_connection_permit must return None. 3.1 Phase 4."
        )

    def test_a3_server_with_no_org_grant_denied(self):
        """A3: Server with no org grant → 'mcp_server_not_permitted' (deny-by-default)."""
        store = _perm_store()
        # No grant seeded for "unknown-server"
        broker = _make_broker(permission_store=store, org_id="default")
        ctx = _make_ctx(server_id="unknown-server")
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", (
            "Server with no org grant must be denied (deny-by-default). "
            "_check_connection_permit must return 'mcp_server_not_permitted'. "
            "3.1 Phase 4 / INV-1."
        )

    def test_a4_gateway_orchestrator_allowed_when_org_grant_exists(self):
        """A4: gateway:orchestrator caller + org grant → permitted."""
        store = _perm_store()
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "my-server",
            BooleanGrantValue(allow=True),
        )
        broker = _make_broker(permission_store=store, org_id="default")
        # The Phase 4 check is org-level only; caller identity doesn't affect it.
        ctx = _make_ctx(
            server_id="my-server",
            caller_agent_id="gateway:orchestrator",
        )
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            "gateway:orchestrator must be allowed when org grant exists. "
            "Phase 4 is org-level only (user_email=None); caller identity "
            "does not affect the org-ceiling check. 3.1 Phase 4."
        )

    @pytest.mark.asyncio
    async def test_a5_enforce_denies_on_phase4_before_opa(self):
        """A5: broker.enforce() returns deny before OPA when Phase 4 fires."""
        store = _perm_store()
        # No grant seeded → deny-by-default
        broker = _make_broker(permission_store=store, org_id="default")
        ctx = _make_ctx(server_id="forbidden-server")

        opa_called = []

        async def fake_query_mcp_decision(**kwargs):
            opa_called.append(True)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_query_mcp_decision), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow, (
            "broker.enforce() must deny when Phase 4 fires (no org grant). "
            "3.1 Phase 4 / deny-by-default."
        )
        assert decision.deny_reason == "mcp_server_not_permitted", (
            f"deny_reason must be 'mcp_server_not_permitted', got {decision.deny_reason!r}"
        )
        assert len(opa_called) == 0, (
            "OPA must NOT be queried when Phase 4 denies. "
            "Phase 4 is a pre-OPA gate. 3.1 Phase 4."
        )


# ─────────────────────────────────────────────────────────────────────────────
# B. Phase 3 — tool allow-list
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase3ToolPermit:
    """McpBroker._check_tool_permit — Phase 3 tool allow-list enforcement."""

    def test_b1_caller_allowed_tools_none_no_restriction(self):
        """B1: caller_allowed_tools=None → no restriction (None returned)."""
        broker = _make_broker()
        ctx = _make_ctx(caller_agent_id="agent-foo", caller_allowed_tools=None)
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "caller_allowed_tools=None means no per-caller restriction. "
            "_check_tool_permit must return None. 3.1 Phase 3."
        )

    def test_b2_caller_allowed_tools_empty_no_restriction(self):
        """B2: caller_allowed_tools=[] → no restriction (None returned)."""
        broker = _make_broker()
        ctx = _make_ctx(caller_agent_id="agent-foo", caller_allowed_tools=[])
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "caller_allowed_tools=[] (empty) means no per-caller restriction. "
            "_check_tool_permit must return None. 3.1 Phase 3."
        )

    def test_b3_tool_in_allowed_list_permitted(self):
        """B3: tool_name in caller_allowed_tools → permitted (None returned)."""
        broker = _make_broker()
        ctx = _make_ctx(
            tool_name="search",
            caller_agent_id="agent-foo",
            caller_allowed_tools=["search", "read_file"],
        )
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "tool_name='search' is in caller_allowed_tools=['search', 'read_file']. "
            "_check_tool_permit must return None (permitted). 3.1 Phase 3."
        )

    def test_b4_tool_not_in_allowed_list_denied(self):
        """B4: tool_name NOT in caller_allowed_tools → 'tool_not_permitted'."""
        broker = _make_broker()
        ctx = _make_ctx(
            tool_name="delete",
            caller_agent_id="agent-foo",
            caller_allowed_tools=["search", "read_file"],
        )
        result = broker._check_tool_permit(ctx)
        assert result == "tool_not_permitted", (
            "tool_name='delete' is NOT in caller_allowed_tools=['search', 'read_file']. "
            "_check_tool_permit must return 'tool_not_permitted'. 3.1 Phase 3."
        )

    def test_b5_gateway_orchestrator_exempt(self):
        """B5: gateway:orchestrator caller is exempt from tool restriction."""
        broker = _make_broker()
        ctx = _make_ctx(
            tool_name="delete",
            caller_agent_id="gateway:orchestrator",
            caller_allowed_tools=["search"],  # 'delete' NOT in list
        )
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "gateway:orchestrator must be exempt from per-caller tool restriction. "
            "_check_tool_permit must return None regardless of caller_allowed_tools. "
            "3.1 Phase 3."
        )

    def test_b6_none_caller_agent_id_exempt(self):
        """B6: caller_agent_id=None (unauthenticated) → no tool restriction."""
        broker = _make_broker()
        ctx = _make_ctx(
            tool_name="delete",
            caller_agent_id=None,
            caller_allowed_tools=["search"],
        )
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "caller_agent_id=None (unauthenticated) must be exempt from tool restriction. "
            "_check_tool_permit must return None. 3.1 Phase 3."
        )

    def test_b7_none_tool_name_exempt(self):
        """B7: tool_name=None (non-tools/call action) → no restriction."""
        broker = _make_broker()
        ctx = _make_ctx(
            tool_name=None,
            caller_agent_id="agent-foo",
            caller_allowed_tools=["search"],
        )
        result = broker._check_tool_permit(ctx)
        assert result is None, (
            "tool_name=None (not a tools/call action) must be exempt from tool restriction. "
            "_check_tool_permit must return None. 3.1 Phase 3."
        )

    @pytest.mark.asyncio
    async def test_b8_enforce_denies_on_phase3_after_phase4_allow(self):
        """B8: broker.enforce() denies for Phase 3 after Phase 4 allows."""
        store = _perm_store()
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        # Seed org grant so Phase 4 passes
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "my-server",
            BooleanGrantValue(allow=True),
        )
        broker = _make_broker(permission_store=store, org_id="default")
        # caller has restricted tool list that doesn't include "delete"
        ctx = _make_ctx(
            server_id="my-server",
            tool_name="delete",
            caller_agent_id="agent-foo",
            caller_allowed_tools=["search"],
        )

        opa_called = []

        async def fake_query_mcp_decision(**kwargs):
            opa_called.append(True)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_query_mcp_decision), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow, (
            "broker.enforce() must deny when Phase 3 fires (tool not in allow-list). "
            "3.1 Phase 3."
        )
        assert decision.deny_reason == "tool_not_permitted", (
            f"deny_reason must be 'tool_not_permitted', got {decision.deny_reason!r}"
        )
        assert len(opa_called) == 0, (
            "OPA must NOT be queried when Phase 3 denies. "
            "Phase 3 fires before the OPA gate. 3.1 Phase 3."
        )


# ─────────────────────────────────────────────────────────────────────────────
# C. McpCallContext.caller_allowed_tools field
# ─────────────────────────────────────────────────────────────────────────────

class TestCallerAllowedToolsField:
    """McpCallContext.caller_allowed_tools — field existence and defaults."""

    def test_c1_field_defaults_to_none(self):
        """C1: caller_allowed_tools defaults to None when not supplied."""
        ctx = _make_ctx()
        assert ctx.caller_allowed_tools is None, (
            "McpCallContext.caller_allowed_tools must default to None. "
            "3.1 Phase 3 additive field."
        )

    def test_c2_field_accepts_list(self):
        """C2: caller_allowed_tools stores an arbitrary tool list."""
        ctx = _make_ctx(caller_allowed_tools=["search", "read_file", "write_file"])
        assert ctx.caller_allowed_tools == ["search", "read_file", "write_file"]

    def test_c3_existing_fields_unaffected(self):
        """C3: Adding caller_allowed_tools must not disturb existing McpCallContext fields."""
        ctx = _make_ctx(caller_allowed_tools=["search"])
        assert ctx.tenant_id == "t1"
        assert ctx.tool_name == "search"
        assert ctx.caller_agent_id is None  # separate from caller_allowed_tools
        assert ctx.server_id == "my-server"


# ─────────────────────────────────────────────────────────────────────────────
# D. Seeder
# ─────────────────────────────────────────────────────────────────────────────

class TestSeedMcpGrants:
    """seed_mcp_grants — idempotent org-level grant seeding."""

    def test_d1_seeds_org_level_grants(self):
        """D1: seed_mcp_grants writes org-level MCP_SERVER grants for all server_ids."""
        from yashigani.permissions import seed_mcp_grants
        from yashigani.permissions.model import ResourceType

        store = _perm_store()
        seed_mcp_grants(store, ["server-a", "server-b"], "my-org")

        grant_a = store.get_boolean_grant(ResourceType.MCP_SERVER, "org", "my-org", "server-a")
        grant_b = store.get_boolean_grant(ResourceType.MCP_SERVER, "org", "my-org", "server-b")

        assert grant_a is not None and grant_a.allow is True, (
            "seed_mcp_grants must write allow=True for server-a in org my-org. "
            "3.1 Phase 4 / seeder B1."
        )
        assert grant_b is not None and grant_b.allow is True, (
            "seed_mcp_grants must write allow=True for server-b in org my-org. "
            "3.1 Phase 4 / seeder B1."
        )

    def test_d2_idempotent_second_call_no_error(self):
        """D2: seed_mcp_grants is idempotent — calling twice raises no error."""
        from yashigani.permissions import seed_mcp_grants
        from yashigani.permissions.model import ResourceType

        store = _perm_store()
        seed_mcp_grants(store, ["server-a"], "my-org")
        seed_mcp_grants(store, ["server-a"], "my-org")  # second call must not fail

        grant = store.get_boolean_grant(ResourceType.MCP_SERVER, "org", "my-org", "server-a")
        assert grant is not None and grant.allow is True

    def test_d3_empty_server_ids_noop(self):
        """D3: seed_mcp_grants with empty server_ids list is a no-op."""
        from yashigani.permissions import seed_mcp_grants
        # Must not raise
        store = _perm_store()
        seed_mcp_grants(store, [], "my-org")

    def test_d4_resolve_returns_true_after_seeding(self):
        """D4: resolve_boolean_grant returns True for a server_id after seeding."""
        from yashigani.permissions import seed_mcp_grants, resolve_boolean_grant
        from yashigani.permissions.model import ResourceType

        store = _perm_store()
        seed_mcp_grants(store, ["my-mcp"], "default")

        allowed = resolve_boolean_grant(
            ResourceType.MCP_SERVER,
            "my-mcp",
            org_id="default",
            group_ids=[],
            principal_scope=None,
            principal_id=None,
            store=store,
        )
        assert allowed is True, (
            "resolve_boolean_grant must return True for a server_id that was seeded "
            "with allow=True at org level. 3.1 Phase 4 / INV-1."
        )

    def test_d5_unseeded_server_denied_by_default(self):
        """D5: resolve_boolean_grant returns False for un-seeded server (deny-by-default)."""
        from yashigani.permissions import resolve_boolean_grant
        from yashigani.permissions.model import ResourceType

        store = _perm_store()
        # No seeding done

        allowed = resolve_boolean_grant(
            ResourceType.MCP_SERVER,
            "unregistered-server",
            org_id="default",
            group_ids=[],
            principal_scope=None,
            principal_id=None,
            store=store,
        )
        assert allowed is False, (
            "resolve_boolean_grant must return False for un-seeded server. "
            "Deny-by-default (INV-1) applies when no org grant exists. "
            "3.1 Phase 4."
        )


# ─────────────────────────────────────────────────────────────────────────────
# E. mcp_router_runtime caller_allowed_tools resolution
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpRuntimeCallerAllowedToolsResolution:
    """
    _handle_mcp_call_inner populates ctx.caller_allowed_tools from the
    identity registry (keyed by caller_agent_id slug).
    """

    def _make_jsonrpc(self, tool: str = "search") -> bytes:
        return json.dumps({
            "jsonrpc": "2.0", "id": "1", "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
        }).encode()

    def _registry_with_broker(self, agent_name: str = "srv1", allow: bool = True):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

        broker_mock = MagicMock()
        opa_dec = OpaDecision(allow=True, deny_reason="ok", redact_args=set(),
                              audit_capture=False, rate_limit_key=None)
        broker_mock.enforce = AsyncMock(return_value=BrokerDecision(
            call_id="c1", allow=allow, deny_reason="ok" if allow else "mcp_server_not_permitted",
            opa_decision=opa_dec, issued_jwt="jwt",
        ))
        egress_dec = EgressDecision(allow=True, deny_reason="ok",
                                    policy_id="mcp.response_decision",
                                    code="MCP_RESULT_OK", user_message="ok", elapsed_ms=1)
        broker_mock.enforce_result = AsyncMock(return_value=egress_dec)
        broker_mock._issuer = MagicMock()
        broker_mock._issuer.issue = MagicMock(return_value="session-jwt")

        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://srv1:8000", is_filesystem_agent=False,
            tenant_id="t1", agent_name=agent_name,
        )
        reg.register(agent_name, broker_mock, cfg)
        return reg, broker_mock

    def _make_identity_registry(self, slug: str, allowed_tools: Optional[list[str]]):
        """Build a minimal mock identity registry."""
        registry = MagicMock()
        identity_rec = {"allowed_tools": allowed_tools} if allowed_tools else {}
        registry.get_by_slug = MagicMock(
            side_effect=lambda s: identity_rec if s == slug else None
        )
        registry.get = MagicMock(return_value=None)
        return registry

    @pytest.mark.asyncio
    async def test_e1_identity_registry_populates_caller_allowed_tools(self):
        """
        E1: When identity_registry.get_by_slug(caller_agent_id) returns a record
        with allowed_tools, ctx.caller_allowed_tools is populated on the ctx
        passed to broker.enforce().
        """
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")
        id_registry = self._make_identity_registry("agent-foo", ["search"])

        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "agent-foo"
        req.headers = {"x-forwarded-user": "alice"}
        req.body = AsyncMock(return_value=self._make_jsonrpc("search"))

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
                identity_registry=id_registry,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_allowed_tools == ["search"], (
            "McpCallContext.caller_allowed_tools must be populated from "
            "identity_registry.get_by_slug(caller_agent_id).allowed_tools. "
            "3.1 Phase 3."
        )

    @pytest.mark.asyncio
    async def test_e2_no_identity_registry_caller_allowed_tools_none(self):
        """E2: No identity_registry → caller_allowed_tools stays None."""
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

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
                identity_registry=None,  # no registry
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_allowed_tools is None, (
            "Without identity_registry, caller_allowed_tools must stay None. "
            "3.1 Phase 3."
        )

    @pytest.mark.asyncio
    async def test_e3_gateway_orchestrator_skips_identity_lookup(self):
        """E3: gateway:orchestrator skips identity registry lookup."""
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")
        id_registry = MagicMock()
        id_registry.get_by_slug = MagicMock(return_value=None)

        req = MagicMock()
        req.state = MagicMock(spec=[])  # no agent_id
        req.headers = {"x-yashigani-orchestration-depth": "1",
                       "x-forwarded-user": "alice"}
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
                identity_registry=id_registry,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_agent_id == "gateway:orchestrator"
        assert ctx_passed.caller_allowed_tools is None, (
            "gateway:orchestrator must skip identity registry lookup. "
            "caller_allowed_tools must stay None (orchestrator is unrestricted). "
            "3.1 Phase 3."
        )
        # Verify get_by_slug was not called with "gateway:orchestrator"
        for c in id_registry.get_by_slug.call_args_list:
            assert c.args[0] != "gateway:orchestrator", (
                "identity_registry.get_by_slug must not be called with "
                "'gateway:orchestrator'. 3.1 Phase 3."
            )

    @pytest.mark.asyncio
    async def test_e4_caller_not_found_in_registry_allowed_tools_none(self):
        """E4: Caller not found in identity registry → caller_allowed_tools stays None."""
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")
        # Registry returns None for any slug
        id_registry = MagicMock()
        id_registry.get_by_slug = MagicMock(return_value=None)
        id_registry.get = MagicMock(return_value=None)

        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "unknown-agent"
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
                identity_registry=id_registry,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx_passed = broker_mock.enforce.call_args.args[0]
        assert ctx_passed.caller_allowed_tools is None, (
            "When caller is not found in identity registry, "
            "caller_allowed_tools must stay None (no restriction). "
            "3.1 Phase 3."
        )
