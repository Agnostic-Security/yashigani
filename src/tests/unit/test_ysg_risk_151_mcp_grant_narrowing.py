# Last updated: 2026-07-27T00:00:00+00:00
"""
YSG-RISK-151 — per-group/per-principal mcp_server grant narrowing.

Before this fix, McpBroker._check_connection_permit() called
resolve_boolean_grant(MCP_SERVER, ..., group_ids=[], principal_scope=None,
principal_id=None) unconditionally — an admin who wrote a group- or
user/agent-scope mcp_server DENY (with its own audit event, via
POST /admin/permissions/declarations/...) had that grant silently ignored:
only the org-level ceiling was ever evaluated. This is config-theater — the
UI/API accepts and persists the narrower grant, but the broker never reads it.

This fix:
  - adds McpCallContext.caller_group_ids / caller_principal_scope /
    caller_principal_id (mcp/_types.py).
  - McpBroker._check_connection_permit() now passes ctx.caller_group_ids /
    ctx.caller_principal_scope / ctx.caller_principal_id into
    resolve_boolean_grant() instead of hardcoded [] / None / None.
  - mcp_router_runtime resolves group_ids (IdentityRecord.groups) and
    principal_scope="agent"/principal_id=caller_agent_id from the SAME
    identity-registry lookup already used for caller_allowed_tools (3.1
    Phase 3), and threads them onto both the tools/call ctx and the
    prompts/get + resources/read ctx_read (YSG-RISK-145).

Test strategy: real McpBroker + real PermissionStore (fakeredis-backed) —
the actual resolve_boolean_grant() narrowing logic runs, not a mocked
verdict.
"""
from __future__ import annotations

import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.mcp._types import BrokerDecision, McpCallContext, McpPosture, OpaDecision, PostureBinding
from yashigani.mcp._transport_http import McpHttpTransport as _RealTransport


def _perm_store():
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(fakeredis.FakeRedis(decode_responses=False))


def _make_broker(permission_store, org_id: str = "default"):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    issuer = McpJwtIssuer(tenant_id="t1")
    cfg = McpBrokerConfig(
        opa_url="http://opa:8181", tenant_id="t1", issuer=issuer,
        permission_store=permission_store, org_id=org_id,
    )
    return McpBroker(config=cfg)


def _make_ctx(
    server_id: str = "my-server",
    caller_group_ids: Optional[list[str]] = None,
    caller_principal_scope: Optional[str] = None,
    caller_principal_id: Optional[str] = None,
) -> McpCallContext:
    posture = McpPosture.MCP_B
    binding = PostureBinding.for_posture(posture)
    return McpCallContext(
        tenant_id="t1", agent_name=server_id, user_id="user-1",
        posture=posture, posture_binding=binding, action="mcp.tools.call",
        tool_name="search", server_id=server_id,
        caller_group_ids=caller_group_ids or [],
        caller_principal_scope=caller_principal_scope,
        caller_principal_id=caller_principal_id,
    )


def _org_allow(store, server_id: str, org_id: str = "default") -> None:
    from yashigani.permissions import ResourceType
    from yashigani.permissions.model import BooleanGrantValue
    store.set_boolean_grant(
        ResourceType.MCP_SERVER, "org", org_id, server_id, BooleanGrantValue(allow=True),
    )


def _group_deny(store, server_id: str, group_id: str) -> None:
    from yashigani.permissions import ResourceType
    from yashigani.permissions.model import BooleanGrantValue
    store.set_boolean_grant(
        ResourceType.MCP_SERVER, "group", group_id, server_id, BooleanGrantValue(allow=False),
    )


def _agent_deny(store, server_id: str, agent_id: str) -> None:
    from yashigani.permissions import ResourceType
    from yashigani.permissions.model import BooleanGrantValue
    store.set_boolean_grant(
        ResourceType.MCP_SERVER, "agent", agent_id, server_id, BooleanGrantValue(allow=False),
    )


class TestGroupScopeGrantNarrowing:
    """A group-scope mcp_server DENY must actually block a caller in that
    group, even though the org grant allows the server."""

    def test_group_deny_blocks_member(self):
        store = _perm_store()
        _org_allow(store, "my-server")
        _group_deny(store, "my-server", "grp-restricted")
        broker = _make_broker(store)

        ctx = _make_ctx(caller_group_ids=["grp-restricted"])
        result = broker._check_connection_permit(ctx)

        assert result == "mcp_server_not_permitted", (
            "A group-scope deny must block a caller whose caller_group_ids "
            "includes that group — this is the YSG-RISK-151 regression: "
            "before the fix, group_ids was always hardcoded [] so this "
            "grant could never be evaluated and rotation/deny silently "
            "never applied."
        )

    def test_org_allow_with_unrelated_group_still_allows(self):
        """Sanity: a group deny for a DIFFERENT group must not affect a
        caller who is not a member of it (narrowing, not a blanket deny)."""
        store = _perm_store()
        _org_allow(store, "my-server")
        _group_deny(store, "my-server", "grp-restricted")
        broker = _make_broker(store)

        ctx = _make_ctx(caller_group_ids=["grp-other"])
        result = broker._check_connection_permit(ctx)

        assert result is None

    def test_no_group_ids_org_allow_still_works(self):
        """Sanity: org-level grants continue to work with no group narrowing
        (caller_group_ids=[], the pre-fix default) — the fix must not break
        the existing org-only path."""
        store = _perm_store()
        _org_allow(store, "my-server")
        broker = _make_broker(store)

        ctx = _make_ctx(caller_group_ids=[])
        result = broker._check_connection_permit(ctx)

        assert result is None


class TestAgentPrincipalScopeGrantNarrowing:
    """An agent-scope mcp_server DENY must block that specific agent
    principal even though the org grant allows the server."""

    def test_agent_scope_deny_blocks_that_agent(self):
        store = _perm_store()
        _org_allow(store, "my-server")
        _agent_deny(store, "my-server", "compromised-agent")
        broker = _make_broker(store)

        ctx = _make_ctx(
            caller_principal_scope="agent", caller_principal_id="compromised-agent",
        )
        result = broker._check_connection_permit(ctx)

        assert result == "mcp_server_not_permitted"

    def test_agent_scope_deny_does_not_block_other_agent(self):
        store = _perm_store()
        _org_allow(store, "my-server")
        _agent_deny(store, "my-server", "compromised-agent")
        broker = _make_broker(store)

        ctx = _make_ctx(
            caller_principal_scope="agent", caller_principal_id="innocent-agent",
        )
        result = broker._check_connection_permit(ctx)

        assert result is None

    def test_principal_scope_none_skips_principal_tier(self):
        """caller_principal_scope=None (e.g. gateway:orchestrator / unidentified
        caller) must skip the principal tier entirely — org+group ceiling only,
        matching the documented resolve_boolean_grant contract."""
        store = _perm_store()
        _org_allow(store, "my-server")
        _agent_deny(store, "my-server", "some-agent")  # unrelated — scope is None
        broker = _make_broker(store)

        ctx = _make_ctx(caller_principal_scope=None, caller_principal_id=None)
        result = broker._check_connection_permit(ctx)

        assert result is None


# ---------------------------------------------------------------------------
# Router-level: mcp_router_runtime resolves group_ids/principal_scope/id from
# the identity registry and threads them onto McpCallContext.
# ---------------------------------------------------------------------------

class _FakeIdentityRecord:
    def __init__(self, allowed_tools=None, groups=None):
        self.allowed_tools = allowed_tools or []
        self.groups = groups or []


class _FakeIdentityRegistry:
    def __init__(self, records: dict):
        self._records = records

    def get_by_slug(self, slug: str):
        return self._records.get(slug)

    def get(self, agent_id: str):
        return self._records.get(agent_id)


def _make_allow_ingress_decision(jwt: str = "test-jwt") -> BrokerDecision:
    return BrokerDecision(
        call_id="test-call", allow=True, deny_reason="ok",
        opa_decision=OpaDecision(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None,
        ),
        issued_jwt=jwt, chain_depth=0, elapsed_ms=1,
    )


def _patch_transport_forward(fake_response: str):
    async def fake_aenter(self: _RealTransport) -> _RealTransport:
        self.forward = AsyncMock(return_value=fake_response)  # type: ignore[method-assign]
        return self
    return patch.object(_RealTransport, "__aenter__", fake_aenter)


_TOOLS_CALL_BODY = json.dumps({
    "jsonrpc": "2.0", "id": "1", "method": "tools/call",
    "params": {"name": "search", "arguments": {}},
})

_UPSTREAM_RESULT = json.dumps({
    "jsonrpc": "2.0", "id": "1", "result": {"content": []},
})


class TestRouterResolvesGroupAndPrincipalOntoCtx:
    """Direct-call pattern (mirrors test_v31_mcp_caller_identity.py's
    request.state.agent_id tests) — exercises _handle_mcp_call_inner without
    the full ASGI/TestClient stack, so request.state.agent_id can be set
    directly (no AgentAuthMiddleware needed)."""

    @staticmethod
    def _registry_with_broker(agent_name: str):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        broker_mock = MagicMock()
        broker_mock.enforce = AsyncMock(return_value=_make_allow_ingress_decision())
        broker_mock.enforce_result = AsyncMock(return_value=MagicMock(allow=True))
        broker_mock._issuer = MagicMock()
        broker_mock._issuer.issue = MagicMock(return_value="session-jwt")

        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://srv1:8000", is_filesystem_agent=False,
            tenant_id="t1", agent_name=agent_name,
        )
        reg.register(agent_name, broker_mock, cfg)
        return reg, broker_mock

    @pytest.mark.asyncio
    async def test_ctx_carries_group_ids_and_agent_principal_from_registry(self):
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        identity_registry = _FakeIdentityRegistry({
            "agent-foo": _FakeIdentityRecord(groups=["grp-a", "grp-b"]),
        })

        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "agent-foo"
        req.headers = {}
        req.body = AsyncMock(return_value=_TOOLS_CALL_BODY.encode())

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=_UPSTREAM_RESULT)  # type: ignore[method-assign]
            return self_

        async def fake_aexit(self_, *a):
            pass

        with (
            patch.object(McpHttpTransport, "__aenter__", fake_aenter),
            patch.object(McpHttpTransport, "__aexit__", fake_aexit),
        ):
            await _handle_mcp_call_inner(
                agent_name="srv1", request=req, registry=reg,
                identity_registry=identity_registry,
            )

        broker_mock.enforce.assert_awaited_once()
        ctx = broker_mock.enforce.call_args.args[0]
        assert ctx.caller_agent_id == "agent-foo"
        assert sorted(ctx.caller_group_ids) == ["grp-a", "grp-b"], (
            "YSG-RISK-151: McpCallContext.caller_group_ids must be populated "
            "from IdentityRecord.groups via the SAME identity-registry lookup "
            "already used for caller_allowed_tools."
        )
        assert ctx.caller_principal_scope == "agent"
        assert ctx.caller_principal_id == "agent-foo"

    @pytest.mark.asyncio
    async def test_no_identity_registry_leaves_defaults(self):
        """No identity_registry wired → caller_group_ids stays empty and
        principal_scope/id stay None (never crashes, never a stray narrowing
        gate — matches the pre-fix behaviour for installs without the
        identity registry configured)."""
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")

        req = MagicMock()
        req.state = MagicMock()
        req.state.agent_id = "agent-foo"
        req.headers = {}
        req.body = AsyncMock(return_value=_TOOLS_CALL_BODY.encode())

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=_UPSTREAM_RESULT)  # type: ignore[method-assign]
            return self_

        async def fake_aexit(self_, *a):
            pass

        with (
            patch.object(McpHttpTransport, "__aenter__", fake_aenter),
            patch.object(McpHttpTransport, "__aexit__", fake_aexit),
        ):
            await _handle_mcp_call_inner(agent_name="srv1", request=req, registry=reg)

        ctx = broker_mock.enforce.call_args.args[0]
        assert ctx.caller_group_ids == []
        assert ctx.caller_principal_scope is None
        assert ctx.caller_principal_id is None

    @pytest.mark.asyncio
    async def test_gateway_orchestrator_skips_identity_lookup(self):
        """"gateway:orchestrator" is exempt from the identity-registry lookup
        (same as the existing caller_allowed_tools exemption) — group/
        principal narrowing stays at defaults for the orchestrator's own
        self-calls."""
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner
        from yashigani.mcp._transport_http import McpHttpTransport

        reg, broker_mock = self._registry_with_broker("srv1")
        identity_registry = _FakeIdentityRegistry({})  # lookup would 404 if attempted

        req = MagicMock()
        req.state = MagicMock(spec=[])  # no agent_id attribute
        req.headers = {
            "x-yashigani-orchestration-depth": "0",
            "x-yashigani-internal-bearer": "test-token",
        }
        req.body = AsyncMock(return_value=_TOOLS_CALL_BODY.encode())

        async def fake_aenter(self_):
            self_.forward = AsyncMock(return_value=_UPSTREAM_RESULT)  # type: ignore[method-assign]
            return self_

        async def fake_aexit(self_, *a):
            pass

        with (
            patch.object(McpHttpTransport, "__aenter__", fake_aenter),
            patch.object(McpHttpTransport, "__aexit__", fake_aexit),
            patch(
                "yashigani.gateway.mcp_router_runtime._mesh_caller_is_internal",
                return_value=True,
            ),
        ):
            await _handle_mcp_call_inner(
                agent_name="srv1", request=req, registry=reg,
                identity_registry=identity_registry,
            )

        ctx = broker_mock.enforce.call_args.args[0]
        assert ctx.caller_agent_id == "gateway:orchestrator"
        assert ctx.caller_group_ids == []
        assert ctx.caller_principal_scope is None
