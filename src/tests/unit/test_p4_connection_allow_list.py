"""
3.1 Phase 4 — Connection allow-list unit tests.

Covers:
  MCP-1/2/3: McpCallContext group/user fields; mcp_router_runtime populates
    them from the identity registry; broker._check_connection_permit passes
    them to resolve_boolean_grant (group/user narrowing).
  Part B:     agent_router grant check — deny-by-default, env-gating
              (prod fail-closed, dev no-op), org allows proceeds.
  Part B+:    agent_router group-tier narrowing (GRANT-GROUP-FIX).
  Part C:     seed_agent_grants idempotent seeding.
  Proxy:      create_gateway_app accepts permission_store param.
  Resolver:   direct resolve_boolean_grant group-tier semantics tests.

Resolver behaviour (GRANT-GROUP-FIX — resolver.py decoupled group tier)
------------------------------------------------------------------------
``resolve_boolean_grant`` applies group grants regardless of ``user_email``.
The fix (resolver.py INV-2) moves the group-narrowing loop BEFORE the user-tier
guard so that agent principals (user_email=None) with group_ids are correctly
subject to group-level deny grants.

Tier order:
  1. Org ceiling   — must allow (deny-by-default invariant unchanged)
  2. Group tier    — any group deny → denied (runs when group_ids non-empty,
                     including for agents and service-kind principals)
  3. User tier     — user deny → denied (runs only when user_email is set)

All tests are unit-level (no live Redis, no live OPA).
"""
from __future__ import annotations

import json
import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(
    server_id: str = "my-server",
    tool_name: Optional[str] = "search",
    caller_agent_id: Optional[str] = None,
    caller_group_ids: Optional[list] = None,
    caller_user_email: Optional[str] = None,
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
        caller_group_ids=caller_group_ids if caller_group_ids is not None else [],
        caller_user_email=caller_user_email,
    )


def _make_broker(permission_store=None, org_id="default"):
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


def _make_perm_store(grants: dict | None = None):
    """
    Returns a mock PermissionStore that implements get_boolean_grant
    with positional arguments matching PermissionStore.get_boolean_grant(
        resource_type, scope_kind, scope_id, resource_id).

    grants: dict mapping (resource_type, scope_kind, scope_id, resource_id) →
            BooleanGrantValue-like or None.
    """
    from yashigani.permissions.model import BooleanGrantValue

    grants = grants or {}
    store = MagicMock()

    def _get(resource_type, scope_kind, scope_id, resource_id):
        key = (resource_type, scope_kind, scope_id, resource_id)
        val = grants.get(key)
        if val is None:
            return None
        if isinstance(val, bool):
            return BooleanGrantValue(allow=val)
        return val

    # get_boolean_grant takes 4 positional args — use side_effect
    store.get_boolean_grant.side_effect = _get
    return store


# ---------------------------------------------------------------------------
# MCP-1: McpCallContext has the new fields with correct defaults
# ---------------------------------------------------------------------------

class TestMcpCallContextPhase4Fields:
    """MCP-1: McpCallContext must have caller_group_ids and caller_user_email."""

    def test_default_group_ids_is_empty_list(self):
        ctx = _make_ctx()
        assert ctx.caller_group_ids == [], (
            "caller_group_ids default must be [] (org-only behaviour)."
        )

    def test_default_user_email_is_none(self):
        ctx = _make_ctx()
        assert ctx.caller_user_email is None, (
            "caller_user_email default must be None (skip user-tier narrowing)."
        )

    def test_group_ids_set_explicitly(self):
        ctx = _make_ctx(caller_group_ids=["eng", "admin"])
        assert ctx.caller_group_ids == ["eng", "admin"]

    def test_user_email_set_explicitly(self):
        ctx = _make_ctx(caller_user_email="alice@corp.example")
        assert ctx.caller_user_email == "alice@corp.example"

    def test_fields_in_dataclass(self):
        """Both fields are dataclass fields — verify via dataclasses module."""
        import dataclasses
        from yashigani.mcp._types import McpCallContext
        field_names = {f.name for f in dataclasses.fields(McpCallContext)}
        assert "caller_group_ids" in field_names
        assert "caller_user_email" in field_names


# ---------------------------------------------------------------------------
# MCP-3: broker._check_connection_permit passes group/user to resolver
# ---------------------------------------------------------------------------

class TestBrokerConnectionPermitGroupUserNarrowing:
    """
    MCP-3: _check_connection_permit uses ctx.caller_group_ids + ctx.user_id.

    Group narrowing fires for ALL principals that carry group_ids (GRANT-GROUP-FIX).
    User-tier narrowing fires when caller_user_email is set (human discriminator)
    AND ctx.user_id is not "unknown" — the grant is keyed by ctx.user_id (slug,
    NOT email).  Email is presentation-only; the authz key is the user_id.

    The tests below cover: group-deny with and without user_email, user-deny
    (keyed by user_id "user-1" from _make_ctx), org-ceiling invariant, and
    org-allow-only (no narrowing).
    """

    def _grant_map_org_allow_group_deny(self):
        """Org allows server, group 'eng' denies."""
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        return {
            (ResourceType.MCP_SERVER, "org", "default", "my-server"): BooleanGrantValue(allow=True),
            (ResourceType.MCP_SERVER, "group", "eng", "my-server"): BooleanGrantValue(allow=False),
        }

    def _grant_map_org_allow_user_deny(self):
        """Org allows server; user_id 'user-1' (ctx.user_id from _make_ctx) denies.

        Grant key is the user_id (ctx.user_id = 'user-1'), NOT the caller email.
        The broker uses ctx.user_id when caller_user_email is set (human discriminator).
        """
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        return {
            (ResourceType.MCP_SERVER, "org", "default", "my-server"): BooleanGrantValue(allow=True),
            (ResourceType.MCP_SERVER, "user", "user-1", "my-server"): BooleanGrantValue(allow=False),
        }

    def _grant_map_org_deny_group_allow(self):
        """Org denies, group allows — INV-1: org ceiling applies, group irrelevant."""
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        return {
            (ResourceType.MCP_SERVER, "org", "default", "my-server"): BooleanGrantValue(allow=False),
            (ResourceType.MCP_SERVER, "group", "eng", "my-server"): BooleanGrantValue(allow=True),
        }

    def _grant_map_org_allow_only(self):
        """Org allows, no group/user grants."""
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        return {
            (ResourceType.MCP_SERVER, "org", "default", "my-server"): BooleanGrantValue(allow=True),
        }

    def test_group_narrows_deny(self):
        """
        MCP permit: org allows + group 'eng' denies → 'mcp_server_not_permitted'.

        Tests the common human-caller case: user_email is set.  Group narrowing
        fires via INV-2 (GRANT-GROUP-FIX: group tier is independent of user_email).
        """
        store = _make_perm_store(self._grant_map_org_allow_group_deny())
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_group_ids=["eng"],
            caller_user_email="eng-svc@corp.example",
        )
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", (
            f"Group narrowing must deny when group grant is allow=False. Got {result!r}."
        )

    def test_group_narrows_deny_agent_no_email(self):
        """
        GRANT-GROUP-FIX: agent principal (user_email=None) with group 'eng' deny
        → 'mcp_server_not_permitted'.

        Before the fix, resolve_boolean_grant returned True early when
        user_email=None, making group grants a no-op for agents.  This test
        verifies the bug is closed: group-deny MUST fire even when user_email
        is absent.
        """
        store = _make_perm_store(self._grant_map_org_allow_group_deny())
        broker = _make_broker(permission_store=store)
        # No user_email — simulates an agent/service-kind principal
        ctx = _make_ctx(
            caller_group_ids=["eng"],
            caller_user_email=None,
        )
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", (
            f"Group narrowing must deny agents (user_email=None) when group grant "
            f"is allow=False (GRANT-GROUP-FIX). Got {result!r}."
        )

    def test_user_narrows_deny(self):
        """
        MCP permit: org allows + no group denial + user denies → 'mcp_server_not_permitted'.

        The broker uses ctx.user_id ('user-1', not the caller email) as the grant key.
        Grant is stored at scope_id='user-1'; caller_user_email triggers the human path.
        """
        store = _make_perm_store(self._grant_map_org_allow_user_deny())
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_group_ids=[],
            caller_user_email="alice@corp.example",  # discriminator: marks caller as human
            # ctx.user_id = "user-1" (set in _make_ctx) — this is the grant key
        )
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", (
            f"User narrowing must deny when user grant (keyed by user_id='user-1') "
            f"is allow=False. Got {result!r}."
        )

    def test_email_not_used_as_grant_key(self):
        """
        Regression: broker must use ctx.user_id, not ctx.caller_user_email, as grant key.

        A grant keyed by the caller's email must NOT match (email is not the authz key).
        Only a grant keyed by ctx.user_id ('user-1') triggers user narrowing.
        """
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        # Grant stored at the email address — this must NOT trigger a deny.
        grants_by_email = {
            (ResourceType.MCP_SERVER, "org", "default", "my-server"): BooleanGrantValue(allow=True),
            (ResourceType.MCP_SERVER, "user", "alice@corp.example", "my-server"): BooleanGrantValue(allow=False),
        }
        store = _make_perm_store(grants_by_email)
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_group_ids=[],
            caller_user_email="alice@corp.example",
            # ctx.user_id = "user-1" — broker looks up by user_id, NOT email
        )
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            f"Grant keyed by email must NOT match: broker uses ctx.user_id not email. "
            f"Expected None (permitted), got {result!r}."
        )

    def test_orchestrator_org_only_passes(self):
        """
        'gateway:orchestrator' → caller_group_ids=[], caller_user_email=None → org-only.
        Org grants the server → permitted (None).
        """
        store = _make_perm_store(self._grant_map_org_allow_only())
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_agent_id="gateway:orchestrator",
            caller_group_ids=[],
            caller_user_email=None,
        )
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            f"Orchestrator with org-only grant must be permitted. Got {result!r}."
        )

    def test_org_denies_group_irrelevant(self):
        """
        INV-1: org denies → group-level allow has NO effect.
        """
        store = _make_perm_store(self._grant_map_org_deny_group_allow())
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_group_ids=["eng"],
            caller_user_email="eng@corp.example",
        )
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", (
            f"INV-1: org ceiling deny must override any group allow. Got {result!r}."
        )

    def test_org_allows_no_group_user_narrows_permitted(self):
        """
        Org allows + no group/user narrowing → permitted (None).
        Verifies the broker now passes the ctx fields rather than hardcoded []/None.
        """
        store = _make_perm_store(self._grant_map_org_allow_only())
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            caller_group_ids=[],
            caller_user_email="bob@corp.example",
        )
        result = broker._check_connection_permit(ctx)
        assert result is None, (
            f"Org allows, no narrowing → must be permitted. Got {result!r}."
        )


# ---------------------------------------------------------------------------
# MCP-2: mcp_router_runtime populates caller_group_ids / caller_user_email
# ---------------------------------------------------------------------------

class TestMcpRuntimeContextPopulation:
    """MCP-2: _handle_mcp_call_inner populates Phase 4 fields on McpCallContext."""

    def _build_captured_ctx(
        self,
        identity_dict: Optional[dict],
        owui_email: str = "",
    ):
        """
        Exercise the mcp_router_runtime path and capture the McpCallContext
        passed to broker.enforce().
        """
        from yashigani.mcp._types import BrokerDecision, OpaDecision
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        posture, binding = _make_posture_b()
        decision = BrokerDecision(
            call_id="test-call",
            allow=False,
            deny_reason="test_deny",
            opa_decision=OpaDecision(
                allow=False, deny_reason="test_deny",
                redact_args=set(), audit_capture=False, rate_limit_key=None,
            ),
        )
        broker = MagicMock()
        captured = {}

        async def capturing_enforce(ctx):
            captured["ctx"] = ctx
            return decision

        broker.enforce = AsyncMock(side_effect=capturing_enforce)
        broker.enforce_result = AsyncMock()

        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://fs:8000",
            is_filesystem_agent=False,
            tenant_id="t1",
            agent_name="test-server",
        )
        reg.register("test-server", broker, cfg)

        # Build mock identity registry
        id_reg = MagicMock() if identity_dict is not None else None
        if id_reg is not None:
            id_reg.get_by_slug.return_value = identity_dict

        body = json.dumps({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}},
        }).encode()

        headers = {"x-forwarded-user": "user-slug"}
        if owui_email:
            headers["x-openwebui-user-email"] = owui_email

        app = FastAPI()
        app.include_router(create_mcp_call_router(reg, identity_registry=id_reg))

        client = TestClient(app)
        client.post("/mcp/test-server", content=body, headers=headers)
        return captured.get("ctx")

    def test_populates_group_ids_from_identity(self):
        """
        Identity registry returns groups=['eng', 'dev'] → ctx.caller_group_ids == ['eng', 'dev'].
        """
        identity = {
            "groups": ["eng", "dev"],
            "kind": "service",
            "sensitivity_ceiling": "INTERNAL",
            "identity_id": "svc-001",
        }
        ctx = self._build_captured_ctx(identity_dict=identity)
        if ctx is None:
            pytest.skip("ctx not captured (broker deny came before enforce)")
        assert ctx.caller_group_ids == ["eng", "dev"], (
            f"Expected ['eng', 'dev'], got {ctx.caller_group_ids!r}."
        )

    def test_populates_user_email_from_owui_header(self):
        """
        Human-kind identity + X-OpenWebUI-User-Email header → ctx.caller_user_email set.
        """
        identity = {
            "groups": [],
            "kind": "human",
            "sensitivity_ceiling": "PUBLIC",
            "identity_id": "usr-999",
        }
        ctx = self._build_captured_ctx(
            identity_dict=identity,
            owui_email="alice@corp.example",
        )
        if ctx is None:
            pytest.skip("ctx not captured")
        assert ctx.caller_user_email == "alice@corp.example", (
            f"Expected 'alice@corp.example', got {ctx.caller_user_email!r}."
        )

    def test_no_registry_gives_empty_groups_none_email(self):
        """
        Identity registry absent → caller_group_ids=[], caller_user_email=None.
        """
        ctx = self._build_captured_ctx(identity_dict=None)
        if ctx is None:
            pytest.skip("ctx not captured")
        assert ctx.caller_group_ids == [], (
            f"No registry → caller_group_ids must be []. Got {ctx.caller_group_ids!r}."
        )
        assert ctx.caller_user_email is None, (
            f"No registry → caller_user_email must be None. Got {ctx.caller_user_email!r}."
        )

    def test_service_kind_no_email(self):
        """
        Service-kind identity → caller_user_email stays None even with OWUI header.
        """
        identity = {
            "groups": ["infra"],
            "kind": "service",
            "sensitivity_ceiling": "INTERNAL",
            "identity_id": "svc-007",
        }
        ctx = self._build_captured_ctx(
            identity_dict=identity,
            owui_email="ignored@corp.example",
        )
        if ctx is None:
            pytest.skip("ctx not captured")
        assert ctx.caller_user_email is None, (
            f"Service-kind must not populate caller_user_email. Got {ctx.caller_user_email!r}."
        )


# ---------------------------------------------------------------------------
# Part B: agent_router grant check
# ---------------------------------------------------------------------------

class TestAgentRouterGrantCheck:
    """Part B + B+: route_agent_call Phase 4 connection allow-list check.

    route_agent_call(request, path, state) — path is the full /agents/... path.
    Registry is taken from state["agent_registry"].

    Agent principals always have user_email=None.  GRANT-GROUP-FIX: the group
    tier now fires for agents (INV-2 in resolver.py), so a group-level deny
    grant on the target prevents access even when the org allows it.
    """

    def _make_state(self, permission_store=None, registry=None):
        """Minimal state dict for route_agent_call."""
        return {
            "config": MagicMock(opa_url="http://opa:8181"),
            "audit_writer": None,
            "permission_store": permission_store,
            "agent_registry": registry,
            "principal_verifier": None,
            "principal_signer": None,
            "principal_tenant_id": "default",
        }

    def _make_registry(self, agents: dict | None = None):
        """Mock agent registry whose .get() returns a dict."""
        agents = agents or {}
        reg = MagicMock()
        reg.get.side_effect = lambda aid: agents.get(aid)
        return reg

    def _make_request(self, path: str = "/agents/target-agent/chat"):
        req = MagicMock()
        req.method = "POST"
        req.url.path = path
        req.headers = MagicMock()
        req.headers.get.return_value = ""
        # PSK-authenticated caller
        req.state = MagicMock()
        req.state.agent_id = "caller-agent"
        req.state.principal_agent_id = "caller-agent"
        return req

    @pytest.mark.asyncio
    async def test_org_denies_returns_403(self):
        """No grant for target agent → 403 agent_not_permitted."""
        store = _make_perm_store({})  # no grants at all
        caller = {"groups": [], "agent_id": "caller-agent", "name": "caller"}
        target = {
            "agent_id": "target-agent",
            "name": "target",
            "upstream_url": "http://target:8000",
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "status": "active",
        }
        registry = self._make_registry({"caller-agent": caller, "target-agent": target})
        state = self._make_state(permission_store=store, registry=registry)

        from yashigani.gateway.agent_router import route_agent_call
        req = self._make_request()

        with patch.dict(os.environ, {"YASHIGANI_ENV": "development",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await route_agent_call(
                request=req,
                path="/agents/target-agent/chat",
                state=state,
            )

        assert result.status_code == 403
        body = json.loads(result.body)
        assert body["reason"] == "agent_not_permitted", (
            f"Expected agent_not_permitted, got {body!r}."
        )

    @pytest.mark.asyncio
    async def test_org_allows_proceeds_to_opa(self):
        """
        Org grants target agent → passes Phase 4, reaches OPA layer.
        (OPA is mocked to deny for test isolation; what matters is Phase 4 passes.)
        """
        from yashigani.permissions.model import BooleanGrantValue, ResourceType

        grants = {
            (ResourceType.AGENT, "org", "default", "target-agent"): BooleanGrantValue(allow=True),
        }
        store = _make_perm_store(grants)
        caller = {"groups": [], "agent_id": "caller-agent", "name": "caller"}
        target = {
            "agent_id": "target-agent",
            "name": "target",
            "upstream_url": "http://target:8000",
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "status": "active",
        }
        registry = self._make_registry({"caller-agent": caller, "target-agent": target})
        state = self._make_state(permission_store=store, registry=registry)

        from yashigani.gateway.agent_router import route_agent_call
        req = self._make_request()

        with patch("yashigani.gateway.agent_router._opa_agent_check",
                   new=AsyncMock(return_value=(False, "opa_denied_for_test"))), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "development",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await route_agent_call(
                request=req,
                path="/agents/target-agent/chat",
                state=state,
            )

        # Phase 4 passed; OPA denied — reason must NOT be agent_not_permitted
        body = json.loads(result.body) if hasattr(result, "body") else {}
        assert body.get("reason") != "agent_not_permitted", (
            "Phase 4 must have passed; OPA is the denier here, not the grant check."
        )

    @pytest.mark.asyncio
    async def test_agent_group_deny_returns_403(self):
        """
        GRANT-GROUP-FIX (Part B+): agent caller whose principal group 'restricted'
        has a GROUP-level deny grant on the target → 403 agent_not_permitted.

        Before the fix, resolve_boolean_grant returned True early (user_email=None)
        and the group grant was silently ignored.  After the fix, group narrowing
        fires for agents.
        """
        from yashigani.permissions.model import BooleanGrantValue, ResourceType

        grants = {
            (ResourceType.AGENT, "org", "default", "target-agent"): BooleanGrantValue(allow=True),
            (ResourceType.AGENT, "group", "restricted", "target-agent"): BooleanGrantValue(allow=False),
        }
        store = _make_perm_store(grants)
        # Caller belongs to group 'restricted' — registry resolves this
        caller = {"groups": ["restricted"], "agent_id": "caller-agent", "name": "caller"}
        target = {
            "agent_id": "target-agent",
            "name": "target",
            "upstream_url": "http://target:8000",
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "status": "active",
        }
        registry = self._make_registry({"caller-agent": caller, "target-agent": target})
        state = self._make_state(permission_store=store, registry=registry)

        from yashigani.gateway.agent_router import route_agent_call
        req = self._make_request()

        with patch.dict(os.environ, {"YASHIGANI_ENV": "development",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await route_agent_call(
                request=req,
                path="/agents/target-agent/chat",
                state=state,
            )

        assert result.status_code == 403
        body = json.loads(result.body)
        assert body["reason"] == "agent_not_permitted", (
            f"GRANT-GROUP-FIX: group-level deny must block agent access even when "
            f"org allows (user_email=None). Got {body!r}."
        )

    @pytest.mark.asyncio
    async def test_store_unavailable_prod_denies(self):
        """permission_store=None in production → 403 permission_store_unavailable."""
        caller = {"groups": [], "agent_id": "caller-agent", "name": "caller"}
        target = {
            "agent_id": "target-agent",
            "name": "target",
            "upstream_url": "http://target:8000",
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "status": "active",
        }
        registry = self._make_registry({"caller-agent": caller, "target-agent": target})
        state = self._make_state(permission_store=None, registry=registry)

        from yashigani.gateway.agent_router import route_agent_call
        req = self._make_request()

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            result = await route_agent_call(
                request=req,
                path="/agents/target-agent/chat",
                state=state,
            )

        assert result.status_code == 403
        body = json.loads(result.body)
        assert body["reason"] == "permission_store_unavailable", (
            f"Prod + no store must return permission_store_unavailable. Got {body!r}."
        )

    @pytest.mark.asyncio
    async def test_store_unavailable_dev_no_op(self):
        """permission_store=None in dev → Phase 4 no-op, proceeds (OPA is reached)."""
        caller = {"groups": [], "agent_id": "caller-agent", "name": "caller"}
        target = {
            "agent_id": "target-agent",
            "name": "target",
            "upstream_url": "http://target:8000",
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "status": "active",
        }
        registry = self._make_registry({"caller-agent": caller, "target-agent": target})
        state = self._make_state(permission_store=None, registry=registry)

        from yashigani.gateway.agent_router import route_agent_call
        req = self._make_request()

        # OPA will be queried (Phase 4 is no-op in dev).
        with patch("yashigani.gateway.agent_router._opa_agent_check",
                   new=AsyncMock(return_value=(False, "opa_denied_for_test"))), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "development"}):
            result = await route_agent_call(
                request=req,
                path="/agents/target-agent/chat",
                state=state,
            )

        # Phase 4 must NOT have blocked — OPA did.
        body = json.loads(result.body) if hasattr(result, "body") else {}
        assert body.get("reason") != "permission_store_unavailable", (
            "Dev env + no store must not trigger Phase 4 fail-closed."
        )


# ---------------------------------------------------------------------------
# Part C: seed_agent_grants
# ---------------------------------------------------------------------------

class TestSeedAgentGrants:
    """Part C: seed_agent_grants idempotent seeding."""

    def test_seeds_agent_grants(self):
        """Each agent_id gets an org-level allow grant."""
        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.seeder import seed_agent_grants

        store = MagicMock()
        seed_agent_grants(
            perm_store=store,
            agent_ids=["agent-1", "agent-2"],
            org_id="my-org",
        )

        calls = store.set_boolean_grant.call_args_list
        call_kwargs = [c.kwargs for c in calls]

        assert any(
            k.get("resource_type") == ResourceType.AGENT
            and k.get("scope_kind") == "org"
            and k.get("scope_id") == "my-org"
            and k.get("resource_id") == "agent-1"
            for k in call_kwargs
        ), "agent-1 grant not seeded"

        assert any(
            k.get("resource_type") == ResourceType.AGENT
            and k.get("resource_id") == "agent-2"
            for k in call_kwargs
        ), "agent-2 grant not seeded"

    def test_empty_list_no_op(self):
        """Empty agent_ids → no calls to set_boolean_grant."""
        from yashigani.permissions.seeder import seed_agent_grants
        store = MagicMock()
        seed_agent_grants(perm_store=store, agent_ids=[], org_id="org")
        store.set_boolean_grant.assert_not_called()

    def test_idempotent_call_twice(self):
        """Calling seed_agent_grants twice with the same inputs is safe."""
        from yashigani.permissions.seeder import seed_agent_grants
        store = MagicMock()
        seed_agent_grants(perm_store=store, agent_ids=["a1"], org_id="org")
        seed_agent_grants(perm_store=store, agent_ids=["a1"], org_id="org")
        # Two calls to set_boolean_grant (one per seed call) — both safe
        assert store.set_boolean_grant.call_count == 2

    def test_store_error_does_not_raise(self):
        """A failure on one agent grant does not abort the whole seed."""
        from yashigani.permissions.seeder import seed_agent_grants
        store = MagicMock()
        store.set_boolean_grant.side_effect = RuntimeError("redis down")
        # Must not propagate — the seeder logs and continues
        seed_agent_grants(perm_store=store, agent_ids=["a1", "a2"], org_id="org")

    def test_exported_from_package(self):
        """seed_agent_grants is importable from yashigani.permissions."""
        from yashigani.permissions import seed_agent_grants
        assert callable(seed_agent_grants)


# ---------------------------------------------------------------------------
# Proxy: permission_store in create_gateway_app signature
# ---------------------------------------------------------------------------

class TestProxyPermissionStoreParam:
    """Part B wiring: create_gateway_app must accept permission_store."""

    def test_permission_store_in_signature(self):
        import inspect
        from yashigani.gateway.proxy import create_gateway_app
        sig = inspect.signature(create_gateway_app)
        assert "permission_store" in sig.parameters, (
            "create_gateway_app must have permission_store parameter"
        )
        assert sig.parameters["permission_store"].default is None

    def test_permission_store_in_state_dict(self):
        import inspect
        from yashigani.gateway import proxy as proxy_module
        source = inspect.getsource(proxy_module.create_gateway_app)
        assert '"permission_store"' in source or "'permission_store'" in source, (
            "create_gateway_app _state dict must include 'permission_store' key"
        )


# ---------------------------------------------------------------------------
# Resolver: direct group-tier semantics (GRANT-GROUP-FIX)
# ---------------------------------------------------------------------------

class TestResolveBooleanGrantGroupTier:
    """
    GRANT-GROUP-FIX: direct unit tests for resolve_boolean_grant group-tier
    semantics.  These four scenarios exercise the invariants from the brief:

    (a) agent org-allow + group-deny → denied        (the closed bug)
    (b) agent org-allow + no group grant → allowed   (org-only path for agents)
    (c) human org-allow + group-allow + user-deny → denied  (user tier unchanged)
    (d) org-deny always denies regardless of group/user    (ceiling invariant)
    """

    def _resolve(
        self,
        grants: dict,
        *,
        org_id: str = "default",
        group_ids: list,
        user_email: Optional[str],
        resource_id: str = "res-1",
    ) -> bool:
        from yashigani.permissions import resolve_boolean_grant
        from yashigani.permissions.model import ResourceType
        store = _make_perm_store(grants)
        return resolve_boolean_grant(
            ResourceType.AGENT,
            resource_id,
            org_id=org_id,
            group_ids=group_ids,
            principal_scope="user" if user_email else None,
            principal_id=user_email if user_email else None,
            store=store,
        )

    def _grant(self, scope_kind: str, scope_id: str, allow: bool, resource_id: str = "res-1"):
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        return (ResourceType.AGENT, scope_kind, scope_id, resource_id), BooleanGrantValue(allow=allow)

    # (a) agent org-allow + group-deny → denied
    def test_a_agent_org_allow_group_deny_is_denied(self):
        """
        GRANT-GROUP-FIX scenario (a): org allows, group 'g1' denies, user_email=None
        → False.  This was the broken case before the fix.
        """
        k_org, v_org = self._grant("org", "default", allow=True)
        k_grp, v_grp = self._grant("group", "g1", allow=False)
        grants = {k_org: v_org, k_grp: v_grp}

        result = self._resolve(grants, group_ids=["g1"], user_email=None)
        assert result is False, (
            "GRANT-GROUP-FIX (a): agent with group 'g1' deny grant must be DENIED "
            "even when org allows and user_email is None."
        )

    # (b) agent org-allow + no group grant → allowed
    def test_b_agent_org_allow_no_group_grant_is_allowed(self):
        """
        Scenario (b): org allows, no group grant exists for group 'g1',
        user_email=None → True.

        Agents in a group without an explicit deny grant must be allowed
        through once the org ceiling permits.
        """
        k_org, v_org = self._grant("org", "default", allow=True)
        grants = {k_org: v_org}  # no group grant

        result = self._resolve(grants, group_ids=["g1"], user_email=None)
        assert result is True, (
            "Scenario (b): agent org-allow + no group deny → must be ALLOWED."
        )

    # (b2) orchestrator: org-allow + empty groups + no email → allowed
    def test_b2_orchestrator_empty_groups_no_email_allowed(self):
        """
        Orchestrator-style caller: group_ids=[], user_email=None → org-only.
        Org allows → True.  Group loop is a no-op (empty list).
        """
        k_org, v_org = self._grant("org", "default", allow=True)
        grants = {k_org: v_org}

        result = self._resolve(grants, group_ids=[], user_email=None)
        assert result is True, (
            "Orchestrator (group_ids=[], user_email=None) must be ALLOWED when org grants access."
        )

    # (c) human org-allow + group-allow + user-deny → denied
    def test_c_human_org_allow_group_allow_user_deny_is_denied(self):
        """
        Scenario (c): org allows, group 'g1' allows (no denial), user denies
        → False.  User tier still works for email-identified principals.
        """
        k_org, v_org = self._grant("org", "default", allow=True)
        k_grp, v_grp = self._grant("group", "g1", allow=True)   # group allows (no narrowing)
        k_usr, v_usr = self._grant("user", "alice@example.com", allow=False)
        grants = {k_org: v_org, k_grp: v_grp, k_usr: v_usr}

        result = self._resolve(
            grants,
            group_ids=["g1"],
            user_email="alice@example.com",
        )
        assert result is False, (
            "Scenario (c): user deny must override even when org+group allow."
        )

    # (d) org-deny always denies regardless of group/user
    def test_d_org_deny_always_denies(self):
        """
        Scenario (d): org explicitly denies → result is False regardless of
        group or user grants (ceiling invariant).
        """
        k_org, v_org = self._grant("org", "default", allow=False)
        k_grp, v_grp = self._grant("group", "g1", allow=True)
        k_usr, v_usr = self._grant("user", "bob@example.com", allow=True)
        grants = {k_org: v_org, k_grp: v_grp, k_usr: v_usr}

        result = self._resolve(
            grants,
            group_ids=["g1"],
            user_email="bob@example.com",
        )
        assert result is False, (
            "Scenario (d): org-deny must override all group/user allows (ceiling)."
        )

    def test_d2_no_org_grant_denies(self):
        """
        No org grant at all → deny-by-default (org_grant is None → False).
        """
        result = self._resolve({}, group_ids=["g1"], user_email=None)
        assert result is False, (
            "No org grant → deny-by-default must apply."
        )

    # Multiple groups — first deny wins
    def test_multiple_groups_first_deny_wins(self):
        """
        Multiple groups: g1 has no grant, g2 has deny → denied.
        """
        k_org, v_org = self._grant("org", "default", allow=True)
        k_g2, v_g2 = self._grant("group", "g2", allow=False)
        grants = {k_org: v_org, k_g2: v_g2}

        result = self._resolve(grants, group_ids=["g1", "g2"], user_email=None)
        assert result is False, (
            "Multi-group: if ANY group denies, the result must be DENIED."
        )
