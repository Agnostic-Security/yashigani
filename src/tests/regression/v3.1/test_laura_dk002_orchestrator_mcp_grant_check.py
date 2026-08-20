"""
Regression test — LAURA-DK-002 (Medium): orchestrator MCP tool-execution path
must enforce the connection allow-list (resolve_boolean_grant) before the OPA
ingress query.

Previously, _execute_mcp_tool called _opa_ingress_for_mcp but never called
resolve_boolean_grant, so a principal with a confirmed user-level DENY grant on
a server could invoke its tools by routing through the cloud9-orchestrate path.

Fix: _check_orchestrator_mcp_grant is called FIRST inside _execute_mcp_tool;
it mirrors broker._check_connection_permit's 3-way principal dispatch and
fail-closes on deny before OPA is ever queried.

Coverage:
  A. DENY grant on server → _check_orchestrator_mcp_grant returns ToolResult(blocked)
     A1. User-scope deny (human caller, kind="user")
     A2. User-scope deny (human caller, kind="human")
     A3. Agent-scope deny (agent caller, kind="agent")
     A4. Group-tier deny (caller in denied group)

  B. ALLOW path → returns None (caller proceeds)
     B1. Org grant present, no group/user deny → allowed (user caller)
     B2. Org grant present, no group/user deny → allowed (agent caller)
     B3. No principal scope (orchestrator/internal) → org ceiling only → allowed

  C. No permission store
     C1. prod env + no store → fail-closed deny ToolResult
     C2. dev env + no store → no-op (None)
     C3. staging env + no store → fail-closed deny ToolResult

  D. Org ceiling deny (deny-by-default)
     D1. No org grant → denied regardless of principal scope
     D2. Org grant is explicitly deny → denied

  E. _execute_mcp_tool integration
     E1. DENY grant → blocked before OPA is called (OPA mock not called)
     E2. ALLOW grant → OPA ingress is reached (OPA mock called)

  F. LAURA-DK-002-fix: startup seeder regression (orchestrator-path server names)
     F1. _resolve_mcp_servers returns {"demo": url} for a demo-mcp upstream URL
     F2. seed_mcp_grants for _resolve_mcp_servers() keys → org-allow for "demo"
         → _check_orchestrator_mcp_grant allows an org-allowed principal
         (validates the fix: default demo works with NO manual grants)
     F3. After startup seeding, user with DENY on "demo" is still blocked
         (DK-002 deny narrowing stays closed — Laura-verified invariant)
"""
from __future__ import annotations

import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perm_store():
    """PermissionStore backed by fakeredis."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(fakeredis.FakeRedis(decode_responses=False))


def _seed_org_allow(store, server_id: str, org_id: str = "default") -> None:
    from yashigani.permissions.model import BooleanGrantValue, ResourceType
    store.set_boolean_grant(ResourceType.MCP_SERVER, "org", org_id, server_id,
                            BooleanGrantValue(allow=True))


def _seed_user_deny(store, user_id: str, server_id: str) -> None:
    from yashigani.permissions.model import BooleanGrantValue, ResourceType
    store.set_boolean_grant(ResourceType.MCP_SERVER, "user", user_id, server_id,
                            BooleanGrantValue(allow=False))


def _seed_agent_deny(store, agent_id: str, server_id: str) -> None:
    from yashigani.permissions.model import BooleanGrantValue, ResourceType
    store.set_boolean_grant(ResourceType.MCP_SERVER, "agent", agent_id, server_id,
                            BooleanGrantValue(allow=False))


def _seed_group_deny(store, group_id: str, server_id: str) -> None:
    from yashigani.permissions.model import BooleanGrantValue, ResourceType
    store.set_boolean_grant(ResourceType.MCP_SERVER, "group", group_id, server_id,
                            BooleanGrantValue(allow=False))


def _human_identity(identity_id: str = "idnt_abc123", kind: str = "user",
                    groups: Optional[list] = None) -> dict:
    return {
        "identity_id": identity_id,
        "kind": kind,
        "groups": groups or [],
        "slug": identity_id,
    }


def _agent_identity(identity_id: str = "agt_xyz789", groups: Optional[list] = None) -> dict:
    return {
        "identity_id": identity_id,
        "kind": "agent",
        "groups": groups or [],
    }


def _internal_identity() -> dict:
    return {
        "identity_id": "internal",
        "kind": "service",
        "groups": [],
    }


def _call_grant_check(identity, server: str, tool: str, perm_store,
                      org_id: str = "default", ysg_env: str = "dev"):
    """Call _check_orchestrator_mcp_grant with a mocked _state.

    _state lives in openai_router and is imported lazily inside orchestrator
    functions; patch it at the source so both _check_orchestrator_mcp_grant
    and the _audit helper pick up the mock.
    """
    from yashigani.gateway.orchestrator import _check_orchestrator_mcp_grant

    mock_state = MagicMock()
    mock_state.permission_store = perm_store
    mock_state.audit_writer = None  # suppress real audit writes in tests

    with patch("yashigani.gateway.openai_router._state", mock_state), \
         patch.dict(os.environ, {"YASHIGANI_ENV": ysg_env, "YASHIGANI_ORG_ID": org_id}):
        return _check_orchestrator_mcp_grant(
            identity=identity,
            server=server,
            tool="demo_info",
            request_id="test-req-001",
            root_rid="test-root-001",
            depth=1,
        )


# ---------------------------------------------------------------------------
# A. DENY paths
# ---------------------------------------------------------------------------

class TestDenyGrant:
    """A1-A4: Principals with a deny grant on the server are blocked."""

    def test_a1_user_scope_deny_kind_user(self):
        """A1. kind='user' caller with user-level DENY → blocked."""
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")
        _seed_org_allow(store, "demo-mcp")
        _seed_user_deny(store, "idnt_abc123", "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None, "Expected a blocked ToolResult, got None (allowed)"
        assert result.blocked, "ToolResult.blocked must be True"
        assert result.http_status == 403
        assert "mcp_server_not_permitted" in result.ingress_opa
        assert "grant:mcp_server_not_permitted" == result.block_source
        assert "LAURA-DK-002" in result.text

    def test_a2_user_scope_deny_kind_human(self):
        """A2. kind='human' (legacy value) caller with user-level DENY → blocked."""
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_def456", kind="human")
        _seed_org_allow(store, "demo-mcp")
        _seed_user_deny(store, "idnt_def456", "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None and result.blocked
        assert result.http_status == 403
        assert "mcp_server_not_permitted" in result.ingress_opa

    def test_a3_agent_scope_deny(self):
        """A3. Agent caller with agent-level DENY → blocked."""
        store = _perm_store()
        identity = _agent_identity(identity_id="agt_xyz789")
        _seed_org_allow(store, "demo-mcp")
        _seed_agent_deny(store, "agt_xyz789", "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None and result.blocked
        assert result.http_status == 403
        assert "mcp_server_not_permitted" in result.ingress_opa

    def test_a4_group_tier_deny(self):
        """A4. Caller in a denied group → blocked (group tier fires regardless of scope)."""
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user",
                                   groups=["grp_restricted"])
        _seed_org_allow(store, "demo-mcp")
        # No user-level deny — group deny is enough.
        _seed_group_deny(store, "grp_restricted", "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None and result.blocked
        assert result.http_status == 403


# ---------------------------------------------------------------------------
# B. ALLOW paths
# ---------------------------------------------------------------------------

class TestAllowGrant:
    """B1-B3: Permitted callers return None so execution continues."""

    def test_b1_org_allow_user_caller_no_deny(self):
        """B1. Org grant present, no group/user deny → allowed (user kind)."""
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")
        _seed_org_allow(store, "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is None, f"Expected None (allowed), got blocked: {result}"

    def test_b2_org_allow_agent_caller_no_deny(self):
        """B2. Org grant present, no deny → allowed (agent kind)."""
        store = _perm_store()
        identity = _agent_identity(identity_id="agt_xyz789")
        _seed_org_allow(store, "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is None, f"Expected None (allowed), got blocked: {result}"

    def test_b3_internal_identity_org_ceiling_only(self):
        """B3. Internal/orchestrator identity — no per-principal narrowing, org ceiling applies."""
        store = _perm_store()
        identity = _internal_identity()
        _seed_org_allow(store, "demo-mcp")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is None, "Orchestrator identity should be allowed when org grant exists"

    def test_b3_internal_identity_no_org_grant_denied(self):
        """B3b. Internal identity with no org grant → denied (deny-by-default)."""
        store = _perm_store()
        identity = _internal_identity()
        # No org grant seeded.

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None and result.blocked, \
            "Org-less server must be denied even for orchestrator identity"


# ---------------------------------------------------------------------------
# C. No permission store
# ---------------------------------------------------------------------------

class TestNoPermissionStore:
    """C1-C3: Behaviour when _state.permission_store is None."""

    def test_c1_prod_env_no_store_fail_closed(self):
        """C1. Production env + no store → fail-closed deny."""
        result = _call_grant_check(
            _human_identity(), "demo-mcp", "demo_info",
            perm_store=None, ysg_env="production",
        )
        assert result is not None and result.blocked
        assert result.http_status == 403
        assert "permission_store_unavailable" in result.ingress_opa

    def test_c2_dev_env_no_store_noop(self):
        """C2. Dev env + no store → no-op (None); backwards-compatible."""
        result = _call_grant_check(
            _human_identity(), "demo-mcp", "demo_info",
            perm_store=None, ysg_env="dev",
        )
        assert result is None, "Dev env with no store must not deny"

    def test_c3_staging_env_no_store_fail_closed(self):
        """C3. Staging env + no store → fail-closed deny (same as production)."""
        result = _call_grant_check(
            _human_identity(), "demo-mcp", "demo_info",
            perm_store=None, ysg_env="staging",
        )
        assert result is not None and result.blocked
        assert result.http_status == 403
        assert "permission_store_unavailable" in result.ingress_opa


# ---------------------------------------------------------------------------
# D. Org ceiling (deny-by-default)
# ---------------------------------------------------------------------------

class TestOrgCeiling:
    """D1-D2: Org ceiling enforces deny-by-default."""

    def test_d1_no_org_grant_denied(self):
        """D1. No org grant → denied for all principal types."""
        store = _perm_store()
        # Do NOT seed org grant — deny-by-default must kick in.
        for identity in [
            _human_identity(kind="user"),
            _agent_identity(),
            _internal_identity(),
        ]:
            result = _call_grant_check(identity, "demo-mcp", "demo_info", store)
            assert result is not None and result.blocked, \
                f"No-org-grant must deny for identity kind={identity.get('kind')}"

    def test_d2_explicit_org_deny(self):
        """D2. Explicit org-level deny → blocked."""
        store = _perm_store()
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        store.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "demo-mcp",
                                BooleanGrantValue(allow=False))
        identity = _human_identity(kind="user")

        result = _call_grant_check(identity, "demo-mcp", "demo_info", store)

        assert result is not None and result.blocked


# ---------------------------------------------------------------------------
# E. _execute_mcp_tool integration
# ---------------------------------------------------------------------------

class TestExecuteMcpToolIntegration:
    """E1-E2: Grant check wired correctly inside _execute_mcp_tool."""

    @pytest.mark.asyncio
    async def test_e1_deny_grant_blocks_before_opa(self):
        """E1. DENY grant → _execute_mcp_tool blocks; OPA ingress never called."""
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")

        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")
        _seed_org_allow(store, "demo-mcp")
        _seed_user_deny(store, "idnt_abc123", "demo-mcp")

        from yashigani.gateway.orchestrator import _execute_mcp_tool

        mock_state = MagicMock()
        mock_state.permission_store = store
        mock_state.audit_writer = None
        mock_state.response_inspection_pipeline = None
        mock_state.sensitivity_classifier = None

        opa_ingress_called = []

        async def _fake_opa_ingress(*args, **kwargs):
            opa_ingress_called.append(True)
            return {"allow": True}

        with patch("yashigani.gateway.openai_router._state", mock_state), \
             patch("yashigani.gateway.orchestrator._opa_ingress_for_mcp",
                   _fake_opa_ingress), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "dev",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await _execute_mcp_tool(
                server="demo-mcp",
                upstream_url="http://demo-mcp:8080/rpc",
                tool="demo_info",
                args={},
                identity=identity,
                depth=1,
                root_rid="root-001",
                request_id="req-001",
            )

        assert result.blocked, "Expected blocked ToolResult from grant check"
        assert result.http_status == 403
        assert "mcp_server_not_permitted" in result.ingress_opa
        assert not opa_ingress_called, \
            "OPA ingress MUST NOT be called when grant check denies"

    @pytest.mark.asyncio
    async def test_e2_allow_grant_reaches_opa(self):
        """E2. ALLOW grant → OPA ingress IS reached (grant check returns None)."""
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")

        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")
        _seed_org_allow(store, "demo-mcp")
        # No user deny → should be allowed.

        from yashigani.gateway.orchestrator import _execute_mcp_tool

        mock_state = MagicMock()
        mock_state.permission_store = store
        mock_state.audit_writer = None
        mock_state.response_inspection_pipeline = None
        mock_state.sensitivity_classifier = None

        opa_ingress_called = []

        async def _fake_opa_ingress(*args, **kwargs):
            opa_ingress_called.append(True)
            # Deny at OPA to keep the test fast (avoids real HTTP upstream call).
            return {"allow": False, "reason": "test_opa_deny"}

        with patch("yashigani.gateway.openai_router._state", mock_state), \
             patch("yashigani.gateway.orchestrator._opa_ingress_for_mcp",
                   _fake_opa_ingress), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "dev",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await _execute_mcp_tool(
                server="demo-mcp",
                upstream_url="http://demo-mcp:8080/rpc",
                tool="demo_info",
                args={},
                identity=identity,
                depth=1,
                root_rid="root-001",
                request_id="req-001",
            )

        assert opa_ingress_called, \
            "OPA ingress MUST be called when grant check passes"
        # The block here is from OPA (test_opa_deny), not from the grant check.
        assert result.blocked
        assert "opa_ingress" in result.block_source

    @pytest.mark.asyncio
    async def test_e3_no_store_prod_blocks_before_opa(self):
        """E3. Production env + no permission_store → fail-closed before OPA."""
        from yashigani.gateway.orchestrator import _execute_mcp_tool

        mock_state = MagicMock()
        mock_state.permission_store = None
        mock_state.audit_writer = None
        mock_state.response_inspection_pipeline = None
        mock_state.sensitivity_classifier = None

        opa_ingress_called = []

        async def _fake_opa_ingress(*args, **kwargs):
            opa_ingress_called.append(True)
            return {"allow": True}

        with patch("yashigani.gateway.openai_router._state", mock_state), \
             patch("yashigani.gateway.orchestrator._opa_ingress_for_mcp",
                   _fake_opa_ingress), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "production",
                                     "YASHIGANI_ORG_ID": "default"}):
            result = await _execute_mcp_tool(
                server="demo-mcp",
                upstream_url="http://demo-mcp:8080/rpc",
                tool="demo_info",
                args={},
                identity=_human_identity(kind="user"),
                depth=1,
                root_rid="root-001",
                request_id="req-001",
            )

        assert result.blocked
        assert result.http_status == 403
        assert "permission_store_unavailable" in result.ingress_opa
        assert not opa_ingress_called, \
            "OPA must not be called when store is missing in production"


# ---------------------------------------------------------------------------
# F. LAURA-DK-002-fix: startup seeder regression (orchestrator-path names)
# ---------------------------------------------------------------------------

class TestDemoStartupSeeding:
    """F1-F3: Orchestrator-path seeder seeds org-allow from _resolve_mcp_servers().

    Regression guard for the regression: the DK-002 fix introduced a grant
    check that denies every cloud9-orchestrate MCP tool call in the default demo
    because the seeder only covered YASHIGANI_MCP_SERVERS broker-path names, not
    the orchestrator-path names resolved by _resolve_mcp_servers().

    The fix: entrypoint.py also calls seed_mcp_grants with
    list(_resolve_mcp_servers().keys()) after the broker-wiring block — same
    function the orchestrator calls — so names can never diverge again.
    """

    def test_f1_resolve_mcp_servers_demo_url(self):
        """F1. _resolve_mcp_servers returns {"demo": url} for a demo-mcp upstream URL.

        This validates the single-source-of-truth: the seeder calls the same
        function the orchestrator calls, so they always agree on the server name.
        """
        from yashigani.gateway.tool_catalog import _resolve_mcp_servers

        with patch.dict(os.environ, {
            "UPSTREAM_MCP_URL": "http://demo-mcp:8000",
            "YASHIGANI_UPSTREAM_URL": "",
            "YASHIGANI_ORCH_MCP_SERVERS": "",
        }):
            servers = _resolve_mcp_servers()

        assert servers == {"demo": "http://demo-mcp:8000"}, \
            f"Expected {{'demo': 'http://demo-mcp:8000'}}, got {servers!r}"

    def test_f1b_resolve_mcp_servers_yashigani_upstream_url(self):
        """F1b. YASHIGANI_UPSTREAM_URL (in-container name) also maps to 'demo'."""
        from yashigani.gateway.tool_catalog import _resolve_mcp_servers

        with patch.dict(os.environ, {
            "UPSTREAM_MCP_URL": "",
            "YASHIGANI_UPSTREAM_URL": "http://demo-mcp:8000",
            "YASHIGANI_ORCH_MCP_SERVERS": "",
        }):
            servers = _resolve_mcp_servers()

        assert servers == {"demo": "http://demo-mcp:8000"}, \
            f"Expected {{'demo': ...}}, got {servers!r}"

    def test_f2_startup_seeder_seeds_demo_grant_allows_principal(self):
        """F2. seed_mcp_grants with _resolve_mcp_servers() keys → grant check passes.

        Simulates what the LAURA-DK-002-fix startup block does in entrypoint.py:
          1. resolve server names from _resolve_mcp_servers() (demo upstream)
          2. seed org-allow via seed_mcp_grants
          3. confirm _check_orchestrator_mcp_grant allows an org-allowed principal

        With NO YASHIGANI_MCP_SERVERS set — the default demo scenario.
        """
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")

        # Step 1: resolve server names exactly as the startup seeder does.
        from yashigani.gateway.tool_catalog import _resolve_mcp_servers
        with patch.dict(os.environ, {
            "UPSTREAM_MCP_URL": "http://demo-mcp:8000",
            "YASHIGANI_UPSTREAM_URL": "",
            "YASHIGANI_ORCH_MCP_SERVERS": "",
            "YASHIGANI_MCP_SERVERS": "",  # NO broker-path servers — pure demo scenario
        }):
            orch_server_ids = list(_resolve_mcp_servers().keys())

        assert "demo" in orch_server_ids, \
            f"_resolve_mcp_servers() must return 'demo' for demo-mcp URL; got {orch_server_ids}"

        # Step 2: seed the org-allow grants (mirrors the entrypoint seeder block).
        from yashigani.permissions.seeder import seed_mcp_grants
        seed_mcp_grants(perm_store=store, server_ids=orch_server_ids, org_id="default")

        # Step 3: grant check now passes for the org-allowed principal.
        result = _call_grant_check(identity, "demo", "demo_info", store)
        assert result is None, (
            f"Expected None (allowed) after startup seeding of 'demo', "
            f"got blocked ToolResult: {result}"
        )

    def test_f3_user_deny_still_blocks_after_startup_seeding(self):
        """F3. DK-002 stays closed: user-DENY on 'demo' blocks even after startup seeding.

        The startup seeder sets the ORG-LEVEL allow ceiling; it never touches
        user/group DENY grants.  An operator-applied user DENY must still fire.
        """
        store = _perm_store()
        identity = _human_identity(identity_id="idnt_abc123", kind="user")

        # Startup seeder seeds org-allow for "demo" (same as entrypoint.py does).
        from yashigani.permissions.seeder import seed_mcp_grants
        seed_mcp_grants(perm_store=store, server_ids=["demo"], org_id="default")

        # Operator narrows: user-level DENY overrides org-allow.
        _seed_user_deny(store, "idnt_abc123", "demo")

        result = _call_grant_check(identity, "demo", "demo_info", store)

        assert result is not None and result.blocked, (
            "User DENY must override startup org-allow (LAURA-DK-002 stays closed)"
        )
        assert result.http_status == 403
        assert "mcp_server_not_permitted" in result.ingress_opa
        assert "grant:mcp_server_not_permitted" == result.block_source
