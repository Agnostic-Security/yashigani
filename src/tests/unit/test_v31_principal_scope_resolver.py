"""
v3.1 principal-scope resolver tests — 8 scenarios (Iris §6).

Verifies that:
  - Agent-scope grants are now read and enforced (Problem #1 fixed).
  - Non-human principals get per-principal narrowing without email (Problem #2 fixed).
  - Human user-scope narrowing is unchanged (backward-compat).
  - Org ceiling holds for all principal types (deny-by-default).
  - Group tier applies to both agents and humans.
  - No cross-scope key contamination (agent grant != user grant for same id).
  - Admin get_effective endpoint can preview agent-scope grants.
  - Admin get_effective rejects ambiguous principal (user_email + agent_id together).

All tests are unit-level (no live Redis, no live OPA).
"""
from __future__ import annotations

import pytest
from typing import Optional

from yashigani.permissions.model import (
    ResourceType,
    BooleanGrantValue,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perm_store():
    """FakeRedis-backed PermissionStore (no live Redis required)."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    redis = fakeredis.FakeRedis(decode_responses=False)
    return PermissionStore(redis, default_org_id="default")


def _grant(
    store: PermissionStore,
    resource_type: ResourceType,
    scope_kind: str,
    scope_id: str,
    resource_id: str,
    allow: bool,
) -> None:
    store.set_boolean_grant(
        resource_type, scope_kind, scope_id, resource_id,
        BooleanGrantValue(allow=allow),
    )


def _resolve(
    resource_type: ResourceType,
    resource_id: str,
    *,
    org_id: str = "default",
    group_ids: list[str] = None,
    principal_scope: Optional[str],
    principal_id: Optional[str],
    store: PermissionStore,
) -> bool:
    from yashigani.permissions.resolver import resolve_boolean_grant
    return resolve_boolean_grant(
        resource_type,
        resource_id,
        org_id=org_id,
        group_ids=group_ids or [],
        principal_scope=principal_scope,
        principal_id=principal_id,
        store=store,
    )


# ---------------------------------------------------------------------------
# Test 6.1 — Per-agent narrowing is now enforced
# ---------------------------------------------------------------------------

class TestPerAgentNarrowing:
    """
    Problem #1 fix: agent-scope grants stored in Redis are now READ and
    enforced.  Previously the admin could write an agent-scope grant via
    PUT /grants/agent/..., but the resolver silently ignored it.
    """

    def test_agent_scope_deny_is_enforced(self):
        """
        Org allows server-A; agent-1 has an agent-scope deny on server-A.
        resolve_boolean_grant with principal_scope="agent", principal_id="agent-1"
        must return False.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-A", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "agent", "agent-1", "server-A", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-A",
            principal_scope="agent", principal_id="agent-1",
            store=store,
        )
        assert result is False, (
            "Agent-scope deny grant must be enforced (Problem #1 fix). "
            "org allows + agent-1 agent-scope deny → DENIED."
        )

    def test_other_agent_not_affected_by_agent1_deny(self):
        """
        agent-2 has no agent-scope grant; org allows → ALLOWED.
        The agent-1 deny grant must not bleed into agent-2.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-A", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "agent", "agent-1", "server-A", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-A",
            principal_scope="agent", principal_id="agent-2",
            store=store,
        )
        assert result is True, (
            "agent-2 has no agent-scope grant; org allows → must be ALLOWED. "
            "agent-1's deny must not contaminate agent-2."
        )


# ---------------------------------------------------------------------------
# Test 6.2 — Non-human principal narrows without email
# ---------------------------------------------------------------------------

class TestNonHumanNarrowingNoEmail:
    """
    Problem #2 fix: agents get per-principal narrowing without supplying an email.
    """

    def test_agent_scope_deny_enforced_without_email(self):
        """
        Org allows target-agent; caller-agent has agent-scope deny on target-agent.
        No email is involved.  Narrowing fires via agent scope.
        """
        store = _perm_store()
        _grant(store, ResourceType.AGENT, "org", "default", "target-agent", allow=True)
        _grant(store, ResourceType.AGENT, "agent", "caller-agent", "target-agent", allow=False)

        result = _resolve(
            ResourceType.AGENT, "target-agent",
            principal_scope="agent", principal_id="caller-agent",
            store=store,
        )
        assert result is False, (
            "Agent-scope deny on AGENT resource type must fire without email. "
            "Problem #2 fix: non-human principal gets per-principal narrowing."
        )


# ---------------------------------------------------------------------------
# Test 6.3 — Human user-scope narrowing still works (backward-compat)
# ---------------------------------------------------------------------------

class TestHumanUserScopeBackwardCompat:
    """User-scope narrowing must work identically after the signature rename."""

    def test_user_scope_deny_enforced(self):
        """
        Org allows server-B; alice has a user-scope deny on server-B.
        principal_scope="user", principal_id="alice@example.com" → DENIED.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-B", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "user", "alice@example.com", "server-B", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-B",
            principal_scope="user", principal_id="alice@example.com",
            store=store,
        )
        assert result is False, (
            "User-scope deny must still be enforced after signature rename."
        )

    def test_user_with_no_grant_allowed(self):
        """
        bob has no user-scope grant; org allows → ALLOWED.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-B", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "user", "alice@example.com", "server-B", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-B",
            principal_scope="user", principal_id="bob@example.com",
            store=store,
        )
        assert result is True, (
            "bob has no user-scope grant; org allows → ALLOWED. "
            "alice's deny must not affect bob."
        )


# ---------------------------------------------------------------------------
# Test 6.4 — Org ceiling holds for all principal types
# ---------------------------------------------------------------------------

class TestOrgCeilingDenyByDefault:
    """INV-1 deny-by-default: no org grant means DENIED regardless of any lower tier."""

    def test_no_org_grant_denies_agent(self):
        """
        No org grant for server-C.  agent-X has agent-scope allow=True (which
        has no effect without an org grant).  Result: DENIED.
        """
        store = _perm_store()
        # No org grant written
        _grant(store, ResourceType.MCP_SERVER, "agent", "agent-X", "server-C", allow=True)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-C",
            principal_scope="agent", principal_id="agent-X",
            store=store,
        )
        assert result is False, (
            "INV-1: no org grant → DENIED regardless of agent-scope allow. "
            "Org ceiling is deny-by-default."
        )


# ---------------------------------------------------------------------------
# Test 6.5 — Group tier applies to all principals regardless of scope
# ---------------------------------------------------------------------------

class TestGroupTierForAllPrincipals:
    """Group-tier deny fires for both agents and humans; principal_scope is irrelevant."""

    def test_group_deny_blocks_agent(self):
        """
        Org allows server-D; group 'restricted' has deny on server-D.
        Agent in 'restricted' group → DENIED.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-D", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "group", "restricted", "server-D", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-D",
            group_ids=["restricted"],
            principal_scope="agent", principal_id="agent-Y",
            store=store,
        )
        assert result is False, (
            "Group deny must block agents in that group (principal_scope='agent')."
        )

    def test_group_deny_blocks_human(self):
        """
        Same setup; human in 'restricted' group with no user-scope grant → DENIED.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-D", allow=True)
        _grant(store, ResourceType.MCP_SERVER, "group", "restricted", "server-D", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-D",
            group_ids=["restricted"],
            principal_scope="user", principal_id="human@example.com",
            store=store,
        )
        assert result is False, (
            "Group deny must block humans in that group (principal_scope='user')."
        )


# ---------------------------------------------------------------------------
# Test 6.6 — No cross-scope key contamination
# ---------------------------------------------------------------------------

class TestNoScopeCrossContamination:
    """
    An agent-scope grant with id="alice@example.com" (pathological: agent_id that
    looks like an email) must NOT affect a user-scope resolution for the same id.
    """

    def test_agent_grant_does_not_affect_user_scope_lookup(self):
        """
        Org allows server-E.
        Agent-scope grant: agent:alice@example.com:server-E → allow=False
        User-scope lookup for alice@example.com → no user grant found → ALLOWED.
        The agent-scope key must NOT be read when principal_scope="user".
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-E", allow=True)
        # Agent-scope deny with an email-shaped agent_id
        _grant(store, ResourceType.MCP_SERVER, "agent", "alice@example.com", "server-E", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-E",
            principal_scope="user", principal_id="alice@example.com",
            store=store,
        )
        assert result is True, (
            "User-scope lookup (principal_scope='user') must NOT read the agent-scope key. "
            "perm:grant:mcp_server:user:alice@example.com:server-E is absent → ALLOWED. "
            "Scope isolation: agent key != user key even when id looks like an email."
        )

    def test_user_grant_does_not_affect_agent_scope_lookup(self):
        """
        Symmetric: user-scope deny for 'agent-X' must not bleed into
        agent-scope lookup for the same id.
        """
        store = _perm_store()
        _grant(store, ResourceType.MCP_SERVER, "org", "default", "server-E", allow=True)
        # User-scope deny with an agent-id-shaped user email
        _grant(store, ResourceType.MCP_SERVER, "user", "agent-X", "server-E", allow=False)

        result = _resolve(
            ResourceType.MCP_SERVER, "server-E",
            principal_scope="agent", principal_id="agent-X",
            store=store,
        )
        assert result is True, (
            "Agent-scope lookup (principal_scope='agent') must NOT read the user-scope key. "
            "perm:grant:mcp_server:agent:agent-X:server-E is absent → ALLOWED."
        )


# ---------------------------------------------------------------------------
# Test 6.7 — Admin get_effective endpoint previews agent-scope grant
# ---------------------------------------------------------------------------

def _make_state_and_perm_store():
    """
    Build a real BackofficeState with fakeredis-backed capability_policy_store.
    Mirrors the pattern used in test_permissions_api.py.
    Returns (state, perm_store).
    """
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.state import BackofficeState
    from unittest.mock import MagicMock

    redis = fakeredis.FakeRedis(decode_responses=False)
    cap_store = CapabilityPolicyStore(redis_client=redis, default_org_id="default")
    state = BackofficeState()
    state.capability_policy_store = cap_store
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()
    return state, cap_store.perm_store


class TestGetEffectiveAgentPreview:
    """Admin can call get_effective with agent_id to preview an agent's effective grant."""

    @pytest.mark.asyncio
    async def test_get_effective_with_agent_id_returns_agent_scope(self):
        """
        Setup: org grant AGENT/target-agent=allow; agent-scope deny caller-agent.
        GET /effective?resource_type=agent&resource_id=target-agent&agent_id=caller-agent
        →  effective=False, principal_scope="agent", principal_grant is not None.
        """
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        from unittest.mock import MagicMock

        state, perm_store = _make_state_and_perm_store()
        perm_store.set_boolean_grant(
            ResourceType.AGENT, "org", "default", "target-agent",
            BooleanGrantValue(allow=True),
        )
        perm_store.set_boolean_grant(
            ResourceType.AGENT, "agent", "caller-agent", "target-agent",
            BooleanGrantValue(allow=False),
        )

        fake_session = MagicMock()

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.get_effective(
                session=fake_session,
                resource_type="agent",
                resource_id="target-agent",
                org_id="default",
                user_id=None,
                agent_id="caller-agent",
                group_ids=None,
            )
        finally:
            perm_mod.backoffice_state = original

        assert result["principal_scope"] == "agent", (
            "principal_scope must be 'agent' when agent_id is supplied."
        )
        assert result["principal_id"] == "caller-agent", (
            "principal_id must match the agent_id supplied by the admin."
        )
        assert result["resolution_path"]["principal_grant"] is not None, (
            "principal_grant must be present in resolution_path when an agent-scope "
            "grant exists for this agent+resource combination."
        )
        assert result["effective_allow"] is False, (
            "Agent-scope deny on caller-agent must make effective_allow=False."
        )


# ---------------------------------------------------------------------------
# Test 6.8 — get_effective rejects ambiguous principal
# ---------------------------------------------------------------------------

class TestGetEffectiveAmbiguousPrincipal:
    """Supplying both user_id and agent_id must be rejected with 422."""

    @pytest.mark.asyncio
    async def test_both_user_email_and_agent_id_rejected(self):
        """
        GET /effective?...&user_id=alice@example.com&agent_id=some-agent
        must raise HTTPException(422, detail.error="ambiguous_principal").
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes import permissions as perm_mod
        from unittest.mock import MagicMock

        state, _ = _make_state_and_perm_store()
        fake_session = MagicMock()

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.get_effective(
                    session=fake_session,
                    resource_type="mcp_server",
                    resource_id="server-A",
                    org_id="default",
                    user_id="alice@example.com",
                    agent_id="some-agent",
                    group_ids=None,
                )
        finally:
            perm_mod.backoffice_state = original

        exc = exc_info.value
        assert exc.status_code == 422, (
            "Ambiguous principal (both user_id and agent_id) must return HTTP 422."
        )
        assert exc.detail.get("error") == "ambiguous_principal", (
            "Error code in detail must be 'ambiguous_principal'."
        )
