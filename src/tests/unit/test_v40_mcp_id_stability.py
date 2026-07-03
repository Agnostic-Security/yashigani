"""
v4.0 Item B — stable mcp_id tests.

MCP servers are now assigned a stable UUID (mcp_id) on first registration.
Grants are keyed by mcp_id, not agent_name.  Renaming a server entry must
NOT orphan existing grants when the operator carries the mcp_id forward via
the "mcp_id" pin in YASHIGANI_MCP_SERVERS.

Coverage:
  A. McpIdStore — get_or_mint
     A1. First call mints a new UUID
     A2. Second call for same agent_name returns same UUID
     A3. Minting is idempotent across multiple calls
     A4. Empty agent_name raises ValueError
     A5. None redis_client raises RuntimeError at construction
     A6. Operator-pinned override_mcp_id is honoured
     A7. Override is idempotent (repeated call with same override = same id)

  B. McpIdStore — reconcile_grants
     B1. Reconcile copies name-keyed grant to mcp_id-keyed grant
     B2. Reconcile is idempotent (second call is a no-op)
     B3. No source grant → copies nothing (returns 0)
     B4. mcp_id-keyed grant already present → no-op (returns 0)
     B5. Missing org_id / agent_name / mcp_id → returns 0 (no crash)

  C. McpBroker._check_connection_permit
     C1. ctx.mcp_id present → grant check uses mcp_id as key
     C2. ctx.mcp_id absent → falls back to ctx.server_id
     C3. ctx.mcp_id and server_id absent → falls back to agent_name
     C4. No grant at mcp_id key → denied (deny-by-default)
     C5. Grant at mcp_id key after rename → still allowed

  D. McpCallContext.mcp_id field
     D1. Defaults to "" (backward compatible)
     D2. Accepts string value

  E. McpBrokerServerConfig.mcp_id field
     E1. Defaults to "" (backward compatible)
     E2. Accepts string value

  F. build_registry_from_env — mcp_id minting
     F1. Without mcp_id_store: mcp_id defaults to "" (backward compat)
     F2. With mcp_id_store: server gets a non-empty mcp_id
     F3. Operator-pinned mcp_id in env entry is used verbatim

  G. Rename survivability (integration)
     G1. After rename without pin: new name gets new UUID → old grant orphaned
     G2. After rename with pin: same UUID preserved → grant still passes
"""
from __future__ import annotations

import json
import uuid
from typing import Optional
from unittest.mock import MagicMock, patch, AsyncMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fake_redis():
    """Return a fakeredis.FakeRedis instance, skip if not installed."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    return fakeredis.FakeRedis(decode_responses=False)


def _perm_store(redis=None):
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(redis or _fake_redis())


def _id_store(redis=None):
    from yashigani.mcp._id_store import McpIdStore
    return McpIdStore(redis or _fake_redis())


def _seed_by_name(store, agent_name: str, allow: bool = True, org_id: str = "org1") -> None:
    """Seed a name-keyed MCP_SERVER grant (pre-4.0 legacy key)."""
    from yashigani.permissions.model import ResourceType, BooleanGrantValue
    store.set_boolean_grant(
        resource_type=ResourceType.MCP_SERVER,
        scope_kind="org",
        scope_id=org_id,
        resource_id=agent_name,
        value=BooleanGrantValue(allow=allow),
    )


def _seed_by_id(store, mcp_id: str, allow: bool = True, org_id: str = "org1") -> None:
    """Seed an mcp_id-keyed MCP_SERVER grant (post-4.0 key)."""
    from yashigani.permissions.model import ResourceType, BooleanGrantValue
    store.set_boolean_grant(
        resource_type=ResourceType.MCP_SERVER,
        scope_kind="org",
        scope_id=org_id,
        resource_id=mcp_id,
        value=BooleanGrantValue(allow=allow),
    )


def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(
    agent_name: str = "test-server",
    server_id: str = "test-server",
    mcp_id: str = "",
    perm_store=None,
):
    from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
    posture, binding = _make_posture_b()
    return McpCallContext(
        tenant_id="t1",
        agent_name=agent_name,
        user_id="u1",
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name="search",
        server_id=server_id,
        mcp_id=mcp_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# A. McpIdStore — get_or_mint
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpIdStoreMint:
    """A1–A7: get_or_mint behaviour."""

    def test_a1_first_call_mints_uuid(self):
        """A1: First call mints a new UUID."""
        store = _id_store()
        mcp_id = store.get_or_mint("filesystem-mcp")
        # Must be a valid UUID
        uuid.UUID(mcp_id)

    def test_a2_second_call_returns_same_id(self):
        """A2: Second call for same agent_name returns same UUID."""
        store = _id_store()
        id1 = store.get_or_mint("filesystem-mcp")
        id2 = store.get_or_mint("filesystem-mcp")
        assert id1 == id2

    def test_a3_idempotent_across_calls(self):
        """A3: Multiple calls all return the same UUID."""
        store = _id_store()
        ids = [store.get_or_mint("my-server") for _ in range(10)]
        assert len(set(ids)) == 1, f"Expected 1 unique id, got: {set(ids)}"

    def test_a4_empty_agent_name_raises(self):
        """A4: Empty agent_name raises ValueError."""
        store = _id_store()
        with pytest.raises(ValueError):
            store.get_or_mint("")

    def test_a5_none_redis_raises_at_construction(self):
        """A5: None redis_client raises RuntimeError at McpIdStore construction."""
        from yashigani.mcp._id_store import McpIdStore
        with pytest.raises(RuntimeError):
            McpIdStore(None)

    def test_a6_operator_pin_honoured(self):
        """A6: override_mcp_id is stored and returned."""
        store = _id_store()
        pinned_id = "00000000-dead-beef-cafe-000000000001"
        result = store.get_or_mint("pinned-server", override_mcp_id=pinned_id)
        assert result == pinned_id

    def test_a7_override_idempotent(self):
        """A7: Repeated calls with same override_mcp_id return same id."""
        store = _id_store()
        pinned_id = "00000000-dead-beef-cafe-000000000002"
        ids = [
            store.get_or_mint("pinned-server", override_mcp_id=pinned_id)
            for _ in range(5)
        ]
        assert all(i == pinned_id for i in ids)

    def test_a_different_names_get_different_ids(self):
        """Two different server names get distinct UUIDs."""
        store = _id_store()
        id_a = store.get_or_mint("server-alpha")
        id_b = store.get_or_mint("server-beta")
        assert id_a != id_b


# ─────────────────────────────────────────────────────────────────────────────
# B. McpIdStore — reconcile_grants
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpIdStoreReconcile:
    """B1–B5: reconcile_grants backfill semantics."""

    def test_b1_copies_name_key_to_id_key(self):
        """B1: Reconcile copies name-keyed grant to mcp_id-keyed grant."""
        redis = _fake_redis()
        pstore = _perm_store(redis)
        id_store = _id_store(redis)

        agent_name = "filesystem-mcp"
        mcp_id = id_store.get_or_mint(agent_name)

        # Seed name-keyed grant (legacy pre-4.0 path)
        _seed_by_name(pstore, agent_name, allow=True)

        copied = id_store.reconcile_grants(pstore, "org1", agent_name, mcp_id)
        assert copied == 1

        # mcp_id key must now have the grant
        from yashigani.permissions.model import ResourceType
        grant = pstore.get_boolean_grant(ResourceType.MCP_SERVER, "org", "org1", mcp_id)
        assert grant is not None
        assert grant.allow is True

    def test_b2_reconcile_idempotent(self):
        """B2: Second reconcile call is a no-op (returns 0)."""
        redis = _fake_redis()
        pstore = _perm_store(redis)
        id_store = _id_store(redis)

        agent_name = "server-b"
        mcp_id = id_store.get_or_mint(agent_name)
        _seed_by_name(pstore, agent_name, allow=True)

        id_store.reconcile_grants(pstore, "org1", agent_name, mcp_id)
        second = id_store.reconcile_grants(pstore, "org1", agent_name, mcp_id)
        assert second == 0

    def test_b3_no_source_grant_copies_nothing(self):
        """B3: No name-keyed grant → reconcile returns 0."""
        redis = _fake_redis()
        pstore = _perm_store(redis)
        id_store = _id_store(redis)

        agent_name = "server-no-grant"
        mcp_id = id_store.get_or_mint(agent_name)

        copied = id_store.reconcile_grants(pstore, "org1", agent_name, mcp_id)
        assert copied == 0

    def test_b4_id_key_already_present_no_op(self):
        """B4: mcp_id-keyed grant already present → no-op (mcp_id key wins)."""
        redis = _fake_redis()
        pstore = _perm_store(redis)
        id_store = _id_store(redis)

        agent_name = "server-c"
        mcp_id = id_store.get_or_mint(agent_name)

        # Both keys seeded — mcp_id key takes priority
        _seed_by_name(pstore, agent_name, allow=True)
        _seed_by_id(pstore, mcp_id, allow=True)

        copied = id_store.reconcile_grants(pstore, "org1", agent_name, mcp_id)
        assert copied == 0

    def test_b5_missing_identifiers_no_crash(self):
        """B5: Missing org_id / agent_name / mcp_id → returns 0, no crash."""
        redis = _fake_redis()
        pstore = _perm_store(redis)
        id_store = _id_store(redis)

        assert id_store.reconcile_grants(pstore, "", "agent", "uuid-x") == 0
        assert id_store.reconcile_grants(pstore, "org1", "", "uuid-x") == 0
        assert id_store.reconcile_grants(pstore, "org1", "agent", "") == 0


# ─────────────────────────────────────────────────────────────────────────────
# C. McpBroker._check_connection_permit with mcp_id
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectionPermitWithMcpId:
    """C1–C5: _check_connection_permit prefers mcp_id as grant key."""

    def _broker(self, perm_store):
        from yashigani.mcp.broker import McpBroker, McpBrokerConfig
        from yashigani.mcp._jwt import McpJwtIssuer

        issuer = McpJwtIssuer(tenant_id="t1")
        config = McpBrokerConfig(
            opa_url="http://opa:8181",
            tenant_id="t1",
            issuer=issuer,
            org_id="org1",
            permission_store=perm_store,
        )
        return McpBroker(config=config)

    def test_c1_mcp_id_used_as_grant_key(self):
        """C1: Grant at mcp_id key → permitted when ctx.mcp_id is set."""
        store = _perm_store()
        mcp_id = str(uuid.uuid4())
        _seed_by_id(store, mcp_id, allow=True)

        broker = self._broker(store)
        ctx = _make_ctx(agent_name="old-name", server_id="old-name", mcp_id=mcp_id)
        result = broker._check_connection_permit(ctx)
        assert result is None, f"Expected None (permitted), got: {result}"

    def test_c2_fallback_to_server_id(self):
        """C2: ctx.mcp_id absent → falls back to ctx.server_id."""
        store = _perm_store()
        _seed_by_id(store, "server-x")

        broker = self._broker(store)
        ctx = _make_ctx(agent_name="agent-a", server_id="server-x", mcp_id="")
        result = broker._check_connection_permit(ctx)
        assert result is None, f"Expected None (permitted), got: {result}"

    def test_c3_fallback_to_agent_name(self):
        """C3: Both mcp_id and server_id absent → falls back to agent_name."""
        store = _perm_store()
        _seed_by_id(store, "agent-fallback")

        broker = self._broker(store)
        ctx = _make_ctx(agent_name="agent-fallback", server_id="", mcp_id="")
        result = broker._check_connection_permit(ctx)
        assert result is None, f"Expected None (permitted), got: {result}"

    def test_c4_no_grant_at_mcp_id_denied(self):
        """C4: Grant at mcp_id key absent → denied."""
        store = _perm_store()
        # Do NOT seed the mcp_id
        broker = self._broker(store)
        ctx = _make_ctx(mcp_id=str(uuid.uuid4()))
        result = broker._check_connection_permit(ctx)
        assert result == "mcp_server_not_permitted", f"Expected deny, got: {result}"

    def test_c5_rename_with_same_mcp_id_preserves_grant(self):
        """C5: Server renamed but same mcp_id pinned → grant still passes."""
        store = _perm_store()
        mcp_id = str(uuid.uuid4())
        # Grant is keyed by mcp_id (not old or new name)
        _seed_by_id(store, mcp_id, allow=True)

        broker = self._broker(store)
        # old_name and new_name share the same mcp_id
        ctx_old = _make_ctx(agent_name="old-server", mcp_id=mcp_id)
        ctx_new = _make_ctx(agent_name="new-server", mcp_id=mcp_id)

        assert broker._check_connection_permit(ctx_old) is None
        assert broker._check_connection_permit(ctx_new) is None


# ─────────────────────────────────────────────────────────────────────────────
# D. McpCallContext.mcp_id field
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpCallContextMcpId:
    """D1–D2: McpCallContext.mcp_id field."""

    def test_d1_defaults_to_empty_string(self):
        """D1: mcp_id defaults to '' (backward compatible)."""
        ctx = _make_ctx()
        assert ctx.mcp_id == ""

    def test_d2_accepts_string_value(self):
        """D2: mcp_id accepts a UUID string."""
        mcp_id = str(uuid.uuid4())
        ctx = _make_ctx(mcp_id=mcp_id)
        assert ctx.mcp_id == mcp_id


# ─────────────────────────────────────────────────────────────────────────────
# E. McpBrokerServerConfig.mcp_id field
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpBrokerServerConfigMcpId:
    """E1–E2: McpBrokerServerConfig.mcp_id field."""

    def test_e1_defaults_to_empty_string(self):
        """E1: mcp_id defaults to '' (backward compatible)."""
        from yashigani.mcp.registry import McpBrokerServerConfig
        cfg = McpBrokerServerConfig(
            agent_name="test",
            upstream_url="http://localhost:9000",
            tenant_id="t1",
            is_filesystem_agent=False,
        )
        assert cfg.mcp_id == ""

    def test_e2_accepts_string_value(self):
        """E2: mcp_id accepts a UUID string."""
        from yashigani.mcp.registry import McpBrokerServerConfig
        mcp_id = str(uuid.uuid4())
        cfg = McpBrokerServerConfig(
            agent_name="test",
            upstream_url="http://localhost:9000",
            tenant_id="t1",
            is_filesystem_agent=False,
            mcp_id=mcp_id,
        )
        assert cfg.mcp_id == mcp_id


# ─────────────────────────────────────────────────────────────────────────────
# F. build_registry_from_env — mcp_id minting
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildRegistryFromEnvMcpId:
    """F1–F3: build_registry_from_env wires mcp_id_store."""

    _ENV = json.dumps([{
        "agent_name": "my-mcp",
        "upstream_url": "http://localhost:9000",
        "tenant_id": "t1",
    }])

    def test_f1_without_id_store_mcp_id_empty(self):
        """F1: Without mcp_id_store, server cfg mcp_id defaults to ''."""
        from yashigani.mcp.registry import build_registry_from_env

        with patch.dict("os.environ", {"YASHIGANI_MCP_SERVERS": self._ENV}):
            registry, _ = build_registry_from_env(
                opa_url="http://opa:8181",
                mcp_id_store=None,
            )
        entry = registry.get("my-mcp")
        assert entry is not None
        _, cfg = entry
        assert cfg.mcp_id == ""

    def test_f2_with_id_store_server_gets_mcp_id(self):
        """F2: With mcp_id_store, server cfg gets a non-empty mcp_id."""
        from yashigani.mcp.registry import build_registry_from_env
        from yashigani.mcp._id_store import McpIdStore

        id_store = McpIdStore(_fake_redis())

        with patch.dict("os.environ", {"YASHIGANI_MCP_SERVERS": self._ENV}):
            registry, _ = build_registry_from_env(
                opa_url="http://opa:8181",
                mcp_id_store=id_store,
            )
        entry = registry.get("my-mcp")
        assert entry is not None
        _, cfg = entry
        assert cfg.mcp_id != "", "Expected non-empty mcp_id from McpIdStore"
        uuid.UUID(cfg.mcp_id)  # Must be a valid UUID

    def test_f3_operator_pin_used_verbatim(self):
        """F3: Operator-pinned mcp_id in env entry is used verbatim."""
        from yashigani.mcp.registry import build_registry_from_env
        from yashigani.mcp._id_store import McpIdStore

        pinned = "00000000-cafe-babe-0000-000000000001"
        env = json.dumps([{
            "agent_name": "pinned-mcp",
            "upstream_url": "http://localhost:9001",
            "tenant_id": "t1",
            "mcp_id": pinned,
        }])
        id_store = McpIdStore(_fake_redis())

        with patch.dict("os.environ", {"YASHIGANI_MCP_SERVERS": env}):
            registry, _ = build_registry_from_env(
                opa_url="http://opa:8181",
                mcp_id_store=id_store,
            )
        entry = registry.get("pinned-mcp")
        assert entry is not None
        _, cfg = entry
        assert cfg.mcp_id == pinned


# ─────────────────────────────────────────────────────────────────────────────
# G. Rename survivability (integration)
# ─────────────────────────────────────────────────────────────────────────────

class TestRenameSurvivability:
    """G1–G2: Rename scenarios with and without operator mcp_id pin."""

    def test_g1_rename_without_pin_orphans_grant(self):
        """G1: Rename without pin mints new UUID → old grant orphaned (expected)."""
        redis = _fake_redis()
        id_store = _id_store(redis)
        pstore = _perm_store(redis)

        # "Old" server registered with its name
        old_id = id_store.get_or_mint("filesystem-mcp")
        _seed_by_id(pstore, old_id, allow=True, org_id="org1")

        # Operator renames "filesystem-mcp" → "filesystem" WITHOUT pin
        new_id = id_store.get_or_mint("filesystem")
        assert new_id != old_id, "Rename without pin should mint a NEW uuid"

        # Grant is at old_id — new_id has no grant
        from yashigani.permissions.model import ResourceType
        grant = pstore.get_boolean_grant(ResourceType.MCP_SERVER, "org", "org1", new_id)
        assert grant is None, "Without pin, new name should have no grant (orphaned)"

    def test_g2_rename_with_pin_preserves_grant(self):
        """G2: Rename with operator pin (same override_mcp_id) → grant preserved."""
        redis = _fake_redis()
        id_store = _id_store(redis)
        pstore = _perm_store(redis)

        # "Old" server registered
        old_id = id_store.get_or_mint("filesystem-mcp")
        _seed_by_id(pstore, old_id, allow=True, org_id="org1")

        # Operator renames "filesystem-mcp" → "filesystem" WITH old_id pin
        carried_id = id_store.get_or_mint("filesystem", override_mcp_id=old_id)
        assert carried_id == old_id, "With override pin, same UUID should be preserved"

        # Grant at old_id is still valid under carried_id (same key)
        from yashigani.permissions.model import ResourceType
        grant = pstore.get_boolean_grant(ResourceType.MCP_SERVER, "org", "org1", carried_id)
        assert grant is not None, "With pin, grant must still be reachable under same UUID"
        assert grant.allow is True
