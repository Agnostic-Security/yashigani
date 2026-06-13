"""Tests for IdentityDurableStore + reconcile_identities_from_durable (Task 2).

These are unit tests that mock the Postgres connection so they run without a
live database.  The integration test (test_identity_durable_store_integration.py)
exercises the full create→flush→reconcile→restored cycle against a live DB and
is marked ``integration``.

Coverage:
  - IdentityDurableStore.upsert / update_status / delete / list_all
  - reconcile_identities_from_durable: Postgres→Redis restore path
  - reconcile_identities_from_durable: back-fill path (empty Postgres, Redis has data)
  - IdentityRegistry dual-write: register wires durable upsert
  - IdentityRegistry dual-write: suspend/reactivate/deactivate wire durable calls
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest
import fakeredis


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def mock_durable():
    """A mock IdentityDurableStore."""
    d = MagicMock()
    d.list_all.return_value = []
    d.list_all_minimal.return_value = []
    return d


@pytest.fixture
def registry(fake_redis, mock_durable):
    from yashigani.identity.registry import IdentityRegistry
    return IdentityRegistry(redis_client=fake_redis, durable_store=mock_durable)


# ---------------------------------------------------------------------------
# IdentityRegistry dual-write: register
# ---------------------------------------------------------------------------

class TestDualWriteRegister:
    def test_register_calls_durable_upsert(self, registry, mock_durable):
        """register() must dual-write to the durable store (SERVICE kind — no Lua)."""
        from yashigani.identity.registry import IdentityKind
        identity_id, key = registry.register(
            kind=IdentityKind.SERVICE,
            name="Test Service",
            slug="test-service-dw",
        )
        mock_durable.upsert.assert_called_once()
        call_kwargs = mock_durable.upsert.call_args[0][0]
        assert call_kwargs["identity_id"] == identity_id
        assert call_kwargs["slug"] == "test-service-dw"
        assert call_kwargs["kind"] == "service"

    def test_register_service_calls_durable_upsert(self, registry, mock_durable):
        """SERVICE kind register also dual-writes."""
        from yashigani.identity.registry import IdentityKind
        identity_id, key = registry.register(
            kind=IdentityKind.SERVICE,
            name="Test Service",
            slug="test-service",
        )
        mock_durable.upsert.assert_called_once()
        call_data = mock_durable.upsert.call_args[0][0]
        assert call_data["kind"] == "service"
        assert call_data["status"] == "active"

    def test_durable_upsert_failure_does_not_abort_register(self, registry, mock_durable):
        """Durable write failure must NOT abort registration (Redis stays live)."""
        mock_durable.upsert.side_effect = RuntimeError("DB down")
        from yashigani.identity.registry import IdentityKind
        # Should succeed — durable failure is best-effort
        identity_id, key = registry.register(
            kind=IdentityKind.SERVICE,
            name="Resilient Agent",
            slug="resilient-agent",
        )
        assert identity_id.startswith("idnt_")
        # Verify it IS in Redis despite the durable failure
        assert registry.get(identity_id) is not None


# ---------------------------------------------------------------------------
# IdentityRegistry dual-write: status mutations
# ---------------------------------------------------------------------------

class TestDualWriteStatusMutations:
    def _register_service(self, registry):
        from yashigani.identity.registry import IdentityKind
        iid, _ = registry.register(kind=IdentityKind.SERVICE, name="SvcA", slug="svc-a")
        return iid

    def test_suspend_calls_durable_update_status(self, registry, mock_durable):
        iid = self._register_service(registry)
        mock_durable.reset_mock()
        registry.suspend(iid)
        mock_durable.update_status.assert_called_once_with(iid, "suspended")

    def test_reactivate_calls_durable_update_status(self, registry, mock_durable):
        iid = self._register_service(registry)
        registry.suspend(iid)
        mock_durable.reset_mock()
        registry.reactivate(iid)
        mock_durable.update_status.assert_called_once_with(iid, "active")

    def test_deactivate_calls_durable_delete(self, registry, mock_durable):
        iid = self._register_service(registry)
        mock_durable.reset_mock()
        registry.deactivate(iid)
        mock_durable.delete.assert_called_once_with(iid)

    def test_status_mutation_failure_does_not_abort(self, registry, mock_durable):
        """Durable failure on suspend must not raise."""
        mock_durable.update_status.side_effect = RuntimeError("DB down")
        iid = self._register_service(registry)
        # Must not raise
        registry.suspend(iid)
        # Redis state still updated
        rec = registry.get(iid)
        assert rec["status"] == "suspended"


# ---------------------------------------------------------------------------
# reconcile_identities_from_durable: restore path
# ---------------------------------------------------------------------------

class TestReconcileRestorePath:
    def test_restores_missing_identity_from_postgres(self, fake_redis):
        """An identity in Postgres but NOT in Redis should be restored."""
        from yashigani.identity.registry import IdentityRegistry
        from yashigani.identity.durable_store import reconcile_identities_from_durable

        mock_durable = MagicMock()
        mock_durable.list_all.return_value = [
            {
                "identity_id": "idnt_aabbccddeeff",
                "kind": "service",
                "name": "Restored Agent",
                "slug": "restored-agent",
                "description": "",
                "expertise": [],
                "system_prompt": "",
                "model_preference": "",
                "sensitivity_ceiling": "PUBLIC",
                "upstream_url": "",
                "container_image": "",
                "container_config": {},
                "capabilities": [],
                "allowed_tools": [],
                "allowed_models": [],
                "icon_url": "",
                "groups": [],
                "allowed_callers": [],
                "allowed_paths": [],
                "allowed_cidrs": [],
                "org_id": "",
                "bound_spiffe_uri": "",
                "api_key_hash": "$2b$12$fakehashvalue",
                "status": "active",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "last_seen_at": "",
                "token_rotation_schedule": "",
                "api_key_created_at": "2026-01-01T00:00:00+00:00",
                "api_key_expires_at": "2026-12-31T00:00:00+00:00",
                "api_key_rotated_at": "2026-01-01T00:00:00+00:00",
            }
        ]

        # Redis starts EMPTY
        reg = IdentityRegistry(redis_client=fake_redis, durable_store=mock_durable)

        restored = reconcile_identities_from_durable(reg, mock_durable)
        assert restored == 1

        # Identity should now be in Redis
        identity = reg.get("idnt_aabbccddeeff")
        assert identity is not None
        assert identity["slug"] == "restored-agent"
        assert identity["kind"] == "service"

    def test_skips_identity_already_in_redis(self, fake_redis):
        """An identity already in Redis must not be overwritten."""
        from yashigani.identity.registry import IdentityRegistry, IdentityKind
        from yashigani.identity.durable_store import reconcile_identities_from_durable

        mock_durable = MagicMock()
        # Pre-register the identity in Redis
        reg = IdentityRegistry(redis_client=fake_redis, durable_store=mock_durable)
        iid, _ = reg.register(kind=IdentityKind.SERVICE, name="Existing", slug="existing")
        mock_durable.reset_mock()

        # Durable also has it
        existing_rec = reg.get(iid)
        existing_rec["api_key_hash"] = ""
        mock_durable.list_all.return_value = [existing_rec]

        restored = reconcile_identities_from_durable(reg, mock_durable)
        assert restored == 0  # Nothing to restore

    def test_returns_zero_when_no_durable(self, fake_redis):
        from yashigani.identity.registry import IdentityRegistry
        from yashigani.identity.durable_store import reconcile_identities_from_durable

        reg = IdentityRegistry(redis_client=fake_redis)
        restored = reconcile_identities_from_durable(reg, None)
        assert restored == 0

    def test_returns_zero_on_durable_list_failure(self, fake_redis):
        from yashigani.identity.registry import IdentityRegistry
        from yashigani.identity.durable_store import reconcile_identities_from_durable

        mock_durable = MagicMock()
        mock_durable.list_all.side_effect = RuntimeError("DB unreachable")
        reg = IdentityRegistry(redis_client=fake_redis, durable_store=mock_durable)
        # Must not raise
        restored = reconcile_identities_from_durable(reg, mock_durable)
        assert restored == 0


# ---------------------------------------------------------------------------
# reconcile_identities_from_durable: back-fill path
# ---------------------------------------------------------------------------

class TestReconcileBackfillPath:
    def test_backfills_postgres_from_redis_when_postgres_empty(self, fake_redis):
        """When Postgres is empty and Redis has identities, back-fill Postgres."""
        from yashigani.identity.registry import IdentityRegistry, IdentityKind
        from yashigani.identity.durable_store import reconcile_identities_from_durable

        mock_durable = MagicMock()
        mock_durable.list_all.return_value = []       # Postgres empty
        mock_durable.list_all_minimal.return_value = []  # No existing rows

        reg = IdentityRegistry(redis_client=fake_redis, durable_store=mock_durable)
        # Put an identity in Redis (registered before this fix existed)
        iid, _ = reg.register(kind=IdentityKind.SERVICE, name="Old Agent", slug="old-agent")
        mock_durable.reset_mock()
        mock_durable.list_all.return_value = []  # Still empty after register (mock doesn't persist)
        mock_durable.list_all_minimal.return_value = []

        reconcile_identities_from_durable(reg, mock_durable)

        # Should have back-filled: upsert called with the Redis identity
        mock_durable.upsert.assert_called()
        upserted = mock_durable.upsert.call_args[0][0]
        assert upserted["identity_id"] == iid


# ---------------------------------------------------------------------------
# IdentityDurableStore unit tests (mocked connection)
# ---------------------------------------------------------------------------

class TestIdentityDurableStoreUnit:
    def _make_store(self):
        from yashigani.identity.durable_store import IdentityDurableStore
        store = IdentityDurableStore(dsn="postgresql://fake:fake@localhost:5432/fake")
        return store

    def test_upsert_raises_on_missing_identity_id(self):
        store = self._make_store()
        with pytest.raises(ValueError, match="missing identity_id"):
            with patch.object(store, "_connect"):
                store.upsert({"name": "no id here"})

    def test_list_all_normalises_timestamps(self):
        """list_all() must return ISO strings for timestamp columns, not datetime objects."""
        import datetime
        store = self._make_store()
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_cur.__enter__ = MagicMock(return_value=mock_cur)
        mock_cur.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cur

        # Simulate a row with datetime objects in timestamp columns
        now = datetime.datetime(2026, 6, 13, 12, 0, 0, tzinfo=datetime.timezone.utc)
        col_names = [
            "identity_id", "kind", "name", "slug", "description",
            "expertise", "system_prompt", "model_preference",
            "sensitivity_ceiling", "upstream_url", "container_image",
            "container_config", "capabilities", "allowed_tools",
            "allowed_models", "icon_url", "groups", "allowed_callers",
            "allowed_paths", "allowed_cidrs", "org_id",
            "bound_spiffe_uri", "api_key_hash", "status",
            "created_at", "updated_at", "last_seen_at",
            "token_rotation_schedule", "api_key_created_at",
            "api_key_expires_at", "api_key_rotated_at",
        ]
        row = (
            "idnt_abc", "service", "Test", "test-slug", "",
            "[]", "", "",
            "PUBLIC", "", "",
            "{}", "[]", "[]",
            "[]", "", "[]", "[]",
            "[]", "[]", "",
            "", "", "active",
            now, now, None,
            "", now, now, now,
        )
        mock_cur.description = [(col,) for col in col_names]
        mock_cur.fetchall.return_value = [row]

        with patch.object(store, "_connect", return_value=mock_conn):
            results = store.list_all()

        assert len(results) == 1
        assert isinstance(results[0]["created_at"], str)
        assert results[0]["last_seen_at"] == ""
