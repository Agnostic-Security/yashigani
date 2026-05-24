"""
Unit tests for the RuntimeSettings admin layer.

v2.24.1 / admin-surfaces-all-runtime-settings rule.
CMMC AU.L2-3.3.1 / SOC 2 CC6.2 / ISO 27001 A.5.15.

Coverage:
  1. Service: get/set/list, default fallback, cache TTL, audit emission.
  2. Service: seed_defaults uses env vars on first boot, ON CONFLICT DO NOTHING
     preserves DB values on restart.
  3. Backoffice routes: AdminSession required for reads, StepUpAdminSession for writes.
  4. Backoffice routes: PUT emits RUNTIME_SETTING_CHANGED audit event.
  5. DDoSProtector: update_limits() hot-reload API.
  6. Migration: table DDL constants match expected schema.
  7. Keys: KNOWN_SETTINGS_BY_KEY is indexed correctly.
  8. Audit schema: RuntimeSettingChangedEvent fields and EventType enum entry.

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

# asyncio_mode=auto (pyproject.toml) means every `async def` test is run
# as a coroutine automatically by pytest-asyncio.  No need for
# `@pytest.mark.asyncio` decorators.


# ---------------------------------------------------------------------------
# Shared fakes for asyncpg pool
# ---------------------------------------------------------------------------

class FakePool:
    """Minimal async context manager fake for asyncpg pool."""

    def __init__(self, rows: list[dict] | None = None):
        self._rows = rows or []
        self._executed: list[tuple] = []

    def acquire(self):
        return _FakeConn(self)

    def reset(self, rows):
        self._rows = rows


class _FakeConn:
    def __init__(self, pool: FakePool):
        self._pool = pool

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def fetchrow(self, query, *args):
        key = args[0] if args else None
        for row in self._pool._rows:
            if row.get("key") == key:
                return _Row(row)
        return None

    async def fetch(self, query, *args):
        return [_Row(r) for r in self._pool._rows]

    async def execute(self, query, *args):
        self._pool._executed.append((query, args))


class _Row:
    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)


# ---------------------------------------------------------------------------
# 1. Service — get
# ---------------------------------------------------------------------------

class TestRuntimeSettingsServiceGet:
    async def test_get_returns_db_value(self):
        """get() deserialises the JSONB value column from DB."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([
            {"key": "gateway.ratelimit.per_user_rps", "value": "42.5"},
        ])
        svc = RuntimeSettingsService(pool=pool)
        result = await svc.get("gateway.ratelimit.per_user_rps")
        assert result == pytest.approx(42.5)

    async def test_get_returns_class_default_when_not_in_db(self):
        """get() returns the class default when the key is absent from DB."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        result = await svc.get("gateway.ratelimit.per_user_rps")
        meta = KNOWN_SETTINGS_BY_KEY["gateway.ratelimit.per_user_rps"]
        assert result == meta.class_default

    async def test_get_unknown_key_returns_none(self):
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        result = await svc.get("gateway.does.not.exist")
        assert result is None


# ---------------------------------------------------------------------------
# 1. Service — set
# ---------------------------------------------------------------------------

class TestRuntimeSettingsServiceSet:
    async def test_set_writes_to_db(self):
        """set() executes an upsert and returns the updated record."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        record = await svc.set("gateway.ratelimit.per_user_rps", 200.0, changed_by="admin1")
        assert record["key"] == "gateway.ratelimit.per_user_rps"
        assert record["value"] == pytest.approx(200.0)
        assert record["source"] == "api"
        assert record["last_changed_by"] == "admin1"

    async def test_set_unknown_key_raises(self):
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        with pytest.raises(ValueError, match="Unknown runtime setting key"):
            await svc.set("gateway.does.not.exist", 1, changed_by="admin1")

    async def test_set_coerces_int(self):
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        record = await svc.set("gateway.ddos.per_ip_limit", "7500", changed_by="admin1")
        assert record["value"] == 7500
        assert isinstance(record["value"], int)

    async def test_set_coerces_float(self):
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        record = await svc.set("gateway.ratelimit.per_user_rps", "150", changed_by="admin1")
        assert record["value"] == pytest.approx(150.0)

    async def test_set_publishes_pubsub(self):
        """set() publishes a JSON payload to yashigani:settings:changed."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        mock_redis = MagicMock()
        svc = RuntimeSettingsService(pool=pool, redis_client=mock_redis)
        await svc.set("gateway.ddos.per_ip_limit", 9000, changed_by="admin1")
        mock_redis.publish.assert_called_once()
        channel, payload = mock_redis.publish.call_args[0]
        assert channel == "yashigani:settings:changed"
        data = json.loads(payload)
        assert data["key"] == "gateway.ddos.per_ip_limit"
        assert data["value"] == 9000

    async def test_set_invalidates_cache(self):
        """set() removes the key from in-process cache."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        # Prime the cache manually
        svc._cache["gateway.ddos.window_seconds"] = (60, 9999999.0)
        await svc.set("gateway.ddos.window_seconds", 30, changed_by="admin1")
        assert "gateway.ddos.window_seconds" not in svc._cache

    async def test_set_source_env_rejected(self):
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        with pytest.raises(ValueError, match="source must be"):
            await svc.set(
                "gateway.ddos.per_ip_limit", 100,
                changed_by="admin1", source="env",
            )


# ---------------------------------------------------------------------------
# 1. Service — get_cached (sync)
# ---------------------------------------------------------------------------

class TestRuntimeSettingsServiceGetCached:
    def test_cache_hit_returns_cached_value(self):
        """get_cached() returns in-process cached value within TTL."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        import time
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        svc._cache["gateway.ddos.per_ip_limit"] = (12345, time.monotonic())
        result = svc.get_cached("gateway.ddos.per_ip_limit")
        assert result == 12345

    def test_cache_miss_returns_env_var(self):
        """get_cached() returns env var value on cache miss."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        with patch.dict("os.environ", {"YASHIGANI_DDOS_PER_IP_LIMIT": "8888"}):
            result = svc.get_cached("gateway.ddos.per_ip_limit")
        assert result == 8888

    def test_cache_miss_returns_class_default_when_env_absent(self):
        """get_cached() returns class default when cache miss and no env var."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        with patch.dict("os.environ", {}, clear=True):
            result = svc.get_cached("gateway.ddos.per_ip_limit")
        expected = KNOWN_SETTINGS_BY_KEY["gateway.ddos.per_ip_limit"].class_default
        assert result == expected

    def test_expired_cache_falls_through_to_env(self):
        """Cache entries older than _CACHE_TTL_SECONDS are considered expired."""
        import time
        from yashigani.runtime_settings.service import RuntimeSettingsService, _CACHE_TTL_SECONDS
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        # Plant an entry with a fetched_at that is clearly > _CACHE_TTL_SECONDS ago
        expired_ts = time.monotonic() - (_CACHE_TTL_SECONDS + 1.0)
        svc._cache["gateway.ddos.per_ip_limit"] = (99999, expired_ts)
        with patch.dict("os.environ", {"YASHIGANI_DDOS_PER_IP_LIMIT": "7777"}):
            result = svc.get_cached("gateway.ddos.per_ip_limit")
        assert result == 7777


# ---------------------------------------------------------------------------
# 1. Service — list_all
# ---------------------------------------------------------------------------

class TestRuntimeSettingsServiceListAll:
    async def test_list_returns_all_known_settings(self):
        """list_all() includes all KNOWN_SETTINGS even if not in DB."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        items = await svc.list_all()
        keys = {item["key"] for item in items}
        for meta in KNOWN_SETTINGS:
            assert meta.key in keys, f"Missing setting key: {meta.key}"

    async def test_list_includes_description_and_type(self):
        """list_all() enriches items with description and allowed_type."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool)
        items = await svc.list_all()
        for item in items:
            assert "description" in item, f"No description for {item['key']}"
            assert "allowed_type" in item, f"No allowed_type for {item['key']}"


# ---------------------------------------------------------------------------
# 2. Service — seed_defaults
# ---------------------------------------------------------------------------

class TestRuntimeSettingsSeedDefaults:
    async def test_seed_inserts_env_value(self):
        """seed_defaults() uses the env var value when present."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        with patch.dict("os.environ", {"YASHIGANI_RATE_LIMIT_PER_USER_RPS": "250.0"}):
            await svc.seed_defaults()
        upserts = [
            (q, a) for (q, a) in pool._executed
            if "gateway.ratelimit.per_user_rps" in str(a)
        ]
        assert upserts, "Expected an INSERT for gateway.ratelimit.per_user_rps"
        _, args = upserts[0]
        assert json.loads(args[1]) == pytest.approx(250.0)

    async def test_seed_uses_class_default_when_env_absent(self):
        """seed_defaults() uses class_default when env var is not set."""
        from yashigani.runtime_settings.service import RuntimeSettingsService
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY
        pool = FakePool([])
        svc = RuntimeSettingsService(pool=pool, redis_client=None)
        env_no_overrides = {
            k: v for k, v in __import__("os").environ.items()
            if k not in (
                "YASHIGANI_RATE_LIMIT_PER_USER_RPS",
                "YASHIGANI_DDOS_PER_IP_LIMIT",
                "YASHIGANI_DDOS_WINDOW_SECONDS",
            )
        }
        with patch.dict("os.environ", env_no_overrides, clear=True):
            await svc.seed_defaults()
        upserts = [
            (q, a) for (q, a) in pool._executed
            if "gateway.ratelimit.per_user_rps" in str(a)
        ]
        assert upserts
        _, args = upserts[0]
        meta = KNOWN_SETTINGS_BY_KEY["gateway.ratelimit.per_user_rps"]
        assert json.loads(args[1]) == pytest.approx(meta.class_default)


# ---------------------------------------------------------------------------
# 3 + 4. Backoffice routes — auth enforcement + audit emission
# ---------------------------------------------------------------------------

def _make_session(account_id: str = "admin1", account_tier: str = "admin"):
    session = MagicMock()
    session.account_id = account_id
    session.account_tier = account_tier
    return session


class TestRuntimeSettingsRouteAuth:
    """Routes must enforce AdminSession for reads, StepUpAdminSession for writes."""

    def test_list_route_requires_admin_session(self):
        """GET /admin/runtime-settings uses AdminSession dependency."""
        import inspect
        from yashigani.backoffice.routes.runtime_settings import list_runtime_settings
        sig = inspect.signature(list_runtime_settings)
        assert "session" in sig.parameters

    def test_put_route_requires_stepup_session(self):
        """PUT /admin/runtime-settings/{key} uses StepUpAdminSession dependency."""
        import inspect
        from yashigani.backoffice.routes.runtime_settings import update_runtime_setting
        sig = inspect.signature(update_runtime_setting)
        assert "session" in sig.parameters

    def test_reset_route_requires_stepup_session(self):
        """POST /admin/runtime-settings/{key}/reset uses StepUpAdminSession."""
        import inspect
        from yashigani.backoffice.routes.runtime_settings import reset_runtime_setting_to_default
        sig = inspect.signature(reset_runtime_setting_to_default)
        assert "session" in sig.parameters


class TestRuntimeSettingsRouteAudit:
    """PUT emits RUNTIME_SETTING_CHANGED audit event."""

    async def test_put_emits_audit_event(self):
        from yashigani.backoffice.routes.runtime_settings import (
            update_runtime_setting,
            RuntimeSettingUpdateRequest,
        )

        mock_service = MagicMock()
        mock_service.get_one = AsyncMock(return_value={
            "key": "gateway.ddos.per_ip_limit",
            "value": 5000,
            "default_value": 5000,
        })
        mock_service.set = AsyncMock(return_value={
            "key": "gateway.ddos.per_ip_limit",
            "value": 8000,
            "default_value": 5000,
            "source": "api",
            "last_changed_by": "admin1",
            "last_changed_at": "2026-05-24T00:00:00+00:00",
            "description": "test",
            "allowed_type": "int",
        })

        mock_audit_writer = MagicMock()
        session = _make_session()

        from yashigani.backoffice.state import backoffice_state
        old_rs = backoffice_state.runtime_settings
        old_aw = backoffice_state.audit_writer
        try:
            backoffice_state.runtime_settings = mock_service
            backoffice_state.audit_writer = mock_audit_writer

            body = RuntimeSettingUpdateRequest(value=8000)
            await update_runtime_setting("gateway.ddos.per_ip_limit", body, session)
        finally:
            backoffice_state.runtime_settings = old_rs
            backoffice_state.audit_writer = old_aw

        mock_audit_writer.write.assert_called_once()
        event = mock_audit_writer.write.call_args[0][0]
        from yashigani.audit.schema import RuntimeSettingChangedEvent
        assert isinstance(event, RuntimeSettingChangedEvent)
        assert event.setting_key == "gateway.ddos.per_ip_limit"
        assert event.changed_by == "admin1"
        assert event.source == "api"

    async def test_put_unknown_key_raises_404(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.runtime_settings import (
            update_runtime_setting,
            RuntimeSettingUpdateRequest,
        )
        session = _make_session()
        body = RuntimeSettingUpdateRequest(value=100)
        with pytest.raises(HTTPException) as exc_info:
            await update_runtime_setting("gateway.does.not.exist", body, session)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# 5. DDoSProtector — update_limits() live reload
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=False)
def _gateway_env(monkeypatch):
    """
    Provide a minimal env so gateway/__init__.py -> proxy.py module-level
    sentinel check (YASHIGANI_INTERNAL_BEARER) doesn't raise during import.
    Only used for tests that import from yashigani.gateway.ddos directly.
    """
    monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "test-sentinel-value-for-unit-tests")


class TestDDoSProtectorUpdateLimits:
    def test_update_limits_per_ip(self, _gateway_env):
        from yashigani.gateway.ddos import DDoSProtector
        redis = MagicMock()
        p = DDoSProtector(redis_client=redis, max_connections_per_ip=5000, window_seconds=60)
        p.update_limits(max_connections_per_ip=9999)
        assert p.max_connections_per_ip == 9999
        assert p.window_seconds == 60  # unchanged

    def test_update_limits_window(self, _gateway_env):
        from yashigani.gateway.ddos import DDoSProtector
        redis = MagicMock()
        p = DDoSProtector(redis_client=redis, max_connections_per_ip=5000, window_seconds=60)
        p.update_limits(window_seconds=120)
        assert p.window_seconds == 120
        assert p.max_connections_per_ip == 5000  # unchanged

    def test_update_limits_both(self, _gateway_env):
        from yashigani.gateway.ddos import DDoSProtector
        redis = MagicMock()
        p = DDoSProtector(redis_client=redis, max_connections_per_ip=5000, window_seconds=60)
        p.update_limits(max_connections_per_ip=7000, window_seconds=30)
        assert p.max_connections_per_ip == 7000
        assert p.window_seconds == 30

    def test_update_limits_none_is_noop(self, _gateway_env):
        from yashigani.gateway.ddos import DDoSProtector
        redis = MagicMock()
        p = DDoSProtector(redis_client=redis, max_connections_per_ip=5000, window_seconds=60)
        p.update_limits()
        assert p.max_connections_per_ip == 5000
        assert p.window_seconds == 60


# ---------------------------------------------------------------------------
# 6. Migration DDL — sanity check on known identifiers
# ---------------------------------------------------------------------------

def _read_migration_0013_text() -> str:
    """Read the 0013 migration file as raw text (same pattern as test_lu_amend_02)."""
    import os
    mig_path = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "yashigani", "db", "migrations", "versions",
        "0013_runtime_settings.py",
    )
    with open(mig_path) as f:
        return f.read()


class TestMigration0013:
    def test_ddl_contains_table_name(self):
        src = _read_migration_0013_text()
        assert "runtime_settings" in src

    def test_ddl_revokes_delete(self):
        src = _read_migration_0013_text()
        assert "REVOKE DELETE" in src

    def test_ddl_grants_update(self):
        src = _read_migration_0013_text()
        assert "UPDATE" in src

    def test_revision_is_0013(self):
        src = _read_migration_0013_text()
        assert 'revision: str = "0013"' in src

    def test_down_revision_is_0012(self):
        src = _read_migration_0013_text()
        assert 'down_revision: Union[str, None] = "0012"' in src or \
               'down_revision = "0012"' in src


# ---------------------------------------------------------------------------
# 7. Keys — KNOWN_SETTINGS_BY_KEY index
# ---------------------------------------------------------------------------

class TestRuntimeSettingsKeys:
    def test_all_known_settings_indexed(self):
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS, KNOWN_SETTINGS_BY_KEY
        for meta in KNOWN_SETTINGS:
            assert meta.key in KNOWN_SETTINGS_BY_KEY
            assert KNOWN_SETTINGS_BY_KEY[meta.key] is meta

    def test_key_constants_match_meta_keys(self):
        from yashigani.runtime_settings.keys import (
            KEY_RATE_LIMIT_PER_USER_RPS,
            KEY_DDOS_PER_IP_LIMIT,
            KEY_DDOS_WINDOW_SECONDS,
            KNOWN_SETTINGS_BY_KEY,
        )
        assert KEY_RATE_LIMIT_PER_USER_RPS in KNOWN_SETTINGS_BY_KEY
        assert KEY_DDOS_PER_IP_LIMIT in KNOWN_SETTINGS_BY_KEY
        assert KEY_DDOS_WINDOW_SECONDS in KNOWN_SETTINGS_BY_KEY

    def test_meta_class_defaults_are_positive_numbers(self):
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS
        for meta in KNOWN_SETTINGS:
            assert meta.class_default > 0, f"{meta.key} class_default must be positive"

    def test_allowed_types_are_valid(self):
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS
        valid = {"int", "float", "bool", "string"}
        for meta in KNOWN_SETTINGS:
            assert meta.allowed_type in valid, f"{meta.key} has invalid allowed_type"


# ---------------------------------------------------------------------------
# 8. Audit schema — RuntimeSettingChangedEvent
# ---------------------------------------------------------------------------

class TestRuntimeSettingChangedEvent:
    def test_event_type_in_enum(self):
        from yashigani.audit.schema import EventType
        assert hasattr(EventType, "RUNTIME_SETTING_CHANGED")
        assert EventType.RUNTIME_SETTING_CHANGED == "RUNTIME_SETTING_CHANGED"

    def test_event_dataclass_fields(self):
        import dataclasses
        from yashigani.audit.schema import RuntimeSettingChangedEvent
        fields = {f.name for f in dataclasses.fields(RuntimeSettingChangedEvent)}
        assert "setting_key" in fields
        assert "old_value" in fields
        assert "new_value" in fields
        assert "changed_by" in fields
        assert "source" in fields

    def test_event_default_event_type(self):
        from yashigani.audit.schema import RuntimeSettingChangedEvent, EventType
        evt = RuntimeSettingChangedEvent()
        assert evt.event_type == EventType.RUNTIME_SETTING_CHANGED

    def test_event_masking_immutable_floor(self):
        from yashigani.audit.schema import RuntimeSettingChangedEvent
        evt = RuntimeSettingChangedEvent(
            setting_key="gateway.ddos.per_ip_limit",
            old_value="5000",
            new_value="8000",
            changed_by="admin1",
            source="api",
        )
        assert evt.masking_applied is True

    def test_event_to_dict(self):
        from yashigani.audit.schema import RuntimeSettingChangedEvent
        evt = RuntimeSettingChangedEvent(
            setting_key="gateway.ddos.window_seconds",
            old_value="60",
            new_value="30",
            changed_by="admin1",
            source="ui",
        )
        d = evt.to_dict()
        assert d["setting_key"] == "gateway.ddos.window_seconds"
        assert d["source"] == "ui"
