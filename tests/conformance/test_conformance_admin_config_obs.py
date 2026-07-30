"""
Conformance group: ADMIN-CONFIG-OBS (ADMIN / CONFIG / OBSERVABILITY surface).

Per-endpoint API conformance for Yashigani 4.1.2 @ 250b486d, backoffice route
modules: admin_workflows.py, services.py, infrastructure.py,
runtime_settings.py, budget.py, models.py, audit.py, audit_search.py,
audit_sinks.py, alerts.py, events.py, cache.py, ratelimit.py, backup.py,
manifest_history.py, crypto_inventory.py, version_check.py, hibp.py,
csp_report.py. 90 declared (method, path) routes total (see _ENDPOINTS below
— includes csp_report.py's two-mount duplicate, see TestCspReportDualMount).

PROVENANCE: this file is PORTED from the prior 12-group fan-out conformance
program (Lu audit YCS-20260723-v4.1.2-CONFORMANCE, C5 gate G1), specifically
the ADMIN-OPS-MISC, AUDIT-SIEM, BUDGET-MODELS-INSPECTION, and
SECRETS-PKI-VAULT groups (branch feat/v412-conformance-suite,
`tests/conformance/`, dated 2026-07-23) — restricted to the 19 files this
dispatch owns (dropping dashboard.py, cloud_override.py, mcp_servers.py,
inspection.py, inspection_backend.py, kms.py, kms_vault.py, secrets.py,
pki_v1.py, cloud_keys.py — those belong to other groups), re-verified
byte-for-byte against 250b486d (see conftest.py docstring), and EXTENDED with:
  - audit_sinks.py (4 endpoints) — had NO conformance coverage in the prior
    program (test_audit_siem.py explicitly excluded it as "not our group";
    no OTHER group file claims it either — verified by grepping all 12 group
    files' _GROUP_PREFIXES for "/admin/audit/sinks" and "/admin/audit/siem/
    config", 2026-07-29: zero matches. Confirmed gap, now closed here).
  - cache.py (4 endpoints) — same: no prior coverage anywhere in the 12-group
    program (grepped for "/admin/cache" across all 12 group files: zero
    matches). Confirmed gap, now closed here.
  - Six NEW deviation findings not present in the ported material (see
    module-level FINDINGS section below and the individual test docstrings):
      F0 (HIGH)   audit_sinks.py: POST /admin/audit/siem/config/test is
                  UNREACHABLE. It collides with audit.py's earlier-registered
                  dynamic route POST /admin/audit/siem/{name}/test (Starlette
                  matches routes in registration order, no
                  literal-beats-dynamic precedence) — every call is silently
                  redirected to a completely different, unrelated named-SIEM-
                  target-test handler. Verified directly against the live
                  Starlette route table. See
                  TestAuditSiemConfigTestRouteCollisionFinding.
      F1 (HIGH)   cache.py: GET /admin/cache (list) reads a Postgres table
                  NEVER written by any code path; PUT/GET-one/DELETE
                  /admin/cache/{tenant_id} read/write REDIS via a completely
                  separate backend. A tenant's cache config set via PUT can
                  NEVER appear in the list view.
      F2 (MEDIUM) audit_sinks.py: DELETE /admin/audit/sinks/queue is
                  documented in the module docstring but never implemented —
                  404 on every call.
      F3 (MEDIUM) ratelimit.py POST /admin/ratelimit/reset/{bucket_key}: the
                  Redis bucket IS deleted (the documented side effect
                  happens) but the handler then crashes on an unguarded
                  `assert audit_writer is not None` — the admin receives
                  HTTP 500 for an operation that actually succeeded.
      F4 (LOW)    infrastructure.py PUT /admin/infrastructure/topology: the
                  audit-write assertion failure is SWALLOWED by a bare
                  `except Exception` — the mutation succeeds (200) but the
                  audit trail is silently skipped with no signal to the
                  caller, unlike every sibling file's `if writer is not
                  None:` guard pattern.
      F5 (LOW)    audit.py has NO graceful degrade at all when audit_writer
                  is unset (`assert writer is not None`, unguarded, in
                  `_audit_writer()` — used by all 13 of its endpoints) —
                  every one of them 500s, in contrast to audit_search.py's
                  sibling `_get_log_path()` which returns a clean 503.
  - A genuine (not mocked) proof that PUT /admin/runtime-settings/{key}
    publishes on the documented `yashigani:settings:changed` Redis pub/sub
    channel — the "applied immediately" claim's actual wire mechanism (see
    TestRuntimeSettingsLiveWiring). This directly answers the dispatch
    brief's "if it claims applied immediately, PROVE the real path honours
    it" instruction for the one setting-toggle surface in this group's scope.

Convention: see tests/conformance/conftest.py module docstring.

Last updated: 2026-07-29T00:00:00+00:00
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from typing import Self

import fakeredis
import httpx
import pytest

pytestmark = pytest.mark.conformance

_ADMIN_SESSION_COOKIE = "__Host-yashigani_admin_session"

# ---------------------------------------------------------------------------
# Explicit endpoint allowlist — every @router.<method> across the 19 files
# this dispatch owns, cross-checked against the live route walk in
# test_group_covers_all_declared_routes below. An EXPLICIT (method, path)
# list is used instead of a coarse prefix filter because several prefixes in
# this group ("/admin/audit", "/admin") are ALSO used by sibling groups'
# files (audit.py/audit_search.py/audit_sinks.py all share "/admin/audit";
# crypto_inventory.py shares the bare "/admin" prefix with dozens of other
# routers) — a prefix filter would silently over- or under-count.
# ---------------------------------------------------------------------------

_ENDPOINTS: list[tuple[str, str]] = [
    # admin_workflows.py (4)
    ("GET", "/admin/workflows"),
    ("GET", "/admin/workflows/{wf_id}"),
    ("GET", "/admin/workflows/{wf_id}/runs"),
    ("PATCH", "/admin/workflows/{wf_id}"),
    # services.py (2)
    ("GET", "/admin/services"),
    ("POST", "/admin/services/{service_id}"),
    # infrastructure.py (4)
    ("GET", "/admin/infrastructure/topology"),
    ("PUT", "/admin/infrastructure/topology"),
    ("GET", "/admin/infrastructure/autoscaling"),
    ("PUT", "/admin/infrastructure/autoscaling/{workload}"),
    # runtime_settings.py (4)
    ("GET", "/admin/runtime-settings"),
    ("GET", "/admin/runtime-settings/{key:path}"),
    ("PUT", "/admin/runtime-settings/{key:path}"),
    ("POST", "/admin/runtime-settings/{key:path}/reset"),
    # budget.py (12)
    ("GET", "/admin/budget/org-caps"),
    ("POST", "/admin/budget/org-caps"),
    ("DELETE", "/admin/budget/org-caps"),
    ("GET", "/admin/budget/groups"),
    ("POST", "/admin/budget/groups"),
    ("DELETE", "/admin/budget/groups"),
    ("GET", "/admin/budget/individuals"),
    ("POST", "/admin/budget/individuals"),
    ("DELETE", "/admin/budget/individuals"),
    ("GET", "/admin/budget/usage/{identity_id}"),
    ("GET", "/admin/budget/tree"),
    ("GET", "/admin/budget/models/local-inventory"),
    # models.py (9)
    ("GET", "/admin/models"),
    ("POST", "/admin/models"),
    ("DELETE", "/admin/models/{alias}"),
    ("GET", "/admin/models/available"),
    ("POST", "/admin/models/pull"),
    ("GET", "/admin/models/allocation-targets"),
    ("GET", "/admin/models/allocations"),
    ("POST", "/admin/models/allocations"),
    ("DELETE", "/admin/models/allocations/{alloc_id}"),
    # audit.py (13)
    ("GET", "/admin/audit/export/raw"),
    ("GET", "/admin/audit/masking/scope"),
    ("PUT", "/admin/audit/masking/scope"),
    ("POST", "/admin/audit/masking/scope/agent"),
    ("DELETE", "/admin/audit/masking/scope/agent/{agent_id}"),
    ("POST", "/admin/audit/masking/scope/user"),
    ("DELETE", "/admin/audit/masking/scope/user/{handle}"),
    ("POST", "/admin/audit/masking/scope/component"),
    ("DELETE", "/admin/audit/masking/scope/component/{component}"),
    ("GET", "/admin/audit/siem"),
    ("POST", "/admin/audit/siem"),
    ("DELETE", "/admin/audit/siem/{name}"),
    ("POST", "/admin/audit/siem/{name}/test"),
    # audit_search.py (3)
    ("GET", "/admin/audit/facets"),
    ("GET", "/admin/audit/search"),
    ("GET", "/admin/audit/export"),
    # audit_sinks.py (4) — NEW coverage, see module docstring F2.
    ("GET", "/admin/audit/sinks"),
    ("GET", "/admin/audit/siem/config"),
    ("PUT", "/admin/audit/siem/config"),
    ("POST", "/admin/audit/siem/config/test"),
    # alerts.py (10)
    ("GET", "/admin/alerts/config"),
    ("PUT", "/admin/alerts/config"),
    ("POST", "/admin/alerts/test/{sink_type}"),
    ("GET", "/admin/alerts/budget-threshold"),
    ("PUT", "/admin/alerts/budget-threshold"),
    ("GET", "/admin/alerts/custom"),
    ("POST", "/admin/alerts/custom"),
    ("GET", "/admin/alerts/custom/{alert_id}"),
    ("PUT", "/admin/alerts/custom/{alert_id}"),
    ("DELETE", "/admin/alerts/custom/{alert_id}"),
    # events.py (1)
    ("GET", "/admin/events/inspection-feed"),
    # cache.py (4) — NEW coverage, see module docstring F1.
    ("GET", "/admin/cache"),
    ("GET", "/admin/cache/{tenant_id}"),
    ("PUT", "/admin/cache/{tenant_id}"),
    ("DELETE", "/admin/cache/{tenant_id}"),
    # ratelimit.py (7)
    ("GET", "/admin/ratelimit/config"),
    ("PUT", "/admin/ratelimit/config"),
    ("GET", "/admin/ratelimit/status"),
    ("POST", "/admin/ratelimit/reset/{bucket_key}"),
    ("GET", "/admin/ratelimit/endpoints"),
    ("POST", "/admin/ratelimit/endpoints"),
    ("DELETE", "/admin/ratelimit/endpoints/{endpoint_hash}"),
    # backup.py (3)
    ("GET", "/admin/backup/status"),
    ("POST", "/admin/backup/verify"),
    ("POST", "/admin/backup/create"),
    # manifest_history.py (3)
    ("GET", "/admin/manifest-registrations"),
    ("GET", "/admin/manifest-registrations/{record_id}"),
    ("POST", "/admin/manifest-registrations/ceremony"),
    # crypto_inventory.py (1)
    ("GET", "/admin/crypto/inventory"),
    # version_check.py (1)
    ("GET", "/admin/version"),
    # hibp.py (3)
    ("GET", "/api/v1/admin/auth/hibp/status"),
    ("PUT", "/api/v1/admin/auth/hibp/key"),
    ("DELETE", "/api/v1/admin/auth/hibp/key"),
    # csp_report.py (2 — same router object mounted TWICE, see
    # TestCspReportDualMount)
    ("POST", "/admin/csp-report"),
    ("POST", "/api/v1/csp-report"),
]


def test_group_covers_all_declared_routes(declared_routes):
    """Route-completeness gate for this group: the app's live route walk,
    restricted to the paths in _ENDPOINTS, must equal _ENDPOINTS exactly —
    catching both (a) a route this file forgot to assert against, and
    (b) a stale entry in _ENDPOINTS for a route that no longer exists."""
    expected = set(_ENDPOINTS)
    assert len(expected) == len(_ENDPOINTS), "duplicate entries in _ENDPOINTS"
    live_paths = {p for (_m, p, _r) in declared_routes}
    declared_matching = {(m, p) for (m, p, _r) in declared_routes if p in {e[1] for e in _ENDPOINTS}}
    missing = expected - declared_matching
    extra = declared_matching - expected
    assert not missing, f"_ENDPOINTS claims routes that do NOT exist in the live app: {sorted(missing)}"
    assert not extra, (
        f"Live app declares routes at these paths that _ENDPOINTS does not "
        f"account for (method mismatch or new route): {sorted(extra)}"
    )
    assert len(expected) == 90, f"expected 90 total endpoints, _ENDPOINTS has {len(expected)}"


# ---------------------------------------------------------------------------
# Group-specific fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def budget_state(fake_redis_client, mock_audit_writer):
    """Wires the REAL BudgetConfigStore (Redis db/3-shaped, accepts
    redis_client directly per src/yashigani/billing/budget_config_store.py)
    against fakeredis, plus a MagicMock budget_enforcer (BudgetEnforcer is
    also redis_client-constructed but its `get_usage_summary` needs live
    gateway-written counters we don't have offline — MagicMock with a
    realistic return shape is the documented fallback)."""
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.billing.budget_config_store import BudgetConfigStore

    store = BudgetConfigStore(redis_client=fake_redis_client)
    enforcer = MagicMock()
    enforcer.get_usage_summary.return_value = {"anthropic": {"used": 0, "cap": 0}}
    enforcer.set_allocation = MagicMock()
    budget_routes.configure(budget_enforcer=enforcer, budget_store=store)
    yield store, enforcer
    budget_routes.configure(budget_enforcer=None, budget_store=None)  # tear down module-level singleton


@pytest.fixture
def ratelimit_state(fake_redis_client, monkeypatch):
    """Wires the REAL RateLimiter against fakeredis (constructor takes
    redis_client directly — src/yashigani/ratelimit/limiter.py:107)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.ratelimit.limiter import RateLimiter

    limiter = RateLimiter(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "rate_limiter", limiter, raising=False)
    monkeypatch.setattr(backoffice_state, "ratelimit_config_last_changed", None, raising=False)
    return limiter


@pytest.fixture
def endpoint_ratelimit_state(fake_redis_client, monkeypatch):
    """Wires the REAL EndpointRateLimiter against fakeredis (constructor
    takes redis_client directly — src/yashigani/gateway/endpoint_ratelimit.py:72).
    `backoffice_state.endpoint_rate_limiter` is a dynamically-added attribute
    (not declared in the BackofficeState dataclass — read via `getattr(...,
    None)` at every call site in ratelimit.py), so `raising=False` is
    required here."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.gateway.endpoint_ratelimit import EndpointRateLimiter

    ep_rl = EndpointRateLimiter(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "endpoint_rate_limiter", ep_rl, raising=False)
    return ep_rl


@pytest.fixture
def models_state(fake_redis_client, monkeypatch):
    """Wires REAL ModelAliasStore + ModelAllocationStore against fakeredis
    (both accept redis_client directly — src/yashigani/models/{alias_store,
    allocation_store}.py)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.models.alias_store import ModelAliasStore
    from yashigani.models.allocation_store import ModelAllocationStore

    alias_store = ModelAliasStore(redis_client=fake_redis_client)
    alloc_store = ModelAllocationStore(redis_client=fake_redis_client, durable_store=None)
    monkeypatch.setattr(backoffice_state, "model_alias_store", alias_store, raising=False)
    monkeypatch.setattr(backoffice_state, "model_allocation_store", alloc_store, raising=False)
    return alias_store, alloc_store


class FakeRuntimeSettingsService:
    """MOCKED: RuntimeSettingsService (src/yashigani/runtime_settings/service.py)
    is asyncpg-pool-backed with no fakeredis-injectable constructor path (its
    __init__ takes `pool` — an asyncpg pool — not a redis_client). This fake
    implements exactly the 4 methods runtime_settings.py's routes call:
    list_all(), get_one(), set(), reset_to_default() — in-memory, seeded from
    the REAL KNOWN_SETTINGS class defaults so key/type/default assertions are
    genuine, only the persistence layer is faked. The route-level pub/sub
    "applied immediately" claim is proven separately against the REAL
    service class in TestRuntimeSettingsLiveWiring below."""

    def __init__(self) -> None:
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS

        self._store: dict[str, dict] = {}
        for meta in KNOWN_SETTINGS:
            self._store[meta.key] = {
                "key": meta.key,
                "value": meta.class_default,
                "default_value": meta.class_default,
                "source": "default",
                "last_changed_by": None,
                "last_changed_at": None,
                "description": meta.description,
                "allowed_type": meta.allowed_type,
            }

    async def list_all(self) -> list[dict]:
        return list(self._store.values())

    async def get_one(self, key: str):
        return self._store.get(key)

    async def set(self, key: str, value, changed_by: str, source: str = "api") -> dict:
        rec = dict(self._store[key])
        rec["value"] = value
        rec["source"] = source
        rec["last_changed_by"] = changed_by
        rec["last_changed_at"] = datetime.now(tz=UTC).isoformat()
        self._store[key] = rec
        return rec

    async def reset_to_default(self, key: str, changed_by: str, source: str = "api") -> dict:
        rec = self._store[key]
        return await self.set(key, rec["default_value"], changed_by=changed_by, source=source)


@pytest.fixture
def runtime_settings_state(monkeypatch):
    from yashigani.backoffice.state import backoffice_state

    svc = FakeRuntimeSettingsService()
    monkeypatch.setattr(backoffice_state, "runtime_settings", svc, raising=False)
    return svc


@pytest.fixture
def alert_config_reset(monkeypatch):
    """Baseline-reset the 3 direct backoffice_state attributes alerts.py
    mutates via bare setattr() (NOT a store object) — alert_config,
    custom_alert_rules, budget_threshold_alert_config."""
    from yashigani.backoffice.state import backoffice_state

    monkeypatch.setattr(backoffice_state, "alert_config", None, raising=False)
    monkeypatch.setattr(backoffice_state, "custom_alert_rules", {}, raising=False)
    monkeypatch.setattr(backoffice_state, "budget_threshold_alert_config", None, raising=False)


@pytest.fixture
def deny_all_dns(monkeypatch):
    """Force socket.getaddrinfo() to fail deterministically and offline-safe
    — exercises assert_webhook_url()'s (yashigani/alerts/_url_guard.py) real
    DNS-resolution-failure rejection path without any real network call or
    dependency on this sandbox having DNS/internet access."""
    import socket as _socket

    def _raise(*_a, **_kw):
        raise _socket.gaierror("no DNS in offline conformance suite")

    monkeypatch.setattr("yashigani.alerts._url_guard.socket.getaddrinfo", _raise)


def _seed_workflow(r_meta, wf_id: str, owner_identity_id: str, name: str = "test-wf",
                    enabled: bool = True) -> None:
    """Write a wf:meta hash + wf:workflows:{owner} index entry directly using
    the REAL key formats from yashigani.backoffice.routes.user_workflows
    (_wf_key / _wf_index_key), so admin_workflows.py's SCAN-based cross-user
    listing walks genuine data, not a stub."""
    r_meta.hset(
        f"wf:meta:{wf_id}",
        mapping={
            "name": name,
            "description": "",
            "owner_identity_id": owner_identity_id,
            "account_id": owner_identity_id,
            "enabled": "1" if enabled else "0",
            "created_at": "2026-07-01T00:00:00+00:00",
            "updated_at": "2026-07-01T00:00:00+00:00",
            "spec": json.dumps({"steps": [], "schedule": {"kind": "none"}}),
        },
    )
    r_meta.sadd(f"wf:workflows:{owner_identity_id}", wf_id)


@pytest.fixture
def admin_workflows_state(monkeypatch):
    """Wires two independent bytes-mode fakeredis clients standing in for
    Redis DB3 (backoffice wf:meta / wf:workflows index, reached via
    backoffice_state.identity_registry._r per user_agents.py:_get_redis) and
    DB6 (gateway workflow-scheduler namespace, reached via
    admin_workflows.py's own `_get_wf_redis` module reference — imported from
    user_workflows.py at admin_workflows.py's import time, so it must be
    monkeypatched on the admin_workflows module object, not user_workflows).
    Both DBs are exercised through the REAL WorkflowSpec/WorkflowRun
    (de)serialisation helpers in yashigani.gateway.workflow_scheduler."""
    from yashigani.backoffice.routes import admin_workflows as aw_routes
    from yashigani.backoffice.state import backoffice_state

    wf_meta_redis = fakeredis.FakeRedis(decode_responses=False)  # DB3 analogue
    wf_sched_redis = fakeredis.FakeRedis(decode_responses=False)  # DB6 analogue

    class _FakeIdentityRegistry:
        _r = wf_meta_redis

    monkeypatch.setattr(
        backoffice_state, "identity_registry", _FakeIdentityRegistry(), raising=False
    )
    monkeypatch.setattr(aw_routes, "_get_wf_redis", lambda: wf_sched_redis, raising=False)
    yield wf_meta_redis, wf_sched_redis
    wf_meta_redis.flushall()
    wf_sched_redis.flushall()


@pytest.fixture
def real_audit_writer(tmp_path, monkeypatch):
    """Wires a REAL AuditLogWriter (yashigani.audit.writer.AuditLogWriter)
    pointed at a pytest tmp_path log file into backoffice_state.audit_writer.

    File-backed, not Redis-backed — fully constructible offline with no
    fakeredis equivalent needed."""
    from yashigani.audit.config import AuditConfig
    from yashigani.audit.writer import AuditLogWriter
    from yashigani.backoffice.state import backoffice_state

    config = AuditConfig(
        log_path=str(tmp_path / "audit.log"),
        max_file_size_mb=100,
        retention_days=90,
    )
    writer = AuditLogWriter(config)
    monkeypatch.setattr(backoffice_state, "audit_writer", writer, raising=False)
    yield writer
    writer.close()


class _FakeHTTPResponse:
    """Context-manager stand-in for urllib.request.urlopen()'s return value."""

    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


@pytest.fixture
def hibp_store_state(monkeypatch):
    """MOCKED: AuthSettingsStore requires live Postgres+pgcrypto — not
    available offline. _FakeAuthSettingsStore implements only
    get_setting/get_metadata/set_setting, the exact surface hibp.py calls
    (verified by reading that file)."""
    from yashigani.backoffice.state import backoffice_state

    class _FakeAuthSettingsStore:
        def __init__(self) -> None:
            self._settings: dict[str, str] = {}
            self._meta: dict[str, dict] = {}

        async def get_setting(self, key: str) -> str:
            return self._settings.get(key, "")

        async def get_metadata(self, key: str):
            return self._meta.get(key)

        async def set_setting(self, key: str, value: str, updated_by: str) -> None:
            self._settings[key] = value
            self._meta[key] = {
                "updated_at": "2026-07-29T00:00:00+00:00",
                "updated_by": updated_by,
            }

    store = _FakeAuthSettingsStore()
    monkeypatch.setattr(backoffice_state, "auth_settings_store", store, raising=False)
    return store


@pytest.fixture
def backup_dir_state(tmp_path, monkeypatch):
    """backup.py's `_BACKUPS_DIR` is a module-level Path bound ONCE at import
    time from an env var (not re-read per-request) — env var monkeypatching
    alone would not take effect. Patching the module attribute directly works
    because the route functions look up `_BACKUPS_DIR` as a module global at
    call time."""
    import yashigani.backoffice.routes.backup as backup_mod

    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", backups_dir, raising=False)
    return backups_dir


def _write_backup_dir(base: Path, name: str, *, sign: bool = True, tamper: bool = False) -> Path:
    import hashlib

    d = base / name
    d.mkdir()
    (d / "bundle.enc").write_bytes(b"conformance-fake-encrypted-bundle-bytes")
    (d / "backup-meta.json").write_text('{"version":"ondemand-v1"}')
    if sign:
        checksums = {}
        for fname in ("bundle.enc", "backup-meta.json"):
            checksums[fname] = hashlib.sha256((d / fname).read_bytes()).hexdigest()
        if tamper:
            checksums["bundle.enc"] = "0" * 64
        manifest_text = "".join(f"{h}  {fname}\n" for fname, h in checksums.items())
        (d / "MANIFEST.sha256").write_text(manifest_text)
        (d / "MANIFEST.sha256.sig").write_bytes(b"conformance-fake-hmac-signature-hex")
    return d


class _FakeAcquireCtx:
    def __init__(self, conn) -> None:
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *_exc):
        return False


class FakeManifestPool:
    """MOCKED: ManifestRegistryService requires a live asyncpg pool — no
    fakeredis equivalent exists (Postgres-only). Implements only the query
    shapes manifest_history.py / manifest_registry/service.py actually issue
    (verified by reading both files)."""

    def __init__(self) -> None:
        self._rows: list[dict] = []
        self._next_id = 1

    def acquire(self):
        return _FakeAcquireCtx(self)

    async def fetchrow(self, query: str, *args):
        q = " ".join(query.split())
        if q.startswith("SELECT manifest_sha256"):
            agent_id = args[0]
            matches = [r for r in self._rows if r["agent_id"] == agent_id]
            if not matches:
                return None
            latest = max(matches, key=lambda r: r["id"])
            return {"manifest_sha256": latest["manifest_sha256"]}
        if q.startswith("INSERT INTO manifest_registrations"):
            tenant_id, agent_id, sha, blob, operator, prev_sha, prov_json = args
            row = {
                "id": self._next_id,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "manifest_sha256": sha,
                "manifest_yaml_blob": blob,
                "registered_by_operator_identity": operator,
                "registered_at": datetime.now(tz=UTC),
                "previous_manifest_sha256": prev_sha,
                "signature_provenance": json.loads(prov_json) if prov_json else None,
            }
            self._rows.append(row)
            self._next_id += 1
            return {"id": row["id"]}
        if q.startswith("SELECT id, tenant_id, agent_id, manifest_sha256,") and "WHERE id = $1" in q:
            record_id = args[0]
            for r in self._rows:
                if r["id"] == record_id:
                    return dict(r)
            return None
        if q.startswith("SELECT COUNT(*)"):
            tenant_id = args[0]
            n = len([r for r in self._rows if r["tenant_id"] == tenant_id])
            return {"n": n}
        raise AssertionError(f"FakeManifestPool.fetchrow: unrecognised query: {query!r}")

    async def fetch(self, query: str, *args):
        q = " ".join(query.split())
        if q.startswith("SELECT id, tenant_id, agent_id, manifest_sha256,") and "WHERE tenant_id = $1" in q:
            tenant_id, limit, offset = args
            matches = sorted(
                [r for r in self._rows if r["tenant_id"] == tenant_id],
                key=lambda r: r["id"],
                reverse=True,
            )
            return [dict(r) for r in matches[offset: offset + limit]]
        raise AssertionError(f"FakeManifestPool.fetch: unrecognised query: {query!r}")


@pytest.fixture
def manifest_pool_state(monkeypatch):
    import yashigani.db as db_module

    pool = FakeManifestPool()
    monkeypatch.setattr(db_module, "get_pool", lambda: pool, raising=False)
    return pool


_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _ceremony_body(**overrides) -> dict:
    import hashlib

    manifest_yaml = overrides.pop("manifest_yaml", "name: conformance-agent\nupstream: http://x\n")
    body = {
        "tenant_id": _PLATFORM_TENANT_ID,
        "agent_id": "conformance-agent",
        "manifest_yaml": manifest_yaml,
        "operator_identity": "conformance-admin1",
        "manifest_sha256": hashlib.sha256(manifest_yaml.encode("utf-8")).hexdigest(),
        "confirmed_at": "2026-07-29T00:00:00+00:00",
        "ack_text_shown": "I confirm this manifest is correct.",
        "ack_response": "Y",
        "signature_provenance": {"alg": "ed25519", "signer": "spiffe://yashigani/cli", "sig": "deadbeef" * 8},
    }
    body.update(overrides)
    return body


@pytest.fixture
def cache_state(monkeypatch):
    """Wires the REAL ResponseCache (accepts redis_client directly —
    src/yashigani/gateway/response_cache.py:24) against a DEDICATED
    decode_responses=False fakeredis client — NOT the shared
    `fake_redis_client` fixture (decode_responses=True, matched to
    SessionStore's own construction). ResponseCache.get_tenant_config()
    compares Redis hash fields against literal bytes (`data.get(b"enabled",
    b"false")`, response_cache.py:63) — with a decode_responses=True client
    hgetall() returns str keys, so `data.get(b"enabled", ...)` never matches
    and the method silently always returns the default shape regardless of
    what was actually stored. Verified empirically (2026-07-29): this
    exact mismatch was caught by this suite's own first draft. See F1 in
    the module docstring: GET /admin/cache (list) does NOT read from this
    store at all — it reads a separate, never-written Postgres table. This
    fixture wires the Redis side only, which is what GET-one/PUT/DELETE
    actually use."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.gateway.response_cache import ResponseCache

    redis_client = fakeredis.FakeRedis(decode_responses=False)
    rc = ResponseCache(redis_client=redis_client)
    monkeypatch.setattr(backoffice_state, "response_cache", rc, raising=False)
    yield rc
    redis_client.flushall()


@pytest.fixture
def siem_config_reset(monkeypatch):
    """audit_sinks.py reads/writes backoffice_state.siem_backend /
    siem_endpoint / siem_wazuh_auto_deploy directly (bare setattr, not a
    store object) — reset to the dataclass defaults before each test."""
    from yashigani.backoffice.state import backoffice_state

    monkeypatch.setattr(backoffice_state, "siem_backend", "none", raising=False)
    monkeypatch.setattr(backoffice_state, "siem_endpoint", None, raising=False)
    monkeypatch.setattr(backoffice_state, "siem_wazuh_auto_deploy", False, raising=False)


# ---------------------------------------------------------------------------
# admin_workflows.py — 4 endpoints. HIGH PRIORITY: cross-user oversight vs
# non-admin blocked-out.
# ---------------------------------------------------------------------------


class TestAdminWorkflowsList:
    # GAP-CLOSED: GET /admin/workflows
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/workflows").status_code == 401

    def test_NON_ADMIN_BLOCKED(self, user_client):
        """OVERSIGHT-SCOPING ASSERTION: a non-admin (user-tier) session must
        be flatly rejected from the entire admin oversight surface — 403
        insufficient_tier, not a BOLA-filtered empty list. Confirmed:
        require_admin_session (AdminSession) is the ONLY dependency on every
        route in this file; there is no code path by which a user-tier
        session reaches _scan_all_wf_ids()."""
        r = user_client.get("/admin/workflows")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_invalid_page_422(self, admin_client, admin_workflows_state):
        r = admin_client.get("/admin/workflows", params={"page": 0})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_page"

    def test_invalid_page_size_422(self, admin_client, admin_workflows_state):
        r = admin_client.get("/admin/workflows", params={"page_size": 500})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_page_size"

    def test_ADMIN_SEES_ACROSS_ALL_USERS(self, admin_client, admin_workflows_state):
        """CROSS-USER OVERSIGHT ASSERTION: admin lists workflows belonging to
        TWO DIFFERENT, unrelated owners in a single call — this IS the
        intended oversight function (admin_workflows.py:5-6: "The
        /user/workflows* routes are BOLA-scoped per owner; these routes
        intentionally bypass that scope for admin oversight."). Confirmed
        with genuine Redis SCAN over real wf:workflows:{owner} index keys."""
        wf_meta_redis, _ = admin_workflows_state
        _seed_workflow(wf_meta_redis, "wfl_owner_a1", "alice@acme.com")
        _seed_workflow(wf_meta_redis, "wfl_owner_b1", "bob@acme.com")

        r = admin_client.get("/admin/workflows")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        owners = {w["owner_identity_id"] for w in body["workflows"]}
        assert owners == {"alice@acme.com", "bob@acme.com"}


class TestAdminWorkflowsGetOne:
    # GAP-CLOSED: GET /admin/workflows/{wf_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/workflows/wfl_x").status_code == 401

    def test_non_admin_blocked(self, user_client):
        assert user_client.get("/admin/workflows/wfl_x").status_code == 403

    def test_unknown_wf_404(self, admin_client, admin_workflows_state):
        r = admin_client.get("/admin/workflows/wfl_does_not_exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_admin_reads_workflow_owned_by_a_different_user(
        self, admin_client, admin_workflows_state,
    ):
        """The key oversight assertion: admin reads a workflow owned by
        someone else, with the FULL spec included (include_spec=True) — no
        BOLA 404 substitution, unlike the user-plane routes."""
        wf_meta_redis, _ = admin_workflows_state
        _seed_workflow(wf_meta_redis, "wfl_carol1", "carol@acme.com", name="Carol's automation")

        r = admin_client.get("/admin/workflows/wfl_carol1")
        assert r.status_code == 200
        body = r.json()
        assert body["owner_identity_id"] == "carol@acme.com"
        assert body["name"] == "Carol's automation"
        assert "spec" in body


class TestAdminWorkflowsRuns:
    # GAP-CLOSED: GET /admin/workflows/{wf_id}/runs
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/workflows/wfl_x/runs").status_code == 401

    def test_non_admin_blocked(self, user_client):
        assert user_client.get("/admin/workflows/wfl_x/runs").status_code == 403

    def test_invalid_limit_422(self, admin_client, admin_workflows_state):
        r = admin_client.get("/admin/workflows/wfl_x/runs", params={"limit": 0})
        assert r.status_code == 422

    def test_unknown_wf_404(self, admin_client, admin_workflows_state):
        r = admin_client.get("/admin/workflows/wfl_does_not_exist/runs")
        assert r.status_code == 404

    def test_admin_reads_run_history_cross_user(self, admin_client, admin_workflows_state):
        from yashigani.gateway.workflow_scheduler import WorkflowRun, _redis_save_run

        wf_meta_redis, wf_sched_redis = admin_workflows_state
        _seed_workflow(wf_meta_redis, "wfl_dave1", "dave@acme.com")
        run = WorkflowRun(
            run_id="run_1", workflow_id="wfl_dave1", owner_identity_id="dave@acme.com",
            status="completed", started_at=1000.0, finished_at=1005.0, trigger_kind="manual",
        )
        _redis_save_run(wf_sched_redis, run)

        r = admin_client.get("/admin/workflows/wfl_dave1/runs")
        assert r.status_code == 200
        body = r.json()
        assert body["workflow_id"] == "wfl_dave1"
        assert len(body["runs"]) == 1
        assert body["runs"][0]["run_id"] == "run_1"
        assert body["runs"][0]["status"] == "completed"


class TestAdminWorkflowsPatch:
    # GAP-CLOSED: PATCH /admin/workflows/{wf_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.patch("/admin/workflows/wfl_x", json={"enabled": False}).status_code == 401

    def test_non_admin_blocked(self, user_client):
        r = user_client.patch("/admin/workflows/wfl_x", json={"enabled": False})
        assert r.status_code == 403

    def test_requires_stepup_not_just_admin(self, admin_client, admin_workflows_state):
        wf_meta_redis, _ = admin_workflows_state
        _seed_workflow(wf_meta_redis, "wfl_e1", "erin@acme.com")
        r = admin_client.patch("/admin/workflows/wfl_e1", json={"enabled": False})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_noop_body_no_redis_touch(self, stepup_admin_client):
        """enabled=None (absent) is documented as a pure no-op that returns
        early WITHOUT ever touching Redis (admin_workflows.py:246-248) — this
        is the one case that needs no admin_workflows_state wiring at all."""
        r = stepup_admin_client.patch("/admin/workflows/wfl_anything", json={})
        assert r.status_code == 200
        assert r.json() == {"workflow_id": "wfl_anything", "updated": []}

    def test_unknown_wf_404(self, stepup_admin_client, admin_workflows_state):
        r = stepup_admin_client.patch(
            "/admin/workflows/wfl_does_not_exist", json={"enabled": False}
        )
        assert r.status_code == 404

    def test_ADMIN_DISABLES_ANOTHER_USERS_WORKFLOW(
        self, stepup_admin_client, admin_workflows_state, mock_audit_writer,
    ):
        """Cross-user disable — the consequential oversight action (EU AI
        Act Art.14). Verifies BOTH DB3 metadata AND DB6 scheduler-index sync
        happen via the REAL WorkflowSpec helpers, plus the audit event."""
        from yashigani.gateway.workflow_scheduler import WorkflowSpec, _redis_get_spec, _redis_set_spec

        wf_meta_redis, wf_sched_redis = admin_workflows_state
        _seed_workflow(wf_meta_redis, "wfl_frank1", "frank@acme.com")
        _redis_set_spec(
            wf_sched_redis,
            WorkflowSpec(workflow_id="wfl_frank1", owner_identity_id="frank@acme.com", enabled=True),
        )

        r = stepup_admin_client.patch("/admin/workflows/wfl_frank1", json={"enabled": False})
        assert r.status_code == 200
        assert r.json()["updated"] == ["enabled"]

        # DB3 metadata updated
        meta = wf_meta_redis.hgetall(b"wf:meta:wfl_frank1")
        assert meta[b"enabled"] == b"0"

        # DB6 scheduler spec updated (real deserialise/reserialise round-trip)
        spec = _redis_get_spec(wf_sched_redis, "wfl_frank1")
        assert spec.enabled is False

        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# services.py — 2 endpoints
# ---------------------------------------------------------------------------


class TestServices:
    # GAP-CLOSED: GET /admin/services
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/services").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/services")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_lists_all_stopped_by_default(self, admin_client, monkeypatch):
        monkeypatch.delenv("YASHIGANI_ENABLED_PROFILES", raising=False)
        r = admin_client.get("/admin/services")
        assert r.status_code == 200
        body = r.json()
        ids = {s["id"] for s in body["services"]}
        assert ids == {"openwebui", "wazuh", "internal-ca", "langflow", "letta", "openclaw"}
        assert all(s["status"] == "stopped" for s in body["services"])

    def test_admin_reflects_enabled_profiles_env(self, admin_client, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENABLED_PROFILES", "openwebui,wazuh")
        r = admin_client.get("/admin/services")
        by_id = {s["id"]: s for s in r.json()["services"]}
        assert by_id["openwebui"]["status"] == "running"
        assert by_id["wazuh"]["status"] == "running"
        assert by_id["letta"]["status"] == "stopped"

    # GAP-CLOSED: POST /admin/services/{service_id}
    def test_manage_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/services/openwebui", json={"action": "enable"})
        assert r.status_code == 401

    def test_manage_requires_stepup_not_just_admin(self, admin_client):
        r = admin_client.post("/admin/services/openwebui", json={"action": "enable"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_manage_unknown_service_404(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/services/not-a-real-service", json={"action": "enable"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "unknown_service"

    def test_manage_invalid_action_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/services/openwebui", json={"action": "delete"})
        assert r.status_code == 422  # Pydantic pattern validation

    def test_manage_known_service_is_informational_only(self, stepup_admin_client):
        """SPEC-CONFORMANCE: this endpoint deliberately does NOT drive the
        container engine (backoffice has no docker/podman socket by design,
        services.py:108-116) — it returns deploy_time_managed guidance, never
        actually starts/stops anything. Pinning this contract so a future
        accidental "looks like it worked" regression is caught."""
        r = stepup_admin_client.post("/admin/services/langflow", json={"action": "enable"})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "deploy_time_managed"
        assert body["profile"] == "langflow"


# ---------------------------------------------------------------------------
# infrastructure.py — 4 endpoints, no backing store (in-memory state only)
# ---------------------------------------------------------------------------


class TestInfrastructure:
    # GAP-CLOSED: GET /admin/infrastructure/topology
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/infrastructure/topology").status_code == 401

    def test_get_topology_defaults(self, admin_client):
        r = admin_client.get("/admin/infrastructure/topology")
        assert r.status_code == 200
        body = r.json()
        assert body["az_count"] == 1
        assert "Single AZ detected" in body["warnings"][0]

    # GAP-CLOSED: PUT /admin/infrastructure/topology
    def test_put_topology_single_az_conflict_422(self, admin_client, mock_audit_writer):
        r = admin_client.put("/admin/infrastructure/topology", json={
            "zones": ["us-east-1a"], "spread_policy": "DoNotSchedule",
        })
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "single_az_conflict"

    def test_put_topology_success(self, admin_client, mock_audit_writer):
        r = admin_client.put("/admin/infrastructure/topology", json={
            "zones": ["us-east-1a", "us-east-1b"], "spread_policy": "DoNotSchedule",
        })
        assert r.status_code == 200
        assert r.json()["az_count"] == 2
        mock_audit_writer.write.assert_called_once()

    def test_put_topology_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/infrastructure/topology", json={"zones": ["a"]})
        assert r.status_code == 401

    # GAP-CLOSED: GET /admin/infrastructure/autoscaling
    def test_get_autoscaling(self, admin_client):
        r = admin_client.get("/admin/infrastructure/autoscaling")
        assert r.status_code == 200
        assert r.json()["keda_enabled"] is True

    # GAP-CLOSED: PUT /admin/infrastructure/autoscaling/{workload}
    def test_put_autoscaling_invalid_workload_404(self, admin_client):
        r = admin_client.put("/admin/infrastructure/autoscaling/not-a-workload", json={
            "min_replicas": 1, "max_replicas": 2,
        })
        assert r.status_code == 404

    def test_put_autoscaling_valid_workload(self, admin_client):
        r = admin_client.put("/admin/infrastructure/autoscaling/gateway", json={
            "min_replicas": 2, "max_replicas": 5,
        })
        assert r.status_code == 200

    def test_put_autoscaling_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/infrastructure/autoscaling/gateway", json={
            "min_replicas": 1, "max_replicas": 2,
        })
        assert r.status_code == 401


class TestInfrastructureAuditWriteSwallowedFinding:
    """YSG-RISK-154 (LOW) — CLOSED. PUT /admin/infrastructure/topology used
    to write the audit event inside `try: assert audit_writer is not None;
    writer.write(...) except Exception: logger.warning(...)` — when
    audit_writer was None (unwired), the AssertionError (AssertionError IS
    an Exception) was silently caught by the bare except and reduced to a
    generic "Audit write failed" log line; the state mutation still
    happened and the response was still 200 with zero signal to the
    caller. Fix: audit_writer being completely UNSET is now checked
    EXPLICITLY BEFORE the mutation and fails closed with 503 — a genuine
    startup-invariant violation, not a transient write hiccup. A
    transient write FAILURE (writer present, .write() itself raises) still
    surfaces as `audit_recorded: false` in a 200 (fail-soft on the
    mutation, per the codebase's existing convention) — see
    test_tom_ysg_risk_153_154_audit_integrity.py."""

    def test_put_topology_rejects_before_mutating_when_writer_unset(self, admin_client):
        from yashigani.backoffice.state import backoffice_state

        assert backoffice_state.audit_writer is None, "test precondition: audit_writer must be unwired"
        r = admin_client.put("/admin/infrastructure/topology", json={
            "zones": ["us-east-1a", "us-east-1b"], "spread_policy": "DoNotSchedule",
        })
        assert r.status_code == 503, (
            f"YSG-RISK-154 REGRESSION: expected a fail-closed 503 when "
            f"audit_writer is unset, got {r.status_code}: {r.text}"
        )
        assert r.json()["detail"]["error"] == "audit_writer_unavailable"


# ---------------------------------------------------------------------------
# runtime_settings.py — 4 endpoints
# ---------------------------------------------------------------------------


class TestRuntimeSettings:
    _KEY = "gateway.ddos.per_ip_limit"

    # GAP-CLOSED: GET /admin/runtime-settings
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/runtime-settings").status_code == 401

    def test_list_503_without_service(self, admin_client):
        r = admin_client.get("/admin/runtime-settings")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "runtime_settings_not_initialised"

    def test_list_with_service(self, admin_client, runtime_settings_state):
        r = admin_client.get("/admin/runtime-settings")
        assert r.status_code == 200
        keys = {s["key"] for s in r.json()["settings"]}
        assert self._KEY in keys

    # GAP-CLOSED: GET /admin/runtime-settings/{key}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get(f"/admin/runtime-settings/{self._KEY}").status_code == 401

    def test_get_unknown_key_404(self, admin_client):
        r = admin_client.get("/admin/runtime-settings/not.a.real.key")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "unknown_setting_key"

    def test_get_known_key_503_without_service(self, admin_client):
        r = admin_client.get(f"/admin/runtime-settings/{self._KEY}")
        assert r.status_code == 503

    def test_get_known_key_with_service(self, admin_client, runtime_settings_state):
        r = admin_client.get(f"/admin/runtime-settings/{self._KEY}")
        assert r.status_code == 200
        assert r.json()["value"] == 5000  # class_default

    # GAP-CLOSED: PUT /admin/runtime-settings/{key}
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put(f"/admin/runtime-settings/{self._KEY}", json={"value": 1000})
        assert r.status_code == 401

    def test_put_requires_stepup(self, admin_client, runtime_settings_state):
        r = admin_client.put(f"/admin/runtime-settings/{self._KEY}", json={"value": 1000})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_put_unknown_key_404(self, stepup_admin_client):
        r = stepup_admin_client.put("/admin/runtime-settings/not.a.real.key", json={"value": 1})
        assert r.status_code == 404

    def test_put_null_value_422(self, stepup_admin_client, runtime_settings_state):
        r = stepup_admin_client.put(f"/admin/runtime-settings/{self._KEY}", json={"value": None})
        assert r.status_code == 422

    def test_put_success_persists_and_audits(
        self, stepup_admin_client, runtime_settings_state, mock_audit_writer,
    ):
        r = stepup_admin_client.put(f"/admin/runtime-settings/{self._KEY}", json={"value": 9000})
        assert r.status_code == 200
        assert r.json()["value"] == 9000
        mock_audit_writer.write.assert_called_once()

        r2 = stepup_admin_client.get(f"/admin/runtime-settings/{self._KEY}")
        assert r2.json()["value"] == 9000, "value did not persist to the real fake store"

    # GAP-CLOSED: POST /admin/runtime-settings/{key}/reset
    def test_reset_unauth_401(self, unauth_client):
        assert unauth_client.post(f"/admin/runtime-settings/{self._KEY}/reset").status_code == 401

    def test_reset_requires_stepup(self, admin_client, runtime_settings_state):
        r = admin_client.post(f"/admin/runtime-settings/{self._KEY}/reset")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_reset_success(self, stepup_admin_client, runtime_settings_state):
        stepup_admin_client.put(f"/admin/runtime-settings/{self._KEY}", json={"value": 1})
        r = stepup_admin_client.post(f"/admin/runtime-settings/{self._KEY}/reset")
        assert r.status_code == 200
        assert r.json()["value"] == 5000  # back to class_default


class TestRuntimeSettingsLiveWiring:
    """PROVES the "applied immediately" claim's actual wire mechanism (dispatch
    brief: "if it claims applied immediately, PROVE the real path honours
    it") — against the REAL RuntimeSettingsService (not the FakeRuntimeSettingsService
    route-level fake above), with a minimal duck-typed asyncpg pool (the
    service's own SQL is trivial enough that a hand-rolled dict-backed fake
    is faithful) and a REAL fakeredis client wired as the service's
    `redis_client`. This is deliberately NOT routed through the FastAPI app —
    it exercises RuntimeSettingsService.set() directly, which is exactly the
    method runtime_settings.py's PUT handler calls."""

    class _FakePgConn:
        def __init__(self, table: dict) -> None:
            self._table = table

        async def fetchrow(self, query: str, key: str):
            row = self._table.get(key)
            if row is None:
                return None
            return {"value": json.dumps(row)}

        async def execute(self, query: str, key, value_json, default_json, source, changed_by, now):
            self._table[key] = json.loads(value_json)

    class _FakePgPool:
        def __init__(self) -> None:
            self._table: dict = {}
            self._conn = None

        def acquire(self):
            if self._conn is None:
                self._conn = TestRuntimeSettingsLiveWiring._FakePgConn(self._table)
            return _FakeAcquireCtx(self._conn)

    def test_set_publishes_on_documented_pubsub_channel(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_PER_IP_LIMIT
        from yashigani.runtime_settings.service import RuntimeSettingsService

        redis_client = fakeredis.FakeRedis(decode_responses=True)
        pubsub = redis_client.pubsub()
        pubsub.subscribe("yashigani:settings:changed")
        pubsub.get_message(timeout=1)  # discard the subscribe-confirmation message

        pool = self._FakePgPool()
        svc = RuntimeSettingsService(pool=pool, redis_client=redis_client)

        import asyncio
        asyncio.run(svc.set(
            key=KEY_DDOS_PER_IP_LIMIT, value=7500, changed_by="conformance-admin1", source="api",
        ))

        msg = pubsub.get_message(timeout=2)
        assert msg is not None, (
            "RuntimeSettingsService.set() did not publish on "
            "yashigani:settings:changed — the gateway's live-reload "
            "subscriber (entrypoint.py's ysg-settings-subscriber thread) "
            "would never see this change; the 'applied immediately' claim "
            "in the PUT endpoint's docstring would be false."
        )
        assert msg["type"] == "message"
        payload = json.loads(msg["data"])
        assert payload == {"key": KEY_DDOS_PER_IP_LIMIT, "value": 7500}

    def test_set_persists_to_pool_before_publishing(self):
        """Real-path proof that the write lands in the persistence layer
        (not just the pub/sub side-channel) — a subsequent get() sees it."""
        from yashigani.runtime_settings.keys import KEY_DDOS_PER_IP_LIMIT
        from yashigani.runtime_settings.service import RuntimeSettingsService

        redis_client = fakeredis.FakeRedis(decode_responses=True)
        pool = self._FakePgPool()
        svc = RuntimeSettingsService(pool=pool, redis_client=redis_client)

        import asyncio
        asyncio.run(svc.set(
            key=KEY_DDOS_PER_IP_LIMIT, value=1234, changed_by="conformance-admin1", source="api",
        ))
        value = asyncio.run(svc.get(KEY_DDOS_PER_IP_LIMIT))
        assert value == 1234


# ---------------------------------------------------------------------------
# budget.py — 12 endpoints, router-level dependencies=[Depends(require_admin_session)]
# ---------------------------------------------------------------------------


class TestBudgetOrgCaps:
    # GAP-CLOSED: GET /admin/budget/org-caps
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/budget/org-caps")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/budget/org-caps")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_empty_list(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/org-caps")
        assert r.status_code == 200
        assert r.json() == {"org_caps": []}

    # GAP-CLOSED: POST /admin/budget/org-caps
    def test_unauth_post_401(self, unauth_client):
        r = unauth_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000,
        })
        assert r.status_code == 401

    def test_admin_create_then_list(self, admin_client, budget_state):
        r = admin_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000, "period": "monthly",
        })
        assert r.status_code == 201
        body = r.json()
        assert body["org_id"] == "acme" and body["token_cap"] == 1000
        # Genuine persistence assertion (real BudgetConfigStore + fakeredis) —
        # proves the mutation actually round-trips, not just constructs a response.
        r2 = admin_client.get("/admin/budget/org-caps")
        assert r2.json()["org_caps"], "org cap did not persist to the real store"

    def test_admin_create_rejects_invalid_period(self, admin_client, budget_state):
        r = admin_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000, "period": "yearly",
        })
        assert r.status_code == 422  # Pydantic pattern validation — spec conformance

    # GAP-CLOSED: DELETE /admin/budget/org-caps
    def test_delete_nonexistent_404(self, admin_client, budget_state):
        r = admin_client.delete("/admin/budget/org-caps", params={"org_id": "nope", "provider": "x"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "org_cap_not_found"

    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/budget/org-caps", params={"org_id": "x", "provider": "y"})
        assert r.status_code == 401


class TestBudgetGroups:
    # GAP-CLOSED: GET/POST/DELETE /admin/budget/groups
    def test_full_lifecycle(self, admin_client, budget_state, mock_audit_writer):
        r = admin_client.get("/admin/budget/groups")
        assert r.status_code == 200 and r.json() == {"group_budgets": []}

        r = admin_client.post("/admin/budget/groups", json={
            "group_id": "eng", "provider": "*", "token_budget": 50000, "period": "monthly",
        })
        assert r.status_code == 201
        assert r.json()["auto_calculated"] is False

        r = admin_client.delete("/admin/budget/groups", params={"group_id": "eng", "provider": "*"})
        assert r.status_code == 204
        mock_audit_writer.write.assert_called_once()

        r = admin_client.delete("/admin/budget/groups", params={"group_id": "eng", "provider": "*"})
        assert r.status_code == 404, "second delete of the same key must 404, not silently 204 again"

    def test_unauth_all_methods_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/groups").status_code == 401
        assert unauth_client.post("/admin/budget/groups", json={}).status_code == 401
        assert unauth_client.delete("/admin/budget/groups", params={"group_id": "x", "provider": "y"}).status_code == 401


class TestBudgetIndividuals:
    # GAP-CLOSED: GET/POST/DELETE /admin/budget/individuals
    def test_full_lifecycle(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/individuals")
        assert r.status_code == 200 and r.json() == {"individual_budgets": []}

        r = admin_client.post("/admin/budget/individuals", json={
            "identity_id": "alice@acme.com", "provider": "*", "token_budget": 5000,
        })
        assert r.status_code == 201
        assert r.json()["remaining"] == 5000
        _store, enforcer = budget_state
        enforcer.set_allocation.assert_called_once_with("alice@acme.com", "*", 5000)

        r = admin_client.delete("/admin/budget/individuals", params={
            "identity_id": "alice@acme.com", "provider": "*",
        })
        assert r.status_code == 204

    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/individuals").status_code == 401


class TestBudgetUsageTreeInventory:
    # GAP-CLOSED: GET /admin/budget/usage/{identity_id}
    def test_usage_503_without_enforcer(self, admin_client):
        r = admin_client.get("/admin/budget/usage/alice@acme.com")
        assert r.status_code == 503, "budget_enforcer is None by default — must fail closed, not 200 empty"

    def test_usage_with_enforcer(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/usage/alice@acme.com")
        assert r.status_code == 200
        assert r.json()["identity_id"] == "alice@acme.com"

    def test_usage_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/usage/x").status_code == 401

    # YSG-RISK-157 CLOSED: GET /admin/budget/tree is an honest 501, not a
    # misleading 200/empty-tree stub — see test_tom_ysg_risk_156_157_honest_
    # stub_endpoints.py.
    def test_tree_admin_501_not_implemented(self, admin_client):
        r = admin_client.get("/admin/budget/tree")
        assert r.status_code == 501
        assert r.json()["detail"]["error"] == "not_implemented"

    def test_tree_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/tree").status_code == 401

    # GAP-CLOSED: GET /admin/budget/models/local-inventory
    def test_local_inventory_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/models/local-inventory").status_code == 401

    def test_local_inventory_admin_ollama_unreachable_502(self, admin_client):
        """Offline-environment reality: this route makes a REAL httpx call to
        Ollama /api/tags with no mock hook (budget.py:544) — there is no
        Ollama in this offline suite, so the genuine, documented fail-closed
        contract is HTTP 502 `ollama_unavailable` (budget.py:557-563), not
        200. Verified as real behaviour, not a stub — the route's error
        path IS being exercised."""
        r = admin_client.get("/admin/budget/models/local-inventory")
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "ollama_unavailable"


class TestBudgetTreeIsAStub:
    """YSG-RISK-157 (LOW) — CLOSED. GET /admin/budget/tree was a literal
    stub (budget.py:334 'Placeholder — will be populated from Postgres in
    integration') that always returned tree=[] regardless of configured
    org caps / group budgets / individual budgets — a misleading 200/empty
    response rather than an honest signal that the nested tree view isn't
    built. A genuinely correct nested tree needs group->org /
    identity->group membership linkage that does not exist in the budget
    schema (deferred past 4.1.2). Fix: the endpoint now returns an honest
    501 not_implemented regardless of configured caps — see
    test_tom_ysg_risk_156_157_honest_stub_endpoints.py. GET
    /admin/budget/{org-caps,groups,individuals} remain the flat
    (non-nested) source of truth and are unaffected."""

    def test_tree_still_501_regardless_of_configured_org_caps(self, admin_client, budget_state):
        admin_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000, "period": "monthly",
        })
        r = admin_client.get("/admin/budget/tree")
        assert r.status_code == 501
        assert r.json()["detail"]["error"] == "not_implemented"

        # The flat, non-nested source of truth is NOT affected by the 501.
        flat = admin_client.get("/admin/budget/org-caps")
        assert flat.status_code == 200


# ---------------------------------------------------------------------------
# models.py — 9 endpoints. Mutations are StepUpAdminSession-gated.
# ---------------------------------------------------------------------------


class TestModelAliases:
    # GAP-CLOSED: GET /admin/models
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models").status_code == 401

    def test_alias_store_unconfigured_503(self, admin_client):
        r = admin_client.get("/admin/models")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "alias_store_unavailable"

    def test_list_empty_with_store(self, admin_client, models_state):
        r = admin_client.get("/admin/models")
        assert r.status_code == 200

    # GAP-CLOSED: POST /admin/models (step-up required)
    def test_create_requires_stepup_not_just_admin(self, admin_client, models_state):
        """SPEC-CONFORMANCE: admin session WITHOUT a fresh TOTP step-up must
        be rejected (401 step_up_required) — this is the exact ASVS V6.8.4
        control this codebase's release history (project_totp memory) flags
        as security-critical. Regression-guards against re-introducing the
        LF-STEPUP-AGENT-CREATE bypass."""
        r = admin_client.post("/admin/models", json={
            "alias": "fast", "provider": "ollama", "model": "qwen2.5:3b",
        })
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_create_with_stepup_201(self, stepup_admin_client, models_state):
        r = stepup_admin_client.post("/admin/models", json={
            "alias": "fast", "provider": "ollama", "model": "qwen2.5:3b",
        })
        assert r.status_code == 201

    # GAP-CLOSED: DELETE /admin/models/{alias}
    def test_delete_requires_stepup(self, admin_client, models_state):
        r = admin_client.delete("/admin/models/fast")
        assert r.status_code == 401

    def test_delete_nonexistent_with_stepup(self, stepup_admin_client, models_state):
        r = stepup_admin_client.delete("/admin/models/does-not-exist")
        assert r.status_code == 404

    # GAP-CLOSED: GET /admin/models/available
    def test_available_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models/available").status_code == 401


class TestModelPull:
    # GAP-CLOSED: POST /admin/models/pull (step-up required)
    def test_pull_requires_stepup(self, admin_client):
        r = admin_client.post("/admin/models/pull", json={"name": "qwen2.5:3b"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_pull_ollama_unreachable_503(self, stepup_admin_client, monkeypatch):
        """Offline-safe: monkeypatch the Ollama transport factory to raise a
        connection error immediately rather than depend on network reachability
        (which is unavailable/undesirable in this offline suite) — proves the
        route's documented fail-closed 503 `ollama_unreachable` contract."""
        import contextlib

        @contextlib.asynccontextmanager
        async def _raise_connect_error(*_a, **_kw):
            raise httpx.ConnectError("no ollama in offline conformance suite")
            yield  # pragma: no cover — unreachable, satisfies generator shape

        monkeypatch.setattr(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            _raise_connect_error,
        )
        r = stepup_admin_client.post("/admin/models/pull", json={"name": "qwen2.5:3b"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "ollama_unreachable"


class TestModelAllocationTargets:
    # GAP-CLOSED: GET /admin/models/allocation-targets
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/models/allocation-targets", params={"target_type": "user"})
        assert r.status_code == 401

    def test_invalid_target_type_400(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "bogus"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_target_type"

    def test_org_target_type_always_has_default(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "org"})
        assert r.status_code == 200
        ids = {t["id"] for t in r.json()["targets"]}
        assert "default" in ids

    def test_user_target_type_degrades_empty_without_auth_service(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "user"})
        assert r.status_code == 200
        assert r.json()["targets"] == []


class TestModelAllocations:
    # GAP-CLOSED: GET/POST/DELETE /admin/models/allocations
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models/allocations").status_code == 401

    def test_lifecycle_with_stores(self, stepup_admin_client, models_state):
        alias_store, _alloc_store = models_state
        from yashigani.models.alias_store import ModelAlias
        alias_store.set("fast", ModelAlias(alias="fast", provider="ollama", model="qwen2.5:3b"))

        r = stepup_admin_client.get("/admin/models/allocations")
        assert r.status_code == 200 and r.json()["allocations"] == []

        r = stepup_admin_client.post("/admin/models/allocations", json={
            "model_alias": "fast", "target_type": "user", "target_id": "alice@acme.com",
        })
        assert r.status_code == 201
        alloc_id = r.json()["allocation"]["id"]

        r = stepup_admin_client.delete(f"/admin/models/allocations/{alloc_id}")
        assert r.status_code == 200

        r = stepup_admin_client.delete(f"/admin/models/allocations/{alloc_id}")
        assert r.status_code == 404

    def test_create_allocation_unknown_alias_404(self, stepup_admin_client, models_state):
        r = stepup_admin_client.post("/admin/models/allocations", json={
            "model_alias": "does-not-exist", "target_type": "user", "target_id": "bob@acme.com",
        })
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "alias_not_found"


# ---------------------------------------------------------------------------
# audit.py — GET /admin/audit/export/raw + masking scope + SIEM targets
# (13 endpoints)
# ---------------------------------------------------------------------------


class TestAuditExportRaw:
    # GAP-CLOSED: GET /admin/audit/export/raw
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/audit/export/raw")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client, real_audit_writer):
        r = user_client.get("/admin/audit/export/raw")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_ndjson_contains_written_event(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(
            ConfigChangedEvent(
                admin_account="export-raw-probe",
                setting="masking.default",
                previous_value="true",
                new_value="false",
            )
        )
        r = admin_client.get("/admin/audit/export/raw")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-ndjson"
        assert "export-raw-probe" in r.text

    def test_admin_csv_format(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="csv-probe"))
        r = admin_client.get("/admin/audit/export/raw", params={"output_format": "csv"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/csv; charset=utf-8"
        assert "csv-probe" in r.text

    def test_invalid_format_422(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/export/raw", params={"output_format": "xml"})
        assert r.status_code == 422


class TestMaskingScopeDefault:
    # GAP-CLOSED: GET /admin/audit/masking/scope
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/masking/scope").status_code == 401

    def test_user_tier_403(self, user_client, real_audit_writer):
        r = user_client.get("/admin/audit/masking/scope")
        assert r.status_code == 403

    def test_admin_defaults(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/masking/scope")
        assert r.status_code == 200
        body = r.json()
        assert body == {
            "mask_all_by_default": True,
            "agent_overrides": {},
            "user_overrides": {},
            "component_overrides": {},
        }

    # GAP-CLOSED: PUT /admin/audit/masking/scope
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/audit/masking/scope", json={"mask_all_by_default": False})
        assert r.status_code == 401

    def test_put_updates_real_writer_state(self, admin_client, real_audit_writer):
        r = admin_client.put("/admin/audit/masking/scope", json={"mask_all_by_default": False})
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "mask_all_by_default": False}
        # Genuine mutation assertion against the real writer instance.
        assert real_audit_writer._masking_scope.mask_all_by_default is False
        # And the config-change event was actually persisted to the real log.
        r2 = admin_client.get("/admin/audit/export/raw")
        assert "masking.default" in r2.text


class TestMaskingScopeAgent:
    # GAP-CLOSED: POST /admin/audit/masking/scope/agent
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-1", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-1", "mask": False}
        )
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
        assert real_audit_writer._masking_scope.agent_overrides["agent-1"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/agent/{agent_id}
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/audit/masking/scope/agent/agent-1")
        assert r.status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/agent/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-2", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/agent/agent-2")
        assert r.status_code == 200
        assert "agent-2" not in real_audit_writer._masking_scope.agent_overrides
        r2 = admin_client.delete("/admin/audit/masking/scope/agent/agent-2")
        assert r2.status_code == 404


class TestMaskingScopeUser:
    # GAP-CLOSED: POST /admin/audit/masking/scope/user
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "alice", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "alice", "mask": False}
        )
        assert r.status_code == 200
        assert real_audit_writer._masking_scope.user_overrides["alice"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/user/{handle}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/audit/masking/scope/user/alice").status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/user/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "bob", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/user/bob")
        assert r.status_code == 200
        assert "bob" not in real_audit_writer._masking_scope.user_overrides


class TestMaskingScopeComponent:
    # GAP-CLOSED: POST /admin/audit/masking/scope/component
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/component", json={"component": "ratelimit", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/component", json={"component": "ratelimit", "mask": False}
        )
        assert r.status_code == 200
        assert real_audit_writer._masking_scope.component_overrides["ratelimit"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/component/{component}
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/audit/masking/scope/component/ratelimit")
        assert r.status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/component/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/component", json={"component": "budget", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/component/budget")
        assert r.status_code == 200
        assert "budget" not in real_audit_writer._masking_scope.component_overrides


class TestSiemTargets:
    # GAP-CLOSED: GET /admin/audit/siem
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/siem").status_code == 401

    def test_list_empty(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/siem")
        assert r.status_code == 200
        assert r.json() == {"siem_targets": [], "total": 0}

    # GAP-CLOSED: POST /admin/audit/siem
    def test_add_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "secret-token",
        })
        assert r.status_code == 401

    def test_add_rejects_non_https_422(self, admin_client, real_audit_writer):
        """SPEC-CONFORMANCE (SSRF hardening, CWE-918/YSG-RISK-007.C): scheme
        must be https — real validate_siem_url() call, not a stub."""
        r = admin_client.post("/admin/audit/siem", json={
            "name": "insecure", "target_type": "webhook", "url": "http://siem.example.com/hook",
            "auth_value": "secret-token",
        })
        assert r.status_code == 422

    def test_add_then_list_bopla_excludes_auth_value(self, admin_client, real_audit_writer, monkeypatch):
        """BOPLA (#90): SiemTargetPublic never returns auth_value."""
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        r = admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "super-secret-token",
        })
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "name": "wazuh"}

        r2 = admin_client.get("/admin/audit/siem")
        assert r2.status_code == 200
        targets = r2.json()["siem_targets"]
        assert len(targets) == 1
        assert targets[0]["name"] == "wazuh"
        assert "auth_value" not in targets[0]

    def test_add_duplicate_name_409(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        payload = {
            "name": "dup-target", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        }
        assert admin_client.post("/admin/audit/siem", json=payload).status_code == 200
        r2 = admin_client.post("/admin/audit/siem", json=payload)
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "siem_target_name_taken"

    # GAP-CLOSED: DELETE /admin/audit/siem/{name}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/audit/siem/wazuh").status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/siem/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "siem_target_not_found"

    def test_delete_existing_200(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "to-remove", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })
        r = admin_client.delete("/admin/audit/siem/to-remove")
        assert r.status_code == 200
        r2 = admin_client.get("/admin/audit/siem")
        assert r2.json()["total"] == 0

    # GAP-CLOSED: POST /admin/audit/siem/{name}/test
    def test_test_connection_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/audit/siem/wazuh/test").status_code == 401

    def test_test_connection_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.post("/admin/audit/siem/does-not-exist/test")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "siem_target_not_found"

    def test_test_connection_success_200(self, admin_client, real_audit_writer, monkeypatch):
        """Offline-safe: monkeypatches urllib.request.urlopen (audit.py has no
        transport-injection hook — this is a real test of the route's own
        _format_for_target + validate_siem_url re-check logic, only the final
        socket call is stubbed)."""
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })

        import urllib.request

        monkeypatch.setattr(
            urllib.request, "urlopen", lambda *a, **kw: _FakeHTTPResponse(200)
        )
        r = admin_client.post("/admin/audit/siem/wazuh/test")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "http_status": 200}

    def test_test_connection_upstream_failure_502(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })

        import urllib.error
        import urllib.request

        def _raise(*_a, **_kw):
            raise urllib.error.HTTPError(
                "https://siem.example.com/hook", 500, "Internal Server Error", {}, None
            )

        monkeypatch.setattr(urllib.request, "urlopen", _raise)
        r = admin_client.post("/admin/audit/siem/wazuh/test")
        assert r.status_code == 502
        assert r.json()["detail"]["http_status"] == 500


class TestAuditHardCrashWithoutWriterFinding:
    """F5 (LOW): audit.py's `_audit_writer()` helper (audit.py:49-53) does
    `assert writer is not None` with NO try/except anywhere in the call
    chain — every one of this file's 13 endpoints uses it as their very
    first statement. When backoffice_state.audit_writer is unset, EVERY
    audit.py endpoint returns HTTP 500 (via the app's generic Exception
    handler) with zero graceful degrade. Contrast with the sibling file
    audit_search.py, whose `_get_log_path()` returns a clean, documented 503
    `audit_log_not_configured` for the exact same "writer not configured"
    condition (see TestAuditSearch.test_admin_503_without_writer below) —
    two files serving the same conceptual "audit log" admin surface behave
    completely differently under the identical failure condition. Neither
    behaviour is a security bypass (both fail closed, no data leak) but the
    inconsistency is real and worth fixing for a coherent error contract."""

    @staticmethod
    def _raw_admin_client(bo_app, session_store, caddy_headers):
        """Local TestClient(raise_server_exceptions=False) — Starlette's
        ServerErrorMiddleware always re-raises after building the response
        ('We always continue to raise the exception ... allows test clients
        to optionally raise the error within the test case') — the shared
        admin_client fixture defaults to raise_server_exceptions=True, which
        would re-raise the AssertionError into THIS test process instead of
        letting us observe the actual HTTP 500 a real deployment (uvicorn)
        delivers to the client. Mirrors the pattern already established in
        the ported manifest_history.py 503-vs-500 divergence test."""
        from fastapi.testclient import TestClient

        session = session_store.create(
            account_id="conformance-admin-hardcrash", account_tier="admin", client_ip="127.0.0.1"
        )
        client = TestClient(bo_app, headers=caddy_headers, raise_server_exceptions=False)
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        return client

    def test_masking_scope_get_500_not_503_when_writer_unset(
        self, bo_app, session_store, caddy_headers,
    ):
        from yashigani.backoffice.state import backoffice_state

        assert backoffice_state.audit_writer is None, "test precondition"
        client = self._raw_admin_client(bo_app, session_store, caddy_headers)
        r = client.get("/admin/audit/masking/scope")
        assert r.status_code == 500
        assert r.json() == {"error": "internal_error", "message": "An internal error occurred"}

    def test_siem_list_500_not_503_when_writer_unset(
        self, bo_app, session_store, caddy_headers,
    ):
        from yashigani.backoffice.state import backoffice_state

        assert backoffice_state.audit_writer is None, "test precondition"
        client = self._raw_admin_client(bo_app, session_store, caddy_headers)
        r = client.get("/admin/audit/siem")
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# audit_search.py — 3 endpoints
# ---------------------------------------------------------------------------


class TestAuditFacets:
    # GAP-CLOSED: GET /admin/audit/facets
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/facets").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/facets").status_code == 403

    def test_admin_200_shape(self, admin_client):
        r = admin_client.get("/admin/audit/facets")
        assert r.status_code == 200
        body = r.json()
        assert {"value": "deny", "label": "Deny"} in body["verdicts"]
        assert {"value": "AGENT", "label": "Agent"} in body["source_types"]


class TestAuditSearch:
    # GAP-CLOSED: GET /admin/audit/search
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/search").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/search").status_code == 403

    def test_admin_503_without_writer(self, admin_client):
        """SPEC-CONFORMANCE: unlike audit.py's assert-based hard-fail (F5
        above), audit_search.py's _get_log_path() gracefully degrades to a
        503 `audit_log_not_configured` when backoffice_state.audit_writer is
        None."""
        r = admin_client.get("/admin/audit/search")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "audit_log_not_configured"

    def test_admin_finds_written_event_by_user_filter(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="alice-search-target"))
        real_audit_writer.write(ConfigChangedEvent(admin_account="bob-other-account"))

        r = admin_client.get("/admin/audit/search", params={"user": "alice-search-target"})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["rows"][0]["admin_account"] == "alice-search-target"
        assert body["has_more"] is False

    def test_admin_event_type_filter(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="event-type-probe"))
        r = admin_client.get("/admin/audit/search", params={"event_type": "CONFIG_CHANGED"})
        assert r.status_code == 200
        assert r.json()["count"] >= 1
        assert all(row["event_type"] == "CONFIG_CHANGED" for row in r.json()["rows"])

    def test_admin_no_match_empty_rows(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/search", params={"user": "nobody-matches-this"})
        assert r.status_code == 200
        assert r.json() == {
            "rows": [], "count": 0, "total_scanned": 0, "cursor": None, "has_more": False,
        }


class TestAuditExportFiltered:
    # GAP-CLOSED: GET /admin/audit/export
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/export").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/export").status_code == 403

    def test_admin_503_without_writer(self, admin_client):
        r = admin_client.get("/admin/audit/export")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "audit_log_not_configured"

    def test_admin_ndjson_default(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="export-filtered-probe"))
        r = admin_client.get("/admin/audit/export")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-ndjson"
        assert "export-filtered-probe" in r.text

    def test_admin_csv_format(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="csv-filtered-probe"))
        r = admin_client.get("/admin/audit/export", params={"output_format": "csv"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/csv; charset=utf-8"
        assert "csv-filtered-probe" in r.text

    def test_invalid_format_422(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/export", params={"output_format": "xml"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# audit_sinks.py — 4 endpoints. NEW coverage (no prior conformance test
# claimed this file — see module docstring). Mounted with NO app-level
# prefix (full paths baked into the decorators), collides on the
# "/admin/audit" family with audit.py/audit_search.py — see the 2026-05-02
# path-collision note in the file's own docstring (audit.py's GET /siem for
# named targets vs this file's GET /siem/config for the single active
# backend).
# ---------------------------------------------------------------------------


class TestAuditSinksList:
    # GAP-CLOSED: GET /admin/audit/sinks
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/sinks").status_code == 401

    def test_admin_degrades_gracefully_without_writer(self, admin_client):
        """SPEC-CONFORMANCE (contrast with F5): unlike audit.py's hard
        assert-crash, this sibling endpoint (same /admin/audit/* family)
        uses `hasattr(audit_writer, "status")` — with audit_writer=None,
        hasattr(None, "status") is False, so it falls through to a
        placeholder shape instead of crashing. A THIRD distinct behaviour
        for the same "audit writer unset" condition across this group's
        files (audit.py=500, audit_search.py=503, audit_sinks.py=200
        placeholder)."""
        from yashigani.backoffice.state import backoffice_state

        assert backoffice_state.audit_writer is None
        r = admin_client.get("/admin/audit/sinks")
        assert r.status_code == 200
        assert r.json() == {"sinks": {"file": {"last_write": None}}}

    def test_admin_reflects_real_writer_status(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/sinks")
        assert r.status_code == 200
        assert "sinks" in r.json()


class TestAuditSiemConfig:
    # GAP-CLOSED: GET /admin/audit/siem/config
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/siem/config").status_code == 401

    def test_get_defaults(self, admin_client, siem_config_reset):
        r = admin_client.get("/admin/audit/siem/config")
        assert r.status_code == 200
        assert r.json() == {"backend": "none", "endpoint": None, "wazuh_auto_deploy": False}

    # GAP-CLOSED: PUT /admin/audit/siem/config (step-up required)
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/audit/siem/config", json={"backend": "splunk", "endpoint": "https://x"})
        assert r.status_code == 401

    def test_put_admin_without_stepup_401(self, admin_client, siem_config_reset):
        r = admin_client.put("/admin/audit/siem/config", json={
            "backend": "splunk", "endpoint": "https://splunk.example.com:8088",
        })
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_put_non_none_backend_requires_endpoint_422(self, stepup_admin_client, siem_config_reset):
        r = stepup_admin_client.put("/admin/audit/siem/config", json={"backend": "splunk"})
        assert r.status_code == 422

    def test_put_ssrf_rejected_422(self, stepup_admin_client, siem_config_reset):
        """FIND-3.0-001 SSRF guard: loopback/private-IP endpoints are
        rejected before being stored (real assert_safe_outbound_url call)."""
        r = stepup_admin_client.put("/admin/audit/siem/config", json={
            "backend": "splunk", "endpoint": "https://127.0.0.1:8088",
        })
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    def test_put_success_persists_to_real_state(self, stepup_admin_client, siem_config_reset, monkeypatch):
        # YASHIGANI_SIEM_HOSTNAMES: assert_safe_outbound_url() does a REAL
        # socket.getaddrinfo() resolution and fails closed (422) on any
        # hostname that doesn't resolve (LAURA-300-001) — "splunk.example.com"
        # is not resolvable in this offline sandbox, so it must be
        # operator-allowlisted exactly as a real deployment's operator would
        # do for an internal-only SIEM host. This is the REAL validation
        # path, not bypassed — see test_put_ssrf_rejected_422 above for the
        # rejection half of the same guard.
        monkeypatch.setenv("YASHIGANI_SIEM_HOSTNAMES", "splunk.example.com")
        r = stepup_admin_client.put("/admin/audit/siem/config", json={
            "backend": "splunk", "endpoint": "https://splunk.example.com:8088", "wazuh_auto_deploy": False,
        })
        assert r.status_code == 200
        assert r.json() == {"status": "updated", "backend": "splunk"}

        from yashigani.backoffice.state import backoffice_state
        assert backoffice_state.siem_backend == "splunk"
        assert backoffice_state.siem_endpoint == "https://splunk.example.com:8088"

        # Genuine persistence round-trip through the sibling GET.
        r2 = stepup_admin_client.get("/admin/audit/siem/config")
        assert r2.json()["backend"] == "splunk"


class TestAuditSiemConfigTestRouteCollisionFinding:
    """YSG-RISK-142 (HIGH) — CLOSED. POST /admin/audit/siem/config/test was
    UNREACHABLE: audit.py registered `POST /admin/audit/siem/{name}/test`
    (audit.py:357) BEFORE audit_sinks.py's literal `POST
    /admin/audit/siem/config/test` was registered — Starlette resolves
    routes in REGISTRATION ORDER with no literal-beats-dynamic precedence,
    so a request to "/admin/audit/siem/config/test" matched audit.py's
    dynamic `{name}/test` template FIRST (binding name="config") and
    audit_sinks.py's literal handler was never reached.

    Fix (app.py, YSG-RISK-142 comment at the include_router call sites):
    audit_sinks_router is now registered BEFORE audit_router, so the
    literal `/admin/audit/siem/config/test` path wins the match and
    audit_sinks.py's `test_siem()` is reached — regardless of whether a
    named SIEM target literally called "config" exists. These tests were
    written against the PRE-FIX behaviour (proving the bug); flipped here
    to assert the CLOSED contract as permanent regression guards, per
    test_tom_ysg_risk_142_siem_test_route_order.py."""

    def test_unauth_401(self, unauth_client):
        # Auth requirement happens to be identical on both handlers
        # (require_admin_session, no step-up) so this assertion holds
        # regardless of which one actually executes.
        assert unauth_client.post("/admin/audit/siem/config/test").status_code == 401

    def test_starlette_resolves_to_audit_sinks_py_not_audit_py(self, bo_app):
        """Direct proof against the live route table — no HTTP round-trip
        needed, this is the routing decision itself. YSG-RISK-142 CLOSED:
        audit_sinks_router is now registered before audit_router, so the
        literal path wins."""
        from starlette.routing import Match

        scope = {"type": "http", "method": "POST", "path": "/admin/audit/siem/config/test"}
        for route in bo_app.router.routes:
            match, _child_scope = route.matches(scope)
            if match == Match.FULL:
                assert route.name == "test_siem", (
                    f"Expected the fixed registration order to resolve to "
                    f"audit_sinks.py's test_siem (literal path) — got "
                    f"{route.name!r} instead. If this assertion fails, the "
                    f"routing order has regressed back to the pre-fix "
                    f"collision; update this test, don't just delete it."
                )
                assert route.path == "/admin/audit/siem/config/test"
                return
        pytest.fail("No route matched POST /admin/audit/siem/config/test at all")

    def test_no_siem_backend_configured_400_not_config_lookup(self, admin_client, real_audit_writer):
        """Observed end-to-end behaviour post-fix: the request reaches
        audit_sinks.py's test_siem(), which 400s ("No SIEM backend
        configured") because no backend is wired via
        backoffice_state.siem_backend — NOT audit.py's 404
        siem_target_not_found (the old collision's symptom, which depended
        on looking up a NAMED target called "config" that this test never
        creates)."""
        r = admin_client.post("/admin/audit/siem/config/test")
        assert r.status_code == 400
        assert r.json()["detail"] == "No SIEM backend configured"

    def test_a_named_target_literally_called_config_is_no_longer_relevant(
        self, admin_client, real_audit_writer, monkeypatch,
    ):
        """YSG-RISK-142 CLOSED: an admin can create an UNRELATED named SIEM
        target called "config" (a plausible name — nothing stops it) via
        POST /admin/audit/siem without it having any bearing on POST
        /admin/audit/siem/config/test any more — that route now
        unconditionally reaches audit_sinks.py's test_siem(), which tests
        the REAL configured backend (or 400s if none is configured), never
        the named target. Proves the collision is gone, not just moved."""
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "config", "target_type": "webhook", "url": "https://unrelated-target.example.com/hook",
            "auth_value": "unrelated-token",
        })

        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: _FakeHTTPResponse(200))

        r = admin_client.post("/admin/audit/siem/config/test")
        assert r.status_code == 400
        assert r.json()["detail"] == "No SIEM backend configured", (
            "This is audit_sinks.py's own unconfigured-backend response "
            "({'detail': 'No SIEM backend configured'}), NOT audit.py's "
            "SiemTarget-test response shape ({'status': 'ok', "
            "'http_status': N}) that the OLD collision would have "
            "produced from the unrelated named target called 'config' — "
            "proof the fixed handler executed and the named target was "
            "never consulted."
        )

    def test_sinks_handler_itself_is_correct_in_isolation(self, monkeypatch):
        """Scopes the fix precisely: calling audit_sinks.py's OWN test_siem()
        function directly (bypassing HTTP routing entirely) proves the
        handler's own logic is correct — the bug is a pure route-registration-
        order collision, not a defect in audit_sinks.py's code. Fix options:
        register audit_sinks_router before audit_router, or rename the
        literal path to something that cannot collide with any
        {name}-shaped template (e.g. /admin/audit/siem/_config/test)."""
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock as _AsyncMock

        from yashigani.backoffice.state import backoffice_state
        from yashigani.backoffice.routes.audit_sinks import test_siem
        from yashigani.audit.sinks import SiemSink

        # YTF consolidation fix (2026-07-29, Iris): these three were direct
        # attribute assignments on the backoffice_state module-level
        # singleton — no monkeypatch, so they LEAK for the rest of the
        # pytest process once this test runs. In this file alone that's
        # invisible (nothing later in the same file depends on
        # kms_provider being None), but once this suite is consolidated
        # into tests/conformance/ alongside test_secrets_pki_vault.py in the
        # SAME pytest process, the leaked SimpleNamespace(get_secret=...)
        # (which lacks .provider_name) makes test_secrets_pki_vault.py's
        # "kms not configured" tests hit an AttributeError instead of their
        # expected 503 — a real, confirmed test-isolation bug (verified:
        # test_secrets_pki_vault.py is 94/94 GREEN run alone, 4 failures
        # only when run after this file in the same process). monkeypatch
        # auto-reverts these after the test, closing the leak.
        monkeypatch.setattr(backoffice_state, "siem_backend", "splunk", raising=False)
        monkeypatch.setattr(backoffice_state, "siem_endpoint", "https://splunk.example.com:8088", raising=False)
        monkeypatch.setattr(backoffice_state, "kms_provider", SimpleNamespace(get_secret=lambda _k: "fake-token"), raising=False)

        write_mock = _AsyncMock(return_value=None)
        monkeypatch.setattr(SiemSink, "write", write_mock)

        session = SimpleNamespace(account_id="conformance-direct-call")
        result = asyncio.run(test_siem(session=session))
        assert result == {"status": "test_sent", "backend": "splunk"}
        write_mock.assert_called_once()


class TestAuditSinksDocumentedButUnimplementedFinding:
    """YSG-RISK-148 (MEDIUM) — CLOSED. The module docstring (audit_sinks.py:8)
    documented `DELETE /admin/audit/sinks/queue — drain the audit queue
    (admin flush)` since 2026-05-02 but it was never implemented (always
    404). Fix: PostgresSink.drain_now() / SiemSink.drain_now() /
    MultiSinkAuditWriter.drain_queues() plus the new
    `DELETE /admin/audit/sinks/queue` route (routes/audit_sinks.py),
    fail-closed 503 if audit_writer is unavailable. See
    test_tom_ysg_risk_148_audit_queue_drain.py."""

    def test_documented_queue_drain_endpoint_drains_and_returns_200(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/sinks/queue")
        assert r.status_code == 200, (
            f"YSG-RISK-148 REGRESSION: expected the now-implemented drain "
            f"endpoint to succeed, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body["status"] in ("drained", "no_queued_sinks")
        assert "sinks" in body

    def test_queue_drain_endpoint_503_when_audit_writer_unavailable(self, admin_client, monkeypatch):
        from yashigani.backoffice.state import backoffice_state

        monkeypatch.setattr(backoffice_state, "audit_writer", None, raising=False)
        r = admin_client.delete("/admin/audit/sinks/queue")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "audit_writer_unavailable"


# ---------------------------------------------------------------------------
# alerts.py — 10 endpoints
# ---------------------------------------------------------------------------


class TestAlertsSinkConfig:
    # GAP-CLOSED: GET /admin/alerts/config
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/alerts/config").status_code == 401

    def test_get_default_unconfigured(self, admin_client, alert_config_reset):
        r = admin_client.get("/admin/alerts/config")
        assert r.status_code == 200
        assert r.json() == {"configured": False, "sinks": []}

    # GAP-CLOSED: PUT /admin/alerts/config
    def test_put_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/alerts/config", json={}).status_code == 401

    def test_put_success_pagerduty(self, admin_client, alert_config_reset, mock_audit_writer):
        r = admin_client.put("/admin/alerts/config", json={"pagerduty_routing_key": "R00000001"})
        assert r.status_code == 200
        assert r.json()["sinks_configured"] == 1
        mock_audit_writer.write.assert_called_once()

        r2 = admin_client.get("/admin/alerts/config")
        assert r2.json()["configured"] is True
        assert r2.json()["sinks"][0]["type"] == "pagerduty"
        assert r2.json()["sinks"][0]["masked_key"].startswith("***")

    def test_put_rejects_ssrf_webhook_url(self, admin_client, alert_config_reset, deny_all_dns):
        """V232-CSCAN-01b: a Slack webhook URL that fails DNS resolution (or
        resolves off-allowlist) must be rejected 400, never persisted."""
        r = admin_client.put("/admin/alerts/config", json={
            "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/XXX",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "webhook_url_forbidden"

        r2 = admin_client.get("/admin/alerts/config")
        assert r2.json()["configured"] is False, "rejected URL must not be persisted"

    # GAP-CLOSED: POST /admin/alerts/test/{sink}
    def test_test_sink_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/alerts/test/slack").status_code == 401

    def test_test_sink_invalid_name_422(self, admin_client):
        r = admin_client.post("/admin/alerts/test/carrier-pigeon")
        assert r.status_code == 422

    def test_test_sink_no_config_404(self, admin_client, alert_config_reset):
        r = admin_client.post("/admin/alerts/test/slack")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "no_alert_config"

    def test_test_sink_not_configured_404(self, admin_client, alert_config_reset, mock_audit_writer):
        admin_client.put("/admin/alerts/config", json={"pagerduty_routing_key": "R00000001"})
        r = admin_client.post("/admin/alerts/test/slack")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "slack_not_configured"

    def test_test_sink_delivered(self, admin_client, alert_config_reset, mock_audit_writer, monkeypatch):
        from yashigani.alerts.pagerduty_sink import PagerDutySink

        admin_client.put("/admin/alerts/config", json={"pagerduty_routing_key": "R00000001"})
        monkeypatch.setattr(PagerDutySink, "test", AsyncMock(return_value=True))
        r = admin_client.post("/admin/alerts/test/pagerduty")
        assert r.status_code == 200
        assert r.json() == {"status": "delivered", "sink": "pagerduty"}

    def test_test_sink_delivery_failed_502(self, admin_client, alert_config_reset, mock_audit_writer, monkeypatch):
        from yashigani.alerts.pagerduty_sink import PagerDutySink

        admin_client.put("/admin/alerts/config", json={"pagerduty_routing_key": "R00000001"})
        monkeypatch.setattr(PagerDutySink, "test", AsyncMock(return_value=False))
        r = admin_client.post("/admin/alerts/test/pagerduty")
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "delivery_failed"


class TestAlertsBudgetThreshold:
    # GAP-CLOSED: GET /admin/alerts/budget-threshold
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/alerts/budget-threshold").status_code == 401

    def test_get_default(self, admin_client, alert_config_reset):
        r = admin_client.get("/admin/alerts/budget-threshold")
        assert r.status_code == 200
        assert r.json() == {
            "enabled": True, "threshold_pct": 85,
            "description": "Alert fires when budget used >= 85% of the limit.",
        }

    # GAP-CLOSED: PUT /admin/alerts/budget-threshold
    def test_put_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/alerts/budget-threshold", json={}).status_code == 401

    def test_put_out_of_range_422(self, admin_client, alert_config_reset):
        r = admin_client.put("/admin/alerts/budget-threshold", json={"threshold_pct": 150})
        assert r.status_code == 422

    def test_put_success(self, admin_client, alert_config_reset, mock_audit_writer):
        r = admin_client.put("/admin/alerts/budget-threshold", json={
            "enabled": False, "threshold_pct": 70,
        })
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "enabled": False, "threshold_pct": 70}
        mock_audit_writer.write.assert_called_once()

        r2 = admin_client.get("/admin/alerts/budget-threshold")
        assert r2.json()["threshold_pct"] == 70


class TestAlertsCustomRules:
    # GAP-CLOSED: GET/POST /admin/alerts/custom, GET/PUT/DELETE /admin/alerts/custom/{alert_id}
    def test_unauth_all_methods_401(self, unauth_client):
        assert unauth_client.get("/admin/alerts/custom").status_code == 401
        assert unauth_client.post("/admin/alerts/custom", json={}).status_code == 401
        assert unauth_client.get("/admin/alerts/custom/x").status_code == 401
        assert unauth_client.put("/admin/alerts/custom/x", json={}).status_code == 401
        assert unauth_client.delete("/admin/alerts/custom/x").status_code == 401

    def test_list_empty_default(self, admin_client, alert_config_reset):
        r = admin_client.get("/admin/alerts/custom")
        assert r.status_code == 200
        assert r.json() == {"count": 0, "custom_alerts": []}

    def test_get_unknown_404(self, admin_client, alert_config_reset):
        r = admin_client.get("/admin/alerts/custom/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "custom_alert_not_found"

    def test_full_crud_lifecycle(self, admin_client, alert_config_reset, mock_audit_writer):
        create_body = {
            "name": "high budget usage",
            "description": "fires when budget hot",
            "trigger_type": "budget_threshold",
            "condition": {"field": "budget_used_pct", "operator": "gte", "threshold": 90.0},
            "channels": [],
            "enabled": True,
            "cooldown_minutes": 30,
        }
        r = admin_client.post("/admin/alerts/custom", json=create_body)
        assert r.status_code == 201
        alert_id = r.json()["id"]
        assert r.json()["name"] == "high budget usage"

        r2 = admin_client.get("/admin/alerts/custom")
        assert r2.json()["count"] == 1

        r3 = admin_client.get(f"/admin/alerts/custom/{alert_id}")
        assert r3.status_code == 200
        assert r3.json()["cooldown_minutes"] == 30

        r4 = admin_client.put(f"/admin/alerts/custom/{alert_id}", json={"cooldown_minutes": 60})
        assert r4.status_code == 200
        assert r4.json()["cooldown_minutes"] == 60
        assert r4.json()["name"] == "high budget usage"  # untouched field preserved

        r5 = admin_client.delete(f"/admin/alerts/custom/{alert_id}")
        assert r5.status_code == 204

        r6 = admin_client.get(f"/admin/alerts/custom/{alert_id}")
        assert r6.status_code == 404

    def test_create_invalid_trigger_type_422(self, admin_client, alert_config_reset):
        r = admin_client.post("/admin/alerts/custom", json={
            "name": "x",
            "trigger_type": "not_a_real_trigger",
            "condition": {"field": "x", "operator": "gte", "threshold": 1},
        })
        assert r.status_code == 422

    def test_put_unknown_404(self, admin_client, alert_config_reset):
        r = admin_client.put("/admin/alerts/custom/does-not-exist", json={"enabled": False})
        assert r.status_code == 404

    def test_delete_unknown_404(self, admin_client, alert_config_reset):
        r = admin_client.delete("/admin/alerts/custom/does-not-exist")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# events.py — 1 endpoint
# ---------------------------------------------------------------------------


class TestEventsInspectionFeed:
    # GAP-CLOSED: GET /admin/events/inspection-feed
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/events/inspection-feed")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/events/inspection-feed")
        assert r.status_code == 403

    def test_admin_clears_gate_sse_headers(self, admin_client, monkeypatch):
        """Positive-path: clears the AdminSession auth gate and returns a real
        text/event-stream response.

        MOCKED: `_sse_generator` is stubbed to a single-yield generator.
        `_sse_generator` is architecturally infinite (15s heartbeat loop that
        only terminates on `request.is_disconnected()` — a real
        `client.stream(...)` + early-close round-trip against the live
        generator would hang the suite). The route itself (auth gate,
        StreamingResponse construction, header wiring) is exercised for real
        — only the inner infinite loop is stubbed."""
        import yashigani.backoffice.routes.events as events_routes

        async def _fake_sse_generator(_request):
            yield ": connected\n\n"

        monkeypatch.setattr(events_routes, "_sse_generator", _fake_sse_generator)
        r = admin_client.get("/admin/events/inspection-feed")
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/event-stream; charset=utf-8"
        # SPEC-CONFORMANCE (real divergence, harmless): the route itself sets
        # Cache-Control: no-cache (events.py:50), but app.py's global
        # `security_headers` middleware (ASVS 3.4 / ZAP 10015-10049
        # hardening) unconditionally overwrites Cache-Control to "no-store"
        # + adds Pragma: no-cache for every non-/static/ path, running AFTER
        # call_next. The delivered header is stricter than the route's own
        # documented value, never weaker — not a security bug, but the
        # route's own header is dead code in practice.
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["pragma"] == "no-cache"
        assert r.text == ": connected\n\n"


# ---------------------------------------------------------------------------
# cache.py — 4 endpoints. NEW coverage (no prior conformance test claimed
# this file — see module docstring).
# ---------------------------------------------------------------------------


class TestCacheList:
    # GAP-CLOSED: GET /admin/cache
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/cache").status_code == 401

    def test_admin_degrades_without_response_cache(self, admin_client):
        r = admin_client.get("/admin/cache")
        assert r.status_code == 200
        assert r.json() == {"tenants": [], "cache_available": False}

    def test_admin_with_response_cache_reads_same_redis_store_as_put(self, admin_client, cache_state):
        """YSG-RISK-143 CLOSED: with response_cache wired (rc is not None),
        GET /admin/cache now reads from the SAME store (Redis, via
        ResponseCache.list_tenant_configs()) that PUT/GET-one/DELETE
        already use — it no longer queries the disconnected, always-empty
        Postgres `cache_config` table. An empty ResponseCache genuinely has
        no configured tenants yet, so the list is empty (not because of a
        Postgres failure) — see the round-trip proof in
        TestCacheListVsSingleTenantSplitBackendFinding below and
        test_ysg_risk_143_admin_cache_store_split.py."""
        r = admin_client.get("/admin/cache")
        assert r.status_code == 200
        assert r.json() == {"tenants": [], "cache_available": True}


class TestCacheSingleTenant:
    # GAP-CLOSED: GET /admin/cache/{tenant_id}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/cache/tenant-1").status_code == 401

    def test_get_503_without_response_cache(self, admin_client):
        r = admin_client.get("/admin/cache/tenant-1")
        assert r.status_code == 503

    def test_get_default_config_with_store(self, admin_client, cache_state):
        r = admin_client.get("/admin/cache/tenant-1")
        assert r.status_code == 200
        assert r.json() == {"enabled": False, "ttl_seconds": 300}

    # GAP-CLOSED: PUT /admin/cache/{tenant_id}
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/cache/tenant-1", json={"enabled": True, "ttl_seconds": 60})
        assert r.status_code == 401

    def test_put_503_without_response_cache(self, admin_client):
        r = admin_client.put("/admin/cache/tenant-1", json={"enabled": True, "ttl_seconds": 60})
        assert r.status_code == 503

    def test_put_ttl_over_max_422(self, admin_client, cache_state):
        r = admin_client.put("/admin/cache/tenant-1", json={"enabled": True, "ttl_seconds": 999999})
        assert r.status_code == 422  # Field(le=3600)

    def test_put_success_persists_and_reads_back(self, admin_client, cache_state):
        r = admin_client.put("/admin/cache/tenant-1", json={"enabled": True, "ttl_seconds": 900})
        assert r.status_code == 200
        assert r.json() == {
            "status": "updated", "tenant_id": "tenant-1", "enabled": True, "ttl_seconds": 900,
        }
        # Genuine round-trip against the REAL ResponseCache + fakeredis.
        r2 = admin_client.get("/admin/cache/tenant-1")
        assert r2.json() == {"enabled": True, "ttl_seconds": 900}

    # GAP-CLOSED: DELETE /admin/cache/{tenant_id}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/cache/tenant-1").status_code == 401

    def test_delete_503_without_response_cache(self, admin_client):
        r = admin_client.delete("/admin/cache/tenant-1")
        assert r.status_code == 503

    def test_delete_zero_keys_when_nothing_cached(self, admin_client, cache_state):
        r = admin_client.delete("/admin/cache/tenant-1")
        assert r.status_code == 200
        assert r.json() == {"status": "invalidated", "tenant_id": "tenant-1", "keys_deleted": 0}

    def test_delete_evicts_real_cached_entries(self, admin_client, cache_state):
        """Genuine mutation proof: seeds a real cache entry via ResponseCache.set()
        (the same method the gateway's hot path calls), then proves DELETE
        actually evicts it from the real fakeredis-backed store."""
        rc = cache_state
        rc.set("tenant-1", b'{"q":"hi"}', b'{"a":"hello"}', ttl=60)
        # decode_responses=False client -> ResponseCache.get() returns raw bytes.
        assert rc.get("tenant-1", b'{"q":"hi"}') == b'{"a":"hello"}'


        r = admin_client.delete("/admin/cache/tenant-1")
        assert r.status_code == 200
        assert r.json()["keys_deleted"] == 1
        assert rc.get("tenant-1", b'{"q":"hi"}') is None


class TestCacheListVsSingleTenantSplitBackendFinding:
    """YSG-RISK-143 (HIGH) — CLOSED. GET /admin/cache (list) and
    {GET,PUT,DELETE} /admin/cache/{tenant_id} (single-tenant) present as
    ONE unified "tenant cache configuration" resource in the API surface,
    but were backed by TWO COMPLETELY SEPARATE persistence layers:
      - GET /admin/cache (list)         -> Postgres `cache_config` table
                                            (never written to by anything)
      - GET/PUT/DELETE .../{tenant_id}  -> Redis, via ResponseCache's
                                            rc:cfg:{tenant_id} hash key

    A config set via PUT was written to Redis but the list endpoint read
    an unrelated, permanently-empty Postgres table — a PUT'd config could
    never appear in the list. Fix: GET /admin/cache now reads from the
    SAME store (Redis, via the new ResponseCache.list_tenant_configs())
    that PUT/GET-one/DELETE already use — see
    test_ysg_risk_143_admin_cache_store_split.py."""

    def test_put_tenant_config_now_appears_in_list_view(self, admin_client, cache_state):
        """YSG-RISK-143 core regression: a config set via PUT MUST appear
        in the GET /admin/cache list — both read the same Redis-backed
        store now."""
        # 1. PUT genuinely persists (Redis side).
        r = admin_client.put("/admin/cache/acme-corp", json={"enabled": True, "ttl_seconds": 120})
        assert r.status_code == 200

        r2 = admin_client.get("/admin/cache/acme-corp")
        assert r2.json() == {"enabled": True, "ttl_seconds": 120}, (
            "PUT did not persist to the per-tenant store — re-verify the "
            "premise of this test before trusting the list-view assertion below."
        )

        # 2. The list view MUST now see it — both endpoints read Redis.
        r3 = admin_client.get("/admin/cache")
        assert r3.status_code == 200
        tenants = {t["tenant_id"]: t for t in r3.json()["tenants"]}
        assert "acme-corp" in tenants, (
            f"YSG-RISK-143 REGRESSION: PUT'd tenant 'acme-corp' did not "
            f"appear in GET /admin/cache list: {r3.json()['tenants']!r}"
        )
        assert tenants["acme-corp"]["enabled"] is True
        assert tenants["acme-corp"]["ttl_seconds"] == 120


# ---------------------------------------------------------------------------
# ratelimit.py — 7 endpoints
# ---------------------------------------------------------------------------


class TestRatelimitConfig:
    # GAP-CLOSED: GET /admin/ratelimit/config
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/config").status_code == 401

    def test_get_config_degraded_without_limiter(self, admin_client):
        r = admin_client.get("/admin/ratelimit/config")
        assert r.status_code == 200
        assert r.json() == {"configured": False}

    def test_get_config_with_limiter(self, admin_client, ratelimit_state):
        r = admin_client.get("/admin/ratelimit/config")
        assert r.status_code == 200
        assert r.json()["configured"] is True

    # GAP-CLOSED: PUT /admin/ratelimit/config
    def test_put_config_503_without_limiter(self, admin_client):
        r = admin_client.put("/admin/ratelimit/config", json={})
        assert r.status_code == 503

    def test_put_config_success(self, admin_client, ratelimit_state):
        r = admin_client.put("/admin/ratelimit/config", json={"global_rps": 2000.0})
        assert r.status_code == 200
        r2 = admin_client.get("/admin/ratelimit/config")
        assert r2.json()["global_rps"] == 2000.0

    def test_put_config_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/ratelimit/config", json={}).status_code == 401

    # GAP-CLOSED: GET /admin/ratelimit/status
    def test_status_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/status").status_code == 401

    def test_status_admin(self, admin_client, ratelimit_state):
        r = admin_client.get("/admin/ratelimit/status")
        assert r.status_code == 200

    # GAP-CLOSED: POST /admin/ratelimit/reset/{bucket_key}
    def test_reset_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/ratelimit/reset/some-key").status_code == 401

    def test_reset_rejects_non_ratelimit_key_422(self, admin_client, ratelimit_state):
        """SPEC-CONFORMANCE (allowlist validation): bucket_key must start
        with `yashigani:rl:` — this is a defence-in-depth allowlist
        preventing an admin-tier-confused-deputy from being used to delete
        arbitrary Redis keys (ratelimit.py:151)."""
        r = admin_client.post("/admin/ratelimit/reset/global")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_bucket_key"

    def test_reset_admin_valid_key(self, admin_client, ratelimit_state, mock_audit_writer):
        r = admin_client.post("/admin/ratelimit/reset/yashigani:rl:ip:deadbeef")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "bucket_key": "yashigani:rl:ip:deadbeef"}
        mock_audit_writer.write.assert_called_once()

    # GAP-CLOSED: GET/POST /admin/ratelimit/endpoints
    def test_endpoints_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/endpoints").status_code == 401

    def test_endpoints_list_degrades_empty_without_store(self, admin_client):
        r = admin_client.get("/admin/ratelimit/endpoints")
        assert r.status_code == 200
        assert r.json() == {"endpoints": []}

    def test_endpoints_list_admin(self, admin_client, endpoint_ratelimit_state):
        r = admin_client.get("/admin/ratelimit/endpoints")
        assert r.status_code == 200

    def test_endpoints_create_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 401

    def test_endpoints_create_503_without_store(self, admin_client):
        r = admin_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 503

    def test_endpoints_create_and_delete_lifecycle(self, admin_client, endpoint_ratelimit_state):
        r = admin_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 200
        ep_hash = r.json()["endpoint_hash"]

        r2 = admin_client.get("/admin/ratelimit/endpoints")
        assert len(r2.json()["endpoints"]) == 1

        r3 = admin_client.delete(f"/admin/ratelimit/endpoints/{ep_hash}")
        assert r3.status_code == 200

    # GAP-CLOSED: DELETE /admin/ratelimit/endpoints/{endpoint_hash}
    def test_endpoints_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/ratelimit/endpoints/deadbeef").status_code == 401

    def test_endpoints_delete_unknown_hash_is_idempotent_200(self, admin_client, endpoint_ratelimit_state):
        """SPEC-CONFORMANCE (divergence note): delete_config() is a bare
        Redis DEL with no existence check (endpoint_ratelimit.py:150) — the
        route returns 200 "deleted" even for an unknown hash, it never 404s.
        This is documented, idempotent-delete behaviour, not a bug."""
        r = admin_client.delete("/admin/ratelimit/endpoints/deadbeef")
        assert r.status_code == 200
        assert r.json() == {"status": "deleted", "endpoint_hash": "deadbeef"}

    def test_endpoints_delete_503_without_store(self, admin_client):
        r = admin_client.delete("/admin/ratelimit/endpoints/deadbeef")
        assert r.status_code == 503


class TestRatelimitResetBucketAuditCrashFinding:
    """YSG-RISK-149 (MEDIUM) — CLOSED. POST /admin/ratelimit/reset/{bucket_key}
    deleted the Redis bucket key FIRST, THEN did `assert state.audit_writer
    is not None` with NO try/except before writing the audit event. When
    audit_writer was unset, the assert raised, propagated unhandled (an
    AssertionError is stripped entirely under python -O), and the admin
    received an unhandled HTTP 500 — but the documented side effect (the
    rate-limit bucket reset) had ALREADY happened and was not rolled back.
    Fix: guard with `if state.audit_writer is not None:`; log a warning and
    skip the (non-critical) audit write when absent, but always return the
    2xx for the already-successful reset — see
    test_ysg_risk_149_ratelimit_reset_assert_crash.py."""

    def test_bucket_is_deleted_and_response_is_200_without_audit_writer(
        self, bo_app, session_store, caddy_headers, ratelimit_state,
    ):
        from fastapi.testclient import TestClient
        from yashigani.backoffice.state import backoffice_state

        assert backoffice_state.audit_writer is None, "test precondition"

        # Seed the bucket key so we can prove it existed before the call.
        ratelimit_state._redis.set("yashigani:rl:ip:deadbeef", "1")
        assert ratelimit_state._redis.exists("yashigani:rl:ip:deadbeef")

        session = session_store.create(
            account_id="conformance-admin-ratelimit-crash", account_tier="admin", client_ip="127.0.0.1",
        )
        client = TestClient(bo_app, headers=caddy_headers, raise_server_exceptions=False)
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)

        r = client.post("/admin/ratelimit/reset/yashigani:rl:ip:deadbeef")
        assert r.status_code == 200, (
            f"YSG-RISK-149 REGRESSION: expected 200 for a successful reset "
            f"with no audit_writer configured, got {r.status_code}: {r.text}"
        )
        assert r.json() == {"status": "ok", "bucket_key": "yashigani:rl:ip:deadbeef"}
        # The bucket reset genuinely happened — the response no longer lies
        # about the operation's outcome either way.
        assert not ratelimit_state._redis.exists("yashigani:rl:ip:deadbeef")


# ---------------------------------------------------------------------------
# backup.py — 3 endpoints
# ---------------------------------------------------------------------------


class TestBackupStatus:
    # GAP-CLOSED: GET /admin/backup/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/backup/status").status_code == 401

    def test_no_backups_dir_never_leaks_absolute_path(self, admin_client, monkeypatch, tmp_path):
        import yashigani.backoffice.routes.backup as backup_mod

        monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path / "does-not-exist", raising=False)
        r = admin_client.get("/admin/backup/status")
        assert r.status_code == 200
        assert r.json() == {"backups": [], "latest": None, "backups_dir": "backups"}

    def test_real_signed_backup_listed_no_absolute_path_leak(self, admin_client, backup_dir_state):
        _write_backup_dir(backup_dir_state, "install-001", sign=True)
        r = admin_client.get("/admin/backup/status")
        assert r.status_code == 200
        body = r.json()
        assert body["backups_dir"] == "backups"  # CWE-200: never str(_BACKUPS_DIR)
        assert str(backup_dir_state) not in r.text
        entry = body["backups"][0]
        assert entry["name"] == "install-001"
        assert entry["manifest_state"] == "signed"
        assert entry["type"] == "install"


class TestBackupVerify:
    # GAP-CLOSED: POST /admin/backup/verify
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/backup/verify", json={"backup_name": "x"})
        assert r.status_code == 401

    def test_invalid_name_traversal_attempt_422(self, admin_client, backup_dir_state):
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "../../etc/passwd"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_backup_name"

    def test_symlink_escape_rejected_422(self, admin_client, backup_dir_state, tmp_path):
        """Genuine defence-in-depth proof: a regex-valid backup_name that is a
        symlink resolving OUTSIDE backups_dir must be rejected (ASVS 9.2.1),
        not followed."""
        target = tmp_path / "outside_target"
        target.mkdir()
        (backup_dir_state / "escaped").symlink_to(target)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "escaped"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "path_traversal_rejected"

    def test_not_found_404(self, admin_client, backup_dir_state):
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "does-not-exist"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "backup_not_found"

    def test_real_signed_backup_ok(self, admin_client, backup_dir_state):
        """Genuine SHA-256 verification — real files, real hashlib, no mocks."""
        _write_backup_dir(backup_dir_state, "install-002", sign=True)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-002"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["manifest_state"] == "signed"
        assert body["mismatches"] == []

    def test_tampered_manifest_detected(self, admin_client, backup_dir_state):
        _write_backup_dir(backup_dir_state, "install-003", sign=True, tamper=True)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-003"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert any(m["issue"] == "checksum_mismatch" for m in body["mismatches"])

    def test_unsigned_backup_ok_with_warning_state(self, admin_client, backup_dir_state):
        d = backup_dir_state / "install-004"
        d.mkdir()
        (d / "some_file.bin").write_bytes(b"conformance-fake-data")
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-004"})
        body = r.json()
        assert r.status_code == 200
        assert body["ok"] is True
        assert body["manifest_state"] == "unsigned"

    def test_corrupt_manifest_state(self, admin_client, backup_dir_state):
        d = backup_dir_state / "install-005"
        d.mkdir()
        (d / "MANIFEST.sha256").write_text("deadbeef  bundle.enc\n")
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-005"})
        body = r.json()
        assert r.status_code == 200
        assert body["ok"] is False
        assert body["manifest_state"] == "corrupt"


class TestBackupCreate:
    # GAP-CLOSED: POST /admin/backup/create (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/backup/create").status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.post("/admin/backup/create")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_no_dsn_configured_503(self, stepup_admin_client, monkeypatch):
        for var in ("YASHIGANI_DB_DSN_ADMIN_DIRECT", "YASHIGANI_DB_DSN_DIRECT", "YASHIGANI_DB_DSN"):
            monkeypatch.delenv(var, raising=False)
        r = stepup_admin_client.post("/admin/backup/create")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "db_dsn_unavailable"

    def test_pg_dump_unavailable_503(self, stepup_admin_client, monkeypatch):
        """pg_dump is genuinely absent from this offline conformance venv —
        shutil.which is monkeypatched to guarantee this holds deterministically
        on any box, not relying on the ambient environment."""
        monkeypatch.setenv("YASHIGANI_DB_DSN_DIRECT", "postgresql://fake-conformance-test/db")
        monkeypatch.setattr("shutil.which", lambda _cmd: None)
        r = stepup_admin_client.post("/admin/backup/create")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "pg_dump_unavailable"


# ---------------------------------------------------------------------------
# manifest_history.py — 3 endpoints
# ---------------------------------------------------------------------------


class TestManifestRegistrationsList:
    # GAP-CLOSED: GET /admin/manifest-registrations
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/manifest-registrations").status_code == 401

    def test_no_pool_returns_500_not_503_SPEC_DIVERGENCE(self, bo_app, session_store, caddy_headers):
        """SPEC-CONFORMANCE DIVERGENCE (manifest_history.py:48-56): `_get_pool()`
        checks `if pool is None: raise HTTPException(503, database_unavailable)`,
        but the underlying `yashigani.db.get_pool()` (postgres.py:177-180) itself
        raises RuntimeError when the pool is uninitialised — it NEVER returns
        None. The `if pool is None` branch is therefore dead code; the actual,
        observable behaviour offline (and in any deployment where the DB pool
        genuinely failed to initialise) is an unhandled RuntimeError caught by
        the app's generic Exception handler, producing HTTP 500
        {"error": "internal_error"} — NOT the documented 503.

        Uses a LOCAL TestClient(raise_server_exceptions=False) rather than the
        shared admin_client fixture — see TestAuditHardCrashWithoutWriterFinding
        for why."""
        from fastapi.testclient import TestClient

        session = session_store.create(
            account_id="conformance-admin-divergence", account_tier="admin", client_ip="127.0.0.1"
        )
        with TestClient(bo_app, headers=caddy_headers, raise_server_exceptions=False) as client:
            client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
            r = client.get("/admin/manifest-registrations")
            assert r.status_code == 500
            assert r.json()["error"] == "internal_error"

    def test_real_pool_empty_list(self, admin_client, manifest_pool_state):
        r = admin_client.get("/admin/manifest-registrations")
        assert r.status_code == 200
        body = r.json()
        assert body == {"items": [], "total": 0, "limit": 50, "offset": 0}

    def test_real_pool_lists_registered_record(self, admin_client, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        stepup_admin_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        r = admin_client.get("/admin/manifest-registrations")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["agent_id"] == "conformance-agent"
        assert item["has_signature_provenance"] is True


class TestManifestRegistrationDetail:
    # GAP-CLOSED: GET /admin/manifest-registrations/{record_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/manifest-registrations/1").status_code == 401

    def test_not_found_404(self, admin_client, manifest_pool_state):
        r = admin_client.get("/admin/manifest-registrations/999")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "record_not_found"

    def test_real_pool_returns_full_detail(self, admin_client, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        create = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony", json=_ceremony_body()
        )
        record_id = create.json()["manifest_registration_id"]
        r = admin_client.get(f"/admin/manifest-registrations/{record_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["agent_id"] == "conformance-agent"
        assert body["manifest_yaml_blob"] == "name: conformance-agent\nupstream: http://x\n"
        assert body["signature_provenance"]["alg"] == "ed25519"


class TestManifestRegistrationCeremony:
    # GAP-CLOSED: POST /admin/manifest-registrations/ceremony (step-up required)
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, manifest_pool_state):
        r = admin_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_ack_not_y_rejected_422(self, stepup_admin_client, manifest_pool_state):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony",
            json=_ceremony_body(ack_response="N"),
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ceremony_ack_required"

    def test_sha256_mismatch_rejected_422(self, stepup_admin_client, manifest_pool_state):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony",
            json=_ceremony_body(manifest_sha256="0" * 64),
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "manifest_sha256_mismatch"

    def test_real_pool_ceremony_success(self, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony", json=_ceremony_body()
        )
        assert r.status_code == 201
        body = r.json()
        assert body["manifest_registration_id"] == 1
        assert body["audit_event_id"]
        mock_audit_writer.write.assert_called_once()
        from yashigani.audit.schema import ManifestCeremonyEvent

        event = mock_audit_writer.write.call_args[0][0]
        assert isinstance(event, ManifestCeremonyEvent)


# ---------------------------------------------------------------------------
# crypto_inventory.py — 1 endpoint
# ---------------------------------------------------------------------------


class TestCryptoInventory:
    # GAP-CLOSED: GET /admin/crypto/inventory
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/crypto/inventory").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/crypto/inventory")
        assert r.status_code == 403

    def test_admin_200_shape_and_content(self, admin_client):
        r = admin_client.get("/admin/crypto/inventory")
        assert r.status_code == 200
        body = r.json()
        for key in ("algorithms", "deprecated", "post_quantum", "compliance",
                    "fips_mode_active", "cmvp_cert"):
            assert key in body
        algo_names = {a["name"] for a in body["algorithms"]}
        # PKI-002 (2026-07-02): stale HMAC-SHA-1 TOTP entry must remain removed.
        assert not any("SHA-1" in name or "SHA1" in name for name in algo_names)
        assert "HMAC-SHA-256" in algo_names
        assert "HMAC-SHA-512" in algo_names

    def test_fips_attestation_reflects_module_load_env(self, admin_client, monkeypatch):
        """FIPS attestation fields are set at MODULE LOAD time from env vars
        (crypto_inventory.py docstring, 2026-05-27 note) — monkeypatching the
        module-level globals directly (rather than the env var + a reload)
        exercises the exact runtime read path the route performs."""
        import yashigani.backoffice.routes.crypto_inventory as ci

        monkeypatch.setattr(ci, "_FIPS_MODE_ACTIVE", True, raising=False)
        monkeypatch.setattr(ci, "_CMVP_CERT", "#4985", raising=False)
        r = admin_client.get("/admin/crypto/inventory")
        assert r.status_code == 200
        body = r.json()
        assert body["fips_mode_active"] is True
        assert body["cmvp_cert"] == "#4985"

    def test_fips_attestation_default_off(self, admin_client, monkeypatch):
        import yashigani.backoffice.routes.crypto_inventory as ci

        monkeypatch.setattr(ci, "_FIPS_MODE_ACTIVE", False, raising=False)
        monkeypatch.setattr(ci, "_CMVP_CERT", None, raising=False)
        r = admin_client.get("/admin/crypto/inventory")
        body = r.json()
        assert body["fips_mode_active"] is False
        assert body["cmvp_cert"] is None


# ---------------------------------------------------------------------------
# version_check.py — 1 endpoint
# ---------------------------------------------------------------------------


class TestVersionCheck:
    # GAP-CLOSED: GET /admin/version
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/version").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/version").status_code == 403

    def test_disabled_by_default(self, admin_client, monkeypatch):
        monkeypatch.delenv("YASHIGANI_VERSION_CHECK_ENABLED", raising=False)
        r = admin_client.get("/admin/version")
        assert r.status_code == 200
        body = r.json()
        assert body["check_enabled"] is False
        assert body["check_skipped"] is True
        assert body["latest_version"] is None

    def test_enabled_network_error_degrades_gracefully(self, admin_client, monkeypatch):
        """Offline-safe: monkeypatch _fetch_latest_release() to raise, rather
        than depend on real network reachability to api.github.com — proves
        the documented graceful-degrade contract (check_skipped=true,
        reason=network_error), never a 500."""
        monkeypatch.setenv("YASHIGANI_VERSION_CHECK_ENABLED", "true")

        async def _raise(*_a, **_kw):
            raise httpx.ConnectError("no network in offline conformance suite")

        monkeypatch.setattr(
            "yashigani.backoffice.routes.version_check._fetch_latest_release", _raise
        )
        r = admin_client.get("/admin/version")
        assert r.status_code == 200
        body = r.json()
        assert body["check_skipped"] is True
        assert body["skip_reason"] is not None
        assert body["update_available"] is None

    def test_enabled_classifies_update_type(self, admin_client, monkeypatch):
        monkeypatch.setenv("YASHIGANI_VERSION_CHECK_ENABLED", "true")

        async def _fake_release(*_a, **_kw):
            return {
                "tag_name": "v99.0.0",
                "is_security": False,
                "html_url": "https://example.invalid/releases/v99.0.0",
                "published_at": "2026-07-23T00:00:00Z",
            }

        monkeypatch.setattr(
            "yashigani.backoffice.routes.version_check._fetch_latest_release", _fake_release
        )
        r = admin_client.get("/admin/version")
        assert r.status_code == 200
        body = r.json()
        assert body["check_skipped"] is False
        assert body["update_available"] is True
        assert body["update_type"] == "major"
        assert body["latest_version"] == "99.0.0"


# ---------------------------------------------------------------------------
# hibp.py — 3 endpoints
# ---------------------------------------------------------------------------


class TestHibpStatus:
    # GAP-CLOSED: GET /api/v1/admin/auth/hibp/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/api/v1/admin/auth/hibp/status").status_code == 401

    def test_store_unavailable_503(self, admin_client):
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "settings_store_unavailable"

    def test_not_configured(self, admin_client, hibp_store_state, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is False
        assert body["source"] == "none"
        assert body["masked_value"] is None

    def test_configured_masks_full_key(self, admin_client, hibp_store_state, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        secret = "conformance-fake-hibp-key-0000000000"
        hibp_store_state._settings["hibp_api_key"] = secret
        hibp_store_state._meta["hibp_api_key"] = {"updated_at": None, "updated_by": "admin1"}
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is True
        assert body["source"] == "admin_panel"
        assert secret not in r.text


class TestHibpSetKey:
    # GAP-CLOSED: PUT /api/v1/admin/auth/hibp/key (step-up required)
    def test_unauth_401(self, unauth_client):
        r = unauth_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": "x" * 10})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, hibp_store_state):
        r = admin_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": "x" * 10})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_format_422(self, stepup_admin_client, hibp_store_state):
        r = stepup_admin_client.put(
            "/api/v1/admin/auth/hibp/key", json={"api_key": "bad key with spaces!"}
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_key_format"

    def test_real_round_trip_never_leaks_full_key(
        self, stepup_admin_client, hibp_store_state, mock_audit_writer
    ):
        secret = "conformance-fake-hibp-put-00000000"
        r = stepup_admin_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": secret})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["hibp_key"]["configured"] is True
        assert secret not in r.text
        assert hibp_store_state._settings["hibp_api_key"] == secret  # genuine persistence
        mock_audit_writer.write.assert_called_once()


class TestHibpClearKey:
    # GAP-CLOSED: DELETE /api/v1/admin/auth/hibp/key (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/api/v1/admin/auth/hibp/key").status_code == 401

    def test_admin_without_stepup_401(self, admin_client, hibp_store_state):
        r = admin_client.delete("/api/v1/admin/auth/hibp/key")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_real_clear(self, stepup_admin_client, hibp_store_state, mock_audit_writer):
        hibp_store_state._settings["hibp_api_key"] = "conformance-fake-existing-key-000"
        r = stepup_admin_client.delete("/api/v1/admin/auth/hibp/key")
        assert r.status_code == 200
        body = r.json()
        assert body["hibp_key"]["configured"] is False
        assert hibp_store_state._settings["hibp_api_key"] == ""
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# csp_report.py — 2 routes (SAME router object mounted TWICE, see
# TestCspReportDualMount)
# ---------------------------------------------------------------------------


class TestCspReport:
    # GAP-CLOSED: POST /admin/csp-report
    def test_valid_report_204_no_auth_required(self, unauth_client):
        """SPEC-CONFORMANCE (documented, deliberate): this endpoint carries no
        AdminSession dependency (csp_report.py:17-18) — browsers POST CSP
        violation reports automatically and cannot attach cookies/CSRF
        tokens, so authentication is intentionally absent."""
        r = unauth_client.post(
            "/admin/csp-report",
            json={"csp-report": {
                "blocked-uri": "https://evil.example.com/x.js",
                "violated-directive": "script-src",
                "document-uri": "https://app.example.com/dashboard",
            }},
        )
        assert r.status_code == 204
        assert r.content == b""

    def test_malformed_json_still_204(self, unauth_client):
        """Documented fail-safe: malformed body is logged and discarded, never
        surfaced as a 4xx/5xx to the reporting browser (csp_report.py:24-29)."""
        r = unauth_client.post(
            "/admin/csp-report",
            content=b"not json at all",
            headers={"Content-Type": "application/csp-report"},
        )
        assert r.status_code == 204

    def test_bare_report_without_wrapper_204(self, unauth_client):
        """Body without the standard `csp-report` wrapper key is still
        accepted (report = body.get("csp-report", body) — csp_report.py:32)."""
        r = unauth_client.post(
            "/admin/csp-report",
            json={"blocked-uri": "https://evil.example.com/x.js"},
        )
        assert r.status_code == 204

    def test_get_method_not_allowed_405(self, unauth_client):
        r = unauth_client.get("/admin/csp-report")
        assert r.status_code == 405


class TestCspReportDualMount:
    """SPEC-CONFORMANCE (documented, deliberate — verified directly against
    app.py, NOT a finding): csp_report.py defines exactly ONE router with ONE
    route (`POST /csp-report`), but app.py `include_router()`s the SAME
    router object TWICE under different prefixes:
      - prefix="/admin"   (tags=["csp"])       -> POST /admin/csp-report
      - prefix="/api/v1"  (tags=["csp"], the
        `_user_csp_report_router` alias)       -> POST /api/v1/csp-report
    Both paths reach the identical handler with identical (absent)
    auth requirements — this is intentional dual-surface exposure (the
    admin-console CSP policy and the user-console CSP policy report to the
    same collector via their respective base paths), not a routing bug.
    Confirmed both paths behave identically."""

    def test_api_v1_path_also_reachable_no_auth(self, unauth_client):
        r = unauth_client.post(
            "/api/v1/csp-report",
            json={"csp-report": {"blocked-uri": "https://evil.example.com/y.js"}},
        )
        assert r.status_code == 204
        assert r.content == b""

    def test_both_mounts_share_the_same_handler_object(self, declared_routes):
        # `declared_routes` fixture (conftest.py) already walks _IncludedRouter
        # correctly — cross-test-file `from conftest import ...` is
        # unreliable per conftest.py's own docstring, use the fixture instead.
        admin_mount = None
        api_v1_mount = None
        for _method, path, route in declared_routes:
            if path == "/admin/csp-report":
                admin_mount = route
            elif path == "/api/v1/csp-report":
                api_v1_mount = route
        assert admin_mount is not None and api_v1_mount is not None
        assert admin_mount.endpoint is api_v1_mount.endpoint, (
            "Both mounts should share the exact same handler function object "
            "(same router, included twice) — if this ever fails, the two "
            "mounts have diverged (e.g. one was forked) and this test's "
            "'not a bug, deliberate' framing needs re-examination."
        )
