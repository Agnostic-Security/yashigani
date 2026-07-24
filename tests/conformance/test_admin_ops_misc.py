"""
Conformance group: ADMIN-OPS-MISC.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/services.py         (2 endpoints)  — /admin/services*
  routes/dashboard.py        (8 endpoints)  — /dashboard/*
  routes/version_check.py    (1 endpoint)   — /admin/version
  routes/cloud_override.py   (4 endpoints)  — /admin/cloud-override/*
  routes/runtime_settings.py (4 endpoints)  — /admin/runtime-settings*
  routes/alerts.py           (10 endpoints) — /admin/alerts/*
  routes/admin_workflows.py  (4 endpoints)  — /admin/workflows/*
  routes/mcp_servers.py      (3 endpoints)  — /admin/mcp/servers/*
Total: 36 endpoints (Lu matrix rows 283-284, 128-135, 348, 122-125, 261-264,
42-51, 21-24, 188-190 — corrected against the live route walk in
test_group_covers_all_declared_routes below, the authoritative count).

Convention: see tests/conformance/conftest.py module docstring.

Highest-value assertions in this group (per dispatch brief):
  - cloud_override.py: dual-admin (maker-checker) propose/approve. Verified
    a REAL, working control — CloudLlmOverrideManager.approve() rejects a
    same-admin self-approval (409 approval_failed, ApprovalError raised
    inside optimization/cloud_override.py:181-183) and rejects a mismatched
    confirming_fingerprint (SOD-1 swap-attack guard). This is NOT a bypass
    finding — the two-person control is genuinely enforced by the manager
    itself, independent of the route layer.
  - admin_workflows.py: cross-user oversight (admin CAN read/list/disable
    ANY user's workflow — by design, no BOLA scope) contrasted against a
    non-admin (`user_client`) being flatly rejected (403 insufficient_tier)
    from the entire admin surface. Both properties verified with genuine
    fakeredis-backed Redis DB3/DB6 wiring (real WorkflowSpec/WorkflowRun
    (de)serialisation code from yashigani.gateway.workflow_scheduler, not a
    duck-typed fake).

Fixtures NOT promoted to conftest.py (own-file-only edits per dispatch brief)
that would be worth promoting if another group needs them:
  - `second_stepup_admin_client` (a second, distinct admin-tier session with
    a fresh step-up — needed for any dual-admin/maker-checker control, not
    just cloud_override; mirrors conftest's `second_user_client` pattern for
    the admin tier).
  - `deny_all_dns` (deterministic, offline-safe socket.getaddrinfo() stub for
    exercising yashigani.alerts._url_guard's real DNS-resolution-failure
    rejection path without any real network call).

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock

import fakeredis
import httpx
import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/services",
    "/dashboard",
    "/admin/version",
    "/admin/cloud-override",
    "/admin/runtime-settings",
    "/admin/alerts",
    "/admin/workflows",
    "/admin/mcp/servers",
)

# Same hardcoded cookie name conftest.py uses — duplicated here rather than
# imported (cross-test-file `from conftest import X` is unreliable, see
# conftest.py's own docstring on this).
_ADMIN_SESSION_COOKIE = "__Host-yashigani_admin_session"


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 36, (
        f"Expected 36 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# Group-specific fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def second_stepup_admin_client(bo_app, session_store, caddy_headers):
    """A SECOND, distinct admin-tier session with a fresh step-up recorded.

    cloud_override.py's dual-admin propose/approve control needs TWO
    different admin identities in the same test — admin_client/
    stepup_admin_client alone only ever supply ONE. Mirrors conftest.py's
    second_user_client (BOLA cross-identity) pattern, for the admin tier +
    step-up TOTP.
    """
    from fastapi.testclient import TestClient

    session = session_store.create(
        account_id="conformance-admin2", account_tier="admin", client_ip="127.0.0.1"
    )
    session_store.record_totp_stepup(session.token)
    with TestClient(bo_app, headers=caddy_headers) as client:
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def cloud_override_state(fake_redis_client, mock_audit_writer, monkeypatch):
    """Wires the REAL CloudLlmOverrideManager (accepts redis_client directly
    per src/yashigani/optimization/cloud_override.py:100) against fakeredis —
    the dual-admin SOD-1/SOD-2 logic under test lives entirely inside this
    class, not the route, so wiring the real class is what makes the
    maker-checker assertions genuine rather than theatre."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.optimization.cloud_override import CloudLlmOverrideManager

    mgr = CloudLlmOverrideManager(redis_client=fake_redis_client, audit_writer=mock_audit_writer)
    monkeypatch.setattr(backoffice_state, "cloud_override_manager", mgr, raising=False)
    return mgr


class FakeRuntimeSettingsService:
    """MOCKED: RuntimeSettingsService (src/yashigani/runtime_settings/service.py)
    is asyncpg-pool-backed with no fakeredis-injectable constructor path (its
    __init__ takes `pool` — an asyncpg pool — not a redis_client). This fake
    implements exactly the 4 methods runtime_settings.py's routes call:
    list_all(), get_one(), set(), reset_to_default() — in-memory, seeded from
    the REAL KNOWN_SETTINGS class defaults so key/type/default assertions are
    genuine, only the persistence layer is faked."""

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
    custom_alert_rules, budget_threshold_alert_config. monkeypatch snapshots
    the value at fixture-setup time and restores it at teardown REGARDLESS of
    what the route handler mutates it to during the test — this is what
    keeps this group's CRUD tests isolated from each other and from
    dashboard.py's budget-summary read of the same attributes."""
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


@pytest.fixture
def clean_alert_buffer():
    from yashigani.backoffice.routes import dashboard as dashboard_routes

    dashboard_routes._alert_buffer.clear()
    yield dashboard_routes._alert_buffer
    dashboard_routes._alert_buffer.clear()


class _FakeOllamaClassifier:
    """MOCKED: duck-typed stand-in for the Ollama-backed classifier object
    dashboard.py reads (._model, .available_models()) — see
    test_budget_models_inspection.py's FakeOllamaClassifier for the identical
    established pattern (not imported cross-file per conftest.py's own
    warning about unreliable cross-test-file imports)."""

    def __init__(self) -> None:
        self._model = "qwen2.5:3b"

    def available_models(self) -> list[str]:
        return ["qwen2.5:3b"]


class _FakeInspectionPipeline:
    def __init__(self) -> None:
        self._classifier = _FakeOllamaClassifier()


class _FakeRotationScheduler:
    _scheduler = object()
    _cron_expr = "0 3 * * *"


class _FakeSiemTarget:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled


@pytest.fixture
def dashboard_all_wired(monkeypatch, mock_audit_writer):
    """Wires every optional subsystem dashboard.py's /health and
    /services-health endpoints read so the "all healthy" rollup path is
    exercised (not just the None-default degrade paths), while keeping the
    suite fully offline: opa_url is set to "" (not_configured — a status
    compute_health_rollup() treats as healthy) rather than left at its real
    default (which would fire a genuine 3s network attempt to a
    non-existent https://policy:8181 — the local_inventory-style "real
    network call, real timeout" pattern is deliberately AVOIDED here since it
    would only slow this group's iteration loop for no additional coverage:
    the opa-unreachable branch is already exercised by the state-store test
    of the SAME code below with opa_url left at its real default)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.chs.resource_monitor import ResourceMetrics

    kms = MagicMock()
    kms.health_check.return_value = True
    kms.provider_name = "test-kms"
    monkeypatch.setattr(backoffice_state, "kms_provider", kms, raising=False)

    monkeypatch.setattr(
        backoffice_state, "rotation_scheduler", _FakeRotationScheduler(), raising=False
    )

    inspection = _FakeInspectionPipeline()
    monkeypatch.setattr(backoffice_state, "inspection_pipeline", inspection, raising=False)

    rm = MagicMock()
    rm.get_metrics.return_value = ResourceMetrics(
        memory_pressure=0.1,
        cpu_throttle=0.05,
        pressure_index=0.09,
        memory_used_bytes=1000,
        memory_max_bytes=10000,
        ttl_tier="low",
        sampled_at=datetime.now(tz=UTC),
    )
    monkeypatch.setattr(backoffice_state, "resource_monitor", rm, raising=False)

    mock_audit_writer._log_path = Path("/nonexistent-yashigani-conformance-dir/audit.log")
    mock_audit_writer._siem_targets = [_FakeSiemTarget(True), _FakeSiemTarget(False)]

    auth_svc = AsyncMock()
    auth_svc.total_admin_count.return_value = 3
    auth_svc.active_admin_count.return_value = 3
    monkeypatch.setattr(backoffice_state, "auth_service", auth_svc, raising=False)

    monkeypatch.setattr(backoffice_state, "opa_url", "", raising=False)

    return {"kms": kms, "resource_monitor": rm, "auth_service": auth_svc}


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
# dashboard.py — 8 endpoints
# ---------------------------------------------------------------------------


class TestDashboardHealth:
    # GAP-CLOSED: GET /dashboard/health
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/health").status_code == 401

    def test_admin_defaults_degrade_to_critical(self, admin_client):
        """Real, non-stubbed assertion: with every optional subsystem at its
        default None (no audit_writer, no auth_service configured beyond the
        session_store the admin_client fixture itself wires), the documented
        fail-closed contract is overall status "critical" — components.audit
        and components.auth both force `_degrade(overall, "critical")`
        (dashboard.py:159,178). This is the genuine offline-default
        behaviour, not a softened assertion."""
        r = admin_client.get("/dashboard/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "critical"
        assert body["components"]["audit"]["status"] == "not_configured"
        assert body["components"]["auth"]["status"] == "critical"
        assert body["components"]["session_store"]["status"] == "ok"

    def test_admin_all_wired_is_ok(self, admin_client, dashboard_all_wired):
        r = admin_client.get("/dashboard/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["components"]["kms"]["status"] == "ok"
        assert body["components"]["inspection"]["status"] == "ok"
        assert body["components"]["auth"]["status"] == "ok"
        assert body["components"]["audit"]["status"] == "ok"


class TestDashboardResources:
    # GAP-CLOSED: GET /dashboard/resources
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/resources").status_code == 401

    def test_503_without_monitor(self, admin_client):
        r = admin_client.get("/dashboard/resources")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "resource_monitor_not_configured"

    def test_200_with_monitor(self, admin_client, dashboard_all_wired):
        r = admin_client.get("/dashboard/resources")
        assert r.status_code == 200
        body = r.json()
        assert body["ttl_tier"] == "low"
        assert body["memory_used_bytes"] == 1000


class TestDashboardSodConflicts:
    # GAP-CLOSED: GET /dashboard/sod-conflicts
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/sod-conflicts").status_code == 401

    def test_admin_default_no_run_yet(self, admin_client):
        r = admin_client.get("/dashboard/sod-conflicts")
        assert r.status_code == 200
        body = r.json()
        assert "conflict_count" in body and "conflicts" in body


class TestDashboardAlerts:
    # GAP-CLOSED: GET /dashboard/alerts
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/alerts").status_code == 401

    def test_invalid_limit_422(self, admin_client):
        r = admin_client.get("/dashboard/alerts", params={"limit": 0})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_limit"

        r2 = admin_client.get("/dashboard/alerts", params={"limit": 500})
        assert r2.status_code == 422

    def test_admin_reads_recorded_alert(self, admin_client, clean_alert_buffer):
        from yashigani.backoffice.routes.dashboard import record_admin_alert

        record_admin_alert({"priority": "P2", "message": "conformance test alert"})
        r = admin_client.get("/dashboard/alerts")
        assert r.status_code == 200
        body = r.json()
        assert body["total_in_buffer"] == 1
        assert body["alerts"][0]["priority"] == "P2"
        assert "received_at" in body["alerts"][0]


class TestDashboardServicesHealth:
    # GAP-CLOSED: GET /dashboard/services-health
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/services-health").status_code == 401

    def test_admin_defaults_criticality_weighted_rollup(self, admin_client):
        """Real default-state assertion: gateway/ollama are not_configured
        (inspection_pipeline is None by default) — not_configured counts as
        healthy for rollup purposes (compute_health_rollup docstring), so the
        rollup should be "ok" purely from caddy/backoffice reachability plus
        not_configured subsystems, UNLESS postgres/redis are critical."""
        r = admin_client.get("/dashboard/services-health")
        assert r.status_code == 200
        body = r.json()
        by_name = {s["name"]: s for s in body["services"]}
        assert by_name["caddy"]["criticality"] is True
        assert by_name["gateway"]["status"] == "not_configured"
        assert by_name["redis"]["status"] == "ok"  # session_store wired by admin_client

    def test_admin_all_wired_is_ok_rollup(self, admin_client, dashboard_all_wired):
        r = admin_client.get("/dashboard/services-health")
        assert r.status_code == 200
        body = r.json()
        assert body["rollup"] == "ok"
        by_name = {s["name"]: s for s in body["services"]}
        assert by_name["gateway"]["status"] == "ok"
        assert by_name["postgres"]["status"] == "ok"

    def test_compute_health_rollup_pure_function(self):
        """compute_health_rollup() is documented as pure/I-O-free and
        explicitly invited to be unit-tested in isolation (dashboard.py:282)."""
        from yashigani.backoffice.routes.dashboard import compute_health_rollup

        assert compute_health_rollup([]) == "ok"
        assert compute_health_rollup([{"status": "ok", "criticality": True}]) == "ok"
        assert compute_health_rollup(
            [{"status": "degraded", "criticality": False}]
        ) == "degraded"
        assert compute_health_rollup(
            [{"status": "critical", "criticality": True}]
        ) == "critical"
        # A non-critical failure must NOT escalate to "critical".
        assert compute_health_rollup(
            [{"status": "critical", "criticality": False}]
        ) == "degraded"


class TestDashboardSecurityMetrics:
    # GAP-CLOSED: GET /dashboard/security-metrics
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/security-metrics").status_code == 401

    def test_admin_shape(self, admin_client, clean_alert_buffer):
        from yashigani.backoffice.routes.dashboard import record_admin_alert

        record_admin_alert({"priority": "P3"})
        r = admin_client.get("/dashboard/security-metrics")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body["opa_blocks_total"], int)
        assert isinstance(body["sensitivity_detections"], dict)
        assert body["recent_alerts_by_priority"]["P3"] >= 1
        assert body["alert_buffer_size"] == 1


class TestDashboardTrafficMetrics:
    # GAP-CLOSED: GET /dashboard/traffic-metrics
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/traffic-metrics").status_code == 401

    def test_admin_shape(self, admin_client, clean_alert_buffer):
        from yashigani.backoffice.routes.dashboard import record_admin_alert

        record_admin_alert({"priority": "P1", "message": "traffic conformance"})
        r = admin_client.get("/dashboard/traffic-metrics")
        assert r.status_code == 200
        body = r.json()
        for key in ("gateway_requests_total", "agent_calls_total",
                    "inspection_requests_total", "ratelimit_violations_total"):
            assert isinstance(body[key], int)
        assert len(body["recent_audit_events"]) == 1


class TestDashboardBudgetSummary:
    # GAP-CLOSED: GET /dashboard/budget-summary
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/dashboard/budget-summary").status_code == 401

    def test_admin_degrades_to_zero_counts_without_store(self, admin_client, alert_config_reset):
        r = admin_client.get("/dashboard/budget-summary")
        assert r.status_code == 200
        body = r.json()
        assert body["org_caps_count"] == 0
        assert body["group_budgets_count"] == 0
        assert body["individual_budgets_count"] == 0
        assert body["budget_threshold_pct"] == 85  # R17 default
        assert body["threshold_alert_enabled"] is True
        assert "cloud" in body["tokens_by_route"]


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
        than depend on real network reachability to api.github.com (which is
        unavailable/undesirable in this offline suite) — proves the
        documented graceful-degrade contract (check_skipped=true,
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
# cloud_override.py — 4 endpoints. HIGHEST PRIORITY: dual-admin maker-checker.
# ---------------------------------------------------------------------------


class TestCloudOverrideStatus:
    # GAP-CLOSED: GET /admin/cloud-override/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/cloud-override/status").status_code == 401

    def test_admin_503_without_manager(self, admin_client):
        r = admin_client.get("/admin/cloud-override/status")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "cloud_override_unavailable"

    def test_admin_inactive_with_manager(self, admin_client, cloud_override_state):
        r = admin_client.get("/admin/cloud-override/status")
        assert r.status_code == 200
        assert r.json() == {"status": "INACTIVE"}


class TestCloudOverrideProposeApprove:
    # GAP-CLOSED: POST /admin/cloud-override/propose
    def test_propose_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude", "justification": "test",
        })
        assert r.status_code == 401

    def test_propose_requires_stepup(self, admin_client, cloud_override_state):
        r = admin_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude", "justification": "test",
        })
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_propose_blank_provider_400(self, stepup_admin_client, cloud_override_state):
        """Whitespace-only provider passes Pydantic's min_length=1 but fails
        the manager's own .strip() check (cloud_override.py:104) — the ONE
        manager-level CloudOverrideError branch reachable past Pydantic
        validation."""
        r = stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": " ", "model": "claude", "justification": "ticket-123",
        })
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_proposal"

    def test_propose_success_returns_fingerprint(self, stepup_admin_client, cloud_override_state):
        r = stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude-3", "justification": "contract #123",
            "ttl_hours": 4,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "pending_approval"
        assert body["state"]["status"] == "PENDING_APPROVAL"
        assert "proposal_fingerprint" in body["state"]

    # GAP-CLOSED: POST /admin/cloud-override/approve
    def test_approve_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/cloud-override/approve", json={"confirming_fingerprint": "x"})
        assert r.status_code == 401

    def test_approve_requires_stepup(self, admin_client, cloud_override_state):
        r = admin_client.post("/admin/cloud-override/approve", json={"confirming_fingerprint": "x"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_MAKER_CHECKER_same_admin_self_approve_is_rejected(
        self, stepup_admin_client, cloud_override_state,
    ):
        """SECURITY FINDING ASSESSMENT (maker-checker / dual-admin control):
        the SAME admin who proposed the override attempts to approve it with
        the CORRECT fingerprint. Real CloudLlmOverrideManager.approve()
        (optimization/cloud_override.py:181-183) rejects this with
        ApprovalError("approver must be a DIFFERENT admin") -> HTTP 409.
        RESULT: the control IS genuinely enforced — this is NOT a bypass."""
        propose_r = stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude-3", "justification": "contract #1",
        })
        fingerprint = propose_r.json()["state"]["proposal_fingerprint"]

        approve_r = stepup_admin_client.post("/admin/cloud-override/approve", json={
            "confirming_fingerprint": fingerprint,
        })
        assert approve_r.status_code == 409
        assert approve_r.json()["detail"]["error"] == "approval_failed"

    def test_MAKER_CHECKER_two_distinct_admins_succeeds(
        self, stepup_admin_client, second_stepup_admin_client, cloud_override_state,
    ):
        """Positive dual-admin path: admin1 proposes, a DIFFERENT admin2
        approves with the correct fingerprint -> 200 ACTIVE. Proves the
        control is usable, not just restrictive."""
        propose_r = stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": "openai", "model": "gpt-4", "justification": "CEO approved via email",
        })
        fingerprint = propose_r.json()["state"]["proposal_fingerprint"]

        approve_r = second_stepup_admin_client.post("/admin/cloud-override/approve", json={
            "confirming_fingerprint": fingerprint,
        })
        assert approve_r.status_code == 200
        body = approve_r.json()
        assert body["status"] == "active"
        assert body["state"]["approver"] == "conformance-admin2"
        assert body["state"]["initiated_by"] == "conformance-admin-stepup"

    def test_MAKER_CHECKER_fingerprint_mismatch_rejected(
        self, stepup_admin_client, second_stepup_admin_client, cloud_override_state,
    ):
        """SOD-1 swap-attack guard: a DIFFERENT admin approves but supplies
        the WRONG confirming_fingerprint -> 409, override does NOT activate."""
        stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude-3", "justification": "ticket #999",
        })
        r = second_stepup_admin_client.post("/admin/cloud-override/approve", json={
            "confirming_fingerprint": "0" * 64,
        })
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "approval_failed"


class TestCloudOverrideRevoke:
    # GAP-CLOSED: POST /admin/cloud-override/revoke
    def test_revoke_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/cloud-override/revoke").status_code == 401

    def test_revoke_requires_stepup(self, admin_client, cloud_override_state):
        r = admin_client.post("/admin/cloud-override/revoke")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_revoke_success(self, stepup_admin_client, second_stepup_admin_client, cloud_override_state):
        propose_r = stepup_admin_client.post("/admin/cloud-override/propose", json={
            "provider": "anthropic", "model": "claude-3", "justification": "ticket #1",
        })
        fingerprint = propose_r.json()["state"]["proposal_fingerprint"]
        second_stepup_admin_client.post("/admin/cloud-override/approve", json={
            "confirming_fingerprint": fingerprint,
        })

        r = stepup_admin_client.post("/admin/cloud-override/revoke")
        assert r.status_code == 200
        assert r.json() == {"status": "revoked"}

        status_r = stepup_admin_client.get("/admin/cloud-override/status")
        assert status_r.json() == {"status": "INACTIVE"}


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
# admin_workflows.py — 4 endpoints. HIGH PRIORITY: cross-user oversight vs
# non-admin blocked-out.
# ---------------------------------------------------------------------------


class TestAdminWorkflowsList:
    # GAP-CLOSED: GET /admin/workflows
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/workflows").status_code == 401

    def test_NON_ADMIN_BLOCKED(self, user_client):
        """OVERSIGHT-SCOPING FINDING ASSESSMENT: a non-admin (user-tier)
        session must be flatly rejected from the entire admin oversight
        surface — 403 insufficient_tier, not a BOLA-filtered empty list.
        Confirmed: require_admin_session (AdminSession) is the ONLY
        dependency on every route in this file; there is no code path by
        which a user-tier session reaches _scan_all_wf_ids()."""
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
        """CROSS-USER OVERSIGHT FINDING ASSESSMENT: admin lists workflows
        belonging to TWO DIFFERENT, unrelated owners in a single call — this
        IS the intended oversight function (admin_workflows.py:5-6: "The
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
# mcp_servers.py — 3 endpoints
# ---------------------------------------------------------------------------


class TestMcpServersList:
    # GAP-CLOSED: GET /admin/mcp/servers/
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/mcp/servers/").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/mcp/servers/").status_code == 403

    def test_admin_503_without_db_pool(self, admin_client):
        """Real offline degrade: CapabilityEnvelopeService needs a live
        asyncpg pool (yashigani.db.get_pool()) which is deliberately absent
        in this offline suite (conftest.py leaves YASHIGANI_DB_DSN unset) —
        _envelope_service() catches the resulting failure and fails closed
        503, never a 500."""
        r = admin_client.get("/admin/mcp/servers/")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_service_unavailable"


class TestMcpServersImport:
    _VALID_BODY: ClassVar[dict[str, str]] = {
        "server_id": "conformance-mcp",
        "upstream_url": "http://10.99.99.99:8000",  # private, non-IMDS/loopback — passes the guard
        "topology": "external_relay",  # no manifest_yaml required
        "egress_posture": "NONE",
    }

    # GAP-CLOSED: POST /admin/mcp/servers/import
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/mcp/servers/import", json=self._VALID_BODY)
        assert r.status_code == 401

    def test_requires_stepup_not_just_admin(self, admin_client):
        r = admin_client.post("/admin/mcp/servers/import", json=self._VALID_BODY)
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_server_id_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/mcp/servers/import", json={
            **self._VALID_BODY, "server_id": "bad id with spaces",
        })
        assert r.status_code == 422

    def test_imds_upstream_url_blocked_422(self, stepup_admin_client):
        """codescan #1 (mustui triage 2026-07-20) regression guard: an
        IMDS-literal upstream_url is rejected at the Pydantic field-validator
        checkpoint before any fetch is attempted — IP-literal fast path
        (ipaddress.ip_address) needs no DNS, fully offline-safe."""
        r = stepup_admin_client.post("/admin/mcp/servers/import", json={
            **self._VALID_BODY, "upstream_url": "http://169.254.169.254/latest/meta-data/",
        })
        assert r.status_code == 422

    def test_offline_upstream_unreachable_502(self, stepup_admin_client, monkeypatch):
        """Real, offline-safe degrade: monkeypatch httpx.AsyncClient.post to
        raise ConnectError immediately (rather than let a real TCP SYN to a
        private, unreachable-in-this-sandbox IP time out slowly) — proves the
        genuine "tools/list fetch failed" -> 502 contract (mcp_servers.py:529-531),
        mirroring the Ollama-unreachable pattern in test_budget_models_inspection.py."""

        async def _raise(*_a, **_kw):
            raise httpx.ConnectError("no upstream MCP server in offline conformance suite")

        monkeypatch.setattr(httpx.AsyncClient, "post", _raise)
        r = stepup_admin_client.post("/admin/mcp/servers/import", json=self._VALID_BODY)
        assert r.status_code == 502


class TestMcpServersDecommission:
    # GAP-CLOSED: DELETE /admin/mcp/servers/{server_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/mcp/servers/conformance-mcp").status_code == 401

    def test_requires_stepup_not_just_admin(self, admin_client):
        r = admin_client.delete("/admin/mcp/servers/conformance-mcp")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_mode_422(self, stepup_admin_client):
        r = stepup_admin_client.delete(
            "/admin/mcp/servers/conformance-mcp", params={"mode": "bogus"}
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_mode"

    def test_503_without_db_pool(self, stepup_admin_client):
        """Same real degrade as the list endpoint — run_decommission_transaction
        acquires the envelope service (Postgres-backed) before doing anything
        else, so this fails closed 503 offline, never a 500."""
        r = stepup_admin_client.delete("/admin/mcp/servers/conformance-mcp")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_service_unavailable"
