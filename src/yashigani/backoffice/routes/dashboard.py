"""
Yashigani Backoffice — Dashboard routes.
GET /dashboard/health           — aggregate system health across all subsystems
GET /dashboard/resources        — resource pressure index and TTL tier from cgroup v2
GET /dashboard/alerts           — recent active admin alerts (in-memory ring buffer)
GET /dashboard/services-health  — R25: per-service health with criticality tags + roll-up semaphore
GET /dashboard/security-metrics — R25: policy denials, sensitivity mix, blocks
GET /dashboard/traffic-metrics  — R25: request rate, agent/MCP activity, top models/identities
GET /dashboard/budget-summary   — R25: budget used/cap/avg per user/group/org + cloud-vs-local split

Last updated: 2026-06-13T00:00:00+01:00
"""
from __future__ import annotations

import collections
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory alert ring buffer (last 200 admin alerts)
# ---------------------------------------------------------------------------

_ALERT_BUFFER_SIZE = 200
_alert_buffer: collections.deque = collections.deque(maxlen=_ALERT_BUFFER_SIZE)
_alert_lock = threading.Lock()


def record_admin_alert(alert: dict) -> None:
    """Called by the inspection pipeline when an admin alert is emitted."""
    with _alert_lock:
        _alert_buffer.appendleft({
            **alert,
            "received_at": datetime.now(tz=timezone.utc).isoformat(),
        })


def get_recent_alerts(limit: int = 50) -> list[dict]:
    with _alert_lock:
        return list(_alert_buffer)[:limit]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/health")
async def system_health(session: AdminSession):
    """
    Aggregate health check across all subsystems.
    Returns per-component status and an overall ok/degraded/critical status.
    """
    state = backoffice_state
    components: dict[str, dict] = {}
    overall = "ok"

    # KMS provider
    if state.kms_provider is not None:
        try:
            healthy = state.kms_provider.health_check()
            components["kms"] = {
                "status": "ok" if healthy else "degraded",
                "provider": state.kms_provider.provider_name,
            }
            if not healthy:
                overall = _degrade(overall, "degraded")
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="kms health check failed", status=500)
            components["kms"] = {"status": "critical", "error": payload["error"], "request_id": payload["request_id"]}
            overall = _degrade(overall, "critical")
    else:
        components["kms"] = {"status": "community", "note": "KMS not required for Community tier"}

    # Rotation scheduler
    if state.rotation_scheduler is not None:
        running = state.rotation_scheduler._scheduler is not None
        components["rotation_scheduler"] = {
            "status": "ok" if running else "stopped",
            "cron_expr": state.rotation_scheduler._cron_expr,
        }
        if not running:
            overall = _degrade(overall, "degraded")
    else:
        components["rotation_scheduler"] = {"status": "community", "note": "Manual rotation — auto-rotation available in Pro+"}

    # Inspection pipeline / Ollama
    if state.inspection_pipeline is not None:
        classifier = state.inspection_pipeline._classifier
        models = classifier.available_models()
        ollama_ok = len(models) > 0
        components["inspection"] = {
            "status": "ok" if ollama_ok else "critical",
            "model": classifier._model,
            "ollama_reachable": ollama_ok,
            "models_available": len(models),
        }
        if not ollama_ok:
            overall = _degrade(overall, "critical")
    else:
        components["inspection"] = {"status": "not_configured"}
        overall = _degrade(overall, "degraded")

    # Session store (Redis ping)
    if state.session_store is not None:
        try:
            state.session_store._redis.ping()  # type: ignore[attr-defined]
            components["session_store"] = {"status": "ok", "backend": "redis"}
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="session store unreachable", status=500)
            components["session_store"] = {"status": "critical", "error": payload["error"], "request_id": payload["request_id"]}
            overall = _degrade(overall, "critical")
    else:
        components["session_store"] = {"status": "not_configured"}
        overall = _degrade(overall, "degraded")

    # Resource monitor
    if state.resource_monitor is not None:
        try:
            metrics = state.resource_monitor.get_metrics()
            components["resource_monitor"] = {
                "status": "ok",
                "pressure_index": round(metrics.pressure_index, 4),
                "ttl_tier": metrics.ttl_tier,
            }
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="resource monitor unavailable", status=500)
            components["resource_monitor"] = {"status": "degraded", "error": payload["error"], "request_id": payload["request_id"]}
            overall = _degrade(overall, "degraded")
    else:
        components["resource_monitor"] = {"status": "not_configured"}

    # Audit writer
    if state.audit_writer is not None:
        try:
            log_path = state.audit_writer._log_path
            size_mb = log_path.stat().st_size / (1024 * 1024) if log_path.exists() else 0
            components["audit"] = {
                "status": "ok",
                "log_path": str(log_path),
                "current_size_mb": round(size_mb, 2),
                "siem_targets": len(state.audit_writer._siem_targets),
                "siem_enabled": sum(
                    1 for t in state.audit_writer._siem_targets if t.enabled
                ),
            }
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="audit writer unavailable", status=500)
            components["audit"] = {"status": "degraded", "error": payload["error"], "request_id": payload["request_id"]}
            overall = _degrade(overall, "degraded")
    else:
        components["audit"] = {"status": "not_configured"}
        overall = _degrade(overall, "critical")

    # Auth service
    if state.auth_service is not None:
        total_admins = await state.auth_service.total_admin_count()
        active_admins = await state.auth_service.active_admin_count()
        below_min = active_admins < state.admin_min_active
        components["auth"] = {
            "status": "warning" if below_min else "ok",
            "total_admins": total_admins,
            "active_admins": active_admins,
            "below_active_minimum": below_min,
            "soft_target": state.admin_soft_target,
            "below_soft_target": total_admins < state.admin_soft_target,
        }
        if below_min:
            overall = _degrade(overall, "degraded")
    else:
        components["auth"] = {"status": "critical"}
        overall = _degrade(overall, "critical")

    return {
        "status": overall,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "components": components,
    }


@router.get("/resources")
async def resource_pressure(session: AdminSession):
    """Return the current resource pressure index and TTL tier from cgroup v2."""
    state = backoffice_state

    if state.resource_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "resource_monitor_not_configured"},
        )

    try:
        metrics = state.resource_monitor.get_metrics()
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="metrics unavailable", status=500)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=payload,
        )

    return {
        "pressure_index": round(metrics.pressure_index, 4),
        "ttl_tier": metrics.ttl_tier,
        "memory_pressure": round(metrics.memory_pressure, 4),
        "cpu_throttle": round(metrics.cpu_throttle, 4),
        "memory_used_bytes": metrics.memory_used_bytes,
        "memory_max_bytes": metrics.memory_max_bytes,
        "source": metrics.source,
        "sampled_at": metrics.sampled_at.isoformat() if metrics.sampled_at else None,
    }


@router.get("/sod-conflicts")
async def sod_conflict_report(session: AdminSession):
    """
    Return the result of the most recent SoD cross-store conflict audit run.

    Reports any admin/user identity collisions detected by the daily cron job
    (SoD-005 / Iris #96). Conflicts indicate a username or email exists in both
    admin_accounts and the identity_registry — operator must remediate manually.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / v2.24.1.
    """
    from yashigani.backoffice.sod_conflict_audit_task import get_last_run_result
    return get_last_run_result()


@router.get("/alerts")
async def recent_alerts(session: AdminSession, limit: int = 50):
    """Return the most recent admin alerts from the in-memory ring buffer."""
    if not 1 <= limit <= _ALERT_BUFFER_SIZE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_limit",
                "message": f"limit must be between 1 and {_ALERT_BUFFER_SIZE}",
            },
        )

    alerts = get_recent_alerts(limit)
    return {
        "alerts": alerts,
        "total_in_buffer": len(_alert_buffer),
        "buffer_capacity": _ALERT_BUFFER_SIZE,
    }


# ---------------------------------------------------------------------------
# R25 — Services health with criticality tags + roll-up semaphore
# ---------------------------------------------------------------------------

# Service criticality catalogue.
# Caddy = sole ingress → critical. Gateway = request processor → critical.
# All others: degraded-but-not-fatal (non-critical).
_SERVICE_CRITICALITY: dict[str, bool] = {
    "caddy": True,        # sole TLS ingress
    "gateway": True,      # LLM proxy / OPA enforcer
    "backoffice": False,  # admin plane — ops impact, not data-plane
    "postgres": False,    # data store — impacts auth on restart, but gateway keeps serving cached sessions
    "redis": False,       # session/rate-limit cache
    "opa": False,         # policy engine — fail-closed in gateway, not sole gating layer
    "ollama": False,      # LLM backend — inspection can degrade gracefully
    "pgbouncer": False,   # connection pool — Postgres side-car
}


def compute_health_rollup(services: list[dict]) -> str:
    """
    Criticality-weighted roll-up of per-service statuses.

    Rules:
      - "critical"    : any service with criticality=True is not "ok"
      - "degraded"    : any service with criticality=False is not "ok"
      - "ok"          : all services are "ok" (or empty list)

    This function is pure (no I/O) so it is unit-testable in isolation.
    """
    for svc in services:
        if svc.get("status") not in ("ok", "community", "not_configured"):
            if svc.get("criticality", False):
                return "critical"
    for svc in services:
        if svc.get("status") not in ("ok", "community", "not_configured"):
            return "degraded"
    return "ok"


@router.get("/services-health")
async def services_health(session: AdminSession):
    """
    R25: Per-service health with criticality tags + roll-up semaphore.

    Returns a `services` list — each item has:
      - name: service identifier
      - status: "ok" | "degraded" | "critical" | "community" | "not_configured"
      - criticality: true (Caddy, Gateway) | false (all others)
      - detail: optional human-readable note

    The `rollup` field is the criticality-weighted aggregate:
      - "ok"       — all services healthy
      - "degraded" — a non-critical service is down
      - "critical" — a critical service (Caddy, Gateway) is down
    """
    state = backoffice_state

    services: list[dict] = []

    def _add(name: str, status_val: str, detail: str = "") -> None:
        crit = _SERVICE_CRITICALITY.get(name, False)
        entry: dict = {"name": name, "status": status_val, "criticality": crit}
        if detail:
            entry["detail"] = detail
        services.append(entry)

    # --- Gateway: inspect inspection_pipeline (proxies Ollama) --
    if state.inspection_pipeline is not None:
        try:
            classifier = state.inspection_pipeline._classifier
            models = classifier.available_models()
            ollama_ok = len(models) > 0
            _add("gateway", "ok" if ollama_ok else "critical",
                 f"model={classifier._model}, ollama_reachable={ollama_ok}")
            _add("ollama", "ok" if ollama_ok else "critical",
                 f"models_available={len(models)}")
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="gateway health check failed", status=500)
            _add("gateway", "critical", payload["error"])
            _add("ollama", "critical", payload["error"])
    else:
        _add("gateway", "not_configured", "inspection_pipeline not wired")
        _add("ollama", "not_configured")

    # --- Caddy: health is inferred — if this endpoint is reachable, Caddy is up ---
    # (If Caddy were down, this request could not have arrived via Caddy → backoffice)
    _add("caddy", "ok", "reachable (sole ingress)")

    # --- Backoffice itself ---
    _add("backoffice", "ok", "serving this request")

    # --- Postgres: test via auth service pool ---
    if state.auth_service is not None:
        try:
            # A lightweight DB call — just fetch total admin count
            _ = await state.auth_service.total_admin_count()
            _add("postgres", "ok", "pool responsive")
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="postgres health check failed", status=500)
            _add("postgres", "critical", payload["error"])
    else:
        _add("postgres", "not_configured")

    # --- Redis: session store ping ---
    if state.session_store is not None:
        try:
            state.session_store._redis.ping()  # type: ignore[attr-defined]
            _add("redis", "ok", "session store responsive")
        except Exception as exc:
            payload, _ = safe_error_envelope(exc, public_message="redis health check failed", status=500)
            _add("redis", "critical", payload["error"])
    else:
        _add("redis", "not_configured")

    # --- OPA: check via opa_url if configured ---
    # AVA-30-002: use the internal CA bundle via client_ssl_context() — the
    # established internal-mTLS pattern.  The bare urllib.request.urlopen()
    # call used previously had no CA trust, causing CERTIFICATE_VERIFY_FAILED.
    opa_url = getattr(state, "opa_url", None)
    if opa_url:
        try:
            import urllib.request as _ureq
            from yashigani.pki.ssl_context import client_ssl_context as _client_ssl_context
            _ssl_ctx = _client_ssl_context()
            req = _ureq.Request(opa_url.rstrip("/") + "/health", method="GET")
            with _ureq.urlopen(req, timeout=3, context=_ssl_ctx) as resp:
                opa_ok = resp.status == 200
            _add("opa", "ok" if opa_ok else "degraded", f"opa_url={opa_url}")
        except Exception as exc:
            _add("opa", "degraded", str(exc)[:120])
    else:
        _add("opa", "not_configured")

    rollup = compute_health_rollup(services)
    return {
        "rollup": rollup,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "services": services,
    }


# ---------------------------------------------------------------------------
# R25 — Security story: policy denials, blocks, sensitivity mix
# ---------------------------------------------------------------------------

@router.get("/security-metrics")
async def security_metrics(session: AdminSession):
    """
    R25: Dashboard security story.

    Sources:
      - Prometheus counters via the in-process registry (no Prometheus scrape needed).
      - Recent admin alerts (in-memory buffer).

    Returns:
      - policy_denials_total       : OPA deny events (lifetime counter)
      - opa_blocks_total           : OPA safety-net blocks (lifetime counter)
      - sensitivity_detections     : per-level detection counts
      - recent_alerts_by_priority  : counts of P1–P5 alerts in the ring buffer
      - alert_buffer_size          : total alerts in buffer
    """
    from yashigani.metrics import registry as _reg

    # Read Prometheus counters directly (no HTTP scrape)
    def _counter_value(metric) -> int:
        try:
            # prometheus_client Counter stores _value as a prometheus_client.values._ValueClass
            return int(metric._value.get())  # type: ignore[attr-defined]
        except Exception:
            return 0

    def _labelled_counter_value(metric, **labels) -> int:
        try:
            return int(metric.labels(**labels)._value.get())  # type: ignore[attr-defined]
        except Exception:
            return 0

    # OPA safety blocks
    opa_blocks = _counter_value(_reg.yashigani_opa_safety_blocks_total)

    # Inspection classifications (policy deny comes via OPA verdict)
    # Collect sensitivity detection counts across all levels
    sensitivity = {}
    for level in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SENSITIVE"):
        val = _labelled_counter_value(_reg.yashigani_sensitivity_detections_total, level=level)
        if val > 0:
            sensitivity[level] = val

    # Recent alerts by priority
    recent = get_recent_alerts(200)
    priority_counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
    for a in recent:
        p = a.get("priority") or a.get("level") or ""
        if p in priority_counts:
            priority_counts[p] += 1

    return {
        "opa_blocks_total": opa_blocks,
        "sensitivity_detections": sensitivity,
        "recent_alerts_by_priority": priority_counts,
        "alert_buffer_size": len(_alert_buffer),
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# R25 — Traffic: req/min, agent/MCP activity, top models, recent audit events
# ---------------------------------------------------------------------------

@router.get("/traffic-metrics")
async def traffic_metrics(session: AdminSession):
    """
    R25: Traffic, agent activity, recent audit, top models.

    Reads in-process Prometheus counters (no external scrape required).
    gateway_requests_total is the source for request rate; agent_calls_total
    for agent/MCP traffic; inspection_backend_requests_total for model usage.

    NOTE: Prometheus counters are monotonically increasing since process start.
    The UI displays lifetime totals and computes approximate rate by polling
    on the 15-second refresh cycle.
    """
    from yashigani.metrics import registry as _reg

    def _sum_counter_samples(metric) -> int:
        """Sum all label-variants of a counter."""
        try:
            total = 0
            for sample in metric.collect():  # type: ignore[attr-defined]
                for s in sample.samples:
                    if s.name.endswith("_total"):
                        total += int(s.value)
            return total
        except Exception:
            return 0

    def _labelled_counter_value(metric, **labels) -> int:
        try:
            return int(metric.labels(**labels)._value.get())  # type: ignore[attr-defined]
        except Exception:
            return 0

    # Gateway request totals
    gateway_total = _sum_counter_samples(_reg.gateway_requests_total)

    # Agent call totals
    agent_total = _sum_counter_samples(_reg.agent_calls_total)

    # Inspection backend requests (proxy for model activity)
    inspection_total = _sum_counter_samples(_reg.inspection_backend_requests_total)

    # Rate limit violations (traffic quality signal)
    ratelimit_total = _sum_counter_samples(_reg.ratelimit_violations_total)

    # Recent audit events from buffer
    recent_alerts = get_recent_alerts(20)

    return {
        "gateway_requests_total": gateway_total,
        "agent_calls_total": agent_total,
        "inspection_requests_total": inspection_total,
        "ratelimit_violations_total": ratelimit_total,
        "recent_audit_events": recent_alerts[:10],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# R25 — Budget summary: used/cap/avg + cloud-vs-local split
# ---------------------------------------------------------------------------

@router.get("/budget-summary")
async def budget_summary(session: AdminSession):
    """
    R25: Budget usage summary for the dashboard widget.

    Returns:
      - org_caps_count             : number of configured org caps
      - group_budgets_count        : number of configured group budgets
      - individual_budgets_count   : number of individual budgets
      - budget_threshold_pct       : the configured alert threshold (default 85)
      - tokens_by_route            : cloud vs local token totals (from Prometheus)
      - budget_utilisation         : {identity_id: pct} dict (from budget store if wired)
    """
    from yashigani.metrics import registry as _reg
    from yashigani.backoffice.routes.budget import _state as _budget_state

    def _sum_by_route(metric, route: str) -> int:
        try:
            total = 0
            for sample in metric.collect():  # type: ignore[attr-defined]
                for s in sample.samples:
                    if s.name.endswith("_total") and s.labels.get("route") == route:
                        total += int(s.value)
            return total
        except Exception:
            return 0

    cloud_tokens = _sum_by_route(_reg.yashigani_budget_tokens_total, "cloud")
    local_tokens = _sum_by_route(_reg.yashigani_budget_tokens_total, "local")

    # Budget threshold from alert config
    from yashigani.backoffice.routes.alerts import _get_budget_threshold_config
    threshold_cfg = _get_budget_threshold_config()

    # Budget counts from the configured store
    org_caps_count = 0
    group_count = 0
    individual_count = 0
    if _budget_state.budget_store is not None:
        try:
            caps = await _budget_state.budget_store.get_org_caps("00000000-0000-0000-0000-000000000000")
            org_caps_count = len(caps) if caps else 0
        except Exception:
            pass
        try:
            groups = await _budget_state.budget_store.get_group_budgets("00000000-0000-0000-0000-000000000000")
            group_count = len(groups) if groups else 0
        except Exception:
            pass
        try:
            inds = await _budget_state.budget_store.get_individual_budgets("00000000-0000-0000-0000-000000000000")
            individual_count = len(inds) if inds else 0
        except Exception:
            pass

    return {
        "org_caps_count": org_caps_count,
        "group_budgets_count": group_count,
        "individual_budgets_count": individual_count,
        "budget_threshold_pct": threshold_cfg.threshold_pct,
        "threshold_alert_enabled": threshold_cfg.enabled,
        "tokens_by_route": {
            "cloud": cloud_tokens,
            "local": local_tokens,
            "total": cloud_tokens + local_tokens,
        },
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"ok": 0, "degraded": 1, "warning": 1, "critical": 2}


def _degrade(current: str, new: str) -> str:
    """Return whichever status is more severe."""
    if _SEVERITY_ORDER.get(new, 0) > _SEVERITY_ORDER.get(current, 0):
        return new
    return current
