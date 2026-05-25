"""
Yashigani Backoffice — Dashboard routes.
GET /dashboard/health     — aggregate system health across all subsystems
GET /dashboard/resources  — resource pressure index and TTL tier from cgroup v2
GET /dashboard/alerts     — recent active admin alerts (in-memory ring buffer)

Last updated: 2026-05-03
"""
from __future__ import annotations

import collections
import threading
from datetime import datetime, timezone
from typing import Optional

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
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"ok": 0, "degraded": 1, "warning": 1, "critical": 2}


def _degrade(current: str, new: str) -> str:
    """Return whichever status is more severe."""
    if _SEVERITY_ORDER.get(new, 0) > _SEVERITY_ORDER.get(current, 0):
        return new
    return current
