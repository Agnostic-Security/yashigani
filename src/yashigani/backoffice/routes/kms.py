"""
Yashigani Backoffice — KMS management routes.
GET  /kms/status          — provider info + health check
GET  /kms/schedule        — current rotation schedule
POST /kms/schedule        — update rotation schedule (cron) [step-up required]
POST /kms/rotate-now      — manual out-of-band rotation trigger [step-up required]
GET  /kms/secrets         — list tracked secret keys (names only, no values)

Mutating KMS operations require step-up TOTP (ASVS V6.8.4).
"""
# Last updated: 2026-05-03T00:00:00+01:00
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

router = APIRouter()


class ScheduleUpdateRequest(BaseModel):
    cron_expr: str = Field(
        min_length=9,
        max_length=100,
        description="Standard 5-field cron expression. Minimum interval: 1 hour.",
    )


@router.get("/status")
async def kms_status(session: AdminSession):
    """Return provider identity and basic health probe."""
    state = backoffice_state
    provider = state.kms_provider

    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "kms_not_configured"},
        )

    try:
        healthy = provider.health_check()
        health_error = None
    except Exception as exc:
        # V232-CSCAN-01e: log full exception (may include Vault address, role-id path)
        # server-side only; surface only a stable string to the admin UI.
        envelope, _ = safe_error_envelope(exc, public_message="kms backend unavailable")
        healthy = False
        health_error = envelope["error"]

    return {
        "provider": provider.provider_name,
        "environment_scope": getattr(provider, "_environment_scope", None),
        "healthy": healthy,
        "health_error": health_error,
    }


@router.get("/schedule")
async def get_schedule(session: AdminSession):
    """Return the current rotation schedule."""
    state = backoffice_state
    scheduler = state.rotation_scheduler

    if scheduler is None:
        return {"configured": False}

    return {
        "configured": True,
        "cron_expr": scheduler._cron_expr,
        "secret_key": _redact_key(scheduler._secret_key),
        "running": scheduler._scheduler is not None,
    }


@router.post("/schedule")
async def update_schedule(body: ScheduleUpdateRequest, session: StepUpAdminSession):
    """Update the rotation cron schedule. Validates 1-hour minimum interval."""
    from yashigani.kms.rotation import _validate_cron

    try:
        _validate_cron(body.cron_expr)
    except ValueError as exc:
        # V232-CSCAN-01g: log full validation error server-side; safe envelope to client.
        payload, _ = safe_error_envelope(
            exc, public_message="invalid cron expression", status=422
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=payload,
        )

    state = backoffice_state
    scheduler = state.rotation_scheduler

    if scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rotation_scheduler_not_configured"},
        )

    scheduler.set_schedule(body.cron_expr)

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id,
        "kms_rotation_schedule",
        scheduler._cron_expr,
        body.cron_expr,
        account_tier=session.account_tier,
    ))

    return {"status": "ok", "cron_expr": body.cron_expr}


@router.post("/rotate-now")
async def rotate_now(session: StepUpAdminSession):
    """Trigger an immediate out-of-band rotation."""
    state = backoffice_state
    scheduler = state.rotation_scheduler

    if scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rotation_scheduler_not_configured"},
        )

    try:
        scheduler.trigger_now()
    except Exception as exc:
        # V232-CSCAN-01g: log full exception server-side; safe envelope to client.
        payload, _ = safe_error_envelope(exc, public_message="rotation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=payload,
        )

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id,
        "kms_manual_rotation",
        "",
        "triggered",
        account_tier=session.account_tier,
    ))

    return {"status": "ok", "message": "Manual rotation triggered"}


@router.get("/secrets")
async def list_secrets(session: AdminSession):
    """List secret key names managed by the current KSM provider. Values never returned."""
    state = backoffice_state
    provider = state.kms_provider

    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "kms_not_configured"},
        )

    try:
        keys = provider.list_secrets()
    except Exception as exc:
        # V232-CSCAN-01g: log full exception server-side; safe envelope to client.
        payload, _ = safe_error_envelope(exc, public_message="failed to list secrets")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=payload,
        )

    return {"secrets": keys, "total": len(keys)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact_key(key: str) -> str:
    """Show first 4 and last 4 chars only."""
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]


def _config_event(admin_id: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import ConfigChangedEvent
    return ConfigChangedEvent(
        account_tier=account_tier,
        admin_account=admin_id,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )
