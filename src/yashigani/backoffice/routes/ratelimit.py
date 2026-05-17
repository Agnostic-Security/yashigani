"""
Yashigani Backoffice — Rate limit management routes.
GET    /ratelimit/config           — current rate limit configuration
PUT    /ratelimit/config           — update rate limit configuration
GET    /ratelimit/status           — live multiplier, current RPI, bucket counters
POST   /ratelimit/reset/{key}      — reset a specific rate limit bucket (unblock a client)
GET    /ratelimit/endpoints        — list per-endpoint rate limit overrides
POST   /ratelimit/endpoints        — set a per-endpoint rate limit override
DELETE /ratelimit/endpoints/{hash} — remove a per-endpoint rate limit override

Path note (2026-05-02): Fixed three decorator paths. The router is mounted at prefix
/admin/ratelimit. The decorators previously used the full absolute path
/admin/ratelimit/endpoints which FastAPI concatenated to the doubled path
/admin/ratelimit/admin/ratelimit/endpoints (unreachable). Changed to relative
paths: /endpoints and /endpoints/{endpoint_hash}.

Last updated: 2026-05-03
"""
from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, require_admin_session
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

router = APIRouter()


class RateLimitConfigRequest(BaseModel):
    enabled: bool = True
    adaptive_enabled: bool = True
    global_rps: float = Field(gt=0, le=100_000, default=1000.0)
    global_burst: int = Field(gt=0, le=10_000, default=200)
    per_ip_rps: float = Field(gt=0, le=10_000, default=50.0)
    per_ip_burst: int = Field(gt=0, le=1_000, default=20)
    per_agent_rps: float = Field(gt=0, le=10_000, default=100.0)
    per_agent_burst: int = Field(gt=0, le=1_000, default=30)
    per_session_rps: float = Field(gt=0, le=1_000, default=20.0)
    per_session_burst: int = Field(gt=0, le=500, default=10)
    rpi_scale_medium: float = Field(ge=0.1, le=1.0, default=0.80)
    rpi_scale_high: float = Field(ge=0.1, le=1.0, default=0.50)
    rpi_scale_critical: float = Field(ge=0.05, le=1.0, default=0.25)


@router.get("/config")
async def get_ratelimit_config(session: AdminSession):
    state = backoffice_state
    if state.rate_limiter is None:
        return {"configured": False}

    cfg = state.rate_limiter.current_config()
    return {
        "configured": True,
        "enabled": cfg.enabled,
        "adaptive_enabled": cfg.adaptive_enabled,
        "global_rps": cfg.global_rps,
        "global_burst": cfg.global_burst,
        "per_ip_rps": cfg.per_ip_rps,
        "per_ip_burst": cfg.per_ip_burst,
        "per_agent_rps": cfg.per_agent_rps,
        "per_agent_burst": cfg.per_agent_burst,
        "per_session_rps": cfg.per_session_rps,
        "per_session_burst": cfg.per_session_burst,
        "rpi_scale_medium": cfg.rpi_scale_medium,
        "rpi_scale_high": cfg.rpi_scale_high,
        "rpi_scale_critical": cfg.rpi_scale_critical,
        "last_changed": state.ratelimit_config_last_changed,
    }


@router.put("/config")
async def update_ratelimit_config(body: RateLimitConfigRequest, session: AdminSession):
    from yashigani.ratelimit.config import RateLimitConfig

    state = backoffice_state
    if state.rate_limiter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rate_limiter_not_configured"},
        )

    prev = state.rate_limiter.current_config()
    new_cfg = RateLimitConfig(**body.model_dump())
    state.rate_limiter.update_config(new_cfg)
    state.ratelimit_config_last_changed = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Emit a specialised event when RPI scale thresholds change (P2-6 / S-11)
    rpi_fields = ("rpi_scale_medium", "rpi_scale_high", "rpi_scale_critical")
    rpi_changed = any(getattr(prev, f) != getattr(new_cfg, f) for f in rpi_fields)
    if rpi_changed and state.audit_writer is not None:
        from yashigani.audit.schema import RateLimitThresholdChangedEvent
        state.audit_writer.write(RateLimitThresholdChangedEvent(
            admin_account=session.account_id,
            previous_rpi_scale_medium=prev.rpi_scale_medium,
            previous_rpi_scale_high=prev.rpi_scale_high,
            previous_rpi_scale_critical=prev.rpi_scale_critical,
            new_rpi_scale_medium=new_cfg.rpi_scale_medium,
            new_rpi_scale_high=new_cfg.rpi_scale_high,
            new_rpi_scale_critical=new_cfg.rpi_scale_critical,
        ))
    elif state.audit_writer is not None:
        state.audit_writer.write(_config_event(
            session.account_id,
            "rate_limit_config",
            f"global_rps={prev.global_rps}",
            f"global_rps={new_cfg.global_rps}",
            account_tier=session.account_tier,
        ))
    return {"status": "ok"}


@router.get("/status")
async def ratelimit_status(session: AdminSession):
    """Return current adaptive multiplier and RPI context."""
    state = backoffice_state
    if state.rate_limiter is None:
        return {"configured": False}

    multiplier = state.rate_limiter.current_rpi_multiplier()
    rpi = 0.0
    if state.resource_monitor is not None:
        try:
            rpi = state.resource_monitor.get_metrics().pressure_index
        except Exception:
            pass

    cfg = state.rate_limiter.current_config()
    return {
        "configured": True,
        "enabled": cfg.enabled,
        "adaptive_enabled": cfg.adaptive_enabled,
        "current_rpi": round(rpi, 4),
        "current_multiplier": round(multiplier, 4),
        "effective_global_rps": round(cfg.global_rps * multiplier, 2),
        "effective_per_ip_rps": round(cfg.per_ip_rps * multiplier, 2),
        "effective_per_agent_rps": round(cfg.per_agent_rps * multiplier, 2),
        "effective_per_session_rps": round(cfg.per_session_rps * multiplier, 2),
    }


@router.post("/reset/{bucket_key}")
async def reset_bucket(bucket_key: str, session: AdminSession):
    """
    Delete a specific rate limit bucket from Redis (unblocks a client/agent/session).
    bucket_key must be a full Redis key, e.g. yashigani:rl:ip:<hash>.
    Only keys prefixed yashigani:rl: are accepted.
    """
    if not bucket_key.startswith("yashigani:rl:"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_bucket_key", "message": "Key must start with yashigani:rl:"},
        )

    state = backoffice_state
    if state.rate_limiter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rate_limiter_not_configured"},
        )

    try:
        state.rate_limiter._redis.delete(bucket_key)
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="rate-limit lookup failed", status=500)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=payload,
        )

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id, "rate_limit_bucket_reset", bucket_key, "deleted",
        account_tier=session.account_tier,
    ))
    return {"status": "ok", "bucket_key": bucket_key}


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


# ── Per-endpoint rate limit overrides ──────────────────────────────────────

from pydantic import BaseModel as _BaseModel


class EndpointRLRequest(_BaseModel):
    endpoint_template: str  # e.g. "/agents/{agent_id}"
    rps: int
    burst: int
    window_seconds: int = 1


@router.get("/endpoints")
async def list_endpoint_overrides(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    ep_rl = getattr(backoffice_state, "endpoint_rate_limiter", None)
    if ep_rl is None:
        return {"endpoints": []}
    return {"endpoints": ep_rl.list_configs()}


@router.post("/endpoints")
async def set_endpoint_override(
    body: EndpointRLRequest,
    session=Depends(require_admin_session),
):
    from yashigani.backoffice.state import backoffice_state
    ep_rl = getattr(backoffice_state, "endpoint_rate_limiter", None)
    if ep_rl is None:
        raise HTTPException(status_code=503, detail="Endpoint rate limiter not initialised")
    ep_hash = ep_rl.set_config(
        body.endpoint_template, body.rps, body.burst, body.window_seconds
    )
    return {"status": "updated", "endpoint_hash": ep_hash, "endpoint_template": body.endpoint_template}


@router.delete("/endpoints/{endpoint_hash}")
async def delete_endpoint_override(
    endpoint_hash: str,
    session=Depends(require_admin_session),
):
    from yashigani.backoffice.state import backoffice_state
    ep_rl = getattr(backoffice_state, "endpoint_rate_limiter", None)
    if ep_rl is None:
        raise HTTPException(status_code=503, detail="Endpoint rate limiter not initialised")
    ep_rl.delete_config(endpoint_hash)
    return {"status": "deleted", "endpoint_hash": endpoint_hash}
