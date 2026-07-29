"""Admin API for response cache configuration.

GET  /admin/cache                  — list all tenant configs
GET  /admin/cache/{tenant_id}      — get config for tenant
PUT  /admin/cache/{tenant_id}      — set config
DELETE /admin/cache/{tenant_id}    — invalidate all entries for tenant

# Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import require_admin_session
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)
cache_router = APIRouter(tags=["cache"])

MAX_TTL = 3600

# V50-CACHE-500: cache_config carries ROW LEVEL SECURITY (0001_initial_schema.py)
# with `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. The pooled
# connection returned by get_pool() never SETs app.tenant_id, so Postgres raises
# `unrecognized configuration parameter "app.tenant_id"` before RLS is even
# evaluated — every call to this handler 500'd unconditionally. Fixed by SETting
# the platform tenant before the query, matching the established idiom used
# elsewhere in this codebase (identity/durable_store.py, agents/durable_store.py,
# audit/chain.py, backoffice/routes/jwt_config.py — all define the same
# well-known all-zeros UUID locally rather than importing a shared constant).
_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


class CacheConfigRequest(BaseModel):
    enabled: bool = False
    ttl_seconds: int = Field(default=300, ge=1, le=MAX_TTL)


@cache_router.get("/admin/cache")
async def list_cache_configs(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        return {"tenants": [], "cache_available": False}
    try:
        from yashigani.db.postgres import get_pool
        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # V50-CACHE-500: RLS on cache_config requires app.tenant_id to be
                # set on this connection before any row is visible/queryable.
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", _PLATFORM_TENANT_ID
                )
                rows = await conn.fetch(
                    "SELECT tenant_id::text, enabled, ttl_seconds FROM cache_config ORDER BY tenant_id"
                )
        return {"tenants": [dict(r) for r in rows], "cache_available": True}
    except Exception as exc:
        # V232-CSCAN-01e: log full exception server-side; degrade gracefully to
        # the client rather than a raw 500 — an admin page failing to fetch its
        # config listing is not fatal, and this mirrors the `rc is None` path
        # above plus the UI's existing `cache_available` badge support
        # (static/ui4/admin/modules/infrastructure.js:299,304).
        payload, _ = safe_error_envelope(exc, public_message="cache config unavailable")
        return JSONResponse(
            status_code=200,
            content={"tenants": [], "cache_available": False, **payload},
        )


@cache_router.get("/admin/cache/{tenant_id}")
async def get_cache_config(tenant_id: str, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    return rc.get_tenant_config(tenant_id)


@cache_router.put("/admin/cache/{tenant_id}")
async def set_cache_config(tenant_id: str, body: CacheConfigRequest, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    rc.set_tenant_config(tenant_id, body.enabled, body.ttl_seconds)
    logger.info("Cache config updated: tenant=%s enabled=%s ttl=%ds", tenant_id, body.enabled, body.ttl_seconds)
    return {"status": "updated", "tenant_id": tenant_id, "enabled": body.enabled, "ttl_seconds": body.ttl_seconds}


@cache_router.delete("/admin/cache/{tenant_id}")
async def invalidate_cache(tenant_id: str, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    count = rc.invalidate(tenant_id)
    logger.info("Cache invalidated: tenant=%s keys_deleted=%d", tenant_id, count)
    return {"status": "invalidated", "tenant_id": tenant_id, "keys_deleted": count}
