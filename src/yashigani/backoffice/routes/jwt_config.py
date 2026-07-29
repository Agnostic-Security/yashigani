"""
Admin API for JWT introspection configuration.

GET  /admin/jwt/config              — list JWT configs
PUT  /admin/jwt/config              — create or update config
DELETE /admin/jwt/config/{tenant_id} — delete config
POST /admin/jwt/config/test         — test a token

Last updated: 2026-05-03
"""

from __future__ import annotations

import logging
import os
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session
from yashigani.backoffice.schemas.bopla import JWTConfigPublic, JWTTestResultPublic, SAFE_JWT_CLAIMS
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)
jwt_config_router = APIRouter(tags=["jwt-config"])

PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


class JWTConfigRequest(BaseModel):
    tenant_id: str = PLATFORM_TENANT_ID
    jwks_url: str
    issuer: str
    audience: str
    fail_closed: bool = True
    scope: Literal["tenant", "platform"] = "tenant"


class JWTTestRequest(BaseModel):
    token: str
    tenant_id: str = PLATFORM_TENANT_ID


@jwt_config_router.get("/admin/jwt/config")
async def list_jwt_configs(session=Depends(require_admin_session)):
    deployment_stream = os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "opensource")
    configs: list[dict] = []
    available = True
    try:
        from yashigani.db.postgres import get_pool

        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # V50-028: jwt_config carries ROW LEVEL SECURITY
                # (0001_initial_schema.py) keyed on
                # current_setting('app.tenant_id'). The pooled connection never
                # SET it, so every call raised "unrecognized configuration
                # parameter" — silently swallowed by the broad except below and
                # returned as an empty list at 200, indistinguishable from a
                # genuinely-empty config table. Fixed by SETting the platform
                # tenant before the query, matching the established idiom
                # (db/postgres.py:tenant_transaction(), routes/cache.py).
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", PLATFORM_TENANT_ID
                )
                rows = await conn.fetch(
                    "SELECT tenant_id::text, jwks_url, issuer, audience, fail_closed, scope "
                    "FROM jwt_config ORDER BY scope DESC, tenant_id"
                )
            # BOPLA allowlist (#90): JWTConfigPublic enforces the allowed field set.
            configs = [
                JWTConfigPublic(
                    tenant_id=row["tenant_id"],
                    jwks_url=row["jwks_url"],
                    issuer=row["issuer"],
                    audience=row["audience"],
                    fail_closed=row["fail_closed"],
                    scope=row["scope"],
                ).model_dump()
                for row in rows
            ]
    except Exception:
        # Log full traceback server-side (was logger.warning with no stack
        # trace); a real failure must never look identical to "no configs
        # saved yet" — `available: false` lets the UI distinguish the two
        # (mirrors cache_available in routes/cache.py).
        logger.exception("jwt_config list failed")
        configs = []
        available = False
    return {
        "configs": configs,
        "deployment_stream": deployment_stream,
        "platform_tenant_id": PLATFORM_TENANT_ID,
        "available": available,
    }


@jwt_config_router.put("/admin/jwt/config")
async def set_jwt_config(body: JWTConfigRequest, session=Depends(require_stepup_admin_session)):
    deployment_stream = os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "opensource")
    if deployment_stream == "opensource" and body.scope == "tenant":
        raise HTTPException(
            status_code=422,
            detail="Per-tenant JWKS not available in opensource stream. Use scope='platform'.",
        )
    if deployment_stream == "saas" and body.scope == "platform" and body.tenant_id != PLATFORM_TENANT_ID:
        raise HTTPException(status_code=422, detail="SaaS stream requires per-tenant JWKS.")
    try:
        import uuid
        from yashigani.db.postgres import get_pool

        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # V50-028 sibling: same missing-set_config bug as the GET above,
                # but here the exception surfaced as a hard 500 on every save —
                # /admin/jwt/config could never be written. SET app.tenant_id to
                # the tenant being configured (not hardcoded platform): the RLS
                # policy's WITH CHECK (derived from USING, since no separate
                # WITH CHECK is defined) requires the new row's tenant_id to
                # equal current_setting('app.tenant_id') OR the platform
                # sentinel, so a genuine per-tenant SaaS write must set the
                # real tenant, not platform.
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", body.tenant_id
                )
                await conn.execute(
                    """
                    INSERT INTO jwt_config (tenant_id, jwks_url, issuer, audience, fail_closed, scope)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (tenant_id, scope) DO UPDATE
                    SET jwks_url=EXCLUDED.jwks_url, issuer=EXCLUDED.issuer,
                        audience=EXCLUDED.audience, fail_closed=EXCLUDED.fail_closed,
                        updated_at=now()
                    """,
                    uuid.UUID(body.tenant_id),
                    body.jwks_url,
                    body.issuer,
                    body.audience,
                    body.fail_closed,
                    body.scope,
                )
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="jwt config update failed", status=500)
        raise HTTPException(status_code=500, detail=payload)
    return {"status": "updated", "tenant_id": body.tenant_id, "scope": body.scope}


@jwt_config_router.delete("/admin/jwt/config/{tenant_id}")
async def delete_jwt_config(tenant_id: str, session=Depends(require_stepup_admin_session)):
    try:
        import uuid
        from yashigani.db.postgres import get_pool

        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                # V50-028 sibling: same missing-set_config bug — SET the
                # tenant being deleted (path param) before the DELETE.
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", tenant_id
                )
                await conn.execute("DELETE FROM jwt_config WHERE tenant_id = $1", uuid.UUID(tenant_id))
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="jwt config delete failed", status=500)
        raise HTTPException(status_code=500, detail=payload)
    return {"status": "deleted", "tenant_id": tenant_id}


@jwt_config_router.post("/admin/jwt/config/test")
async def test_jwt_config(body: JWTTestRequest, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state

    jwt_inspector = getattr(backoffice_state, "jwt_inspector", None)
    if jwt_inspector is None:
        raise HTTPException(status_code=503, detail="JWT inspector not initialised")
    result = await jwt_inspector.inspect(body.token, tenant_id=body.tenant_id)
    # BOPLA allowlist (#90): JWTTestResultPublic + SAFE_JWT_CLAIMS filter strips
    # sensitive identity claims (email, phone_number, address, etc.) from the
    # test response. Only structural/integrity claims are returned.
    raw_claims: dict = result.claims or {}
    safe_claims = {k: v for k, v in raw_claims.items() if k in SAFE_JWT_CLAIMS}
    return JWTTestResultPublic(
        valid=result.valid,
        sub=result.sub,
        tenant_id=result.tenant_id,
        error=result.error,
        claims=safe_claims,
    ).model_dump()
