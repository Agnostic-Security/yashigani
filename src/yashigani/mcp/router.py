"""
MCP Broker — FastAPI router.

Endpoints:
  GET  /.well-known/yashigani-mcp-jwks.json  — JWKS endpoint (public, no auth)
  GET  /mcp/health                            — MCP broker + OPA health probe

The JWKS endpoint MUST:
  - Require no authentication (upstream MCP servers fetch without Yashigani creds).
  - Serve Cache-Control: max-age=300, must-revalidate (Nico spec §5).
  - Be served over TLS (TLS is enforced at the Caddy layer — not this router).

The /mcp/health endpoint:
  - Queries OPA /health (add to gateway healthcheck ASVS V11.1.1 / C9).
  - Returns 200 {"status": "ok"} when broker + OPA are healthy.
  - Returns 503 when OPA is unreachable (fail-closed).

Note on MCP request routing:
  MCP call enforcement is NOT a separate HTTP endpoint in this router.
  The enforcement pipeline (McpBroker.enforce()) is called by the transport
  layer (McpStdioTransport or McpHttpTransport) which is wired into the
  gateway's proxy.py agent router. The router here only adds the public
  JWKS endpoint + health probe.

v2.25.0 / P1 W3 Phase 2b-ii / Nico spec §5.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Response

from yashigani.mcp._jwks import JWKS_CACHE_CONTROL, JWKS_PATH, JwksStore

logger = logging.getLogger(__name__)

router = APIRouter()


async def _opa_health_check(opa_url: str) -> bool:
    """Direct OPA /health reachability check — mirrors McpBroker.opa_health()
    exactly, but needs no broker instance (v5.0 LAURA-V50-014).

    ``create_mcp_router`` is mounted as soon as the MCP feature is
    CONFIGURED (a JwksStore was built — boot-list entries OR the durable
    registry/SEAM-1d-07 lazy-load store is wired), which can be BEFORE any
    server has ever been onboarded/lazy-built this process lifetime
    (McpBrokerRegistry.all_brokers() reads only the in-memory, already-
    registered dict). The health probe must still report the feature as
    configured+healthy in that window instead of requiring a broker
    instance that may not exist yet.
    """
    url = f"{opa_url.rstrip('/')}/health"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(url)
            return resp.status_code == 200
    except Exception as exc:
        logger.warning("mcp-broker: OPA health check failed (opa_url path): %s", exc)
        return False


def create_mcp_router(
    jwks_store: JwksStore,
    broker: Optional[object] = None,  # McpBroker, typed as Any to avoid circular
    opa_url: Optional[str] = None,  # v5.0 LAURA-V50-014 — broker-less health fallback
) -> APIRouter:
    """
    Create the MCP broker FastAPI router.

    Parameters
    ----------
    jwks_store:
        JwksStore instance — provides the JWKS response atomically.

    broker:
        McpBroker instance for the /mcp/health OPA health check. May be
        None even when MCP IS configured (durable-registry/SEAM-1d-07
        topology with zero servers lazily built yet this process lifetime
        — see _opa_health_check above) — in that case ``opa_url`` is used
        as a fallback so health reporting does not require a broker
        instance to already exist.

    opa_url:
        v5.0 LAURA-V50-014 — used for the /mcp/health OPA check when
        ``broker`` is None. If BOTH ``broker`` and ``opa_url`` are None,
        the MCP feature is genuinely not configured and /mcp/health
        returns 503 ``mcp_broker_not_configured`` (unchanged pre-fix
        behaviour for that case).
    """
    mcp_router = APIRouter()

    @mcp_router.get(
        JWKS_PATH,
        include_in_schema=False,  # not in Swagger — public security endpoint
        response_model=None,
    )
    async def get_mcp_jwks(response: Response):
        """
        JWKS endpoint — public, no authentication.

        Returns the gateway's MCP identity signing public key in JWK Set format.
        Upstream MCP servers use this to verify gateway-issued identity JWTs.

        Cache-Control: max-age=300 (Nico spec §5 — short TTL for rapid rotation).
        """
        response.headers["Cache-Control"] = JWKS_CACHE_CONTROL
        response.headers["Content-Type"] = "application/json"
        return jwks_store.response()

    @mcp_router.get("/mcp/health")
    async def mcp_health():
        """
        MCP broker + OPA health probe.

        Used by gateway HEALTHCHECK and monitoring. Returns 200 when broker
        and OPA are healthy, 503 otherwise (fail-closed per C9).

        v5.0 LAURA-V50-014: a live-onboard-only deployment (empty
        YASHIGANI_MCP_SERVERS at boot, the normal demo/production
        topology) has NO broker instance yet on a fresh boot — only
        opa_url. Prefer the broker's own opa_health() when a broker IS
        available (exercises the exact tenant-scoped client the broker
        uses); fall back to the direct opa_url check otherwise. Only
        report mcp_broker_not_configured when NEITHER is available (the
        feature is genuinely off — no boot-list entries AND no durable
        registry/Redis).
        """
        if broker is not None:
            opa_ok = await broker.opa_health()  # type: ignore[union-attr]
        elif opa_url:
            opa_ok = await _opa_health_check(opa_url)
        else:
            logger.warning("mcp-broker: health check: MCP feature not configured")
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"status": "error", "detail": "mcp_broker_not_configured"},
            )

        if opa_ok:
            return {"status": "ok", "opa": "healthy"}
        else:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"status": "error", "detail": "opa_unreachable"},
            )

    return mcp_router
