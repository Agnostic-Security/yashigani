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

from fastapi import APIRouter, Response

from yashigani.mcp._jwks import JWKS_CACHE_CONTROL, JWKS_PATH, JwksStore

logger = logging.getLogger(__name__)

router = APIRouter()


def create_mcp_router(
    jwks_store: JwksStore,
    broker: Optional[object] = None,  # McpBroker, typed as Any to avoid circular
) -> APIRouter:
    """
    Create the MCP broker FastAPI router.

    Parameters
    ----------
    jwks_store:
        JwksStore instance — provides the JWKS response atomically.

    broker:
        McpBroker instance for the /mcp/health OPA health check.
        If None, /mcp/health returns 503 (no broker = not healthy).
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
        """
        if broker is None:
            logger.warning("mcp-broker: health check: no broker configured")
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"status": "error", "detail": "mcp_broker_not_configured"},
            )

        opa_ok = await broker.opa_health()  # type: ignore[union-attr]
        if opa_ok:
            return {"status": "ok", "opa": "healthy"}
        else:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"status": "error", "detail": "opa_unreachable"},
            )

    return mcp_router
