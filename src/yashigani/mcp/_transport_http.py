"""
MCP Broker — Streamable HTTP transport (Shape B + Shape C).

Shape B: MCP client → gateway (network, TLS-terminated at gateway) → MCP server.
Shape C: MCP client relay → gateway → upstream MCP server over HTTP.

Posture assignment:
  - Network TCP/TLS request without upstream JWT → mcp-b (tls_channel).
  - Network TCP/TLS request WITH upstream JWT (verified) → mcp-c (spiffe_cert).

Security notes:
  - Forwarded/X-Forwarded-For headers MUST be stripped before posture derivation.
    The physical socket peer determines posture — never forwarded headers.
  - A client that injects X-Posture: mcp-a in a request header MUST be ignored.
    This class never reads posture from request headers.
  - mcp-a is NEVER returned by this transport (HTTP transport = network channel).

Upstream MCP server communication:
  - For mcp-b/mcp-c, the broker forwards the MCP call to the upstream MCP server
    over HTTP with the gateway-signed JWT in the Authorization header.
  - The upstream server URL comes from the McpBrokerConfig (never from the client).

DEFER to phase-2:
  - TODO[P8]: Upstream MCP-server cert/SPIFFE pinning enforcement.
             Currently the broker connects to the upstream URL without pinning.
             Pin the upstream server's SPIFFE cert at this call site in phase-2.
  - TODO[P1-pool]: Per-tenant provider-key cache + per-tenant connection pools.
             Currently uses a single shared httpx.AsyncClient per broker instance.

v2.25.0 / P1 W3 Phase 2b-ii.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from yashigani.mcp._types import McpPosture, McpTransportKind, PostureBinding
from yashigani.mcp._posture import derive_posture_from_channel

logger = logging.getLogger(__name__)

_DEFAULT_UPSTREAM_TIMEOUT = 30.0   # seconds


class HttpTransportError(RuntimeError):
    """Raised when the HTTP transport fails to communicate with the upstream."""


class McpHttpTransport:
    """
    HTTP transport for MCP calls (Shape B = remote, Shape C = chained relay).

    Posture is derived from:
      - is_relay=False, upstream_chain=None/[] → mcp-b
      - is_relay=True, upstream_chain=[...], upstream_jwt_verified=True → mcp-c

    Usage::

        transport = McpHttpTransport(
            upstream_url="https://mcp-server.internal:8443",
            is_relay=False,  # set True for mcp-c
        )
        posture, binding = transport.derive_posture()
        response = await transport.forward(
            mcp_request_json=...,
            gateway_jwt=...,
        )

    Note: Forwarded/X-Forwarded-For headers from the inbound HTTP request
    MUST be stripped by the FastAPI router before calling derive_posture().
    This class has no access to inbound request headers — callers own stripping.
    """

    def __init__(
        self,
        upstream_url: str,
        is_relay: bool = False,
        upstream_chain: Optional[list[str]] = None,
        upstream_jwt_verified: bool = False,
        http_client: Optional[httpx.AsyncClient] = None,
        timeout_seconds: float = _DEFAULT_UPSTREAM_TIMEOUT,
    ) -> None:
        self._upstream_url = upstream_url.rstrip("/")
        self._is_relay = is_relay
        self._upstream_chain = upstream_chain or []
        self._upstream_jwt_verified = upstream_jwt_verified
        self._timeout = timeout_seconds
        # Shared client (caller owns lifetime if provided; we create one if not)
        self._http_client = http_client
        self._own_client = http_client is None

    async def __aenter__(self) -> "McpHttpTransport":
        if self._own_client:
            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._own_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def derive_posture(self) -> tuple[McpPosture, PostureBinding]:
        """
        Derive MCP posture from the HTTP transport descriptor.

        NEVER returns mcp-a — HTTP transport is always a network channel.
        Returns mcp-c only when upstream_jwt_verified=True and chain is non-empty.

        Raises PostureDerivationError if is_relay=True but chain/verification
        preconditions are not met.
        """
        if self._is_relay:
            transport_kind = McpTransportKind.CHAINED_RELAY
        else:
            transport_kind = McpTransportKind.NETWORK_STREAMABLE_HTTP

        return derive_posture_from_channel(
            transport_kind=transport_kind,
            upstream_chain=self._upstream_chain if self._upstream_chain else None,
            upstream_jwt_verified=self._upstream_jwt_verified,
        )

    async def forward(
        self,
        mcp_request_json: str,
        gateway_jwt: str,
        path: str = "/mcp",
    ) -> str:
        """
        Forward a JSON-RPC MCP request to the upstream MCP server.

        Attaches the gateway-signed JWT as Authorization: Bearer.
        The upstream MCP server verifies the JWT against the JWKS endpoint.

        TODO[P8] — phase-2: pin upstream server's SPIFFE cert here.
        TODO[P1-pool] — phase-2: use per-tenant connection pool.

        Returns the upstream response body as a string.
        Raises HttpTransportError on failure.
        """
        if self._http_client is None:
            raise HttpTransportError(
                "Transport not started — use 'async with McpHttpTransport(...) as t:'"
            )

        url = f"{self._upstream_url}{path}"
        headers = {
            "Authorization": f"Bearer {gateway_jwt}",
            "Content-Type": "application/json",
        }

        try:
            resp = await self._http_client.post(
                url,
                content=mcp_request_json.encode("utf-8"),
                headers=headers,
            )
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPStatusError as exc:
            raise HttpTransportError(
                f"Upstream MCP server returned HTTP {exc.response.status_code} "
                f"for {url}: {exc.response.text[:256]}"
            ) from exc
        except Exception as exc:
            raise HttpTransportError(
                f"Failed to forward MCP request to {url}: {exc}"
            ) from exc
