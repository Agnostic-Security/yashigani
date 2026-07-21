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

SSRF guard (3.1 Phase 5):
  - ``forward()`` uses ``net.HttpClient`` with ``bypass_private_for_allowlisted=True``
    (NOT a raw ``httpx.AsyncClient``).  The guard allows only the registered upstream
    hosts, hard-blocks IMDS (169.254.169.254, link-local, loopback), and rejects any
    redirect to a host outside the allowlist.
  - The allowlist defaults to the single ``upstream_url`` hostname this transport
    instance was created for.  Callers may pass ``trusted_upstream_urls`` to supply
    an explicit multi-entry list (e.g. the full registry for future multi-hop support).

DEFER to phase-2:
  - TODO[P8]: Upstream MCP-server cert/SPIFFE pinning enforcement.
             Currently the broker connects to the upstream URL without pinning.
             Pin the upstream server's SPIFFE cert at this call site in phase-2.
  - TODO[P1-pool]: Per-tenant provider-key cache + per-tenant connection pools.
             Currently uses a single shared HttpClient per broker instance.

v2.25.0 / P1 W3 Phase 2b-ii.
v3.1 Phase 5 — SSRF guard via net.HttpClient.
"""
from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from yashigani.mcp._types import McpPosture, McpTransportKind, PostureBinding
from yashigani.mcp._posture import derive_posture_from_channel

logger = logging.getLogger(__name__)

_DEFAULT_UPSTREAM_TIMEOUT = 30.0   # seconds


def _extract_allowlist_from_urls(urls: list[str]) -> list[str]:
    """Extract the lowercase hostname from each URL for use as an allowlist entry.

    ``urlparse("http://filesystem-mcp:8000").hostname`` → ``"filesystem-mcp"``
    ``urlparse("http://10.0.0.5:8000").hostname``       → ``"10.0.0.5"``

    Returns the deduplicated list of hostnames in the order they appear.
    Skips malformed URLs (no hostname extracted).
    """
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        try:
            h = (urlparse(url).hostname or "").strip().lower()
        except Exception:
            h = ""
        if h and h not in seen:
            seen.add(h)
            result.append(h)
    return result


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
        trusted_upstream_urls: Optional[list[str]] = None,
        expected_spiffe_id: Optional[str] = None,
    ) -> None:
        self._upstream_url = upstream_url.rstrip("/")
        self._is_relay = is_relay
        self._upstream_chain = upstream_chain or []
        self._upstream_jwt_verified = upstream_jwt_verified
        self._timeout = timeout_seconds
        # trusted_upstream_urls: explicit list of upstream URLs whose hostnames
        # form the SSRF-guard allowlist.  When None (the common case), defaults
        # to [upstream_url] so every transport instance is auto-guarded to only
        # reach its own registered upstream.
        self._trusted_upstream_urls = trusted_upstream_urls
        # FINDING C (v4.1.2 final onboarding e2e): the expected SPIFFE URI SAN
        # of the ring-fenced agent's per-instance Caddy front leaf. Threaded
        # through to net.HttpClient so an https:// upstream is verified by
        # SPIFFE identity instead of DNS hostname (the leaf carries no DNS
        # SAN). None for plain-HTTP bridge upstreams (unused there) and for
        # legacy/pre-Phase-2a boot-env https entries — see http_client.py's
        # fail-closed refusal when an https:// bypass-mode request has no
        # expected_spiffe_id.
        self._expected_spiffe_id = expected_spiffe_id
        # Shared client (caller owns lifetime if provided; we create one if not).
        # When http_client is injected (tests / pooling), SSRF guard is bypassed
        # at this layer — the injected client is fully caller-controlled.
        self._http_client: Any = http_client
        self._own_client = http_client is None

    async def __aenter__(self) -> "McpHttpTransport":
        if self._own_client:
            # ── 3.1 Phase 5: SSRF-guarded HTTP client ───────────────────────
            # Replace the raw httpx.AsyncClient with net.HttpClient configured
            # for the MCP upstream guard mode:
            #   * bypass_private_for_allowlisted=True — allowlisted RFC-1918
            #     Docker bridge IPs pass; IMDS/link-local/loopback hard-blocked.
            #   * allow_http=True — internal MCP upstreams use plain HTTP inside
            #     the Docker bridge network (TLS is terminated at Caddy).
            #   * follow_redirects=False (HttpClient default) — redirect-based
            #     SSRF blocked.
            # Allowlist: either the explicitly-supplied trusted_upstream_urls, or
            # [upstream_url] as a safe default (auto-derived per-instance guard).
            urls_for_allowlist = (
                self._trusted_upstream_urls
                if self._trusted_upstream_urls is not None
                else [self._upstream_url]
            )
            allowlist = _extract_allowlist_from_urls(urls_for_allowlist)
            from yashigani.net.http_client import HttpClient
            self._http_client = HttpClient(
                allowlist=allowlist,
                allow_http=True,                     # Docker bridge uses HTTP
                bypass_private_for_allowlisted=True, # allow RFC-1918 MCP hosts
                timeout_s=self._timeout,
                expected_spiffe_id=self._expected_spiffe_id,  # FINDING C
            )
            logger.debug(
                "mcp-transport: SSRF guard active upstream=%r allowlist=%r",
                self._upstream_url, allowlist,
            )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._own_client and self._http_client is not None:
            # HttpClient.aclose() is a no-op; httpx.AsyncClient.aclose() closes
            # the connection pool.  Both implement .aclose() — call uniformly.
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

        SSRF guard (3.1 Phase 5):
            The underlying HTTP client (``net.HttpClient``) enforces an
            allowlist-only policy against the target URL before issuing the
            request.  ``BlockedByPolicy`` is caught and re-raised as
            ``HttpTransportError`` so callers see a consistent error type.

        TODO[P8] — phase-2: pin upstream server's SPIFFE cert here.
        TODO[P1-pool] — phase-2: use per-tenant connection pool.

        Returns the upstream response body as a string.
        Raises HttpTransportError on failure (includes SSRF-blocked attempts).
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
        except HttpTransportError:
            raise  # re-raise without wrapping
        except Exception as exc:
            # Wraps BlockedByPolicy (SSRF guard) and network errors alike so
            # callers see HttpTransportError regardless of what went wrong.
            raise HttpTransportError(
                f"Failed to forward MCP request to {url}: {exc}"
            ) from exc
