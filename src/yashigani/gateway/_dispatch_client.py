"""
Mesh-identity httpx client for agent dispatch THROUGH the Caddy ingress fronts.

v4.1 unified-sidecar §2.5 (dispatch repoint): the §2.6 split-ringfence
migration removed gateway/backoffice L3 reach to the bundled agents; the
registered upstream URLs now point at each agent's Caddy INGRESS front
(``https://caddy:<mesh_port>/agents/<tenant>/<system>``), which terminates
mTLS ``require_and_verify`` against the internal intermediate CA.  A bare
``httpx.AsyncClient`` presents no client leaf and is refused at the TLS
handshake — every dispatch fails CLOSED before any HTTP exchange.

This module is the SINGLE place the dispatch AsyncClient is created for
agent-front upstreams (gateway ``agent_router`` forward leg, gateway
``langflow_client`` / module-level ``letta_chat``, backoffice
``user_agents`` draft-flow creation via ``langflow_client.create_flow``).

Primary path: :func:`yashigani.pki.client.internal_httpx_client` — the
per-process ServiceIdentity leaf (``YASHIGANI_SERVICE_NAME``: gateway leaf
in the gateway container, backoffice leaf in the backoffice container) +
internal root-CA trust.  ``/auth/verify-mcp`` admits both transport
subjects (gateway unconditionally; backoffice only toward the bundled
langflow front — see backoffice/routes/auth.py).

Fallback (dev/test only — FIX-MCP-001 precedent, mcp/_opa.py
``_make_opa_http_client``): when the ServiceIdentity secrets are absent
(unit tests, plain-HTTP upstreams, no /run/secrets mount), fall back to a
bare client.  The fallback stays fail-closed against a mesh front: an
identity-less client is refused at the handshake → dispatch error, never
an open path.

Last updated: 2026-07-07T00:00:00+00:00
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


def agent_dispatch_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Return the httpx.AsyncClient for dispatching to an agent upstream.

    Presents the process's mesh ServiceIdentity leaf (internal PKI) so the
    agent's Caddy ingress front (``require_and_verify``) accepts the
    handshake.  Falls back to a bare client only when the ServiceIdentity
    is unavailable (dev/test) — that fallback cannot pass a mesh front.
    """
    try:
        from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415
        client = internal_httpx_client(timeout=timeout)
        logger.debug("agent-dispatch: client using mesh ServiceIdentity (mTLS)")
        return client
    except Exception as exc:  # noqa: BLE001 — dev/test fallback, fail-closed vs mesh
        logger.warning(
            "agent-dispatch: mesh ServiceIdentity unavailable (%s) — falling "
            "back to identity-less client (dev/test path; an agent ingress "
            "front will refuse this client at the TLS handshake → dispatch "
            "fails closed)",
            exc,
        )
    return httpx.AsyncClient(timeout=timeout)
