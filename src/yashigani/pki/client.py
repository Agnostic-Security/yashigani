"""
httpx client factories pre-wired with internal-CA trust and client cert.

Every outbound call from one Yashigani service to another internal service
should go through :func:`internal_httpx_client` (async) or
:func:`internal_httpx_sync_client` (sync for init-time paths).

These wrappers provide mutual TLS identity without the caller needing to
know about cert paths — identity comes from ``YASHIGANI_SERVICE_NAME`` +
the secrets directory bind-mount.

The separate :mod:`yashigani.net.http_client` (SSRF-guarded httpx wrapper)
is used for OUTBOUND-TO-INTERNET calls. Internal mesh calls use this
module. The two are orthogonal: SSRF guards prevent leaking to the
internet; internal mTLS prevents rogue services from pretending to be in
the mesh.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from yashigani.pki.identity import ServiceIdentity
from yashigani.pki.ssl_context import client_ssl_context, client_ssl_context_verify_spiffe

logger = logging.getLogger(__name__)


def internal_httpx_client(
    *,
    identity: Optional[ServiceIdentity] = None,
    timeout: float = 10.0,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` that uses the internal CA + client cert.

    Extra ``kwargs`` are forwarded to :class:`httpx.AsyncClient`. The
    ``verify`` and ``cert`` parameters cannot be overridden — they are
    fixed by the internal PKI policy.
    """
    if "verify" in kwargs or "cert" in kwargs:
        raise TypeError(
            "internal_httpx_client: verify/cert are controlled by internal PKI "
            "policy and cannot be overridden. Use httpx.AsyncClient directly "
            "if you need custom TLS config."
        )
    ctx = client_ssl_context(identity)
    return httpx.AsyncClient(verify=ctx, timeout=timeout, **kwargs)


def internal_httpx_client_verify_spiffe(
    expected_spiffe_id: str,
    *,
    identity: Optional[ServiceIdentity] = None,
    timeout: float = 10.0,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` for a ring-fenced-agent peer verified
    by SPIFFE URI SAN instead of DNS hostname (FINDING C, v4.1.2 final
    onboarding e2e).

    Use this — never a bare ``internal_httpx_client()`` — when dialling a
    per-instance MCP agent Caddy front (``https://caddy:<mesh_port>/mcp/...``):
    those leaves carry a SPIFFE URI SAN only (no DNS SAN), so the default
    hostname check in :func:`internal_httpx_client` always fails against
    them. Chain verification against the internal CA is unchanged; only the
    identity-matching strategy differs. See
    :func:`yashigani.pki.ssl_context.client_ssl_context_verify_spiffe` for
    the full rationale and threat-model note.

    ``verify``/``cert`` cannot be overridden, same contract as
    :func:`internal_httpx_client`.
    """
    if "verify" in kwargs or "cert" in kwargs:
        raise TypeError(
            "internal_httpx_client_verify_spiffe: verify/cert are controlled "
            "by internal PKI policy and cannot be overridden. Use "
            "httpx.AsyncClient directly if you need custom TLS config."
        )
    ctx = client_ssl_context_verify_spiffe(expected_spiffe_id, identity)
    return httpx.AsyncClient(verify=ctx, timeout=timeout, **kwargs)


def internal_httpx_sync_client(
    *,
    identity: Optional[ServiceIdentity] = None,
    timeout: float = 10.0,
    **kwargs: Any,
) -> httpx.Client:
    """Synchronous variant of :func:`internal_httpx_client` for init paths."""
    if "verify" in kwargs or "cert" in kwargs:
        raise TypeError(
            "internal_httpx_sync_client: verify/cert are controlled by "
            "internal PKI policy and cannot be overridden."
        )
    ctx = client_ssl_context(identity)
    return httpx.Client(verify=ctx, timeout=timeout, **kwargs)
