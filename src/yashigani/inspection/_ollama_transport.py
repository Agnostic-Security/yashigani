# Last updated: 2026-07-06T00:00:00+00:00 (v4.1 Phase 1c — Ollama mesh seam)
"""
Ollama HTTP transport — mesh-mTLS aware (v4.1 Phase 1c, LAURA-I1-01 seam).

Since v4.1 Phase 1b-ii (Su, ffe660b2) Ollama is reachable ONLY via the Caddy
mesh front ``https://caddy:11435/ollama`` (``require_and_verify`` against the
internal intermediate CA).  Every in-process Ollama client must therefore
present this service's mesh leaf (gateway_client / backoffice_client) on the
TLS handshake — a plain ``urllib``/``httpx`` call fails CLOSED at the
handshake (correct posture, but a dead classifier).

This module is the SINGLE transport used by every OLLAMA_BASE_URL consumer:

  * ``yashigani.inspection.classifier.PromptInjectionClassifier``
  * ``yashigani.inspection.backends.ollama.OllamaBackend``
    (the backoffice semantic-intent sidecar backend)
  * ``yashigani.optimization.sensitivity_classifier.SensitivityClassifier``
  * ``yashigani.backoffice.routes.models`` (admin model list / pull)

Scheme rule (keeps dev/test behaviour byte-compatible):

  * ``https://...`` → :func:`yashigani.pki.client.internal_httpx_sync_client`
    (mesh leaf + internal-CA verify; ``client_ssl_context`` policy — verify
    REQUIRED, TLS 1.3, hostname check).  The :11435 front presents the caddy
    service cert whose DNS SANs include ``caddy``, so hostname verification
    holds.  (Per-MCP instance-leaf fronts are different: their SANs are
    loopback-only and are verified by SPIFFE URI/trust — see SYNTHESIS.md
    Issue-2 caveat.  Those fronts are NOT dialled through this module.)
  * ``http://...``  → plain ``httpx`` client (legacy single-bridge / unit-test
    path — no mesh certs exist there).

Fail-closed: no ``verify=False`` path exists here and none may be added.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Default request timeout mirrors the classifier's historical default.
_DEFAULT_TIMEOUT = 30.0

# YSG-RISK-113: hard ceiling on the CONNECT phase, decoupled from the (often
# much longer) read timeout that a caller passes for model-generation latency.
# A backend that is completely unreachable (TCP refused / host down / no
# listener) must fail in seconds, not wait out the full read timeout meant
# for a slow-but-alive model. Never raised above the caller's own timeout.
_CONNECT_TIMEOUT_CEILING = 5.0


def _is_mesh_url(base_url: str) -> bool:
    """True when *base_url* requires the internal-mesh mTLS client."""
    return base_url.strip().lower().startswith("https://")


def _build_timeout(timeout: float | httpx.Timeout) -> httpx.Timeout:
    """Normalize *timeout* into an explicit httpx.Timeout with a fast-failing
    connect phase (YSG-RISK-113 fail-fast hardening).

    A bare float applies the SAME duration to connect/read/write/pool, which
    means a fully dead backend (nothing listening) waits just as long as a
    slow-but-alive one before failing. Splitting connect off to a short,
    fixed ceiling makes "backend unreachable" fail fast while preserving the
    caller's intended read timeout for "backend alive but slow to respond".
    """
    if isinstance(timeout, httpx.Timeout):
        return timeout
    connect = min(float(timeout), _CONNECT_TIMEOUT_CEILING)
    return httpx.Timeout(float(timeout), connect=connect)


def ollama_sync_client(
    base_url: str, *, timeout: "float | httpx.Timeout" = _DEFAULT_TIMEOUT,
) -> httpx.Client:
    """Return a sync httpx client appropriate for *base_url*.

    https → internal mesh mTLS client (presents this service's leaf).
    http  → plain client (legacy/dev path, unchanged behaviour).

    ``timeout`` accepts a plain float or an ``httpx.Timeout`` (needed by the
    long-running model-pull stream). A bare float is normalized via
    :func:`_build_timeout` so the connect phase fails fast even when the
    read timeout is long (YSG-RISK-113).
    """
    timeout = _build_timeout(timeout)
    if _is_mesh_url(base_url):
        # Lazy import: pki.client pulls in ssl-context machinery that must not
        # be a hard import cost for test environments using http:// URLs.
        from yashigani.pki.client import internal_httpx_sync_client  # noqa: PLC0415
        client = internal_httpx_sync_client()
        client.timeout = timeout  # httpx TimeoutTypes — float or Timeout
        return client
    return httpx.Client(timeout=timeout)


def ollama_async_client(
    base_url: str, *, timeout: "float | httpx.Timeout" = _DEFAULT_TIMEOUT,
) -> httpx.AsyncClient:
    """Async variant of :func:`ollama_sync_client` (same scheme rule)."""
    timeout = _build_timeout(timeout)
    if _is_mesh_url(base_url):
        from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415
        client = internal_httpx_client()
        client.timeout = timeout  # httpx TimeoutTypes — float or Timeout
        return client
    return httpx.AsyncClient(timeout=timeout)


def ollama_post_json(
    base_url: str,
    path: str,
    payload: dict,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict:
    """POST *payload* as JSON to ``<base_url><path>`` and return the JSON body.

    Raises ``httpx.HTTPError`` (connect/timeout/status) on failure — callers
    keep their existing fail-closed handling.
    """
    url = f"{base_url.rstrip('/')}{path}"
    with ollama_sync_client(base_url, timeout=timeout) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        result: dict = resp.json()
        return result


def ollama_get_json(
    base_url: str,
    path: str,
    *,
    timeout: float = 5.0,
) -> Optional[dict]:
    """GET ``<base_url><path>`` and return the JSON body, or None on any error.

    Mirrors the historical best-effort semantics of ``available_models`` /
    ``health_check`` (errors → None, never raises).
    """
    url = f"{base_url.rstrip('/')}{path}"
    try:
        with ollama_sync_client(base_url, timeout=timeout) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return None
            result: dict = resp.json()
            return result
    except Exception as exc:  # noqa: BLE001 — best-effort probe by contract
        logger.debug("ollama_get_json: %s unreachable: %s", url, exc)
        return None


__all__ = [
    "ollama_async_client",
    "ollama_get_json",
    "ollama_post_json",
    "ollama_sync_client",
]
