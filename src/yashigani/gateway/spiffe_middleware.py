"""
Yashigani Gateway — SPIFFE peer-cert verification middleware.

# Last updated: 2026-05-19T00:00:00+01:00 (Option C: AND-couple x-spiffe-id with X-Caddy-Verified-Secret)

LF-SPIFFE-FORGE fix (V10.3.5, 2026-04-27)
------------------------------------------
The original V10.3.5 fix in _resolve_identity() trusts the X-SPIFFE-ID header
that arrives with an HTTP request.  When the caller routes through Caddy, this
header is set by Caddy from the TLS peer cert URI SAN (strip-then-set pattern).
However, the gateway listener runs at 0.0.0.0:8080 with CERT_REQUIRED — any
service holding a valid internal-CA cert can connect DIRECTLY to gateway:8080
and forge X-SPIFFE-ID to match a stolen bearer token's bound_spiffe_uri.

Fix: this ASGI middleware extracts the SPIFFE URI SAN from the actual TLS peer
cert (via uvicorn's ASGI scope extensions) and writes it to a server-internal
header ``X-SPIFFE-ID-Peer-Cert`` that is NOT settable by clients (it is always
overwritten by this middleware before the request reaches a route handler).

LAURA-V232-002 (2026-04-30) and ISSUE-019 correction (2026-05-19)
------------------------------------------------------------------
Laura's finding confirmed that uvicorn does NOT populate ``peer_cert`` in the
ASGI TLS scope extension in any released version (confirmed on 0.46.0, verified
still absent on 0.39.0+).  ``_get_peer_cert_uri()`` therefore always returns
``""`` at runtime.

Su's LAURA-V232-002 fix (commit 4a7a5a8) stripped BOTH ``x-spiffe-id-peer-cert``
AND ``x-spiffe-id`` from all inbound scopes to prevent forge attacks.  However
this fix contained a design error: the comment described ``x-spiffe-id`` as a
"client-supplied" header that is "NOT present in the inbound scope" because
"Caddy injects it at the Caddy→upstream hop".  This is incorrect.

Reality: this middleware runs inside the BACKOFFICE/GATEWAY uvicorn process.
On the Caddy→backoffice TCP connection, ``x-spiffe-id`` IS present in the scope
— Caddy set it before forwarding the request.  Stripping it broke the Caddy
path entirely: every SPIFFE-gated endpoint returns 401 for both the browser-
via-Caddy path AND the direct-backoffice path (e.g. install.sh agent registration),
because ``x-spiffe-id-peer-cert`` is always empty and ``x-spiffe-id`` is stripped.
ISSUE-019 confirmed this: POST /admin/agents returns 401 no_spiffe_id.

Correction (ISSUE-019 fix):
- Strip ONLY ``x-spiffe-id-peer-cert`` (a server-controlled header that clients
  must not be able to set to a trusted value).
- Do NOT strip ``x-spiffe-id``.  This header is trusted under the following
  defence-in-depth model (see "Threat model" below).
- ``require_spiffe_id()`` checks ``x-spiffe-id-peer-cert`` first (populated
  when uvicorn eventually exposes the ASGI TLS extension), then falls back to
  ``x-spiffe-id`` (Caddy-injected via Caddyfile ``request_header`` directive,
  or install.sh-injected on the direct-backoffice path).

Option C tightening (Laura ACCEPT-WITH-RESIDUAL, v2.23.4):
  ``x-spiffe-id`` is now ONLY preserved when ``X-Caddy-Verified-Secret``
  validates successfully (via ``validate_caddy_secret()`` in caddy_verified.py).
  A direct-mesh attacker who forges ``X-SPIFFE-ID`` but lacks a valid HMAC
  secret will have that header stripped here before it reaches
  ``require_spiffe_id()``.  The AND-coupling means the attacker must hold BOTH
  the CA-signed mTLS cert AND the per-install HMAC secret to preserve the
  SPIFFE header — neither artefact alone is sufficient.

Residual risk (accepted for v2.23.4, after Option C):
  An attacker on ``caddy_internal`` holding BOTH a CA-signed cert AND the HMAC
  secret can still forge ``x-spiffe-id``.  As established in the Laura verdict
  (2026-05-19), both artefacts co-locate in every service container on that
  network — there is no realistic single-artefact path.  The residual is the
  same as the pre-LAURA-V232-002 baseline.  Documented in YSG-RISK-012b.
  Long-term fix: Laura's Option A (remove direct-TLS access to backoffice:8443
  / gateway:8080), tracked for v2.24.0.

  The forge path for ``/internal/metrics`` (no session requirement) is the
  higher-concern case.  Mitigating factors: Prometheus is on the ``obs``
  network, not ``caddy_internal``; only Caddy, prometheus, and grafana hold
  certs for that network; the HMAC secret is mounted read-only in those
  containers.  An attacker who can read the HMAC secret from those containers
  has already exfiltrated metrics.  Compensating control: network policy
  isolates ``obs`` from ``data``; zero-trust mTLS on the TLS layer.

  The correct long-term fix (Laura's Option A, LAURA-V232-002) is to remove
  direct-TLS access to backoffice:8443 and gateway:8080 — all access via Caddy
  only.  This is tracked as a v2.24.0 architectural change.

Peer cert extraction path (forward-looking):
  When uvicorn exposes ``scope["extensions"]["tls"]["peer_cert"]``, the
  middleware sets ``x-spiffe-id-peer-cert`` from the actual TLS handshake cert.
  This is the highest-trust signal and takes precedence over ``x-spiffe-id``.

uvicorn requirement: >=0.34.0 (``peer_cert`` ASGI extension targeted; currently
not implemented in any uvicorn release — tracked as upstream issue).

Design
------
This middleware runs BEFORE any route handler.  It modifies the ASGI scope's
``headers`` list to:
1. Strip client-supplied ``x-spiffe-id-peer-cert`` and re-set it from the
   TLS handshake (or empty string — current uvicorn behaviour).
2. Conditionally preserve ``x-spiffe-id``:
   - If ``X-Caddy-Verified-Secret`` validates → preserve ``x-spiffe-id``
     (Caddy-proxied path; or install.sh direct path with valid HMAC).
   - If ``X-Caddy-Verified-Secret`` is absent or invalid → strip ``x-spiffe-id``
     (direct-mesh forge attempt without the HMAC secret).
   This is Option C from Laura's ACCEPT-WITH-RESIDUAL verdict (2026-05-19).

Peer cert extraction (uvicorn 0.34+ / ASGI 3.0 extensions, forward-looking):
  scope["extensions"]["tls"]["peer_cert"]  → ssl.SSLSocket.getpeercert() dict

If the TLS scope extension is absent (current uvicorn behaviour), the header is
set to an empty string.  The gate in ``require_spiffe_id()`` falls back to the
``x-spiffe-id`` header (Caddy-injected or install.sh-injected).

References
----------
- ASVS v5 V10.3.5 (CWE-287)
- LAURA-V232-002 finding: /Users/max/Documents/Claude/Internal/Compliance/yashigani/v2.23.2/laura-pentest/findings/LAURA-V232-002_spiffe-peer-cert-forge.md
- ISSUE-019: /admin/agents 401 no_spiffe_id on fresh install with agent bundles
- YSG-RISK-012b (risk register: accepted residual risk on direct-mesh forge)
"""
from __future__ import annotations

import logging
import ssl
from typing import Callable

logger = logging.getLogger(__name__)


def _extract_spiffe_uri_from_cert(peer_cert: dict | None) -> str:
    """Extract the first SPIFFE URI SAN from an ssl.getpeercert() dict.

    Returns empty string if not found or cert is None.
    """
    if not peer_cert:
        return ""
    for typ, value in peer_cert.get("subjectAltName", []):
        if typ == "URI" and value.startswith("spiffe://"):
            return value
    return ""


class SpiffePeerCertMiddleware:
    """ASGI middleware: inject X-SPIFFE-ID-Peer-Cert from the TLS handshake
    and AND-couple x-spiffe-id preservation with X-Caddy-Verified-Secret.

    Must be registered BEFORE any route handlers that need this header.

    Header handling (Option C — Laura ACCEPT-WITH-RESIDUAL 2026-05-19):
    1. ``x-spiffe-id-peer-cert``: always stripped and re-set from the ASGI TLS
       extension (empty when uvicorn does not expose it — current behaviour).
    2. ``x-spiffe-id``: preserved ONLY when ``X-Caddy-Verified-Secret`` is
       present and valid (HMAC match against per-install caddy_internal_hmac).
       If the secret is absent or invalid the header is stripped here, so a
       direct-mesh forge attempt never reaches ``require_spiffe_id()``.
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            peer_cert_uri = self._get_peer_cert_uri(scope)
            peer_cert_bytes = peer_cert_uri.encode("ascii", errors="replace")
            peer_cert_header_name = b"x-spiffe-id-peer-cert"
            spiffe_id_header_name = b"x-spiffe-id"
            caddy_secret_header_name = b"x-caddy-verified-secret"

            raw_headers = scope.get("headers", [])

            # --- Option C: AND-couple x-spiffe-id with X-Caddy-Verified-Secret ---
            # Extract the Caddy HMAC header from the incoming scope (raw bytes).
            caddy_secret_val = ""
            for k, v in raw_headers:
                if k.lower() == caddy_secret_header_name:
                    try:
                        caddy_secret_val = v.decode("ascii", errors="replace")
                    except Exception:  # noqa: BLE001
                        caddy_secret_val = ""
                    break

            # Validate: import here (not at module top-level) to avoid import
            # cycles; caddy_verified is imported lazily because it references the
            # module-level _caddy_secret which is only set after lifespan startup.
            from yashigani.auth.caddy_verified import validate_caddy_secret

            hmac_valid = validate_caddy_secret(caddy_secret_val)

            # Strip both server-controlled header (always overwritten) and
            # x-spiffe-id if the HMAC check failed (forge attempt without secret).
            headers = []
            for k, v in raw_headers:
                k_lower = k.lower()
                if k_lower == peer_cert_header_name:
                    # Always strip — re-set from TLS handshake below.
                    continue
                if k_lower == spiffe_id_header_name and not hmac_valid:
                    # Strip: direct-mesh request without valid X-Caddy-Verified-Secret.
                    # Log at DEBUG so this is traceable without noisy prod logs.
                    logger.debug(
                        "spiffe-middleware (Option C): stripping x-spiffe-id — "
                        "X-Caddy-Verified-Secret absent or invalid (forge path blocked)"
                    )
                    continue
                headers.append((k, v))

            # Append the server-set peer-cert value (empty on current uvicorn).
            headers.append((peer_cert_header_name, peer_cert_bytes))
            scope = dict(scope)
            scope["headers"] = headers

        await self._app(scope, receive, send)

    @staticmethod
    def _get_peer_cert_uri(scope: dict) -> str:
        """Extract SPIFFE URI from the ASGI TLS extension (forward-looking).

        Returns empty string on any error or if the extension is absent.
        Currently returns empty string on all uvicorn releases — the
        ``scope["extensions"]["tls"]["peer_cert"]`` key is not populated by
        any released version of uvicorn (confirmed 0.39.0 / 0.46.0).
        The code is retained so the high-trust direct-cert path activates
        automatically when uvicorn adds the extension.
        """
        try:
            tls_ext = scope.get("extensions", {}).get("tls", {})
            # uvicorn 0.34+ target: exposes getpeercert() result under 'peer_cert'
            peer_cert = tls_ext.get("peer_cert")
            if peer_cert is None:
                # Extension absent (current uvicorn behaviour) — fall back to
                # x-spiffe-id (Caddy-injected or install.sh-injected).
                return ""
            return _extract_spiffe_uri_from_cert(peer_cert)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "spiffe-middleware: failed to extract peer cert URI: %s", exc
            )
            return ""


__all__ = ["SpiffePeerCertMiddleware", "_extract_spiffe_uri_from_cert"]
