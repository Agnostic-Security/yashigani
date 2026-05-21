"""
Yashigani Gateway — SPIFFE peer-cert verification middleware.

# Last updated: 2026-05-21T00:00:00+01:00 (V240-001: remove _get_peer_cert_uri() dead-code — architecture-accepted)

Architectural decision (V240-001, Tom spike 2026-05-21)
-------------------------------------------------------
``scope["extensions"]["tls"]["peer_cert"]`` is NOT populated by any production-grade
ASGI server in any released version:

- **uvicorn 0.47.0**: ``scope["extensions"]`` is ``{}`` — key absent entirely.
- **granian 2.7.4**: ``scope["extensions"]`` contains only HTTP/2-specific keys;
  no ``tls`` key.  Granian terminates TLS in Rust (Rustls); the Python ssl layer
  is inaccessible by design — ``getpeercert()`` cannot reach the handshake.
- **hypercorn 0.18.0**: ``scope["extensions"]`` contains H/2-specific keys; no
  ``tls`` key.  Additionally, mTLS is broken on Python 3.14 (connection reset on
  every ``CERT_REQUIRED`` connection — asyncio and trio backends both affected).

The ASGI server swap slot (V240-001 original thesis) is **the wrong architectural
slot** for this problem.  No mainstream ASGI server surfaces peer_cert; this is a
TLS-layer primitive the ASGI spec does not mandate.

**Sole identity source of truth (this release and forward):**
Caddy-mediated identity injection with HMAC-AND-SPIFFE coupling (Tom Option C,
v2.23.4).  The trust chain:

1. Caddy validates the client cert at the TLS layer via ``tls.client_auth``.
2. Caddy strips any inbound ``X-SPIFFE-ID`` before setting its own value from
   ``{http.request.tls.client.san.uris.0}`` — a co-tenant cannot forge.
3. This middleware AND-couples ``x-spiffe-id`` preservation with a valid
   ``X-Caddy-Verified-Secret`` HMAC (``validate_caddy_secret()``).  A direct-mesh
   attacker who has a CA-signed cert but not the HMAC secret has the header
   stripped here before it reaches ``require_spiffe_id()``.
4. ``require_spiffe_id()`` enforces an endpoint-level allow-list from
   ``service_identities.yaml``.

Residual (YSG-RISK-012b, LOW):
  A direct-mesh attacker holding BOTH a CA-signed leaf cert AND the
  ``caddy_internal_hmac`` HMAC secret can still forge ``x-spiffe-id``.  Both
  prerequisites require filesystem-level compromise of 0440-mode secrets.
  Accepted LOW per Tiago 2026-05-19.

Forward-track:
  Caddy-only edge (remove direct-TLS listeners from backoffice/gateway entirely)
  is tracked as BACKLOG-V240-001-renamed for v2.25.0.  Prerequisite: install.sh
  must gate the agent-registration call behind a Caddy health check — the current
  ``https://localhost:8443/admin/agents`` call runs before Caddy is confirmed
  healthy, which means dropping direct-TLS from backoffice:8443 without that gate
  is a P0 regression.  See Iris post-spike reframe 2026-05-21.

LF-SPIFFE-FORGE fix (V10.3.5, 2026-04-27)
------------------------------------------
The original V10.3.5 fix in _resolve_identity() trusts the X-SPIFFE-ID header
that arrives with an HTTP request.  When the caller routes through Caddy, this
header is set by Caddy from the TLS peer cert URI SAN (strip-then-set pattern).
However, the gateway listener runs at 0.0.0.0:8080 with CERT_REQUIRED — any
service holding a valid internal-CA cert can connect DIRECTLY to gateway:8080
and forge X-SPIFFE-ID to match a stolen bearer token's bound_spiffe_uri.

LAURA-V232-002 (2026-04-30) and ISSUE-019 correction (2026-05-19)
------------------------------------------------------------------
Laura's finding confirmed that uvicorn does NOT populate ``peer_cert`` in the
ASGI TLS scope extension in any released version (confirmed on 0.46.0, verified
still absent on 0.39.0+).  Tom V240-001 spike (2026-05-21) confirmed the same
on granian 2.7.4 and hypercorn 0.18.0 — no ASGI server surfaces this extension.

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
  defence-in-depth model (see "Threat model" above).

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
  Long-term fix: Caddy-only edge (remove direct-TLS access to backoffice:8443
  / gateway:8080), tracked as BACKLOG-V240-001-renamed for v2.25.0.

  The forge path for ``/internal/metrics`` (no session requirement) is the
  higher-concern case.  Mitigating factors: Prometheus is on the ``obs``
  network, not ``caddy_internal``; only Caddy, prometheus, and grafana hold
  certs for that network; the HMAC secret is mounted read-only in those
  containers.  An attacker who can read the HMAC secret from those containers
  has already exfiltrated metrics.  Compensating control: network policy
  isolates ``obs`` from ``data``; zero-trust mTLS on the TLS layer.

Design
------
This middleware runs BEFORE any route handler.  It modifies the ASGI scope's
``headers`` list to:
1. Strip client-supplied ``x-spiffe-id-peer-cert`` and re-set it to an empty
   byte string.  The header name is kept in scope so downstream code that
   checks its presence sees a server-controlled (empty) value rather than any
   client-supplied forge attempt.  The peer_cert ASGI extension is permanently
   absent on all production ASGI servers (V240-001 spike, 2026-05-21).
2. Conditionally preserve ``x-spiffe-id``:
   - If ``X-Caddy-Verified-Secret`` validates → preserve ``x-spiffe-id``
     (Caddy-proxied path; or install.sh direct path with valid HMAC).
   - If ``X-Caddy-Verified-Secret`` is absent or invalid → strip ``x-spiffe-id``
     (direct-mesh forge attempt without the HMAC secret).
   This is Option C from Laura's ACCEPT-WITH-RESIDUAL verdict (2026-05-19).

References
----------
- ASVS v5 V10.3.5 (CWE-287)
- LAURA-V232-002 finding: /Users/max/Documents/Claude/Internal/Compliance/yashigani/v2.23.2/laura-pentest/findings/LAURA-V232-002_spiffe-peer-cert-forge.md
- Tom V240-001 spike 2026-05-21: /Users/max/Documents/Claude/internal-docs/yashigani/tom-v240-001-asgi-spike.md
- Iris V240-001 post-spike reframe 2026-05-21: /Users/max/Documents/Claude/internal-docs/yashigani/iris-v240-001-post-spike-reframe.md
- Laura V240-001 post-spike threat-model 2026-05-21: /Users/max/Documents/Claude/internal-docs/yashigani/laura-v240-001-post-spike-threat-model.md
- ISSUE-019: /admin/agents 401 no_spiffe_id on fresh install with agent bundles
- YSG-RISK-012b (risk register: accepted residual risk on direct-mesh forge)
- YSG-RISK-047 (CLOSED-ARCHITECTURE-ACCEPTED 2026-05-21 — peer_cert not available via any ASGI server)
"""
from __future__ import annotations

import logging
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
    """ASGI middleware: strip forge attempts on X-SPIFFE-ID-Peer-Cert and
    AND-couple x-spiffe-id preservation with X-Caddy-Verified-Secret (Option C).

    Must be registered BEFORE any route handlers that need this header.

    Identity source of truth (V240-001 architecture-accepted, 2026-05-21):
    No production ASGI server (uvicorn, granian, hypercorn) populates
    ``scope["extensions"]["tls"]["peer_cert"]``.  Tom spike 2026-05-21 confirmed
    this on all three candidates.  The peer_cert TLS-extension path is therefore
    NOT used — ``x-spiffe-id`` (Caddy-injected or install.sh-injected) is the
    sole SPIFFE identity source.  ``_get_peer_cert_uri()`` has been removed;
    it was dead code at runtime.

    Header handling (Option C — Laura ACCEPT-WITH-RESIDUAL 2026-05-19):
    1. ``x-spiffe-id-peer-cert``: always stripped and re-set to an empty byte
       string (forge-prevention — no client may set this header to a trusted
       value).  The peer_cert ASGI extension is permanently absent; the value
       is always empty.
    2. ``x-spiffe-id``: preserved ONLY when ``X-Caddy-Verified-Secret`` is
       present and valid (HMAC match against per-install caddy_internal_hmac).
       If the secret is absent or invalid the header is stripped here, so a
       direct-mesh forge attempt never reaches ``require_spiffe_id()``.

    Cross-references:
    - Tom V240-001 spike: internal-docs/yashigani/tom-v240-001-asgi-spike.md
    - Iris post-spike reframe: internal-docs/yashigani/iris-v240-001-post-spike-reframe.md
    - YSG-RISK-047: CLOSED-ARCHITECTURE-ACCEPTED 2026-05-21
    - YSG-RISK-012b: LOW residual, four compensating controls active
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            # peer_cert is permanently absent on all ASGI servers (V240-001 spike,
            # 2026-05-21).  Set the server-controlled header to empty bytes so
            # downstream code always sees a server-set (never client-set) value.
            peer_cert_bytes = b""
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

            # Append the server-set peer-cert value (always empty — peer_cert ASGI
            # extension absent on all production ASGI servers per V240-001 spike).
            headers.append((peer_cert_header_name, peer_cert_bytes))
            scope = dict(scope)
            scope["headers"] = headers

        await self._app(scope, receive, send)


__all__ = ["SpiffePeerCertMiddleware", "_extract_spiffe_uri_from_cert"]
