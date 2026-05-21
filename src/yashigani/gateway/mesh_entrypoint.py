"""
Yashigani Gateway — Internal mesh ASGI entrypoint (plain HTTP, port 8081).

Builds the same FastAPI application as entrypoint.py via _build_app(mesh_mode=True).
The mesh_mode flag skips the two mTLS-specific middleware layers:
  - SpiffePeerCertMiddleware (reads TLS peer cert from ASGI scope — N/A on plain HTTP)
  - CaddyVerifiedMiddleware  (enforces X-Caddy-Verified-Secret — N/A for direct mesh calls)

Security model:
  Port 8080 (mTLS) — reached via Caddy only; protected by:
    (1) Docker network isolation: caddy_internal only
    (2) mTLS: client cert required (ssl.CERT_REQUIRED)
    (3) CaddyVerifiedMiddleware: X-Caddy-Verified-Secret header check
    (4) SpiffePeerCertMiddleware: SPIFFE peer cert URI forwarding

  Port 8081 (plain HTTP) — reached by Open WebUI only; protected by:
    (1) Docker network isolation: data network only (never host-mapped)
    (2) AgentAuthMiddleware: Open WebUI presents its OPENAI_API_KEY
    (3) LicenseEnforcementMiddleware: licence state enforced

Open WebUI is in-cluster (same Docker bridge / K8s namespace) and does not
require cryptographic auth at the transport layer — network isolation on the
`data` bridge is sufficient, consistent with how gateway→redis, gateway→OPA,
gateway→ollama connections are protected.

Last updated: 2026-05-17T00:00:00+00:00
"""
from __future__ import annotations

from yashigani.gateway.entrypoint import _build_app

# Build the same gateway app with mesh_mode=True (no CaddyVerified / no Spiffe).
# All other middleware (AgentAuth, LicenseEnforcement, Prometheus, etc.) are active.
app = _build_app(mesh_mode=True)
