"""
EX-231-10 Layer B — Caddy HMAC shared-secret verifier.

Last updated: 2026-04-29T17:45:00+01:00

Layer A (EX-231-09, network isolation) ensures only Caddy can reach
backoffice:8443 and gateway:8080 at the Docker-network layer. Layer B adds a
cryptographic marker that closes the residual: a container on caddy_internal
that already holds a valid mTLS cert (e.g. prometheus_client cert) and forges
X-SPIFFE-ID can still reach internal endpoints. Without Layer B this yields
HTTP 200. With Layer B active it yields 401 because the attacker cannot know
the per-install ``caddy_internal_hmac`` secret.

Design (static-shared-secret variant — Caddy 2 has no inline HMAC module):
- ``install.sh`` generates ``caddy_internal_hmac`` (32-byte hex, 64 chars).
- Caddy reads ``CADDY_INTERNAL_HMAC`` env var and injects the raw value as
  ``X-Caddy-Verified-Secret`` on every ``reverse_proxy`` to backoffice/gateway.
  Caddy also strips any inbound ``X-Caddy-Verified-Secret`` (snippet
  ``inject-caddy-verified`` in Caddyfile.selfsigned and Caddyfile.acme).
  IMPORTANT: the Caddyfile uses ``{$CADDY_INTERNAL_HMAC}`` (parse-time env
  substitution) NOT ``{env.CADDY_INTERNAL_HMAC}`` (request-time placeholder
  that is NOT resolved in header_up directives). This distinction was the root
  cause of the Round 1 failure (2026-04-29).
- ``load_caddy_secret()`` is called at lifespan startup of both backoffice and
  gateway.  If the secret cannot be loaded, a ``RuntimeError`` is raised and
  the container refuses to start (fail-closed per CLAUDE.md §3).
- ``CaddyVerifiedMiddleware`` runs on every request.  It allows:
  - ``/healthz`` (gateway) and ``/admin/healthz`` (backoffice) and ``/readyz``
    unconditionally (inside-pod healthcheck exec hits localhost directly, not
    via Caddy, so it carries no header).
  - Everything else → checks ``X-Caddy-Verified-Secret`` with
    ``hmac.compare_digest``.  Absent or mismatched → 401 JSON response.
  - If ``_caddy_secret`` is ``None`` at middleware evaluation time (lifespan
    startup silently failed) → 401, never pass-through.

Security note (replay):
Replay is accepted as residual risk (DevOps evidence doc da3dc08, §HMAC
Pattern).  The secret only flows over caddy_internal — the mTLS-protected
bridge. An attacker able to sniff this network has already broken mTLS, which
is a more severe finding.  The secret is rotated on every ``install.sh
--upgrade`` restart.

Closes: EX-231-10 Layer B (Engineering dispatch 2026-04-29, Round 2).
Ref: captain-layer-b-2026-04-29.md (Agnostic Security Internal/Compliance).
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_log = logging.getLogger(__name__)

# Module-level secret store.  Set by load_caddy_secret() at lifespan startup.
# Never None after a successful startup — fail-closed enforced in middleware.
_caddy_secret: str | None = None

# Header Caddy sets (and strips inbound) on every reverse_proxy upstream call.
_HEADER_NAME = "x-caddy-verified-secret"   # lowercase: Starlette normalises

# Paths that the inside-pod healthcheck exec hits directly (no Caddy hop) and
# therefore carry no X-Caddy-Verified-Secret header.  Exact-match only — no
# prefix match to avoid /healthzx bypass surface.
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/healthz",          # gateway + backoffice
    "/admin/healthz",    # backoffice (if present)
    "/readyz",           # gateway (from endpoint_ratelimit.py + ddos.py)
    "/livez",            # future-proof (not currently used but in same pattern)
})


def load_caddy_secret() -> str:
    """Load the per-install caddy_internal_hmac secret.

    Call this exactly once from each app's lifespan startup block.  It sets
    the module-level ``_caddy_secret`` and returns the value.

    Resolution order:
    1. ``CADDY_INTERNAL_HMAC`` environment variable.
    2. File at ``{YASHIGANI_SECRETS_DIR}/caddy_internal_hmac``
       (default dir: ``/run/secrets``).

    Raises:
        RuntimeError: if the secret cannot be read or is empty.  The caller
            (lifespan) must NOT swallow this — let it propagate so uvicorn
            exits non-zero and the orchestrator surfaces the fault.
    """
    global _caddy_secret

    secret = os.environ.get("CADDY_INTERNAL_HMAC", "").strip()

    if not secret:
        secrets_dir = os.environ.get("YASHIGANI_SECRETS_DIR", "/run/secrets")
        secret_path = os.path.join(secrets_dir, "caddy_internal_hmac")
        try:
            with open(secret_path) as fh:
                secret = fh.read().strip()
        except OSError as exc:
            raise RuntimeError(
                f"CADDY_INTERNAL_HMAC not set and {secret_path!r} not readable "
                f"— Layer B fail-closed: {exc}"
            ) from exc

    if not secret:
        raise RuntimeError(
            "CADDY_INTERNAL_HMAC is empty — Layer B fail-closed. "
            "Ensure install.sh has generated caddy_internal_hmac."
        )

    _caddy_secret = secret
    _log.info(
        "Layer B: caddy_internal_hmac loaded (%d chars)", len(secret)
    )
    return secret


class CaddyVerifiedMiddleware(BaseHTTPMiddleware):
    """Starlette/FastAPI middleware that enforces the Layer B shared-secret gate.

    Every request (except the healthcheck allow-list) must carry
    ``X-Caddy-Verified-Secret`` matching the per-install ``caddy_internal_hmac``
    secret.  Mismatch or absent header → 401.

    Caddy injects this header on every ``reverse_proxy`` upstream hop and strips
    any inbound value first (``inject-caddy-verified`` snippet), so only
    legitimate Caddy-proxied requests carry the correct value.

    Fail-closed: if ``_caddy_secret`` is ``None`` at evaluation time (startup
    silently broke without raising) the middleware returns 401 and logs CRITICAL
    — it never passes the request through.

    Healthcheck exemption: ``/healthz``, ``/admin/healthz``, ``/readyz``,
    ``/livez`` are exempt because inside-pod healthcheck execs hit localhost
    directly without going through Caddy and therefore carry no header.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Healthcheck paths bypass — exact-match only.
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        # Fail-closed sentinel: if _caddy_secret is None, startup silently
        # failed to set it.  Return 401 and alert; never pass through.
        secret = _caddy_secret
        if secret is None:
            _log.critical(
                "Layer B: _caddy_secret is None at dispatch — lifespan startup "
                "failed silently.  Returning 401 fail-closed."
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "CADDY_VERIFIED_REQUIRED",
                    "detail": (
                        "Layer B caddy_internal_hmac not loaded — "
                        "service misconfigured, refusing request"
                    ),
                },
            )

        header_val = request.headers.get(_HEADER_NAME, "")

        if not header_val:
            _log.warning(
                "Layer B: missing X-Caddy-Verified-Secret on %s %s — 401",
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "CADDY_VERIFIED_REQUIRED",
                    "detail": "X-Caddy-Verified-Secret header required",
                },
            )

        try:
            match = hmac.compare_digest(
                header_val.encode("ascii"),
                secret.encode("ascii"),
            )
        except (UnicodeEncodeError, ValueError):
            # Non-ASCII in header value — treat as mismatch.
            match = False

        if not match:
            _log.warning(
                "Layer B: X-Caddy-Verified-Secret mismatch on %s %s — 401",
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "CADDY_VERIFIED_REQUIRED",
                    "detail": "X-Caddy-Verified-Secret header value invalid",
                },
            )

        return await call_next(request)


def validate_caddy_secret(header_value: str) -> bool:
    """Return True if *header_value* matches the loaded per-install secret.

    Used by SpiffePeerCertMiddleware (Option C, Laura ACCEPT-WITH-RESIDUAL) to
    AND-couple the HMAC gate with ``x-spiffe-id`` preservation.  Only requests
    that carry a valid ``X-Caddy-Verified-Secret`` are allowed to pass an
    ``x-spiffe-id`` header through to route handlers.  Requests without a
    matching secret (direct-mesh forge attempt) have their ``x-spiffe-id``
    stripped.

    Returns False if:
    - ``_caddy_secret`` is None (lifespan not yet run — fail-closed).
    - ``header_value`` is empty.
    - ``header_value`` does not match (constant-time compare_digest).
    - ``header_value`` contains non-ASCII (treated as mismatch).
    """
    secret = _caddy_secret
    if secret is None or not header_value:
        return False
    try:
        return hmac.compare_digest(
            header_value.encode("ascii"),
            secret.encode("ascii"),
        )
    except (UnicodeEncodeError, ValueError):
        return False


__all__ = ["load_caddy_secret", "CaddyVerifiedMiddleware", "validate_caddy_secret"]
