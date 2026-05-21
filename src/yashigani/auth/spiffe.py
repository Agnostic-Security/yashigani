"""
SPIFFE URI ACL gate — application-layer identity check for service-to-service
callers.

Last updated: 2026-05-21T00:00:00+01:00 (V240-001: remove peer_cert dual-resolution — architecture-accepted)

Architectural decision (V240-001, 2026-05-21)
----------------------------------------------
``scope["extensions"]["tls"]["peer_cert"]`` is NOT populated by any production-grade
ASGI server (uvicorn, granian, hypercorn) — confirmed by Tom spike 2026-05-21.
The ``x-spiffe-id-peer-cert`` dual-resolution preference path (previously: prefer
peer-cert header over Caddy-set header) has been removed.  The sole SPIFFE
identity source is the Caddy-injected ``X-SPIFFE-ID`` header.

Trust model: ``X-SPIFFE-ID`` on the Caddy-proxied path is trustworthy because:
1. Caddy strips any inbound ``X-SPIFFE-ID`` at the client→Caddy hop.
2. Caddy re-injects from ``{http.request.tls.client.san.uris.0}`` (validated
   TLS peer cert URI SAN).
3. ``SpiffePeerCertMiddleware`` (Option C) AND-couples header preservation with
   a valid ``X-Caddy-Verified-Secret`` HMAC — without the HMAC secret the header
   is stripped before this gate runs.
4. This ACL gate enforces an endpoint-level allow-list from
   ``service_identities.yaml``.

The install.sh direct-path injection (``X-SPIFFE-ID: spiffe://yashigani.internal/backoffice``)
is trustworthy because install.sh runs inside the backoffice container (the
only entity holding backoffice_client.crt) and because the HMAC check is
enforced before this gate via ``CaddyVerifiedMiddleware`` Layer B.

Threat model and trust boundary
-------------------------------
Every request arriving at /internal/metrics (and future gated endpoints) passes
through Caddy, our internal TLS edge and CA. Caddy validates the peer's client
certificate against the internal CA and forwards the first URI SAN of the
verified peer cert as the ``X-SPIFFE-ID`` header. Caddy strips any inbound
occurrence of that header before setting its own — a co-tenant on the internal
bridge network cannot forge the value.

Python's trust in the header depends on the transport hop that delivered it:
the upstream connection from Caddy to gateway/backoffice is already on
core-plane mTLS (see internal-mtls Caddyfile snippet and Uvicorn's
``ssl_cert_reqs=CERT_REQUIRED``). Any request on that listener that claims a
SPIFFE ID therefore came via Caddy. We do NOT honour ``X-SPIFFE-ID`` on
public-facing paths — this module is only attached to internal endpoints.

Contract
--------
``require_spiffe_id(path)`` returns a FastAPI dependency that:

  * 401 if the header is missing (``no_spiffe_id``)
  * 403 if the ACL table has no entry for this path (``no_acl_for_path``)
  * 403 if the header value is not in the allowlist (``spiffe_id_not_allowed``)
  * 200-passthrough (returns the caller SPIFFE ID) on success

The ACL source is the same ``service_identities.yaml`` manifest used by the
PKI issuer. This keeps the allowlist in one place: the file that also mints
the cert that carries the URI SAN, reviewed under git.

Fail-closed semantics
---------------------
If the manifest is missing or unreadable at initial load, the ACL cache is an
empty dict — every gated path returns 403.  There is no silent open mode.

On TTL-triggered refresh, a parse or I/O failure retains the **previous** good
cache (retain-on-parse-failure). This prevents a transient manifest edit or
mid-write file state from turning into an outage.  The failure is logged at
CRITICAL so operators are alerted without a service interruption.

Cache + TTL
-----------
The manifest is loaded lazily on the first gate call. After loading it is
cached for ``YASHIGANI_SPIFFE_ACL_TTL_SECONDS`` seconds (default 60). On
every gate call the cached age is checked; if stale, a reload is attempted.
SVID revocation therefore propagates within one TTL window — satisfying ASVS
v5 V8.3.3 (permission propagation across services within defined TTL).

Closes: ASVS v5 V8.3.3
Stage B report: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-stage-b-class3-2026-04-28.md §8.1
"""
from __future__ import annotations

import logging
import os
import time
from threading import Lock
from typing import Any, Callable, Coroutine, Optional, Tuple

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# Cache state: (loaded_at_monotonic, acl_dict)
# None means "not yet loaded".
_CACHE: Optional[Tuple[float, dict[str, frozenset[str]]]] = None
_CACHE_LOCK = Lock()

_DEFAULT_MANIFEST_PATH = "/etc/yashigani/service_identities.yaml"

# Sole identity header — both lower-case (FastAPI lowercases on lookup):
#
# `x-spiffe-id` is the CADDY-SET header on the Caddy-proxied path.
# Caddy validates the peer cert and re-emits the URI SAN here.
# Caddy strips any inbound `x-spiffe-id` before setting its own value,
# so on the Caddy-proxied path this is trustworthy.
#
# `x-spiffe-id-peer-cert` (previously: server-controlled peer-cert header
# from SpiffePeerCertMiddleware) is still STRIPPED and overwritten to an
# empty byte string by SpiffePeerCertMiddleware — but it is no longer read
# here.  The peer_cert ASGI extension is permanently absent on all production
# ASGI servers (Tom V240-001 spike 2026-05-21: uvicorn 0.47.0 / granian 2.7.4 /
# hypercorn 0.18.0 — all FAIL the peer_cert gate).  YSG-RISK-047 closed as
# ARCHITECTURE-ACCEPTED.  Caddy-mediated identity is the architectural answer.
_HEADER_NAME = "x-spiffe-id"
_DEFAULT_TTL_SECONDS = 60

# LF-SPIFFE-RETAIN: maximum time a stale ACL cache is retained after a
# parse/I/O failure.  After this window the gate fails-closed (returns empty
# ACL → 403 for all gated paths) and logs CRITICAL every subsequent attempt.
# Env-tunable: YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS (default: 86400 = 24h).
_DEFAULT_MAX_STALE_SECONDS = 86400

# Monotonic timestamp of the LAST successful manifest load.  None = never loaded.
_LAST_GOOD_LOAD_AT: float | None = None


def _get_ttl() -> float:
    """Return the configured TTL in seconds (env-tunable, default 60)."""
    raw = os.getenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS))
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "spiffe-gate: invalid YASHIGANI_SPIFFE_ACL_TTL_SECONDS=%r — using default %s",
            raw,
            _DEFAULT_TTL_SECONDS,
        )
        return float(_DEFAULT_TTL_SECONDS)


def _get_max_stale() -> float:
    """Return the maximum stale retention window in seconds (env-tunable, default 86400 = 24h).

    LF-SPIFFE-RETAIN: caps how long retain-on-parse-failure can keep a stale
    ACL alive.  After this window, the gate fails-closed-empty.
    """
    raw = os.getenv("YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS", str(_DEFAULT_MAX_STALE_SECONDS))
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "spiffe-gate: invalid YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS=%r — using default %s",
            raw,
            _DEFAULT_MAX_STALE_SECONDS,
        )
        return float(_DEFAULT_MAX_STALE_SECONDS)


def _read_manifest() -> dict[str, frozenset[str]]:
    """Read and parse the manifest from disk. Raises on any failure."""
    manifest_path = os.getenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", _DEFAULT_MANIFEST_PATH
    )
    # Local import so tests can monkeypatch load_manifest on the identity
    # module without racing this module's import.
    from yashigani.pki.identity import load_manifest

    manifest = load_manifest(manifest_path)
    return dict(manifest.endpoint_acls)


def _load_acls() -> dict[str, frozenset[str]]:
    """Return the current ACL dict, refreshing if the TTL has expired.

    First call: loads from disk; on failure returns {} (fail-closed).
    Subsequent calls within TTL: returns cached value.
    TTL-expired calls: attempts reload; on failure retains previous cache
    and logs CRITICAL (retain-on-parse-failure — avoids outage during
    transient manifest edits).

    LF-SPIFFE-RETAIN: retain-on-parse-failure is bounded by
    YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS (default 86400 = 24h).  After
    the bound is exceeded, the gate fails-closed-empty and continues logging
    CRITICAL on every retry until the manifest is fixed.
    """
    global _CACHE, _LAST_GOOD_LOAD_AT
    ttl = _get_ttl()
    max_stale = _get_max_stale()
    now = time.monotonic()

    # Fast path — check without the lock first (double-checked locking).
    cache = _CACHE
    if cache is not None:
        loaded_at, acls = cache
        if (now - loaded_at) <= ttl:
            return acls

    with _CACHE_LOCK:
        # Re-read under lock to avoid stampede.
        cache = _CACHE
        now = time.monotonic()
        if cache is not None:
            loaded_at, acls = cache
            if (now - loaded_at) <= ttl:
                return acls

        # Reload is due (either first load or TTL expired).
        try:
            fresh = _read_manifest()
            _CACHE = (time.monotonic(), fresh)
            _LAST_GOOD_LOAD_AT = time.monotonic()
            return fresh
        except Exception as exc:
            if cache is None:
                # First load failed — fail-closed with empty ACL.
                logger.error(
                    "spiffe-gate: initial manifest load failed — "
                    "every gated endpoint will 403: %s",
                    exc,
                )
                _CACHE = (time.monotonic(), {})
                return {}
            else:
                # TTL refresh failed — check whether we are still within the
                # bounded retain window (LF-SPIFFE-RETAIN).
                _, prev_acls = cache
                stale_age = (now - _LAST_GOOD_LOAD_AT) if _LAST_GOOD_LOAD_AT is not None else float("inf")
                if stale_age > max_stale:
                    # Bounded retention exceeded — fail-closed-empty.
                    logger.critical(
                        "spiffe-gate: retain-on-parse-failure exceeded max-stale "
                        "window (%.0fs > %.0fs) — failing closed (empty ACL). "
                        "ALL gated endpoints will 403 until manifest is fixed. "
                        "Error: %s",
                        stale_age, max_stale, exc,
                    )
                    _CACHE = (time.monotonic(), {})
                    return {}
                else:
                    logger.critical(
                        "spiffe-gate: TTL refresh failed — retaining previous ACL cache "
                        "(retain-on-parse-failure, stale %.0fs/%.0fs). "
                        "Resolve manifest error immediately. Error: %s",
                        stale_age, max_stale, exc,
                    )
                    # Bump the timestamp so we don't re-attempt on every request
                    # while the manifest is broken (back-off by one full TTL).
                    _CACHE = (time.monotonic(), prev_acls)
                    return prev_acls


def _reset_cache_for_tests() -> None:
    """Test helper — clear the TTL ACL cache and last-good-load timestamp entirely."""
    global _CACHE, _LAST_GOOD_LOAD_AT
    with _CACHE_LOCK:
        _CACHE = None
        _LAST_GOOD_LOAD_AT = None


def require_spiffe_id(path: str) -> Callable[[Request], Coroutine[Any, Any, str]]:
    """Return a FastAPI dependency that enforces the SPIFFE URI ACL for *path*.

    Usage::

        @app.get(
            "/internal/metrics",
            dependencies=[Depends(require_spiffe_id("/internal/metrics"))],
        )
        async def metrics():
            ...

    The ``path`` argument must match the key under ``endpoint_acls`` in
    ``service_identities.yaml``. It is passed explicitly (rather than read from
    ``request.url.path``) so the ACL wiring is visible in the route source and
    so that trailing-slash or rewrite quirks can't mis-select the rule.
    """

    async def _dep(request: Request) -> str:
        acls = _load_acls()
        allowed = acls.get(path)
        if not allowed:
            # Default-deny: no rule for this path.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="no_acl_for_path",
            )

        # Sole identity source: Caddy-set x-spiffe-id header.
        #
        # Caddy validates the peer cert and injects this header from
        # {http.request.tls.client.san.uris.0}; Caddy strips any inbound
        # x-spiffe-id before setting its own value — a co-tenant cannot forge.
        #
        # SpiffePeerCertMiddleware (Option C) AND-couples header preservation
        # with a valid X-Caddy-Verified-Secret HMAC, so a direct-mesh attacker
        # without the HMAC secret has x-spiffe-id stripped before reaching here.
        #
        # The x-spiffe-id-peer-cert dual-resolution path (previously preferred
        # over x-spiffe-id) has been REMOVED.  No ASGI server populates the
        # peer_cert TLS extension (V240-001 spike, 2026-05-21); that header is
        # always empty.  YSG-RISK-047 closed as ARCHITECTURE-ACCEPTED.
        caller = request.headers.get(_HEADER_NAME)
        if not caller:
            logger.warning(
                "spiffe-gate: 401 no_spiffe_id for path=%s — "
                "x-spiffe-id absent (Caddy-proxied path: Caddy HMAC check failed "
                "or request did not transit Caddy)",
                path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="no_spiffe_id",
            )

        if caller not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="spiffe_id_not_allowed",
            )

        return caller

    return _dep


__all__ = ["require_spiffe_id"]
