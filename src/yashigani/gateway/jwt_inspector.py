"""
JWT Introspection — Phase 7.

Validates Bearer JWTs using JWKS from the configured endpoint.
Two-level cache: in-memory (5 min TTL) + Redis (5 min TTL).
alg:none rejected unconditionally. exp/iss/aud validated.

JWKS resolution waterfall (Q1 resolution in PLAN_v0.5.0.md):
  1. jwt_config WHERE tenant_id = $tenant_id AND scope = 'tenant'
  2. jwt_config WHERE tenant_id = PLATFORM_SENTINEL AND scope = 'platform'
  3. YASHIGANI_JWKS_URL env var
  4. fail per fail_closed setting (default: True)

Three streams (YASHIGANI_DEPLOYMENT_STREAM):
  opensource  — skip per-tenant lookup, use platform only
  corporate   — per-tenant first, platform fallback
  saas        — per-tenant mandatory

SSRF note (LAURA-2255-010 / CWE-918): PyJWKClient uses urllib.request internally
and bypasses this project's SSRF guard. We no longer use PyJWKClient. Instead we
fetch the JWKS document ourselves via the guarded HttpClient and parse it with
PyJWKSet.from_dict(). This ensures the SSRF guard runs on every fetch — not just
at client-construction time — which is required because PyJWKClient.get_jwk_set()
calls fetch_data() unconditionally on each lookup (cache_keys=True only caches at
the kid level, not the network call).

Last updated: 2026-06-19
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import jwt as pyjwt
from jwt import PyJWKSet

from yashigani.net.http_client import BlockedByPolicy, HttpClient

logger = logging.getLogger(__name__)

PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"
JWKS_CACHE_TTL = 300  # 5 minutes
_MEMORY_CACHE: dict[str, tuple[float, object]] = {}


@dataclass
class JWTConfig:
    jwks_url: str
    issuer: str
    audience: str
    fail_closed: bool = True
    scope: str = "tenant"


@dataclass
class JWTInspectionResult:
    valid: bool
    sub: Optional[str] = None
    tenant_id: Optional[str] = None
    error: Optional[str] = None
    claims: dict = field(default_factory=dict)


class JWTInspector:
    """
    Validates Bearer JWTs against the configured JWKS endpoint.
    Instantiated once per process.
    """

    ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client
        self._deployment_stream = os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "opensource")

    async def inspect(self, token: str, tenant_id: str = PLATFORM_TENANT_ID) -> JWTInspectionResult:
        try:
            return await self._inspect(token, tenant_id)
        except Exception as exc:
            logger.error("JWTInspector unexpected error: %s", exc)
            return JWTInspectionResult(valid=False, error=type(exc).__name__)

    async def _inspect(self, token: str, tenant_id: str) -> JWTInspectionResult:
        # Parse header once — used for alg:none check AND kid extraction.
        try:
            header = pyjwt.get_unverified_header(token)
            if header.get("alg", "").lower() == "none":
                _inc_counter("invalid")
                return JWTInspectionResult(valid=False, error="alg:none rejected")
        except Exception as exc:
            _inc_counter("invalid")
            return JWTInspectionResult(valid=False, error=f"header_parse_error: {exc}")

        kid = header.get("kid")

        config = await self._resolve_config(tenant_id)
        if config is None:
            _inc_counter("fetch_error")
            return JWTInspectionResult(valid=False, error="no_jwks_configured")

        try:
            jwk_set = await self._fetch_jwks(config.jwks_url)
        except BlockedByPolicy as exc:
            logger.warning("JWKS fetch blocked by SSRF policy for %s: %s", config.jwks_url, exc)
            _inc_counter("fetch_error")
            return JWTInspectionResult(valid=False, error="jwks_ssrf_blocked")
        except Exception as exc:
            logger.warning("JWKS fetch failed for %s: %s", config.jwks_url, exc)
            _inc_counter("fetch_error")
            if config.fail_closed:
                return JWTInspectionResult(valid=False, error="jwks_fetch_failed")
            return JWTInspectionResult(valid=True, error="jwks_fetch_failed_fail_open")

        try:
            signing_key = _get_signing_key_from_set(jwk_set, kid)
            options: dict[str, object] = {}
            decode_kwargs: dict = dict(
                algorithms=self.ALLOWED_ALGORITHMS,
                options=options,
            )
            if config.audience:
                decode_kwargs["audience"] = config.audience
            if config.issuer:
                decode_kwargs["issuer"] = config.issuer
            claims = pyjwt.decode(token, signing_key.key, **decode_kwargs)
            _inc_counter("valid")
            return JWTInspectionResult(
                valid=True,
                sub=claims.get("sub"),
                tenant_id=claims.get("tenant_id") or tenant_id,
                claims=claims,
            )
        except Exception as exc:
            if isinstance(exc, pyjwt.ExpiredSignatureError):
                _inc_counter("expired")
                return JWTInspectionResult(valid=False, error="token_expired")
            _inc_counter("invalid")
            return JWTInspectionResult(valid=False, error=type(exc).__name__)

    async def _resolve_config(self, tenant_id: str) -> Optional[JWTConfig]:
        if self._deployment_stream != "opensource" and tenant_id != PLATFORM_TENANT_ID:
            config = await self._load_tenant_config(tenant_id, scope="tenant")
            if config:
                return config

        config = await self._load_tenant_config(PLATFORM_TENANT_ID, scope="platform")
        if config:
            return config

        jwks_url = os.getenv("YASHIGANI_JWKS_URL")
        if jwks_url:
            return JWTConfig(
                jwks_url=jwks_url,
                issuer=os.getenv("YASHIGANI_JWT_ISSUER", ""),
                audience=os.getenv("YASHIGANI_JWT_AUDIENCE", ""),
                fail_closed=os.getenv("YASHIGANI_JWT_FAIL_CLOSED", "true").lower() == "true",
                scope="platform",
            )
        return None

    async def _load_tenant_config(self, tenant_id: str, scope: str) -> Optional[JWTConfig]:
        try:
            import uuid
            from yashigani.db.postgres import get_pool
            pool = get_pool()
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT jwks_url, issuer, audience, fail_closed, scope "
                    "FROM jwt_config WHERE tenant_id = $1 AND scope = $2 LIMIT 1",
                    uuid.UUID(tenant_id), scope,
                )
                if row:
                    return JWTConfig(
                        jwks_url=row["jwks_url"],
                        issuer=row["issuer"],
                        audience=row["audience"],
                        fail_closed=row["fail_closed"],
                        scope=row["scope"],
                    )
        except Exception as exc:
            logger.warning("jwt_config DB lookup failed: %s", exc)
        return None

    async def _fetch_jwks(self, jwks_url: str) -> PyJWKSet:
        """Fetch the JWKS document via the SSRF-guarded HttpClient.

        Two-level cache (memory + Redis) with JWKS_CACHE_TTL TTL.  The
        HttpClient._check_policy() runs on every fetch — not just the first
        one — because PyJWKClient.get_jwk_set() calls urllib.request on every
        lookup and that bypass cannot be contained (LAURA-2255-010 / CWE-918).
        By fetching ourselves we guarantee the SSRF guard runs for every
        network call, cached or not; a cache hit returns the parsed PyJWKSet
        without touching the network.

        Raises
        ------
        BlockedByPolicy
            If ``jwks_url`` violates the SSRF policy.  Caller maps this to
            ``jwks_ssrf_blocked`` (always fail-closed, regardless of
            ``fail_closed`` config).
        httpx.HTTPError / OSError
            Network errors; caller handles per ``fail_closed`` flag.
        """
        url_hash = hashlib.sha256(jwks_url.encode()).hexdigest()[:16]
        now = time.monotonic()

        # Policy check BEFORE any cache/network access. BlockedByPolicy is
        # raised here and must not be caught below — it must surface to the
        # caller so it can be treated as unconditionally fail-closed.
        _http = HttpClient(timeout_s=10.0)
        _http._check_policy(jwks_url)

        # Memory cache hit — no network call.
        if jwks_url in _MEMORY_CACHE:
            cached_at, jwk_set = _MEMORY_CACHE[jwks_url]
            if now - cached_at < JWKS_CACHE_TTL:
                _hit_counter("memory")
                return jwk_set

        # Redis cache hit — avoid re-fetching from the IdP.
        if self._redis is not None:
            try:
                cached = self._redis.get(f"jwks:{url_hash}")
                if cached:
                    _hit_counter("redis")
                    jwk_data = json.loads(cached)
                    jwk_set = PyJWKSet.from_dict(jwk_data)
                    _MEMORY_CACHE[jwks_url] = (now, jwk_set)
                    return jwk_set
            except Exception:
                logger.debug("jwt_inspector: Redis JWKS cache read failed for url_hash=%s", url_hash, exc_info=True)

        # Guarded network fetch — HttpClient enforces SSRF policy on the
        # actual HTTP call (scheme, host, IP-category).
        resp = await _http.get(jwks_url)
        resp.raise_for_status()
        jwk_data = resp.json()

        jwk_set = PyJWKSet.from_dict(jwk_data)
        _MEMORY_CACHE[jwks_url] = (now, jwk_set)

        if self._redis is not None:
            try:
                self._redis.setex(f"jwks:{url_hash}", JWKS_CACHE_TTL, json.dumps(jwk_data))
            except Exception:
                logger.debug("jwt_inspector: Redis JWKS cache write failed for url_hash=%s", url_hash, exc_info=True)

        return jwk_set


def _get_signing_key_from_set(jwk_set: PyJWKSet, kid: Optional[str]):
    """Return the PyJWK in ``jwk_set`` that matches ``kid``.

    Replaces PyJWKClient.get_signing_key_from_jwt() so we can use a
    PyJWKSet obtained via our own guarded HTTP fetch rather than via
    PyJWKClient (which uses urllib.request internally — LAURA-2255-010).

    Raises
    ------
    pyjwt.PyJWKClientError
        If no signing key matching ``kid`` is found in the set.
    """
    from jwt.exceptions import PyJWKClientError

    signing_keys = [
        k for k in jwk_set.keys
        if k.public_key_use in ("sig", None) and k.key_id
    ]
    if not signing_keys:
        raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

    if kid:
        for k in signing_keys:
            if k.key_id == kid:
                return k
        raise PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')

    # No kid in token header — use the first signing key (common for single-key sets).
    return signing_keys[0]


def _inc_counter(result: str) -> None:
    try:
        from yashigani.metrics.registry import jwt_validations_total
        jwt_validations_total.labels(result=result).inc()
    except Exception:
        logger.debug("jwt_inspector: metric increment failed for jwt_validations_total result=%s", result, exc_info=True)


def _hit_counter(layer: str) -> None:
    try:
        from yashigani.metrics.registry import jwks_cache_hits_total
        jwks_cache_hits_total.labels(layer=layer).inc()
    except Exception:
        logger.debug("jwt_inspector: metric increment failed for jwks_cache_hits_total layer=%s", layer, exc_info=True)
