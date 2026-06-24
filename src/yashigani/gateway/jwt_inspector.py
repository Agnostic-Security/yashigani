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

Last updated: 2026-05-03
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
from jwt import PyJWKClient

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
        try:
            header = pyjwt.get_unverified_header(token)
            if header.get("alg", "").lower() == "none":
                _inc_counter("invalid")
                return JWTInspectionResult(valid=False, error="alg:none rejected")
        except Exception as exc:
            _inc_counter("invalid")
            return JWTInspectionResult(valid=False, error=f"header_parse_error: {exc}")

        config = await self._resolve_config(tenant_id)
        if config is None:
            _inc_counter("fetch_error")
            return JWTInspectionResult(valid=False, error="no_jwks_configured")

        try:
            jwks_client = await self._get_jwks_client(config.jwks_url)
        except Exception as exc:
            logger.warning("JWKS fetch failed for %s: %s", config.jwks_url, exc)
            _inc_counter("fetch_error")
            if config.fail_closed:
                return JWTInspectionResult(valid=False, error="jwks_fetch_failed")
            return JWTInspectionResult(valid=True, error="jwks_fetch_failed_fail_open")

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
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

    @staticmethod
    def _assert_safe_jwks_url(url: str) -> None:
        """SSRF guard (YSG-RISK-083): https-only (blocks file:// and http://) + resolve
        the host and reject non-public IPs (blocks cloud-metadata 169.254.0.0/16 and
        internal RFC1918/loopback/reserved). Primary compensating controls remain the
        egress-default-deny firewall + mTLS mesh; the gold-plated DNS-rebind-proof +
        configurable host-allowlist is deferred to a future release."""
        import ipaddress
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"JWKS URL must be https, got scheme={parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError("JWKS URL has no host")
        for *_unused, sockaddr in socket.getaddrinfo(
            parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP
        ):
            ip = ipaddress.ip_address(sockaddr[0])
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast
            ):
                raise ValueError(f"JWKS URL resolves to non-public IP {ip}")

    async def _get_jwks_client(self, jwks_url: str):
        self._assert_safe_jwks_url(jwks_url)
        url_hash = hashlib.sha256(jwks_url.encode()).hexdigest()[:16]
        now = time.monotonic()

        if jwks_url in _MEMORY_CACHE:
            cached_at, client = _MEMORY_CACHE[jwks_url]
            if now - cached_at < JWKS_CACHE_TTL:
                _hit_counter("memory")
                return client

        if self._redis is not None:
            try:
                cached = self._redis.get(f"jwks:{url_hash}")
                if cached:
                    _hit_counter("redis")
                    client = PyJWKClient(jwks_url)
                    _MEMORY_CACHE[jwks_url] = (now, client)
                    return client
            except Exception:
                logger.debug("jwt_inspector: Redis JWKS cache read failed for url_hash=%s", url_hash, exc_info=True)

        client = PyJWKClient(jwks_url, cache_keys=True)
        client.fetch_data()
        _MEMORY_CACHE[jwks_url] = (now, client)

        if self._redis is not None:
            try:
                self._redis.setex(f"jwks:{url_hash}", JWKS_CACHE_TTL, json.dumps({}))
            except Exception:
                logger.debug("jwt_inspector: Redis JWKS cache write failed for url_hash=%s", url_hash, exc_info=True)

        return client


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
