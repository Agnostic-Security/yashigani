"""
Redis response cache — Phase 6.

Cache key = SHA-256(tenant_id + json-normalized body).
Only caches CLEAN inspection results (action=FORWARDED).
Max TTL 3600s enforced server-side. Disabled per-tenant by default.
Binary/non-JSON bodies skip caching.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

MAX_TTL = 3600
DEFAULT_TTL = 300
_CACHE_KEY_PREFIX = "rc:"


class ResponseCache:
    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def get(self, tenant_id: str, body: bytes) -> Optional[bytes]:
        try:
            key = self._make_key(tenant_id, body)
            value = self._redis.get(key)
            if value is not None:
                _inc("hits", tenant_id)
                return value
            _inc("misses", tenant_id)
            return None
        except Exception as exc:
            logger.error("ResponseCache.get error: %s", exc)
            return None

    def set(self, tenant_id: str, body: bytes, response_bytes: bytes, ttl: int = DEFAULT_TTL) -> None:
        effective_ttl = min(ttl, MAX_TTL)
        try:
            key = self._make_key(tenant_id, body)
            self._redis.setex(key, effective_ttl, response_bytes)
        except Exception as exc:
            logger.error("ResponseCache.set error: %s", exc)

    def invalidate(self, tenant_id: str) -> int:
        try:
            pattern = f"{_CACHE_KEY_PREFIX}{tenant_id[:8]}:*"
            keys = self._redis.keys(pattern)
            if keys:
                self._redis.delete(*keys)
                _inc_evictions(tenant_id, len(keys))
                return len(keys)
        except Exception as exc:
            logger.error("ResponseCache.invalidate error: %s", exc)
        return 0

    def get_tenant_config(self, tenant_id: str) -> dict:
        try:
            cfg_key = f"rc:cfg:{tenant_id}"
            data = self._redis.hgetall(cfg_key)
            if data:
                return {
                    "enabled": data.get(b"enabled", b"false") == b"true",
                    "ttl_seconds": int(data.get(b"ttl_seconds", DEFAULT_TTL)),
                }
        except Exception:
            logger.debug("response_cache: tenant config read failed for tenant_id=%s", tenant_id, exc_info=True)
        return {"enabled": False, "ttl_seconds": DEFAULT_TTL}

    def set_tenant_config(self, tenant_id: str, enabled: bool, ttl_seconds: int) -> None:
        cfg_key = f"rc:cfg:{tenant_id}"
        self._redis.hset(cfg_key, mapping={
            "enabled": "true" if enabled else "false",
            "ttl_seconds": min(ttl_seconds, MAX_TTL),
        })

    def list_tenant_configs(self) -> list[dict]:
        """Return every per-tenant cache config currently stored in Redis.

        YSG-RISK-143: this is now the SINGLE source of truth for
        GET /admin/cache (list). Previously the list endpoint queried a
        Postgres ``cache_config`` table that no code path ever wrote to,
        while get/set/invalidate all read/write Redis via this class — so a
        PUT'd config could never appear in the list. Reading and writing
        MUST hit the same store; this method reads the exact keys
        get_tenant_config()/set_tenant_config() use (``rc:cfg:<tenant_id>``).
        """
        cfg_prefix = "rc:cfg:"
        try:
            keys = self._redis.keys(f"{cfg_prefix}*")
        except Exception as exc:
            logger.error("ResponseCache.list_tenant_configs error: %s", exc)
            raise

        results: list[dict] = []
        for key in keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            if not key_str.startswith(cfg_prefix):
                continue
            tenant_id = key_str[len(cfg_prefix):]
            try:
                data = self._redis.hgetall(key)
            except Exception:
                logger.debug(
                    "response_cache: tenant config read failed during list for "
                    "tenant_id=%s", tenant_id, exc_info=True,
                )
                continue
            results.append({
                "tenant_id": tenant_id,
                "enabled": _hval(data, "enabled", "false") == "true",
                "ttl_seconds": int(_hval(data, "ttl_seconds", str(DEFAULT_TTL))),
            })
        return sorted(results, key=lambda r: r["tenant_id"])

    @staticmethod
    def _make_key(tenant_id: str, body: bytes) -> str:
        normalized = _normalize_body(body)
        content = tenant_id.encode() + b":" + normalized
        digest = hashlib.sha256(content).hexdigest()[:24]
        return f"{_CACHE_KEY_PREFIX}{tenant_id[:8]}:{digest}"

    @staticmethod
    def should_cache(body: bytes) -> bool:
        if not body:
            return False
        try:
            json.loads(body)
            return True
        except Exception:
            return False


def _hval(data: dict, field: str, default: str) -> str:
    """Read a hash field from a redis HGETALL result, tolerating both
    bytes-keyed (real redis-py / fakeredis default) and str-keyed
    (decode_responses=True) dicts.
    """
    if field.encode() in data:
        raw = data[field.encode()]
    elif field in data:
        raw = data[field]
    else:
        return default
    return raw.decode() if isinstance(raw, bytes) else str(raw)


def _normalize_body(body: bytes) -> bytes:
    try:
        parsed = json.loads(body)
        return json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
    except Exception:
        return body


def _inc(kind: str, tenant_id: str) -> None:
    try:
        from yashigani.metrics.registry import cache_hits_total, cache_misses_total
        if kind == "hits":
            cache_hits_total.labels(tenant_id=tenant_id).inc()
        else:
            cache_misses_total.labels(tenant_id=tenant_id).inc()
    except Exception:
        logger.debug("response_cache: metric increment failed for cache %s tenant_id=%s", kind, tenant_id, exc_info=True)


def _inc_evictions(tenant_id: str, count: int) -> None:
    try:
        from yashigani.metrics.registry import cache_evictions_total
        cache_evictions_total.labels(tenant_id=tenant_id).inc(count)
    except Exception:
        logger.debug("response_cache: metric increment failed for cache_evictions_total tenant_id=%s", tenant_id, exc_info=True)
