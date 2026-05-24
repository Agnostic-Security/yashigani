"""
Yashigani Runtime Settings Service.

Provides DB-backed get/set/list operations with:
  - Seed-on-first-boot from env vars (or class defaults when env unset).
  - RUNTIME_SETTING_CHANGED audit event on every change.
  - Redis pub/sub publish on yashigani:settings:changed so gateway
    consumers (DDoSProtector, RateLimiter) can reload cached values.
  - Short-TTL in-process cache (5 s) so hot-path reads don't hit Postgres
    on every gateway request.

Design notes:
  - DB pool is asyncpg (async).  Service has both async (for backoffice routes)
    and sync (for gateway entrypoint, which is sync at startup) interfaces.
  - sync_seed() is called once at gateway startup.  get_cached() is called
    on the hot path; it returns the in-process cache if < 5 s old, otherwise
    re-reads from DB (or falls back to env/default on error).
  - Writes always go through set() (async) and invalidate the in-process
    cache entry.

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Redis pub/sub channel for settings change notifications.
_PUBSUB_CHANNEL = "yashigani:settings:changed"

# In-process cache TTL (seconds).  Gateway refreshes from DB after this.
_CACHE_TTL_SECONDS = 5.0


class RuntimeSettingsService:
    """
    Async service backed by asyncpg pool.

    Inject via backoffice_state.runtime_settings (initialised in lifespan).
    """

    def __init__(self, pool, redis_client=None) -> None:
        """
        Parameters
        ----------
        pool:
            asyncpg connection pool (from yashigani.db.get_pool()).
        redis_client:
            Optional redis-py client for pub/sub notifications.
            If None, pub/sub is skipped (consumers will rely on TTL-based refresh).
        """
        self._pool = pool
        self._redis = redis_client
        # in-process cache: {key: (value, fetched_at)}
        self._cache: dict[str, tuple[Any, float]] = {}

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Any:
        """
        Return the current value for *key* from DB.

        Returns the class default from KNOWN_SETTINGS if the key is not yet
        seeded, so callers don't need to handle None.
        """
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT value FROM runtime_settings WHERE key = $1", key
                )
            if row is not None:
                return json.loads(row["value"])
        except Exception as exc:
            logger.warning("RuntimeSettingsService.get(%r) DB error: %s — using default", key, exc)

        # Fall back to class default
        meta = KNOWN_SETTINGS_BY_KEY.get(key)
        if meta is not None:
            return meta.class_default
        return None

    def get_cached(self, key: str) -> Any:
        """
        Synchronous, cache-first read for the hot request path.

        Returns the in-process cached value if < _CACHE_TTL_SECONDS old.
        On cache miss: reads from the DB-backed sync fallback (env or default).
        Full async re-fetch cannot happen synchronously; callers that need
        freshness must call refresh_cache() first.

        This is safe for the gateway hot path:
        - On cache hit (TTL not expired): O(1) dict lookup.
        - On cache miss: returns env var or class default (never blocks).
        - Full DB refresh happens async via refresh_cache() on the backoffice
          pub/sub subscriber or at next sync_seed() call.
        """
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None:
            value, fetched_at = cached
            if now - fetched_at < _CACHE_TTL_SECONDS:
                return value

        # Cache miss or expired: return env var fallback so the gateway
        # doesn't block.  Cache entry will be populated by next refresh.
        meta = KNOWN_SETTINGS_BY_KEY.get(key)
        if meta is None:
            return None

        env_raw = os.environ.get(meta.env_var, "")
        if env_raw.strip():
            try:
                if meta.allowed_type == "float":
                    return float(env_raw.strip())
                if meta.allowed_type == "int":
                    return int(env_raw.strip())
                if meta.allowed_type == "bool":
                    return env_raw.strip().lower() in ("1", "true", "yes")
                return env_raw.strip()
            except (ValueError, TypeError):
                pass
        return meta.class_default

    async def list_all(self) -> list[dict]:
        """
        Return all settings as a list of dicts suitable for the admin UI.
        Missing settings (not yet seeded) are returned with their defaults.
        """
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS, KNOWN_SETTINGS_BY_KEY

        rows_by_key: dict[str, dict] = {}
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT key, value, default_value, source,
                           last_changed_by, last_changed_at
                    FROM runtime_settings
                    ORDER BY key
                    """
                )
            for row in rows:
                rows_by_key[row["key"]] = {
                    "key": row["key"],
                    "value": json.loads(row["value"]),
                    "default_value": json.loads(row["default_value"]),
                    "source": row["source"],
                    "last_changed_by": row["last_changed_by"],
                    "last_changed_at": row["last_changed_at"].isoformat()
                    if row["last_changed_at"] else None,
                }
        except Exception as exc:
            logger.warning("RuntimeSettingsService.list_all DB error: %s", exc)

        # Fill in any not-yet-seeded settings with their defaults
        result = []
        for meta in KNOWN_SETTINGS:
            if meta.key in rows_by_key:
                result.append(rows_by_key[meta.key])
            else:
                result.append({
                    "key": meta.key,
                    "value": meta.class_default,
                    "default_value": meta.class_default,
                    "source": "default",
                    "last_changed_by": None,
                    "last_changed_at": None,
                    "description": meta.description,
                    "allowed_type": meta.allowed_type,
                })

        # Enrich rows from DB with description/type metadata
        for item in result:
            meta = KNOWN_SETTINGS_BY_KEY.get(item["key"])
            if meta and "description" not in item:
                item["description"] = meta.description
                item["allowed_type"] = meta.allowed_type

        return result

    async def get_one(self, key: str) -> Optional[dict]:
        """Return a single setting record dict, or None if key not known."""
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

        meta = KNOWN_SETTINGS_BY_KEY.get(key)
        if meta is None:
            return None

        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT key, value, default_value, source,
                           last_changed_by, last_changed_at
                    FROM runtime_settings WHERE key = $1
                    """,
                    key,
                )
            if row is not None:
                return {
                    "key": row["key"],
                    "value": json.loads(row["value"]),
                    "default_value": json.loads(row["default_value"]),
                    "source": row["source"],
                    "last_changed_by": row["last_changed_by"],
                    "last_changed_at": row["last_changed_at"].isoformat()
                    if row["last_changed_at"] else None,
                    "description": meta.description,
                    "allowed_type": meta.allowed_type,
                }
        except Exception as exc:
            logger.warning("RuntimeSettingsService.get_one(%r) DB error: %s", key, exc)

        # Not seeded yet — return default record
        return {
            "key": key,
            "value": meta.class_default,
            "default_value": meta.class_default,
            "source": "default",
            "last_changed_by": None,
            "last_changed_at": None,
            "description": meta.description,
            "allowed_type": meta.allowed_type,
        }

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    async def set(
        self,
        key: str,
        value: Any,
        changed_by: str,
        source: str = "api",
    ) -> dict:
        """
        Persist *value* for *key*.

        Parameters
        ----------
        key:       Setting key (must be in KNOWN_SETTINGS_BY_KEY).
        value:     New value (Python int/float/bool/str).
        changed_by: Admin account id for audit trail.
        source:    'ui' | 'api' (never 'env' — that's for seed only).

        Returns the updated setting record dict.
        Emits RUNTIME_SETTING_CHANGED audit event (caller must provide
        audit_writer separately — see backoffice route).
        Publishes on Redis pub/sub channel yashigani:settings:changed.
        Invalidates the in-process cache entry.
        """
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY
        import datetime

        if key not in KNOWN_SETTINGS_BY_KEY:
            raise ValueError(f"Unknown runtime setting key: {key!r}")
        if source not in ("ui", "api"):
            raise ValueError(f"source must be 'ui' or 'api', got {source!r}")

        meta = KNOWN_SETTINGS_BY_KEY[key]
        value = _coerce_value(value, meta.allowed_type)

        value_json = json.dumps(value)
        default_json = json.dumps(meta.class_default)
        now = datetime.datetime.now(datetime.timezone.utc)

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO runtime_settings
                        (key, value, default_value, source, last_changed_by, last_changed_at)
                    VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, $6)
                    ON CONFLICT (key) DO UPDATE
                        SET value = EXCLUDED.value,
                            source = EXCLUDED.source,
                            last_changed_by = EXCLUDED.last_changed_by,
                            last_changed_at = EXCLUDED.last_changed_at
                    """,
                    key, value_json, default_json, source, changed_by, now,
                )
        except Exception as exc:
            logger.error("RuntimeSettingsService.set(%r) DB error: %s", key, exc)
            raise

        # Invalidate in-process cache
        self._cache.pop(key, None)

        # Publish change notification so gateway consumers can reload
        if self._redis is not None:
            try:
                payload = json.dumps({"key": key, "value": value})
                self._redis.publish(_PUBSUB_CHANNEL, payload)
            except Exception as exc:
                logger.warning("RuntimeSettingsService pub/sub publish failed: %s", exc)

        return {
            "key": key,
            "value": value,
            "default_value": meta.class_default,
            "source": source,
            "last_changed_by": changed_by,
            "last_changed_at": now.isoformat(),
            "description": meta.description,
            "allowed_type": meta.allowed_type,
        }

    async def reset_to_default(self, key: str, changed_by: str, source: str = "api") -> dict:
        """Reset a setting to its class default value."""
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

        meta = KNOWN_SETTINGS_BY_KEY.get(key)
        if meta is None:
            raise ValueError(f"Unknown runtime setting key: {key!r}")

        return await self.set(key, meta.class_default, changed_by=changed_by, source=source)

    # ------------------------------------------------------------------
    # Seed / cache refresh
    # ------------------------------------------------------------------

    async def seed_defaults(self) -> None:
        """
        Seed all KNOWN_SETTINGS from env vars (or class defaults) on first boot.

        Uses INSERT ... ON CONFLICT DO NOTHING so existing DB values are
        preserved on subsequent restarts (the operator's changes survive a
        container restart).
        """
        import datetime
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS

        now = datetime.datetime.now(datetime.timezone.utc)
        for meta in KNOWN_SETTINGS:
            env_raw = os.environ.get(meta.env_var, "")
            if env_raw.strip():
                try:
                    value = _coerce_value(env_raw.strip(), meta.allowed_type)
                    source = "env"
                except (ValueError, TypeError):
                    logger.warning(
                        "RuntimeSettingsService.seed: invalid %s=%r — using class default",
                        meta.env_var, env_raw,
                    )
                    value = meta.class_default
                    source = "env"
            else:
                value = meta.class_default
                source = "env"

            value_json = json.dumps(value)
            default_json = json.dumps(meta.class_default)
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO runtime_settings
                            (key, value, default_value, source, last_changed_by, last_changed_at)
                        VALUES ($1, $2::jsonb, $3::jsonb, $4, NULL, $5)
                        ON CONFLICT (key) DO NOTHING
                        """,
                        meta.key, value_json, default_json, source, now,
                    )
            except Exception as exc:
                logger.error(
                    "RuntimeSettingsService.seed_defaults: failed to seed %r: %s",
                    meta.key, exc,
                )

        # Prime the in-process cache after seeding
        await self._refresh_cache()
        logger.info("RuntimeSettingsService: seeded %d settings", len(KNOWN_SETTINGS))

    async def _refresh_cache(self) -> None:
        """Re-populate in-process cache from DB."""
        from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch("SELECT key, value FROM runtime_settings")
            now = time.monotonic()
            for row in rows:
                if row["key"] in KNOWN_SETTINGS_BY_KEY:
                    self._cache[row["key"]] = (json.loads(row["value"]), now)
        except Exception as exc:
            logger.warning("RuntimeSettingsService._refresh_cache error: %s", exc)

    def update_cache_entry(self, key: str, value: Any) -> None:
        """
        Synchronously update a single cache entry.

        Called by the pub/sub subscriber in the gateway when it receives a
        yashigani:settings:changed message, so the gateway's in-process cache
        reflects the new value without waiting for the TTL to expire.
        """
        self._cache[key] = (value, time.monotonic())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _coerce_value(value: Any, allowed_type: str) -> Any:
    """Coerce *value* to the expected Python type for *allowed_type*."""
    if allowed_type == "float":
        return float(value)
    if allowed_type == "int":
        return int(float(value))  # int("100.0") raises; float first is safe
    if allowed_type == "bool":
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("1", "true", "yes")
    return str(value)
