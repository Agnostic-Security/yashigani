"""
Yashigani Models — Redis-backed model alias store.

Redis key schema (db/1, separate namespace from session store):
    model:alias:{alias_name}  →  JSON string
        {
            "alias":               str,
            "provider":            str,
            "model":               str,
            "force_local":         bool,
            "sensitivity_ceiling": str | null   # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
        }

All keys are prefixed model:alias: so they coexist safely with session keys
on Redis db/1 without collision.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_KEY_PREFIX = "model:alias:"

# YSG-RISK-183 — admin-configurable DEFAULT model pointer. A single string
# key (NOT under model:alias: so it never collides with the SCAN-based
# list_all() alias enumeration) holding the alias name an admin has
# explicitly set as the effective default. Absent (None) => the gateway
# falls back to its spec-chosen LOCAL model (OLLAMA_MODEL, auto-selected by
# install.sh from GPU/VRAM detection at install time) — "local unless a
# cloud model is configured with an API key AND set as default".
_DEFAULT_KEY = "model:default_alias"

# Seeded on first boot when the namespace is empty
_DEFAULTS: list[dict] = [
    {
        "alias": "fast",
        "provider": "ollama",
        "model": "qwen2.5:3b",
        "force_local": True,
        "sensitivity_ceiling": None,
    },
    {
        "alias": "smart",
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "force_local": False,
        "sensitivity_ceiling": None,
    },
    {
        "alias": "secure",
        "provider": "ollama",
        "model": "qwen2.5:3b",
        "force_local": True,
        "sensitivity_ceiling": "CONFIDENTIAL",
    },
    {
        "alias": "balanced",
        "provider": "ollama",
        "model": "qwen2.5:3b",
        "force_local": False,   # OE decides cloud/local at routing time
        "sensitivity_ceiling": None,
    },
    {
        "alias": "code",
        "provider": "ollama",
        "model": "qwen2.5-coder:3b",
        "force_local": True,
        "sensitivity_ceiling": None,
    },
]


@dataclass
class ModelAlias:
    """Domain object for a model alias configuration."""

    alias: str
    provider: str
    model: str
    force_local: bool = False
    sensitivity_ceiling: Optional[str] = None  # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ModelAlias":
        return cls(
            alias=d["alias"],
            provider=d["provider"],
            model=d["model"],
            force_local=bool(d.get("force_local", False)),
            sensitivity_ceiling=d.get("sensitivity_ceiling"),
        )


class ModelAliasStore:
    """
    Redis-backed store for model aliases.

    Designed to share Redis db/1 with the session store — the key prefix
    model:alias: guarantees namespace isolation.

    No in-memory cache is kept deliberately: aliases change rarely and Redis
    reads are cheap. This keeps the store stateless between restarts and
    avoids stale-cache bugs.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, alias: str) -> Optional[ModelAlias]:
        """Return the ModelAlias for *alias*, or None if it does not exist."""
        try:
            raw = self._redis.get(_KEY_PREFIX + alias)
            if raw is None:
                return None
            d = json.loads(raw)
            return ModelAlias.from_dict(d)
        except Exception as exc:
            logger.error("ModelAliasStore.get(%r) failed: %s", alias, exc)
            return None

    def set(self, alias: str, config: ModelAlias) -> None:
        """Persist *config* under *alias*. Overwrites any existing entry."""
        try:
            payload = json.dumps(config.to_dict())
            self._redis.set(_KEY_PREFIX + alias, payload)
        except Exception as exc:
            logger.error("ModelAliasStore.set(%r) failed: %s", alias, exc)
            raise

    def delete(self, alias: str) -> bool:
        """
        Delete the alias.

        Returns True if the key existed and was removed, False if it was
        already absent.
        """
        try:
            deleted = self._redis.delete(_KEY_PREFIX + alias)
            return bool(deleted)
        except Exception as exc:
            logger.error("ModelAliasStore.delete(%r) failed: %s", alias, exc)
            raise

    def list_all(self) -> dict[str, ModelAlias]:
        """
        Return a dict mapping alias name → ModelAlias for every stored alias.

        Uses SCAN to avoid blocking the Redis server on large key sets.
        """
        result: dict[str, ModelAlias] = {}
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(
                    cursor, match=_KEY_PREFIX + "*", count=200
                )
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        d = json.loads(raw)
                        obj = ModelAlias.from_dict(d)
                        result[obj.alias] = obj
                    except Exception as exc:
                        logger.error(
                            "ModelAliasStore: failed to deserialise %s: %s", key, exc
                        )
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error("ModelAliasStore.list_all() failed: %s", exc)
        return result

    # ------------------------------------------------------------------
    # Default-alias pointer (YSG-RISK-183 — admin-configurable default)
    # ------------------------------------------------------------------

    def get_default(self) -> Optional[str]:
        """Return the alias name an admin has explicitly set as the
        effective default, or None if never set / on any store error
        (fail-closed to "no admin default" — callers then fall back to the
        spec-chosen local model, never to an unusable state)."""
        try:
            raw = self._redis.get(_DEFAULT_KEY)
            if raw is None:
                return None
            return raw.decode() if isinstance(raw, bytes) else str(raw)
        except Exception as exc:
            logger.error("ModelAliasStore.get_default() failed: %s", exc)
            return None

    def set_default(self, alias: str) -> None:
        """Persist *alias* as the admin-configured default. Caller
        (admin API) is responsible for validating the alias exists and,
        when it resolves to a cloud provider, that a valid API key is
        configured — this method only persists the pointer."""
        try:
            self._redis.set(_DEFAULT_KEY, alias)
        except Exception as exc:
            logger.error("ModelAliasStore.set_default(%r) failed: %s", alias, exc)
            raise

    def clear_default(self) -> None:
        """Remove the admin-configured default pointer, reverting to the
        spec-chosen local model."""
        try:
            self._redis.delete(_DEFAULT_KEY)
        except Exception as exc:
            logger.error("ModelAliasStore.clear_default() failed: %s", exc)
            raise

    def seed_defaults(self) -> None:
        """
        Populate default aliases if the namespace is currently empty.

        Idempotent — a second call is a no-op if any model:alias:* key exists.
        """
        try:
            cursor, keys = self._redis.scan(0, match=_KEY_PREFIX + "*", count=1)
            if keys:
                logger.debug("ModelAliasStore.seed_defaults: namespace not empty, skipping")
                return
            for entry in _DEFAULTS:
                obj = ModelAlias.from_dict(entry)
                self.set(obj.alias, obj)
            logger.info(
                "ModelAliasStore.seed_defaults: seeded %d default aliases", len(_DEFAULTS)
            )
        except Exception as exc:
            logger.error("ModelAliasStore.seed_defaults() failed: %s", exc)
            raise
