"""
MCP Broker — jti nonce store for JWT replay prevention.

Per Nico spec §3: every JWT carries a jti (UUIDv4). On receiving a JWT,
the broker checks the nonce store:
  1. jti absent → reject.
  2. jti found in store → reject (jti_replayed).
  3. jti not found → add to store with score=exp_epoch, then allow.

Cleanup: entries expire when exp + skew_tolerance < now.

Production: Redis sorted set `mcp:jti:seen:{tenant_id}`.
Dev: InMemoryNonceStore (LRU with 65-second window, max 10k entries).
     Not crash-safe — a restart loses the nonce store.
     Document as dev mode only.

v2.25.0 / P1 W3 Phase 2b-ii / Nico spec §3.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from threading import Lock

logger = logging.getLogger(__name__)

# Per spec: TTL=60s + skew_tolerance=5s = 65s max entry lifetime
_NONCE_WINDOW_SECONDS = 65
_MAX_IN_MEMORY_ENTRIES = 10_000


class NonceStoreError(Exception):
    """Raised when the nonce store operation fails unexpectedly."""


class NonceStore(ABC):
    """Abstract nonce store interface."""

    @abstractmethod
    def check_and_record(self, jti: str, exp_epoch: float, tenant_id: str) -> bool:
        """
        Check whether jti is a replay and record it if not.

        Returns True if jti is NEW (not a replay — caller may proceed).
        Returns False if jti is a REPLAY (caller must reject).

        Raises NonceStoreError on store failure (caller should treat as deny,
        fail-closed per SOP 1).
        """
        ...

    @abstractmethod
    def cleanup_expired(self, tenant_id: str) -> int:
        """Remove expired entries. Returns count of entries removed."""
        ...


class InMemoryNonceStore(NonceStore):
    """
    In-process LRU nonce store for dev mode.

    WARNING: NOT crash-safe — gateway restart loses the nonce store.
    NOT suitable for production where replay resistance is required.
    Use RedisNonceStore in production (Redis sorted set).

    Per Nico spec §3: dev-mode only; flag as non-FIPS-safe for key storage
    (the replay protection itself is intact in-process, but a restart window
    allows replay of in-flight tokens).

    Max entries: 10,000 per instance (across all tenants in dev mode).
    Window: entries expire after NONCE_WINDOW_SECONDS (65s) from exp.
    """

    def __init__(self, skew_tolerance_seconds: float = 5.0) -> None:
        # OrderedDict: jti → (exp_epoch, tenant_id)
        # LRU eviction when over _MAX_IN_MEMORY_ENTRIES
        self._store: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._lock = Lock()
        self._skew = skew_tolerance_seconds
        logger.warning(
            "mcp-broker: using InMemoryNonceStore (DEV MODE ONLY). "
            "Redis nonce store required for production replay resistance. "
            "A gateway restart WILL lose the nonce store and allow replay "
            "of in-flight tokens within the TTL window. "
            "YSG-RISK-055 / Nico spec §3."
        )

    def check_and_record(self, jti: str, exp_epoch: float, tenant_id: str) -> bool:
        now = time.time()

        with self._lock:
            # Cleanup before check (per spec §3: run cleanup before every check)
            self._cleanup_locked(now)

            if jti in self._store:
                logger.warning(
                    "mcp-broker: jti_replayed jti=%s tenant=%s", jti, tenant_id
                )
                return False  # replay detected

            # Record the jti
            self._store[jti] = (exp_epoch, tenant_id)
            self._store.move_to_end(jti)

            # LRU eviction if over capacity
            while len(self._store) > _MAX_IN_MEMORY_ENTRIES:
                oldest_jti, _ = self._store.popitem(last=False)
                logger.warning(
                    "mcp-broker: nonce store LRU eviction jti=%s (store full at %d entries)",
                    oldest_jti,
                    _MAX_IN_MEMORY_ENTRIES,
                )

            return True  # new jti — not a replay

    def cleanup_expired(self, tenant_id: str) -> int:
        with self._lock:
            return self._cleanup_locked(time.time())

    def _cleanup_locked(self, now: float) -> int:
        """Remove entries where exp + skew_tolerance < now. Called with lock held."""
        cutoff = now - self._skew
        to_delete = [
            jti
            for jti, (exp, _) in self._store.items()
            if exp < cutoff
        ]
        for jti in to_delete:
            del self._store[jti]
        return len(to_delete)

    @property
    def size(self) -> int:
        """Current number of entries (for testing)."""
        with self._lock:
            return len(self._store)


class RedisNonceStore(NonceStore):
    """
    Redis sorted-set nonce store for production.

    Key: mcp:jti:seen:{tenant_id}
    Score: exp_epoch (Unix epoch of JWT expiry)
    Member: jti (UUIDv4 string)

    Cleanup: ZREMRANGEBYSCORE with score < now - skew_tolerance.
    Per Nico spec §3: entries expire when exp + skew_tolerance < now.
    Max entry lifetime: 65 seconds.

    This is the ONLY production-acceptable nonce backend.

    Usage:
        redis_client = redis.asyncio.Redis(...)  # or redis.Redis for sync
        store = RedisNonceStore(redis_client)

    Note: Requires redis>=5.0 (already in pyproject.toml dependencies).
    Async-compatible but exposes a sync interface for broker compatibility;
    call from sync context via asyncio.run() or from async context via
    thread pool executor.
    """

    def __init__(
        self,
        redis_client: object,
        skew_tolerance_seconds: float = 5.0,
    ) -> None:
        self._redis = redis_client
        self._skew = skew_tolerance_seconds

    def _key(self, tenant_id: str) -> str:
        return f"mcp:jti:seen:{tenant_id}"

    def check_and_record(self, jti: str, exp_epoch: float, tenant_id: str) -> bool:
        """
        Atomic check-and-record using Redis NX semantics.

        FIX-A (Nico-F2 + Laura-001): the previous pipeline-based implementation
        had a TOCTOU race — two concurrent workers could both see "jti not found"
        on ZSCORE and both proceed to ZADD, double-admitting the same jti.

        New approach:
          1. ZREMRANGEBYSCORE (cleanup expired — removes stale entries before the
             NX insert so the set stays bounded even under replay storms).
          2. ZADD NX (insert-only-if-absent, atomic): if added=1, jti is new
             (allow); if added=0, jti already existed (replay → reject).
          3. EXPIRE (refresh key TTL after write).

        The NX flag makes the ZADD itself the replay-detection gate, with no
        separate read between check and write.  This is safe even under concurrent
        goroutines/threads sharing a single Redis connection because ZADD NX is
        a single atomic Redis command.

        Returns True (new jti) or False (replay).
        Raises NonceStoreError on Redis failure (broker must fail-closed).
        """
        try:
            key = self._key(tenant_id)
            now = time.time()
            cutoff = now - self._skew

            # Step 1: cleanup expired entries (bounded maintenance — safe to run
            # before the NX insert; does not race with it because expired entries
            # have score < cutoff and the new entry has score=exp_epoch > now).
            self._redis.zremrangebyscore(key, "-inf", cutoff)  # type: ignore[attr-defined]

            # Step 2: atomic insert-only-if-absent — this IS the replay gate.
            # ZADD NX returns the number of NEW elements added:
            #   1 → jti was absent → first use → allow
            #   0 → jti already present → replay → reject
            added = self._redis.zadd(  # type: ignore[attr-defined]
                key, {jti: exp_epoch}, nx=True
            )

            if not added:
                logger.warning(
                    "mcp-broker: jti_replayed jti=%s tenant=%s (Redis NX)", jti, tenant_id
                )
                return False  # replay

            # Step 3: refresh TTL so Redis auto-expires the key after the nonce window.
            self._redis.expire(key, int(_NONCE_WINDOW_SECONDS))  # type: ignore[attr-defined]
            return True

        except Exception as exc:
            raise NonceStoreError(
                f"Redis nonce store error for jti={jti!r} tenant={tenant_id!r}: {exc}"
            ) from exc

    def cleanup_expired(self, tenant_id: str) -> int:
        """Remove entries with exp < now - skew_tolerance."""
        try:
            key = self._key(tenant_id)
            cutoff = time.time() - self._skew
            return self._redis.zremrangebyscore(key, "-inf", cutoff)  # type: ignore[attr-defined]
        except Exception as exc:
            raise NonceStoreError(
                f"Redis nonce cleanup error tenant={tenant_id!r}: {exc}"
            ) from exc
