"""
Yashigani Gateway — Application-level DDoS mitigation (v2.2).

Tracks concurrent/recent connections per IP address using Redis counters with
a fixed-window TTL.  A single Redis INCR + EXPIRE pair is the hot path;
no Lua scripting or blocking calls required.

Key namespace: ddos:{ip}:{window_bucket}
  where window_bucket = int(time.time() / window_seconds)

Design rationale:
  - Counter is incremented on every inbound request (call record()).
  - check() reads the current counter and returns False when the IP has
    exceeded max_connections_per_ip within the rolling window.
  - Both operations are O(1) and synchronous — safe to call inline in
    the gateway request path before any expensive processing.
  - The namespace "ddos:" is intentionally separate from "rl:" (rate limit)
    to allow independent monitoring and per-dimension metrics.
  - Never raises: any Redis error causes check() to allow the request
    (fail-open), matching the existing EndpointRateLimiter behaviour.
    A failed Redis connection should not gate legitimate traffic when the
    risk signal is unavailable.

Default threshold rationale (v2.4.1 → v2.24.1):
  max_connections_per_ip scales with the licensed max_end_users count so
  that large deployments (corporate offices, multi-org Pro+, enterprise)
  are never blocked by an arbitrary fixed ceiling.
  Formula: max(5000, max_end_users * 25)
  Unlimited tiers (enterprise, academic_nonprofit, max_end_users == -1)
  → 100 000 (very permissive; operator expected to tune or add own DDoS
  perimeter).  Caddy timeouts remain the first-line flood defence; this
  second-line per-IP throttle fires only on EXTREME volume.
  Override via YASHIGANI_DDOS_PER_IP_LIMIT (env) — env wins over computed
  default.  Risk register: YSG-RISK-056.
  Tiago 2026-05-24: "tie the threshold to the number of users so you don't
  block big deployments".

OWASP ASVS Level 3 alignment:
  V4.2.1 — Enforced at application layer (not solely network layer).
  V4.2.2 — Per-IP isolation prevents one tenant flooding another.
  V11.1.4 — Counters are stored in Redis, not in-process, so they survive
             multiple gateway replicas.
"""
from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)

# Environment variable names (module-level constants used by entrypoint.py).
ENV_PER_IP_LIMIT = "YASHIGANI_DDOS_PER_IP_LIMIT"
ENV_WINDOW_SECONDS = "YASHIGANI_DDOS_WINDOW_SECONDS"
ENV_EXEMPT_PATHS = "YASHIGANI_DDOS_EXEMPT_PATHS"

# Default thresholds — permissive by design (see module docstring / YSG-RISK-056).
# _DEFAULT_MAX_CONNECTIONS_PER_IP is the floor used by _ddos_default_per_ip_limit()
# and also the fallback when no license is loaded (community / canary / dev).
# Override via YASHIGANI_DDOS_PER_IP_LIMIT and YASHIGANI_DDOS_WINDOW_SECONDS.
_DEFAULT_MAX_CONNECTIONS_PER_IP: int = 5000
_DEFAULT_WINDOW_SECONDS: int = 60


def _ddos_default_per_ip_limit(max_end_users: int) -> int:
    """
    Compute the default per-IP connection limit scaled to the licensed user count.

    Per-IP connection limit scales with licensed max_end_users so big-NAT
    deployments (corporate offices, multi-org Pro+, enterprise) aren't blocked
    by an arbitrary ceiling.

    Formula: max(5000, max_end_users * 25)

    The 25x multiplier assumes a worst case where many users share one NAT
    (realistic for corporate office networks or multi-team Pro+ installs).

    Unlimited tiers (max_end_users == -1 — enterprise, academic_nonprofit)
    → 100 000 (very permissive; operator is expected to override via
    YASHIGANI_DDOS_PER_IP_LIMIT or front with their own DDoS perimeter).

    Resulting per-tier defaults:
      community        (5)    → 5 000  (floor — 5*25=125 < 5000)
      canary           (5)    → 5 000  (floor)
      igniter          (50)   → 5 000  (floor — 50*25=1250 < 5000)
      starter          (100)  → 5 000  (floor — 100*25=2500 < 5000)
      professional     (500)  → 12 500
      professional_plus (4000) → 100 000  (4000*25=100000)
      enterprise       (-1)   → 100 000  (sentinel)
      academic_nonprofit (-1) → 100 000  (sentinel)

    Authority: Tiago 2026-05-24 — "tie the threshold to the number of users
    so you don't block big deployments".
    Risk register: YSG-RISK-056.
    """
    if max_end_users == -1:
        return 100_000  # enterprise / academic — operator-tuned
    return max(5_000, max_end_users * 25)

# Paths exempt from DDoS tracking (health/metrics must always respond).
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/healthz",
    "/readyz",
    "/internal/metrics",
    "/metrics",
    "/-/healthy",
    "/_yashigani/healthz",
})


class DDoSProtector:
    """
    Per-IP connection rate counter backed by Redis.

    Usage (inside gateway request handler)::

        protector = DDoSProtector(redis_client=redis)
        protector.record(client_ip)          # always call first
        if not protector.check(client_ip):
            return 429 / drop connection

    Parameters
    ----------
    redis_client:
        Synchronous Redis client (redis-py or fakeredis).  Must support
        INCR, EXPIRE, and GET commands.
    max_connections_per_ip:
        Maximum requests allowed from a single IP within ``window_seconds``.
        Default: 5000 (permissive — see YSG-RISK-056 / module docstring).
        Override via ``YASHIGANI_DDOS_PER_IP_LIMIT`` env var.
    window_seconds:
        Fixed-window duration in seconds.  Default: 60.
        Override via ``YASHIGANI_DDOS_WINDOW_SECONDS`` env var.
    """

    def __init__(
        self,
        redis_client,
        max_connections_per_ip: int = _DEFAULT_MAX_CONNECTIONS_PER_IP,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._redis = redis_client
        self.max_connections_per_ip = max_connections_per_ip
        self.window_seconds = window_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, ip: str, path: str = "") -> bool:
        """
        Return True if the IP is within its connection budget, False if it
        has exceeded the threshold and should be blocked.

        Never raises — Redis failures return True (fail-open).

        Parameters
        ----------
        ip:
            Client IP address string (IPv4 or IPv6).
        path:
            Optional request path used to skip exempt paths (e.g. /healthz).
        """
        if path in _EXEMPT_PATHS:
            return True
        try:
            key = self._key(ip)
            raw = self._redis.get(key)
            count = int(raw) if raw is not None else 0
            return count <= self.max_connections_per_ip
        except Exception as exc:
            logger.warning(
                "DDoSProtector.check failed for ip=%s: %s — allowing (fail-open)",
                _redact_ip(ip),
                exc,
            )
            return True

    def record(self, ip: str, path: str = "") -> None:
        """
        Increment the connection counter for ``ip``.  Sets the key TTL on
        first increment so the counter expires automatically.

        Silently ignores Redis errors.

        Parameters
        ----------
        ip:
            Client IP address string.
        path:
            Optional request path used to skip exempt paths.
        """
        if path in _EXEMPT_PATHS:
            return
        try:
            key = self._key(ip)
            count = self._redis.incr(key)
            if count == 1:
                # First request in this window — set expiry.
                # Expire after 2x the window so the key overlaps slightly and
                # avoids a race between INCR and EXPIRE on the bucket boundary.
                self._redis.expire(key, self.window_seconds * 2)
        except Exception as exc:
            logger.warning(
                "DDoSProtector.record failed for ip=%s: %s",
                _redact_ip(ip),
                exc,
            )

    def current_count(self, ip: str) -> int:
        """Return the current window counter for ``ip``.  Returns 0 on error."""
        try:
            key = self._key(ip)
            raw = self._redis.get(key)
            return int(raw) if raw is not None else 0
        except Exception:
            return 0

    def update_limits(
        self,
        max_connections_per_ip: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        """
        Hot-update the per-IP limit and/or window without restart.

        Called by the runtime settings live-reload subscriber when
        gateway.ddos.per_ip_limit or gateway.ddos.window_seconds changes.
        Thread-safe for the GIL-protected int attribute assignments used here.
        """
        if max_connections_per_ip is not None:
            self.max_connections_per_ip = int(max_connections_per_ip)
            logger.info(
                "DDoSProtector.max_connections_per_ip updated to %d (live reload)",
                self.max_connections_per_ip,
            )
        if window_seconds is not None:
            self.window_seconds = int(window_seconds)
            logger.info(
                "DDoSProtector.window_seconds updated to %d (live reload)",
                self.window_seconds,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _key(self, ip: str) -> str:
        bucket = int(time.time() / self.window_seconds)
        return f"ddos:{ip}:{bucket}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact_ip(ip: str) -> str:
    """Partially redact an IP for logging (last octet/group zeroed)."""
    if ":" in ip:
        # IPv6 — keep first 4 groups
        parts = ip.split(":")
        return ":".join(parts[:4]) + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    return "****"
