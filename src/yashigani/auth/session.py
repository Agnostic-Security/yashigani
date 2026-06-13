"""
Yashigani Auth — Session management.
ASVS V3: 256-bit tokens, HttpOnly/Secure/SameSite=Strict,
15-min idle timeout, 4-hour absolute maximum, Redis-backed.

Last updated: 2026-04-27T00:00:00+01:00
"""
from __future__ import annotations

import ipaddress
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

_IDLE_TIMEOUT_SECONDS = 900       # 15 minutes
_ABSOLUTE_TIMEOUT_SECONDS = 14400 # 4 hours
_TOKEN_BYTES = 32                  # 256-bit


@dataclass
class Session:
    token: str
    account_id: str
    account_tier: str               # "admin" | "user"
    created_at: float
    last_active_at: float
    expires_at: float               # absolute expiry
    ip_prefix: str                  # last octet masked for privacy
    # V6.8.4 step-up auth: timestamp of last successful TOTP re-verification.
    # None = no step-up performed this session; 0.0 = never.
    last_totp_verified_at: Optional[float] = field(default=None)


def _import_redis():
    try:
        import redis
        return redis
    except ImportError as exc:
        raise ImportError(
            "redis is required. Install with: pip install redis"
        ) from exc


class SessionStore:
    """
    Redis-backed session store.
    Admin sessions are scoped to port 8443 — validated by tier claim.
    Concurrent sessions: not permitted (new login invalidates prior session).
    """

    def __init__(self, redis_url: str = "redis://redis:6379/0") -> None:
        r = _import_redis()
        self._redis = r.Redis.from_url(redis_url, decode_responses=True)
        self._account_index_prefix = "yashigani:account_sessions:"
        self._session_prefix = "yashigani:session:"

    # -- Public API ----------------------------------------------------------

    def record_totp_stepup(self, token: str) -> bool:
        """
        Record a successful step-up TOTP verification for a session.
        Updates last_totp_verified_at to the current time.
        Returns True if the session was found and updated, False otherwise.
        """
        key = f"{self._session_prefix}{token}"
        if not self._redis.exists(key):
            return False
        self._redis.hset(key, "last_totp_verified_at", str(time.time()))
        return True

    def create(
        self,
        account_id: str,
        account_tier: str,
        client_ip: str,
    ) -> Session:
        """
        Create a new session. Invalidates any existing session for this account
        (ASVS V3 — no concurrent sessions).
        """
        self.invalidate_all_for_account(account_id)

        token = secrets.token_hex(_TOKEN_BYTES)  # 64-char hex, 256-bit
        now = time.time()
        session = Session(
            token=token,
            account_id=account_id,
            account_tier=account_tier,
            created_at=now,
            last_active_at=now,
            expires_at=now + _ABSOLUTE_TIMEOUT_SECONDS,
            ip_prefix=_mask_ip(client_ip),
        )
        self._save(session)
        return session

    def get(self, token: str) -> Optional[Session]:
        """
        Retrieve and validate a session. Returns None if not found, expired,
        or idle-timed-out. Updates last_active_at on success.
        """
        data = self._redis.hgetall(f"{self._session_prefix}{token}")
        if not data:
            return None

        session = _dict_to_session(token, data)
        now = time.time()

        # Check absolute expiry
        if now > session.expires_at:
            self.invalidate(token)
            return None

        # Check idle timeout
        if now - session.last_active_at > _IDLE_TIMEOUT_SECONDS:
            self.invalidate(token)
            return None

        # Refresh last_active_at
        session.last_active_at = now
        self._redis.hset(
            f"{self._session_prefix}{token}",
            "last_active_at", str(now),
        )
        return session

    def invalidate(self, token: str) -> None:
        """Invalidate a single session."""
        data = self._redis.hgetall(f"{self._session_prefix}{token}")
        if data:
            account_id = data.get("account_id", "")
            self._redis.srem(f"{self._account_index_prefix}{account_id}", token)
        self._redis.delete(f"{self._session_prefix}{token}")

    def invalidate_all_for_account(self, account_id: str) -> int:
        """
        Invalidate all sessions for an account. Returns count invalidated.
        Used on password change, TOTP reprovision, and new login.
        """
        index_key = f"{self._account_index_prefix}{account_id}"
        tokens = self._redis.smembers(index_key)
        pipe = self._redis.pipeline()
        for token in tokens:
            pipe.delete(f"{self._session_prefix}{token}")
        pipe.delete(index_key)
        pipe.execute()
        return len(tokens)

    def active_sessions_for_account(self, account_id: str) -> list[dict]:
        """
        Return summary of active sessions (no full tokens, masked IPs).
        For user self-service session listing.
        """
        index_key = f"{self._account_index_prefix}{account_id}"
        tokens = self._redis.smembers(index_key)
        result = []
        for token in tokens:
            data = self._redis.hgetall(f"{self._session_prefix}{token}")
            if data:
                result.append({
                    "session_id_prefix": token[:8],
                    "created_at": data.get("created_at"),
                    "last_active_at": data.get("last_active_at"),
                    "ip_prefix": data.get("ip_prefix"),
                })
        return result

    def count_active_all(self) -> int:
        """Return the number of currently active session keys in Redis.

        Used by MetricsCollector to update yashigani_auth_active_sessions.
        Performs a SCAN over yashigani:session:* keys — count is approximate
        (eventual TTL expiry) but suitable for dashboard display.
        Never raises: returns 0 on any Redis error.
        """
        try:
            count = 0
            pattern = f"{self._session_prefix}*"
            for _ in self._redis.scan_iter(pattern, count=100):
                count += 1
            return count
        except Exception:
            return 0

    # -- Internal ------------------------------------------------------------

    def _save(self, session: Session) -> None:
        key = f"{self._session_prefix}{session.token}"
        ttl = int(session.expires_at - time.time()) + 60  # Redis TTL with buffer
        pipe = self._redis.pipeline()
        pipe.hset(key, mapping=_session_to_dict(session))
        pipe.expire(key, ttl)
        pipe.sadd(
            f"{self._account_index_prefix}{session.account_id}",
            session.token,
        )
        pipe.execute()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask_ip(ip_str: str) -> str:
    """Mask the client IP for privacy: last octet (IPv4) or last 80 bits (IPv6)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            # Mask last octet: 192.168.1.100 -> 192.168.1.0/24
            net4 = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            return str(net4.network_address)
        else:
            # Mask last 80 bits: keep first 48 bits (site prefix)
            net6 = ipaddress.IPv6Network(f"{ip_str}/48", strict=False)
            return str(net6.network_address)
    except ValueError:
        return "unknown"


def _session_to_dict(s: Session) -> dict:
    d = {
        "account_id": s.account_id,
        "account_tier": s.account_tier,
        "created_at": str(s.created_at),
        "last_active_at": str(s.last_active_at),
        "expires_at": str(s.expires_at),
        "ip_prefix": s.ip_prefix,
    }
    if s.last_totp_verified_at is not None:
        d["last_totp_verified_at"] = str(s.last_totp_verified_at)
    return d


def _dict_to_session(token: str, d: dict) -> Session:
    raw_stepup = d.get("last_totp_verified_at")
    last_totp_verified_at: Optional[float] = float(raw_stepup) if raw_stepup else None
    return Session(
        token=token,
        account_id=d["account_id"],
        account_tier=d["account_tier"],
        created_at=float(d["created_at"]),
        last_active_at=float(d["last_active_at"]),
        expires_at=float(d["expires_at"]),
        ip_prefix=d.get("ip_prefix", ""),
        last_totp_verified_at=last_totp_verified_at,
    )
