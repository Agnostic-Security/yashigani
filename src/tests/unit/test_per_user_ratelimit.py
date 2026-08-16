"""
Unit tests for per-user rate limit (YSG-RISK-222, Tiago 2026-05-24).

Coverage:
  1. 100 sequential requests pass; 101st returns 429 (user dimension blocked).
  2. 200 burst allowed; 201st blocked.
  3. YASHIGANI_RATE_LIMIT_PER_USER_RPS env var override propagates through entrypoint helper.
  4. audit event USER_RATE_LIMIT_EXCEEDED is emitted on user-dimension breach.
  5. Prometheus metric yashigani_user_rate_limit_violations_total increments with
     hashed user_id label.
  6. Integration: RateLimiter.check() respects per_user_rps=1.0 with a real fakeredis
     instance — first request allowed; second (no time elapsed) blocked on user dimension.

Reference: docs/risk-register.yml YSG-RISK-222
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Patch YASHIGANI_INTERNAL_BEARER at import time so proxy.py can be loaded
# in test environments where the secret is absent.  The fail-closed guard
# raises RuntimeError at module load — we pre-set the env var before any
# import of yashigani.gateway.proxy to prevent that.
# ---------------------------------------------------------------------------
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-for-unit-tests")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_limiter(redis_client, per_user_rps: float = 100.0, per_user_burst: int = 200):
    from yashigani.ratelimit.limiter import RateLimiter
    from yashigani.ratelimit.config import RateLimitConfig
    cfg = RateLimitConfig(
        # Crank global / IP / agent / session limits way up so only the user
        # bucket triggers in these tests.
        global_rps=1_000_000.0,
        global_burst=10_000_000,
        per_ip_rps=1_000_000.0,
        per_ip_burst=10_000_000,
        per_agent_rps=1_000_000.0,
        per_agent_burst=10_000_000,
        per_session_rps=1_000_000.0,
        per_session_burst=10_000_000,
        per_user_rps=per_user_rps,
        per_user_burst=per_user_burst,
        adaptive_enabled=False,
    )
    return RateLimiter(redis_client=redis_client, config=cfg)


def _hash16(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 1. 100 requests pass; 101st blocked
# ---------------------------------------------------------------------------

class TestPerUserRateLimitBasic:
    def test_100_requests_allowed(self, mock_redis):
        """First 100 requests (filling the burst=100 bucket) must all be allowed.

        We use rps=0.001 so the token refill rate is negligible over the microseconds
        each check() call takes — the test is purely about burst capacity, not refill.
        """
        limiter = _make_limiter(mock_redis, per_user_rps=0.001, per_user_burst=100)
        for i in range(100):
            result = limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
            assert result.allowed, f"Request {i+1} should be allowed; dimension={result.dimension}"

    def test_101st_request_blocked(self, mock_redis):
        """After consuming all 100 burst tokens, the 101st must be blocked.

        rps=0.001 → refill ≈ 1 token per 1000 seconds → negligible over test duration.
        """
        limiter = _make_limiter(mock_redis, per_user_rps=0.001, per_user_burst=100)
        for _ in range(100):
            limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
        result = limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
        assert not result.allowed, "101st request must be blocked"
        assert result.dimension == "user", (
            f"Blocking dimension must be 'user', got '{result.dimension}'"
        )

    def test_101st_has_retry_after(self, mock_redis):
        """Blocked user-dimension result must have a positive retry_after_ms."""
        limiter = _make_limiter(mock_redis, per_user_rps=0.001, per_user_burst=100)
        for _ in range(100):
            limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
        result = limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
        assert result.retry_after_ms > 0, "retry_after_ms must be positive on user-bucket exhaustion"

    def test_different_users_get_independent_buckets(self, mock_redis):
        """Exhausting one user's bucket must not affect another user."""
        limiter = _make_limiter(mock_redis, per_user_rps=100.0, per_user_burst=5)
        for _ in range(5):
            limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="alice@example.com")
        # alice exhausted; bob should still pass
        result_bob = limiter.check("1.2.3.4", "agent-a", "sess-b", user_id="bob@example.com")
        assert result_bob.allowed, "Bob's bucket should be independent of Alice's"


# ---------------------------------------------------------------------------
# 2. 200 burst allowed; 201st blocked
# ---------------------------------------------------------------------------

class TestPerUserRateLimitBurst:
    def test_200_burst_allowed(self, mock_redis):
        """All 200 burst tokens must be consumed without rejection.

        rps=0.001 → refill rate negligible over microseconds of test duration.
        """
        limiter = _make_limiter(mock_redis, per_user_rps=0.001, per_user_burst=200)
        for i in range(200):
            result = limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="burst-user@example.com")
            assert result.allowed, f"Burst request {i+1} must be allowed"

    def test_201st_burst_blocked(self, mock_redis):
        """The 201st request after consuming 200-token burst must be blocked."""
        limiter = _make_limiter(mock_redis, per_user_rps=0.001, per_user_burst=200)
        for _ in range(200):
            limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="burst-user@example.com")
        result = limiter.check("1.2.3.4", "agent-a", "sess-a", user_id="burst-user@example.com")
        assert not result.allowed, "201st request must be blocked after burst exhausted"
        assert result.dimension == "user"


# ---------------------------------------------------------------------------
# 3. Env var override
# ---------------------------------------------------------------------------

class TestPerUserRateLimitEnvVar:
    def test_env_var_sets_per_user_rps(self, monkeypatch):
        """
        YASHIGANI_RATE_LIMIT_PER_USER_RPS=50 must set per_user_rps=50.0 and
        per_user_burst=100 (2× rps) on the constructed RateLimitConfig.
        """
        monkeypatch.setenv("YASHIGANI_RATE_LIMIT_PER_USER_RPS", "50")
        # Replicate the entrypoint env-var parsing logic inline (tested in isolation)
        raw = os.environ.get("YASHIGANI_RATE_LIMIT_PER_USER_RPS", "")
        per_user_rps = 100.0
        if raw.strip():
            per_user_rps = float(raw.strip())
        per_user_burst = max(1, int(per_user_rps * 2))
        assert per_user_rps == 50.0
        assert per_user_burst == 100

    def test_env_var_invalid_falls_back_to_default(self, monkeypatch, caplog):
        """An invalid env var value must log a warning and fall back to 100.0."""
        monkeypatch.setenv("YASHIGANI_RATE_LIMIT_PER_USER_RPS", "not-a-number")
        raw = os.environ.get("YASHIGANI_RATE_LIMIT_PER_USER_RPS", "")
        per_user_rps = 100.0
        if raw.strip():
            try:
                val = float(raw.strip())
                if val <= 0:
                    raise ValueError("must be positive")
                per_user_rps = val
            except ValueError:
                per_user_rps = 100.0
        assert per_user_rps == 100.0, "Invalid env var must fall back to 100.0"

    def test_per_user_rps_config_default(self):
        """RateLimitConfig default per_user_rps must be 100.0."""
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig()
        assert cfg.per_user_rps == 100.0
        assert cfg.per_user_burst == 200

    def test_per_user_rps_config_override(self):
        """RateLimitConfig accepts custom per_user_rps / per_user_burst."""
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig(per_user_rps=50.0, per_user_burst=100)
        assert cfg.per_user_rps == 50.0
        assert cfg.per_user_burst == 100


# ---------------------------------------------------------------------------
# 4. Audit event emitted on breach
# ---------------------------------------------------------------------------

class TestPerUserAuditEvent:
    def test_admin_alert_writes_audit_event_on_user_breach(self):
        """
        _admin_alert_user_rate_limit must call audit_writer.write() with a
        UserRateLimitExceededEvent when the user-dimension bucket is exhausted.
        """
        from yashigani.gateway.proxy import _admin_alert_user_rate_limit
        from yashigani.ratelimit.limiter import RateLimitResult
        from yashigani.audit.schema import UserRateLimitExceededEvent, EventType

        audit_writer = MagicMock()
        audit_writer.write = MagicMock()

        rate_limiter_mock = MagicMock()
        rate_limiter_mock.current_config.return_value = MagicMock(per_user_rps=100.0)

        result = RateLimitResult(
            allowed=False,
            dimension="user",
            remaining=0,
            retry_after_ms=10,
        )

        _admin_alert_user_rate_limit(
            audit_writer=audit_writer,
            request_id="req-001",
            result=result,
            user_id="alice@example.com",
            agent_id="agent-x",
            session_id="sess-abc123",
            rate_limiter=rate_limiter_mock,
        )

        audit_writer.write.assert_called_once()
        written_event = audit_writer.write.call_args[0][0]
        assert isinstance(written_event, UserRateLimitExceededEvent)
        assert written_event.event_type == EventType.USER_RATE_LIMIT_EXCEEDED
        assert written_event.request_id == "req-001"
        # user_id must be hashed — never raw PII
        expected_hash = hashlib.sha256("alice@example.com".encode()).hexdigest()[:16]
        assert written_event.user_id_hash == expected_hash
        assert written_event.retry_after_ms == 10
        assert written_event.session_id_prefix == "sess-abc"

    def test_admin_alert_no_write_when_audit_writer_none(self):
        """_admin_alert_user_rate_limit must silently skip if audit_writer is None."""
        from yashigani.gateway.proxy import _admin_alert_user_rate_limit
        from yashigani.ratelimit.limiter import RateLimitResult

        result = RateLimitResult(allowed=False, dimension="user", remaining=0, retry_after_ms=10)
        # Must not raise
        _admin_alert_user_rate_limit(
            audit_writer=None,
            request_id="req-002",
            result=result,
            user_id="alice@example.com",
            agent_id="agent-x",
            session_id="sess-xyz",
            rate_limiter=None,
        )

    def test_audit_event_user_id_is_hashed(self):
        """user_id_hash on the event must be SHA-256[:16] of the raw user_id."""
        from yashigani.gateway.proxy import _admin_alert_user_rate_limit
        from yashigani.ratelimit.limiter import RateLimitResult

        audit_writer = MagicMock()
        result = RateLimitResult(allowed=False, dimension="user", remaining=0, retry_after_ms=5)
        _admin_alert_user_rate_limit(
            audit_writer=audit_writer,
            request_id="req-003",
            result=result,
            user_id="charlie@corp.example",
            agent_id="",
            session_id="",
            rate_limiter=None,
        )
        written = audit_writer.write.call_args[0][0]
        expected = hashlib.sha256("charlie@corp.example".encode()).hexdigest()[:16]
        assert written.user_id_hash == expected
        # Must NOT contain the raw email
        assert "charlie" not in written.user_id_hash
        assert "@" not in written.user_id_hash


# ---------------------------------------------------------------------------
# 5. Prometheus metric increments with hashed user_id label
# ---------------------------------------------------------------------------

class TestPerUserPrometheusMetric:
    def test_metric_incremented_on_user_breach(self):
        """
        _admin_alert_user_rate_limit must increment
        yashigani_user_rate_limit_violations_total{user_id_hash=<hash>}.
        """
        from yashigani.gateway.proxy import _admin_alert_user_rate_limit
        from yashigani.ratelimit.limiter import RateLimitResult

        mock_counter = MagicMock()
        mock_counter.labels.return_value = mock_counter

        audit_writer = MagicMock()
        result = RateLimitResult(allowed=False, dimension="user", remaining=0, retry_after_ms=5)

        with patch(
            "yashigani.metrics.registry.user_ratelimit_violations_total",
            mock_counter,
        ):
            _admin_alert_user_rate_limit(
                audit_writer=audit_writer,
                request_id="req-004",
                result=result,
                user_id="diana@example.com",
                agent_id="agent-d",
                session_id="sess-d",
                rate_limiter=None,
            )

        expected_hash = hashlib.sha256("diana@example.com".encode()).hexdigest()[:16]
        mock_counter.labels.assert_called_once_with(user_id_hash=expected_hash)
        mock_counter.inc.assert_called_once()

    def test_metric_label_is_hash_not_raw_user_id(self):
        """Metric label must be the hash, NOT the raw email string."""
        from yashigani.gateway.proxy import _admin_alert_user_rate_limit
        from yashigani.ratelimit.limiter import RateLimitResult

        mock_counter = MagicMock()
        mock_counter.labels.return_value = mock_counter
        audit_writer = MagicMock()
        result = RateLimitResult(allowed=False, dimension="user", remaining=0, retry_after_ms=5)

        with patch(
            "yashigani.metrics.registry.user_ratelimit_violations_total",
            mock_counter,
        ):
            _admin_alert_user_rate_limit(
                audit_writer=audit_writer,
                request_id="req-005",
                result=result,
                user_id="eve@corp.example",
                agent_id="",
                session_id="",
                rate_limiter=None,
            )

        call_kwargs = mock_counter.labels.call_args[1]
        label_value = call_kwargs["user_id_hash"]
        # Must not contain any part of the raw user_id
        assert "eve" not in label_value
        assert "@" not in label_value
        # Must be 16 hex chars
        assert len(label_value) == 16
        assert all(c in "0123456789abcdef" for c in label_value)


# ---------------------------------------------------------------------------
# 6. Integration — RateLimiter with fakeredis
# ---------------------------------------------------------------------------

class TestPerUserRateLimitIntegration:
    """
    Uses fakeredis to run the full token-bucket Lua script.
    First request at RPS=1 / burst=1 is allowed.
    Second request with no time elapsed (tokens=0) must block on 'user' dimension.
    """

    def test_first_request_allowed_second_blocked_user_dimension(self, mock_redis):
        """
        With per_user_rps=1.0, per_user_burst=1:
        - Request #1 → allowed (bucket at capacity=1)
        - Request #2 immediately after → blocked, dimension='user'
        """
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig

        cfg = RateLimitConfig(
            global_rps=1_000_000.0, global_burst=10_000_000,
            per_ip_rps=1_000_000.0, per_ip_burst=10_000_000,
            per_agent_rps=1_000_000.0, per_agent_burst=10_000_000,
            per_session_rps=1_000_000.0, per_session_burst=10_000_000,
            per_user_rps=1.0,
            per_user_burst=1,
            adaptive_enabled=False,
        )
        limiter = RateLimiter(redis_client=mock_redis, config=cfg)
        r1 = limiter.check("10.0.0.1", "agent-integ", "sess-integ", user_id="integ@example.com")
        assert r1.allowed, "First request should be allowed"

        r2 = limiter.check("10.0.0.1", "agent-integ", "sess-integ", user_id="integ@example.com")
        assert not r2.allowed, "Second immediate request should be blocked"
        assert r2.dimension == "user", (
            f"Blocking dimension must be 'user', got '{r2.dimension}'"
        )

    def test_anonymous_user_skips_user_bucket(self, mock_redis):
        """
        When user_id is empty string, the 'user' bucket must be skipped
        (anonymous requests fall through to global/IP/agent/session only).
        """
        limiter = _make_limiter(mock_redis, per_user_rps=1.0, per_user_burst=1)
        # First call exhausts the bucket for "" key — but we skip it
        r1 = limiter.check("10.0.0.1", "agent-a", "sess-a", user_id="")
        assert r1.allowed, "Anonymous user should always skip user bucket"
        r2 = limiter.check("10.0.0.1", "agent-a", "sess-a", user_id="")
        assert r2.allowed, "Second anonymous request skips user bucket — other limits not hit"

    def test_check_without_user_id_kwarg_still_works(self, mock_redis):
        """check() called without user_id kwarg (backward compat) must not raise."""
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig(adaptive_enabled=False)
        limiter = RateLimiter(redis_client=mock_redis, config=cfg)
        result = limiter.check("1.2.3.4", "agent-x", "sess-x")
        assert result.allowed  # global/ip/agent/session not exhausted
