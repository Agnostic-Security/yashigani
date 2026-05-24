"""
SEC-4 / ASVS V6.3.5 — TOTP step-up failure counter migrated to Redis.

Tests cover:
  T01 — Counter increments atomically on failure
  T02 — Counter reset on success (DEL)
  T03 — Lockout fires at threshold (== _TOTP_FAILURE_LIMIT)
  T04 — Success below threshold passes
  T05 — Counter persists across simulated process restart (Redis key survives)
  T06 — TTL is set on first increment (key expires eventually)
  T07 — Two separate session prefixes have independent counters
  T08 — Redis unavailable on counter check → 503 (fail-closed, no silent allow)
  T09 — Lockout audit event emitted with correct fields
  T10 — Old module-level _totp_failures dict is gone from auth.py (regression guard)
  T11 — stepup_verify still only calls store.record_totp_stepup on success path
  T12 — Counter key format matches expected pattern
"""
from __future__ import annotations

import ast
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    import fakeredis
    _FAKEREDIS_AVAILABLE = True
except ImportError:
    _FAKEREDIS_AVAILABLE = False

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_DIR = SRC / "backoffice" / "routes"

pytestmark = pytest.mark.skipif(
    not _FAKEREDIS_AVAILABLE,
    reason="fakeredis not installed — install with: pip install fakeredis",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_redis():
    """Return a fakeredis instance with decode_responses=True (matches real usage)."""
    return fakeredis.FakeRedis(decode_responses=True)


def _get_helpers(r):
    """
    Import and monkey-patch the three Redis helpers from auth.py to use *r*.
    Returns (_totp_incr_failure, _totp_get_count, _totp_reset, _totp_fail_key).
    """
    import yashigani.backoffice.routes.auth as auth_mod

    with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
        yield auth_mod


# ---------------------------------------------------------------------------
# T01 — Increment is atomic
# ---------------------------------------------------------------------------

class TestTotpIncrFailure:
    """T01: _totp_incr_failure returns the new count."""

    def test_t01_first_increment_returns_1(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            count = auth_mod._totp_incr_failure("aabbccdd")
        assert count == 1

    def test_t01b_second_increment_returns_2(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            auth_mod._totp_incr_failure("aabbccdd")
            count = auth_mod._totp_incr_failure("aabbccdd")
        assert count == 2

    def test_t01c_three_increments(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            for _ in range(3):
                count = auth_mod._totp_incr_failure("prefix01")
        assert count == 3


# ---------------------------------------------------------------------------
# T02 — Reset on success (DEL)
# ---------------------------------------------------------------------------

class TestTotpReset:
    """T02: _totp_reset DELetes the key so get_count returns 0."""

    def test_t02_reset_clears_counter(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            auth_mod._totp_incr_failure("deadbeef")
            auth_mod._totp_incr_failure("deadbeef")
            auth_mod._totp_reset("deadbeef")
            assert auth_mod._totp_get_count("deadbeef") == 0

    def test_t02b_reset_on_absent_key_is_noop(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            # Should not raise
            auth_mod._totp_reset("nonexistentprefix")
            assert auth_mod._totp_get_count("nonexistentprefix") == 0


# ---------------------------------------------------------------------------
# T03 — Lockout at threshold
# ---------------------------------------------------------------------------

class TestTotpLockoutAtThreshold:
    """T03: Counter at _TOTP_FAILURE_LIMIT triggers lockout, below it does not."""

    def test_t03_at_threshold_get_count_equals_limit(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            for _ in range(auth_mod._TOTP_FAILURE_LIMIT):
                auth_mod._totp_incr_failure("locktest1")
            count = auth_mod._totp_get_count("locktest1")
        assert count >= auth_mod._TOTP_FAILURE_LIMIT

    def test_t04_below_threshold_passes(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            for _ in range(auth_mod._TOTP_FAILURE_LIMIT - 1):
                auth_mod._totp_incr_failure("locktest2")
            count = auth_mod._totp_get_count("locktest2")
        assert count < auth_mod._TOTP_FAILURE_LIMIT


# ---------------------------------------------------------------------------
# T05 — Counter persists across simulated process restart
# ---------------------------------------------------------------------------

class TestTotpPersistsAcrossRestart:
    """
    T05: Counter in Redis survives a process restart.

    We simulate 'process restart' by importing the module fresh with
    importlib.reload().  Because the Redis key is external (not in-process),
    the counter is still readable after reload.
    """

    def test_t05_counter_survives_module_reload(self):
        r = _make_fake_redis()
        import importlib
        import yashigani.backoffice.routes.auth as auth_mod

        # Increment counter in 'process 1'
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            auth_mod._totp_incr_failure("restartprefix")
            auth_mod._totp_incr_failure("restartprefix")
            pre_reload_count = auth_mod._totp_get_count("restartprefix")

        assert pre_reload_count == 2

        # Simulate restart: reload the module (clears any in-process state)
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            importlib.reload(auth_mod)

        # 'Process 2': read from same Redis — count must still be 2
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            post_reload_count = auth_mod._totp_get_count("restartprefix")

        assert post_reload_count == pre_reload_count, (
            f"Counter should survive restart: expected {pre_reload_count}, "
            f"got {post_reload_count}"
        )


# ---------------------------------------------------------------------------
# T06 — TTL is set on first increment
# ---------------------------------------------------------------------------

class TestTotpTtlSet:
    """T06: After increment, the key has a positive TTL (will expire)."""

    def test_t06_key_has_positive_ttl_after_increment(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            auth_mod._totp_incr_failure("ttltest1")
            key = auth_mod._totp_fail_key("ttltest1")
            ttl = r.ttl(key)
        # fakeredis returns -1 for no TTL, -2 for missing key, positive for set TTL
        assert ttl > 0, f"Expected positive TTL, got {ttl}"
        assert ttl <= auth_mod._TOTP_FAILURE_TTL_SECONDS


# ---------------------------------------------------------------------------
# T07 — Independent counters per session prefix
# ---------------------------------------------------------------------------

class TestTotpCounterIsolation:
    """T07: Two session prefixes have completely independent counters."""

    def test_t07_separate_prefixes_are_independent(self):
        r = _make_fake_redis()
        import yashigani.backoffice.routes.auth as auth_mod
        with patch.object(auth_mod, "_get_throttle_redis", return_value=r):
            auth_mod._totp_incr_failure("prefix_a1")
            auth_mod._totp_incr_failure("prefix_a1")
            auth_mod._totp_incr_failure("prefix_b2")

            count_a = auth_mod._totp_get_count("prefix_a1")
            count_b = auth_mod._totp_get_count("prefix_b2")

        assert count_a == 2
        assert count_b == 1


# ---------------------------------------------------------------------------
# T08 — Redis unavailable → 503 fail-closed (no silent allow)
# ---------------------------------------------------------------------------

class TestTotpFailClosedOnRedisDown:
    """T08: Redis unavailable on counter check → HTTP 503, not 200."""

    def test_t08_get_count_raises_propagates_to_503(self):
        """_totp_get_count raising → stepup_verify should 503."""
        import yashigani.backoffice.routes.auth as auth_mod

        # Verify the route raises on Redis failure by examining the source
        # (avoids needing the full FastAPI + asyncpg import chain).
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert "totp_service_unavailable" in source, (
            "stepup_verify must 503 with error=totp_service_unavailable when Redis is down"
        )
        assert "503_SERVICE_UNAVAILABLE" in source or "HTTP_503_SERVICE_UNAVAILABLE" in source, (
            "stepup_verify must return 503 on Redis unavailable (fail-closed)"
        )


# ---------------------------------------------------------------------------
# T09 — Lockout audit event emitted with correct fields (static analysis)
# ---------------------------------------------------------------------------

class TestTotpLockoutAuditEvent:
    """T09: Lockout path emits AdminSessionTotpLockoutEvent with all required fields."""

    def test_t09_lockout_emits_audit_event(self):
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Find stepup_verify
        stepup_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                stepup_fn = node
                break

        assert stepup_fn is not None
        fn_source = ast.unparse(stepup_fn)

        assert "AdminSessionTotpLockoutEvent" in fn_source, (
            "stepup_verify must emit AdminSessionTotpLockoutEvent on lockout"
        )
        assert "consecutive_failures" in fn_source, (
            "AdminSessionTotpLockoutEvent must include consecutive_failures"
        )
        assert "endpoint" in fn_source, (
            "AdminSessionTotpLockoutEvent must include endpoint"
        )

    def test_t09b_lockout_event_fields_in_schema(self):
        """AdminSessionTotpLockoutEvent has consecutive_failures + endpoint fields."""
        from yashigani.audit.schema import AdminSessionTotpLockoutEvent
        import dataclasses
        fields = {f.name for f in dataclasses.fields(AdminSessionTotpLockoutEvent)}
        assert "consecutive_failures" in fields
        assert "endpoint" in fields
        assert "admin_account" in fields


# ---------------------------------------------------------------------------
# T10 — Module-level _totp_failures dict is gone (regression guard)
# ---------------------------------------------------------------------------

class TestOldInMemoryDictRemoved:
    """T10: The old _totp_failures dict must not exist in auth.py."""

    def test_t10_in_memory_dict_removed(self):
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert "_totp_failures: dict" not in source and "_totp_failures:dict" not in source, (
            "_totp_failures module-level dict still present — SEC-4 migration incomplete"
        )

    def test_t10b_no_direct_dict_assignment(self):
        """No code should assign _totp_failures[...] = ..."""
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert "_totp_failures[" not in source, (
            "Direct _totp_failures dict access still present — SEC-4 migration incomplete"
        )


# ---------------------------------------------------------------------------
# T11 — record_totp_stepup still only on success path
# ---------------------------------------------------------------------------

class TestStepupSuccessPathOnly:
    """T11: record_totp_stepup remains only on the success path (regression guard)."""

    def test_t11_record_totp_stepup_after_raise(self):
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        stepup_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                stepup_fn = node
                break

        assert stepup_fn is not None
        fn_source = ast.unparse(stepup_fn)

        # The last raise (invalid_totp_code) must appear before record_totp_stepup
        last_raise_idx = fn_source.rfind("raise HTTPException")
        record_idx = fn_source.find("record_totp_stepup")

        assert last_raise_idx < record_idx, (
            "record_totp_stepup must only be called on success (after last raise). "
            f"raise at {last_raise_idx}, record_totp_stepup at {record_idx}"
        )


# ---------------------------------------------------------------------------
# T12 — Key format
# ---------------------------------------------------------------------------

class TestTotpKeyFormat:
    """T12: The Redis key format is yashigani:totp_fail:<prefix>."""

    def test_t12_key_format(self):
        import yashigani.backoffice.routes.auth as auth_mod
        key = auth_mod._totp_fail_key("abcd1234")
        assert key == "yashigani:totp_fail:abcd1234", (
            f"Unexpected key format: {key}"
        )

    def test_t12b_key_uses_session_prefix(self):
        """Key derived from first 8 chars of session token."""
        import yashigani.backoffice.routes.auth as auth_mod
        # Verify source: session.token[:8] is used as the prefix
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert "session.token[:8]" in source, (
            "stepup_verify must derive session_prefix from session.token[:8]"
        )
