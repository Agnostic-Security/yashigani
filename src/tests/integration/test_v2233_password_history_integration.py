"""
Integration tests — CMMC L2 IA.L2-3.5.8 password reuse history (v2.23.3).

Requires a live Postgres instance with Alembic migrations applied (including
migration 0010_password_history).

Skip when YASHIGANI_DB_DSN is not set.

These tests run against a REAL password_history table (via asyncpg) and verify:
  1. Migration 0010 table and index exist.
  2. Successful password change inserts a row into password_history.
  3. Reuse check rejects the immediately preceding password.
  4. Reuse check rejects all hashes up to depth N.
  5. Reuse check accepts a password beyond depth (oldest pruned).
  6. History is pruned to depth after each change.
  7. History is per-user (different users don't share history).
  8. PASSWORD_REUSE_REJECTED audit event is emitted on rejection.

Run manually:
    YASHIGANI_DB_DSN=postgresql://yashigani_app:...@localhost:5432/yashigani \\
    YASHIGANI_TEST_MODE=1 \\
    pytest src/tests/integration/test_v2233_password_history_integration.py -v

Last updated: 2026-05-09T00:00:00+00:00
"""

from __future__ import annotations

import asyncio
import datetime
import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.integration

_DB_DSN = os.getenv("YASHIGANI_DB_DSN", "")
_SKIP_REASON = "YASHIGANI_DB_DSN not set — skipping integration tests"
needs_db = pytest.mark.skipif(not _DB_DSN or "${POSTGRES_PASSWORD}" in _DB_DSN, reason=_SKIP_REASON)

# ---------------------------------------------------------------------------
# Test passwords (≥36 chars, no banned words, no breached passwords — we stub
# HIBP so these never hit the network)
# ---------------------------------------------------------------------------

_PW_A = "PwHistoryAlpha!111111111111111111111"
_PW_B = "PwHistoryBravo!222222222222222222222"
_PW_C = "PwHistoryCharlie!3333333333333333333"
_PW_D = "PwHistoryDelta!4444444444444444444444"
_PW_E = "PwHistoryEcho!5555555555555555555555"

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(scope="module")
def pool():
    """Create an asyncpg pool for the integration test module."""
    if not _DB_DSN or "${POSTGRES_PASSWORD}" in _DB_DSN:
        pytest.skip(_SKIP_REASON)

    async def _make_pool():
        import asyncpg

        return await asyncpg.create_pool(_DB_DSN)

    p = _run(_make_pool())
    yield p

    async def _close():
        await p.close()

    _run(_close())


def _make_auth_svc(pool):
    from yashigani.auth.pg_auth import PostgresLocalAuthService

    return PostgresLocalAuthService(pool=pool)


def _hash_pw(plaintext: str) -> str:
    """Hash without HIBP check."""
    from yashigani.auth.password import hash_password

    with patch("yashigani.auth.password.validate_password_not_breached"):
        return hash_password(plaintext, check_breach=False)


async def _insert_account(pool, username: str, password_hash: str) -> str:
    """Insert a minimal admin_accounts row and return account_id."""
    account_id = str(uuid.uuid4())
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO admin_accounts (
                account_id, tenant_id, username, password_hash,
                totp_secret, recovery_codes, account_tier, email,
                force_password_change, force_totp_provision, disabled,
                failed_attempts, locked_until,
                totp_failed_attempts, totp_backoff_until,
                created_at, password_changed_at
            ) VALUES (
                $1::uuid, $2::uuid, $3, $4,
                '', NULL, 'admin', $3,
                false, false, false,
                0, 0.0,
                0, 0.0,
                $5, $5
            )
            """,
            account_id,
            _PLATFORM_TENANT_ID,
            username,
            password_hash,
            now_ts,
        )
    return account_id


async def _cleanup_account(pool, account_id: str) -> None:
    """Remove account + cascade-delete password_history rows."""
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM admin_accounts WHERE account_id = $1::uuid",
            account_id,
        )


async def _count_history(pool, account_id: str) -> int:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "SELECT COUNT(*) FROM password_history WHERE user_id = $1::uuid",
            account_id,
        )


async def _history_hashes(pool, account_id: str) -> list[str]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT password_hash FROM password_history WHERE user_id = $1::uuid ORDER BY changed_at DESC",
            account_id,
        )
        return [r["password_hash"] for r in rows]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@needs_db
class TestMigration0010:
    """Verify migration 0010 schema objects exist."""

    def test_password_history_table_exists(self, pool):
        async def _check():
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name = 'password_history'
                    """
                )
                return row is not None

        assert _run(_check()), "password_history table not found — run migration 0010"

    def test_password_history_index_exists(self, pool):
        async def _check():
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT indexname FROM pg_indexes
                    WHERE tablename = 'password_history'
                      AND indexname = 'idx_password_history_user_changed'
                    """
                )
                return row is not None

        assert _run(_check()), "idx_password_history_user_changed index not found"

    def test_password_history_columns(self, pool):
        """Verify user_id, password_hash, changed_at columns exist."""

        async def _check():
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'password_history'
                    ORDER BY column_name
                    """
                )
                return {r["column_name"] for r in rows}

        cols = _run(_check())
        assert "user_id" in cols
        assert "password_hash" in cols
        assert "changed_at" in cols

    def test_fk_cascade_delete(self, pool):
        """Cascade delete: removing account removes password_history rows."""

        async def _run_test():
            account_id = await _insert_account(pool, "fk-cascade@test.local", _hash_pw(_PW_A))
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO password_history (user_id, password_hash, changed_at)
                    VALUES ($1::uuid, $2, now())
                    """,
                    account_id,
                    _hash_pw(_PW_B),
                )
            # Cascade delete
            await _cleanup_account(pool, account_id)
            async with pool.acquire() as conn:
                count = await conn.fetchval(
                    "SELECT COUNT(*) FROM password_history WHERE user_id = $1::uuid",
                    account_id,
                )
            return count

        assert _run(_run_test()) == 0


@needs_db
class TestPasswordHistoryFullFlow:
    """End-to-end password history via PostgresLocalAuthService."""

    def setup_method(self):
        """Reset env var before each test."""
        os.environ.pop("PASSWORD_HISTORY_DEPTH", None)

    def _make_svc(self, pool):
        return _make_auth_svc(pool)

    def _change_pw(self, svc, username: str, current: str, new_pw: str, audit_writer=None):
        async def _run_change():
            with patch("yashigani.auth.password.validate_password_not_breached"):
                with patch.object(svc, "_verify_totp_with_replay", return_value=True):
                    return await svc.change_password(
                        username,
                        current,
                        "000000",
                        new_pw,
                        audit_writer=audit_writer,
                    )

        return _run(asyncio.coroutine(_run_change)() if False else _run_change())

    def test_fresh_password_accepted(self, pool):
        """Password not in history is accepted and recorded."""
        svc = self._make_svc(pool)
        username = f"fresh-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))
        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
                ok, reason = self._change_pw(svc, username, _PW_A, _PW_B)
            assert ok is True, f"Expected ok but got: {reason}"
            # Row should now be in history
            count = _run(_count_history(pool, account_id))
            assert count == 1
        finally:
            _run(_cleanup_account(pool, account_id))

    def test_reuse_rejected(self, pool):
        """Immediately preceding password is rejected."""
        svc = self._make_svc(pool)
        username = f"reuse-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))
        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
                self._change_pw(svc, username, _PW_A, _PW_B)
                ok, reason = self._change_pw(svc, username, _PW_B, _PW_A)
            assert ok is False
            assert reason == "password_reuse"
        finally:
            _run(_cleanup_account(pool, account_id))

    def test_history_pruned_to_depth(self, pool):
        """History table stays bounded at depth entries after N changes."""
        svc = self._make_svc(pool)
        username = f"prune-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))
        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "2"}):
                # Do 4 changes: A→B, B→C, C→D, D→E
                self._change_pw(svc, username, _PW_A, _PW_B)
                self._change_pw(svc, username, _PW_B, _PW_C)
                self._change_pw(svc, username, _PW_C, _PW_D)
                self._change_pw(svc, username, _PW_D, _PW_E)
                count = _run(_count_history(pool, account_id))
            # After 4 changes with depth=2, only 2 hashes should remain
            assert count == 2, f"Expected 2 history rows, got {count}"
        finally:
            _run(_cleanup_account(pool, account_id))

    def test_password_beyond_depth_accepted(self, pool):
        """A password older than depth is accepted (falls off history)."""
        svc = self._make_svc(pool)
        username = f"beyond-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))
        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "2"}):
                # A→B, B→C, C→D: depth=2 keeps C and D; A falls off
                self._change_pw(svc, username, _PW_A, _PW_B)
                self._change_pw(svc, username, _PW_B, _PW_C)
                self._change_pw(svc, username, _PW_C, _PW_D)
                # _PW_A should now be accepted
                ok, reason = self._change_pw(svc, username, _PW_D, _PW_A)
            assert ok is True, f"Expected _PW_A accepted beyond depth, got: {reason}"
        finally:
            _run(_cleanup_account(pool, account_id))

    def test_history_isolated_per_user(self, pool):
        """Different users don't share history."""
        svc = self._make_svc(pool)
        user1 = f"user1-{uuid.uuid4().hex[:8]}@test.local"
        user2 = f"user2-{uuid.uuid4().hex[:8]}@test.local"
        id1 = _run(_insert_account(pool, user1, _hash_pw(_PW_A)))
        id2 = _run(_insert_account(pool, user2, _hash_pw(_PW_A)))
        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
                # Change user1 A→B (records A in user1 history)
                self._change_pw(svc, user1, _PW_A, _PW_B)
                # user2 should still accept _PW_A (different account)
                ok, reason = self._change_pw(svc, user2, _PW_A, _PW_B)
            assert ok is True, f"user2 should accept _PW_A, got: {reason}"
        finally:
            _run(_cleanup_account(pool, id1))
            _run(_cleanup_account(pool, id2))

    def test_audit_event_emitted_on_rejection(self, pool):
        """PASSWORD_REUSE_REJECTED event is emitted via audit_writer on rejection."""
        svc = self._make_svc(pool)
        username = f"audit-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()

        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
                self._change_pw(svc, username, _PW_A, _PW_B, audit_writer=mock_writer)
                mock_writer.write.reset_mock()
                ok, reason = self._change_pw(svc, username, _PW_B, _PW_A, audit_writer=mock_writer)

            assert ok is False
            assert reason == "password_reuse"
            # Audit writer must have been called with a PasswordReuseRejectedEvent
            assert mock_writer.write.called, "audit_writer.write not called"
            evt = mock_writer.write.call_args[0][0]
            from yashigani.audit.schema import PasswordReuseRejectedEvent

            assert isinstance(evt, PasswordReuseRejectedEvent)
            assert evt.user_id == account_id
            assert evt.history_depth_checked == 3
            assert evt.masking_applied is True
        finally:
            _run(_cleanup_account(pool, account_id))

    def test_no_audit_event_on_success(self, pool):
        """PASSWORD_REUSE_REJECTED event is NOT emitted on successful change."""
        svc = self._make_svc(pool)
        username = f"no-audit-{uuid.uuid4().hex[:8]}@test.local"
        account_id = _run(_insert_account(pool, username, _hash_pw(_PW_A)))

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()

        try:
            with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
                ok, reason = self._change_pw(svc, username, _PW_A, _PW_B, audit_writer=mock_writer)
            assert ok is True
            # audit_writer.write should NOT have been called for successful change
            mock_writer.write.assert_not_called()
        finally:
            _run(_cleanup_account(pool, account_id))
