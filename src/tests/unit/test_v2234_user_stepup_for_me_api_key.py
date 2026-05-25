"""
Unit tests — v2.23.4 Gap B: widen /auth/stepup to accept user sessions.

Finding: /me/api-key unreachable for regular users because /auth/stepup
previously required AdminSession (403 insufficient_tier for non-admins).
Fix: Changed session dependency from AdminSession → AnySession in auth.py.

ASVS V6.8.4 — Re-authentication before critical operations.
ASVS V7.3.4 — Audit log accuracy: account_tier in stepup event reflects actual tier.

Last updated: 2026-05-17T23:55:00+01:00

Test matrix:
  T1  — Anonymous session (no cookie) → 401 authentication_required
  T2  — Admin session + fresh valid TOTP → 200 stepup_verified=true (regression)
  T3  — User session + fresh valid TOTP → 200 stepup_verified=true (NEW)
  T4  — User session + wrong TOTP → 401 invalid_totp_code + failure counter incremented
  T5  — User session + replayed TOTP (used in same window) → 401 (replay-rejected)
  T6  — Wrong-tenant user (account_id not in DB) → 403 totp_not_configured
  T7  — User session, 4 failures → 5th attempt → 429 stepup_attempts_exceeded
  T8  — After successful user-stepup, assert_fresh_stepup passes (me/api-key gate opens)
  T9  — User-tier step-up audit event has account_tier="user" (Iris FINDING-001)
  T10 — Admin-tier step-up audit event has account_tier="admin" (Iris FINDING-001)
  T14 — _make_login_attempt_event passes account_tier through (Iris class-of-bug follow-on)
"""
from __future__ import annotations

import asyncio
import time
import unittest.mock as mock
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(
    token: str = "a" * 64,
    account_id: str = "acc-user-001",
    account_tier: str = "user",
    last_totp_verified_at: Optional[float] = None,
):
    from yashigani.auth.session import Session
    return Session(
        token=token,
        account_id=account_id,
        account_tier=account_tier,
        created_at=time.time(),
        last_active_at=time.time(),
        expires_at=time.time() + 3600,
        ip_prefix="192.168.1.0",
        last_totp_verified_at=last_totp_verified_at,
    )


def _make_admin_session(token: str = "b" * 64, account_id: str = "acc-admin-001"):
    return _make_session(token=token, account_id=account_id, account_tier="admin")


def _make_account_record(
    account_id: str = "acc-user-001",
    username: str = "alice",
    account_tier: str = "user",
    totp_secret: str = "JBSWY3DPEHPK3PXP",
):
    from yashigani.auth.local_auth import AccountRecord
    return AccountRecord(
        account_id=account_id,
        username=username,
        password_hash="$2b$12$fakehash",
        totp_secret=totp_secret,
        recovery_codes=None,
        account_tier=account_tier,
        force_password_change=False,
        force_totp_provision=False,
    )


@asynccontextmanager
async def _fake_pg_ctx():
    """Minimal async context manager simulating _pg_tenant_transaction()."""
    yield MagicMock()  # connection object — not used in tests


def _patch_stepup_route(
    session: object,
    account_record: object,
    totp_ok: bool = True,
    store_record_returns: bool = True,
):
    """
    Return a dict of patch targets to wire a stepup_verify call.
    Caller is expected to use patch.multiple or individual patches.
    """
    from yashigani.backoffice import state as _state_mod

    mock_store = MagicMock()
    mock_store.record_totp_stepup.return_value = store_record_returns

    mock_auth_service = MagicMock()
    mock_auth_service.get_account_by_id = AsyncMock(return_value=account_record)
    mock_auth_service._verify_totp_with_replay = AsyncMock(return_value=totp_ok)

    mock_audit = MagicMock()

    bs = _state_mod.backoffice_state
    return {
        "auth_service": mock_auth_service,
        "audit_writer": mock_audit,
        "store": mock_store,
    }


# ---------------------------------------------------------------------------
# Invoke stepup_verify directly (no HTTP server needed)
# ---------------------------------------------------------------------------

async def _call_stepup(session, account_record, totp_ok=True, totp_code="123456"):
    """
    Call stepup_verify() directly with mocked dependencies.
    Returns (result_dict, mock_store) or raises HTTPException.
    """
    result, mock_store, _audit = await _call_stepup_full(session, account_record, totp_ok=totp_ok, totp_code=totp_code)
    return result, mock_store


async def _call_stepup_full(
    session,
    account_record,
    totp_ok=True,
    totp_code="123456",
    failure_count_override: int = 0,
):
    """
    Call stepup_verify() directly with mocked dependencies.
    Returns (result_dict, mock_store, mock_audit) or raises HTTPException.
    Exposes mock_audit so callers can inspect write() call args.

    Redis helpers (_totp_get_count, _totp_incr_failure, _totp_reset) are patched
    to avoid requiring a live Redis connection in unit tests.  The failure counter
    starts at `failure_count_override` (default 0 = below limit).
    """
    from yashigani.backoffice.routes.auth import StepUpRequest
    from yashigani.backoffice import state as _state_mod

    body = StepUpRequest(totp_code=totp_code)

    mock_store = MagicMock()
    mock_store.record_totp_stepup.return_value = True

    mock_auth_service = MagicMock()
    mock_auth_service.get_account_by_id = AsyncMock(return_value=account_record)
    mock_auth_service._verify_totp_with_replay = AsyncMock(return_value=totp_ok)

    mock_audit = MagicMock()

    orig_auth = _state_mod.backoffice_state.auth_service
    orig_audit = _state_mod.backoffice_state.audit_writer

    try:
        _state_mod.backoffice_state.auth_service = mock_auth_service
        _state_mod.backoffice_state.audit_writer = mock_audit

        from yashigani.backoffice.routes import auth as auth_mod

        @asynccontextmanager
        async def _fake_pg():
            yield MagicMock()

        with patch.object(auth_mod, "_pg_tenant_transaction", return_value=_fake_pg()), \
             patch("yashigani.backoffice.routes.auth._totp_get_count", return_value=failure_count_override), \
             patch("yashigani.backoffice.routes.auth._totp_incr_failure", return_value=failure_count_override + 1), \
             patch("yashigani.backoffice.routes.auth._totp_reset", return_value=None):
            from yashigani.backoffice.routes.auth import stepup_verify
            result = await stepup_verify(body=body, session=session, store=mock_store)
            return result, mock_store, mock_audit
    finally:
        _state_mod.backoffice_state.auth_service = orig_auth
        _state_mod.backoffice_state.audit_writer = orig_audit


# ---------------------------------------------------------------------------
# T1 — Anonymous session → 401 authentication_required
# ---------------------------------------------------------------------------

class TestT1AnonymousRejected:
    """T1: No session cookie → 401 authentication_required from AnySession dependency."""

    def test_require_any_session_raises_401_when_no_token(self):
        """
        AnySession (require_any_session) raises 401 authentication_required
        when no cookie is present. This covers the anonymous path for
        /auth/stepup since it now uses AnySession.
        """
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from fastapi import FastAPI, Request
        from yashigani.backoffice.middleware import require_any_session

        # Build a tiny app to exercise the dependency
        app = FastAPI()

        mock_store = MagicMock()
        mock_store.get.return_value = None

        @app.get("/test")
        async def _test(session=mock.sentinel):
            return {"ok": True}

        # Exercise require_any_session directly with no cookie
        from fastapi import Request as FR
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "query_string": b"",
            "headers": [],
        }
        req = FR(scope=scope)

        async def _run():
            from yashigani.backoffice.middleware import require_any_session, get_session_store
            with pytest.raises(HTTPException) as exc_info:
                await require_any_session(request=req, store=mock_store)
            return exc_info.value

        exc = asyncio.run(_run())
        assert exc.status_code == 401
        assert exc.detail["error"] == "authentication_required"


# ---------------------------------------------------------------------------
# T2 — Admin session + fresh valid TOTP → 200 (regression)
# ---------------------------------------------------------------------------

class TestT2AdminSessionRegression:
    """T2: Admin session path still works after widening to AnySession."""

    def test_admin_session_valid_totp_succeeds(self):
        """Admin session + valid TOTP returns 200 with stepup_verified=True."""
        session = _make_admin_session()
        record = _make_account_record(
            account_id="acc-admin-001",
            username="admin",
            account_tier="admin",
        )

        async def _run():
            result, store = await _call_stepup(session, record, totp_ok=True)
            return result, store

        result, store = asyncio.run(_run())
        assert result["stepup_verified"] is True
        assert result["status"] == "ok"
        assert "ttl_seconds" in result
        store.record_totp_stepup.assert_called_once_with(session.token)


# ---------------------------------------------------------------------------
# T3 — User session + fresh valid TOTP → 200 (NEW positive case)
# ---------------------------------------------------------------------------

class TestT3UserSessionValidTotp:
    """T3: Regular user (group users) + valid TOTP → 200 stepup_verified=True."""

    def test_user_session_valid_totp_succeeds(self):
        """alice (account_tier='user') can now satisfy the step-up prerequisite."""
        session = _make_session(account_tier="user", account_id="acc-user-001")
        record = _make_account_record(
            account_id="acc-user-001",
            username="alice",
            account_tier="user",
        )

        async def _run():
            result, store = await _call_stepup(session, record, totp_ok=True)
            return result, store

        result, store = asyncio.run(_run())
        assert result["stepup_verified"] is True
        assert result["status"] == "ok"
        assert "ttl_seconds" in result
        store.record_totp_stepup.assert_called_once_with(session.token)


# ---------------------------------------------------------------------------
# T4 — User session + wrong TOTP → 401 + failure counter incremented
# ---------------------------------------------------------------------------

class TestT4UserSessionWrongTotp:
    """T4: Wrong TOTP code → 401 invalid_totp_code + failure counter incremented.

    The failure counter was migrated from in-memory _totp_failures dict to Redis
    (_totp_incr_failure / _totp_get_count / _totp_reset).  This test verifies
    that _totp_incr_failure is called exactly once on a wrong-TOTP path.

    We call stepup_verify directly (not through _call_stepup_full) so we can
    capture _totp_incr_failure without it being pre-patched by the helper.
    """

    def test_user_session_wrong_totp_increments_counter(self):
        from fastapi import HTTPException
        from yashigani.backoffice import state as _state_mod
        from yashigani.backoffice.routes import auth as auth_mod

        session = _make_session(token="c" * 64, account_tier="user", account_id="acc-user-002")
        record = _make_account_record(account_id="acc-user-002", username="bob")

        incr_calls: list[str] = []

        def _fake_incr(prefix: str) -> int:
            incr_calls.append(prefix)
            return 1  # first failure; below lock-out limit of 3

        mock_store = MagicMock()
        mock_auth_service = MagicMock()
        mock_auth_service.get_account_by_id = AsyncMock(return_value=record)
        mock_auth_service._verify_totp_with_replay = AsyncMock(return_value=False)
        mock_audit = MagicMock()

        orig_auth = _state_mod.backoffice_state.auth_service
        orig_audit = _state_mod.backoffice_state.audit_writer
        try:
            _state_mod.backoffice_state.auth_service = mock_auth_service
            _state_mod.backoffice_state.audit_writer = mock_audit

            from yashigani.backoffice.routes.auth import StepUpRequest, stepup_verify

            @asynccontextmanager
            async def _fake_pg():
                yield MagicMock()

            async def _run():
                body = StepUpRequest(totp_code="000000")
                with patch.object(auth_mod, "_pg_tenant_transaction", return_value=_fake_pg()), \
                     patch("yashigani.backoffice.routes.auth._totp_get_count", return_value=0), \
                     patch("yashigani.backoffice.routes.auth._totp_incr_failure", side_effect=_fake_incr), \
                     patch("yashigani.backoffice.routes.auth._totp_reset", return_value=None):
                    with pytest.raises(HTTPException) as exc_info:
                        await stepup_verify(body=body, session=session, store=mock_store)
                return exc_info.value

            exc = asyncio.run(_run())
        finally:
            _state_mod.backoffice_state.auth_service = orig_auth
            _state_mod.backoffice_state.audit_writer = orig_audit

        assert exc.status_code == 401
        assert exc.detail["error"] == "invalid_totp_code"
        assert len(incr_calls) == 1, (
            f"_totp_incr_failure must be called exactly once on wrong TOTP; got {incr_calls}"
        )
        assert incr_calls[0] == session.token[:8], (
            f"incr called with wrong prefix: {incr_calls[0]!r} != {session.token[:8]!r}"
        )


# ---------------------------------------------------------------------------
# T5 — User session + replayed TOTP → 401 (replay-rejected via _verify_totp_with_replay)
# ---------------------------------------------------------------------------

class TestT5UserSessionReplay:
    """T5: Replay attack — _verify_totp_with_replay returns False → 401."""

    def test_replay_attack_rejected_for_user_session(self):
        """Replay of a used TOTP code is blocked by the Postgres replay cache."""
        from fastapi import HTTPException

        session = _make_session(token="d" * 64, account_tier="user", account_id="acc-user-003")
        record = _make_account_record(account_id="acc-user-003", username="carol")

        async def _run():
            # totp_ok=False simulates _verify_totp_with_replay returning False
            # (same path regardless of whether code is wrong or replayed)
            with pytest.raises(HTTPException) as exc_info:
                await _call_stepup(session, record, totp_ok=False, totp_code="654321")
            return exc_info.value

        exc = asyncio.run(_run())
        assert exc.status_code == 401
        assert exc.detail["error"] == "invalid_totp_code"


# ---------------------------------------------------------------------------
# T6 — Wrong-tenant user → 403 totp_not_configured
# ---------------------------------------------------------------------------

class TestT6WrongTenantUser:
    """T6: account_id not found in DB → 403 totp_not_configured (cross-tenant isolation)."""

    def test_wrong_tenant_account_returns_403(self):
        """
        If session.account_id does not exist in the platform DB
        (e.g., fabricated token or wrong-org session), get_account_by_id
        returns None → stepup_verify raises 403 totp_not_configured.

        Note: the 403 is returned BEFORE the TOTP failure counter is checked,
        so no Redis patching is needed for the core assertion.  We patch Redis
        helpers anyway for consistency (the function reaches _totp_get_count
        after the account lookup on None path, but it is guarded by an early
        return on None account_record).
        """
        from fastapi import HTTPException
        from yashigani.backoffice import state as _state_mod
        from yashigani.backoffice.routes import auth as auth_mod

        session = _make_session(token="e" * 64, account_tier="user", account_id="acc-nonexistent")
        # account_record=None → DB returned nothing
        account_record = None

        mock_store = MagicMock()
        mock_auth_service = MagicMock()
        mock_auth_service.get_account_by_id = AsyncMock(return_value=account_record)
        mock_audit = MagicMock()

        orig_auth = _state_mod.backoffice_state.auth_service
        orig_audit = _state_mod.backoffice_state.audit_writer
        try:
            _state_mod.backoffice_state.auth_service = mock_auth_service
            _state_mod.backoffice_state.audit_writer = mock_audit

            from yashigani.backoffice.routes.auth import StepUpRequest, stepup_verify

            @asynccontextmanager
            async def _fake_pg():
                yield MagicMock()

            async def _run():
                body = StepUpRequest(totp_code="000000")
                with patch.object(auth_mod, "_pg_tenant_transaction", return_value=_fake_pg()), \
                     patch("yashigani.backoffice.routes.auth._totp_get_count", return_value=0), \
                     patch("yashigani.backoffice.routes.auth._totp_incr_failure", return_value=1), \
                     patch("yashigani.backoffice.routes.auth._totp_reset", return_value=None):
                    with pytest.raises(HTTPException) as exc_info:
                        await stepup_verify(body=body, session=session, store=mock_store)
                return exc_info.value

            exc = asyncio.run(_run())
            assert exc.status_code == 403
            assert exc.detail["error"] == "totp_not_configured"
        finally:
            _state_mod.backoffice_state.auth_service = orig_auth
            _state_mod.backoffice_state.audit_writer = orig_audit


# ---------------------------------------------------------------------------
# T7 — 4 failed attempts → 5th attempt → 429 stepup_attempts_exceeded
# ---------------------------------------------------------------------------

class TestT7FailureLimitExceeded:
    """T7: _TOTP_FAILURE_LIMIT (3) exceeded → 429 stepup_attempts_exceeded.

    The failure counter is Redis-backed (_totp_get_count).  Simulate the limit
    being exceeded by patching _totp_get_count to return _TOTP_FAILURE_LIMIT.
    """

    def test_fifth_attempt_returns_429(self):
        """
        When the failure counter is already at or above _TOTP_FAILURE_LIMIT,
        the next attempt receives 429 immediately without calling TOTP verify.
        """
        from fastapi import HTTPException
        from unittest.mock import patch as _patch
        from yashigani.backoffice.routes.auth import _TOTP_FAILURE_LIMIT
        from yashigani.backoffice import state as _state_mod
        from yashigani.backoffice.routes import auth as auth_mod

        session = _make_session(token="f" * 64, account_tier="user", account_id="acc-user-007")
        record = _make_account_record(account_id="acc-user-007", username="dave")

        mock_store = MagicMock()
        mock_auth_service = MagicMock()
        mock_auth_service.get_account_by_id = AsyncMock(return_value=record)
        mock_audit = MagicMock()

        orig_auth = _state_mod.backoffice_state.auth_service
        orig_audit = _state_mod.backoffice_state.audit_writer
        try:
            _state_mod.backoffice_state.auth_service = mock_auth_service
            _state_mod.backoffice_state.audit_writer = mock_audit

            from yashigani.backoffice.routes.auth import StepUpRequest, stepup_verify

            @asynccontextmanager
            async def _fake_pg():
                yield MagicMock()

            # Patch _totp_get_count to return the limit (counter already at threshold)
            with _patch("yashigani.backoffice.routes.auth._totp_get_count", return_value=_TOTP_FAILURE_LIMIT):
                async def _run():
                    body = StepUpRequest(totp_code="111111")
                    with patch.object(auth_mod, "_pg_tenant_transaction", return_value=_fake_pg()):
                        with pytest.raises(HTTPException) as exc_info:
                            await stepup_verify(body=body, session=session, store=mock_store)
                    return exc_info.value

                exc = asyncio.run(_run())

            assert exc.status_code == 429
            assert exc.detail["error"] == "stepup_attempts_exceeded"
        finally:
            _state_mod.backoffice_state.auth_service = orig_auth
            _state_mod.backoffice_state.audit_writer = orig_audit


# ---------------------------------------------------------------------------
# T8 — After successful user-stepup, assert_fresh_stepup passes
# ---------------------------------------------------------------------------

class TestT8AssertFreshStepupPassesAfterUserStepup:
    """T8: session.last_totp_verified_at is set → assert_fresh_stepup does not raise."""

    def test_assert_fresh_stepup_passes_after_successful_user_stepup(self):
        """
        Simulates the full user-side flow:
        1. User stepup_verify succeeds → store.record_totp_stepup() is called.
        2. In-memory session has last_totp_verified_at set to now.
        3. assert_fresh_stepup(session) does NOT raise — /me/api-key gate opens.

        Note: store.record_totp_stepup updates Redis; we simulate it by updating
        the in-memory Session object directly, which is what the real flow does
        via SessionStore.get() on the next request.
        """
        from yashigani.auth.stepup import assert_fresh_stepup, StepUpRequired

        session = _make_session(account_tier="user", account_id="acc-user-008")
        record = _make_account_record(account_id="acc-user-008", username="eve")

        async def _run():
            # Perform stepup — record_totp_stepup will be called on the mock store.
            result, store = await _call_stepup(session, record, totp_ok=True)
            # Verify store.record_totp_stepup was called with the session token.
            store.record_totp_stepup.assert_called_once_with(session.token)
            return result

        result = asyncio.run(_run())
        assert result["stepup_verified"] is True

        # Simulate what SessionStore.get() returns after record_totp_stepup:
        # the session's last_totp_verified_at is set to time.time().
        session.last_totp_verified_at = time.time()

        # Now the /me/api-key gate (assert_fresh_stepup) must pass.
        # StepUpRequired must NOT be raised.
        assert_fresh_stepup(session)  # raises StepUpRequired on failure


# ---------------------------------------------------------------------------
# T9 — User-tier step-up audit event has account_tier="user" (Iris FINDING-001)
# ---------------------------------------------------------------------------

class TestT9UserTierAuditEvent:
    """T9: Iris FINDING-001 / ASVS V7.3.4 — user-tier stepup writes account_tier='user'."""

    def test_user_stepup_audit_event_has_user_tier(self):
        """
        After a successful user-tier step-up, the audit event written to the
        audit_writer must carry account_tier='user', not 'admin'.
        """
        session = _make_session(account_tier="user", account_id="acc-user-009", token="g" * 64)
        record = _make_account_record(
            account_id="acc-user-009",
            username="frank",
            account_tier="user",
        )

        async def _run():
            result, store, audit = await _call_stepup_full(session, record, totp_ok=True)
            return audit

        mock_audit = asyncio.run(_run())
        mock_audit.write.assert_called_once()
        event = mock_audit.write.call_args[0][0]
        assert event.account_tier == "user", (
            f"FINDING-001: expected account_tier='user' on user stepup event, got {event.account_tier!r}"
        )


# ---------------------------------------------------------------------------
# T10 — Admin-tier step-up audit event has account_tier="admin" (Iris FINDING-001)
# ---------------------------------------------------------------------------

class TestT10AdminTierAuditEvent:
    """T10: Iris FINDING-001 / ASVS V7.3.4 — admin-tier stepup writes account_tier='admin'."""

    def test_admin_stepup_audit_event_has_admin_tier(self):
        """
        After a successful admin-tier step-up, the audit event written to the
        audit_writer must carry account_tier='admin' (regression guard).
        """
        session = _make_admin_session(token="h" * 64, account_id="acc-admin-010")
        record = _make_account_record(
            account_id="acc-admin-010",
            username="superadmin",
            account_tier="admin",
        )

        async def _run():
            result, store, audit = await _call_stepup_full(session, record, totp_ok=True)
            return audit

        mock_audit = asyncio.run(_run())
        mock_audit.write.assert_called_once()
        event = mock_audit.write.call_args[0][0]
        assert event.account_tier == "admin", (
            f"FINDING-001 regression: expected account_tier='admin' on admin stepup event, got {event.account_tier!r}"
        )


# ---------------------------------------------------------------------------
# Structural guard — AnySession now wires /auth/stepup
# ---------------------------------------------------------------------------

class TestStructuralGuard:
    """Static analysis: stepup_verify must use AnySession, not AdminSession."""

    def test_stepup_verify_uses_any_session_not_admin_session(self):
        """
        AST check: the stepup_verify function's parameter annotations must use
        AnySession (not AdminSession) for the session dependency.

        Note: we check the function *signature* (arguments) only, not the entire
        function body.  The body legitimately imports AdminSessionTotpLockoutEvent
        (an audit event class), which contains the substring "AdminSession" but is
        NOT a session dependency — using ast.unparse(fn.args) avoids the false
        positive from that event class import.
        """
        import ast
        from pathlib import Path

        auth_path = (
            Path(__file__).resolve().parents[2]
            / "yashigani" / "backoffice" / "routes" / "auth.py"
        )
        source = auth_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        stepup_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                stepup_fn = node
                break

        assert stepup_fn is not None, "stepup_verify not found in auth.py"

        # Check only the function signature (arguments + annotations) — not the body.
        # This avoids false positives from event-class imports inside the body that
        # contain "AdminSession" as a substring (e.g. AdminSessionTotpLockoutEvent).
        sig_src = ast.unparse(stepup_fn.args)

        assert "AnySession" in sig_src, (
            f"stepup_verify signature must use AnySession — Gap B fix not applied.\n"
            f"Signature: {sig_src}"
        )
        assert "AdminSession" not in sig_src, (
            f"stepup_verify signature must NOT use AdminSession — it would reject user-tier sessions.\n"
            f"Signature: {sig_src}"
        )


# ---------------------------------------------------------------------------
# T11–T13 — Iris class-of-bug: provision/password_changed/sessions_invalidated
#            events derive account_tier from session (ASVS V7.3.4)
# ---------------------------------------------------------------------------

class TestT11ProvisionEventTier:
    """T11: _make_provision_event passes account_tier through (Iris class-of-bug)."""

    def test_user_tier_provision_event_has_user_tier(self):
        """
        _make_provision_event called with account_tier='user' must produce an event
        whose account_tier is 'user', not the old hardcoded 'admin'.
        """
        from yashigani.backoffice.routes.auth import _make_provision_event

        event = _make_provision_event("alice", account_tier="user")
        assert event.account_tier == "user", (
            f"Iris class-of-bug: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_provision_event_has_admin_tier(self):
        """Regression guard: admin-tier provision event must still carry 'admin'."""
        from yashigani.backoffice.routes.auth import _make_provision_event

        event = _make_provision_event("superadmin", account_tier="admin")
        assert event.account_tier == "admin"

    def test_provision_event_default_is_admin_for_backward_compat(self):
        """Default (no account_tier arg) must still produce 'admin' for legacy callers."""
        from yashigani.backoffice.routes.auth import _make_provision_event

        event = _make_provision_event("legacyuser")
        assert event.account_tier == "admin"


class TestT12PasswordChangedEventTier:
    """T12: _make_password_changed_event passes account_tier through (Iris class-of-bug)."""

    def test_user_tier_password_changed_event_has_user_tier(self):
        """
        _make_password_changed_event called with account_tier='user' must produce an
        event whose account_tier is 'user', not the old hardcoded 'admin'.
        """
        from yashigani.backoffice.routes.auth import _make_password_changed_event

        event = _make_password_changed_event(
            "alice",
            change_type="self_service",
            old_hash_tail="abcd1234",
            new_hash_tail="efgh5678",
            account_tier="user",
        )
        assert event.account_tier == "user", (
            f"Iris class-of-bug: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_password_changed_event_has_admin_tier(self):
        """Regression guard: admin-tier password-changed event still carries 'admin'."""
        from yashigani.backoffice.routes.auth import _make_password_changed_event

        event = _make_password_changed_event(
            "superadmin",
            change_type="forced",
            old_hash_tail="abcd1234",
            new_hash_tail="efgh5678",
            account_tier="admin",
        )
        assert event.account_tier == "admin"


class TestT13SessionsInvalidatedEventTier:
    """T13: _make_sessions_invalidated_event passes account_tier through (Iris class-of-bug)."""

    def test_user_tier_sessions_invalidated_event_has_user_tier(self):
        """
        _make_sessions_invalidated_event called with account_tier='user' must produce
        an event whose account_tier is 'user', not the old hardcoded 'admin'.
        """
        from yashigani.backoffice.routes.auth import _make_sessions_invalidated_event

        event = _make_sessions_invalidated_event(
            admin_account="alice",
            acting_admin="",
            reason="password_change",
            account_tier="user",
        )
        assert event.account_tier == "user", (
            f"Iris class-of-bug: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_sessions_invalidated_event_has_admin_tier(self):
        """Regression guard: admin-tier sessions-invalidated event still carries 'admin'."""
        from yashigani.backoffice.routes.auth import _make_sessions_invalidated_event

        event = _make_sessions_invalidated_event(
            admin_account="superadmin",
            acting_admin="",
            reason="password_change",
            account_tier="admin",
        )
        assert event.account_tier == "admin"

    def test_sessions_invalidated_default_is_admin_for_backward_compat(self):
        """Default (no account_tier arg) must still produce 'admin' for legacy callers."""
        from yashigani.backoffice.routes.auth import _make_sessions_invalidated_event

        event = _make_sessions_invalidated_event(
            admin_account="legacyuser",
            acting_admin="",
            reason="self_reset",
        )
        assert event.account_tier == "admin"


class TestT14LoginAttemptEventTier:
    """T14: _make_login_attempt_event passes account_tier through (Iris class-of-bug follow-on).

    The function fires at the top of login() BEFORE authenticate() returns a
    record, so the default="admin" is preserved for backward-compat with that
    pre-auth call site.  Any future call site that has a record in scope (e.g.
    a self-service flow that pre-fetches the account) MUST pass
    record.account_tier explicitly — this test asserts that path works.
    """

    def test_user_tier_login_attempt_event_has_user_tier(self):
        """
        When account_tier='user' is passed explicitly, the emitted event must
        carry account_tier='user' — not the old hardcoded 'admin'.
        """
        from yashigani.backoffice.routes.auth import _make_login_attempt_event

        event = _make_login_attempt_event("alice@example.com", "10.0.0.1", account_tier="user")
        assert event.account_tier == "user", (
            f"Iris class-of-bug follow-on: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_login_attempt_event_has_admin_tier(self):
        """Regression guard: admin-tier login-attempt event still carries 'admin'."""
        from yashigani.backoffice.routes.auth import _make_login_attempt_event

        event = _make_login_attempt_event("admin@example.com", "10.0.0.2", account_tier="admin")
        assert event.account_tier == "admin"

    def test_login_attempt_default_is_admin_for_pre_auth_call_site(self):
        """Default (no account_tier arg) must still produce 'admin' for the pre-auth login() call."""
        from yashigani.backoffice.routes.auth import _make_login_attempt_event

        event = _make_login_attempt_event("whoever@example.com", "192.168.1.1")
        assert event.account_tier == "admin", (
            "Pre-auth login() call site must default to 'admin' when record not yet available"
        )
