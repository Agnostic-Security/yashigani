"""
Regression test — YSG-RISK-139 (MED, CWE-640): admin full-reset returns the
new temporary password.

Bug: POST /admin/users/{username}/full-reset stripped a user's password,
TOTP, and sessions, and generated a brand-new temporary password internally
-- but never returned it in the HTTP response. The admin therefore had no
usable credential to hand to the reset user, and the user was permanently
locked out (CWE-640: Weak Password Recovery Mechanism for Forgotten
Password -- more precisely here, a recovery mechanism that destroys access
without delivering the replacement credential).

Fix (mirrors the existing create-user / admin-self-reset one-time-delivery
convention -- see POST /admin/users (UserCreateResponse.temporary_password)
and POST /auth/self-reset (auth.py:1400-1405)):

  - src/yashigani/auth/local_auth.py:421   LocalAuthService.full_reset_user
  - src/yashigani/auth/pg_auth.py:483      PgAuthService.full_reset_user
    Both now return (success: bool, reason: str, temporary_password:
    Optional[str]) instead of (bool, str). temporary_password is the SAME
    plaintext used to set record.password_hash -- never re-derived,
    never re-generated -- so what the admin receives is guaranteed to
    match what will authenticate.

  - src/yashigani/backoffice/routes/users.py:494 full_reset_user() route
    Unpacks the 3-tuple and returns temporary_password + explicit
    force_password_change=true in the JSON response body. Plaintext
    appears ONLY in that HTTP response -- the audit event
    (_full_reset_event / UserFullResetEvent) carries no credential field
    at all (same as the pre-existing create-user/self-reset audit events),
    so there is nothing to fingerprint on that path; this suite asserts
    that invariant holds (T3 below) so a future change can't silently
    reintroduce a plaintext-in-audit regression.

Live login-after-reset (temp password actually authenticates through the
full HTTP auth stack) is NOT exercised here -- that requires a running
Postgres-backed stack per T1 (migration/runtime discipline) and is out of
scope for a unit suite against the in-memory LocalAuthService. What IS
proven here (T2) is the tighter, decisive claim: the exact plaintext
returned is verified with the SAME verify_password() the login path uses,
against the SAME password_hash full_reset_user() persisted on the record.
That is the whole of what "the returned temp pw actually works" reduces to
once you factor out network/HTTP plumbing.
"""
from __future__ import annotations

import time

import pytest


# ---------------------------------------------------------------------------
# T1 -- LocalAuthService.full_reset_user returns a working temp password
# ---------------------------------------------------------------------------

class TestT1LocalAuthFullResetReturnsTempPassword:
    def _make_service_with_accounts(self):
        from yashigani.auth.local_auth import LocalAuthService
        from yashigani.auth.password import generate_password
        from yashigani.auth.totp import (
            TOTP_ALGO_SHA512,
            TOTP_DIGITS_ADMIN,
            generate_provisioning,
        )

        svc = LocalAuthService()

        # Admin account, fully enrolled with a SHA-512/8-digit TOTP secret
        # (admin tier per Phase 13 role-tiered TOTP).
        admin_record, _ = svc.create_admin("admin@example.com", auto_generate=True)
        admin_totp = generate_provisioning(
            account_name="admin@example.com",
            algorithm=TOTP_ALGO_SHA512,
            digits=TOTP_DIGITS_ADMIN,
        )
        admin_record.totp_secret = admin_totp.secret_b32
        admin_record.totp_algorithm = TOTP_ALGO_SHA512
        admin_record.force_totp_provision = False

        # Target user account to be reset. Use generate_password() so we
        # satisfy both the min-length (36 chars) AND context/breach
        # validation — this is a throwaway pre-reset credential, its value
        # is otherwise irrelevant.
        svc.create_user("alice", generate_password(36))

        return svc, admin_record

    def _valid_admin_totp_code(self, admin_record) -> str:
        from yashigani.auth.totp import _totp_at

        return _totp_at(
            admin_record.totp_secret,
            int(time.time()),
            admin_record.totp_algorithm,
            8,
        )

    def test_success_returns_nonempty_temp_password_and_force_change(self):
        svc, admin_record = self._make_service_with_accounts()
        code = self._valid_admin_totp_code(admin_record)

        success, reason, temp_password = svc.full_reset_user(
            "alice",
            admin_totp_secret=admin_record.totp_secret,
            admin_totp_code=code,
            admin_totp_algorithm=admin_record.totp_algorithm,
            admin_totp_digits=8,
        )

        assert success is True
        assert reason == "ok"
        assert temp_password, "YSG-RISK-139: full-reset must return a non-empty temporary_password"
        assert isinstance(temp_password, str)
        assert len(temp_password) >= 20  # generate_password(36) — sanity floor

        record = svc._accounts["alice"]
        assert record.force_password_change is True

    def test_returned_credential_matches_what_was_set(self):
        """The returned plaintext must be THE credential that now authenticates
        -- not a decorative/independent value. This is the load-bearing
        assertion for the bug: it proves the reset user can actually log in
        with what the admin was handed."""
        from yashigani.auth.password import verify_password

        svc, admin_record = self._make_service_with_accounts()
        code = self._valid_admin_totp_code(admin_record)

        success, reason, temp_password = svc.full_reset_user(
            "alice",
            admin_totp_secret=admin_record.totp_secret,
            admin_totp_code=code,
            admin_totp_algorithm=admin_record.totp_algorithm,
            admin_totp_digits=8,
        )
        assert success is True

        record = svc._accounts["alice"]
        assert verify_password(temp_password, record.password_hash) is True, (
            "returned temporary_password does not verify against the hash "
            "full_reset_user() persisted -- reset user would still be locked out"
        )

    def test_invalid_admin_totp_returns_none_temp_password(self):
        svc, admin_record = self._make_service_with_accounts()

        success, reason, temp_password = svc.full_reset_user(
            "alice",
            admin_totp_secret=admin_record.totp_secret,
            admin_totp_code="000000",
            admin_totp_algorithm=admin_record.totp_algorithm,
            admin_totp_digits=8,
        )

        assert success is False
        assert reason == "invalid_admin_totp"
        assert temp_password is None

    def test_unknown_user_returns_none_temp_password(self):
        svc, admin_record = self._make_service_with_accounts()
        code = self._valid_admin_totp_code(admin_record)

        success, reason, temp_password = svc.full_reset_user(
            "no-such-user",
            admin_totp_secret=admin_record.totp_secret,
            admin_totp_code=code,
            admin_totp_algorithm=admin_record.totp_algorithm,
            admin_totp_digits=8,
        )

        assert success is False
        assert reason == "user_not_found"
        assert temp_password is None


# ---------------------------------------------------------------------------
# T2 -- Route layer surfaces temporary_password in the HTTP response
# ---------------------------------------------------------------------------

class _StubSessionStore:
    def invalidate_all_for_account(self, account_id: str) -> int:
        return 0


class _StubAuditWriter:
    def __init__(self):
        self.events = []

    def write(self, event) -> None:
        self.events.append(event)


class _StubUserRecord:
    def __init__(self, username, account_id, account_tier="user"):
        self.username = username
        self.account_id = account_id
        self.account_tier = account_tier
        self.totp_secret = "STUBSECRET"
        self.totp_algorithm = "SHA512"


class _StubAuthServiceForRoute:
    """Async stub — mirrors only what full_reset_user() the route needs."""

    TEMP_PASSWORD = "unit-test-temp-password-abc123XYZ!!"  # noqa: S105 — test fixture literal

    def __init__(self):
        self._admin = _StubUserRecord("admin@example.com", "admin-id-001", "admin")
        self._user = _StubUserRecord("alice", "user-id-001", "user")

    async def get_account_by_id(self, account_id):
        return self._admin

    async def get_account(self, username):
        if username == self._user.username:
            return self._user
        return None

    async def full_reset_user(self, username, admin_totp_secret, admin_totp_code,
                               admin_totp_algorithm, admin_totp_digits):
        if username != self._user.username:
            return False, "user_not_found", None
        return True, "ok", self.TEMP_PASSWORD


def _build_users_app(auth_svc):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI

    from yashigani.auth.session import Session
    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.routes import users as users_mod

    originals = (
        state_mod.backoffice_state.auth_service,
        state_mod.backoffice_state.session_store,
        state_mod.backoffice_state.audit_writer,
    )

    audit_writer = _StubAuditWriter()
    state_mod.backoffice_state.auth_service = auth_svc
    state_mod.backoffice_state.session_store = _StubSessionStore()  # type: ignore[assignment]
    state_mod.backoffice_state.audit_writer = audit_writer  # type: ignore[assignment]

    app = FastAPI()
    app.include_router(users_mod.router, prefix="/users")

    def _make_session() -> Session:
        s = Session.__new__(Session)
        s.account_id = "admin-id-001"
        s.account_tier = "admin"
        s.token = "fake-token"
        s.created_at = 0.0
        s.last_active_at = 0.0
        s.expires_at = time.time() + 3600
        s.ip_prefix = "127.0.0"
        s.last_totp_verified_at = time.time()  # fresh step-up
        return s

    async def _fake_admin_session() -> Session:
        return _make_session()

    async def _fake_stepup_session() -> Session:
        return _make_session()

    app.dependency_overrides[require_admin_session] = _fake_admin_session
    app.dependency_overrides[require_stepup_admin_session] = _fake_stepup_session

    return app, originals, audit_writer


class TestT2RouteSurfacesTempPasswordInResponse:
    def test_full_reset_response_includes_temp_password_and_force_change(self):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        auth_svc = _StubAuthServiceForRoute()
        app, originals, audit_writer = _build_users_app(auth_svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/users/alice/full-reset", json={"totp_code": "12345678"})
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body.get("status") == "ok"
            assert body.get("temporary_password") == auth_svc.TEMP_PASSWORD, (
                "YSG-RISK-139: full-reset response must surface the new temporary_password"
            )
            assert body.get("force_password_change") is True
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]

    def test_audit_event_never_carries_the_plaintext_temp_password(self):
        """Defence-in-depth regression: the temp password must appear ONLY in
        the HTTP response body, never in any audit/log record. Walks every
        field on the written audit event and asserts none of them equal
        (or contain) the plaintext temp password."""
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        auth_svc = _StubAuthServiceForRoute()
        app, originals, audit_writer = _build_users_app(auth_svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/users/alice/full-reset", json={"totp_code": "12345678"})
            assert resp.status_code == 200, resp.text

            assert len(audit_writer.events) == 1
            event = audit_writer.events[0]
            for field_name, value in vars(event).items():
                if isinstance(value, str):
                    assert auth_svc.TEMP_PASSWORD not in value, (
                        f"plaintext temp password leaked into audit field {field_name!r}"
                    )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
