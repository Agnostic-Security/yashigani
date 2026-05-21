"""
Gap 3 / v2.23.4 arch-completion — HUMAN identity registration on local-auth login.

Locks in the behaviour added to auth.py::login (post-TOTP success path):
  - user-tier login → identity_registry.register(kind=HUMAN) called once
  - admin-tier login → identity_registry.register() NOT called
  - login response → cookie + status dict, NO plaintext_token field
  - re-login (identity exists) → register() called once total (idempotent)
  - community-tier (registry=None) → login succeeds without HUMAN registration
  - seat limit hit → login rejected with HTTP 403, no orphan session

Source-code regression target:
  src/yashigani/backoffice/routes/auth.py — _register_human_identity_on_login()
  called before session creation in the login() route handler.

ASVS v5 controls: V4.1.1 (access control enforcement), V4.2.1 (BOLA/IDOR).
Gap reference: project_yashigani_arch_completion_v2235.md § Gap 3

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, call

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------

@dataclass
class _StubRecord:
    """Mirrors the AccountRecord fields accessed by the login handler and helper."""
    username: str
    account_id: str
    account_tier: str       # "admin" | "user" | "totp_provisioning"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False
    email: Optional[str] = None
    password_hash: str = "hashed"
    totp_secret: str = "JBSWY3DPEHPK3PXP"


class _StubAuthService:
    """Sync-style stub for tests that drive _register_human_identity_on_login directly."""

    def __init__(self, record: _StubRecord):
        self._record = record

    async def authenticate(self, username, password, totp_code, *, audit_writer=None):
        return True, self._record, None

    async def get_account_by_id(self, account_id: str):
        return self._record


class _StubSessionStore:
    """Session store stub — create() returns a minimal session object."""

    def __init__(self):
        self.created = []
        self._redis = _StubRedis()

    def create(self, *, account_id, account_tier, client_ip):
        sess = MagicMock()
        sess.token = f"tok-{account_id}"
        sess.account_tier = account_tier
        self.created.append(sess)
        return sess

    def invalidate_all_for_account(self, account_id: str) -> int:
        return 0

    def get(self, token):
        return None


class _StubRedis:
    """Minimal Redis stub for throttle helpers in auth.py."""

    def __init__(self):
        self._data: dict = {}

    def exists(self, key):
        return key in self._data

    def smembers(self, key):
        return set()

    def pipeline(self):
        return _StubPipeline(self)

    def get(self, key):
        return self._data.get(key)

    def incr(self, key):
        self._data[key] = int(self._data.get(key, 0)) + 1
        return self._data[key]

    def expire(self, key, seconds):
        pass

    def set(self, key, value, ex=None):
        self._data[key] = value

    def delete(self, *keys):
        for k in keys:
            self._data.pop(k, None)

    def scan_iter(self, pattern):
        return iter([])


class _StubPipeline:
    def __init__(self, redis):
        self._redis = redis
        self._cmds = []

    def get(self, key):
        self._cmds.append(("get", key))
        return self

    def execute(self):
        return [None] * len(self._cmds)


class _StubAuditWriter:
    def write(self, event) -> None:
        pass


def _make_registry_stub():
    """
    MagicMock IdentityRegistry with no existing slugs.
    register() returns a valid (identity_id, plaintext_key) tuple.
    """
    registry = MagicMock()
    registry.get_by_slug = MagicMock(return_value=None)
    registry.register = MagicMock(return_value=("idnt_abc123", "plaintext-api-key"))
    return registry


def _make_state(registry=None):
    """Return a minimal BackofficeState-like object."""
    state = MagicMock()
    state.auth_service = None       # not needed for helper-direct tests
    state.session_store = _StubSessionStore()
    state.audit_writer = _StubAuditWriter()
    state.identity_registry = registry
    return state


# ---------------------------------------------------------------------------
# Unit tests for _register_human_identity_on_login directly
# ---------------------------------------------------------------------------

class TestRegisterHumanIdentityHelper:
    """
    Drive auth.py::_register_human_identity_on_login() directly without
    spinning up a FastAPI app.  These cover the helper's branching logic.
    """

    def _call(self, record, registry=None):
        from yashigani.backoffice.routes.auth import _register_human_identity_on_login
        state = _make_state(registry=registry)
        _register_human_identity_on_login(record, state)
        return state

    def test_user_tier_with_email_registers_human_identity(self):
        """
        Gap 3 regression: user-tier login triggers HUMAN registration.
        If _register_human_identity_on_login is removed or skipped for user-tier,
        registry.register is never called and this test fails.
        """
        from yashigani.identity.registry import IdentityKind

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        self._call(record, registry=registry)

        registry.register.assert_called_once()
        call_kwargs = registry.register.call_args
        # kind=HUMAN
        assert call_kwargs.kwargs.get("kind") == IdentityKind.HUMAN or (
            call_kwargs.args and call_kwargs.args[0] == IdentityKind.HUMAN
        ), f"Expected kind=HUMAN, got: {call_kwargs}"
        # slug derived from email
        slug_arg = call_kwargs.kwargs.get("slug", "")
        assert "alice" in slug_arg, f"Expected alice in slug, got: {slug_arg}"
        # description contains account_id
        desc = call_kwargs.kwargs.get("description", "")
        assert "user-uuid-001" in desc, f"Expected account_id in description, got: {desc}"

    def test_admin_tier_does_not_register_human_identity(self):
        """
        Gap 2 invariant: admin-tier accounts MUST NOT be registered as HUMAN
        identities.  If account_tier guard is removed, register() is called
        for admins and this test fails.
        """
        record = _StubRecord(
            username="admin@example.com",
            account_id="admin-uuid-001",
            account_tier="admin",
            email="admin@example.com",
        )
        registry = _make_registry_stub()
        self._call(record, registry=registry)

        registry.register.assert_not_called()

    def test_totp_provisioning_tier_does_not_register_human_identity(self):
        """
        totp_provisioning is a restricted pre-auth tier — MUST NOT create
        HUMAN identities.  Acceptance criterion 5 in the brief.
        """
        record = _StubRecord(
            username="newuser",
            account_id="user-uuid-002",
            account_tier="totp_provisioning",
            email="newuser@example.com",
        )
        registry = _make_registry_stub()
        self._call(record, registry=registry)

        registry.register.assert_not_called()

    def test_community_tier_registry_none_skips_silently(self):
        """
        When identity_registry is None (community-tier / pre-init), the helper
        must return without raising.  Brief acceptance criterion 7.
        Login continues normally.
        """
        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        # registry=None — community tier path
        state = self._call(record, registry=None)
        # No exception raised: test passes if we get here

    def test_idempotent_existing_identity_not_re_registered(self):
        """
        If get_by_slug() returns an existing identity, register() MUST NOT be
        called again.  Brief acceptance criterion 2 (idempotent).
        If idempotency guard is removed, register() is called twice on re-login
        which would raise ValueError("Slug already taken").
        """
        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        # Simulate existing identity
        registry.get_by_slug = MagicMock(return_value={
            "identity_id": "idnt_existing",
            "kind": "human",
            "slug": "alice-example-com",
        })
        self._call(record, registry=registry)

        registry.register.assert_not_called()

    def test_no_email_falls_back_to_synthetic_slug(self):
        """
        Legacy user with no email field gets synthetic email {username}@yashigani.local
        and a corresponding slug.  Brief: email=None legacy case handled via fallback.
        """
        record = _StubRecord(
            username="legacyuser",
            account_id="user-uuid-legacy",
            account_tier="user",
            email=None,         # no email set — legacy account
        )
        registry = _make_registry_stub()
        self._call(record, registry=registry)

        registry.register.assert_called_once()
        call_kwargs = registry.register.call_args
        slug_arg = call_kwargs.kwargs.get("slug", "")
        assert "legacyuser" in slug_arg, (
            f"Expected legacyuser in synthetic slug, got: {slug_arg}"
        )
        assert "yashigani" in slug_arg, (
            f"Expected yashigani.local domain in synthetic slug, got: {slug_arg}"
        )

    def test_seat_limit_raises_http_403(self):
        """
        When register() raises LicenseLimitExceeded, the helper MUST raise
        HTTPException(403).  Brief: seat limit → 4xx, no orphan session.
        If the exception is swallowed, login would succeed without a HUMAN
        identity and this test fails.
        """
        from fastapi import HTTPException
        from yashigani.licensing.enforcer import LicenseLimitExceeded

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        registry.register.side_effect = LicenseLimitExceeded(
            limit_name="max_end_users",
            current=10,
            max_val=10,
        )

        with pytest.raises(HTTPException) as exc_info:
            self._call(record, registry=registry)

        assert exc_info.value.status_code == 403
        detail = exc_info.value.detail
        assert detail["error"] == "seat_limit_exceeded"
        assert detail["current"] == 10
        assert detail["max"] == 10


# ---------------------------------------------------------------------------
# Integration-style tests via FastAPI TestClient (login route)
# ---------------------------------------------------------------------------

class _StubRedisForLogin(_StubRedis):
    """Extended stub that also supports throttle pipeline pattern auth.py uses."""

    def pipeline(self):
        return _FullStubPipeline()


class _FullStubPipeline:
    def __init__(self):
        self._ops = []

    def get(self, key):
        self._ops.append(key)
        return self

    def execute(self):
        # Return [None, None, None, None] — no throttle active
        return [None, None, None, None]


def _build_login_app(record: _StubRecord, registry=None):
    """
    Minimal FastAPI app with the /auth/login route.
    auth_service.authenticate() always returns success for the given record.
    session_store.create() is a real stub that returns a token.
    """
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.routes import auth as auth_mod

    # Stash originals
    orig_auth = state_mod.backoffice_state.auth_service
    orig_session = state_mod.backoffice_state.session_store
    orig_audit = state_mod.backoffice_state.audit_writer
    orig_registry = state_mod.backoffice_state.identity_registry

    # Install stubs
    auth_svc = _StubAuthService(record)
    session_store = _StubSessionStore()
    state_mod.backoffice_state.auth_service = auth_svc
    state_mod.backoffice_state.session_store = session_store
    state_mod.backoffice_state.audit_writer = _StubAuditWriter()
    state_mod.backoffice_state.identity_registry = registry

    app = FastAPI()
    app.include_router(auth_mod.router, prefix="/auth")

    return app, session_store, (orig_auth, orig_session, orig_audit, orig_registry)


class TestLoginRouteHumanIdentity:
    """
    End-to-end tests through the FastAPI login route.  The stub auth_service
    always succeeds; we verify the side-effects on identity_registry.
    """

    _LOGIN_PAYLOAD = {
        "username": "alice",
        "password": "correctpassword",
        "totp_code": "123456",
    }

    def test_login_creates_human_identity_for_user_tier(self):
        """
        POST /auth/login for a user-tier account → identity_registry.register()
        called with kind=HUMAN.

        Regression: if _register_human_identity_on_login is removed from the
        login handler, register() is never called and this test fails.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod
        from yashigani.identity.registry import IdentityKind

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, session_store, originals = _build_login_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"

            # HUMAN identity registered
            registry.register.assert_called_once()
            call_kwargs = registry.register.call_args
            assert call_kwargs.kwargs.get("kind") == IdentityKind.HUMAN
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_login_does_not_create_human_identity_for_admin(self):
        """
        POST /auth/login for admin-tier → register() MUST NOT be called.

        Regression: if the account_tier guard is removed or inverted,
        admin accounts gain HUMAN identities and the separation invariant
        (Gap 2) is broken.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        record = _StubRecord(
            username="admin@example.com",
            account_id="admin-uuid-001",
            account_tier="admin",
            email="admin@example.com",
        )
        registry = _make_registry_stub()
        app, session_store, originals = _build_login_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"

            registry.register.assert_not_called()
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_login_returns_cookie_not_bearer(self):
        """
        POST /auth/login response body MUST NOT contain plaintext_token.
        The Bearer is Gap 4 (/me/api-key) — not returned at login time.

        Regression: if plaintext_token is accidentally added to the login
        response, this test fails and flags the security regression.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, session_store, originals = _build_login_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"

            body = resp.json()
            # Must have cookie-session shape
            assert body.get("status") == "ok", f"Expected status=ok, got: {body}"
            # MUST NOT expose Bearer
            assert "plaintext_token" not in body, (
                "REGRESSION: login response contains plaintext_token — "
                "Bearer must not be returned at login (Gap 4 scope). "
                f"Body: {body}"
            )
            assert "api_key" not in body, (
                f"REGRESSION: login response contains api_key. Body: {body}"
            )
            assert "bearer" not in str(body).lower() or "bearer" not in body, (
                f"REGRESSION: login response leaks bearer token. Body: {body}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_login_idempotent_for_existing_identity(self):
        """
        User logs in twice → register() called exactly ONCE across both logins.
        On second login, get_by_slug() returns the existing identity → skip.

        Regression: if idempotency guard is removed, register() is called on
        every login and would raise ValueError("Slug already taken") on the real
        registry — this test catches the regression before that runtime error.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()

        # After first call, simulate the slug now existing
        existing_identity = {"identity_id": "idnt_existing", "kind": "human"}
        call_count = {"n": 0}
        real_get_by_slug = registry.get_by_slug

        def _get_by_slug_stateful(slug):
            call_count["n"] += 1
            if call_count["n"] > 1:
                return existing_identity
            return None

        registry.get_by_slug = MagicMock(side_effect=_get_by_slug_stateful)

        app, session_store, originals = _build_login_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            # First login
            resp1 = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp1.status_code == 200
            # Second login
            resp2 = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp2.status_code == 200

            # register() called exactly once (first login only)
            assert registry.register.call_count == 1, (
                f"REGRESSION: register() called {registry.register.call_count} times — "
                "expected 1 (idempotent: second login should skip re-registration)"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_login_skips_human_registration_when_registry_unavailable(self):
        """
        Community-tier: identity_registry is None → login returns 200 without
        calling register().

        Regression: if None-check is removed, AttributeError is raised and
        login fails for community-tier deployments.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        # registry=None → community-tier path
        app, session_store, originals = _build_login_app(record, registry=None)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp.status_code == 200, (
                f"REGRESSION: community-tier login failed with registry=None: "
                f"{resp.status_code} {resp.text}"
            )
            body = resp.json()
            assert body.get("status") == "ok"
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_login_rejects_at_seat_limit(self):
        """
        When the seat limit is exhausted, login MUST return 403.
        No session cookie must be set (session not created before registration
        because _register_human_identity_on_login is called first).

        Regression: if seat-limit exception is swallowed, login succeeds
        silently without a HUMAN identity — this test fails and catches it.
        """
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod
        from yashigani.licensing.enforcer import LicenseLimitExceeded

        record = _StubRecord(
            username="alice",
            account_id="user-uuid-001",
            account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        registry.register.side_effect = LicenseLimitExceeded(
            limit_name="max_end_users",
            current=5,
            max_val=5,
        )

        app, session_store, originals = _build_login_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/auth/login", json=self._LOGIN_PAYLOAD)
            assert resp.status_code == 403, (
                f"REGRESSION: seat-limit login should return 403, got "
                f"{resp.status_code} {resp.text}"
            )
            body = resp.json()
            detail = body.get("detail", {})
            assert detail.get("error") == "seat_limit_exceeded", (
                f"Expected error=seat_limit_exceeded, got: {detail}"
            )
            # No session created — session_store.created should be empty
            assert len(session_store.created) == 0, (
                "REGRESSION: session was created despite seat-limit rejection — "
                f"orphan session count: {len(session_store.created)}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]
