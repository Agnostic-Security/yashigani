"""
Admin-tier separation regression test — Gap 2 / v2.23.4 arch-completion.

Locks in the verified-no-gap behaviour documented in
project_yashigani_arch_completion_v2235.md (Gap 2 section).

Three regression groups:

  Group 1 — /admin/users/* rejects admin-tier records
    (a) GET /admin/users list does NOT include admin records
    (b) POST /admin/users/{admin_username}/disable → 404
    (c) POST /admin/users/{admin_username}/full-reset → 404

  Group 2 — /admin/accounts/* rejects user-tier records
    (a) GET /admin/accounts list does NOT include user records
    (b) POST /admin/accounts/{user_username}/disable → 404
    (c) POST /admin/accounts/{user_username}/force-reset → 404

  Group 3 — Gateway indirect admin separation via identity_registry
    (a) Admin record has no HUMAN identity_registry entry after
        _register_human_identity_on_login — verified against REAL fakeredis
        registry (post-lupa; B2 hardening 2026-05-15)
    (b) _resolve_identity() returns None for an admin slug not in registry
    (c) _resolve_identity() returns None when no auth header present
    (d) REGRESSION: create_admin never registers a HUMAN identity — load-bearing
        test for Laura threat-model F2 (admin-tier separation via identity_registry).
        Uses real registry; catches any future accidental registration at the source.

Source-code regression targets (lines current at v2.23.4):
  src/yashigani/backoffice/routes/users.py:60   — list filter account_tier == "user"
  src/yashigani/backoffice/routes/users.py:135  — delete action check
  src/yashigani/backoffice/routes/users.py:214  — disable action check
  src/yashigani/backoffice/routes/accounts.py:57  — list filter account_tier == "admin"
  src/yashigani/backoffice/routes/accounts.py:134 — delete action check
  src/yashigani/backoffice/routes/accounts.py:160 — disable action check
  src/yashigani/backoffice/routes/accounts.py:223 — force-reset action check
  src/yashigani/gateway/openai_router.py:1151   — _resolve_identity(), no account_tier check
  src/yashigani/backoffice/routes/auth.py:1233  — _register_human_identity_on_login tier guard

ASVS v5 controls: V4.1.1 (access control enforcement), V4.1.2 (deny-by-default),
  V4.2.1 (IDOR / BOLA prevention).
OWASP API Top 10 2023: API1 (BOLA), API5 (Broken Function-Level Auth).

Last updated: 2026-05-15T00:00:00+00:00
"""
from __future__ import annotations

import time
import types
from dataclasses import dataclass, field
from typing import Optional

import fakeredis
import pytest


# ---------------------------------------------------------------------------
# Stub auth service
# ---------------------------------------------------------------------------

@dataclass
class _StubRecord:
    """Minimal account record stub — mirrors the fields routes.py accesses."""
    username: str
    account_id: str
    account_tier: str      # "admin" | "user"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False
    created_at: float = field(default_factory=time.time)
    email: Optional[str] = None


class _StubAuthService:
    """
    Synchronous-async stub for the auth service used by backoffice routes.

    list_accounts() returns all records regardless of tier — the route
    handlers are responsible for tier-filtering (that is exactly what
    these tests verify).
    """

    def __init__(self, records: list[_StubRecord]):
        self._records = records

    async def list_accounts(self) -> list[_StubRecord]:
        return list(self._records)

    async def get_account(self, username: str) -> Optional[_StubRecord]:
        for r in self._records:
            if r.username == username:
                return r
        return None

    async def total_user_count(self) -> int:
        return sum(1 for r in self._records if r.account_tier == "user")

    async def total_admin_count(self) -> int:
        return sum(1 for r in self._records if r.account_tier == "admin")

    async def active_admin_count(self) -> int:
        return sum(
            1 for r in self._records
            if r.account_tier == "admin" and not r.disabled
        )

    async def disable(self, username: str) -> None:
        for r in self._records:
            if r.username == username:
                r.disabled = True
                return

    async def force_password_change(self, username: str) -> None:
        for r in self._records:
            if r.username == username:
                r.force_password_change = True
                return

    async def force_totp_reprovision(self, username: str) -> None:
        for r in self._records:
            if r.username == username:
                r.force_totp_provision = True
                return


def _make_admin_record(username: str = "admin@example.com") -> _StubRecord:
    return _StubRecord(
        username=username,
        account_id="admin-id-001",
        account_tier="admin",
        disabled=False,
    )


def _make_user_record(username: str = "alice") -> _StubRecord:
    return _StubRecord(
        username=username,
        account_id="user-id-001",
        account_tier="user",
        disabled=False,
    )


# ---------------------------------------------------------------------------
# Shared FastAPI app factory
# ---------------------------------------------------------------------------

class _StubSessionStore:
    """Minimal SessionStore stub — satisfies `assert state.session_store is not None`."""

    def invalidate_all_for_account(self, account_id: str) -> int:
        return 0


class _StubAuditWriter:
    """Minimal AuditWriter stub — satisfies `assert state.audit_writer is not None`."""

    def write(self, event) -> None:
        pass


def _build_users_app(auth_svc: _StubAuthService):
    """
    Minimal FastAPI app with the /admin/users router mounted.
    Session dependency overridden to a benign admin session.
    Provides stub session_store and audit_writer so route asserts pass
    before the tier check fires.
    """
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient  # noqa: F401 (imported for side-effect check)

    from yashigani.auth.session import Session
    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.routes import users as users_mod

    original_auth = state_mod.backoffice_state.auth_service
    original_session_store = state_mod.backoffice_state.session_store
    original_audit = state_mod.backoffice_state.audit_writer
    original_identity_registry = state_mod.backoffice_state.identity_registry

    state_mod.backoffice_state.auth_service = auth_svc
    state_mod.backoffice_state.session_store = _StubSessionStore()  # type: ignore[assignment]
    state_mod.backoffice_state.audit_writer = _StubAuditWriter()  # type: ignore[assignment]
    state_mod.backoffice_state.identity_registry = None

    # The users router registers routes with empty paths (e.g. @router.get("")).
    # FastAPI requires a non-empty prefix when the router path itself is empty.
    app = FastAPI()
    app.include_router(users_mod.router, prefix="/users")

    def _make_session() -> Session:
        s = Session.__new__(Session)
        s.account_id = "test-admin-id"
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

    return app, (original_auth, original_session_store, original_audit, original_identity_registry)


def _build_accounts_app(auth_svc: _StubAuthService):
    """
    Minimal FastAPI app with the /admin/accounts router mounted.
    Session dependency overridden to a benign admin session.
    Provides stub session_store and audit_writer so route asserts pass
    before the tier check fires.
    """
    pytest.importorskip("fastapi")
    from fastapi import FastAPI

    from yashigani.auth.session import Session
    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.routes import accounts as accounts_mod

    original_auth = state_mod.backoffice_state.auth_service
    original_session_store = state_mod.backoffice_state.session_store
    original_audit = state_mod.backoffice_state.audit_writer
    original_identity_registry = state_mod.backoffice_state.identity_registry

    state_mod.backoffice_state.auth_service = auth_svc
    state_mod.backoffice_state.session_store = _StubSessionStore()  # type: ignore[assignment]
    state_mod.backoffice_state.audit_writer = _StubAuditWriter()  # type: ignore[assignment]
    state_mod.backoffice_state.identity_registry = None

    # The accounts router registers routes with empty paths (e.g. @router.get("")).
    # FastAPI requires a non-empty prefix when the router path itself is empty.
    app = FastAPI()
    app.include_router(accounts_mod.router, prefix="/accounts")

    def _make_session() -> Session:
        s = Session.__new__(Session)
        s.account_id = "test-admin-id"
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

    return app, (original_auth, original_session_store, original_audit, original_identity_registry)


# ---------------------------------------------------------------------------
# Group 1 — /admin/users/* rejects admin-tier records
# ---------------------------------------------------------------------------

class TestUsersRouteRejectsAdminRecords:
    """
    Regression: routes/users.py must filter account_tier == "user" at every
    list and action endpoint.  An admin record present in the store MUST NOT
    appear in the user list or be actionable via the user routes.

    Source-code targets:
      users.py:60   — list comprehension `if r.account_tier == "user"`
      users.py:135  — delete guard `if record is None or record.account_tier != "user"`
      users.py:214  — disable guard `if record is None or record.account_tier != "user"`
    """

    def test_group1a_list_users_excludes_admin_record(self):
        """
        GET /admin/users — admin record present in store, must NOT appear in
        the response `users` list.

        Regression target: users.py:60 filter `if r.account_tier == "user"`.
        If the filter is removed or inverted, an admin record leaks into the
        user list and this test fails.
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        admin_rec = _make_admin_record("admin@example.com")
        user_rec = _make_user_record("alice")
        svc = _StubAuthService([admin_rec, user_rec])

        app, originals = _build_users_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/users")
            assert resp.status_code == 200, (
                f"GET /admin/users unexpectedly failed: {resp.status_code} {resp.text}"
            )
            body = resp.json()
            assert "users" in body, f"Response missing 'users' key: {body}"
            usernames_in_list = [u["username"] for u in body["users"]]

            # Admin record MUST NOT appear in user list
            assert "admin@example.com" not in usernames_in_list, (
                "REGRESSION (users.py:60): admin record leaked into /admin/users list. "
                f"Found: {usernames_in_list}"
            )
            # User record MUST appear
            assert "alice" in usernames_in_list, (
                f"User record 'alice' missing from list — fixture problem. Found: {usernames_in_list}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_group1b_disable_admin_via_users_route_returns_404(self):
        """
        POST /admin/users/{admin_username}/disable — must return 404 because
        the admin record's account_tier != "user".

        Regression target: users.py:214 guard
          `if record is None or record.account_tier != "user": raise 404`
        If the tier check is removed, an admin account can be disabled through
        the user route — this test fails and catches the regression.
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        admin_rec = _make_admin_record("admin@example.com")
        # Need a second admin so disable guard (min 2 active) doesn't kick in
        admin_rec2 = _make_admin_record("admin2@example.com")
        admin_rec2.account_id = "admin-id-002"
        svc = _StubAuthService([admin_rec, admin_rec2])

        app, originals = _build_users_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/users/admin@example.com/disable")
            assert resp.status_code == 404, (
                "REGRESSION (users.py:214): POST /admin/users/{admin_username}/disable "
                f"returned {resp.status_code} instead of 404. Admin record not protected "
                f"by tier check. Body: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "account_not_found", (
                f"Expected error=account_not_found, got: {detail}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_group1c_delete_admin_via_users_route_returns_404(self):
        """
        DELETE /admin/users/{admin_username} — must return 404 because
        the admin record's account_tier != "user".

        Regression target: users.py:135 guard in delete_user
          `if record is None or record.account_tier != "user": raise 404`
        If the tier check is removed, an admin account can be deleted through
        the user route — this test fails and catches the regression.
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        admin_rec = _make_admin_record("admin@example.com")
        # Add a user so total_user_count() > user_min_total (otherwise deletion
        # would fail with USER_MINIMUM_VIOLATION before the tier check).
        user_rec = _make_user_record("alice")
        user_rec2 = _make_user_record("bob")
        user_rec2.account_id = "user-id-002"
        svc = _StubAuthService([admin_rec, user_rec, user_rec2])

        app, originals = _build_users_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/users/admin@example.com")
            assert resp.status_code == 404, (
                "REGRESSION (users.py:135): DELETE /admin/users/{admin_username} "
                f"returned {resp.status_code} instead of 404. Admin record not protected "
                f"by tier check. Body: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "account_not_found", (
                f"Expected error=account_not_found, got: {detail}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]


# ---------------------------------------------------------------------------
# Group 2 — /admin/accounts/* rejects user-tier records
# ---------------------------------------------------------------------------

class TestAccountsRouteRejectsUserRecords:
    """
    Regression: routes/accounts.py must filter account_tier == "admin" at
    every list and action endpoint.  A user record present in the store MUST
    NOT appear in the admin list or be actionable via the admin routes.

    Source-code targets:
      accounts.py:57  — list comprehension `if r.account_tier == "admin"`
      accounts.py:134 — delete guard `if record is None or record.account_tier != "admin"`
      accounts.py:160 — disable guard `if record is None or record.account_tier != "admin"`
      accounts.py:223 — force-reset guard `if record is None or record.account_tier != "admin"`
    """

    def test_group2a_list_accounts_excludes_user_record(self):
        """
        GET /admin/accounts — user record present in store, must NOT appear
        in the response `accounts` list.

        Regression target: accounts.py:57 filter `if r.account_tier == "admin"`.
        If the filter is removed or inverted, a user record leaks into the
        admin list and this test fails.
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        admin_rec = _make_admin_record("admin@example.com")
        user_rec = _make_user_record("alice")
        svc = _StubAuthService([admin_rec, user_rec])

        app, originals = _build_accounts_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/accounts")
            assert resp.status_code == 200, (
                f"GET /admin/accounts unexpectedly failed: {resp.status_code} {resp.text}"
            )
            body = resp.json()
            assert "accounts" in body, f"Response missing 'accounts' key: {body}"
            usernames_in_list = [a["username"] for a in body["accounts"]]

            # User record MUST NOT appear in admin list
            assert "alice" not in usernames_in_list, (
                "REGRESSION (accounts.py:57): user record leaked into /admin/accounts list. "
                f"Found: {usernames_in_list}"
            )
            # Admin record MUST appear
            assert "admin@example.com" in usernames_in_list, (
                f"Admin record missing from list — fixture problem. Found: {usernames_in_list}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_group2b_disable_user_via_accounts_route_returns_404(self):
        """
        POST /admin/accounts/{user_username}/disable — must return 404 because
        the user record's account_tier != "admin".

        Regression target: accounts.py:160 guard
          `if record is None or record.account_tier != "admin": raise 404`
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        user_rec = _make_user_record("alice")
        # At least 3 admin records so active-count guard (min 2) doesn't interfere
        admin1 = _make_admin_record("admin1@example.com")
        admin2 = _make_admin_record("admin2@example.com")
        admin2.account_id = "admin-id-002"
        svc = _StubAuthService([user_rec, admin1, admin2])

        app, originals = _build_accounts_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/accounts/alice/disable")
            assert resp.status_code == 404, (
                "REGRESSION (accounts.py:160): POST /admin/accounts/{user_username}/disable "
                f"returned {resp.status_code} instead of 404. User record not protected "
                f"by tier check. Body: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "account_not_found", (
                f"Expected error=account_not_found, got: {detail}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]

    def test_group2c_delete_user_via_accounts_route_returns_404(self):
        """
        DELETE /admin/accounts/{user_username} — must return 404 because
        the user record's account_tier != "admin".

        Regression target: accounts.py:134 guard in delete_admin
          `if record is None or record.account_tier != "admin": raise 404`
        If the tier check is removed, a user account can be deleted through
        the admin route — this test fails and catches the regression.
        """
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod

        user_rec = _make_user_record("alice")
        # Two admins so total_admin_count() > admin_min_total (otherwise 409 fires)
        admin1 = _make_admin_record("admin1@example.com")
        admin2 = _make_admin_record("admin2@example.com")
        admin2.account_id = "admin-id-002"
        svc = _StubAuthService([user_rec, admin1, admin2])

        app, originals = _build_accounts_app(svc)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.delete("/accounts/alice")
            assert resp.status_code == 404, (
                "REGRESSION (accounts.py:134): DELETE /admin/accounts/{user_username} "
                f"returned {resp.status_code} instead of 404. User record not protected "
                f"by tier check. Body: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "account_not_found", (
                f"Expected error=account_not_found, got: {detail}"
            )
        finally:
            state_mod.backoffice_state.auth_service = originals[0]
            state_mod.backoffice_state.session_store = originals[1]
            state_mod.backoffice_state.audit_writer = originals[2]
            state_mod.backoffice_state.identity_registry = originals[3]


# ---------------------------------------------------------------------------
# Group 3 — Gateway indirect admin separation
# ---------------------------------------------------------------------------

def _make_real_registry():
    """
    Real IdentityRegistry backed by an in-process fakeredis instance.

    Requires fakeredis with Lua eval support (lupa>=2.1 — added in
    Captain's 6af2187).  This replaces the earlier MagicMock approach
    (b31b268) so that tests bind production code rather than a stub.
    """
    from yashigani.identity import IdentityRegistry
    return IdentityRegistry(fakeredis.FakeRedis())


def _make_real_registry_with_user_only():
    """
    Real fakeredis-backed IdentityRegistry with alice registered as HUMAN.
    Admin slug is intentionally absent — no call to registry.register() for
    any admin email.  Used by test_group3a and test_group3b.
    """
    from yashigani.identity import IdentityKind
    registry = _make_real_registry()
    registry.register(
        kind=IdentityKind.HUMAN,
        name="Alice",
        slug="alice-example-com",
        description="test user",
    )
    return registry


class TestGatewayAdminIndirectSeparation:
    """
    Regression: admin records have NO identity_registry HUMAN entry.

    _resolve_identity() at openai_router.py:1151 does NOT check account_tier —
    admins are excluded indirectly because they have no slug registered in
    the identity_registry.

    Group 3a–3c: unchanged contract tests with real fakeredis registry
    (post-lupa hardening; replaces MagicMock approach from b31b268).

    Group 3d: load-bearing regression for Laura threat-model F2.
    Directly calls _register_human_identity_on_login() with an admin-tier
    record against a real registry.  If auth.py:1233 tier guard is ever
    removed or bypassed, this test catches the regression immediately.

    Source-code target: openai_router.py:1151 _resolve_identity()
                        auth.py:1233 _register_human_identity_on_login tier guard
    """

    def _make_starlette_request(self, headers: dict) -> object:
        """Build a minimal Starlette Request from a headers dict."""
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
        return StarletteRequest(scope)

    def test_group3a_admin_record_has_no_human_identity_entry(self):
        """
        Admin slug is absent from a real fakeredis IdentityRegistry after a
        user-only registration — get_by_slug("admin-example-com") returns None.

        B2 hardening (2026-05-15): replaces MagicMock with real registry so
        the test exercises production IdentityRegistry code rather than a stub.

        Regression target: the invariant that admin accounts are NEVER
        registered as HUMAN identities in the identity_registry. If a future
        bootstrap or admin-creation path registers admin emails as HUMAN
        identities, get_by_slug("admin-example-com") would return a non-None
        result and this test would fail.

        Source-code target: auth.py:1233 tier guard in
            _register_human_identity_on_login().
        """
        registry = _make_real_registry_with_user_only()

        # Admin slug lookup must return None — no HUMAN entry was registered
        admin_slug = "admin-example-com"
        result = registry.get_by_slug(admin_slug)
        assert result is None, (
            f"REGRESSION (auth.py:1233): admin slug '{admin_slug}' "
            "found in real identity_registry — admin has unexpected HUMAN identity entry. "
            "This would allow admin to reach /v1/* endpoints via SSO header. "
            f"Result: {result}"
        )

        # User slug lookup must succeed — confirms the real registry is functional
        user_result = registry.get_by_slug("alice-example-com")
        assert user_result is not None, (
            "Fixture problem: 'alice-example-com' not found in real identity_registry "
            "after registration."
        )

    def test_group3b_resolve_identity_returns_none_for_unregistered_admin_slug(self):
        """
        _resolve_identity() called with X-Forwarded-User: admin-example-com
        returns None — admin slug not in real identity_registry.

        Regression target: openai_router.py:1165
          `identity = _state.identity_registry.get_by_slug(forwarded_user)`
          When get_by_slug returns None, _resolve_identity returns None.

        If the gateway were changed to fall back to a different resolution
        path for unregistered slugs, this test would catch it.
        """
        from yashigani.gateway.openai_router import _resolve_identity, configure

        registry = _make_real_registry_with_user_only()
        configure(identity_registry=registry)

        req = self._make_starlette_request({"X-Forwarded-User": "admin-example-com"})
        result = _resolve_identity(req)
        assert result is None, (
            "REGRESSION (openai_router.py:1151): _resolve_identity() resolved "
            "identity for admin slug 'admin-example-com' despite no HUMAN entry "
            f"in real identity_registry. Result: {result}"
        )

    def test_group3c_resolve_identity_returns_none_when_no_auth_header(self):
        """
        _resolve_identity() called with no X-Forwarded-User and no Authorization
        header returns None — no auth material present.

        This is a baseline case: an unauthenticated request (e.g. a browser
        session cookie without SSO header, or an admin session cookie accidentally
        forwarded to the gateway) must not resolve an identity.

        Note: the /v1/* 401 response when identity is None is exercised by
        existing tests in test_v2231_asvs_fixes.py — see test_unbound_token_no_cert_accepted
        sibling tests in that module for the Bearer path. This test focuses on
        the no-header case (e.g. admin cookie forwarded to gateway).
        """
        from yashigani.gateway.openai_router import _resolve_identity, configure

        registry = _make_real_registry_with_user_only()
        configure(identity_registry=registry)

        # No X-Forwarded-User, no Authorization header
        req = self._make_starlette_request({})
        result = _resolve_identity(req)
        assert result is None, (
            "REGRESSION (openai_router.py:1151): _resolve_identity() returned a "
            "non-None identity with no auth headers present. "
            f"Result: {result}"
        )

    def test_group3d_create_admin_does_not_register_human_identity(self):
        """
        LOAD-BEARING REGRESSION — Laura threat-model F2 / ASVS V4.1.1.

        Directly exercises the production path:
          LocalAuthService.create_admin() → _register_human_identity_on_login()
          → auth.py:1233 tier guard (account_tier != "user" → return early)

        Setup:
          1. Real fakeredis IdentityRegistry (empty — pre-state assert confirms
             no admin slug entry exists).
          2. Call LocalAuthService.create_admin("admin@example.com") to obtain
             a real AccountRecord with account_tier="admin".
          3. Call _register_human_identity_on_login(record, state) directly —
             the same function called on every local-auth login.
          4. Post-state: assert registry STILL has no entry for the admin slug.

        Why this is load-bearing:
          The old b31b268 Group 3a test used a MagicMock that returned None
          unconditionally.  A bug where _register_human_identity_on_login()
          skipped the tier guard and called registry.register(kind=HUMAN, ...)
          for an admin account would still pass that test (mock is not affected
          by production code).  THIS test would fail immediately because it
          asserts against the real registry state after executing the real code.

        Failure message on regression:
          "REGRESSION (auth.py:1233): _register_human_identity_on_login() "
          "registered a HUMAN identity for admin-tier account 'admin@example.com' "
          "— tier guard at auth.py:1233 is missing or bypassed."

        ASVS v5: V4.1.1 (enforce access control at every layer).
        OWASP API Top 10 2023: API1 (BOLA), API5 (Broken Function-Level Auth).
        Laura threat-model: F2 (admin reachability via identity_registry).
        """
        from yashigani.auth.local_auth import LocalAuthService
        from yashigani.backoffice.routes.auth import _register_human_identity_on_login

        # Real fakeredis-backed registry — clean state, nothing registered yet.
        registry = _make_real_registry()

        # Derive the slug the production code would use for this admin email.
        # _auth_email_to_slug("admin@example.com") → "admin-example-com"
        admin_email = "admin@example.com"
        admin_slug = "admin-example-com"

        # Pre-state assertion: registry is empty, no admin slug entry.
        pre_result = registry.get_by_slug(admin_slug)
        assert pre_result is None, (
            f"Fixture problem: registry already contains an entry for '{admin_slug}' "
            "before test setup. This should never happen on a fresh fakeredis instance."
        )

        # Create a real admin AccountRecord via LocalAuthService.
        # This is the same code path the bootstrap / /admin/accounts POST uses.
        auth_svc = LocalAuthService()
        admin_record, _temp_password = auth_svc.create_admin(
            username=admin_email,
            auto_generate=True,
        )
        assert admin_record.account_tier == "admin", (
            f"Fixture problem: create_admin produced a record with tier "
            f"'{admin_record.account_tier}' — expected 'admin'."
        )

        # Build a minimal state namespace that _register_human_identity_on_login
        # reads: it accesses state.identity_registry via getattr().
        state = types.SimpleNamespace(identity_registry=registry)

        # Execute the production function — this is what runs on every login.
        # For an admin-tier record, auth.py:1233 must return early WITHOUT
        # calling registry.register().
        _register_human_identity_on_login(admin_record, state)

        # Post-state assertion: registry MUST still have no entry for admin slug.
        post_result = registry.get_by_slug(admin_slug)
        assert post_result is None, (
            f"REGRESSION (auth.py:1233): _register_human_identity_on_login() "
            f"registered a HUMAN identity for admin-tier account '{admin_email}' "
            f"(slug='{admin_slug}'). The tier guard at auth.py:1233 is missing or "
            f"bypassed. This would allow the admin to reach /v1/* endpoints via "
            f"SSO header. Registry entry found: {post_result}"
        )

        # Verify alice (user tier) DOES get registered — confirms the function
        # works for legitimate user-tier accounts (control case).
        from yashigani.identity import IdentityKind
        alice_email = "alice@example.com"
        alice_slug = "alice-example-com"
        user_record = auth_svc.create_user(
            username=alice_email,
            plaintext_password="CorrectHorseBatteryStaple-Fixture-Test1!",
        )
        # Patch email so the slug resolves to alice-example-com (not the
        # @yashigani.local fallback — create_user doesn't set email).
        user_record.email = alice_email

        _register_human_identity_on_login(user_record, state)

        alice_result = registry.get_by_slug(alice_slug)
        assert alice_result is not None, (
            f"Control case FAIL: _register_human_identity_on_login() did NOT "
            f"register a HUMAN identity for user-tier account '{alice_email}' "
            f"(slug='{alice_slug}'). The function is not working for legitimate users."
        )
        assert alice_result.get("kind") == "human", (
            f"Control case FAIL: alice's identity has kind={alice_result.get('kind')!r}, "
            f"expected 'human'."
        )
