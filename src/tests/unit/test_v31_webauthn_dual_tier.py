"""
3.1 — WebAuthn dual-tier unit tests.

Covers:
  - Admin WebAuthn registration + login (existing path, regression guard)
  - User WebAuthn registration + login (new path)
  - Reveal logic intent: #webauthn-section defaults to class="hidden"
  - Tier isolation: admin login endpoint rejects user accounts; user endpoint rejects admins
  - UserSession middleware rejects non-user sessions
  - Audit event dataclass shapes for user-tier events
  - pg_webauthn helpers invoked correctly per tier
  - webauthn_user routes return correct responses

Excluded: live DB / Redis calls — those are integration tests.
All DB / service calls are mocked.

ASVS V2.8 replay tests are in test_v233_webauthn_unit.py; not duplicated here.
"""
from __future__ import annotations

import secrets
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_webauthn_credential(user_id: str = None, sign_count: int = 0):
    from yashigani.auth.webauthn import WebAuthnCredential

    uid = user_id or str(uuid.uuid4())
    return WebAuthnCredential(
        id=str(uuid.uuid4()),
        user_id=uid,
        credential_id=secrets.token_bytes(32),
        public_key=secrets.token_bytes(64),
        sign_count=sign_count,
        aaguid="00000000000000000000000000000000",
        name="Test Key",
        created_at=datetime.now(timezone.utc),
    )


def _make_session(account_id: str = None, account_tier: str = "admin"):
    """Create a Session directly using the real dataclass constructor."""
    from yashigani.auth.session import Session

    now = time.time()
    return Session(
        token=secrets.token_hex(32),
        account_id=account_id or str(uuid.uuid4()),
        account_tier=account_tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 14400,
        ip_prefix="127.0.0.x",
    )


# ---------------------------------------------------------------------------
# A. UserSession middleware
# ---------------------------------------------------------------------------


class TestUserSessionMiddleware:
    """UserSession dependency should accept user sessions and reject admin/other tiers."""

    def test_user_tier_accepted(self):
        from yashigani.backoffice.middleware import require_user_session

        store = MagicMock()
        session = _make_session(account_tier="user")
        store.get.return_value = session
        request = MagicMock()

        with patch("yashigani.backoffice.middleware._resolve_token", return_value="tok"):
            result = require_user_session(request=request, store=store)
        assert result.account_tier == "user"

    def test_admin_tier_rejected(self):
        from fastapi import HTTPException
        from yashigani.backoffice.middleware import require_user_session

        store = MagicMock()
        session = _make_session(account_tier="admin")
        store.get.return_value = session
        request = MagicMock()

        with patch("yashigani.backoffice.middleware._resolve_token", return_value="tok"):
            with pytest.raises(HTTPException) as exc_info:
                require_user_session(request=request, store=store)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "user_tier_required"

    def test_no_token_returns_401(self):
        from fastapi import HTTPException
        from yashigani.backoffice.middleware import require_user_session

        store = MagicMock()
        request = MagicMock()

        with patch("yashigani.backoffice.middleware._resolve_token", return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                require_user_session(request=request, store=store)
        assert exc_info.value.status_code == 401

    def test_expired_session_returns_401(self):
        from fastapi import HTTPException
        from yashigani.backoffice.middleware import require_user_session

        store = MagicMock()
        store.get.return_value = None  # session not found / expired
        request = MagicMock()

        with patch("yashigani.backoffice.middleware._resolve_token", return_value="stale-tok"):
            with pytest.raises(HTTPException) as exc_info:
                require_user_session(request=request, store=store)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# B. Tier isolation — _resolve_user_id vs _resolve_admin_id
# ---------------------------------------------------------------------------


class TestTierIsolation:
    """Admin and user resolver helpers must be restricted to their respective tier."""

    @pytest.mark.asyncio
    async def test_resolve_admin_id_returns_none_when_db_returns_nothing(self):
        """_resolve_admin_id returns None when DB has no matching admin account."""
        from yashigani.backoffice.routes.webauthn_v1 import _resolve_admin_id

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        # tenant_transaction is imported inside the function, so patch at the module level
        with patch("yashigani.db.postgres.tenant_transaction") as mock_tx:
            mock_tx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_tx.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await _resolve_admin_id("user@example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_user_id_returns_none_when_db_returns_nothing(self):
        """_resolve_user_id returns None when DB has no matching user account."""
        from yashigani.backoffice.routes.webauthn_user import _resolve_user_id

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch("yashigani.db.postgres.tenant_transaction") as mock_tx:
            mock_tx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_tx.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await _resolve_user_id("admin@yashigani.local")

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_user_id_returns_user_account_id(self):
        """_resolve_user_id returns account_id for a valid user account."""
        from yashigani.backoffice.routes.webauthn_user import _resolve_user_id

        uid = uuid.uuid4()
        mock_row = {"account_id": uid}
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=mock_row)

        with patch("yashigani.db.postgres.tenant_transaction") as mock_tx:
            mock_tx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_tx.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await _resolve_user_id("user@example.com")

        assert result == str(uid)


# ---------------------------------------------------------------------------
# C. User WebAuthn route unit tests (mocked service)
# ---------------------------------------------------------------------------


def _mock_pg_service():
    svc = AsyncMock()
    return svc


def _make_request(ip="127.0.0.1"):
    """Make a minimal mock Request."""
    request = MagicMock()
    request.headers = {"host": "localhost"}
    request.url.scheme = "https"
    request.url.netloc = "localhost"
    request.client = MagicMock()
    request.client.host = ip
    return request


class TestUserWebAuthnRoutes:
    """Unit test the user-tier WebAuthn route functions directly (no HTTP)."""

    @pytest.mark.asyncio
    async def test_user_register_start_returns_options(self):
        """user_register_start should call begin_registration and return options JSON."""
        from yashigani.backoffice.routes.webauthn_user import (
            user_register_start,
            UserRegisterStartRequest,
        )

        session = _make_session(account_tier="user")
        request = _make_request()
        body = UserRegisterStartRequest(credential_name="Test Key")

        svc = _mock_pg_service()
        svc.begin_registration = AsyncMock(return_value='{"challenge":"abc"}')

        with patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ):
            result = await user_register_start(body=body, session=session, request=request)

        assert result["status"] == "ok"
        assert "options" in result
        svc.begin_registration.assert_called_once_with(
            user_id=session.account_id,
            user_name=session.account_id,
        )

    @pytest.mark.asyncio
    async def test_user_register_finish_success(self):
        """user_register_finish should call complete_registration and return credential info."""
        from yashigani.backoffice.routes.webauthn_user import (
            user_register_finish,
            UserRegisterFinishRequest,
        )

        session = _make_session(account_tier="user")
        request = _make_request()
        body = UserRegisterFinishRequest(
            credential_response={"id": "abc", "rawId": "abc"},
            credential_name="YubiKey",
        )

        cred = _make_webauthn_credential(user_id=session.account_id)
        svc = _mock_pg_service()
        svc.complete_registration = AsyncMock(return_value=cred)

        state = MagicMock()
        state.audit_writer = None

        with patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ), patch("yashigani.backoffice.routes.webauthn_user.backoffice_state", state):
            result = await user_register_finish(body=body, session=session, request=request)

        assert result["status"] == "ok"
        assert result["credential_id"] == cred.id

    @pytest.mark.asyncio
    async def test_user_login_start_no_credentials_returns_400(self):
        """user_login_start with no registered creds returns 400."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.webauthn_user import (
            user_login_start,
            UserLoginStartRequest,
        )

        request = _make_request()
        response = MagicMock()
        body = UserLoginStartRequest(username="user@example.com")

        with patch(
            "yashigani.backoffice.routes.webauthn_user._resolve_user_id",
            new_callable=AsyncMock,
            return_value=None,
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._check_ip_access"
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._apply_auth_throttle"
        ):
            with pytest.raises(HTTPException) as exc_info:
                await user_login_start(body=body, request=request, response=response)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error"] == "no_credentials_registered"

    @pytest.mark.asyncio
    async def test_user_login_finish_issues_user_session(self):
        """user_login_finish must issue account_tier='user' session cookie."""
        from yashigani.backoffice.routes.webauthn_user import (
            user_login_finish,
            UserLoginFinishRequest,
        )

        uid = str(uuid.uuid4())
        request = _make_request()
        response = MagicMock()
        body = UserLoginFinishRequest(
            username="user@example.com",
            credential_response={"id": "abc", "rawId": "abc"},
        )

        svc = _mock_pg_service()
        svc.complete_authentication = AsyncMock(return_value=uid)

        store = MagicMock()
        issued_session = _make_session(account_id=uid, account_tier="user")
        store.create = MagicMock(return_value=issued_session)

        state = MagicMock()
        state.audit_writer = None

        with patch(
            "yashigani.backoffice.routes.webauthn_user._resolve_user_id",
            new_callable=AsyncMock,
            return_value=uid,
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ), patch(
            "yashigani.backoffice.routes.webauthn_user.get_session_store",
            return_value=store,
        ), patch(
            "yashigani.backoffice.routes.webauthn_user.backoffice_state", state
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._check_ip_access"
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._apply_auth_throttle"
        ), patch(
            "yashigani.backoffice.routes.webauthn_user._reset_ip_auth_failures"
        ):
            result = await user_login_finish(body=body, request=request, response=response)

        # Session created with user tier
        store.create.assert_called_once_with(
            account_id=uid,
            account_tier="user",
            client_ip="127.0.0.1",
        )
        # Cookie set with the user session cookie name
        response.set_cookie.assert_called_once()
        cookie_kwargs = response.set_cookie.call_args.kwargs
        assert cookie_kwargs.get("key") == "__Host-yashigani_session"
        # Response body
        assert result["status"] == "ok"
        assert result["redirect_to"] == "/app/webui"

    @pytest.mark.asyncio
    async def test_user_list_credentials_returns_list(self):
        """user_list_credentials returns a list with a recovery_note."""
        from yashigani.backoffice.routes.webauthn_user import user_list_credentials

        session = _make_session(account_tier="user")
        cred = _make_webauthn_credential(user_id=session.account_id)
        svc = _mock_pg_service()
        svc.list_credentials = AsyncMock(return_value=[cred])

        with patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ):
            result = await user_list_credentials(session=session)

        assert result["total"] == 1
        assert "recovery_note" in result
        assert "password + TOTP" in result["recovery_note"]

    @pytest.mark.asyncio
    async def test_user_revoke_credential_success(self):
        """user_revoke_credential calls delete_credential and returns 200."""
        from yashigani.backoffice.routes.webauthn_user import user_revoke_credential

        session = _make_session(account_tier="user")
        cred_id = str(uuid.uuid4())
        svc = _mock_pg_service()
        svc.delete_credential = AsyncMock(return_value=True)

        state = MagicMock()
        state.audit_writer = None

        with patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ), patch("yashigani.backoffice.routes.webauthn_user.backoffice_state", state):
            result = await user_revoke_credential(
                credential_id=cred_id, session=session
            )

        assert result["status"] == "ok"
        assert result["credential_id"] == cred_id

    @pytest.mark.asyncio
    async def test_user_revoke_credential_not_found_raises_404(self):
        """user_revoke_credential returns 404 when credential not found."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.webauthn_user import user_revoke_credential

        session = _make_session(account_tier="user")
        svc = _mock_pg_service()
        svc.delete_credential = AsyncMock(return_value=False)

        with patch(
            "yashigani.backoffice.routes.webauthn_user._get_pg_service",
            return_value=svc,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await user_revoke_credential(
                    credential_id=str(uuid.uuid4()), session=session
                )

        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# D. Template reveal logic — #webauthn-section must default hidden
# ---------------------------------------------------------------------------


class TestTemplateRevealLogic:
    """Verify the HTML templates default #webauthn-section to class='hidden'."""

    def _read_template(self, name: str) -> str:
        import os

        templates_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "yashigani",
            "backoffice",
            "templates",
        )
        path = os.path.join(templates_dir, name)
        with open(path) as f:
            return f.read()

    def test_admin_login_webauthn_section_default_hidden(self):
        """Admin login.html must have id='webauthn-section' with class='hidden' by default."""
        html = self._read_template("login.html")
        assert 'id="webauthn-section"' in html
        # Find the element and verify hidden class is present
        idx = html.index('id="webauthn-section"')
        context = html[max(0, idx - 30): idx + 100]
        assert "hidden" in context, (
            f"webauthn-section not default-hidden in admin login:\n{context}"
        )

    def test_user_login_webauthn_section_default_hidden(self):
        """User login user_login.html must have id='webauthn-section' with class='hidden'."""
        html = self._read_template("user_login.html")
        assert 'id="webauthn-section"' in html
        idx = html.index('id="webauthn-section"')
        context = html[max(0, idx - 30): idx + 100]
        assert "hidden" in context, (
            f"webauthn-section not default-hidden in user login:\n{context}"
        )

    def test_admin_login_includes_webauthn_login_js(self):
        """Admin login page must load webauthn_login.js."""
        html = self._read_template("login.html")
        assert "webauthn_login.js" in html

    def test_user_login_includes_webauthn_user_login_js(self):
        """User login page must load webauthn_user_login.js."""
        html = self._read_template("user_login.html")
        assert "webauthn_user_login.js" in html

    def test_user_login_includes_security_key_button(self):
        """User login page must have the security key button."""
        html = self._read_template("user_login.html")
        assert 'id="webauthn-login-btn"' in html
        assert "Sign in with Security Key" in html


# ---------------------------------------------------------------------------
# E. JS reveal logic — classList usage (inspect source)
# ---------------------------------------------------------------------------


class TestJsRevealLogic:
    """Verify the JS files use classList-based reveal, not inline style."""

    def _read_js(self, name: str) -> str:
        import os

        js_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "yashigani",
            "backoffice",
            "static",
            "js",
        )
        with open(os.path.join(js_dir, name)) as f:
            return f.read()

    def test_admin_webauthn_js_removes_hidden_class(self):
        """webauthn_login.js must call classList.remove('hidden') to reveal the section."""
        src = self._read_js("webauthn_login.js")
        assert "classList.remove('hidden')" in src

    def test_admin_webauthn_js_does_not_use_inline_style_to_hide(self):
        """webauthn_login.js must NOT set style.display = 'none' directly."""
        src = self._read_js("webauthn_login.js")
        # Inline style manipulation is replaced by classList
        assert "style.display = 'none'" not in src

    def test_admin_webauthn_js_adds_hidden_class_on_unsupported(self):
        """webauthn_login.js must add 'hidden' class (not inline style) when unsupported."""
        src = self._read_js("webauthn_login.js")
        assert "classList.add('hidden')" in src

    def test_user_webauthn_js_removes_hidden_class(self):
        """webauthn_user_login.js must call classList.remove('hidden') to reveal."""
        src = self._read_js("webauthn_user_login.js")
        assert "classList.remove('hidden')" in src

    def test_user_webauthn_js_calls_user_tier_endpoints(self):
        """webauthn_user_login.js must call user-tier endpoints."""
        src = self._read_js("webauthn_user_login.js")
        assert "/api/v1/user/webauthn/login/start" in src
        assert "/api/v1/user/webauthn/login/finish" in src

    def test_admin_webauthn_js_calls_admin_tier_endpoints(self):
        """webauthn_login.js must call admin-tier endpoints."""
        src = self._read_js("webauthn_login.js")
        assert "/api/v1/admin/webauthn/login/start" in src
        assert "/api/v1/admin/webauthn/login/finish" in src

    def test_user_webauthn_js_redirects_to_app_webui(self):
        """webauthn_user_login.js must fall back to /app/webui redirect."""
        src = self._read_js("webauthn_user_login.js")
        assert "/app/webui" in src


# ---------------------------------------------------------------------------
# F. Audit event dataclasses — user-tier shapes
# ---------------------------------------------------------------------------


class TestUserWebAuthnAuditEvents:
    def test_webauthn_user_login_success_event_shape(self):
        from yashigani.audit.schema import (
            WebAuthnUserLoginSuccessEvent,
            EventType,
            AccountTier,
        )

        evt = WebAuthnUserLoginSuccessEvent(user_account="user-1")
        assert evt.event_type == EventType.WEBAUTHN_USER_LOGIN_SUCCESS
        assert evt.account_tier == AccountTier.USER
        assert evt.user_account == "user-1"

    def test_webauthn_user_login_failure_event_shape(self):
        from yashigani.audit.schema import (
            WebAuthnUserLoginFailureEvent,
            EventType,
            AccountTier,
        )

        evt = WebAuthnUserLoginFailureEvent(
            user_account="user-1", failure_reason="bad sig"
        )
        assert evt.event_type == EventType.WEBAUTHN_USER_LOGIN_FAILURE
        assert evt.account_tier == AccountTier.USER
        assert evt.failure_reason == "bad sig"

    def test_webauthn_user_credential_registered_event_shape(self):
        from yashigani.audit.schema import (
            WebAuthnUserCredentialRegisteredEvent,
            EventType,
            AccountTier,
        )

        evt = WebAuthnUserCredentialRegisteredEvent(
            user_account="user-1", credential_name="YubiKey", outcome="success"
        )
        assert evt.event_type == EventType.WEBAUTHN_USER_CREDENTIAL_REGISTERED
        assert evt.account_tier == AccountTier.USER
        assert evt.outcome == "success"

    def test_webauthn_user_credential_revoked_event_shape(self):
        from yashigani.audit.schema import (
            WebAuthnUserCredentialRevokedEvent,
            EventType,
            AccountTier,
        )

        evt = WebAuthnUserCredentialRevokedEvent(
            user_account="user-1", credential_uuid="cred-uuid-1"
        )
        assert evt.event_type == EventType.WEBAUTHN_USER_CREDENTIAL_REVOKED
        assert evt.account_tier == AccountTier.USER

    def test_all_user_webauthn_event_types_in_enum(self):
        """EventType enum must contain all four user-tier WebAuthn entries."""
        from yashigani.audit.schema import EventType

        assert hasattr(EventType, "WEBAUTHN_USER_LOGIN_SUCCESS")
        assert hasattr(EventType, "WEBAUTHN_USER_LOGIN_FAILURE")
        assert hasattr(EventType, "WEBAUTHN_USER_CREDENTIAL_REGISTERED")
        assert hasattr(EventType, "WEBAUTHN_USER_CREDENTIAL_REVOKED")


# ---------------------------------------------------------------------------
# G. Credential storage — user_id TEXT column serves both tiers
# ---------------------------------------------------------------------------


class TestCredentialStorageTier:
    """
    Verify that the in-memory WebAuthnCredentialStore correctly isolates
    credentials by user_id regardless of account tier.
    The PgWebAuthnCredentialStore uses the same user_id TEXT column for lookup.
    """

    def test_admin_and_user_credentials_isolated_by_user_id(self):
        from yashigani.auth.webauthn import WebAuthnCredentialStore

        admin_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        store = WebAuthnCredentialStore()
        admin_cred = _make_webauthn_credential(user_id=admin_id)
        user_cred = _make_webauthn_credential(user_id=user_id)

        store.add(admin_cred)
        store.add(user_cred)

        assert store.list_for_user(admin_id) == [admin_cred]
        assert store.list_for_user(user_id) == [user_cred]

    def test_cross_tier_lookup_isolation(self):
        """An admin user_id should never return user credentials and vice versa."""
        from yashigani.auth.webauthn import WebAuthnCredentialStore

        admin_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        store = WebAuthnCredentialStore()
        admin_cred = _make_webauthn_credential(user_id=admin_id)
        store.add(admin_cred)

        # User ID returns empty (credential stored under admin_id)
        assert store.list_for_user(user_id) == []

    def test_multiple_credentials_per_user(self):
        """A user can register multiple FIDO2 credentials."""
        from yashigani.auth.webauthn import WebAuthnCredentialStore

        user_id = str(uuid.uuid4())
        store = WebAuthnCredentialStore()

        key1 = _make_webauthn_credential(user_id=user_id)
        key2 = _make_webauthn_credential(user_id=user_id)
        store.add(key1)
        store.add(key2)

        all_creds = store.list_for_user(user_id)
        assert len(all_creds) == 2


# ---------------------------------------------------------------------------
# H. Admin WebAuthn login still issues admin sessions (regression guard)
# ---------------------------------------------------------------------------


class TestAdminWebAuthnLoginRegressionGuard:
    """Ensure the admin login ceremony still issues admin-tier sessions correctly."""

    @pytest.mark.asyncio
    async def test_admin_login_finish_issues_admin_session(self):
        """login_finish in webauthn_v1 must issue account_tier='admin' sessions."""
        from yashigani.backoffice.routes.webauthn_v1 import login_finish, LoginFinishRequest

        uid = str(uuid.uuid4())
        request = _make_request()
        response = MagicMock()
        body = LoginFinishRequest(
            username="admin@yashigani.local",
            credential_response={"id": "abc", "rawId": "abc"},
        )

        svc = _mock_pg_service()
        svc.complete_authentication = AsyncMock(return_value=uid)

        store = MagicMock()
        issued_session = _make_session(account_id=uid, account_tier="admin")
        store.create = MagicMock(return_value=issued_session)

        state = MagicMock()
        state.audit_writer = None

        with patch(
            "yashigani.backoffice.routes.webauthn_v1._resolve_admin_id",
            new_callable=AsyncMock,
            return_value=uid,
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._get_pg_service",
            return_value=svc,
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1.get_session_store",
            return_value=store,
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1.backoffice_state", state
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._check_ip_access"
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._apply_auth_throttle"
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._reset_ip_auth_failures"
        ):
            result = await login_finish(body=body, request=request, response=response)

        # Must create an ADMIN session
        store.create.assert_called_once_with(
            account_id=uid,
            account_tier="admin",
            client_ip="127.0.0.1",
        )
        response.set_cookie.assert_called_once()
        cookie_kwargs = response.set_cookie.call_args.kwargs
        # Admin endpoint must set the admin session cookie
        assert cookie_kwargs.get("key") == "__Host-yashigani_admin_session"

    @pytest.mark.asyncio
    async def test_admin_login_finish_requires_admin_tier_resolution(self):
        """If _resolve_admin_id returns None, login_finish returns 401."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.webauthn_v1 import login_finish, LoginFinishRequest

        request = _make_request()
        response = MagicMock()
        body = LoginFinishRequest(
            username="nobody@example.com",
            credential_response={"id": "abc"},
        )

        state = MagicMock()
        state.audit_writer = None

        with patch(
            "yashigani.backoffice.routes.webauthn_v1._resolve_admin_id",
            new_callable=AsyncMock,
            return_value=None,
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1.backoffice_state", state
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._check_ip_access"
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._apply_auth_throttle"
        ), patch(
            "yashigani.backoffice.routes.webauthn_v1._record_auth_failure"
        ):
            with pytest.raises(HTTPException) as exc_info:
                await login_finish(body=body, request=request, response=response)

        assert exc_info.value.status_code == 401
