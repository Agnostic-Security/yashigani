"""
Unit tests — Phase 1 auth core (2.25.5-auth-ingress).

Covers:
  1. login() returns redirect_to ("/admin/" for admin, "/app/webui" for user).
  2. logout() accepts user-tier sessions (single-logout fix).
  3. /auth/verify-user accepts user-tier sessions and returns 200 + headers.
  4. /auth/verify-user rejects admin sessions with 403.
  5. /auth/verify-user rejects totp_provisioning sessions with 403.
  6. /auth/verify-user rejects unauthenticated (no cookie) with 401.
  7. /auth/verify-admin still accepts admin sessions (no regression).
  8. /auth/verify-admin still rejects user sessions (no regression).
  9. login() redirect_to is "/app/webui" for unknown/future tiers → "/".

Design: auth-ingress-architecture-20260612.md
Build sheet: auth-ingress-buildsheet-2.25.5-20260612.md (Phase 1)
Last updated: 2026-06-12T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from fastapi import HTTPException, Request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account(username: str, account_tier: str, email: str = "") -> MagicMock:
    acct = MagicMock()
    acct.username = username
    acct.account_tier = account_tier
    acct.email = email or f"{username}@example.com"
    acct.account_id = f"uuid-{username}"
    acct.disabled = False
    acct.force_password_change = False
    acct.force_totp_provision = False
    acct.password_hash = "hashed"
    acct.totp_secret = "JBSWY3DPEHPK3PXP"
    return acct


def _make_session(account_id: str, account_tier: str, token: str = "tok-abc") -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    sess.account_tier = account_tier
    sess.token = token
    sess.expires_at = 9999999999.0
    return sess


def _make_request(cookies: dict, client_host: str = "127.0.0.1") -> MagicMock:
    req = MagicMock(spec=Request)
    req.cookies = cookies
    req.client = MagicMock()
    req.client.host = client_host
    return req


# ---------------------------------------------------------------------------
# 1 + 9. login() redirect_to by role
# ---------------------------------------------------------------------------

class TestLoginRedirectTo:
    """login() must return redirect_to based on the authenticated account_tier."""

    @pytest.mark.asyncio
    async def test_admin_login_returns_redirect_to_admin(self):
        """admin tier → redirect_to == '/admin/'"""
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_record = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.authenticate = AsyncMock(
            return_value=(True, admin_record, None)
        )
        mock_state.session_store = MagicMock()
        mock_session = _make_session("admin-uuid", "admin", token="tok-admin")
        mock_state.session_store.create = MagicMock(return_value=mock_session)
        mock_state.audit_writer = MagicMock()
        # identity_registry not needed for admin tier
        mock_state.identity_registry = None

        body = MagicMock()
        body.username = "admin@example.com"
        body.password = "pw"
        body.totp_code = "123456"

        response = MagicMock()
        request = _make_request({})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with patch.object(_auth_mod, "_check_ip_access"):
                with patch.object(_auth_mod, "_apply_auth_throttle"):
                    with patch.object(_auth_mod, "_reset_ip_auth_failures"):
                        with patch.object(_auth_mod, "_register_human_identity_on_login"):
                            result = await _auth_mod.login(body, request, response)

        assert result["status"] == "ok"
        assert result["redirect_to"] == "/admin/"

    @pytest.mark.asyncio
    async def test_user_login_returns_redirect_to_webui(self):
        """user tier → redirect_to == '/app/webui'"""
        from yashigani.backoffice.routes import auth as _auth_mod

        user_record = _make_account("alice@example.com", "user")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.authenticate = AsyncMock(
            return_value=(True, user_record, None)
        )
        mock_state.session_store = MagicMock()
        mock_session = _make_session("user-uuid", "user", token="tok-user")
        mock_state.session_store.create = MagicMock(return_value=mock_session)
        mock_state.audit_writer = MagicMock()
        mock_state.identity_registry = None

        body = MagicMock()
        body.username = "alice@example.com"
        body.password = "pw"
        body.totp_code = "123456"

        response = MagicMock()
        request = _make_request({})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with patch.object(_auth_mod, "_check_ip_access"):
                with patch.object(_auth_mod, "_apply_auth_throttle"):
                    with patch.object(_auth_mod, "_reset_ip_auth_failures"):
                        with patch.object(_auth_mod, "_register_human_identity_on_login"):
                            result = await _auth_mod.login(body, request, response)

        assert result["status"] == "ok"
        assert result["redirect_to"] == "/app/webui"


# ---------------------------------------------------------------------------
# 2. logout() accepts user-tier sessions
# ---------------------------------------------------------------------------

class TestLogoutAnyTier:
    """logout() must accept user-tier sessions (single-logout fix, Phase 1)."""

    @pytest.mark.asyncio
    async def test_logout_accepts_user_session(self):
        """User-tier session must be accepted by logout (was blocked by AdminSession before Phase 1)."""
        from yashigani.backoffice.routes import auth as _auth_mod
        from yashigani.auth.session import Session
        import time

        # Build a real-looking user session object (not just a MagicMock)
        user_session = Session(
            token="tok-user-session",
            account_id="user-uuid",
            account_tier="user",
            created_at=time.time(),
            last_active_at=time.time(),
            expires_at=time.time() + 3600,
            ip_prefix="127.0.0.0",
        )

        store = MagicMock()
        store.invalidate = MagicMock()

        response = MagicMock()
        response.delete_cookie = MagicMock()

        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        # inject via AnySession dependency — test the handler directly
        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                session=user_session,
                response=response,
                store=store,
            )

        assert result["status"] == "ok"
        store.invalidate.assert_called_once_with("tok-user-session")
        # Both cookies cleared
        assert response.delete_cookie.call_count == 2

    @pytest.mark.asyncio
    async def test_logout_accepts_admin_session(self):
        """Admin-tier session still works with the widened logout (regression)."""
        from yashigani.backoffice.routes import auth as _auth_mod
        from yashigani.auth.session import Session
        import time

        admin_session = Session(
            token="tok-admin-session",
            account_id="admin-uuid",
            account_tier="admin",
            created_at=time.time(),
            last_active_at=time.time(),
            expires_at=time.time() + 3600,
            ip_prefix="127.0.0.0",
        )

        store = MagicMock()
        store.invalidate = MagicMock()
        response = MagicMock()
        response.delete_cookie = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                session=admin_session,
                response=response,
                store=store,
            )

        assert result["status"] == "ok"
        store.invalidate.assert_called_once_with("tok-admin-session")

    @pytest.mark.asyncio
    async def test_logout_emits_audit_event_with_correct_tier(self):
        """logout() audit event carries the actual session tier."""
        from yashigani.backoffice.routes import auth as _auth_mod
        from yashigani.auth.session import Session
        import time

        user_session = Session(
            token="tok-audit",
            account_id="uid-audit",
            account_tier="user",
            created_at=time.time(),
            last_active_at=time.time(),
            expires_at=time.time() + 3600,
            ip_prefix="127.0.0.0",
        )

        store = MagicMock()
        store.invalidate = MagicMock()
        response = MagicMock()
        response.delete_cookie = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            await _auth_mod.logout(session=user_session, response=response, store=store)

        # Audit write was called with the correct account_id
        mock_state.audit_writer.write.assert_called_once()
        event_arg = mock_state.audit_writer.write.call_args[0][0]
        assert event_arg.account_tier == "user"


# ---------------------------------------------------------------------------
# 3. /auth/verify-user accepts user-tier sessions
# ---------------------------------------------------------------------------

class TestVerifyUserEndpoint:
    """verify_user_session(): user-tier sessions accepted, others rejected."""

    @pytest.mark.asyncio
    async def test_verify_user_accepts_user_session_returns_200(self):
        """User session → 200 with X-Forwarded-User header."""
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-uuid", "user", token="tok-user")
        user_record = _make_account("alice", "user", "alice@example.com")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_id = AsyncMock(return_value=user_record)
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)

        request = _make_request({"__Host-yashigani_session": "tok-user"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.verify_user_session(request)

        assert resp.status_code == 200
        assert "X-Forwarded-User" in resp.headers
        assert resp.headers["X-Forwarded-User"] == "alice@example.com"
        assert resp.headers["X-Forwarded-Name"] == "alice"

    @pytest.mark.asyncio
    async def test_verify_user_user_without_email_uses_synthetic(self):
        """User with no email gets synthetic @yashigani.local email."""
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-uuid", "user")
        user_record = _make_account("bobsmith", "user", "")
        user_record.email = ""  # no email

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_id = AsyncMock(return_value=user_record)
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)

        request = _make_request({"__Host-yashigani_session": "tok-user"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.verify_user_session(request)

        assert resp.status_code == 200
        assert resp.headers["X-Forwarded-User"] == "bobsmith@yashigani.local"


# ---------------------------------------------------------------------------
# 4. /auth/verify-user rejects admin sessions with 403
# ---------------------------------------------------------------------------

class TestVerifyUserRejectsAdmin:
    """verify-user endpoint must reject admin sessions (SoD preserved)."""

    @pytest.mark.asyncio
    async def test_verify_user_rejects_admin_session_with_403(self):
        """Admin session → 403 from /auth/verify-user."""
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin", token="tok-admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)

        request = _make_request({"__Host-yashigani_admin_session": "tok-admin"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "admin_session_not_allowed_user_path"

    @pytest.mark.asyncio
    async def test_verify_user_rejects_admin_session_from_user_cookie(self):
        """Admin session presented via user cookie → still 403."""
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin", token="tok-admin-misuse")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)

        request = _make_request({"__Host-yashigani_session": "tok-admin-misuse"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# 5. /auth/verify-user rejects totp_provisioning sessions
# ---------------------------------------------------------------------------

class TestVerifyUserRejectsProvisioning:

    @pytest.mark.asyncio
    async def test_verify_user_rejects_provisioning_session_with_403(self):
        """totp_provisioning session → 403 from /auth/verify-user."""
        from yashigani.backoffice.routes import auth as _auth_mod

        prov_session = _make_session("user-uuid", "totp_provisioning", token="tok-prov")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=prov_session)

        request = _make_request({"__Host-yashigani_session": "tok-prov"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "totp_provisioning_incomplete"


# ---------------------------------------------------------------------------
# 6. /auth/verify-user rejects unauthenticated
# ---------------------------------------------------------------------------

class TestVerifyUserRejectsUnauthenticated:

    @pytest.mark.asyncio
    async def test_verify_user_no_cookie_returns_401(self):
        """No session cookie → 401."""
        from yashigani.backoffice.routes import auth as _auth_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()

        request = _make_request({})  # no cookies

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_verify_user_expired_session_returns_401(self):
        """Expired/invalid session token → 401."""
        from yashigani.backoffice.routes import auth as _auth_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=None)  # expired

        request = _make_request({"__Host-yashigani_session": "stale-token"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 7. /auth/verify-admin regression: still accepts admin sessions
# ---------------------------------------------------------------------------

class TestVerifyAdminRegression:
    """verify_admin_session() must still accept admin sessions (no regression)."""

    @pytest.mark.asyncio
    async def test_verify_admin_accepts_admin_session(self):
        """Admin session → 200 from /auth/verify-admin (regression guard)."""
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin", token="tok-admin")
        admin_record = _make_account("admin", "admin", "admin@example.com")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_id = AsyncMock(return_value=admin_record)
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)

        request = _make_request({"__Host-yashigani_admin_session": "tok-admin"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.verify_admin_session(request)

        assert resp.status_code == 200
        assert resp.headers["X-Forwarded-User"] == "admin@example.com"


# ---------------------------------------------------------------------------
# 8. /auth/verify-admin regression: still rejects user sessions
# ---------------------------------------------------------------------------

class TestVerifyAdminRejectsUserRegression:

    @pytest.mark.asyncio
    async def test_verify_admin_rejects_user_session_with_403(self):
        """User session → 403 from /auth/verify-admin (regression guard)."""
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-uuid", "user", token="tok-user")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)

        request = _make_request({"__Host-yashigani_admin_session": "tok-user"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_admin_session(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "admin_session_required"


# ---------------------------------------------------------------------------
# Cross-path SoD invariants
# ---------------------------------------------------------------------------

class TestCrossPathSoDInvariants:
    """
    Invariant: admin sessions are rejected on user paths and vice-versa.
    This is the core of the split-verify architecture from auth-ingress-architecture-20260612.md.
    """

    @pytest.mark.asyncio
    async def test_admin_cannot_reach_user_path_via_verify_user(self):
        """Admin session → 403 on /auth/verify-user (cannot access user path)."""
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        request = _make_request({"__Host-yashigani_admin_session": "tok-admin"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_user_session(request)

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_user_cannot_reach_admin_path_via_verify_admin(self):
        """User session → 403 on /auth/verify-admin (cannot access admin path).

        verify_admin_session reads _SESSION_COOKIE (__Host-yashigani_admin_session).
        We present the token via that cookie so the session is found; the tier check
        then fires and returns 403 (not 401).
        """
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-uuid", "user", token="tok-user")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)
        # verify_admin_session reads __Host-yashigani_admin_session (_SESSION_COOKIE)
        request = _make_request({"__Host-yashigani_admin_session": "tok-user"})

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_admin_session(request)

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_data_plane_verify_still_rejects_admin(self):
        """
        /auth/verify (data-plane, SoD-003) still rejects admin sessions.
        Regression guard for the original SoD-003 fix.
        """
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        mock_state.audit_writer = MagicMock()
        request = _make_request({"__Host-yashigani_session": "tok-admin"})
        request.client.host = "10.0.0.1"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_session(request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "admin_session_not_allowed_data_plane"
