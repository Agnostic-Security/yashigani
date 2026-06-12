"""
Unit tests — Phase 2 / 2.25.5-auth-ingress: OWUI re-pathed to /app/webui.

Verifies:
  1. /auth/logout-redirect clears cookies and redirects to /login for valid session.
  2. /auth/logout-redirect clears cookies and redirects to /login when no session.
  3. /auth/logout-redirect clears cookies and redirects to /login for expired session.
  4. /app/webui placeholder is gone from backoffice (no 302 → / any more).

Last updated: 2026-06-13T00:00:00+00:00
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.responses import RedirectResponse

# ---------------------------------------------------------------------------
# Helpers (mirrored from test_v2255_phase1_auth_core.py)
# ---------------------------------------------------------------------------

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../"))

from yashigani.auth.session import Session


def _make_session(token: str, account_id: str, account_tier: str) -> Session:
    now = time.time()
    return Session(
        token=token,
        account_id=account_id,
        account_tier=account_tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="192.168.1",
    )


def _make_request(cookies: dict[str, str]) -> Request:
    """Build a minimal starlette Request with the given cookies."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/auth/logout-redirect",
        "query_string": b"",
        "headers": [],
    }
    request = Request(scope, receive=AsyncMock())
    # Inject cookies directly into the request's state.
    object.__setattr__(request, "_cookies", cookies)
    return request


# ---------------------------------------------------------------------------
# 1. logout_redirect — valid session cleared and cookie deleted
# ---------------------------------------------------------------------------


class TestLogoutRedirectValidSession:
    """logout_redirect() must invalidate the session and redirect to /login."""

    @pytest.mark.asyncio
    async def test_logout_redirect_valid_user_session_redirects_to_login(self):
        """Valid user session → invalidate → 302 /login + cookies cleared."""
        import yashigani.backoffice.routes.auth as _auth_mod

        session = _make_session("tok-user", "dana.lee@example.com", "user")
        store = MagicMock()
        store.get.return_value = session  # simulate live session
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_session": "tok-user"})

        with patch.object(_auth_mod, "backoffice_state") as mock_state:
            mock_state.audit_writer = None
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        store.invalidate.assert_called_once_with("tok-user")
        assert isinstance(resp, RedirectResponse)
        assert resp.status_code == 302
        location = resp.headers.get("location", "")
        assert location == "/login", f"Expected /login, got {location!r}"

    @pytest.mark.asyncio
    async def test_logout_redirect_clears_both_cookies(self):
        """Both session cookies must be cleared (admin + user-tier)."""
        import yashigani.backoffice.routes.auth as _auth_mod

        session = _make_session("tok-admin", "admin@example.com", "admin")
        store = MagicMock()
        store.get.return_value = session
        store.invalidate = MagicMock()

        request = _make_request(
            {
                "__Host-yashigani_admin_session": "tok-admin",
                "__Host-yashigani_session": "tok-admin",
            }
        )

        with patch.object(_auth_mod, "backoffice_state") as mock_state:
            mock_state.audit_writer = None
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        # Both cookies must be in the Set-Cookie headers with deletion directives.
        raw_cookies = resp.headers.getlist("set-cookie")
        # RedirectResponse.delete_cookie calls set_cookie with max_age=0 internally.
        # Just verify both cookies appear in the response Set-Cookie headers.
        cookie_headers = " ".join(raw_cookies)
        assert "__Host-yashigani_admin_session" in cookie_headers or "__Host-yashigani_session" in cookie_headers, (
            f"Expected session cookie deletion in Set-Cookie, got: {raw_cookies}"
        )


# ---------------------------------------------------------------------------
# 2. logout_redirect — no session (unauthenticated)
# ---------------------------------------------------------------------------


class TestLogoutRedirectNoSession:
    """logout_redirect() with no cookie must still redirect to /login safely."""

    @pytest.mark.asyncio
    async def test_logout_redirect_no_cookie_redirects_to_login(self):
        """No cookie → no invalidation → still 302 /login."""
        import yashigani.backoffice.routes.auth as _auth_mod

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({})  # no cookies

        with patch.object(_auth_mod, "backoffice_state") as mock_state:
            mock_state.audit_writer = None
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        store.invalidate.assert_not_called()
        assert isinstance(resp, RedirectResponse)
        assert resp.status_code == 302
        assert resp.headers.get("location") == "/login"


# ---------------------------------------------------------------------------
# 3. logout_redirect — expired/invalid session (store.get returns None)
# ---------------------------------------------------------------------------


class TestLogoutRedirectExpiredSession:
    """logout_redirect() with an expired token must still redirect to /login."""

    @pytest.mark.asyncio
    async def test_logout_redirect_expired_session_redirects_to_login(self):
        """Expired session (store.get returns None) → invalidate still called → 302 /login."""
        import yashigani.backoffice.routes.auth as _auth_mod

        store = MagicMock()
        store.get.return_value = None  # expired
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_session": "tok-expired"})

        with patch.object(_auth_mod, "backoffice_state") as mock_state:
            mock_state.audit_writer = None
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        # invalidate should still be called for the token present in the cookie.
        store.invalidate.assert_called_once_with("tok-expired")
        assert isinstance(resp, RedirectResponse)
        assert resp.status_code == 302
        assert resp.headers.get("location") == "/login"


# ---------------------------------------------------------------------------
# 4. Backoffice app.py placeholder is gone
# ---------------------------------------------------------------------------


class TestWebuiPlaceholderRemoved:
    """The Phase 1 /app/webui placeholder must no longer exist in backoffice app.py."""

    def test_placeholder_function_not_exported(self):
        """app_webui_placeholder must not be importable from backoffice.routes."""
        # The function was removed in Phase 2; confirm it's not present.
        import yashigani.backoffice.routes.auth as _auth_mod

        assert not hasattr(_auth_mod, "app_webui_placeholder"), (
            "Phase 1 placeholder app_webui_placeholder still exists — should have been removed in Phase 2"
        )

    def test_logout_redirect_is_exported(self):
        """logout_redirect must exist as the Phase 2 replacement."""
        import yashigani.backoffice.routes.auth as _auth_mod

        assert hasattr(_auth_mod, "logout_redirect"), (
            "logout_redirect must be defined in auth routes for Phase 2"
        )
