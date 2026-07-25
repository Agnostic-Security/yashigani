"""
Regression tests for WA-10 — incomplete logout / session invalidation.

Ava's finding (2026-07-15, 4.1.2 RC):
  Browser holding BOTH __Host-yashigani_session (user) and
  __Host-yashigani_admin_session (admin) hits /auth/logout-redirect.
  After redirect, a subsequent /admin/* request returns 200 (should be 401).

Root cause 1 (server-side): logout handlers invalidated only the single token
  resolved by _resolve_token / cookie-priority logic (admin first for POST
  /logout; user first for GET /logout-redirect).  The other session was never
  revoked from Redis.

Root cause 2 (client-side): clearance Set-Cookie headers for __Host- prefixed
  cookies lacked the mandatory Secure attribute.  Per RFC 6265bis §4.1.3, a
  __Host- clearance without Secure is rejected by the browser, so the
  Max-Age=0 directive was silently ignored and the original token stayed live.

Fix:
  1. Both handlers now enumerate ALL cookie slots and invalidate every distinct
     token independently.
  2. _clear_session_cookie() helper added — mirrors _set_session_cookie()
     attribute-for-attribute (Secure, HttpOnly, SameSite=Strict, Path=/).

ASVS V3.3.1 (server-side logout), V3.4.1 (__Host- cookie security).

Last updated: 2026-07-15T00:00:00+00:00
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(token: str, account_id: str, account_tier: str):
    """Build a real-ish Session object using the production dataclass."""
    from yashigani.auth.session import Session

    return Session(
        token=token,
        account_id=account_id,
        account_tier=account_tier,
        created_at=time.time(),
        last_active_at=time.time(),
        expires_at=time.time() + 3600,
        ip_prefix="127.0.0.0",
    )


def _make_request(cookies: dict[str, str]):
    """Build a minimal Request-like mock with a .cookies mapping."""
    req = MagicMock()
    req.cookies = cookies
    return req


def _cookie_names_in_headers(response) -> list[str]:
    """Return the cookie names mentioned in Set-Cookie response headers."""
    raw = response.headers.getlist("set-cookie") if hasattr(response.headers, "getlist") else []
    names = []
    for h in raw:
        # First token before '=' is the cookie name
        name = h.split("=")[0].strip()
        names.append(name)
    return names


def _set_cookie_has_attr(response, cookie_name: str, attr: str) -> bool:
    """True if any Set-Cookie header for cookie_name contains the attribute string."""
    raw = response.headers.getlist("set-cookie") if hasattr(response.headers, "getlist") else []
    for h in raw:
        if h.startswith(cookie_name + "="):
            if attr.lower() in h.lower():
                return True
    return False


# ---------------------------------------------------------------------------
# Part 1 — POST /logout: dual-session server-side revocation (WA-10 RC1)
# ---------------------------------------------------------------------------


class TestLogoutDualSessionRevocation:
    """logout() must revoke ALL session tokens present, not just the first resolved."""

    @pytest.mark.asyncio
    async def test_both_sessions_revoked_when_dual_cookies_present(self):
        """
        Browser holds admin + user cookie (different tokens, different sessions).
        logout() must invalidate BOTH server-side.
        This is the exact WA-10 repro: previously only session.token (admin) was
        revoked; the user session stayed live.
        """
        import yashigani.backoffice.routes.auth as _auth_mod

        admin_session = _make_session("tok-admin", "admin-uuid", "admin")
        user_token = "tok-user-different"  # distinct from admin token

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_admin_session": "tok-admin",
            "__Host-yashigani_session": user_token,
        })
        response = MagicMock()

        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                request=request,
                session=admin_session,
                response=response,
                store=store,
            )

        assert result["status"] == "ok"

        # Both tokens must be revoked
        invalidated = {call.args[0] for call in store.invalidate.call_args_list}
        assert "tok-admin" in invalidated, "Admin session not revoked"
        assert user_token in invalidated, (
            "WA-10 regression: user session was NOT revoked when dual cookies present"
        )

    @pytest.mark.asyncio
    async def test_only_admin_session_when_user_cookie_absent(self):
        """Single admin cookie → only one invalidation (no phantom second call)."""
        import yashigani.backoffice.routes.auth as _auth_mod

        admin_session = _make_session("tok-admin-only", "admin-uuid", "admin")

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_admin_session": "tok-admin-only",
        })
        response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                request=request,
                session=admin_session,
                response=response,
                store=store,
            )

        assert result["status"] == "ok"
        invalidated = {call.args[0] for call in store.invalidate.call_args_list}
        assert "tok-admin-only" in invalidated
        # No extra revocations
        assert len(invalidated) == 1

    @pytest.mark.asyncio
    async def test_same_token_in_both_slots_revoked_once(self):
        """When both cookie slots carry the same token, it is revoked exactly once."""
        import yashigani.backoffice.routes.auth as _auth_mod

        shared_token = "tok-shared"
        session = _make_session(shared_token, "user-uuid", "user")

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_admin_session": shared_token,
            "__Host-yashigani_session": shared_token,
        })
        response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            await _auth_mod.logout(
                request=request,
                session=session,
                response=response,
                store=store,
            )

        # Deduplicated — only one invalidate() call
        assert store.invalidate.call_count == 1

    @pytest.mark.asyncio
    async def test_user_only_cookie_logout_still_works(self):
        """Single user-tier cookie logout is a regression check for normal flow."""
        import yashigani.backoffice.routes.auth as _auth_mod

        user_session = _make_session("tok-user-session", "user-uuid", "user")

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_session": "tok-user-session"})
        response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                request=request,
                session=user_session,
                response=response,
                store=store,
            )

        assert result["status"] == "ok"
        store.invalidate.assert_called_once_with("tok-user-session")


# ---------------------------------------------------------------------------
# Part 2 — POST /logout: __Host- cookie clearance must include Secure (WA-10 RC2)
# ---------------------------------------------------------------------------


class TestLogoutCookieClearanceAttributes:
    """Clearance Set-Cookie headers must carry Secure; HttpOnly; Path=/ for __Host-."""

    @pytest.mark.asyncio
    async def test_clearance_headers_include_secure_attribute(self):
        """
        The Set-Cookie clearance for __Host- cookies must include 'Secure'.
        Without Secure, RFC 6265bis §4.1.3 mandates that browsers reject the
        directive — the token stays live in the browser.
        """
        from fastapi.responses import Response as FastAPIResponse
        import yashigani.backoffice.routes.auth as _auth_mod

        session = _make_session("tok-secure-check", "uid", "admin")

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_admin_session": "tok-secure-check"})
        # Use a real FastAPI Response so headers are actually populated
        response = FastAPIResponse()
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            await _auth_mod.logout(
                request=request,
                session=session,
                response=response,
                store=store,
            )

        raw_cookies = response.headers.getlist("set-cookie")
        assert raw_cookies, "No Set-Cookie headers in logout response"

        admin_cookies = [h for h in raw_cookies if "__Host-yashigani_admin_session" in h]
        user_cookies = [h for h in raw_cookies if "__Host-yashigani_session" in h]

        assert admin_cookies, "Admin cookie clearance header missing"
        assert user_cookies, "User cookie clearance header missing"

        for hdr in admin_cookies + user_cookies:
            assert "secure" in hdr.lower(), (
                f"WA-10 RC2 regression: Secure attribute missing from clearance header: {hdr!r}"
            )
            assert "httponly" in hdr.lower(), (
                f"WA-10 RC2 regression: HttpOnly attribute missing from clearance header: {hdr!r}"
            )
            assert "path=/" in hdr.lower(), (
                f"WA-10 RC2 regression: Path=/ missing from clearance header: {hdr!r}"
            )
            assert "max-age=0" in hdr.lower(), (
                f"Clearance header must carry Max-Age=0: {hdr!r}"
            )

    @pytest.mark.asyncio
    async def test_clearance_samesite_matches_set_path(self):
        """Clearance SameSite must match the value used when setting the cookie (Strict)."""
        from fastapi.responses import Response as FastAPIResponse
        import yashigani.backoffice.routes.auth as _auth_mod

        session = _make_session("tok-samesite", "uid", "user")
        store = MagicMock()
        store.invalidate = MagicMock()
        request = _make_request({"__Host-yashigani_session": "tok-samesite"})
        response = FastAPIResponse()
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            await _auth_mod.logout(
                request=request,
                session=session,
                response=response,
                store=store,
            )

        raw_cookies = response.headers.getlist("set-cookie")
        user_cookies = [h for h in raw_cookies if "__Host-yashigani_session" in h]
        assert user_cookies, "User cookie clearance header missing"
        for hdr in user_cookies:
            assert "samesite=strict" in hdr.lower(), (
                f"SameSite=Strict missing from clearance: {hdr!r}"
            )


# ---------------------------------------------------------------------------
# Part 3 — GET /logout-redirect: dual-session server-side revocation (WA-10 RC1)
# ---------------------------------------------------------------------------


class TestLogoutRedirectDualSessionRevocation:
    """logout_redirect() must revoke ALL session tokens present, not just user-first."""

    @pytest.mark.asyncio
    async def test_both_sessions_revoked_when_dual_cookies_present(self):
        """
        This is the exact Ava repro path: /auth/logout-redirect is called with
        both cookies present.  Previously user-cookie was resolved first; the
        admin session remained live and /admin/* returned 200.
        """
        import yashigani.backoffice.routes.auth as _auth_mod
        from fastapi.responses import RedirectResponse

        user_session = _make_session("tok-user", "user-uuid", "user")
        admin_token = "tok-admin-different"

        store = MagicMock()
        # store.get: return session data before invalidation
        store.get.side_effect = lambda tok: user_session if tok == "tok-user" else None
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_session": "tok-user",
            "__Host-yashigani_admin_session": admin_token,
        })

        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)

        invalidated = {call.args[0] for call in store.invalidate.call_args_list}
        assert "tok-user" in invalidated, "User session not revoked"
        assert admin_token in invalidated, (
            "WA-10 regression: admin session was NOT revoked by logout_redirect"
        )

    @pytest.mark.asyncio
    async def test_no_cookies_no_invalidation_still_redirects(self):
        """No cookies → zero invalidation calls → still 302 /login."""
        import yashigani.backoffice.routes.auth as _auth_mod
        from fastapi.responses import RedirectResponse

        store = MagicMock()
        store.invalidate = MagicMock()

        request = _make_request({})
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        store.invalidate.assert_not_called()
        assert isinstance(resp, RedirectResponse)

    @pytest.mark.asyncio
    async def test_redirect_clearance_headers_include_secure(self):
        """
        Set-Cookie clearance on the redirect response must include Secure.
        Without Secure, browsers reject the __Host- clearance.
        """
        import yashigani.backoffice.routes.auth as _auth_mod
        from fastapi.responses import RedirectResponse

        store = MagicMock()
        store.get.return_value = None
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_session": "tok-r",
            "__Host-yashigani_admin_session": "tok-r-admin",
        })
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        raw_cookies = resp.headers.getlist("set-cookie")
        assert raw_cookies, "No Set-Cookie on redirect response"

        for hdr in raw_cookies:
            assert "secure" in hdr.lower(), (
                f"WA-10 RC2 regression: Secure missing from redirect clearance: {hdr!r}"
            )
            assert "max-age=0" in hdr.lower(), (
                f"Redirect clearance must carry Max-Age=0: {hdr!r}"
            )


# ---------------------------------------------------------------------------
# Part 4 — change_password: cookie clearance completeness (related WA-10 fix)
# ---------------------------------------------------------------------------


class TestChangePasswordCookieClearance:
    """change_password() must clear BOTH cookies with correct attributes."""

    def test_clear_session_cookie_helper_emits_secure(self):
        """
        _clear_session_cookie() must emit Secure, HttpOnly, Path=/, Max-Age=0.
        This is the unit-level contract for the helper introduced in WA-10.
        """
        from fastapi.responses import Response as FastAPIResponse
        from yashigani.backoffice.routes.auth import _clear_session_cookie

        response = FastAPIResponse()
        _clear_session_cookie(response, "__Host-yashigani_admin_session")

        raw_cookies = response.headers.getlist("set-cookie")
        assert raw_cookies, "No Set-Cookie emitted by _clear_session_cookie"
        hdr = raw_cookies[0]

        assert "__Host-yashigani_admin_session" in hdr
        assert "secure" in hdr.lower(), f"Secure missing: {hdr!r}"
        assert "httponly" in hdr.lower(), f"HttpOnly missing: {hdr!r}"
        assert "path=/" in hdr.lower(), f"Path=/ missing: {hdr!r}"
        assert "max-age=0" in hdr.lower(), f"Max-Age=0 missing: {hdr!r}"
        assert "samesite=strict" in hdr.lower(), f"SameSite=Strict missing: {hdr!r}"

    def test_clear_session_cookie_helper_user_cookie(self):
        """Same contract for __Host-yashigani_session (user cookie)."""
        from fastapi.responses import Response as FastAPIResponse
        from yashigani.backoffice.routes.auth import _clear_session_cookie

        response = FastAPIResponse()
        _clear_session_cookie(response, "__Host-yashigani_session")

        raw_cookies = response.headers.getlist("set-cookie")
        assert raw_cookies
        hdr = raw_cookies[0]
        assert "__Host-yashigani_session" in hdr
        assert "secure" in hdr.lower()
        assert "max-age=0" in hdr.lower()

    def test_set_and_clear_attributes_are_symmetric(self):
        """
        _set_session_cookie and _clear_session_cookie must use the same attributes
        for Secure, HttpOnly, SameSite, Path — they cannot drift independently.
        """
        from fastapi.responses import Response as FastAPIResponse
        from yashigani.backoffice.routes.auth import (
            _clear_session_cookie,
            _set_session_cookie,
        )

        set_resp = FastAPIResponse()
        _set_session_cookie(set_resp, "fake-token", "user")
        set_cookies = set_resp.headers.getlist("set-cookie")
        assert set_cookies
        set_hdr = set_cookies[0]

        clear_resp = FastAPIResponse()
        _clear_session_cookie(clear_resp, "__Host-yashigani_session")
        clear_cookies = clear_resp.headers.getlist("set-cookie")
        assert clear_cookies
        clear_hdr = clear_cookies[0]

        # Both must carry the same security attributes
        for attr in ("secure", "httponly", "samesite=strict", "path=/"):
            assert attr in set_hdr.lower(), f"Set missing {attr}: {set_hdr!r}"
            assert attr in clear_hdr.lower(), f"Clear missing {attr}: {clear_hdr!r}"


# ---------------------------------------------------------------------------
# Part 5 — Regression: existing single-session logout flows still work
# ---------------------------------------------------------------------------


class TestSingleSessionLogoutRegression:
    """Confirm that normal (single-session) logout flows are unaffected."""

    @pytest.mark.asyncio
    async def test_admin_single_session_logout_ok(self):
        """Admin-only logout: session invalidated, 200 ok returned."""
        import yashigani.backoffice.routes.auth as _auth_mod

        admin_session = _make_session("tok-admin-single", "admin-uuid", "admin")

        store = MagicMock()
        store.invalidate = MagicMock()
        request = _make_request({"__Host-yashigani_admin_session": "tok-admin-single"})
        response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            result = await _auth_mod.logout(
                request=request,
                session=admin_session,
                response=response,
                store=store,
            )

        assert result == {"status": "ok"}
        store.invalidate.assert_any_call("tok-admin-single")
        mock_state.audit_writer.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_user_single_session_logout_redirect_ok(self):
        """User-only logout-redirect: session invalidated, 302 /login returned."""
        import yashigani.backoffice.routes.auth as _auth_mod
        from fastapi.responses import RedirectResponse

        user_session = _make_session("tok-user-single", "user-uuid", "user")

        store = MagicMock()
        store.get.return_value = user_session
        store.invalidate = MagicMock()
        request = _make_request({"__Host-yashigani_session": "tok-user-single"})
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        store.invalidate.assert_called_once_with("tok-user-single")

    @pytest.mark.asyncio
    async def test_audit_event_emitted_on_logout(self):
        """Audit event with correct tier is still emitted after WA-10 refactor."""
        import yashigani.backoffice.routes.auth as _auth_mod

        user_session = _make_session("tok-audit-check", "uid-audit", "user")

        store = MagicMock()
        store.invalidate = MagicMock()
        request = _make_request({"__Host-yashigani_session": "tok-audit-check"})
        response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            await _auth_mod.logout(
                request=request,
                session=user_session,
                response=response,
                store=store,
            )

        mock_state.audit_writer.write.assert_called_once()
        event = mock_state.audit_writer.write.call_args[0][0]
        assert event.account_tier == "user"
        # _make_login_event maps the first arg (session.account_id) → admin_account field
        assert event.admin_account == "uid-audit"
