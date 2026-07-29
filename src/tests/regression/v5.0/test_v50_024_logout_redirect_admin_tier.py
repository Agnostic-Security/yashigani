# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-024: GET /auth/logout-redirect hardcoded redirect_to=/login
for BOTH tiers, so an admin logging out landed on the end-user login page
instead of /admin/login.

Fix: the redirect target is now keyed off the admin cookie's presence in the
request (captured before cookie clearance) — the strongest available tier
signal, since an already-expired session may no longer resolve via
store.get() by the time the handler gets to it.

Session invalidation itself was already correct (WA-10, v4.1.2) — this is
purely the redirect-target fix. See test_wa10_logout_session_invalidation.py
for the invalidation-correctness suite; this file only covers the redirect
target added by V50-024 and confirms the WA-10 behaviour is unaffected.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.responses import RedirectResponse


def _make_session(token: str, account_id: str, account_tier: str):
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
    req = MagicMock()
    req.cookies = cookies
    return req


class TestLogoutRedirectTierTarget:
    """V50-024: redirect target must match the caller's session tier."""

    @pytest.mark.asyncio
    async def test_admin_cookie_present_redirects_to_admin_login(self):
        """
        Exact V50-024 repro: an admin session logs out via /auth/logout-redirect
        (e.g. the OWUI-relayed sign-out path). Must land on /admin/login, not
        the end-user /login page.
        """
        import yashigani.backoffice.routes.auth as _auth_mod

        admin_session = _make_session("tok-admin-v50024", "admin-uuid", "admin")
        store = MagicMock()
        store.get.return_value = admin_session
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_admin_session": "tok-admin-v50024"})
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        location = resp.headers.get("location", "")
        assert location == "/admin/login", (
            f"V50-024 regression: admin-tier logout-redirect landed on {location!r}, "
            "expected /admin/login"
        )

    @pytest.mark.asyncio
    async def test_user_cookie_only_still_redirects_to_login(self):
        """User-tier session (no admin cookie) → unchanged /login target."""
        import yashigani.backoffice.routes.auth as _auth_mod

        user_session = _make_session("tok-user-v50024", "user-uuid", "user")
        store = MagicMock()
        store.get.return_value = user_session
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_session": "tok-user-v50024"})
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        assert resp.headers.get("location") == "/login"

    @pytest.mark.asyncio
    async def test_no_cookies_still_redirects_to_login(self):
        """No session at all → safe default of /login (unchanged)."""
        import yashigani.backoffice.routes.auth as _auth_mod

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

        assert isinstance(resp, RedirectResponse)
        assert resp.headers.get("location") == "/login"

    @pytest.mark.asyncio
    async def test_dual_cookies_present_redirects_to_admin_login(self):
        """
        Browser holds BOTH cookies (admin logged in, previously also had a
        stale user session). Admin cookie presence wins — /admin/login.
        WA-10 invalidation of BOTH tokens must still hold.
        """
        import yashigani.backoffice.routes.auth as _auth_mod

        user_session = _make_session("tok-user-dual", "user-uuid", "user")
        store = MagicMock()
        store.get.side_effect = lambda tok: user_session if tok == "tok-user-dual" else None
        store.invalidate = MagicMock()

        request = _make_request({
            "__Host-yashigani_session": "tok-user-dual",
            "__Host-yashigani_admin_session": "tok-admin-dual",
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
        assert resp.headers.get("location") == "/admin/login"

        # WA-10 invariant must still hold: both distinct tokens revoked.
        invalidated = {call.args[0] for call in store.invalidate.call_args_list}
        assert "tok-user-dual" in invalidated
        assert "tok-admin-dual" in invalidated

    @pytest.mark.asyncio
    async def test_expired_admin_session_still_redirects_to_admin_login(self):
        """
        Admin cookie present but store.get() returns None (session already
        expired/gone) — the tier signal must come from cookie presence, not
        session lookup, since the lookup can legitimately fail here.
        """
        import yashigani.backoffice.routes.auth as _auth_mod

        store = MagicMock()
        store.get.return_value = None
        store.invalidate = MagicMock()

        request = _make_request({"__Host-yashigani_admin_session": "tok-admin-expired"})
        mock_state = MagicMock()
        mock_state.audit_writer = None

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.logout_redirect(
                request=request,
                response=MagicMock(),
                store=store,
            )

        assert isinstance(resp, RedirectResponse)
        assert resp.headers.get("location") == "/admin/login"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
