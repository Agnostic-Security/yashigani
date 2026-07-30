"""
Regression test -- v4.1.2 YSG-RISK-176 (LOW): GET /admin/ shell served to
any authenticated session regardless of account tier.

Root cause (backoffice/app.py, ui4_admin_page): the /admin/ route's cookie
pre-flight only checked that a session cookie was PRESENT ("__Host-
yashigani_admin_session" or "__Host-yashigani_session") -- it never resolved
the session and checked account_tier. A perfectly valid USER-tier session
(logged in at /chat, not /admin/login) therefore received the SAME 200 Lit
admin shell as a real admin. Every underlying /admin/* API call still
correctly 403'd for a non-admin caller (per-action authz was never
bypassed) -- this was shell/asset-surface enumeration only, not a privilege
escalation, hence LOW rather than HIGH/CRITICAL.

Fix: resolve the session (mirrors middleware.require_admin_session's own
account_tier == "admin" check exactly, including the
admin_password_change_required tier, which is also != "admin" and
therefore also correctly denied) BEFORE serving the shell. No session at
all still gets the pre-existing friendly redirect to /admin/login; a
present-but-non-admin session now gets 403 insufficient_tier instead of the
200 shell.

Pattern follows src/tests/unit/test_openapi_exposure.py's established
backoffice TestClient + CaddyVerifiedMiddleware-bypass + session-store-mock
harness exactly (same helpers duplicated locally to keep this regression
test self-contained per src/tests/regression/ convention).
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient


_TEST_CADDY_SECRET = "test-caddy-secret-unit-test-only"


@contextmanager
def _caddy_bypass():
    import yashigani.auth.caddy_verified as _cv
    original = _cv._caddy_secret
    _cv._caddy_secret = _TEST_CADDY_SECRET
    try:
        yield _TEST_CADDY_SECRET
    finally:
        _cv._caddy_secret = original


def _make_backoffice_client(session_cookie: str | None = None):
    from yashigani.backoffice.app import create_backoffice_app
    app = create_backoffice_app()
    client = TestClient(app, raise_server_exceptions=False)
    if session_cookie:
        client.cookies.set("__Host-yashigani_admin_session", session_cookie)
    return app, client


def _inject_session_store(token: str, tier: str | None):
    """Monkeypatch backoffice_state.session_store. tier=None simulates
    store.get() returning None (expired/invalid/unknown token)."""
    from yashigani.auth.session import Session

    mock_store = MagicMock()
    if tier is None:
        mock_store.get.return_value = None
    else:
        mock_session = MagicMock(spec=Session)
        mock_session.account_tier = tier
        mock_store.get.return_value = mock_session

    from yashigani.backoffice import state as _state_mod
    original = getattr(_state_mod, "backoffice_state", None)
    mock_state = MagicMock()
    mock_state.session_store = mock_store
    _state_mod.backoffice_state = mock_state
    return mock_state, original


class TestAdminShellTierCheck:
    def test_no_session_redirects_to_login(self):
        """Pre-existing behaviour, unchanged: no cookie at all -> friendly
        302 redirect to /admin/login (not a bare 401/403)."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client()
            response = client.get(
                "/admin/",
                headers={"X-Caddy-Verified-Secret": secret},
                follow_redirects=False,
            )
            assert response.status_code == 302
            assert "/admin/login" in response.headers.get("location", "")

    def test_user_tier_session_is_forbidden_not_200(self):
        """YSG-RISK-176: a valid, non-expired USER-tier session must NOT
        receive the 200 admin shell."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="user-token")
            mock_state, original = _inject_session_store("user-token", tier="user")
            try:
                response = client.get(
                    "/admin/",
                    headers={"X-Caddy-Verified-Secret": secret},
                    follow_redirects=False,
                )
                assert response.status_code in (401, 403), (
                    f"YSG-RISK-176 regression: user-tier session received "
                    f"{response.status_code} (expected 401/403) at GET /admin/ "
                    f"-- the admin shell must not 200 for a non-admin caller."
                )
                assert response.status_code != 200
            finally:
                from yashigani.backoffice import state as _state_mod
                _state_mod.backoffice_state = original

    def test_admin_password_change_required_tier_is_forbidden(self):
        """The force-password-change admin tier (not yet a full admin
        session) must also be denied the shell -- mirrors
        require_admin_session's own explicit denial of this tier."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="pwchange-token")
            mock_state, original = _inject_session_store(
                "pwchange-token", tier="admin_password_change_required"
            )
            try:
                response = client.get(
                    "/admin/",
                    headers={"X-Caddy-Verified-Secret": secret},
                    follow_redirects=False,
                )
                assert response.status_code != 200
                assert response.status_code in (401, 403)
            finally:
                from yashigani.backoffice import state as _state_mod
                _state_mod.backoffice_state = original

    def test_expired_or_invalid_session_is_forbidden(self):
        """A session cookie is present but the store no longer recognises
        the token (expired/invalidated) -- must not 200, and must be
        treated the SAME as "not logged in" (friendly redirect to login,
        NOT a bare 403 -- Iris integration audit LOW #4: require_admin_session
        itself raises 401/"please re-authenticate" for this exact case, never
        403, so the /admin/ shell preflight must mirror that, not diverge
        into a confusing 403 for someone who simply needs to log back in)."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="stale-token")
            mock_state, original = _inject_session_store("stale-token", tier=None)
            try:
                response = client.get(
                    "/admin/",
                    headers={"X-Caddy-Verified-Secret": secret},
                    follow_redirects=False,
                )
                assert response.status_code == 302, (
                    f"YSG-RISK-177 LOW#4 regression: expired/invalid session "
                    f"got {response.status_code} (expected 302 redirect to "
                    f"login, mirroring require_admin_session's no-session "
                    f"handling — 403 is reserved for a VALID non-admin "
                    f"session)."
                )
                assert "/admin/login" in response.headers.get("location", "")
            finally:
                from yashigani.backoffice import state as _state_mod
                _state_mod.backoffice_state = original

    def test_admin_password_change_required_tier_gets_actionable_message(self):
        """The admin_password_change_required tier must get the SAME
        actionable error body require_admin_session returns for it (not the
        generic insufficient_tier message) -- Iris LOW #4."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="pwchange-token")
            mock_state, original = _inject_session_store(
                "pwchange-token", tier="admin_password_change_required"
            )
            try:
                response = client.get(
                    "/admin/",
                    headers={"X-Caddy-Verified-Secret": secret},
                    follow_redirects=False,
                )
                assert response.status_code == 403
                body = response.json()
                assert body.get("error") == "admin_password_change_required"
                assert "password" in body.get("message", "").lower()
            finally:
                from yashigani.backoffice import state as _state_mod
                _state_mod.backoffice_state = original

    def test_admin_tier_session_still_gets_200(self):
        """Sanity: the fix must not regress the legitimate admin path."""
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="admin-token")
            mock_state, original = _inject_session_store("admin-token", tier="admin")
            try:
                response = client.get(
                    "/admin/",
                    headers={"X-Caddy-Verified-Secret": secret},
                    follow_redirects=False,
                )
                assert response.status_code == 200, (
                    f"Admin-tier session must still receive the 200 shell, "
                    f"got {response.status_code}: {response.text[:200]}"
                )
                assert "text/html" in response.headers.get("content-type", "")
            finally:
                from yashigani.backoffice import state as _state_mod
                _state_mod.backoffice_state = original
