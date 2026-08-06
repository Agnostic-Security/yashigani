"""
Regression test -- v4.1.2 FIND-P-CSRF (MEDIUM, Bypass, batch-fix 2026-08-04).

Laura's admin-surface pentest proved `POST /admin/rbac/groups` succeeded
with a foreign Origin header and NO CSRF token — the server performed ZERO
Origin/Referer validation, relying solely on the admin session cookie's
`SameSite=strict` attribute. Reproduced identically across podman AND
docker legs (2/3 runtimes at the time of the finding).

Fix: `src/yashigani/backoffice/app.py` — new `csrf_origin_referer_check`
middleware, added to `create_backoffice_app()`. Rejects any state-changing
(POST/PUT/PATCH/DELETE) request under `/admin/*` or `/auth/*` that (a)
carries an admin/user session cookie AND (b) declares an Origin (or,
absent that, a Referer) that does not reflect this server's own
Host/X-Forwarded-Host + scheme/X-Forwarded-Proto. Requests with NEITHER
header present are left to SameSite (matches OWASP CSRF cheatsheet
guidance — this is what Django's CsrfViewMiddleware does too).

These tests exercise the REAL FastAPI app + middleware stack (not a mock),
via TestClient, mirroring the existing `test_openapi_exposure.py` pattern
for backoffice middleware tests (Caddy-secret bypass + direct session
cookie injection — the CSRF check only inspects cookie NAMES, not session
validity, so no session-store mock is required).
"""
from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

_TEST_CADDY_SECRET = "test-caddy-secret-csrf-unit"
_PROBE_BODY = {"name": "csrf-probe-group", "description": "", "members": []}


@contextmanager
def _caddy_bypass():
    """Patch caddy_verified._caddy_secret so CaddyVerifiedMiddleware accepts
    our test requests (mirrors test_openapi_exposure.py's helper)."""
    import yashigani.auth.caddy_verified as _cv

    original = _cv._caddy_secret
    _cv._caddy_secret = _TEST_CADDY_SECRET
    try:
        yield _TEST_CADDY_SECRET
    finally:
        _cv._caddy_secret = original


def _make_client():
    from yashigani.backoffice.app import create_backoffice_app

    app = create_backoffice_app()
    return app, TestClient(app, raise_server_exceptions=False)


def _csrf_error(response) -> str | None:
    ctype = response.headers.get("content-type", "")
    if not ctype.startswith("application/json"):
        return None
    try:
        return response.json().get("error")
    except Exception:
        return None


class TestFindPCsrfOriginRefererValidation:
    def test_foreign_origin_state_changing_admin_request_rejected(self):
        """FIND-P-CSRF: the exact bypass Laura proved — foreign Origin +
        admin session cookie + no CSRF token on POST /admin/rbac/groups —
        must now be rejected 403 csrf_origin_mismatch."""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            client.cookies.set("__Host-yashigani_admin_session", "some-token")
            response = client.post(
                "/admin/rbac/groups",
                json=_PROBE_BODY,
                headers={
                    "X-Caddy-Verified-Secret": secret,
                    "Origin": "https://evil.example",
                },
            )
            assert response.status_code == 403
            assert _csrf_error(response) == "csrf_origin_mismatch"

    def test_foreign_referer_state_changing_admin_request_rejected(self):
        """Same bypass shape via Referer (no Origin header at all — some
        older/simple cross-site form submissions only send Referer)."""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            client.cookies.set("__Host-yashigani_admin_session", "some-token")
            response = client.post(
                "/admin/rbac/groups",
                json=_PROBE_BODY,
                headers={
                    "X-Caddy-Verified-Secret": secret,
                    "Referer": "https://evil.example/attack.html",
                },
            )
            assert response.status_code == 403
            assert _csrf_error(response) == "csrf_origin_mismatch"

    def test_same_origin_request_not_blocked_by_csrf_check(self):
        """An Origin that reflects the server's own host must NOT be
        rejected by the CSRF layer. (Downstream auth may still 401 for other
        reasons since no session-store mock is wired here — only the CSRF
        middleware's own decision is under test.)"""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            client.cookies.set("__Host-yashigani_admin_session", "some-token")
            response = client.post(
                "/admin/rbac/groups",
                json=_PROBE_BODY,
                headers={
                    "X-Caddy-Verified-Secret": secret,
                    "Origin": "http://testserver",
                },
            )
            assert _csrf_error(response) != "csrf_origin_mismatch"

    def test_no_session_cookie_request_not_csrf_checked(self):
        """No admin/user session cookie present at all — the CSRF check is
        scoped to cookie-authenticated requests (Bearer/API-key auth is not
        CSRF-exploitable); a foreign Origin here must not be rejected BY THE
        CSRF LAYER specifically."""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            response = client.post(
                "/admin/rbac/groups",
                json=_PROBE_BODY,
                headers={
                    "X-Caddy-Verified-Secret": secret,
                    "Origin": "https://evil.example",
                },
            )
            assert _csrf_error(response) != "csrf_origin_mismatch"

    def test_missing_origin_and_referer_not_blocked(self):
        """Neither Origin nor Referer present — per OWASP CSRF cheatsheet
        guidance this is NOT auto-rejected here (SameSite=strict remains the
        primary control for that case; this also avoids breaking cookie-
        based internal tooling/test harnesses that never set either
        header)."""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            client.cookies.set("__Host-yashigani_admin_session", "some-token")
            response = client.post(
                "/admin/rbac/groups",
                json=_PROBE_BODY,
                headers={"X-Caddy-Verified-Secret": secret},
            )
            assert _csrf_error(response) != "csrf_origin_mismatch"

    def test_get_request_not_csrf_checked(self):
        """GET is not state-changing — never blocked by the CSRF check
        regardless of Origin."""
        with _caddy_bypass() as secret:
            _app, client = _make_client()
            client.cookies.set("__Host-yashigani_admin_session", "some-token")
            response = client.get(
                "/admin/rbac/groups",
                headers={
                    "X-Caddy-Verified-Secret": secret,
                    "Origin": "https://evil.example",
                },
            )
            assert _csrf_error(response) != "csrf_origin_mismatch"

