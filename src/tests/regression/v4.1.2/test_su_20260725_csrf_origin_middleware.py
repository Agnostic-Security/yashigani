"""
Regression test -- TD-2026-07-25-04 (Ava): CSRF Origin/Referer not
server-validated on cookie-authenticated admin routes.

Finding: admin-mutating POSTs (e.g. POST /admin/rbac/groups) accepted a
forged `Origin: https://evil.example` header and returned 201.
`SameSite=Strict` on both session cookies (__Host-yashigani_admin_session,
__Host-yashigani_session -- see auth/session.py) is the PRIMARY, already-
effective mitigation (a browser that honours SameSite never attaches the
cookie to a cross-site-initiated request, so there is no valid session to
even reach this check in a genuine cross-site attack) -- Ava rated this
LOW / defense-in-depth, not exploitable. This test proves the added
server-side belt-and-braces check in
yashigani.backoffice.middleware._enforce_csrf_origin() / require_admin_session:

  - A state-changing request (POST/PUT/PATCH/DELETE) carrying a PRESENT and
    MISMATCHED Origin header is rejected 403 csrf_origin_mismatch -- fail
    CLOSED, no downgrade path.
  - A state-changing request with NO Origin header is left alone (same-
    origin form posts, and every non-cookie API-key/bearer caller, which
    never sends a session cookie and has no CSRF surface to begin with).
  - A state-changing request with a Origin header matching the configured
    deployment host (YASHIGANI_TLS_DOMAIN, or "localhost" default) passes.
  - GET/HEAD (read-only, no mutating effect) are never rejected regardless
    of Origin -- this check is scoped to state-changing methods only.

Last updated: 2026-07-25T00:00:00+01:00
"""
from __future__ import annotations

import os

import pytest
from starlette.requests import Request

os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")


def _fake_request(method: str, headers: dict[str, str]) -> Request:
    """Build a bare Starlette Request carrying only method + headers --
    enough for _enforce_csrf_origin(), which only reads request.method and
    request.headers.  Mirrors the _fake_request() helper in
    test_tom_webauthn_origin_mismatch_fix.py."""
    encoded = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": method,
        "path": "/admin/rbac/groups",
        "headers": encoded,
        "scheme": "https",
        "server": ("backoffice", 8443),
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
    }
    return Request(scope)


def _import():
    from yashigani.backoffice.middleware import (
        _enforce_csrf_origin,
        _origin_is_same_site,
        _configured_public_hosts,
    )
    return _enforce_csrf_origin, _origin_is_same_site, _configured_public_hosts


class TestEnforceCsrfOrigin:
    def test_forged_cross_site_origin_on_post_is_rejected(self, monkeypatch):
        """The exact Ava finding: POST with a forged evil.example Origin
        must now raise 403 csrf_origin_mismatch instead of proceeding."""
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "https://evil.example"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            enforce(req)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == {"error": "csrf_origin_mismatch"}

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_forged_origin_rejected_on_every_unsafe_method(self, monkeypatch, method):
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request(method, {"origin": "https://evil.example"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            enforce(req)

    @pytest.mark.parametrize("method", ["GET", "HEAD"])
    def test_forged_origin_ignored_on_safe_methods(self, monkeypatch, method):
        """CSRF-relevant methods only -- a cross-site GET has no mutating
        effect, so this check must not touch it."""
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request(method, {"origin": "https://evil.example"})
        enforce(req)  # must not raise

    def test_missing_origin_on_post_is_not_rejected(self, monkeypatch):
        """No Origin header (same-origin nav, many legitimate same-origin
        form posts, and every API-key/bearer caller with no cookie) must
        not be rejected by this check -- it is left to the existing
        session-cookie auth checks."""
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request("POST", {})
        enforce(req)  # must not raise

    def test_matching_configured_domain_origin_is_allowed(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "https://yashigani.example.com"})
        enforce(req)  # must not raise

    def test_matching_configured_domain_origin_nonstandard_port_is_allowed(self, monkeypatch):
        """Hostname-only comparison: a non-default port on OUR own domain
        (e.g. the self-signed dev default :8443) must still be accepted --
        the Origin header is only ever attacker-controlled by navigating to
        a different SITE, never by picking a different port on our site."""
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "https://localhost:8443"})
        enforce(req)  # must not raise

    def test_default_localhost_origin_allowed_when_no_domain_configured(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "https://localhost"})
        enforce(req)  # must not raise

    def test_subdomain_of_configured_domain_is_still_rejected(self, monkeypatch):
        """Hostname equality, not suffix matching -- evil.yashigani.example.com
        must not be treated as same-site just because it shares a suffix."""
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "https://evil.yashigani.example.com"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            enforce(req)

    def test_malformed_origin_header_is_rejected_not_crashed(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)
        enforce, _, _ = _import()
        req = _fake_request("POST", {"origin": "not-a-valid-origin"})
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            enforce(req)


class TestRequireAdminSessionWiresCsrfCheck:
    """Confirms the CSRF check actually runs INSIDE require_admin_session
    (the dependency every AdminSession/StepUpAdminSession-typed admin route
    uses -- rbac.py, scim.py, agents.py, etc.), not just as a standalone
    unused helper."""

    def test_require_admin_session_source_calls_enforce_csrf_origin(self):
        import inspect
        from yashigani.backoffice import middleware

        source = inspect.getsource(middleware.require_admin_session)
        assert "_enforce_csrf_origin(request)" in source, (
            "require_admin_session must call _enforce_csrf_origin(request) -- "
            "TD-2026-07-25-04 fix must be wired into the actual admin-session "
            "dependency, not left as dead code."
        )
