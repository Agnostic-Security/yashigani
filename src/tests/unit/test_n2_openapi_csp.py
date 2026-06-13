"""
Regression tests for N2 — OpenAPI docs pages must render under strict CSP.

Verifies:
- swagger_ui_html() emits no inline <script> tag
- swagger_ui_html() references swagger-ui-init.js (externalised init)
- swagger_ui_html() passes the openapi_url via data attribute (no inline JS value)
- redoc_html() emits no inline <script> or <style> tags with content
- redoc_html() uses <redoc spec-url="..."> web component (no SwaggerUIBundle call)
- redoc_html() response header includes worker-src blob: child-src blob:
- redoc_html() response header includes style-src 'unsafe-inline'
- Backoffice /admin/api-docs: authenticated response has no inline init script
- Backoffice /admin/api-redoc: authenticated response header has worker-src blob:

These tests would fail on the pre-fix code where get_swagger_ui_html() emitted
an inline <script>const ui = SwaggerUIBundle({...})</script> and get_redoc_html()
emitted inline <style>body { margin: 0; }</style>.

Last updated: 2026-06-13T00:00:00+00:00 (N2 fix, 2.25.5)
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest


# ── api_docs module unit tests ─────────────────────────────────────────────

class TestSwaggerUiHtml:
    """Unit tests for yashigani.api_docs.swagger_ui_html."""

    def test_no_inline_script_block(self):
        """swagger_ui_html() must not emit an inline <script>...</script> block.

        Pre-fix: get_swagger_ui_html() emitted:
            <script>
            const ui = SwaggerUIBundle({...})
            </script>
        That inline block is blocked by script-src 'self' (no 'unsafe-inline').
        """
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        # No inline script content — only src= references are allowed
        inline_scripts = re.findall(r"<script(?![^>]*\bsrc\b)[^>]*>(.+?)</script>", html, re.DOTALL)
        assert not inline_scripts, (
            f"swagger_ui_html() must emit no inline <script> blocks; "
            f"found: {inline_scripts!r}"
        )

    def test_references_swagger_ui_init_js(self):
        """swagger_ui_html() must load the externalised init script."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        assert "swagger-ui-init.js" in html, (
            "swagger_ui_html() must reference swagger-ui-init.js — "
            "the externalised SwaggerUIBundle init (N2 fix)"
        )

    def test_openapi_url_via_data_attribute(self):
        """openapi_url must be injected via data-openapi-url, not inline JS."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/my-spec.json",
            title="Test",
        )
        assert 'data-openapi-url="/my-spec.json"' in html, (
            "openapi_url must be set as a data attribute on #swagger-ui, "
            "not in an inline script"
        )

    def test_no_cdn_urls(self):
        """swagger_ui_html() must not reference any CDN URLs."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        assert "cdn.jsdelivr.net" not in html
        assert "fastapi.tiangolo.com" not in html
        assert "fonts.googleapis.com" not in html

    def test_references_self_hosted_css(self):
        """swagger_ui_html() must load swagger-ui.css from /static/swagger-ui/."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        assert "/static/swagger-ui/swagger-ui.css" in html

    def test_no_inline_style_block(self):
        """swagger_ui_html() must not emit an inline <style> block."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        assert "<style" not in html, (
            "swagger_ui_html() must not emit any inline <style> block"
        )

    def test_title_is_escaped(self):
        """Title with HTML special chars must be escaped."""
        from yashigani.api_docs import swagger_ui_html
        html = swagger_ui_html(
            openapi_url="/test/openapi.json",
            title="Test <script>alert(1)</script>",
        )
        assert "<script>alert(1)</script>" not in html


class TestRedocHtml:
    """Unit tests for yashigani.api_docs.redoc_html."""

    def test_no_inline_script_block(self):
        """redoc_html() must not emit an inline <script>...</script> block.

        Pre-fix: get_redoc_html() is actually clean of inline scripts by
        default (the redoc web component handles init), but we verify this
        continues to hold.
        """
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        html = resp.body.decode()
        inline_scripts = re.findall(r"<script(?![^>]*\bsrc\b)[^>]*>(.+?)</script>", html, re.DOTALL)
        assert not inline_scripts, (
            f"redoc_html() must emit no inline <script> blocks; "
            f"found: {inline_scripts!r}"
        )

    def test_no_standalone_inline_style(self):
        """redoc_html() must not emit an inline <style> block in the document head/body.

        Pre-fix: get_redoc_html() emitted:
            <style>
            body { margin: 0; padding: 0; }
            </style>
        That inline block is blocked by style-src 'self' (no 'unsafe-inline')
        and caused a CSP violation on the page itself.
        """
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        html = resp.body.decode()
        assert "<style" not in html, (
            "redoc_html() must not emit any inline <style> block in the HTML "
            "(Redoc's Shadow DOM styles are exempted; we check the document-level <style>)"
        )

    def test_uses_redoc_web_component(self):
        """redoc_html() must use <redoc spec-url="..."> web component."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/my-spec.json",
            title="Test",
        )
        html = resp.body.decode()
        assert 'spec-url="/my-spec.json"' in html, (
            "redoc_html() must use <redoc spec-url='...'> web component "
            "to pass the openapi_url without inline JavaScript"
        )

    def test_response_header_worker_src_blob(self):
        """redoc_html() response must carry worker-src blob: in CSP.

        Redoc spawns a Web Worker via blob: URL.  Without worker-src blob:
        the worker is blocked and Redoc renders 'Something went wrong...'.
        """
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        csp = resp.headers.get("content-security-policy", "")
        assert "worker-src blob:" in csp, (
            f"redoc_html() CSP response header must include 'worker-src blob:'; "
            f"got: {csp!r}"
        )

    def test_response_header_child_src_blob(self):
        """redoc_html() response must carry child-src blob: in CSP (older browser compat)."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        csp = resp.headers.get("content-security-policy", "")
        assert "child-src blob:" in csp, (
            f"redoc_html() CSP header must include 'child-src blob:'; got: {csp!r}"
        )

    def test_response_header_style_unsafe_inline(self):
        """redoc_html() response must carry style-src 'unsafe-inline' in CSP.

        Redoc injects inline styles via its Shadow DOM web component at render time.
        Without 'unsafe-inline' on style-src, Redoc's styling is blocked and the
        spec renders unstyled or broken.
        """
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        csp = resp.headers.get("content-security-policy", "")
        assert "'unsafe-inline'" in csp and "style-src" in csp, (
            f"redoc_html() CSP header must include style-src 'unsafe-inline'; "
            f"got: {csp!r}"
        )

    def test_response_header_no_unsafe_eval(self):
        """redoc_html() response must NOT add 'unsafe-eval'."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        csp = resp.headers.get("content-security-policy", "")
        assert "'unsafe-eval'" not in csp, (
            "redoc_html() CSP must not include 'unsafe-eval' — "
            "Redoc standalone does not require eval"
        )

    def test_response_header_no_unsafe_inline_script(self):
        """redoc_html() response CSP must not globally allow script 'unsafe-inline'."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        csp = resp.headers.get("content-security-policy", "")
        # script-src must stay 'self' only
        assert "script-src 'self'" in csp, (
            f"script-src must remain 'self' in redoc CSP; got: {csp!r}"
        )
        # Ensure 'unsafe-inline' does not appear next to script-src
        # (it may appear in style-src — that's expected)
        script_src_match = re.search(r"script-src([^;]+)", csp)
        if script_src_match:
            script_src_val = script_src_match.group(1)
            assert "'unsafe-inline'" not in script_src_val, (
                f"script-src must not include 'unsafe-inline'; "
                f"script-src value: {script_src_val!r}"
            )

    def test_no_cdn_urls(self):
        """redoc_html() must not reference any CDN URLs."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test",
        )
        html = resp.body.decode()
        assert "cdn.jsdelivr.net" not in html
        assert "fastapi.tiangolo.com" not in html
        assert "fonts.googleapis.com" not in html

    def test_title_is_escaped(self):
        """Title with HTML special chars must be escaped (< > become &lt; &gt;)."""
        from yashigani.api_docs import redoc_html
        resp = redoc_html(
            openapi_url="/test/openapi.json",
            title="Test <img src=x onerror=alert(1)>",
        )
        html = resp.body.decode()
        # The raw unescaped tag must not appear (< must be &lt;)
        assert "<img" not in html, (
            "Title must be HTML-escaped; raw <img tag must not appear"
        )


# ── Backoffice integration: CSP-clean HTML responses ──────────────────────

_TEST_CADDY_SECRET = "test-caddy-secret-n2-csp-unit"


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
    from fastapi.testclient import TestClient
    app = create_backoffice_app()
    client = TestClient(app, raise_server_exceptions=False)
    if session_cookie:
        client.cookies.set("__Host-yashigani_admin_session", session_cookie)
    return app, client


def _inject_session_store(app, token: str, tier: str = "admin"):
    from yashigani.auth.session import Session
    from yashigani.backoffice import state as _state_mod
    mock_store = MagicMock()
    mock_session = MagicMock(spec=Session)
    mock_session.account_tier = tier
    mock_store.get.return_value = mock_session
    original = getattr(_state_mod, "backoffice_state", None)
    mock_state = MagicMock()
    mock_state.session_store = mock_store
    _state_mod.backoffice_state = mock_state
    return mock_state, original


class TestBackofficeSwaggerCspClean:
    """Backoffice /admin/api-docs returns CSP-clean HTML (N2 regression)."""

    def test_no_inline_script_in_api_docs_response(self):
        """Authenticated /admin/api-docs response must contain no inline <script> block."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-docs",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200
                html = response.text
                inline_scripts = re.findall(
                    r"<script(?![^>]*\bsrc\b)[^>]*>(.+?)</script>",
                    html,
                    re.DOTALL,
                )
                assert not inline_scripts, (
                    f"N2 regression: /admin/api-docs must emit no inline <script> blocks "
                    f"(blocked by script-src 'self'); found: {inline_scripts!r}"
                )
            finally:
                _state_mod.backoffice_state = original

    def test_api_docs_references_init_js(self):
        """Authenticated /admin/api-docs HTML must reference swagger-ui-init.js."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-docs",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200
                assert "swagger-ui-init.js" in response.text, (
                    "N2 fix: /admin/api-docs must load swagger-ui-init.js "
                    "(externalised init replaces inline block)"
                )
            finally:
                _state_mod.backoffice_state = original


class TestBackofficeRedocCspClean:
    """Backoffice /admin/api-redoc returns CSP-clean HTML + correct CSP header (N2 regression)."""

    def test_no_inline_script_in_api_redoc_response(self):
        """Authenticated /admin/api-redoc response must contain no inline <script> block."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-redoc",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200
                html = response.text
                inline_scripts = re.findall(
                    r"<script(?![^>]*\bsrc\b)[^>]*>(.+?)</script>",
                    html,
                    re.DOTALL,
                )
                assert not inline_scripts, (
                    f"N2 regression: /admin/api-redoc must emit no inline <script> blocks; "
                    f"found: {inline_scripts!r}"
                )
            finally:
                _state_mod.backoffice_state = original

    def test_api_redoc_response_has_worker_src_blob(self):
        """Authenticated /admin/api-redoc response header must include worker-src blob:."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-redoc",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200
                csp = response.headers.get("content-security-policy", "")
                assert "worker-src blob:" in csp, (
                    f"N2 fix: /admin/api-redoc response CSP must include 'worker-src blob:' "
                    f"for Redoc's Web Worker; got: {csp!r}"
                )
            finally:
                _state_mod.backoffice_state = original

    def test_api_redoc_uses_web_component(self):
        """Authenticated /admin/api-redoc HTML must use <redoc spec-url='...'> web component."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-redoc",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200
                assert "spec-url=" in response.text, (
                    "N2 fix: /admin/api-redoc must use <redoc spec-url='...'> "
                    "web component (no inline init script)"
                )
            finally:
                _state_mod.backoffice_state = original
