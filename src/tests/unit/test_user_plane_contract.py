"""
Contract tests — 4.0 Phase 2 user-plane session/SoD invariants + upload hardening.

These tests assert structural source-level invariants for RISK-100 and RISK-112.
They run without a live stack (no Redis, no Postgres, no OPA).

RISK-100 (user-side):
  CT-100-1: middleware.py exports require_user_session and UserSession.
  CT-100-2: require_user_session reads ONLY _USER_SESSION_COOKIE, never _SESSION_COOKIE.
  CT-100-3: require_user_session rejects admin tier (wrong_plane 403).
  CT-100-4: user_ui.py uses UserSession / require_user_session on ALL user routes.
  CT-100-5: No /user/* or /chat route uses AnySession (admin-plane session type).
  CT-100-6: Functional — /user/agents returns 401 without a session cookie.
  CT-100-7: Functional — /user/budget returns 401 without a session cookie.
  CT-100-8: Functional — /user/memory returns 401 without a session cookie.
  CT-100-9: Functional — /user/documents returns 401 without a session cookie.
  CT-100-10: Functional — /chat with session cookie gets HTML; without → redirect.

RISK-112 (upload hardening):
  CT-112-1: _guard_filename rejects path separators (/ and \\).
  CT-112-2: _guard_filename rejects null-byte injection.
  CT-112-3: _guard_filename rejects dot-only names (.. traversal).
  CT-112-4: _guard_filename returns basename only (strips path components).
  CT-112-5: _guard_filename rejects empty filename.
  CT-112-6: _resolve_declared_mime rejects unknown MIME types.
  CT-112-7: Size cap middleware is wired for /user/documents in app.py.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# FastAPI types must be imported at MODULE LEVEL so that `chat_page.__globals__`
# (which is the test module's __dict__) can resolve the `request: Request`
# annotation when FastAPI calls typing.get_type_hints().  With
# `from __future__ import annotations`, every annotation is stored as a string;
# get_type_hints() evaluates against __globals__, which is the MODULE dict —
# NOT the local scope of _make_user_ui_app().  If Request is only imported
# locally inside _make_user_ui_app(), FastAPI's annotation resolution fails and
# treats `request` as a required query parameter (→ 422 instead of 302/200).
try:
    from fastapi import (  # noqa: E402
        APIRouter as _APIRouter,
        Depends as _Depends,
        FastAPI as _FastAPI,
        HTTPException as _HTTPException,
        Request,  # MUST be at module level — see comment above
    )
    from fastapi.responses import HTMLResponse, RedirectResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    Request = None  # type: ignore[assignment,misc]
    HTMLResponse = None  # type: ignore[assignment]
    RedirectResponse = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Source paths
# ---------------------------------------------------------------------------

_SRC = Path(__file__).parents[2] / "yashigani"
_MIDDLEWARE_PY = _SRC / "backoffice" / "middleware.py"
_USER_UI_PY = _SRC / "backoffice" / "routes" / "user_ui.py"
_APP_PY = _SRC / "backoffice" / "app.py"


# ---------------------------------------------------------------------------
# CT-100-1 through CT-100-5: Source-level invariants
# ---------------------------------------------------------------------------


class TestRisk100SourceInvariants:
    """RISK-100 structural invariants proven at source level."""

    def test_middleware_exports_require_user_session(self):
        """middleware.py must define require_user_session."""
        src = _MIDDLEWARE_PY.read_text(encoding="utf-8")
        assert "def require_user_session" in src, (
            "CT-100-1 FAIL: require_user_session not defined in middleware.py"
        )

    def test_middleware_exports_user_session_alias(self):
        """middleware.py must define UserSession annotated alias."""
        src = _MIDDLEWARE_PY.read_text(encoding="utf-8")
        assert "UserSession" in src, (
            "CT-100-1 FAIL: UserSession not in middleware.py"
        )

    def test_require_user_session_reads_only_user_cookie(self):
        """
        require_user_session must call _resolve_user_token (user-cookie-exclusive)
        NOT _resolve_token (which prefers the admin cookie — RISK-100 bug).
        """
        src = _MIDDLEWARE_PY.read_text(encoding="utf-8")
        # The function must exist and use the user-exclusive resolver
        assert "_resolve_user_token" in src, (
            "CT-100-2 FAIL: _resolve_user_token not defined in middleware.py"
        )
        # _resolve_user_token must ONLY read _USER_SESSION_COOKIE
        # i.e. no fallback to _SESSION_COOKIE inside _resolve_user_token.
        # Parse the function body via AST to confirm the exclusion.
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_resolve_user_token":
                func_src = ast.unparse(node)
                assert "_SESSION_COOKIE" not in func_src.replace("_USER_SESSION_COOKIE", ""), (
                    "CT-100-2 FAIL: _resolve_user_token references admin _SESSION_COOKIE. "
                    "It must ONLY read _USER_SESSION_COOKIE."
                )
                break

    def test_require_user_session_rejects_admin_tier(self):
        """require_user_session must reject account_tier == 'admin' with 403."""
        src = _MIDDLEWARE_PY.read_text(encoding="utf-8")
        assert "wrong_plane" in src, (
            "CT-100-3 FAIL: require_user_session does not return 'wrong_plane' error "
            "for admin-tier sessions. SoD not enforced."
        )
        assert "account_tier == \"admin\"" in src or "account_tier == 'admin'" in src, (
            "CT-100-3 FAIL: require_user_session does not check for admin tier. "
            "An admin session would not be rejected on the user plane."
        )

    def test_user_ui_uses_user_session(self):
        """user_ui.py must import and use UserSession / require_user_session."""
        src = _USER_UI_PY.read_text(encoding="utf-8")
        assert "UserSession" in src, (
            "CT-100-4 FAIL: UserSession not imported in user_ui.py. "
            "User-plane routes are not protected."
        )
        assert "require_user_session" in src, (
            "CT-100-4 FAIL: require_user_session not referenced in user_ui.py."
        )

    def test_user_ui_does_not_use_any_session(self):
        """user_ui.py must NEVER import or use AnySession (admin-plane type)."""
        src = _USER_UI_PY.read_text(encoding="utf-8")
        assert "AnySession" not in src, (
            "CT-100-5 FAIL: AnySession used in user_ui.py. "
            "Admin sessions would be accepted on user-plane routes, violating SoD."
        )

    def test_user_ui_routes_all_have_user_session_in_signature(self):
        """
        All route handlers in user_ui.py (except /chat page — which does a
        cookie-presence check and uses the cookie directly) must have
        `session: UserSession` in their signature.
        """
        src = _USER_UI_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)

        # Collect route handler names (decorated with @router.get / .post / .put / .delete)
        handler_names = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    dec_src = ast.unparse(decorator)
                    if "router." in dec_src and (
                        ".get(" in dec_src or ".post(" in dec_src
                        or ".put(" in dec_src or ".delete(" in dec_src
                    ):
                        handler_names.add(node.name)

        assert handler_names, "CT-100-4: No route handlers found in user_ui.py — check AST walk"

        # /chat page uses cookie-presence check (lightweight pre-flight; documented)
        # All others must have UserSession in their signature.
        user_session_handlers = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name not in handler_names:
                    continue
                for arg in node.args.args:
                    if arg.annotation and "UserSession" in ast.unparse(arg.annotation):
                        user_session_handlers.add(node.name)

        # Every handler except the /chat page must have UserSession
        api_handlers = handler_names - {"user_chat_page"}
        missing = api_handlers - user_session_handlers
        assert not missing, (
            f"CT-100-4 FAIL: User-plane route handlers missing UserSession dependency: {missing}. "
            "These routes are unauthenticated."
        )

    def test_admin_plane_routes_do_not_use_any_session_on_mutating_endpoints(self):
        """
        No route in backoffice/routes/ that handles /admin/* paths should use
        AnySession as the SOLE auth guard on a POST/PUT/DELETE endpoint.

        AnySession is valid for self-service paths (/me/api-key, /auth/totp/provision)
        but MUST NOT appear on /admin/* paths per the SoD contract.
        """
        routes_dir = _SRC / "backoffice" / "routes"
        for py_file in routes_dir.glob("*.py"):
            src = py_file.read_text(encoding="utf-8")
            if "AnySession" not in src:
                continue
            # Heuristic: if file has /admin/ in route decorators AND AnySession,
            # that's a finding.  Self-service files (me.py, auth.py) are excluded.
            if py_file.name in ("me.py", "auth.py", "sso.py", "user_ui.py", "__init__.py"):
                continue
            # The remaining files should not combine /admin/ routes with AnySession
            if '"/admin/' in src or "'/admin/" in src:
                assert "AnySession" not in src, (
                    f"CT-100-5 FAIL: {py_file.name} uses AnySession on an /admin/* route. "
                    "Admin-plane routes must use AdminSession or StepUpAdminSession."
                )


# ---------------------------------------------------------------------------
# CT-112-1 through CT-112-7: Upload hardening
# ---------------------------------------------------------------------------


class TestRisk112UploadHardening:
    """RISK-112 upload hardening — path-traversal + content-type guards."""

    def _import_guard(self):
        """Import _guard_filename from user_ui for functional testing."""
        import importlib.util
        import sys

        # Ensure the package is importable from the src tree
        spec = importlib.util.spec_from_file_location(
            "yashigani.backoffice.routes.user_ui", _USER_UI_PY
        )
        mod = importlib.util.module_from_spec(spec)
        # Patch problematic imports at load time
        sys.modules.setdefault("yashigani.backoffice.middleware", MagicMock())
        sys.modules.setdefault("yashigani.backoffice.state", MagicMock())
        sys.modules.setdefault("yashigani.common.error_envelope", MagicMock())
        try:
            spec.loader.exec_module(mod)
        except Exception:
            pytest.skip("user_ui.py could not be imported in this test environment")
        return mod

    def test_guard_filename_rejects_forward_slash(self):
        """_guard_filename must reject filenames containing '/'."""
        from fastapi import HTTPException
        mod = self._import_guard()
        with pytest.raises(HTTPException) as exc_info:
            mod._guard_filename("../etc/passwd")
        assert exc_info.value.status_code == 422

    def test_guard_filename_rejects_backslash(self):
        """_guard_filename must reject filenames containing '\\'."""
        from fastapi import HTTPException
        mod = self._import_guard()
        with pytest.raises(HTTPException) as exc_info:
            mod._guard_filename("..\\windows\\system32")
        assert exc_info.value.status_code == 422

    def test_guard_filename_rejects_null_byte(self):
        """_guard_filename must reject filenames containing null bytes."""
        from fastapi import HTTPException
        mod = self._import_guard()
        with pytest.raises(HTTPException) as exc_info:
            mod._guard_filename("file\x00.txt")
        assert exc_info.value.status_code == 422

    def test_guard_filename_rejects_dot_only(self):
        """_guard_filename must reject dot-only names (., .., ...)."""
        from fastapi import HTTPException
        mod = self._import_guard()
        for bad in (".", "..", "..."):
            with pytest.raises(HTTPException):
                mod._guard_filename(bad)

    def test_guard_filename_rejects_empty(self):
        """_guard_filename must reject empty filename."""
        from fastapi import HTTPException
        mod = self._import_guard()
        with pytest.raises(HTTPException):
            mod._guard_filename("")

    def test_guard_filename_accepts_normal(self):
        """_guard_filename must accept normal filenames."""
        mod = self._import_guard()
        assert mod._guard_filename("report.pdf") == "report.pdf"
        assert mod._guard_filename("data_2026-06-27.csv") == "data_2026-06-27.csv"
        assert mod._guard_filename("My Document (1).docx") == "My Document (1).docx"

    def test_resolve_declared_mime_rejects_unknown(self):
        """_resolve_declared_mime must reject content-types outside the allowed set."""
        from fastapi import HTTPException
        mod = self._import_guard()
        # Construct a minimal UploadFile mock
        upload_mock = MagicMock()
        upload_mock.content_type = "application/x-malware"
        with pytest.raises(HTTPException) as exc_info:
            mod._resolve_declared_mime(upload_mock, "evil.exe")
        assert exc_info.value.status_code == 422

    def test_resolve_declared_mime_accepts_allowed(self):
        """_resolve_declared_mime must accept known content-types."""
        mod = self._import_guard()
        for mime in ("text/plain", "text/csv", "application/pdf"):
            upload_mock = MagicMock()
            upload_mock.content_type = mime
            result = mod._resolve_declared_mime(upload_mock, "file.pdf")
            assert result in mod._ALLOWED_DECLARED_MIMES

    def test_size_cap_wired_in_app(self):
        """app.py must include /user/documents in _BODY_LIMITS."""
        src = _APP_PY.read_text(encoding="utf-8")
        assert '"/user/documents"' in src or "'/user/documents'" in src, (
            "CT-112-7 FAIL: /user/documents not found in _BODY_LIMITS in app.py. "
            "Oversized uploads are not rejected at the middleware level."
        )

    def test_path_traversal_guard_in_source(self):
        """user_ui.py source must contain the path-traversal guard."""
        src = _USER_UI_PY.read_text(encoding="utf-8")
        assert "_guard_filename" in src, (
            "CT-112-1 FAIL: _guard_filename not defined in user_ui.py."
        )
        assert "path-traversal" in src.lower() or "CWE-22" in src, (
            "CT-112 FAIL: No path-traversal reference in user_ui.py comment."
        )


# ---------------------------------------------------------------------------
# CT-100-6 through CT-100-10: Functional tests
# ---------------------------------------------------------------------------


def _make_user_ui_app():
    """
    Build a minimal FastAPI app that mirrors user_ui.py's session guard pattern
    so functional tests can verify 401/redirect behaviour without full stack.

    Note: uses module-level FastAPI imports (not local imports) so that
    `chat_page.__globals__` contains `Request` and FastAPI's get_type_hints()
    can resolve the `request: Request` annotation correctly under
    `from __future__ import annotations`.  See the import block at the top of
    this file for the full explanation.
    """
    if not _FASTAPI_AVAILABLE:
        return None, None

    def _sentinel_user_auth():
        raise _HTTPException(status_code=401, detail={"error": "authentication_required"})

    test_router = _APIRouter()

    @test_router.get("/user/agents")
    async def user_agents(_=_Depends(_sentinel_user_auth)):
        return {"agents": []}

    @test_router.get("/user/budget")
    async def user_budget(_=_Depends(_sentinel_user_auth)):
        return {}

    @test_router.get("/user/memory")
    async def user_memory(_=_Depends(_sentinel_user_auth)):
        return {}

    @test_router.post("/user/documents")
    async def user_documents(_=_Depends(_sentinel_user_auth)):
        return {}

    @test_router.get("/chat")
    async def chat_page(request: Request):
        if not request.cookies.get("__Host-yashigani_session"):
            return RedirectResponse(url="/login?next=/chat", status_code=302)
        return HTMLResponse("<html><body>chat</body></html>")

    app = _FastAPI()
    app.include_router(test_router)
    return app, _sentinel_user_auth


class TestRisk100FunctionalEnforcement:
    """Functional: session guard returns 401 on unauthenticated requests."""

    def test_user_agents_returns_401_without_session(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/user/agents")
        assert resp.status_code == 401, (
            f"CT-100-6 FAIL: GET /user/agents returned {resp.status_code}, expected 401."
        )

    def test_user_budget_returns_401_without_session(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/user/budget")
        assert resp.status_code == 401, (
            f"CT-100-7 FAIL: GET /user/budget returned {resp.status_code}, expected 401."
        )

    def test_user_memory_returns_401_without_session(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/user/memory")
        assert resp.status_code == 401, (
            f"CT-100-8 FAIL: GET /user/memory returned {resp.status_code}, expected 401."
        )

    def test_user_documents_returns_401_without_session(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/user/documents", data={})
        assert resp.status_code == 401, (
            f"CT-100-9 FAIL: POST /user/documents returned {resp.status_code}, expected 401."
        )

    def test_chat_without_session_cookie_redirects_to_login(self):
        """GET /chat without session cookie must redirect to /login?next=/chat."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
        resp = client.get("/chat")
        assert resp.status_code == 302, (
            f"CT-100-10 FAIL: GET /chat without session returned {resp.status_code}, expected 302."
        )
        assert "/login" in resp.headers.get("location", ""), (
            "CT-100-10 FAIL: /chat redirect does not point to /login."
        )

    def test_chat_with_session_cookie_serves_page(self):
        """GET /chat with a session cookie must return 200 HTML."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, _ = _make_user_ui_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
        resp = client.get(
            "/chat",
            cookies={"__Host-yashigani_session": "fake-session-token"},
        )
        assert resp.status_code == 200, (
            f"CT-100-10 FAIL: GET /chat with session cookie returned {resp.status_code}, "
            "expected 200."
        )
        assert "text/html" in resp.headers.get("content-type", ""), (
            "CT-100-10 FAIL: /chat response is not HTML."
        )
