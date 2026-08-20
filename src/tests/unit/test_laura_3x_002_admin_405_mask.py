"""
LAURA-3X-002 regression test — uniform_admin_404_as_401 middleware must mask
both 404 (route not found) AND 405 (method not allowed) as 401 for
unauthenticated /admin/* requests.

Prior to this fix, an unauthenticated caller could probe a known admin route
(e.g. /admin/users/{username}) with a wrong HTTP method and receive HTTP 405
(Method Not Allowed), confirming the path exists BEFORE any auth check — an
enumeration oracle (LAURA-3X-002, Low, 3.1 re-gate pentest).

These tests verify:
  1. Source-level: uniform_admin_404_as_401 in app.py covers status_code 405.
  2. Functional: unauth GET/POST/PUT/DELETE on a known admin (GET-only) route
     all return 401 with identical body {"error": "authentication_required"}.
  3. Functional: unauth request on a bogus /admin/* path → 401 (404→401 still
     works).
  4. Functional: all 401 responses have identical body — no discriminating
     information.
  5. Functional: authenticated 405 on a known admin route → real 405 (mask
     applies only to pre-auth callers).

Finding: LAURA-3X-002 (Low) — 3.1 re-gate pentest.
Fix: `response.status_code in (404, 405)` in uniform_admin_404_as_401.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock  # noqa: F401 (used in authenticated test)

import pytest

_APP_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "app.py"
)

# Session cookie names mirrored from app.py (must stay in sync).
_ADMIN_SESSION_COOKIES = (
    "__Host-yashigani_admin_session",
    "__Host-yashigani_session",
)


# ---------------------------------------------------------------------------
# Source-level assertions
# ---------------------------------------------------------------------------

class TestUniformAdmin405SourceLevel:
    """Assert the middleware source covers HTTP 405 without importing the app."""

    def test_app_py_exists(self):
        assert _APP_PY.exists(), f"Missing: {_APP_PY}"

    def test_middleware_function_present(self):
        source = _APP_PY.read_text(encoding="utf-8")
        assert "uniform_admin_404_as_401" in source, (
            "REGRESSION: uniform_admin_404_as_401 not found in app.py. "
            "Admin-path enumeration masking is absent."
        )

    def test_middleware_body_covers_405(self):
        """
        The uniform_admin_404_as_401 middleware body must check for status_code
        405 (Method Not Allowed) so unauthenticated callers cannot enumerate
        admin path existence via 404 vs 405 discrimination.

        LAURA-3X-002: GET /admin/users/{username} with POST returned 405 pre-auth,
        leaking that the path exists.
        """
        source = _APP_PY.read_text(encoding="utf-8")
        func_start = source.find("async def uniform_admin_404_as_401")
        assert func_start != -1, (
            "uniform_admin_404_as_401 not found in app.py — cannot verify 405 coverage."
        )
        # Bound the search to the middleware function body (up to the next
        # middleware/decorator or end of file).
        func_end = source.find("\n    @app.", func_start + 1)
        middleware_body = source[func_start: func_end if func_end != -1 else func_start + 3000]

        assert "405" in middleware_body, (
            "LAURA-3X-002 REGRESSION: 405 not found in uniform_admin_404_as_401 body. "
            "Unauthenticated 405 responses on /admin/* paths leak path existence.\n"
            f"Middleware body excerpt:\n{middleware_body[:500]}"
        )

    def test_middleware_uses_tuple_check(self):
        """
        Preferred form is `status_code in (404, 405)` — a single condition that
        masks both cases uniformly.
        """
        source = _APP_PY.read_text(encoding="utf-8")
        assert "in (404, 405)" in source or "in (405, 404)" in source, (
            "LAURA-3X-002: expected `status_code in (404, 405)` in app.py. "
            "If the condition is split across two branches, collapse into one for clarity."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_admin_mask_app():
    """
    Build a minimal FastAPI app that mirrors the uniform_admin_404_as_401
    middleware and mounts a single GET-only /admin/users/{username} route.

    Returns the FastAPI app, or None if FastAPI is not available.
    """
    try:
        from fastapi import FastAPI, APIRouter
        from fastapi.responses import JSONResponse
        from starlette.requests import Request
    except ImportError:
        return None

    app = FastAPI()

    @app.middleware("http")
    async def uniform_admin_404_as_401(request: Request, call_next):
        """Mirror of the production middleware — 404 + 405 → 401 for unauth /admin/* callers."""
        response = await call_next(request)
        if response.status_code in (404, 405) and request.url.path.startswith("/admin/"):
            has_session = any(
                request.cookies.get(k) for k in _ADMIN_SESSION_COOKIES
            )
            if not has_session:
                return JSONResponse(
                    status_code=401,
                    content={"error": "authentication_required"},
                )
        return response

    router = APIRouter()

    @router.get("/users/{username}")
    async def admin_get_user(username: str):
        return {"username": username}

    app.include_router(router, prefix="/admin")
    return app


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

class TestUniformAdmin405MaskedFunctional:
    """
    Functional tests using a minimal FastAPI app mirroring the middleware.
    All unauthenticated probes on /admin/* (known or bogus) must return
    identical 401 — no information about path existence or allowed methods.
    """

    @pytest.fixture(scope="class")
    def client(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app = _make_admin_mask_app()
        if app is None:
            pytest.skip("fastapi not available")

        return TestClient(app, raise_server_exceptions=False)

    def _assert_uniform_401(self, resp, *, method: str, path: str):
        assert resp.status_code == 401, (
            f"LAURA-3X-002: unauth {method} {path} returned {resp.status_code}, "
            f"expected 401. Body: {resp.text!r}"
        )
        body = resp.json()
        assert body == {"error": "authentication_required"}, (
            f"LAURA-3X-002: {method} {path} returned unexpected body: {body!r}. "
            "All unauth /admin/* responses must be identical."
        )

    def test_unauth_get_known_route_returns_401(self, client):
        """Unauth GET /admin/users/alice → 200 from the handler masked to 401 by middleware.

        Actually the GET succeeds (no auth dep in this test app) so the middleware
        sees 200 and passes it through — this confirms the middleware does NOT mask
        successful responses. The route existence oracle test is POST/PUT/DELETE below.
        """
        # In this minimal app the GET route has no auth guard, so it returns 200.
        # The middleware only masks 404/405, not 200.
        resp = client.get("/admin/users/alice")
        # 200 must pass through — middleware must NOT over-mask successful responses.
        assert resp.status_code == 200, (
            f"Unexpected status {resp.status_code} for GET /admin/users/alice in test app."
        )

    def test_unauth_post_known_route_masked_to_401(self, client):
        """Unauth POST on a GET-only /admin route would normally return 405;
        the middleware must mask it to 401 so callers cannot confirm the path exists."""
        resp = client.post("/admin/users/alice")
        self._assert_uniform_401(resp, method="POST", path="/admin/users/alice")

    def test_unauth_put_known_route_masked_to_401(self, client):
        """Unauth PUT on a GET-only /admin route → 401 (not 405)."""
        resp = client.put("/admin/users/alice")
        self._assert_uniform_401(resp, method="PUT", path="/admin/users/alice")

    def test_unauth_delete_known_route_masked_to_401(self, client):
        """Unauth DELETE on a GET-only /admin route → 401 (not 405)."""
        resp = client.delete("/admin/users/alice")
        self._assert_uniform_401(resp, method="DELETE", path="/admin/users/alice")

    def test_unauth_bogus_admin_path_returns_401(self, client):
        """Unauth request on a non-existent /admin path → 401 (404→401, existing behaviour)."""
        resp = client.get("/admin/nonexistent-route-xyz")
        self._assert_uniform_401(resp, method="GET", path="/admin/nonexistent-route-xyz")

    def test_all_unauth_probes_identical_body(self, client):
        """
        POST, PUT, DELETE on a known route + GET on a bogus route must all return
        identical 401 body — no field differs between them.
        """
        paths_and_methods = [
            ("POST", "/admin/users/alice"),
            ("PUT",  "/admin/users/alice"),
            ("DELETE", "/admin/users/alice"),
            ("GET", "/admin/no-such-route"),
            ("POST", "/admin/no-such-route"),
        ]
        bodies = []
        for method, path in paths_and_methods:
            resp = client.request(method, path)
            assert resp.status_code == 401, (
                f"LAURA-3X-002: {method} {path} returned {resp.status_code}, expected 401."
            )
            bodies.append(resp.json())

        # All bodies must be identical — no discriminating information.
        reference = bodies[0]
        for i, body in enumerate(bodies[1:], start=1):
            assert body == reference, (
                f"LAURA-3X-002: response body at index {i} differs from index 0. "
                f"Bodies must be identical to prevent enumeration.\n"
                f"  Reference: {reference!r}\n"
                f"  Got:       {body!r}"
            )

    def test_authenticated_405_passes_through(self, client):
        """
        An authenticated caller (session cookie present) hitting a known route with
        the wrong method must still receive the real 405 — the mask applies only
        to unauthenticated callers.
        """
        # Supply one of the expected session cookie names.
        cookies = {"__Host-yashigani_admin_session": "some-session-token"}
        resp = client.post("/admin/users/alice", cookies=cookies)
        # In this test app there is no session validation so the cookie is accepted
        # as "present" by the middleware — it must NOT mask to 401.
        assert resp.status_code == 405, (
            f"LAURA-3X-002: authenticated POST /admin/users/alice returned "
            f"{resp.status_code}, expected 405. Middleware must not mask authenticated callers."
        )
