"""
Unit tests for OpenAPI exposure behind auth (v2.23.4).

Verifies:
- Backoffice: /admin/openapi.json and /admin/api-docs require admin session
- Backoffice: authenticated admin can retrieve OpenAPI schema and Swagger UI
- Gateway: /openapi.json requires a resolved identity (Bearer)
- Gateway: unauthenticated /openapi.json returns 401

Last updated: 2026-05-17T00:00:00+01:00
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── Caddy middleware bypass for unit tests ─────────────────────────────────
#
# CaddyVerifiedMiddleware requires _caddy_secret to be set (set by lifespan
# startup in production). In unit tests, the lifespan is not invoked via
# TestClient by default. We patch the module-level _caddy_secret to a known
# value and include it in test requests. This matches how other unit tests
# handle infrastructure middleware.

_TEST_CADDY_SECRET = "test-caddy-secret-unit-test-only"


@contextmanager
def _caddy_bypass():
    """Context manager: patch caddy_verified._caddy_secret to a known value."""
    import yashigani.auth.caddy_verified as _cv
    original = _cv._caddy_secret
    _cv._caddy_secret = _TEST_CADDY_SECRET
    try:
        yield _TEST_CADDY_SECRET
    finally:
        _cv._caddy_secret = original


# ── Backoffice fixtures ────────────────────────────────────────────────────

def _make_backoffice_client(session_cookie: str | None = None, caddy_secret: str | None = None):
    """Create a TestClient for the backoffice app with optional session cookie."""
    from yashigani.backoffice.app import create_backoffice_app
    app = create_backoffice_app()
    client = TestClient(app, raise_server_exceptions=False)
    if session_cookie:
        client.cookies.set("__Host-yashigani_admin_session", session_cookie)
    return app, client


def _inject_session_store(app, token: str, tier: str = "admin"):
    """Monkeypatch the backoffice state to return a valid session."""
    from yashigani.auth.session import Session
    mock_store = MagicMock()
    mock_session = MagicMock(spec=Session)
    mock_session.account_tier = tier
    mock_store.get.return_value = mock_session

    from yashigani.backoffice import state as _state_mod
    original = getattr(_state_mod, "backoffice_state", None)

    mock_state = MagicMock()
    mock_state.session_store = mock_store
    _state_mod.backoffice_state = mock_state
    return mock_state, original


# ── Backoffice: /admin/openapi.json ───────────────────────────────────────

class TestBackofficeOpenAPISchema:
    def test_unauthenticated_openapi_json_returns_401_or_403(self):
        """GET /admin/openapi.json without session must return 401 or 403.

        No Caddy secret header → CaddyVerifiedMiddleware returns 401 before
        the route or session dependency even runs.
        """
        app, client = _make_backoffice_client()
        # No caddy secret → Caddy middleware returns 401 immediately
        response = client.get("/admin/openapi.json")
        assert response.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated /admin/openapi.json, "
            f"got {response.status_code}"
        )

    def test_caddy_without_session_returns_401(self):
        """Valid Caddy header but no session cookie → 401 from require_admin_session."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client()
            # Inject a session store that returns None for any token lookup
            # (simulating "session not found"). get_session_store() requires
            # backoffice_state.session_store to be set; inject a minimal mock.
            mock_state, original = _inject_session_store(app, "any-token", tier="admin")
            mock_state.session_store.get.return_value = None  # no valid session
            try:
                response = client.get(
                    "/admin/openapi.json",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                # No session cookie → require_admin_session raises 401 (token is None)
                assert response.status_code == 401, (
                    f"Expected 401 for missing session, got {response.status_code}"
                )
            finally:
                _state_mod.backoffice_state = original

    def test_authenticated_admin_gets_openapi_schema(self):
        """GET /admin/openapi.json with valid admin session returns 200 + schema."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/openapi.json",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200, (
                    f"Expected 200 for authenticated /admin/openapi.json, "
                    f"got {response.status_code}: {response.text[:200]}"
                )
                schema = response.json()
                # Must be a valid OpenAPI object
                assert "openapi" in schema, "Response must contain 'openapi' key"
                assert "info" in schema, "Response must contain 'info' key"
                assert schema["info"]["title"] == "Yashigani Backoffice"
                # Must contain paths
                assert "paths" in schema
                assert len(schema["paths"]) > 0, "Schema must have at least one path"
            finally:
                _state_mod.backoffice_state = original

    def test_non_admin_session_is_forbidden(self):
        """GET /admin/openapi.json with a user-tier session must return 403."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="user-token")
            mock_state, original = _inject_session_store(app, "user-token", tier="user")
            try:
                response = client.get(
                    "/admin/openapi.json",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code in (401, 403), (
                    f"Expected 401/403 for user-tier session, got {response.status_code}"
                )
            finally:
                _state_mod.backoffice_state = original


# ── Backoffice: /admin/api-docs ────────────────────────────────────────────

class TestBackofficeSwaggerUI:
    def test_unauthenticated_api_docs_returns_401_or_403(self):
        """GET /admin/api-docs without session must return 401 or 403."""
        app, client = _make_backoffice_client()
        response = client.get("/admin/api-docs")
        assert response.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated /admin/api-docs, "
            f"got {response.status_code}"
        )

    def test_authenticated_admin_gets_swagger_html(self):
        """GET /admin/api-docs with valid admin session returns 200 + Swagger HTML."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-docs",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200, (
                    f"Expected 200 for authenticated /admin/api-docs, "
                    f"got {response.status_code}: {response.text[:200]}"
                )
                html = response.text
                # Must be Swagger UI HTML
                assert "swagger" in html.lower() or "openapi" in html.lower(), (
                    "Response must contain Swagger/OpenAPI reference"
                )
                assert "Yashigani Backoffice" in html, (
                    "Swagger UI must show the app title"
                )
                # Swagger JS must be self-hosted (no CDN)
                assert "cdn.jsdelivr.net" not in html, (
                    "Swagger UI must not load assets from cdn.jsdelivr.net (CSP violation)"
                )
                # Self-hosted path must be referenced
                assert "/static/swagger-ui/" in html, (
                    "Swagger UI must load assets from /static/swagger-ui/ (self-hosted)"
                )
            finally:
                _state_mod.backoffice_state = original

    def test_api_docs_uses_admin_openapi_json_url(self):
        """Swagger UI must reference /admin/openapi.json (not root /openapi.json)."""
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
                assert "/admin/openapi.json" in html, (
                    "Swagger UI must reference /admin/openapi.json not the root path"
                )
            finally:
                _state_mod.backoffice_state = original


# ── Backoffice: /admin/api-redoc ──────────────────────────────────────────

class TestBackofficeReDocUI:
    def test_unauthenticated_api_redoc_returns_401_or_403(self):
        """GET /admin/api-redoc without session must return 401 or 403."""
        app, client = _make_backoffice_client()
        response = client.get("/admin/api-redoc")
        assert response.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated /admin/api-redoc, "
            f"got {response.status_code}"
        )

    def test_authenticated_admin_gets_redoc_html(self):
        """GET /admin/api-redoc with valid admin session returns 200 + ReDoc HTML."""
        from yashigani.backoffice import state as _state_mod
        with _caddy_bypass() as secret:
            app, client = _make_backoffice_client(session_cookie="valid-token")
            mock_state, original = _inject_session_store(app, "valid-token", tier="admin")
            try:
                response = client.get(
                    "/admin/api-redoc",
                    headers={"X-Caddy-Verified-Secret": secret},
                )
                assert response.status_code == 200, (
                    f"Expected 200 for authenticated /admin/api-redoc, "
                    f"got {response.status_code}: {response.text[:200]}"
                )
                html = response.text
                assert "redoc" in html.lower() or "openapi" in html.lower(), (
                    "Response must contain ReDoc reference"
                )
            finally:
                _state_mod.backoffice_state = original


# ── Gateway: /openapi.json ────────────────────────────────────────────────

def _make_gateway_client():
    """Create a TestClient for the gateway app."""
    from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
    from yashigani.gateway.openai_router import router as openai_router

    mock_pipeline = MagicMock()
    mock_pipeline.inspect.return_value = MagicMock(action="ALLOW", sanitized_content=None)
    cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
    app = create_gateway_app(
        config=cfg,
        inspection_pipeline=mock_pipeline,
        chs=MagicMock(),
        audit_writer=MagicMock(),
        rate_limiter=None,
        rbac_store=None,
        agent_registry=None,
        extra_routers=[openai_router],
    )
    return app, TestClient(app, raise_server_exceptions=False)


class TestGatewayOpenAPISchema:
    def test_unauthenticated_openapi_json_returns_401(self):
        """GET /openapi.json without Bearer returns 401."""
        from yashigani.gateway import openai_router as _openai_mod
        # Ensure identity registry returns None (no identity)
        with patch.object(_openai_mod._state, "identity_registry", None):
            app, client = _make_gateway_client()
            response = client.get("/openapi.json")
            # The catch-all proxy route would forward unknown paths, but /openapi.json
            # is mounted before the catch-all and requires identity
            assert response.status_code == 401, (
                f"Expected 401 for unauthenticated /openapi.json, "
                f"got {response.status_code}"
            )

    def test_bearer_token_allows_openapi_json(self):
        """GET /openapi.json with a valid Bearer token returns 200 + schema."""
        from yashigani.gateway import openai_router as _openai_mod
        # Mock identity registry to resolve the bearer token
        mock_registry = MagicMock()
        mock_registry.get_by_api_key.return_value = {
            "identity_id": "test-agent",
            "status": "active",
            "kind": "agent",
            "groups": [],
            "allowed_models": [],
            "bound_spiffe_uri": "",
        }
        with patch.object(_openai_mod._state, "identity_registry", mock_registry):
            app, client = _make_gateway_client()
            response = client.get(
                "/openapi.json",
                headers={"Authorization": "Bearer test-api-key"},
            )
            assert response.status_code == 200, (
                f"Expected 200 for authenticated /openapi.json, "
                f"got {response.status_code}: {response.text[:200]}"
            )
            schema = response.json()
            assert "openapi" in schema
            assert "info" in schema
            assert schema["info"]["title"] == "Yashigani Gateway"

    def test_invalid_bearer_token_returns_401(self):
        """GET /openapi.json with Bearer that resolves to None returns 401."""
        from yashigani.gateway import openai_router as _openai_mod
        mock_registry = MagicMock()
        mock_registry.get_by_api_key.return_value = None  # unknown key
        with patch.object(_openai_mod._state, "identity_registry", mock_registry):
            app, client = _make_gateway_client()
            response = client.get(
                "/openapi.json",
                headers={"Authorization": "Bearer bad-key"},
            )
            assert response.status_code == 401, (
                f"Expected 401 for unresolved Bearer, got {response.status_code}"
            )
