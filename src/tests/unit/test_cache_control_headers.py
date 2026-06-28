"""Unit tests for ZAP 10015/10049 Cache-Control: no-store headers.

Both the backoffice (backoffice/app.py) and gateway (gateway/proxy.py)
security_headers middlewares must set Cache-Control: no-store + Pragma:
no-cache on every dynamic response, and MUST NOT set them on /static/* paths.

These tests use minimal FastAPI apps that replay just the middleware logic
so they do not require live DB / Redis / OPA.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Helper: build a tiny FastAPI app that mirrors the middleware logic from
# backoffice/app.py and gateway/proxy.py without their heavy dependencies.
# ---------------------------------------------------------------------------

def _make_app_with_cache_middleware() -> FastAPI:
    """Minimal app that applies only the Cache-Control/Pragma middleware."""
    app = FastAPI()

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        # Mirror the logic from backoffice/app.py and gateway/proxy.py exactly:
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/api/some/endpoint")
    async def dynamic_endpoint():
        return PlainTextResponse("dynamic")

    @app.get("/healthz")
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/static/js/dashboard.js")
    async def static_js():
        return PlainTextResponse("/* js */", media_type="application/javascript")

    @app.get("/static/css/dashboard.css")
    async def static_css():
        return PlainTextResponse("/* css */", media_type="text/css")

    return app


@pytest.fixture(scope="module")
def client():
    app = _make_app_with_cache_middleware()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Dynamic paths MUST have Cache-Control: no-store and Pragma: no-cache
# ---------------------------------------------------------------------------

class TestCacheControlDynamic:
    """Dynamic paths get no-store / no-cache headers."""

    def test_api_endpoint_has_no_store(self, client):
        r = client.get("/api/some/endpoint")
        assert r.headers.get("cache-control") == "no-store", (
            "Dynamic API path must carry Cache-Control: no-store (ZAP 10015/10049)"
        )

    def test_api_endpoint_has_pragma_no_cache(self, client):
        r = client.get("/api/some/endpoint")
        assert r.headers.get("pragma") == "no-cache", (
            "Dynamic API path must carry Pragma: no-cache (ZAP 10015/10049)"
        )

    def test_healthz_has_no_store(self, client):
        """Health endpoint is a dynamic response — must also be no-store."""
        r = client.get("/healthz")
        assert r.headers.get("cache-control") == "no-store"

    def test_healthz_has_pragma_no_cache(self, client):
        r = client.get("/healthz")
        assert r.headers.get("pragma") == "no-cache"


# ---------------------------------------------------------------------------
# /static/* paths MUST NOT get Cache-Control: no-store
# ---------------------------------------------------------------------------

class TestCacheControlStatic:
    """Static assets under /static/ must not be forced no-store."""

    def test_static_js_has_no_cache_control(self, client):
        r = client.get("/static/js/dashboard.js")
        assert "cache-control" not in r.headers, (
            "/static/ assets must NOT receive Cache-Control: no-store — "
            "fingerprinted assets are safe to cache"
        )

    def test_static_css_has_no_pragma(self, client):
        r = client.get("/static/css/dashboard.css")
        assert "pragma" not in r.headers, (
            "/static/ assets must NOT receive Pragma: no-cache"
        )

    def test_static_js_no_store_absent(self, client):
        r = client.get("/static/js/dashboard.js")
        cc = r.headers.get("cache-control", "")
        assert "no-store" not in cc

    def test_static_css_no_store_absent(self, client):
        r = client.get("/static/css/dashboard.css")
        cc = r.headers.get("cache-control", "")
        assert "no-store" not in cc


# ---------------------------------------------------------------------------
# Gateway app integration smoke (create_gateway_app factory)
# ---------------------------------------------------------------------------

class TestGatewayCacheControl:
    """Verify the real gateway app factory sets Cache-Control: no-store."""

    @pytest.fixture(scope="class")
    def gw_client(self):
        from unittest.mock import MagicMock
        # Minimal mocks so we can call create_gateway_app without real services.
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
        mock_pipeline = MagicMock()
        cfg = GatewayConfig(
            upstream_base_url="http://mcp:8080",
            opa_url="http://opa:8181",
        )
        app = create_gateway_app(
            config=cfg,
            inspection_pipeline=mock_pipeline,
            chs=MagicMock(),
            audit_writer=MagicMock(),
            rate_limiter=None,
            rbac_store=None,
            agent_registry=None,
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_healthz_is_no_store(self, gw_client):
        """Gateway /healthz (dynamic) must carry Cache-Control: no-store."""
        r = gw_client.get("/healthz")
        assert r.headers.get("cache-control") == "no-store", (
            "Gateway /healthz must carry Cache-Control: no-store"
        )

    def test_healthz_pragma(self, gw_client):
        r = gw_client.get("/healthz")
        assert r.headers.get("pragma") == "no-cache"

    def test_static_swagger_no_forced_no_store(self, gw_client):
        """/static/swagger-ui/* assets must NOT be forced no-store by middleware.

        The gateway may return 404 for this path in the test environment (no
        static files mounted), which is fine — the point is that if the response
        exists it must NOT have no-store injected by the middleware.
        """
        r = gw_client.get("/static/swagger-ui/swagger-ui-bundle.js")
        # Accept 404 (no static mount in test) or 200 — either way no no-store.
        cc = r.headers.get("cache-control", "")
        assert "no-store" not in cc, (
            "/static/ assets must not receive Cache-Control: no-store from middleware"
        )
