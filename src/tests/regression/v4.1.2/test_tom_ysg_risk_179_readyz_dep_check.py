"""
Regression test -- v4.1.2 YSG-RISK-179 (dep-checked readiness):

``/readyz`` was already referenced in every rate-limit / DDoS exemption
allowlist (``gateway/ddos.py``, ``gateway/endpoint_ratelimit.py``,
``auth/caddy_verified.py``) but no route ever implemented it in either the
gateway or the backoffice -- Caddy / k8s readiness probes hit a bare 404.

Fix: ``yashigani.net.readiness`` provides ``postgres_ready`` /
``redis_ready`` / ``dependency_readiness`` helpers; both
``gateway/proxy.py`` and ``backoffice/app.py`` now register a ``/readyz``
route that runs them and returns 200 when every *configured* dependency is
reachable, 503 otherwise. ``/healthz`` is untouched -- it stays the shallow
liveness probe.

Dep-not-configured (no DB DSN, no redis client wired) is trivially "ready"
-- a readiness probe must not fail on an intentionally-absent optional
dependency (community/dev deploys without Postgres).
"""
from __future__ import annotations

import os

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")


# ---------------------------------------------------------------------------
# Unit tests for the shared readiness helpers
# ---------------------------------------------------------------------------

class TestPostgresReady:
    @pytest.mark.asyncio
    async def test_not_configured_is_trivially_ready(self, monkeypatch):
        monkeypatch.delenv("_YASHIGANI_DB_READY", raising=False)
        from yashigani.net.readiness import postgres_ready
        ready, detail = await postgres_ready()
        assert ready is True
        assert detail == "postgres_not_configured"

    @pytest.mark.asyncio
    async def test_configured_but_pool_missing_is_not_ready(self, monkeypatch):
        monkeypatch.setenv("_YASHIGANI_DB_READY", "1")
        import yashigani.db as _db_pkg
        monkeypatch.setattr(_db_pkg, "get_pool", lambda: (_ for _ in ()).throw(RuntimeError("no pool")))
        from yashigani.net.readiness import postgres_ready
        ready, detail = await postgres_ready()
        assert ready is False
        assert "not_initialized" in detail

    @pytest.mark.asyncio
    async def test_configured_and_pool_healthy_is_ready(self, monkeypatch):
        monkeypatch.setenv("_YASHIGANI_DB_READY", "1")

        class _FakeConn:
            async def fetchval(self, query):
                assert query == "SELECT 1"
                return 1

        class _FakePool:
            async def acquire(self):
                return _FakeConn()

            async def release(self, conn):
                pass

        import yashigani.db as _db_pkg
        monkeypatch.setattr(_db_pkg, "get_pool", lambda: _FakePool())
        from yashigani.net.readiness import postgres_ready
        ready, detail = await postgres_ready()
        assert ready is True
        assert detail == "postgres_ok"

    @pytest.mark.asyncio
    async def test_configured_and_pool_unreachable_is_not_ready(self, monkeypatch):
        monkeypatch.setenv("_YASHIGANI_DB_READY", "1")

        class _FakePool:
            async def acquire(self):
                raise ConnectionRefusedError("postgres down")

            async def release(self, conn):
                pass

        import yashigani.db as _db_pkg
        monkeypatch.setattr(_db_pkg, "get_pool", lambda: _FakePool())
        from yashigani.net.readiness import postgres_ready
        ready, detail = await postgres_ready()
        assert ready is False
        assert "postgres_unreachable" in detail


class TestRedisReady:
    def test_no_client_is_trivially_ready(self):
        from yashigani.net.readiness import redis_ready
        ready, detail = redis_ready(None)
        assert ready is True
        assert detail == "redis_not_configured"

    def test_reachable_client_is_ready(self, mock_redis):
        from yashigani.net.readiness import redis_ready
        ready, detail = redis_ready(mock_redis)
        assert ready is True
        assert detail == "redis_ok"

    def test_unreachable_client_is_not_ready(self):
        from yashigani.net.readiness import redis_ready

        class _BrokenRedis:
            def ping(self):
                raise ConnectionError("redis down")

        ready, detail = redis_ready(_BrokenRedis())
        assert ready is False
        assert "redis_unreachable" in detail


# ---------------------------------------------------------------------------
# Gateway /readyz route
# ---------------------------------------------------------------------------

class TestGatewayReadyzRoute:
    def _build_app(self, rate_limiter=None):
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
        from unittest.mock import MagicMock
        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
        return create_gateway_app(
            config=cfg,
            inspection_pipeline=MagicMock(),
            chs=MagicMock(),
            audit_writer=MagicMock(),
            rate_limiter=rate_limiter,
        )

    def test_readyz_no_deps_configured_returns_200(self, monkeypatch):
        monkeypatch.delenv("_YASHIGANI_DB_READY", raising=False)
        app = self._build_app(rate_limiter=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["checks"]["postgres"] == "postgres_not_configured"
        assert body["checks"]["redis"] == "redis_not_configured"

    def test_readyz_redis_up_returns_200(self, monkeypatch, mock_redis):
        monkeypatch.delenv("_YASHIGANI_DB_READY", raising=False)
        from yashigani.ratelimit.limiter import RateLimiter
        rl = RateLimiter(mock_redis)
        app = self._build_app(rate_limiter=rl)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["checks"]["redis"] == "redis_ok"

    def test_readyz_redis_down_returns_503(self, monkeypatch):
        monkeypatch.delenv("_YASHIGANI_DB_READY", raising=False)
        from unittest.mock import MagicMock

        class _BrokenRedis:
            def ping(self):
                raise ConnectionError("redis down")

        fake_rl = MagicMock()
        fake_rl._redis = _BrokenRedis()
        app = self._build_app(rate_limiter=fake_rl)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert "redis_unreachable" in resp.json()["checks"]["redis"]

    def test_readyz_exempt_from_caddy_verified_secret(self):
        """/readyz must be reachable without X-Caddy-Verified-Secret (matches
        /healthz) -- confirms the exemption list in auth/caddy_verified.py
        actually lines up with a real route now."""
        from yashigani.auth.caddy_verified import _EXEMPT_PATHS
        assert "/readyz" in _EXEMPT_PATHS

    def test_healthz_unaffected_still_shallow(self):
        app = self._build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Backoffice /readyz route
# ---------------------------------------------------------------------------

class TestBackofficeReadyzRoute:
    def test_readyz_route_registered_and_returns_200_no_deps(self, monkeypatch):
        """Backoffice /readyz was previously entirely absent (404). Route
        construction does not require a live DB/Redis (that wiring happens
        in the lifespan, not at create_backoffice_app() call time) -- with
        no dependencies configured, /readyz must return 200 (trivially
        ready), mirroring the gateway-side behaviour."""
        monkeypatch.delenv("_YASHIGANI_DB_READY", raising=False)
        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        assert "/readyz" in [r.path for r in app.routes]

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["checks"]["postgres"] == "postgres_not_configured"
        assert body["checks"]["redis"] == "redis_not_configured"

    def test_healthz_unaffected_still_shallow(self):
        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
