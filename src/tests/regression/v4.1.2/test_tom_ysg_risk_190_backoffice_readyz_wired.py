"""
Regression test -- v4.1.2 YSG-RISK-190 (self-inflicted, incomplete RISK-179):

The gateway's ``/readyz`` (``gateway/proxy.py``) is dep-checked correctly:
``gateway/entrypoint.py`` sets ``_YASHIGANI_DB_READY=1`` right after a
configured Postgres pool opens, and ``net.readiness.postgres_ready()`` only
does the real ``SELECT 1`` check when that env var is ``"1"``.

The backoffice's ``/readyz`` route (``backoffice/app.py``) reused the same
``dependency_readiness()`` helper, but the backoffice **lifespan** never set
``_YASHIGANI_DB_READY=1`` after ``await create_pool()`` -- so
``postgres_ready()`` always took the "not configured" trivial-pass branch,
even on a real deployment with a configured, migrated, pool-backed Postgres.
Chaos-confirmed: killing postgres under a running backoffice left
``/readyz`` reporting 200 "ready" (fail-OPEN) instead of 503.

Fix: ``backoffice/app.py`` lifespan now sets
``os.environ["_YASHIGANI_DB_READY"] = "1"`` immediately after
``await create_pool()`` succeeds, in the same DSN-configured branch,
mirroring ``gateway/entrypoint.py``'s existing pattern.

Redis side was already correctly wired (``AnomalyDetector``/``RateLimiter``
both expose ``._redis``, and the backoffice route already looked those up) --
only the postgres leg was dead.
"""
from __future__ import annotations

import pathlib
import re

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_APP_PY = _REPO_ROOT / "yashigani" / "backoffice" / "app.py"


class TestLifespanSetsDbReadyEnvVar:
    """Source-level check: the env var is set in the RIGHT branch (DSN
    configured), AFTER create_pool() succeeds and BEFORE any dependent
    subsystem (admin bootstrap) runs -- not merely present somewhere in the
    file."""

    def test_env_var_set_in_dsn_configured_branch_after_create_pool(self):
        src = _APP_PY.read_text()
        branch_start = src.index('if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:')
        branch_end = src.index("_bootstrap_admin_accounts(auth_service, backoffice_state)")
        branch = src[branch_start:branch_end]

        assert "await create_pool()" in branch
        assert 'os.environ["_YASHIGANI_DB_READY"] = "1"' in branch

        pool_idx = branch.index("await create_pool()")
        env_idx = branch.index('os.environ["_YASHIGANI_DB_READY"] = "1"')
        assert env_idx > pool_idx, (
            "_YASHIGANI_DB_READY must be set AFTER create_pool() succeeds -- "
            "setting it earlier would mark postgres ready before the pool exists."
        )


class TestBackofficeReadyzFailsClosedOnDbOutage:
    """The gap RISK-179's test suite missed: a backoffice deployment where
    Postgres IS configured (_YASHIGANI_DB_READY=1, as the lifespan now sets)
    but is unreachable at request time MUST return 503, not the trivial
    "not_configured" 200 pass."""

    def test_readyz_returns_503_when_db_configured_but_unreachable(self, monkeypatch):
        monkeypatch.setenv("_YASHIGANI_DB_READY", "1")

        class _BrokenPool:
            async def acquire(self):
                raise ConnectionRefusedError("postgres down (chaos test)")

            async def release(self, conn):
                pass

        import yashigani.db as _db_pkg
        monkeypatch.setattr(_db_pkg, "get_pool", lambda: _BrokenPool())

        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert "postgres_unreachable" in body["checks"]["postgres"]

    def test_readyz_returns_200_when_db_configured_and_healthy(self, monkeypatch):
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

        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["checks"]["postgres"] == "postgres_ok"

    def test_readyz_redis_down_still_fails_closed_with_db_ready_set(self, monkeypatch):
        """Confirms the postgres fix didn't regress the already-working
        redis leg (RISK-179) -- both dependencies are independently checked."""
        monkeypatch.setenv("_YASHIGANI_DB_READY", "1")

        class _FakeConn:
            async def fetchval(self, query):
                return 1

        class _FakePool:
            async def acquire(self):
                return _FakeConn()

            async def release(self, conn):
                pass

        class _BrokenRedis:
            def ping(self):
                raise ConnectionError("redis down")

        import yashigani.db as _db_pkg
        monkeypatch.setattr(_db_pkg, "get_pool", lambda: _FakePool())

        from unittest.mock import MagicMock
        from yashigani.backoffice.app import create_backoffice_app
        from yashigani.backoffice.state import backoffice_state

        app = create_backoffice_app()
        fake_detector = MagicMock()
        fake_detector._redis = _BrokenRedis()
        monkeypatch.setattr(backoffice_state, "rate_limiter", None)
        monkeypatch.setattr(backoffice_state, "anomaly_detector", fake_detector)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/readyz")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert "redis_unreachable" in body["checks"]["redis"]
        assert body["checks"]["postgres"] == "postgres_ok"
