"""
Regression tests — YSG-RISK-143 (HIGH): /admin/cache Postgres/Redis store split.

ROOT CAUSE (backoffice/routes/cache.py, pre-fix):
  GET  /admin/cache            -> queried Postgres ``cache_config`` table
                                   (SELECT ... FROM cache_config) — a table
                                   that NO code path in the repo ever wrote to
                                   (grep confirmed: only referenced by the
                                   migration that creates/drops it and by this
                                   one SELECT).
  GET  /admin/cache/{tenant_id}
  PUT  /admin/cache/{tenant_id}
  DELETE /admin/cache/{tenant_id} -> all three go through
                                   ResponseCache.get_tenant_config() /
                                   set_tenant_config() / invalidate(), which
                                   are entirely Redis-backed
                                   (key ``rc:cfg:<tenant_id>``).

  Net effect: a config set via PUT was written to Redis but the list endpoint
  read an unrelated, permanently-empty Postgres table — a PUT'd config could
  never appear in the list.

FIX: GET /admin/cache now reads from the SAME store (Redis, via the new
ResponseCache.list_tenant_configs()) that PUT/GET/DELETE already use.

Cross-ref: docs/risk-register.yml YSG-RISK-143.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

try:
    import fakeredis
    _HAVE_FAKEREDIS = True
except ImportError:  # pragma: no cover
    _HAVE_FAKEREDIS = False

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(
    not (_HAVE_FASTAPI and _HAVE_FAKEREDIS),
    reason="fastapi + fakeredis required",
)

_TENANT_A = "11111111-1111-1111-1111-111111111111"
_TENANT_B = "22222222-2222-2222-2222-222222222222"


def _make_app():
    """Mount only the cache router with auth bypassed, backed by fakeredis."""
    from yashigani.backoffice.routes import cache as cache_routes
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.state import backoffice_state
    from yashigani.gateway.response_cache import ResponseCache

    rc = ResponseCache(fakeredis.FakeStrictRedis())
    backoffice_state.response_cache = rc

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin@test.local", account_tier="admin"
    )
    app.include_router(cache_routes.cache_router)
    return app, rc


def _teardown():
    from yashigani.backoffice.state import backoffice_state
    backoffice_state.response_cache = None


class TestAdminCacheStoreUnification:
    def test_put_then_list_round_trips(self):
        """YSG-RISK-143 core regression: a config set via PUT MUST appear in
        the GET /admin/cache list. Pre-fix, list read Postgres (always empty)
        while PUT wrote Redis -> this assertion failed (tenants == []).
        """
        app, _rc = _make_app()
        try:
            client = TestClient(app)

            put_resp = client.put(
                f"/admin/cache/{_TENANT_A}",
                json={"enabled": True, "ttl_seconds": 120},
            )
            assert put_resp.status_code == 200, put_resp.text

            list_resp = client.get("/admin/cache")
            assert list_resp.status_code == 200, list_resp.text
            body = list_resp.json()
            assert body["cache_available"] is True

            tenants = {t["tenant_id"]: t for t in body["tenants"]}
            assert _TENANT_A in tenants, (
                f"YSG-RISK-143 REGRESSION: PUT'd tenant {_TENANT_A} did not "
                f"appear in GET /admin/cache list: {body['tenants']!r}"
            )
            assert tenants[_TENANT_A]["enabled"] is True
            assert tenants[_TENANT_A]["ttl_seconds"] == 120
        finally:
            _teardown()

    def test_put_then_get_single_tenant_matches_list(self):
        """GET /admin/cache/{tenant_id} (single) and GET /admin/cache (list)
        must agree — both read the same store.
        """
        app, _rc = _make_app()
        try:
            client = TestClient(app)
            client.put(f"/admin/cache/{_TENANT_B}", json={"enabled": False, "ttl_seconds": 60})

            single = client.get(f"/admin/cache/{_TENANT_B}").json()
            listing = client.get("/admin/cache").json()
            tenants = {t["tenant_id"]: t for t in listing["tenants"]}

            assert tenants[_TENANT_B]["enabled"] == single["enabled"]
            assert tenants[_TENANT_B]["ttl_seconds"] == single["ttl_seconds"]
        finally:
            _teardown()

    def test_multiple_tenants_all_listed_sorted(self):
        app, _rc = _make_app()
        try:
            client = TestClient(app)
            client.put(f"/admin/cache/{_TENANT_B}", json={"enabled": True, "ttl_seconds": 90})
            client.put(f"/admin/cache/{_TENANT_A}", json={"enabled": False, "ttl_seconds": 30})

            listing = client.get("/admin/cache").json()
            listed_ids = [t["tenant_id"] for t in listing["tenants"]]
            assert set(listed_ids) == {_TENANT_A, _TENANT_B}
            assert listed_ids == sorted(listed_ids)
        finally:
            _teardown()

    def test_delete_removes_data_keys_config_untouched(self):
        """DELETE invalidates cached response entries; the tenant CONFIG
        (enabled/ttl) is a separate key and is not expected to disappear from
        the list purely from a cache-entry invalidation call.
        """
        app, rc = _make_app()
        try:
            client = TestClient(app)
            client.put(f"/admin/cache/{_TENANT_A}", json={"enabled": True, "ttl_seconds": 45})
            del_resp = client.delete(f"/admin/cache/{_TENANT_A}")
            assert del_resp.status_code == 200

            listing = client.get("/admin/cache").json()
            tenants = {t["tenant_id"]: t for t in listing["tenants"]}
            assert _TENANT_A in tenants
            assert tenants[_TENANT_A]["enabled"] is True
        finally:
            _teardown()

    def test_no_response_cache_configured_returns_unavailable(self):
        from yashigani.backoffice.routes import cache as cache_routes
        from yashigani.backoffice.middleware import require_admin_session
        from yashigani.backoffice.state import backoffice_state

        backoffice_state.response_cache = None
        app = FastAPI()
        app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
            account_id="admin@test.local", account_tier="admin"
        )
        app.include_router(cache_routes.cache_router)
        client = TestClient(app)

        resp = client.get("/admin/cache")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"tenants": [], "cache_available": False}


class TestResponseCacheListTenantConfigs:
    """Unit tests for ResponseCache.list_tenant_configs() in isolation."""

    def _rc(self):
        from yashigani.gateway.response_cache import ResponseCache
        return ResponseCache(fakeredis.FakeStrictRedis())

    def test_empty_store_returns_empty_list(self):
        rc = self._rc()
        assert rc.list_tenant_configs() == []

    def test_set_then_list_reflects_values(self):
        rc = self._rc()
        rc.set_tenant_config(_TENANT_A, True, 500)
        results = rc.list_tenant_configs()
        assert len(results) == 1
        assert results[0]["tenant_id"] == _TENANT_A
        assert results[0]["enabled"] is True
        assert results[0]["ttl_seconds"] == 500

    def test_data_cache_keys_are_not_mistaken_for_config_keys(self):
        """A cached response entry (rc:<8char>:<digest>) must never be
        misparsed as a tenant config row.
        """
        rc = self._rc()
        rc.set(_TENANT_A, b'{"q":1}', b"cached-response-bytes")
        assert rc.list_tenant_configs() == []
        rc.set_tenant_config(_TENANT_A, True, 300)
        results = rc.list_tenant_configs()
        assert len(results) == 1
        assert results[0]["tenant_id"] == _TENANT_A
