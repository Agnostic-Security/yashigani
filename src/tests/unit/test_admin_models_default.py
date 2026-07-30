"""
Unit tests — YSG-RISK-178 admin-configurable default model.

``GET/PUT/DELETE /admin/models/default`` (src/yashigani/backoffice/routes/models.py).
Uses fakeredis for the ModelAliasStore + a FastAPI TestClient with the
admin/step-up session dependencies overridden.

NOTE on async style: tests are native ``async def`` (project pyproject.toml
sets ``asyncio_mode = "auto"``), NOT ``asyncio.run(...)``-wrapped sync tests.
``asyncio.run()`` opens AND CLOSES its own event loop per call; closing it
unsets the thread's "current" event loop, which breaks any OTHER test file
in the same pytest session that still relies on the deprecated
``asyncio.get_event_loop()`` auto-creation behaviour (e.g.
test_cloud_key_routing.py's TestOpenAICloudCall/TestAnthropicCloudCall) —
confirmed by reproducing that exact failure with an earlier
asyncio.run()-based draft of this file (alphabetically,
test_admin_models_default.py collects BEFORE test_cloud_key_routing.py, so
the pollution would hit on every full-suite run). Native async tests avoid
opening/closing a competing loop entirely.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import fakeredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from yashigani.models.alias_store import ModelAliasStore


def _app(kms_provider=None):
    from yashigani.backoffice.routes import models as models_routes
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.state import backoffice_state

    redis = fakeredis.FakeRedis()
    store = ModelAliasStore(redis_client=redis)
    store.seed_defaults()
    backoffice_state.model_alias_store = store
    backoffice_state.kms_provider = kms_provider

    app = FastAPI()
    sess = SimpleNamespace(account_id="admin1", account_tier="admin")
    app.dependency_overrides[require_admin_session] = lambda: sess
    app.dependency_overrides[require_stepup_admin_session] = lambda: sess
    app.include_router(models_routes.router, prefix="/admin/models")
    return app, store


async def _get(app, path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path)


async def _put(app, path, json=None):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.put(path, json=json or {})


async def _delete(app, path):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.delete(path)


class TestGetDefaultModel:
    async def test_no_admin_default_reports_system_spec_local(self):
        app, _store = _app()
        r = await _get(app, "/admin/models/default")
        assert r.status_code == 200
        body = r.json()
        assert body["alias"] is None
        assert body["source"] == "system_spec_local"

    async def test_local_default_reports_usable(self):
        app, store = _app()
        store.set_default("fast")  # local, force_local=True
        r = await _get(app, "/admin/models/default")
        body = r.json()
        assert body["alias"] == "fast"
        assert body["is_local"] is True
        assert body["usable"] is True

    async def test_cloud_default_without_key_reports_unusable(self):
        app, store = _app(kms_provider=None)
        store.set_default("smart")  # anthropic, no key configured anywhere
        r = await _get(app, "/admin/models/default")
        body = r.json()
        assert body["alias"] == "smart"
        assert body["is_local"] is False
        assert body["usable"] is False

    async def test_cloud_default_with_kms_key_reports_usable(self):
        kms = MagicMock()
        kms.get_secret.return_value = "sk-configured"
        app, store = _app(kms_provider=kms)
        store.set_default("smart")
        r = await _get(app, "/admin/models/default")
        body = r.json()
        assert body["usable"] is True

    async def test_missing_alias_pointer_reports_unusable_with_warning(self):
        app, store = _app()
        store.set_default("ghost-alias")  # never created
        r = await _get(app, "/admin/models/default")
        body = r.json()
        assert body["alias"] == "ghost-alias"
        assert body["usable"] is False
        assert "warning" in body


class TestSetDefaultModel:
    async def test_set_local_alias_as_default_succeeds(self):
        app, store = _app()
        r = await _put(app, "/admin/models/default", {"alias": "fast"})
        assert r.status_code == 200
        assert store.get_default() == "fast"

    async def test_set_cloud_alias_without_key_rejected_400(self):
        app, store = _app(kms_provider=None)
        r = await _put(app, "/admin/models/default", {"alias": "smart"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "cloud_default_requires_api_key"
        # Rejected write must NOT persist — the pointer stays unset.
        assert store.get_default() is None

    async def test_set_cloud_alias_with_key_succeeds(self):
        kms = MagicMock()
        kms.get_secret.return_value = "sk-configured"
        app, store = _app(kms_provider=kms)
        r = await _put(app, "/admin/models/default", {"alias": "smart"})
        assert r.status_code == 200
        assert store.get_default() == "smart"

    async def test_set_nonexistent_alias_404(self):
        app, _store = _app()
        r = await _put(app, "/admin/models/default", {"alias": "does-not-exist"})
        assert r.status_code == 404

    async def test_set_default_is_overwritable(self):
        kms = MagicMock()
        kms.get_secret.return_value = "sk-configured"
        app, store = _app(kms_provider=kms)
        await _put(app, "/admin/models/default", {"alias": "smart"})
        r = await _put(app, "/admin/models/default", {"alias": "fast"})
        assert r.status_code == 200
        assert store.get_default() == "fast"


class TestClearDefaultModel:
    async def test_clear_reverts_to_none(self):
        app, store = _app()
        store.set_default("fast")
        r = await _delete(app, "/admin/models/default")
        assert r.status_code == 200
        assert store.get_default() is None

    async def test_delete_default_does_not_hit_the_alias_catchall_route(self):
        """Route-ordering regression guard: DELETE /admin/models/default must
        resolve to clear_default_model, NOT be swallowed by the catch-all
        DELETE /{alias} route (which would 404 'alias_not_found' since no
        alias literally named 'default' exists)."""
        app, store = _app()
        store.set_default("fast")
        r = await _delete(app, "/admin/models/default")
        assert r.status_code == 200
        assert r.json().get("status") == "ok"

    async def test_clear_when_unset_is_a_noop_200(self):
        app, _store = _app()
        r = await _delete(app, "/admin/models/default")
        assert r.status_code == 200
