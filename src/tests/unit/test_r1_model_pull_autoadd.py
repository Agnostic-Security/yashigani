"""
Unit tests — R1 model pull → auto-add alias (2.25.5).

Covers:
  1. _model_name_to_alias: correct slug derivation for common patterns
  2. pull_model: successful pull creates alias (alias_created=True)
  3. pull_model: second identical pull is idempotent (alias_existed=True)
  4. pull_model: alias store unavailable → pull still succeeds (alias_created=False)
  5. pull_model: Ollama unreachable → 503, alias not created
  6. pull_model: Ollama returns non-200 → 502, alias not created
  7. pull_model: response includes alias, alias_created, alias_existed fields
  8. pull_model: pulled model visible in GET /admin/models after auto-add

Pattern follows test_v2255_admin_ui_crud.py:
mutate backoffice_state directly, use httpx.AsyncClient + ASGITransport.
Alias store backed by fakeredis for full isolation; pull I/O is mocked.

Last updated: 2026-06-13T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from yashigani.backoffice.routes.models import _model_name_to_alias

try:
    import fakeredis
    _FAKEREDIS_AVAILABLE = True
except ImportError:
    _FAKEREDIS_AVAILABLE = False

try:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not (_FAKEREDIS_AVAILABLE and _FASTAPI_AVAILABLE),
    reason="fakeredis and fastapi/httpx required",
)


class TestModelNameToAlias:
    def test_simple_name_no_tag(self):
        assert _model_name_to_alias("llama3") == "llama3"

    def test_colon_tag_becomes_dash(self):
        assert _model_name_to_alias("llama3:8b") == "llama3-8b"

    def test_dot_becomes_dash(self):
        assert _model_name_to_alias("qwen2.5:3b") == "qwen2-5-3b"

    def test_slash_becomes_dash(self):
        assert _model_name_to_alias("my/model:latest") == "my-model-latest"

    def test_consecutive_special_chars_collapsed(self):
        # "foo::bar" -> "foo--bar" -> collapsed -> "foo-bar"
        assert _model_name_to_alias("foo::bar") == "foo-bar"

    def test_truncated_to_64_chars(self):
        long_name = "a" * 100
        result = _model_name_to_alias(long_name)
        assert len(result) <= 64

    def test_empty_name_returns_model(self):
        # edge: empty string after stripping special chars → 'model'
        assert _model_name_to_alias(":::") == "model"

    def test_coder_model(self):
        assert _model_name_to_alias("qwen2.5-coder:7b") == "qwen2-5-coder-7b"

    def test_lowercase(self):
        assert _model_name_to_alias("LLAMA3:8B") == "llama3-8b"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def _make_models_app(fake_redis=None):
    """Build minimal FastAPI app with models router + fakeredis alias store."""
    from yashigani.backoffice.routes import models as models_routes
    from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session
    from yashigani.backoffice.state import backoffice_state
    from yashigani.models.alias_store import ModelAliasStore

    backoffice_state.inspection_pipeline = None
    backoffice_state.model_allocation_store = None
    backoffice_state.opa_url = "http://policy:8181"

    if fake_redis is not None:
        backoffice_state.model_alias_store = ModelAliasStore(redis_client=fake_redis)
    else:
        backoffice_state.model_alias_store = None  # store unavailable → 503

    sess = SimpleNamespace(account_id="admin1", account_tier="admin")
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: sess
    app.dependency_overrides[require_stepup_admin_session] = lambda: sess
    app.include_router(models_routes.router, prefix="/admin/models")
    return app


def _ndjson(events: list[dict]) -> list[str]:
    return [json.dumps(e) for e in events]


def _mock_httpx_stream(lines: list[str], status_code: int = 200):
    """Return a mock that looks like httpx.AsyncClient.stream(...)."""
    stream_ctx = MagicMock()
    stream_ctx.__aenter__ = AsyncMock(return_value=stream_ctx)
    stream_ctx.__aexit__ = AsyncMock(return_value=False)
    stream_ctx.status_code = status_code

    async def _aiter_lines():
        for line in lines:
            yield line

    stream_ctx.aiter_lines = _aiter_lines

    client_ctx = MagicMock()
    client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
    client_ctx.__aexit__ = AsyncMock(return_value=False)
    client_ctx.stream = MagicMock(return_value=stream_ctx)
    return client_ctx, stream_ctx


# ---------------------------------------------------------------------------
# R1 — pull_model endpoint
# ---------------------------------------------------------------------------

class TestPullModelAutoAdd:
    """R1: pull_model auto-adds alias on success."""

    def test_successful_pull_creates_alias(self, monkeypatch):
        """Successful pull → alias_created=True, alias persisted in store."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        lines = _ndjson([{"status": "pulling manifest"}, {"status": "success"}])
        client_ctx, _ = _mock_httpx_stream(lines)
        monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/models/pull", json={"name": "llama3:8b"})

        resp = _run(go())
        assert resp.status_code == 202, f"Got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["status"] == "ok"
        assert body["model"] == "llama3:8b"
        assert body["alias"] == "llama3-8b"
        assert body["alias_created"] is True
        assert body["alias_existed"] is False

        # Verify alias really landed in the store
        from yashigani.models.alias_store import ModelAliasStore
        store = ModelAliasStore(redis_client=fr)
        alias = store.get("llama3-8b")
        assert alias is not None
        assert alias.model == "llama3:8b"
        assert alias.provider == "ollama"
        assert alias.force_local is True

    def test_second_pull_same_model_is_idempotent(self, monkeypatch):
        """Second pull of same model: alias_existed=True, alias_created=False."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        lines = _ndjson([{"status": "success"}])

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                # First pull
                client_ctx1, _ = _mock_httpx_stream(lines)
                monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx1)
                resp1 = await c.post("/admin/models/pull", json={"name": "qwen2.5:3b"})

                # Second pull — same model
                client_ctx2, _ = _mock_httpx_stream(lines)
                monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx2)
                resp2 = await c.post("/admin/models/pull", json={"name": "qwen2.5:3b"})
                return resp1, resp2

        r1, r2 = _run(go())
        assert r1.status_code == 202
        assert r1.json()["alias_created"] is True

        assert r2.status_code == 202
        assert r2.json()["alias_existed"] is True
        assert r2.json()["alias_created"] is False

    def test_pull_succeeds_when_alias_store_unavailable(self, monkeypatch):
        """Pull succeeds even when alias store is None (503 guard swallowed)."""
        import httpx as httpx_mod
        app = _make_models_app(fake_redis=None)  # no store

        lines = _ndjson([{"status": "success"}])
        client_ctx, _ = _mock_httpx_stream(lines)
        monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/models/pull", json={"name": "llama3:8b"})

        resp = _run(go())
        assert resp.status_code == 202, f"Got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["status"] == "ok"
        assert body["alias_created"] is False
        assert body["alias_existed"] is False

    def test_pull_ollama_unreachable_returns_503(self, monkeypatch):
        """When Ollama is unreachable, POST /pull returns 503."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        client_ctx = MagicMock()
        client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
        client_ctx.__aexit__ = AsyncMock(return_value=False)
        client_ctx.stream = MagicMock(side_effect=httpx_mod.ConnectError("refused"))
        monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/models/pull", json={"name": "llama3:8b"})

        resp = _run(go())
        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "ollama_unreachable"

    def test_pull_ollama_non_200_returns_502(self, monkeypatch):
        """When Ollama returns non-200, POST /pull returns 502."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        stream_ctx = MagicMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_ctx)
        stream_ctx.__aexit__ = AsyncMock(return_value=False)
        stream_ctx.status_code = 404

        async def _empty():
            return
            yield  # pragma: no cover

        stream_ctx.aiter_lines = _empty
        client_ctx = MagicMock()
        client_ctx.__aenter__ = AsyncMock(return_value=client_ctx)
        client_ctx.__aexit__ = AsyncMock(return_value=False)
        client_ctx.stream = MagicMock(return_value=stream_ctx)
        monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/models/pull", json={"name": "llama3:8b"})

        resp = _run(go())
        assert resp.status_code == 502
        assert resp.json()["detail"]["error"] == "pull_failed"

    def test_pull_response_has_all_r1_fields(self, monkeypatch):
        """Response must include alias, alias_created, alias_existed, ollama_status."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        lines = _ndjson([{"status": "success"}])
        client_ctx, _ = _mock_httpx_stream(lines)
        monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/models/pull", json={"name": "gemma3:4b"})

        resp = _run(go())
        assert resp.status_code == 202
        body = resp.json()
        required = {"status", "model", "ollama_status", "alias", "alias_created", "alias_existed"}
        missing = required - set(body.keys())
        assert not missing, f"Missing R1 fields in response: {missing}"

    def test_pulled_model_visible_in_alias_list(self, monkeypatch):
        """After pull, GET /admin/models returns the auto-created alias."""
        import httpx as httpx_mod
        fr = fakeredis.FakeRedis()
        app = _make_models_app(fr)

        lines = _ndjson([{"status": "success"}])

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                client_ctx1, _ = _mock_httpx_stream(lines)
                monkeypatch.setattr(httpx_mod, "AsyncClient", lambda **kw: client_ctx1)
                pull_resp = await c.post("/admin/models/pull", json={"name": "mistral:7b"})

                list_resp = await c.get("/admin/models")
                return pull_resp, list_resp

        pull_r, list_r = _run(go())
        assert pull_r.status_code == 202
        assert list_r.status_code == 200

        aliases = {a["alias"]: a for a in list_r.json()["aliases"]}
        assert "mistral-7b" in aliases, f"Expected mistral-7b in {list(aliases.keys())}"
        assert aliases["mistral-7b"]["model"] == "mistral:7b"
