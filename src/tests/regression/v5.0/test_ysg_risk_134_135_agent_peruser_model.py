"""
Regression test — YSG-RISK-134/135: per-user Letta AND Langflow agent
instances were provisioned with a GLOBAL hardcoded brain model
(YASHIGANI_LETTA_BRAIN_MODEL / YASHIGANI_LANGFLOW_MODEL), ignoring the
caller's already-existing per-user model profile (models/effective.py +
models/allocation_store.py) — the same effective-allowed-models resolution
the /v1 chat egress leg already applies via
openai_router._effective_allowed_models().

Fix (openai_router.py):
  * New ``_resolve_agent_brain_model(identity, default_model)`` — mirrors
    the /v1 leg's "empty allowed_models == default" semantics using
    ``models.effective.EffectiveModels.pick_allowed_local_default`` for the
    LOCAL-only fallback (an agent brain model must be an Ollama-served local
    model per letta_client/langflow_client's own module docstrings).
    Raises ``ModelNotAllocatedError`` (never silently substitutes the
    global default) when the caller is restricted and no local model in
    their effective set is usable.
  * Wired into BOTH Letta call sites (persona/pool @-alias path,
    static/globally-registered @letta path) and the Langflow flow-run path
    (openai_router.py, buffered agent-call branch).
  * letta_client.py: ``LettaClientPool._ensure_agent_for_user`` /
    ``for_user`` / ``letta_chat`` gained an optional ``brain_model`` kwarg
    (defaults to the legacy global default when omitted — back-compat for
    unrelated call sites in backoffice/routes/user_agents.py).
  * langflow_client.py: ``langflow_chat`` gained an optional ``model`` kwarg.
    Because the default "Yashigani Chat" flow is SHARED/global (one
    persisted flow, not per-user), the per-user override is applied via
    Langflow's runtime ``tweaks`` mechanism targeting the flow's OpenAIModel
    node id (resolved once by ``_ensure_initialized``) — the flow itself
    stays shared; only the model used for THIS run varies.

Per-project scoping (per the fix brief): grepped the request/session/identity
models (ChatCompletionRequest, the resolved identity dict, backoffice
UserSession) for any project/workspace concept — NONE exists today. Per-user
is implemented fully here; no half-baked per-project key was invented.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_ysg_risk_147_letta_static_peruser.py
# conventions — kept self-contained rather than cross-imported).
# ---------------------------------------------------------------------------


def _make_agent_record(name: str, upstream_url: str, protocol: str = "letta") -> dict:
    return {
        "name": name,
        "upstream_url": upstream_url,
        "protocol": protocol,
        "status": "active",
        "agent_id": f"agnt_{name}",
        "created_at": "2026-01-01T00:00:00+00:00",
        "last_seen_at": "",
        "groups": [],
        "allowed_caller_groups": [],
        "allowed_paths": [],
        "allowed_cidrs": [],
    }


@dataclass
class _ContainerInfo:
    container_id: str
    container_name: str
    identity_id: str
    service_slug: str
    image: str
    endpoint: str
    status: str
    created_at: float
    last_active: float
    health_failures: int = 0


def _make_request() -> MagicMock:
    req = MagicMock(spec=Request)
    headers_mock = MagicMock()
    headers_mock.get = lambda key, default="": (
        "Bearer irrelevant-not-internal" if key.lower() == "authorization" else default
    )
    req.headers = headers_mock
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.scope = {"type": "http", "path": "/v1/chat/completions"}
    req.app = MagicMock()
    req.app.state = MagicMock()
    return req


def _make_state_stubs():
    return {
        "identity_registry": None,
        "sensitivity_classifier": None,
        "complexity_scorer": None,
        "budget_enforcer": None,
        "token_counter": None,
        "optimization_engine": None,
        "audit_writer": None,
        "ollama_url": "http://ollama:11434",
        "default_model": "qwen2.5:3b",
        "available_models": [],
        "agent_registry": None,
        "response_inspection_pipeline": None,
        "ddos_protector": None,
        "pii_detector": None,
        "pii_cloud_bypass": False,
        "opa_url": "",
        "content_relay_detector": None,
        "pool_manager": None,
    }


@pytest.fixture(autouse=True)
def _reset_router_state():
    import os as _os

    old_env = _os.environ.copy()
    _os.environ["YASHIGANI_OPA_OPTIONAL"] = "true"
    _os.environ["YASHIGANI_INTERNAL_BEARER"] = "test-token"
    _os.environ["YASHIGANI_ENV"] = "dev"

    from yashigani.gateway import openai_router as _mod

    orig = {k: getattr(_mod._state, k) for k in vars(_mod._state)}

    yield _mod

    for k, v in orig.items():
        try:
            setattr(_mod._state, k, v)
        except Exception:
            pass

    _os.environ.clear()
    _os.environ.update(old_env)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _identity(identity_id: str, allowed_models: list[str] | None = None) -> dict:
    return {
        "identity_id": identity_id,
        "status": "active",
        "kind": "human",
        "groups": ["users"],
        "allowed_models": allowed_models or [],
        "sensitivity_ceiling": "PUBLIC",
    }


# ===========================================================================
# 1. Unit tests — _resolve_agent_brain_model (pure function, no HTTP)
# ===========================================================================


class TestResolveAgentBrainModelUnit:
    def test_no_identity_returns_default(self, _reset_router_state):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        assert mod._resolve_agent_brain_model(None, "qwen2.5:3b") == "qwen2.5:3b"

    def test_unrestricted_caller_returns_default(self, _reset_router_state):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        identity = _identity("u1", allowed_models=[])
        assert mod._resolve_agent_brain_model(identity, "qwen2.5:3b") == "qwen2.5:3b"

    def test_restricted_caller_allocated_the_default_gets_default(self, _reset_router_state):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        identity = _identity("u1", allowed_models=["qwen2.5:3b"])
        assert mod._resolve_agent_brain_model(identity, "qwen2.5:3b") == "qwen2.5:3b"

    def test_restricted_caller_allocated_other_local_model_gets_that_model(
        self, _reset_router_state
    ):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        identity = _identity("u1", allowed_models=["llama3:8b"])
        assert mod._resolve_agent_brain_model(identity, "qwen2.5:3b") == "llama3:8b"

    def test_two_users_different_allocations_get_different_models(self, _reset_router_state):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        alice = _identity("alice", allowed_models=["llama3:8b"])
        bob = _identity("bob", allowed_models=["phi3:mini"])
        alice_model = mod._resolve_agent_brain_model(alice, "qwen2.5:3b")
        bob_model = mod._resolve_agent_brain_model(bob, "qwen2.5:3b")
        assert alice_model == "llama3:8b"
        assert bob_model == "phi3:mini"
        assert alice_model != bob_model

    def test_restricted_caller_with_no_usable_local_model_raises(self, _reset_router_state):
        mod = _reset_router_state
        mod.configure(**_make_state_stubs())
        # Only a provider-qualified (cloud-shaped) model allocated -- the
        # bare-name local-fallback pass in pick_allowed_local_default
        # excludes any name containing "/".
        identity = _identity("u1", allowed_models=["openai/gpt-4o"])
        with pytest.raises(mod.ModelNotAllocatedError):
            mod._resolve_agent_brain_model(identity, "qwen2.5:3b")


# ===========================================================================
# 2. Static @letta path — per-user brain model reaches agent creation
# ===========================================================================


class _FakeLettaServer:
    """Captures (name, model) passed at agent-creation time."""

    def __init__(self):
        self.agents_by_endpoint: dict[str, list[dict]] = {}
        self.create_calls: list[tuple[str, str, str]] = []  # (endpoint, name, model)

    def client_for(self, endpoint: str):
        server = self

        async def _get(url, *a, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.json = MagicMock(return_value=server.agents_by_endpoint.get(endpoint, []))
            return resp

        async def _post(url, *a, **kw):
            resp = MagicMock()
            if url.endswith("/v1/agents/"):
                body = kw.get("json", {})
                name = body.get("name", "")
                model = body.get("model", "")
                agent_id = f"agent-{endpoint}-{name}"
                server.agents_by_endpoint.setdefault(endpoint, []).append(
                    {"id": agent_id, "name": name}
                )
                server.create_calls.append((endpoint, name, model))
                resp.status_code = 200
                resp.json = MagicMock(return_value={"id": agent_id})
            elif "/messages" in url:
                resp.status_code = 200
                resp.json = MagicMock(
                    return_value={
                        "messages": [
                            {"message_type": "assistant_message", "content": f"reply-{url}"}
                        ],
                        "usage": {},
                    }
                )
            else:
                resp.status_code = 404
                resp.json = MagicMock(return_value={})
            return resp

        client = MagicMock()
        client.get = AsyncMock(side_effect=_get)
        client.post = AsyncMock(side_effect=_post)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        return client


def _pool_manager_for(server: _FakeLettaServer, endpoint_by_identity: dict[str, str]):
    pm = MagicMock()

    def _goc(identity_id, service_slug, image=None, **kw):
        endpoint = endpoint_by_identity[identity_id]
        return _ContainerInfo(
            container_id=f"stub-{identity_id}",
            container_name=f"ysg-letta-{identity_id}",
            identity_id=identity_id,
            service_slug=service_slug or "letta",
            image=image or "letta",
            endpoint=endpoint,
            status="running",
            created_at=1700000000.0,
            last_active=1700000000.0,
        )

    pm.get_or_create = MagicMock(side_effect=_goc)
    return pm


class TestStaticLettaPathPerUserModel:
    def test_allocated_user_agent_created_with_their_model_not_global_default(
        self, _reset_router_state
    ):
        mod = _reset_router_state

        server = _FakeLettaServer()
        alice_id = "alice-uuid-1111"
        endpoint_by_identity = {alice_id: "172.18.0.10:8283"}
        pool_manager = _pool_manager_for(server, endpoint_by_identity)

        agent_registry = MagicMock()
        agent_registry._r = MagicMock()
        agent_registry._r.hget.return_value = None
        agent_registry.list_all.return_value = [
            _make_agent_record("letta", "https://caddy:9775/agents/default/letta"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        def _client_ctor(*a, **kw):
            router = MagicMock()

            async def _dispatch_get(url, *a2, **kw2):
                for endpoint in endpoint_by_identity.values():
                    if endpoint in url:
                        return await server.client_for(endpoint).get(url)
                raise AssertionError(f"unexpected GET {url}")

            async def _dispatch_post(url, *a2, **kw2):
                for endpoint in endpoint_by_identity.values():
                    if endpoint in url:
                        return await server.client_for(endpoint).post(url, *a2, **kw2)
                raise AssertionError(f"unexpected POST {url}")

            router.get = AsyncMock(side_effect=_dispatch_get)
            router.post = AsyncMock(side_effect=_dispatch_post)
            router.__aenter__ = AsyncMock(return_value=router)
            router.__aexit__ = AsyncMock(return_value=None)
            return router

        request = _make_request()
        body = ChatCompletionRequest(
            model="@letta", messages=[ChatMessage(role="user", content="hi")]
        )

        # Alice is allocated ONLY "llama3:8b" -- NOT the global default
        # ("qwen2.5:3b" behind YASHIGANI_LETTA_BRAIN_MODEL's default handle).
        with (
            patch.object(
                mod, "_resolve_identity",
                return_value=_identity(alice_id, allowed_models=["llama3:8b"]),
            ),
            patch("httpx.AsyncClient", side_effect=_client_ctor),
        ):
            result = _run(mod.chat_completions(body, request))

        assert not isinstance(result, JSONResponse) or result.status_code == 200
        assert len(server.create_calls) == 1
        _endpoint, _name, model = server.create_calls[0]
        assert model == "openai-proxy/llama3:8b"
        assert model != "openai-proxy/qwen2.5:3b"  # never the global default

    def test_restricted_user_with_no_usable_local_model_gets_403_no_agent_created(
        self, _reset_router_state
    ):
        mod = _reset_router_state

        server = _FakeLettaServer()
        bob_id = "bob-uuid-22222"
        endpoint_by_identity = {bob_id: "172.18.0.11:8283"}
        pool_manager = _pool_manager_for(server, endpoint_by_identity)

        agent_registry = MagicMock()
        agent_registry._r = MagicMock()
        agent_registry._r.hget.return_value = None
        agent_registry.list_all.return_value = [
            _make_agent_record("letta", "https://caddy:9775/agents/default/letta"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        request = _make_request()
        body = ChatCompletionRequest(
            model="@letta", messages=[ChatMessage(role="user", content="hi")]
        )

        # Bob is allocated ONLY a provider-qualified (non-local) model --
        # never allocated the default and no local fallback exists.
        with patch.object(
            mod, "_resolve_identity",
            return_value=_identity(bob_id, allowed_models=["openai/gpt-4o"]),
        ):
            result = _run(mod.chat_completions(body, request))

        assert isinstance(result, JSONResponse)
        assert result.status_code == 403
        import json as _json
        payload = _json.loads(bytes(result.body).decode())
        assert payload["error"]["code"] == "model_not_allocated"
        # Fail-safe: no agent was ever created for the denied model.
        assert server.create_calls == []
        pool_manager.get_or_create.assert_not_called()


# ===========================================================================
# 3. Langflow flow-run path — per-user model override via tweaks
# ===========================================================================


class TestLangflowPathPerUserModel:
    def test_allocated_user_run_overrides_model_via_tweaks(self, _reset_router_state):
        mod = _reset_router_state

        agent_registry = MagicMock()
        agent_registry._r = MagicMock()
        agent_registry._r.hget.return_value = None
        agent_registry.list_all.return_value = [
            _make_agent_record(
                "langflow", "https://caddy:9705/agents/default/langflow", protocol="langflow"
            ),
        ]

        stubs = _make_state_stubs()
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        request = _make_request()
        body = ChatCompletionRequest(
            model="@langflow", messages=[ChatMessage(role="user", content="hi")]
        )

        fake_langflow_chat = AsyncMock(
            return_value={
                "choices": [{"message": {"role": "assistant", "content": "lf-ok"}}],
                "usage": {},
            }
        )

        with (
            patch.object(
                mod, "_resolve_identity",
                return_value=_identity("carol", allowed_models=["phi3:mini"]),
            ),
            patch("yashigani.gateway.langflow_client.langflow_chat", fake_langflow_chat),
        ):
            result = _run(mod.chat_completions(body, request))

        assert not isinstance(result, JSONResponse) or result.status_code == 200
        fake_langflow_chat.assert_awaited_once()
        assert fake_langflow_chat.await_args.kwargs["model"] == "phi3:mini"

    def test_unrestricted_user_gets_global_default_model(self, _reset_router_state):
        mod = _reset_router_state

        agent_registry = MagicMock()
        agent_registry._r = MagicMock()
        agent_registry._r.hget.return_value = None
        agent_registry.list_all.return_value = [
            _make_agent_record(
                "langflow", "https://caddy:9705/agents/default/langflow", protocol="langflow"
            ),
        ]

        stubs = _make_state_stubs()
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage
        from yashigani.gateway.langflow_client import _DEFAULT_MODEL

        request = _make_request()
        body = ChatCompletionRequest(
            model="@langflow", messages=[ChatMessage(role="user", content="hi")]
        )

        fake_langflow_chat = AsyncMock(
            return_value={
                "choices": [{"message": {"role": "assistant", "content": "lf-ok"}}],
                "usage": {},
            }
        )

        with (
            patch.object(
                mod, "_resolve_identity",
                return_value=_identity("dave", allowed_models=[]),
            ),
            patch("yashigani.gateway.langflow_client.langflow_chat", fake_langflow_chat),
        ):
            result = _run(mod.chat_completions(body, request))

        assert not isinstance(result, JSONResponse) or result.status_code == 200
        fake_langflow_chat.assert_awaited_once()
        assert fake_langflow_chat.await_args.kwargs["model"] == _DEFAULT_MODEL
