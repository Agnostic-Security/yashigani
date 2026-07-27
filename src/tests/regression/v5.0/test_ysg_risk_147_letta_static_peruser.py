"""
Regression test — YSG-RISK-147: the static/globally-registered @letta agent
path routed EVERY caller through ONE shared Letta agent -> cross-user memory
bleed.

Background:
  RISK-107 (4.0 Phase 3) introduced LettaClientPool for per-user Letta
  container + agent isolation, but it was only wired into the persona/pool
  @-alias branch of chat_completions() (openai_router.py, the
  ``_ua_kind == "persona"`` block, ~line 2749). The STATIC path — an agent
  registered in agent_registry with protocol="letta" and a plain (non
  pool://) upstream_url, reached via @<agent_name> when no per-user alias
  matches — still called the module-level ``letta_chat()`` /
  ``_ensure_agent()`` in letta_client.py, which caches a SINGLE
  "yashigani-default" agent (module-global ``_default_agent_id``) for the
  ENTIRE process. Two different users hitting the static @letta path shared
  the same Letta agent and its persistent memory.

Fix (openai_router.py, buffered agent-call branch, ``agent_protocol ==
"letta"``): when the request carries a real user identity
(identity_id not None/"internal") AND a PoolManager is configured, route
through the SAME ``LettaClientPool.letta_chat(user_id=identity_id, ...)``
the persona path uses, instead of the shared module-level ``letta_chat()``.
The module-level shared path is retained ONLY as the fallback for
non-identified (internal/system) traffic or deployments with no PoolManager.

This test proves, via the full ``chat_completions()`` request/response path
(agent_registry + pool_manager mocked, httpx.AsyncClient intercepted):
  1. Two different users hitting the same static @letta agent name get
     DIFFERENT Letta agent ids/names — never the shared "yashigani-default".
  2. A single user's second call reuses the agent the (mocked) Letta
     container already reports for their name (no re-create, same id).
  3. pool_manager.get_or_create() is invoked keyed on the CALLING user's
     identity_id (container-level isolation), not a static/shared identity.
  4. The persona/pool @-alias path (RISK-107's original fix) is untouched —
     it still resolves via LettaClientPool.for_user() exactly as before.
  5. When no user identity is present (identity_id == "internal"), the
     legacy shared module-level letta_chat()/_ensure_agent() path is used
     (no per-user pool possible for non-identified traffic; not a
     regression — RISK-147 only requires per-user isolation for identified
     users, per the fix brief).
"""
from __future__ import annotations

import asyncio
import json as _json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Helpers (mirrors src/tests/unit/test_pool_dispatch_wiring.py conventions)
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
    """Minimal ASGI request stub — identity comes from a patched
    _resolve_identity, not the bearer, so any header value is fine."""
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


def _identity(identity_id: str) -> dict:
    return {
        "identity_id": identity_id,
        "status": "active",
        "kind": "human",
        "groups": ["users"],
        "allowed_models": [],
        "sensitivity_ceiling": "PUBLIC",
    }


# ---------------------------------------------------------------------------
# Fake stateful Letta container HTTP server, shared per container endpoint —
# models the REAL Letta container's persistent agent store (survives across
# separate request-scoped LettaClientPool() instances, exactly like the
# production Letta container's own DB persists across gateway requests).
# ---------------------------------------------------------------------------


class _FakeLettaServer:
    """agents_by_endpoint: endpoint -> list[{"id":..., "name":...}]"""

    def __init__(self):
        self.agents_by_endpoint: dict[str, list[dict]] = {}
        self.create_calls: list[tuple[str, str]] = []  # (endpoint, name)

    def client_for(self, endpoint: str):
        server = self

        async def _get(url, *a, **kw):
            resp = MagicMock()
            resp.status_code = 200
            resp.json = MagicMock(
                return_value=server.agents_by_endpoint.get(endpoint, [])
            )
            return resp

        async def _post(url, *a, **kw):
            resp = MagicMock()
            if url.endswith("/v1/agents/"):
                name = kw.get("json", {}).get("name", "")
                agent_id = f"agent-{endpoint}-{name}"
                server.agents_by_endpoint.setdefault(endpoint, []).append(
                    {"id": agent_id, "name": name}
                )
                server.create_calls.append((endpoint, name))
                resp.status_code = 200
                resp.json = MagicMock(return_value={"id": agent_id})
            elif "/messages" in url:
                resp.status_code = 200
                resp.json = MagicMock(
                    return_value={
                        "messages": [
                            {
                                "message_type": "assistant_message",
                                "content": f"reply-from-{url}",
                            }
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
    """PoolManager.get_or_create() stub keyed by identity_id -> fixed endpoint,
    so each user resolves to its own (fake) container -- and the mocked
    httpx.AsyncClient() constructor dispatches to that container's fake
    server based on which base_url is dialled."""
    pm = MagicMock()

    def _goc(identity_id, service_slug, image=None, **kw):
        endpoint = endpoint_by_identity[identity_id]
        info = _ContainerInfo(
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
        return info

    pm.get_or_create = MagicMock(side_effect=_goc)
    return pm


# ---------------------------------------------------------------------------
# 1 + 3. Two different users -> different agent ids/names, different
#          containers (get_or_create keyed on the calling identity_id)
# ---------------------------------------------------------------------------


class TestStaticLettaPathPerUserIsolation:
    def test_two_users_get_different_agents_not_shared_default(self, _reset_router_state):
        mod = _reset_router_state

        server = _FakeLettaServer()
        alice_id = "alice-uuid-1111"
        bob_id = "bob-uuid-22222"
        endpoint_by_identity = {
            alice_id: "172.18.0.10:8283",
            bob_id: "172.18.0.11:8283",
        }
        pool_manager = _pool_manager_for(server, endpoint_by_identity)

        agent_registry = MagicMock()
        # No per-user alias entry for either user -> falls through to the
        # global/static registry lookup (the RISK-147 gap).
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
            # httpx.AsyncClient(...) is constructed fresh inside
            # LettaClientPool.letta_chat(); we can't know the endpoint from
            # the constructor call alone, so return a router client that
            # inspects the URL at request time.
            router = MagicMock()

            async def _dispatch_get(url, *a2, **kw2):
                for endpoint, agents in server.agents_by_endpoint.items():
                    if endpoint in url:
                        return await server.client_for(endpoint).get(url)
                # unseen endpoint -> empty agent list
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
        body_alice = ChatCompletionRequest(
            model="@letta", messages=[ChatMessage(role="user", content="hi from alice")]
        )
        body_bob = ChatCompletionRequest(
            model="@letta", messages=[ChatMessage(role="user", content="hi from bob")]
        )

        with (
            patch.object(mod, "_resolve_identity", return_value=_identity(alice_id)),
            patch("httpx.AsyncClient", side_effect=_client_ctor),
        ):
            _run(mod.chat_completions(body_alice, request))

        with (
            patch.object(mod, "_resolve_identity", return_value=_identity(bob_id)),
            patch("httpx.AsyncClient", side_effect=_client_ctor),
        ):
            _run(mod.chat_completions(body_bob, request))

        # -- Container-level isolation: get_or_create called per identity --
        called_identities = {c.kwargs["identity_id"] for c in pool_manager.get_or_create.call_args_list}
        assert called_identities == {alice_id, bob_id}

        # -- Agent-level isolation: distinct agent NAMEs were created, and
        #    NEITHER is the shared "yashigani-default" name. --
        created_names = {name for (_ep, name) in server.create_calls}
        assert created_names == {
            f"yashigani-{alice_id[:8]}",
            f"yashigani-{bob_id[:8]}",
        }
        assert "yashigani-default" not in created_names

        # -- Distinct agent ids (derived from distinct endpoint+name pairs) --
        alice_agents = server.agents_by_endpoint[endpoint_by_identity[alice_id]]
        bob_agents = server.agents_by_endpoint[endpoint_by_identity[bob_id]]
        assert len(alice_agents) == 1 and len(bob_agents) == 1
        assert alice_agents[0]["id"] != bob_agents[0]["id"]

    def test_same_user_second_call_reuses_existing_agent_no_recreate(
        self, _reset_router_state
    ):
        mod = _reset_router_state

        server = _FakeLettaServer()
        alice_id = "alice-uuid-1111"
        endpoint = "172.18.0.10:8283"
        pool_manager = _pool_manager_for(server, {alice_id: endpoint})

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
                return await server.client_for(endpoint).get(url)

            async def _dispatch_post(url, *a2, **kw2):
                return await server.client_for(endpoint).post(url, *a2, **kw2)

            router.get = AsyncMock(side_effect=_dispatch_get)
            router.post = AsyncMock(side_effect=_dispatch_post)
            router.__aenter__ = AsyncMock(return_value=router)
            router.__aexit__ = AsyncMock(return_value=None)
            return router

        request = _make_request()
        body = ChatCompletionRequest(
            model="@letta", messages=[ChatMessage(role="user", content="turn 1")]
        )

        with (
            patch.object(mod, "_resolve_identity", return_value=_identity(alice_id)),
            patch("httpx.AsyncClient", side_effect=_client_ctor),
        ):
            _run(mod.chat_completions(body, request))
            # Second call — a NEW request-scoped LettaClientPool is
            # constructed (mirroring the persona path's own per-request
            # instantiation), so reuse must come from the container's own
            # persistent agent list, exactly as production behaves.
            body2 = ChatCompletionRequest(
                model="@letta", messages=[ChatMessage(role="user", content="turn 2")]
            )
            _run(mod.chat_completions(body2, request))

        # Only ONE create call for alice -- the second request found the
        # existing agent via GET /v1/agents/ and reused it.
        assert server.create_calls == [(endpoint, f"yashigani-{alice_id[:8]}")]
        assert len(server.agents_by_endpoint[endpoint]) == 1


# ---------------------------------------------------------------------------
# 5. No user identity (internal/system caller) -> legacy shared module path,
#    unchanged (not a regression -- RISK-147 only requires per-user
#    isolation for IDENTIFIED user traffic).
# ---------------------------------------------------------------------------


class TestStaticLettaPathNoIdentityFallback:
    def test_internal_identity_uses_legacy_shared_letta_chat(self, _reset_router_state):
        mod = _reset_router_state

        pool_manager = MagicMock()
        agent_registry = MagicMock()
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
            model="@letta", messages=[ChatMessage(role="user", content="internal call")]
        )

        fake_module_letta_chat = AsyncMock(
            return_value={
                "choices": [{"message": {"role": "assistant", "content": "shared-ok"}}],
                "usage": {},
            }
        )

        with (
            patch.object(mod, "_resolve_identity", return_value=_identity("internal")),
            patch(
                "yashigani.gateway.letta_client.letta_chat",
                fake_module_letta_chat,
            ),
        ):
            result = _run(mod.chat_completions(body, request))

        fake_module_letta_chat.assert_awaited_once()
        assert fake_module_letta_chat.await_args.kwargs["base_url"] == (
            "https://caddy:9775/agents/default/letta"
        )
        pool_manager.get_or_create.assert_not_called()
        assert not isinstance(result, JSONResponse) or result.status_code != 502


# ---------------------------------------------------------------------------
# 4. Persona/pool @-alias path (RISK-107's original fix) is UNCHANGED --
#    still resolves the per-user Letta container via LettaClientPool.for_user()
#    exactly as before the RISK-147 fix (which only touches the static path).
# ---------------------------------------------------------------------------


class TestPersonaPathUnchanged:
    def test_persona_alias_still_routes_via_letta_client_pool_for_user(
        self, _reset_router_state
    ):
        mod = _reset_router_state

        alice_id = "alice-uuid-1111"
        pool_manager = MagicMock()

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = []

        raw_meta = {
            "account_id": alice_id,
            "kind": "persona",
            "personality": "{}",
            "letta_agent_id": "",
        }

        def _hget(key, field):
            if key == f"ua:alias:{alice_id}" and field == "buddy":
                return "ua-1"
            return None

        def _hgetall(key):
            if key == "ua:meta:ua-1":
                return dict(raw_meta)
            return {}

        agent_registry._r = MagicMock()
        agent_registry._r.hget = MagicMock(side_effect=_hget)
        agent_registry._r.hgetall = MagicMock(side_effect=_hgetall)

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        request = _make_request()
        body = ChatCompletionRequest(
            model="@buddy", messages=[ChatMessage(role="user", content="hi buddy")]
        )

        fake_client = MagicMock()
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json = MagicMock(
            return_value={
                "messages": [
                    {"message_type": "assistant_message", "content": "persona-reply"}
                ]
            }
        )
        fake_client.post = AsyncMock(return_value=fake_resp)
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=None)

        fake_for_user = AsyncMock(
            return_value=(fake_client, "http://172.18.0.20:8283", "persona-agent-id")
        )

        with (
            patch.object(mod, "_resolve_identity", return_value=_identity(alice_id)),
            patch(
                "yashigani.gateway.letta_client.LettaClientPool.for_user",
                fake_for_user,
            ),
        ):
            result = _run(mod.chat_completions(body, request))

        fake_for_user.assert_awaited_once_with(alice_id)
        assert not isinstance(result, JSONResponse) or result.status_code == 200
