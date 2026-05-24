"""
Unit tests -- PoolManager dispatch wiring in openai_router.py.

v2.4.1 -- PoolManager wiring: container-per-identity dispatch via pool:// upstream.

Coverage:
  1. Pool-managed agent dispatch calls PoolManager.get_or_create() and routes to
     the returned ContainerInfo.endpoint.
  2. Non-pool agent dispatch bypasses PoolManager entirely (regression).
  3. PoolLimitExceeded returns HTTP 402 with the expected error body.
  4. Identity (identity_id) is propagated correctly to get_or_create().
  5. PoolManager=None (unavailable) returns HTTP 502 pool_backend_unavailable.
  6. ContainerBackend exception during get_or_create() returns HTTP 502.

Identity resolution strategy: use the YASHIGANI_INTERNAL_BEARER value so
_resolve_identity() takes the fast-path (internal service identity), bypassing
Redis/registry. This avoids mock complexity on the request Headers object.
The internal identity has identity_id="internal".
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent_record(name: str, upstream_url: str, protocol: str = "openai") -> dict:
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


def _make_container_info(identity_id: str, agent_name: str, image: str) -> _ContainerInfo:
    return _ContainerInfo(
        container_id="stub-abc123",
        container_name=f"ysg-{agent_name}-{identity_id[-4:]}-aabbcc",
        identity_id=identity_id,
        service_slug=agent_name,
        image=image,
        endpoint="172.17.0.5:8080",
        status="starting",
        created_at=1700000000.0,
        last_active=1700000000.0,
    )


def _make_request() -> MagicMock:
    """Minimal ASGI request stub authenticated via the internal bearer."""
    bearer = os.environ.get("YASHIGANI_INTERNAL_BEARER", "test-token")
    req = MagicMock(spec=Request)
    # Use a MagicMock for headers that supports case-insensitive get
    headers_mock = MagicMock()
    headers_mock.get = lambda key, default="": (
        f"Bearer {bearer}" if key.lower() == "authorization" else default
    )
    req.headers = headers_mock
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.scope = {"type": "http", "path": "/v1/chat/completions"}
    req.app = MagicMock()
    req.app.state = MagicMock()
    return req


def _make_state_stubs():
    """Return a dict of kwargs for configure() that stubs out everything
    except pool_manager and agent_registry (set by each test)."""
    return {
        "identity_registry": None,  # internal bearer bypasses registry
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_router_state():
    """Configure openai_router._state for each test and restore after."""
    import os as _os

    old_env = _os.environ.copy()
    _os.environ["YASHIGANI_OPA_OPTIONAL"] = "true"
    _os.environ["YASHIGANI_INTERNAL_BEARER"] = "test-token"
    _os.environ["YASHIGANI_ENV"] = "dev"

    from yashigani.gateway import openai_router as _mod

    # Snapshot original state values
    orig = {k: getattr(_mod._state, k) for k in vars(_mod._state)}

    yield _mod

    # Restore
    for k, v in orig.items():
        try:
            setattr(_mod._state, k, v)
        except Exception:
            pass

    _os.environ.clear()
    _os.environ.update(old_env)


# ---------------------------------------------------------------------------
# Helpers for async execution
# ---------------------------------------------------------------------------


def _run(coro):
    """Run a coroutine in a new event loop (tests may be called from sync)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Mock for buffered agent HTTP call
# ---------------------------------------------------------------------------


def _mock_httpx_client(response_dict: dict):
    """Return a context-manager mock for httpx.AsyncClient that returns canned response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = response_dict

    async def _fake_post(*a, **kw):
        return resp

    mock_client = MagicMock()
    mock_client.post = _fake_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    mock_cls = MagicMock(return_value=mock_client)
    return mock_cls


_GOOD_RESPONSE = {
    "choices": [{"message": {"role": "assistant", "content": "Hello"}}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    "model": "goose",
    "id": "chatcmpl-test",
    "created": 1700000000,
}


# ---------------------------------------------------------------------------
# Test 1 — Pool-managed agent dispatch calls get_or_create()
# ---------------------------------------------------------------------------


class TestPoolDispatch:
    def test_pool_managed_agent_calls_get_or_create(self, _reset_router_state):
        """
        When an agent has upstream_url='pool://ghcr.io/myco/goose:latest',
        chat_completions must call pool_manager.get_or_create() with the
        correct identity_id, service_slug, and image.
        """
        mod = _reset_router_state

        pool_manager = MagicMock()
        container = _make_container_info("internal", "goose", "ghcr.io/myco/goose:latest")
        pool_manager.get_or_create.return_value = container
        pool_manager._limits.total_concurrent = 3
        pool_manager.count.return_value = 1

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("goose", "pool://ghcr.io/myco/goose:latest"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@goose",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        with patch("httpx.AsyncClient", _mock_httpx_client(_GOOD_RESPONSE)):
            _run(mod.chat_completions(body, request))

        pool_manager.get_or_create.assert_called_once_with(
            identity_id="internal",
            service_slug="goose",
            image="ghcr.io/myco/goose:latest",
        )

    def test_non_pool_agent_bypasses_pool_manager(self, _reset_router_state):
        """
        A normal externally-deployed agent (http:// upstream) must NOT
        call pool_manager.get_or_create().
        """
        mod = _reset_router_state

        pool_manager = MagicMock()
        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("openclaw", "http://openclaw:8080"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@openclaw",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        with patch("httpx.AsyncClient", _mock_httpx_client(_GOOD_RESPONSE)):
            _run(mod.chat_completions(body, request))

        pool_manager.get_or_create.assert_not_called()

    def test_pool_limit_exceeded_returns_402(self, _reset_router_state):
        """
        PoolLimitExceeded from get_or_create() must produce HTTP 402
        with error='pool_limit_exceeded'.
        """
        mod = _reset_router_state

        from yashigani.pool.manager import PoolLimitExceeded

        pool_manager = MagicMock()
        pool_manager.get_or_create.side_effect = PoolLimitExceeded("limit=3 current=3")
        pool_manager._limits.total_concurrent = 3
        pool_manager.count.return_value = 3

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("goose", "pool://ghcr.io/myco/goose:latest"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@goose",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        result = _run(mod.chat_completions(body, request))

        assert isinstance(result, JSONResponse)
        assert result.status_code == 402
        import json
        body_dict = json.loads(result.body)
        assert body_dict["error"] == "pool_limit_exceeded"
        assert body_dict["limit"] == 3

    def test_identity_id_propagated_to_get_or_create(self, _reset_router_state):
        """
        The identity_id resolved from the request (here: 'internal' via the
        internal bearer) must be forwarded to get_or_create() unchanged.
        """
        mod = _reset_router_state

        pool_manager = MagicMock()
        container = _make_container_info("internal", "goose", "ghcr.io/myco/goose:latest")
        pool_manager.get_or_create.return_value = container
        pool_manager._limits.total_concurrent = 3
        pool_manager.count.return_value = 0

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("goose", "pool://ghcr.io/myco/goose:latest"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@goose",
            messages=[ChatMessage(role="user", content="identity test")],
        )

        with patch("httpx.AsyncClient", _mock_httpx_client(_GOOD_RESPONSE)):
            _run(mod.chat_completions(body, request))

        call_kwargs = pool_manager.get_or_create.call_args
        assert call_kwargs.kwargs["identity_id"] == "internal"

    def test_pool_manager_none_returns_502(self, _reset_router_state):
        """
        When pool_manager is None (backend unavailable), a pool-managed
        agent dispatch must return HTTP 502 with code='pool_backend_unavailable'.
        """
        mod = _reset_router_state

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("goose", "pool://ghcr.io/myco/goose:latest"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = None  # unavailable
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@goose",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        result = _run(mod.chat_completions(body, request))

        assert isinstance(result, JSONResponse)
        assert result.status_code == 502
        import json
        body_dict = json.loads(result.body)
        assert body_dict["error"]["code"] == "pool_backend_unavailable"

    def test_backend_exception_returns_502(self, _reset_router_state):
        """
        An unexpected exception from get_or_create() must return HTTP 502
        and must NOT propagate the exception to the caller.
        """
        mod = _reset_router_state

        pool_manager = MagicMock()
        pool_manager.get_or_create.side_effect = RuntimeError("docker socket unavailable")
        pool_manager._limits.total_concurrent = 3
        pool_manager.count.return_value = 0

        agent_registry = MagicMock()
        agent_registry.list_all.return_value = [
            _make_agent_record("goose", "pool://ghcr.io/myco/goose:latest"),
        ]

        stubs = _make_state_stubs()
        stubs["pool_manager"] = pool_manager
        stubs["agent_registry"] = agent_registry
        mod.configure(**stubs)

        request = _make_request()
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="@goose",
            messages=[ChatMessage(role="user", content="Hello")],
        )

        result = _run(mod.chat_completions(body, request))

        assert isinstance(result, JSONResponse)
        assert result.status_code == 502
        import json
        body_dict = json.loads(result.body)
        assert body_dict["error"]["code"] == "pool_backend_unavailable"
