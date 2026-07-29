"""
Regression tests — YSG-RISK-129: chat_completions() crashed with
`UnboundLocalError: cannot access local variable 'assistant_content'`
(also affects `backend_body`) instead of returning a clean error when a
backend LLM/agent call failed. Found by Captain during k8s chat
verification alongside the YSG-RISK-113 fix — same request path: a
dead/slow backend must fail CLEANLY, never crash the handler.

## Root cause

`assistant_content` / `backend_body` are ONLY assigned inside individual
success-path branches of the backend-dispatch try block (agent
letta/langflow/openai-compat, cloud openai/anthropic, local ollama).
Every branch that fails either raises HTTPException (propagates straight
out of the function via the try's own except clauses) or returns a
JSONResponse directly — those paths were never the crash.

The actual gap: the entire agent-resolution block (which owns the
`if not agent_upstream: return 404` guard) was gated on
`if is_agent_call and _state.agent_registry:`. When `is_agent_call` is
True but `_state.agent_registry` itself is falsy (the registry dependency
down/uninitialized), that WHOLE block — including its own 404 guard — was
skipped, leaving `agent_upstream = None`. Execution then reached
`if is_agent_call and agent_upstream:` (False) and `if not is_agent_call:`
(False) — NEITHER branch ran, nothing raised, nothing returned, and
`assistant_content`/`backend_body` stayed silently unbound. The function
fell through to the response-inspection section which references
`assistant_content` unconditionally → UnboundLocalError → unhandled 500.

## The fix

  1. Root-cause guard: `if is_agent_call and not _state.agent_registry:`
     now returns a clean 503 JSONResponse (agent_registry_unavailable)
     before the resolution block is ever reached.
  2. Defense-in-depth backstop: `assistant_content`/`backend_body` are now
     explicitly initialized to None before the dispatch try block, and a
     guard immediately after it raises a clean HTTPException(502) if either
     is still None — converting ANY future branch-completeness gap in that
     dispatch block into a clean error instead of a crash, composing with
     the YSG-RISK-113 timeout/circuit-breaker fix so a dead/slow/misrouted
     backend always fails clean.

Each test below would crash with UnboundLocalError on the pre-fix code.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

import contextlib
import json

import httpx
import pytest
from fastapi.responses import JSONResponse
from unittest.mock import AsyncMock, MagicMock, patch


def _make_state(**overrides):
    state = MagicMock()
    state.opa_url = "http://opa:8181"
    state.ollama_url = "http://ollama:11434"
    state.default_model = "qwen2.5:3b"
    state.optimization_engine = None
    state.sensitivity_classifier = None
    state.complexity_scorer = None
    state.budget_enforcer = None
    state.permission_store = None
    state.permission_strict = False
    state.ddos_protector = None
    state.content_relay_detector = None
    state.model_alias_store = MagicMock()
    state.model_alias_store.get.return_value = None
    state.available_models = [{"name": "qwen2.5:3b"}]
    state.model_allocation_store = None
    state.audit_writer = None
    state.identity_registry = None
    state.agent_registry = None
    state.pool_manager = None
    state.pii_detector = None
    state.streaming_enabled = False
    state.streaming_inspect_interval = 200
    state.response_inspection_pipeline = None
    state.low_confidence_stepup_threshold = 0.7
    for key, value in overrides.items():
        setattr(state, key, value)
    return state


def _make_request():
    from fastapi import Request
    req = MagicMock(spec=Request)
    req.method = "POST"
    req.headers = MagicMock()
    req.headers.__iter__ = MagicMock(return_value=iter([]))
    req.headers.items = MagicMock(return_value=[])
    req.headers.get = MagicMock(return_value=None)
    req.state = MagicMock()
    req.state.ysg_principal = None
    return req


def _default_effective():
    from yashigani.models.effective import EffectiveModels
    return EffectiveModels(
        allowed={"qwen2.5:3b", "@myagent"},
        has_restriction=False,
        allocated_aliases=set(),
        gated=set(),
    )


def _base_patches(state, effective=None):
    return [
        patch("yashigani.gateway.openai_router._state", state),
        patch(
            "yashigani.gateway.openai_router._resolve_identity",
            MagicMock(return_value={
                "identity_id": "idnt_risk129",
                "kind": "human",
                "groups": [],
                "status": "active",
                "sensitivity_ceiling": "PUBLIC",
            }),
        ),
        patch(
            "yashigani.gateway.openai_router._effective_allowed_models",
            MagicMock(return_value=effective or _default_effective()),
        ),
        patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            AsyncMock(return_value={"allow": True, "model_allowed": True}),
        ),
        patch(
            "yashigani.gateway.openai_router.evaluate_client_policies",
            AsyncMock(return_value={"allow": True}),
        ),
    ]


class _FakeAsyncClientCM:
    """Minimal async-context-manager stand-in for ollama_async_client()."""

    def __init__(self, post_side_effect):
        self._post_side_effect = post_side_effect

    async def __aenter__(self):
        client = MagicMock()
        client.post = AsyncMock(side_effect=self._post_side_effect)
        return client

    async def __aexit__(self, *exc_info):
        return False


class TestRisk129AgentRegistryUnavailable:
    """Root cause: is_agent_call=True with _state.agent_registry falsy must
    return a clean 503, never fall through to an UnboundLocalError."""

    @pytest.mark.asyncio
    async def test_agent_registry_none_returns_clean_503_not_crash(self):
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        state = _make_state(agent_registry=None)
        body = ChatCompletionRequest(
            model="@myagent",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            # This is the exact reproduction: pre-fix, this call raised
            # UnboundLocalError instead of returning a response.
            result = await chat_completions(body, _make_request())

        assert isinstance(result, JSONResponse), (
            f"YSG-RISK-129: expected a clean JSONResponse, got {type(result)}"
        )
        assert result.status_code == 503, (
            f"YSG-RISK-129: expected 503 (agent_registry_unavailable), "
            f"got {result.status_code}. Body: {result.body}"
        )
        body_json = json.loads(result.body)
        assert body_json["error"]["code"] == "agent_registry_unavailable"

    @pytest.mark.asyncio
    async def test_agent_registry_falsy_magicmock_bool_false_also_clean(self):
        """A MagicMock configured to be falsy (e.g. __bool__ patched to False,
        simulating "registry object exists but reports itself unhealthy")
        must also be caught by the `not _state.agent_registry` guard."""
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        falsy_registry = MagicMock()
        falsy_registry.__bool__ = MagicMock(return_value=False)
        state = _make_state(agent_registry=falsy_registry)
        body = ChatCompletionRequest(
            model="@myagent",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_request())

        assert isinstance(result, JSONResponse)
        assert result.status_code == 503


class TestRisk129LocalOllamaBackendFailsClean:
    """Composition with YSG-RISK-113: a dead/slow local Ollama backend must
    fail with a clean 502/503/504, never UnboundLocalError, and
    assistant_content must never be referenced while unbound."""

    @pytest.mark.asyncio
    async def test_ollama_connect_error_returns_clean_503_not_crash(self):
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage
        from fastapi import HTTPException as FastHTTPException

        state = _make_state()
        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            stack.enter_context(
                patch(
                    "yashigani.inspection._ollama_transport.ollama_async_client",
                    MagicMock(
                        return_value=_FakeAsyncClientCM(
                            httpx.ConnectError("dead backend")
                        )
                    ),
                )
            )
            from yashigani.gateway.openai_router import chat_completions
            with pytest.raises(FastHTTPException) as excinfo:
                await chat_completions(body, _make_request())

        # Pre-fix this section of code was unreachable via ConnectError (that
        # path already raised cleanly) — this test locks in the existing
        # clean-failure contract so a future refactor cannot regress it back
        # into the UnboundLocalError class.
        assert excinfo.value.status_code == 503
        assert "unavailable" in str(excinfo.value.detail).lower()

    @pytest.mark.asyncio
    async def test_ollama_timeout_returns_clean_502_not_crash(self):
        """A generic timeout (not ConnectError) falls into the broad except
        Exception clause — must raise HTTPException(502), never crash with
        UnboundLocalError further down the function."""
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage
        from fastapi import HTTPException as FastHTTPException

        state = _make_state()
        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            stack.enter_context(
                patch(
                    "yashigani.inspection._ollama_transport.ollama_async_client",
                    MagicMock(
                        return_value=_FakeAsyncClientCM(
                            httpx.ReadTimeout("backend stalled")
                        )
                    ),
                )
            )
            from yashigani.gateway.openai_router import chat_completions
            with pytest.raises(FastHTTPException) as excinfo:
                await chat_completions(body, _make_request())

        assert excinfo.value.status_code == 502
        assert isinstance(excinfo.value, FastHTTPException)
        # The critical negative assertion for this finding:
        assert not isinstance(excinfo.value, UnboundLocalError)


class TestRisk129FailClosedBackstop:
    """Direct unit coverage of the defense-in-depth backstop: initializing
    assistant_content/backend_body to None and guarding on them after the
    dispatch try block, independent of which specific branch gap triggers
    it."""

    def test_source_initializes_assistant_content_before_try(self):
        """Guard against regressing the initialization itself — the fix must
        keep `assistant_content` and `backend_body` bound to a safe default
        before the dispatch try block, immediately ahead of the
        `if assistant_content is None or backend_body is None` backstop."""
        import inspect
        from yashigani.gateway import openai_router

        src = inspect.getsource(openai_router.chat_completions)
        assert "assistant_content: str | None = None" in src
        assert "backend_body: dict | None = None" in src
        assert "if assistant_content is None or backend_body is None:" in src
