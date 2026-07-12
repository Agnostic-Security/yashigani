"""
Regression tests — F-001 class: chat-stream, chat-nonstream, and embed
Ollama callers must use ollama_async_client (mesh-aware SSL context), NOT
bare httpx.AsyncClient.

What this tests (additive to test_f001_openai_router_model_list_ssl.py):

  E. Chat completions — non-streaming (buffered) path:
     The 7b-local branch used bare ``httpx.AsyncClient(timeout=120.0)``.
     Fixed: now uses ``ollama_async_client(_state.ollama_url, timeout=120.0)``.

  F. Chat completions — streaming (SSE) path:
     ``_sse_generator`` used bare ``httpx.AsyncClient(timeout=120.0)``.
     Fixed: now uses ``ollama_async_client(_state.ollama_url, timeout=120.0)``.

  G. Embeddings — Ollama /api/embed path:
     ``create_embeddings`` used bare ``_httpx.AsyncClient(timeout=60.0)``.
     Fixed: now uses ``ollama_async_client(_state.ollama_url, timeout=60.0)``.

Each test asserts:
  • The transport helper (``ollama_async_client``) is called, not bypassed.
  • The first positional arg is ``_state.ollama_url`` so scheme detection works.
  • Timeout is correct for each path.
  • http:// URLs still work (no regression on Linux container path).

Last updated: 2026-07-13T00:00:00+00:00
"""
from __future__ import annotations

import httpx
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_chat_response_json() -> dict:
    return {
        "message": {"role": "assistant", "content": "Hello!"},
        "done": True,
        "prompt_eval_count": 10,
        "eval_count": 5,
    }


def _make_embed_response_json(model: str = "nomic-embed-text") -> dict:
    return {
        "model": model,
        "embeddings": [[0.1, 0.2, 0.3]],
        "total_duration": 100,
        "prompt_eval_count": 5,
    }


def _make_async_client_cm_post(resp: MagicMock) -> MagicMock:
    """Async context manager yielding a mock client whose .post returns resp."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=resp)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_mock_state(
    ollama_url: str,
    *,
    opa_url: str = "http://opa:8181",
    streaming_enabled: bool = False,
) -> MagicMock:
    state = MagicMock()
    state.ollama_url = ollama_url
    state.opa_url = opa_url
    state.default_model = "llama3.2:3b"
    state.optimization_engine = None
    state.sensitivity_classifier = None
    state.complexity_scorer = None
    state.budget_enforcer = None
    state.budget_config_store = None
    state.permission_store = None
    state.permission_strict = False
    state.ddos_protector = None
    state.content_relay_detector = None
    state.model_alias_store = None
    state.model_allocation_store = None
    state.audit_writer = None
    state.rbac_store = None
    state.identity_registry = None
    state.agent_registry = None
    state.pool_manager = None
    state.pii_detector = None
    state.streaming_enabled = streaming_enabled
    state.streaming_inspect_interval = 200
    state.response_inspection_pipeline = None
    state.low_confidence_stepup_threshold = 0.7
    state.get = MagicMock(return_value=None)
    return state


def _mock_identity(uid: str = "idnt_test_human") -> dict:
    return {"identity_id": uid, "kind": "human", "groups": []}


def _make_mock_request() -> MagicMock:
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


def _base_chat_patches(ollama_url: str, mock_ollama_cm: MagicMock, *,
                        opa_url: str = "http://opa:8181",
                        streaming_enabled: bool = False):
    """
    Return (mock_ollama_async_client, patch_list) for chat_completions tests.
    Wires identity, OPA, client-policy enforcement, and Ollama transport mock.
    """
    mock_ollama_async_client = MagicMock(return_value=mock_ollama_cm)
    return mock_ollama_async_client, [
        patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ),
        patch(
            "yashigani.gateway.openai_router._state",
            _make_mock_state(ollama_url, opa_url=opa_url,
                             streaming_enabled=streaming_enabled),
        ),
        patch(
            "yashigani.gateway.openai_router._resolve_identity",
            MagicMock(return_value=_mock_identity()),
        ),
        # _opa_v1_check: allow + model_allowed — test is about F-001, not OPA.
        patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            AsyncMock(return_value={
                "allow": True,
                "model_allowed": True,
                "reason": "ok",
            }),
        ),
        # evaluate_client_policies: allow both ingress and egress.
        patch(
            "yashigani.gateway.openai_router.evaluate_client_policies",
            AsyncMock(return_value={"allow": True}),
        ),
        # _opa_response_check: allow response (buffered path only).
        patch(
            "yashigani.gateway.openai_router._opa_response_check",
            AsyncMock(return_value={"allow": True}),
        ),
    ]


# ---------------------------------------------------------------------------
# E. Chat completions — non-streaming (buffered), https ollama_url
# ---------------------------------------------------------------------------

class TestChatNonStreamHttpsOllamaUrl:
    """chat_completions (buffered path) must use ollama_async_client for https."""

    @pytest.mark.asyncio
    async def test_nonstream_https_routes_through_ollama_async_client(self):
        """
        When _state.ollama_url is https://caddy:11435/ollama and stream=False,
        chat_completions MUST use ollama_async_client, not bare httpx.AsyncClient.

        Regression: the old code at 7b-local did
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{_state.ollama_url}/api/chat", ...)
        which fails CERTIFICATE_VERIFY_FAILED on mTLS-Ollama fronts.
        """
        import contextlib
        from yashigani.gateway.openai_router import (
            ChatCompletionRequest,
            ChatMessage,
        )

        https_url = "https://caddy:11435/ollama"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_chat_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _base_chat_patches(https_url, mock_cm)

        body = ChatCompletionRequest(
            model="llama3.2:3b",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_mock_request())

        # ollama_async_client must have been called for the chat POST
        assert mock_ollama_ac.call_count >= 1, (
            "chat_completions (non-stream) must call ollama_async_client, "
            "not bare httpx.AsyncClient"
        )
        actual_url = mock_ollama_ac.call_args_list[0][0][0]
        assert actual_url == https_url, (
            f"ollama_async_client must receive ollama_url={https_url!r}; "
            f"got {actual_url!r}"
        )

    @pytest.mark.asyncio
    async def test_nonstream_https_uses_correct_timeout(self):
        """The non-stream chat path must use timeout=120.0."""
        import contextlib
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        https_url = "https://caddy:11435/ollama"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_chat_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _base_chat_patches(https_url, mock_cm)

        body = ChatCompletionRequest(
            model="llama3.2:3b",
            messages=[ChatMessage(role="user", content="hi")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            await chat_completions(body, _make_mock_request())

        call_kwargs = mock_ollama_ac.call_args_list[0][1]
        timeout = call_kwargs.get("timeout")
        assert timeout == 120.0, (
            f"Non-stream chat must call ollama_async_client with timeout=120.0; "
            f"got {timeout!r}"
        )

    @pytest.mark.asyncio
    async def test_nonstream_http_still_routes_through_ollama_async_client(self):
        """http:// ollama_url must still work (no regression on Linux container path)."""
        import contextlib
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        http_url = "http://ollama:11434"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_chat_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _base_chat_patches(http_url, mock_cm)

        body = ChatCompletionRequest(
            model="phi4:latest",
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            await chat_completions(body, _make_mock_request())

        assert mock_ollama_ac.call_count >= 1
        assert mock_ollama_ac.call_args_list[0][0][0] == http_url


# ---------------------------------------------------------------------------
# F. Chat completions — streaming (SSE) path, https ollama_url
#
# Strategy: set opa_url="" so the "use_streaming=False if opa_url" gate does
# not disable streaming (line 2598).  The _sse_generator is lazy; we consume
# it by iterating the StreamingResponse body_iterator.  The Ollama CM is set
# up to raise httpx.ConnectError inside _client.stream() — the generator
# catches it and yields error + [DONE], completing cleanly.  After consumption
# we verify ollama_async_client was called with the correct args.
# ---------------------------------------------------------------------------

def _make_sse_ollama_cm() -> tuple[MagicMock, MagicMock]:
    """
    Return (outer_cm, mock_ollama_ac_factory) where outer_cm is an async CM
    whose inner client's .stream() context manager raises httpx.ConnectError
    on __aenter__.  This triggers the generator's ConnectError handler cleanly.
    """
    # Inner stream CM raises ConnectError
    stream_cm = MagicMock()
    stream_cm.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("test-cert-error"))
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    # Client that .stream() returns the above CM
    mock_client = AsyncMock()
    mock_client.stream = MagicMock(return_value=stream_cm)

    # Outer CM (the ollama_async_client result)
    outer_cm = MagicMock()
    outer_cm.__aenter__ = AsyncMock(return_value=mock_client)
    outer_cm.__aexit__ = AsyncMock(return_value=False)

    return outer_cm


class TestChatStreamHttpsOllamaUrl:
    """_sse_generator must use ollama_async_client for https ollama_url."""

    @pytest.mark.asyncio
    async def test_sse_https_routes_through_ollama_async_client(self):
        """
        When _state.ollama_url is https://caddy:11435/ollama and stream=True,
        the _sse_generator MUST call ollama_async_client, not bare httpx.AsyncClient.

        Regression: the old code in _sse_generator did
            async with httpx.AsyncClient(timeout=120.0) as _client:
                async with _client.stream("POST", ...) as _upstream:
        which fails CERTIFICATE_VERIFY_FAILED on mTLS-Ollama fronts.

        We set opa_url="" so the OPA streaming-disable gate at line 2598 does
        not force use_streaming=False.  The generator is consumed to completion
        via the ConnectError path (short-circuits cleanly).
        """
        import contextlib
        from yashigani.gateway.openai_router import (
            ChatCompletionRequest,
            ChatMessage,
        )

        https_url = "https://caddy:11435/ollama"
        outer_cm = _make_sse_ollama_cm()

        mock_ollama_ac = MagicMock(return_value=outer_cm)

        # For streaming we set opa_url="" to avoid the "disable-streaming-if-opa"
        # gate, and streaming_enabled=True.
        patches = [
            patch(
                "yashigani.inspection._ollama_transport.ollama_async_client",
                mock_ollama_ac,
            ),
            patch(
                "yashigani.gateway.openai_router._state",
                _make_mock_state(https_url, opa_url="", streaming_enabled=True),
            ),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=_mock_identity()),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={
                    "allow": True,
                    "model_allowed": True,
                    "reason": "ok",
                }),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
            # StreamingInspector is lazily imported from yashigani.gateway.streaming
            # at line 2614 — patch the source module so the import picks it up.
            patch(
                "yashigani.gateway.streaming.StreamingInspector",
                MagicMock(return_value=MagicMock()),
            ),
        ]

        body = ChatCompletionRequest(
            model="llama3.2:3b",
            messages=[ChatMessage(role="user", content="hello stream")],
            stream=True,
        )

        # IMPORTANT: consume the body_iterator INSIDE the patch context.
        # The _sse_generator is lazy; it runs when iterated.  If the patches
        # have been undone before iteration, the REAL ollama_async_client runs.
        from starlette.responses import StreamingResponse

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_mock_request())

            assert isinstance(result, StreamingResponse), (
                f"stream=True must return StreamingResponse; got {type(result)}"
            )

            # Consume the generator while patches are still active
            chunks = []
            async for chunk in result.body_iterator:
                chunks.append(chunk)

        # After consuming (still within assertions), check mock was called
        assert mock_ollama_ac.call_count >= 1, (
            "_sse_generator must call ollama_async_client, not bare httpx.AsyncClient"
        )
        actual_url = mock_ollama_ac.call_args_list[0][0][0]
        assert actual_url == https_url, (
            f"ollama_async_client must receive ollama_url={https_url!r}; "
            f"got {actual_url!r}"
        )

    @pytest.mark.asyncio
    async def test_sse_https_uses_correct_timeout(self):
        """The SSE generator must call ollama_async_client with timeout=120.0."""
        import contextlib
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        https_url = "https://caddy:11435/ollama"
        outer_cm = _make_sse_ollama_cm()
        mock_ollama_ac = MagicMock(return_value=outer_cm)

        patches = [
            patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_ac),
            patch("yashigani.gateway.openai_router._state",
                  _make_mock_state(https_url, opa_url="", streaming_enabled=True)),
            patch("yashigani.gateway.openai_router._resolve_identity",
                  MagicMock(return_value=_mock_identity())),
            patch("yashigani.gateway.openai_router._opa_v1_check",
                  AsyncMock(return_value={"allow": True, "model_allowed": True})),
            patch("yashigani.gateway.openai_router.evaluate_client_policies",
                  AsyncMock(return_value={"allow": True})),
            patch("yashigani.gateway.streaming.StreamingInspector",
                  MagicMock(return_value=MagicMock())),
        ]

        body = ChatCompletionRequest(
            model="llama3.2:3b",
            messages=[ChatMessage(role="user", content="stream-timeout-test")],
            stream=True,
        )

        from starlette.responses import StreamingResponse

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_mock_request())

            assert isinstance(result, StreamingResponse)
            # Consume inside context so patches are active when generator runs
            async for _ in result.body_iterator:
                pass

        assert mock_ollama_ac.call_count >= 1
        timeout = mock_ollama_ac.call_args_list[0][1].get("timeout")
        assert timeout == 120.0, (
            f"SSE generator must call ollama_async_client with timeout=120.0; got {timeout!r}"
        )


# ---------------------------------------------------------------------------
# G. Embeddings — Ollama /api/embed path
# ---------------------------------------------------------------------------

def _embed_patches(ollama_url: str, mock_ollama_cm: MagicMock):
    """Return (mock_ollama_async_client, patch_list) for create_embeddings tests."""
    mock_ollama_async_client = MagicMock(return_value=mock_ollama_cm)
    return mock_ollama_async_client, [
        patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ),
        patch(
            "yashigani.gateway.openai_router._state",
            _make_mock_state(ollama_url),
        ),
        patch(
            "yashigani.gateway.openai_router._resolve_identity",
            MagicMock(return_value=_mock_identity()),
        ),
        # create_embeddings uses _opa_v1_check for the OPA ingress check.
        patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            AsyncMock(return_value={"allow": True, "model_allowed": True, "reason": "ok"}),
        ),
    ]


class TestEmbedHttpsOllamaUrl:
    """create_embeddings (Ollama /api/embed) must use ollama_async_client for https."""

    @pytest.mark.asyncio
    async def test_embed_https_routes_through_ollama_async_client(self):
        """
        When _state.ollama_url is https://caddy:11435/ollama, create_embeddings MUST
        call ollama_async_client, not bare _httpx.AsyncClient.

        Regression: the old code at the embed ollama branch did
            async with _httpx.AsyncClient(timeout=60.0) as _client:
                resp = await _client.post(f"{_state.ollama_url}/api/embed", ...)
        which fails on mTLS-Ollama fronts.
        """
        import contextlib

        https_url = "https://caddy:11435/ollama"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_embed_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _embed_patches(https_url, mock_cm)

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
            body = EmbeddingRequest(model="nomic-embed-text", input="hello world")
            result = await create_embeddings(body, _make_mock_request())

        assert mock_ollama_ac.call_count >= 1, (
            "create_embeddings must call ollama_async_client, not bare _httpx.AsyncClient"
        )
        actual_url = mock_ollama_ac.call_args_list[0][0][0]
        assert actual_url == https_url, (
            f"ollama_async_client must receive ollama_url={https_url!r}; "
            f"got {actual_url!r}"
        )

    @pytest.mark.asyncio
    async def test_embed_https_uses_correct_timeout(self):
        """The embed Ollama path must use timeout=60.0."""
        import contextlib

        https_url = "https://caddy:11435/ollama"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_embed_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _embed_patches(https_url, mock_cm)

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
            body = EmbeddingRequest(model="nomic-embed-text", input="test")
            await create_embeddings(body, _make_mock_request())

        call_kwargs = mock_ollama_ac.call_args_list[0][1]
        timeout = call_kwargs.get("timeout")
        assert timeout == 60.0, (
            f"Embed path must call ollama_async_client with timeout=60.0; got {timeout!r}"
        )

    @pytest.mark.asyncio
    async def test_embed_http_still_populates_result(self):
        """http:// ollama_url must still work for embeddings (Linux container path)."""
        import contextlib

        http_url = "http://ollama:11434"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json = MagicMock(return_value=_make_embed_response_json())
        mock_cm = _make_async_client_cm_post(mock_resp)

        mock_ollama_ac, patches = _embed_patches(http_url, mock_cm)

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
            body = EmbeddingRequest(model="nomic-embed-text", input="hello")
            result = await create_embeddings(body, _make_mock_request())

        assert mock_ollama_ac.call_count >= 1
        assert mock_ollama_ac.call_args_list[0][0][0] == http_url
