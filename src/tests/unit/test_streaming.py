"""
Unit tests for yashigani.gateway.streaming.

Covers:
  - Clean stream passes through all chunks
  - Stream with PII mid-way triggers termination
  - Stream end (final_inspect) triggers termination when LLM layer detects
  - Buffer accumulation and interval-based FastText check
  - Streaming disabled falls back to buffered path (router-level test)

All tests use a mock SensitivityClassifier so no Ollama or FastText binary
is required.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Direct module import — avoids pulling in the full gateway package tree
# ---------------------------------------------------------------------------

def _import_streaming():
    if "yashigani.gateway.streaming" in sys.modules:
        return sys.modules["yashigani.gateway.streaming"]
    src_root = Path(__file__).parent.parent.parent
    path = src_root / "yashigani" / "gateway" / "streaming.py"
    spec = importlib.util.spec_from_file_location("yashigani.gateway.streaming", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["yashigani.gateway.streaming"] = module
    spec.loader.exec_module(module)
    return module


_streaming = _import_streaming()
StreamingInspector = _streaming.StreamingInspector
stream_response = _streaming.stream_response
_TERMINATION_CHUNK_CONTENT = _streaming._TERMINATION_CHUNK_CONTENT


# ---------------------------------------------------------------------------
# Helpers — mock SensitivityClassifier
# ---------------------------------------------------------------------------

class _MockSensitivityLevel:
    """Minimal stand-in matching SensitivityClassifier's ._scan_* return shape."""
    def __init__(self, value: str):
        self.value = value


class _MockSensitivityResult:
    def __init__(self, level_value: str):
        self.level = _MockSensitivityLevel(level_value)


def _make_classifier(
    regex_level: str = "PUBLIC",
    fasttext_level: str = "PUBLIC",
    full_classify_level: str = "PUBLIC",
):
    """
    Build a mock SensitivityClassifier.

    - ``_scan_regex``       returns ``_MockSensitivityLevel(regex_level)``
    - ``_scan_classifier``  returns ``_MockSensitivityLevel(fasttext_level)``
    - ``classify``          returns ``_MockSensitivityResult(full_classify_level)``

    ``_scan_fasttext`` is kept as a deprecated alias so tests that call it
    directly still work (back-compat alias coverage).
    """
    clf = MagicMock()

    def _scan_regex(text, triggers):
        return _MockSensitivityLevel(regex_level)

    def _scan_classifier(text, triggers):
        return _MockSensitivityLevel(fasttext_level)

    def _classify(text):
        return _MockSensitivityResult(full_classify_level)

    clf._scan_regex = _scan_regex
    clf._scan_classifier = _scan_classifier
    # Deprecated alias — streaming.py no longer calls this directly, but kept
    # for any test that still exercises the old name.
    clf._scan_fasttext = _scan_classifier
    clf.classify = _classify
    # F-RT1: final_inspect now prefers classify_decoded (decode-before-classify).
    # The mock returns the same level either way (decode is a superset of classify).
    clf.classify_decoded = _classify
    return clf


def _make_inspector(
    regex_level: str = "PUBLIC",
    fasttext_level: str = "PUBLIC",
    full_classify_level: str = "PUBLIC",
    inspect_interval: int = 200,
    on_audit=None,
) -> StreamingInspector:
    clf = _make_classifier(regex_level, fasttext_level, full_classify_level)
    return StreamingInspector(
        sensitivity_classifier=clf,
        inspect_interval=inspect_interval,
        request_id="test-req-001",
        session_id="test-session",
        agent_id="test-agent",
        on_audit=on_audit or (lambda name, data: None),
    )


# ---------------------------------------------------------------------------
# StreamingInspector unit tests
# ---------------------------------------------------------------------------

class TestStreamingInspectorClean:
    def test_clean_chunks_all_pass(self):
        """All PUBLIC chunks return True from feed()."""
        inspector = _make_inspector()
        for text in ["Hello ", "world! ", "How are you?"]:
            assert inspector.feed(text) is True
        assert inspector.terminated is False

    def test_terminated_flag_not_set_on_clean(self):
        inspector = _make_inspector()
        inspector.feed("A" * 50)
        assert inspector.terminated is False
        assert inspector.termination_trigger == ""

    def test_full_text_accumulates(self):
        inspector = _make_inspector()
        inspector.feed("foo")
        inspector.feed("bar")
        assert inspector._full_text == "foobar"

    def test_final_inspect_returns_true_for_clean(self):
        inspector = _make_inspector(full_classify_level="PUBLIC")
        inspector.feed("some clean text")
        assert inspector.final_inspect() is True

    def test_final_inspect_no_text_returns_true(self):
        """final_inspect on empty buffer should not raise and should return True."""
        inspector = _make_inspector()
        assert inspector.final_inspect() is True


class TestStreamingInspectorTermination:
    def test_regex_hit_terminates(self):
        """A RESTRICTED chunk from regex scan causes feed() to return False."""
        inspector = _make_inspector(regex_level="RESTRICTED")
        result = inspector.feed("4111 1111 1111 1111")  # credit card-ish
        assert result is False
        assert inspector.terminated is True
        assert "regex" in inspector.termination_trigger

    def test_confidential_regex_also_terminates(self):
        inspector = _make_inspector(regex_level="CONFIDENTIAL")
        result = inspector.feed("123-45-6789")  # SSN-ish
        assert result is False
        assert inspector.terminated is True

    def test_fasttext_hit_at_interval_terminates(self):
        """Classifier RESTRICTED hit at interval boundary terminates stream."""
        # interval=10 so we trip it after 10+ chars
        inspector = _make_inspector(fasttext_level="RESTRICTED", inspect_interval=10)
        result = inspector.feed("A" * 15)  # > interval=10
        assert result is False
        assert inspector.terminated is True
        assert "classifier" in inspector.termination_trigger

    def test_final_inspect_blocked_level_terminates(self):
        """final_inspect returns False when full classify returns CONFIDENTIAL."""
        inspector = _make_inspector(full_classify_level="CONFIDENTIAL")
        inspector.feed("some text")
        result = inspector.final_inspect()
        assert result is False
        assert inspector.terminated is True
        assert "final" in inspector.termination_trigger

    def test_feed_after_terminated_always_false(self):
        """Once terminated, every subsequent feed returns False immediately."""
        inspector = _make_inspector(regex_level="RESTRICTED")
        inspector.feed("trigger")
        assert inspector.terminated is True
        # Subsequent feeds
        assert inspector.feed("more text") is False
        assert inspector.feed("even more") is False

    def test_audit_callback_fires_on_termination(self):
        audit_events = []
        inspector = _make_inspector(
            regex_level="RESTRICTED",
            on_audit=lambda name, data: audit_events.append((name, data)),
        )
        inspector.feed("credit card 4111 1111 1111 1111")
        assert len(audit_events) == 1
        event_name, event_data = audit_events[0]
        assert event_name == "STREAM_TERMINATED"
        assert event_data["request_id"] == "test-req-001"
        assert "trigger" in event_data


class TestStreamingInspectorBufferAccumulation:
    def test_window_cleared_after_interval(self):
        """Window buffer resets at each inspect-interval boundary."""
        inspector = _make_inspector(inspect_interval=5)
        inspector.feed("ABCDE")   # exactly 5 chars — triggers check + clear
        assert inspector._window == ""
        assert inspector._chars_since_last_check == 0

    def test_window_accumulates_before_interval(self):
        """Window grows until the interval is reached."""
        inspector = _make_inspector(inspect_interval=20)
        inspector.feed("abc")      # 3 chars
        inspector.feed("defg")     # +4 = 7 chars
        assert inspector._window == "abcdefg"
        assert inspector._chars_since_last_check == 7

    def test_full_text_independent_of_window(self):
        """_full_text keeps the complete text even after window clears."""
        inspector = _make_inspector(inspect_interval=5)
        inspector.feed("ABCDE")   # triggers window clear
        inspector.feed("FGHIJ")   # triggers window clear
        assert inspector._full_text == "ABCDEFGHIJ"

    def test_no_classifier_passes_everything(self):
        """Inspector with classifier=None is a no-op pass-through."""
        inspector = StreamingInspector(
            sensitivity_classifier=None,
            inspect_interval=10,
            request_id="r1",
            session_id="s1",
            agent_id="a1",
        )
        for text in ["anything", "goes", "here " * 100]:
            assert inspector.feed(text) is True
        assert inspector.final_inspect() is True


# ---------------------------------------------------------------------------
# stream_response generator tests
# ---------------------------------------------------------------------------

def _make_ollama_line(content: str, done: bool = False) -> str:
    obj = {"message": {"content": content}, "done": done}
    if done:
        obj["prompt_eval_count"] = 5
        obj["eval_count"] = 10
    return json.dumps(obj)


class _FakeUpstreamResponse:
    """Minimal async iterable that yields pre-baked Ollama NDJSON lines."""

    def __init__(self, lines: list[str], status_code: int = 200):
        self.status_code = status_code
        self._lines = lines

    async def aiter_lines(self):
        for line in self._lines:
            yield line


@pytest.mark.asyncio
async def test_stream_response_clean_passthrough():
    """All chunks from a clean stream appear in the SSE output."""
    lines = [
        _make_ollama_line("Hello "),
        _make_ollama_line("world"),
        _make_ollama_line("", done=True),
    ]
    upstream = _FakeUpstreamResponse(lines)
    inspector = _make_inspector()

    chunks = []
    async for chunk in stream_response(upstream, inspector, "req-1", "model-x"):
        chunks.append(chunk)

    # Last chunk must be the [DONE] sentinel
    assert chunks[-1] == "data: [DONE]\n\n"
    # First two are SSE data lines carrying "Hello " and "world"
    assert len(chunks) == 3
    payload_1 = json.loads(chunks[0][len("data: "):-2])
    assert payload_1["choices"][0]["delta"]["content"] == "Hello "
    payload_2 = json.loads(chunks[1][len("data: "):-2])
    assert payload_2["choices"][0]["delta"]["content"] == "world"


@pytest.mark.asyncio
async def test_stream_response_termination_midstream():
    """When inspector triggers mid-stream, a termination chunk is injected."""
    lines = [
        _make_ollama_line("clean chunk"),
        _make_ollama_line("4111 1111 1111 1111"),  # triggers regex
        _make_ollama_line("more content"),
        _make_ollama_line("", done=True),
    ]
    upstream = _FakeUpstreamResponse(lines)
    inspector = _make_inspector(regex_level="RESTRICTED")

    chunks = []
    async for chunk in stream_response(upstream, inspector, "req-2", "model-x"):
        chunks.append(chunk)

    # Since regex fires on every feed call (mocked to always return RESTRICTED),
    # even the first chunk trips it. The termination chunk + [DONE] must be present.
    # Verify the sequence ends with DONE
    assert chunks[-1] == "data: [DONE]\n\n"
    # The second-to-last chunk carries the termination message
    term_payload = json.loads(chunks[-2][len("data: "):-2])
    assert _TERMINATION_CHUNK_CONTENT in term_payload["choices"][0]["delta"]["content"]


@pytest.mark.asyncio
async def test_stream_response_final_inspect_termination():
    """
    Final inspection (LLM layer) blocks the [DONE] sentinel and injects
    termination instead.
    """
    lines = [
        _make_ollama_line("some "),
        _make_ollama_line("text"),
        _make_ollama_line("", done=True),
    ]
    upstream = _FakeUpstreamResponse(lines)
    # All chunks clean at regex/classifier level but full classify is CONFIDENTIAL
    inspector = _make_inspector(
        regex_level="PUBLIC",
        fasttext_level="PUBLIC",
        full_classify_level="CONFIDENTIAL",
    )

    chunks = []
    async for chunk in stream_response(upstream, inspector, "req-3", "model-x"):
        chunks.append(chunk)

    assert chunks[-1] == "data: [DONE]\n\n"
    term_payload = json.loads(chunks[-2][len("data: "):-2])
    assert _TERMINATION_CHUNK_CONTENT in term_payload["choices"][0]["delta"]["content"]


@pytest.mark.asyncio
async def test_stream_response_usage_callback_invoked():
    """Token counts from the final Ollama chunk are forwarded to usage_callback."""
    lines = [
        _make_ollama_line("hello"),
        _make_ollama_line("", done=True),  # done=True carries prompt_eval_count=5, eval_count=10
    ]
    upstream = _FakeUpstreamResponse(lines)
    inspector = _make_inspector()

    received = {}

    def _cb(pt, ct):
        received["pt"] = pt
        received["ct"] = ct

    async for _ in stream_response(upstream, inspector, "req-4", "m", usage_callback=_cb):
        pass

    assert received["pt"] == 5
    assert received["ct"] == 10


@pytest.mark.asyncio
async def test_stream_response_empty_done_only():
    """Stream that emits only a done chunk without content doesn't crash."""
    lines = [_make_ollama_line("", done=True)]
    upstream = _FakeUpstreamResponse(lines)
    inspector = _make_inspector()

    chunks = []
    async for chunk in stream_response(upstream, inspector, "req-5", "model-x"):
        chunks.append(chunk)

    assert "data: [DONE]\n\n" in chunks


# ---------------------------------------------------------------------------
# Router-level: streaming disabled falls back to buffered path
#
# These tests require fastapi. They are skipped gracefully when the package
# is absent (same pattern as test_ddos.py / TestProxyIntegration).
# ---------------------------------------------------------------------------

_fastapi_available = importlib.util.find_spec("fastapi") is not None


def _import_router_fresh(streaming_enabled: bool):
    """
    Load openai_router into a fresh module object and patch _state.

    Using a unique module name each call avoids sys.modules cache collisions
    between the two test variants.
    """
    src_root = Path(__file__).parent.parent.parent
    router_path = src_root / "yashigani" / "gateway" / "openai_router.py"
    mod_name = f"yashigani.gateway.openai_router._test_{streaming_enabled}"
    spec = importlib.util.spec_from_file_location(mod_name, router_path)
    mod = importlib.util.module_from_spec(spec)
    # Register so relative imports inside the module resolve
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

    mod._state.streaming_enabled = streaming_enabled
    mod._state.streaming_inspect_interval = 200
    mod._state.ddos_protector = None
    mod._state.identity_registry = None
    mod._state.sensitivity_classifier = None
    mod._state.complexity_scorer = None
    mod._state.budget_enforcer = None
    mod._state.token_counter = None
    mod._state.audit_writer = None
    mod._state.optimization_engine = None
    mod._state.ollama_url = "http://ollama-test:11434"
    mod._state.default_model = "test-model"
    mod._state.available_models = []
    mod._state.agent_registry = None
    mod._state.response_inspection_pipeline = None
    mod._state.pii_detector = None
    mod._state.pii_cloud_bypass = False
    mod._state.opa_url = ""  # Disable OPA in unit tests
    # OPA is fail-closed by default: an unconfigured opa_url denies unless the
    # explicit dev opt-in is set (non-production + YASHIGANI_OPA_OPTIONAL=true).
    # These unit tests exercise the streaming/buffered branching with OPA off, so
    # opt in to the dev bypass. Production behaviour (fail-closed) is unchanged.
    os.environ["YASHIGANI_OPA_OPTIONAL"] = "true"
    os.environ.setdefault("YASHIGANI_ENV", "test")
    return mod


@pytest.mark.skipif(not _fastapi_available, reason="fastapi not installed")
class TestStreamingRouterFallback:
    """
    Verify that when YASHIGANI_STREAMING_ENABLED=false the router ignores
    body.stream=True and calls the buffered Ollama path; and vice-versa.
    """

    async def _run_buffered(self, mod, *, stream: bool):
        """
        Drive chat_completions with streaming force-disabled at the upstream
        level, capturing the Ollama request bodies.  Returns (result, captured).
        """
        captured_bodies = []

        async def _fake_post(url, json=None, **kwargs):
            captured_bodies.append(json)
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "message": {"content": "buffered reply"},
                "prompt_eval_count": 3,
                "eval_count": 5,
            }
            return resp

        # Authenticate as the internal service account so _resolve_identity does not
        # return None (which would raise 401 before streaming logic is reached).
        # The internal bearer must match the module's cached _INTERNAL_BEARER.
        # Use a MagicMock for headers so .get() works case-insensitively.
        _headers_data = {"authorization": f"Bearer {mod._INTERNAL_BEARER}"}
        _headers_mock = MagicMock()
        _headers_mock.get = lambda key, default="": _headers_data.get(key.lower(), default)
        mock_request = MagicMock()
        mock_request.headers = _headers_mock
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = _fake_post

        with patch("httpx.AsyncClient", return_value=mock_client):
            # Import request models from the fresh module so Pydantic validation
            # runs against the same class objects the handler sees.
            ChatCompletionRequest = mod.ChatCompletionRequest
            ChatMessage = mod.ChatMessage
            body = ChatCompletionRequest(
                model="test-model",
                messages=[ChatMessage(role="user", content="hello")],
                stream=stream,
            )
            result = await mod.chat_completions(body, mock_request)
        return result, captured_bodies

    @pytest.mark.asyncio
    async def test_streaming_disabled_uses_buffered_upstream(self):
        """
        When streaming is disabled, the buffered Ollama endpoint is called
        (upstream stream=False), regardless of the client's stream flag.
        """
        mod = _import_router_fresh(streaming_enabled=False)
        result, captured_bodies = await self._run_buffered(mod, stream=False)

        # stream=False client request → plain JSONResponse
        from fastapi.responses import StreamingResponse as _SR
        assert not isinstance(result, _SR), (
            "Expected buffered JSONResponse but got StreamingResponse"
        )

        # The Ollama call must have used stream=False
        assert len(captured_bodies) == 1
        assert captured_bodies[0].get("stream") is False

    @pytest.mark.asyncio
    async def test_streaming_disabled_but_client_stream_true_returns_sse(self):
        """
        F-STREAM (2026-06-09): when streaming is force-disabled (OPA / PII) the
        upstream is still buffered (stream=False), but a client that requested
        ``stream:true`` MUST receive ``text/event-stream`` with a single
        chat.completion.chunk carrying the full assistant text + a [DONE]
        sentinel.  Otherwise Open WebUI's SSE reader renders nothing.
        """
        mod = _import_router_fresh(streaming_enabled=False)
        result, captured_bodies = await self._run_buffered(mod, stream=True)

        from fastapi.responses import StreamingResponse as _SR
        assert isinstance(result, _SR), (
            "Expected SSE StreamingResponse for a stream:true buffered request"
        )
        assert result.media_type == "text/event-stream"

        # Upstream Ollama was still called buffered (stream=False) — inspection
        # ran on the full body before SSE-wrapping.
        assert len(captured_bodies) == 1
        assert captured_bodies[0].get("stream") is False

        # Drain the SSE body and verify it carries a data chunk + [DONE].
        body_parts = []
        async for part in result.body_iterator:
            body_parts.append(part if isinstance(part, str) else part.decode())
        body_text = "".join(body_parts)
        assert "data: " in body_text
        assert "data: [DONE]\n\n" in body_text

        # The frames must be OpenAI chat.completion.chunk objects. We emit the
        # canonical role → content → finish framing (multiple frames).
        data_lines = [
            ln[len("data: "):]
            for ln in body_text.split("\n\n")
            if ln.startswith("data: ") and not ln.endswith("[DONE]")
        ]
        assert len(data_lines) >= 1
        chunks = [json.loads(d) for d in data_lines]
        for c in chunks:
            assert c["object"] == "chat.completion.chunk"

        # Across the frames: an assistant role opener, the full content, and a
        # stop finish_reason must all be present.
        roles = [c["choices"][0]["delta"].get("role") for c in chunks]
        contents = [c["choices"][0]["delta"].get("content") for c in chunks]
        finishes = [c["choices"][0].get("finish_reason") for c in chunks]
        assert "assistant" in roles
        assert "buffered reply" in [x for x in contents if x]
        assert "stop" in finishes

    @pytest.mark.asyncio
    async def test_streaming_enabled_uses_streaming_response(self):
        """
        When streaming is enabled and body.stream=True, the router returns
        a StreamingResponse without calling the buffered JSON path.
        """
        mod = _import_router_fresh(streaming_enabled=True)

        # Authenticate as the internal service account — same pattern as the
        # buffered test above. _resolve_identity checks Authorization header.
        _headers_data_2 = {"authorization": f"Bearer {mod._INTERNAL_BEARER}"}
        _headers_mock_2 = MagicMock()
        _headers_mock_2.get = lambda key, default="": _headers_data_2.get(key.lower(), default)
        mock_request = MagicMock()
        mock_request.headers = _headers_mock_2
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        # Patch httpx.AsyncClient.stream context manager — we just need the
        # router to reach the return statement without actually connecting.
        mock_stream_cm = MagicMock()
        mock_stream_cm.__aenter__ = AsyncMock(return_value=MagicMock(status_code=200))
        mock_stream_cm.__aexit__ = AsyncMock(return_value=False)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.stream = MagicMock(return_value=mock_stream_cm)

        with patch("httpx.AsyncClient", return_value=mock_client):
            ChatCompletionRequest = mod.ChatCompletionRequest
            ChatMessage = mod.ChatMessage
            body = ChatCompletionRequest(
                model="test-model",
                messages=[ChatMessage(role="user", content="hello")],
                stream=True,
            )
            result = await mod.chat_completions(body, mock_request)

        from fastapi.responses import StreamingResponse as _SR
        assert isinstance(result, _SR), (
            "Expected StreamingResponse but got something else"
        )
        assert result.media_type == "text/event-stream"
