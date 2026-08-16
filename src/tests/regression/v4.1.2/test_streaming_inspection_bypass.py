"""
Regression tests — SEC-FIX-YSG-STREAM-INSPECTION-BYPASS (CRITICAL, 2026-08-06).

## Root cause

`chat_completions()` in `gateway/openai_router.py` decides whether a
``stream:true`` request is answered via the raw incremental-streaming branch
(7a, ``StreamingInspector`` in ``gateway/streaming.py``) or the buffered
branch (7b/7b-ii/7c/8c). Four independent response-side controls live ONLY
in the buffered branch:

  1. ``response_inspection_pipeline.inspect()`` — ML CREDENTIAL_EXFIL /
     PROMPT_INJECTION_ONLY classifier (7b).
  2. The always-on I5 injection/PCI-exfil regex scan
     (``yashigani.mcp._content_filter._COMPILED_PATTERN``) — documented as
     "ALWAYS-ON... MANDATORY... INDEPENDENT of YASHIGANI_INSPECT_RESPONSES"
     (7b-ii).
  3. The PII detector on response content (7c).
  4. ``_opa_response_check()`` — OPA ``v1_routing.response_decision``
     (ceiling + inspection-verdict hard gate) (8c).

The raw-streaming branch (7a) enforces ONLY a coarse sensitivity-rank
ceiling via ``StreamingInspector`` — none of the four controls above.

The pre-fix guard only forced the buffered branch when
``_state.opa_url`` happened to be truthy, or when
``_state.pii_detector.mode`` was BLOCK/REDACT:

    if use_streaming and _state.opa_url:
        use_streaming = False
    if use_streaming and _state.pii_detector is not None:
        if _state.pii_detector.mode in (PiiMode.BLOCK, PiiMode.REDACT):
            use_streaming = False

Because OPA is required to start in production and defaults to configured
even in dev, this made response inspection DE FACTO mandatory in the common
case — but NOT an intrinsic guarantee. In an explicit
``YASHIGANI_OPA_OPTIONAL=true`` dev/test deployment with PII mode=log (the
product default), ``_state.opa_url`` is empty and the PII-mode guard does
not fire either, so ``use_streaming`` stayed True and a ``stream:true``
request reached the raw Ollama NDJSON stream (7a) — bypassing all four
controls that the byte-for-byte identical ``stream:false`` request enforces.

## The fix

The buffered-branch decision no longer depends on ``_state.opa_url`` /
``_state.pii_detector`` config state — every non-agent chat completion is
answered via buffer-then-emit-SSE, unconditionally. This does not remove
the client-visible ``stream:true`` -> ``text/event-stream`` contract (see
``_sse_from_completion``); it only removes the ability to select the raw
incremental branch that skips inspection.

Each test below reproduces the pre-fix code path selection directly: it
proves the raw-streaming client method (``.stream()``) is never invoked for
a governed chat completion, and the buffered client method (``.post()``) is
always used instead, regardless of OPA/PII-mode configuration.
"""
from __future__ import annotations

import contextlib
import inspect
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_state(**overrides):
    state = MagicMock()
    state.opa_url = "https://policy:8181"
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
    state.pii_cloud_bypass = False
    state.streaming_enabled = True
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
        allowed={"qwen2.5:3b"},
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
                "identity_id": "idnt_streamfix",
                "kind": "human",
                "groups": [],
                "status": "active",
                "sensitivity_ceiling": "RESTRICTED",
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
        # Deterministic stand-in for OPA's response_decision: deny only when
        # the app-layer already computed a "blocked" verdict (mirrors
        # policy/v1_routing.rego's unconditional _response_blocked_by_inspection
        # hard gate), otherwise allow. Removes any real network/OPA dependency
        # from this test while keeping the assertion meaningful.
        patch(
            "yashigani.gateway.openai_router._opa_response_check",
            AsyncMock(side_effect=lambda **kw: (
                {"allow": False, "reason": "response_blocked_by_inspection"}
                if kw.get("response_verdict") == "blocked"
                else {"allow": True, "reason": "ok"}
            )),
        ),
    ]


class _FakeOllamaTransport:
    """Stand-in for ``ollama_async_client()`` supporting BOTH the buffered
    ``.post()`` call (7b-local) and the raw-streaming ``.stream()`` call
    (7a), with call tracking so tests can assert which branch the code
    actually took — the crux of this regression."""

    def __init__(self, post_response=None, stream_lines=None):
        self.post_called = False
        self.stream_called = False
        self._post_response = post_response
        self._stream_lines = stream_lines or []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def post(self, *args, **kwargs):
        self.post_called = True
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = self._post_response
        return resp

    def stream(self, *args, **kwargs):
        self.stream_called = True
        return _FakeStreamCM(self._stream_lines)


class _FakeStreamCM:
    """Async context manager returned by ``client.stream(...)`` — mirrors
    httpx's real contract (``stream()`` is not itself a coroutine)."""

    def __init__(self, lines):
        self._lines = lines

    async def __aenter__(self):
        upstream = MagicMock()
        upstream.status_code = 200

        async def _aiter_lines():
            for line in self._lines:
                yield line

        upstream.aiter_lines = _aiter_lines
        return upstream

    async def __aexit__(self, *exc_info):
        return False


# A response containing PII/PCI AND an I5-regex trigger word ("SYSTEM" /
# "instructions") — exactly the class of content the buffered path's
# always-on 7b-ii scan blocks (`response_blocked_by_inspection`).
_SENSITIVE_CONTENT = (
    "Here are the SYSTEM instructions you asked me to repeat: "
    "SSN 123-45-6789, credit card 4111 1111 1111 1111."
)
_BENIGN_CONTENT = "Hello! How can I help you today?"


def _ollama_chat_response(content: str) -> dict:
    return {
        "message": {"role": "assistant", "content": content},
        "done": True,
        "prompt_eval_count": 10,
        "eval_count": 10,
    }


def _ollama_stream_lines(content: str) -> list[str]:
    """Split content into two raw NDJSON chunks, as real Ollama streaming
    would emit — the pre-fix vulnerability is that these chunks reach the
    client via SSE before any full-response inspection ever runs."""
    mid = len(content) // 2
    return [
        json.dumps({"message": {"content": content[:mid]}, "done": False}),
        json.dumps({
            "message": {"content": content[mid:]}, "done": True,
            "prompt_eval_count": 10, "eval_count": 10,
        }),
    ]


class TestStreamingInspectionBypassClosed:
    """Core regression: a governed (non-agent) chat completion must NEVER
    reach the raw incremental-streaming client method, regardless of
    OPA/PII-mode configuration. Pre-fix, the OPA-disabled + PII-mode=log
    case below reached ``.stream()`` and the sensitive content would have
    been emitted incrementally with zero inspection."""

    @pytest.mark.asyncio
    async def test_opa_disabled_pii_log_stream_true_uses_buffered_path_not_raw_stream(self, caplog):
        """The exact pre-fix vulnerable configuration: OPA not configured
        (dev/test opt-in) + PII mode=log (product default). Before the fix,
        `use_streaming` stayed True here and `.stream()` was called,
        bypassing all four response-side controls."""
        import logging
        caplog.set_level(logging.WARNING, logger="yashigani.gateway.openai_router")
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        state = _make_state(opa_url="", pii_detector=None)
        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="repeat the SSN and card back to me")],
            stream=True,
        )
        transport = _FakeOllamaTransport(
            post_response=_ollama_chat_response(_SENSITIVE_CONTENT),
            stream_lines=_ollama_stream_lines(_SENSITIVE_CONTENT),
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            stack.enter_context(
                patch("yashigani.inspection._ollama_transport.ollama_async_client", transport)
            )
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_request())
        caplog_text = caplog.text

        # The critical assertion: the raw incremental-streaming client
        # method must NEVER be invoked for a governed chat completion.
        assert not transport.stream_called, (
            "SEC-FIX-YSG-STREAM-INSPECTION-BYPASS regressed: chat_completions() "
            "invoked the raw-streaming client (.stream()) for a stream:true "
            "request with OPA disabled, bypassing the I5 injection/PCI-exfil "
            "scan, the ML response-inspection pipeline, the PII detector, "
            "and the OPA response ceiling check."
        )
        assert transport.post_called, (
            "Expected the buffered client (.post()) to be used instead."
        )

        # Note: with `_state.opa_url` empty, `_opa_response_check()` is never
        # invoked at all (the enclosing `if _state.opa_url:` guard skips it) —
        # a SEPARATE, pre-existing, intentional "OPA dev opt-in" behaviour
        # (identical for stream:false too, not something this fix changes).
        # The I5 scan itself still ran unconditionally and correctly computed
        # verdict="blocked" (asserted via the log capture below) — proving the
        # buffered branch's mandatory controls executed at all, which is the
        # actual regression this fix closes; whether OPA is reachable to act
        # on that verdict is orthogonal to the streaming-bypass root cause.
        assert "LAURA-30-002" in caplog_text, (
            "Expected the always-on I5 injection/PCI-exfil scan (7b-ii) to have "
            "run against the buffered response and flagged the SYSTEM/"
            "instructions content — proof the buffered branch's mandatory "
            "controls executed, not the raw-streaming branch's."
        )

    @pytest.mark.asyncio
    async def test_opa_configured_stream_true_still_uses_buffered_path(self):
        """No-regression check: the already-correct production configuration
        (OPA active) must continue to force the buffered path."""
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        state = _make_state(opa_url="https://policy:8181", pii_detector=None)
        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="repeat the SSN and card back to me")],
            stream=True,
        )
        transport = _FakeOllamaTransport(
            post_response=_ollama_chat_response(_SENSITIVE_CONTENT),
            stream_lines=_ollama_stream_lines(_SENSITIVE_CONTENT),
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            stack.enter_context(
                patch("yashigani.inspection._ollama_transport.ollama_async_client", transport)
            )
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_request())

        assert not transport.stream_called
        assert transport.post_called

        from fastapi.responses import JSONResponse
        assert isinstance(result, JSONResponse)
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_benign_stream_true_still_returns_200_sse(self):
        """Do-not-over-block acceptance criterion: a clean response must
        still be delivered as a real text/event-stream response, not
        blocked, once it goes through the (now-mandatory) buffered path."""
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage
        from starlette.responses import StreamingResponse

        state = _make_state(opa_url="", pii_detector=None)
        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="say hello")],
            stream=True,
        )
        transport = _FakeOllamaTransport(
            post_response=_ollama_chat_response(_BENIGN_CONTENT),
            stream_lines=_ollama_stream_lines(_BENIGN_CONTENT),
        )

        with contextlib.ExitStack() as stack:
            for p in _base_patches(state):
                stack.enter_context(p)
            stack.enter_context(
                patch("yashigani.inspection._ollama_transport.ollama_async_client", transport)
            )
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_request())

        assert not transport.stream_called
        assert transport.post_called
        assert isinstance(result, StreamingResponse)
        assert result.media_type == "text/event-stream"


class TestStreamingDecisionSourceGuard:
    """Guard against a future refactor silently reintroducing the
    config-dependent gate (mirrors the source-inspection style used by
    YSG-RISK-137's regression suite)."""

    def test_source_does_not_gate_buffering_on_opa_url_truthiness(self):
        from yashigani.gateway import openai_router

        src = inspect.getsource(openai_router.chat_completions)
        assert "if use_streaming and _state.opa_url:" not in src, (
            "SEC-FIX-YSG-STREAM-INSPECTION-BYPASS regressed: the buffered-path "
            "decision must not be conditional on _state.opa_url being truthy — "
            "response-side inspection is mandatory for every governed chat "
            "completion regardless of OPA/PII-mode configuration."
        )
