"""
Yashigani Gateway — Streaming response handler for /v1/chat/completions.

v2.2: Adds chunk-level inspection so that sensitivity violations in streamed
      responses terminate the stream early rather than being silently delivered.

Design decisions
----------------
Layer constraints during streaming:
  - Regex (Layer 1): runs on every chunk — sub-millisecond, safe to call inline.
  - sklearn classifier (Layer 2): runs on the accumulated buffer at every inspect
    interval (default 200 chars). Still fast (<1 ms), acceptable for streaming.
  - Ollama LLM (Layer 3): NOT called during streaming — latency (200-500 ms)
    would cause visible pauses between chunks. Runs once on the complete
    accumulated text after the stream ends.

Budget headers limitation
-------------------------
SSE responses set headers before the body begins. By the time we know the
token count (from the `usage` field in the final `[DONE]` chunk, or estimated
from char count), headers have already been sent. Budget accounting is
performed and recorded, but X-Yashigani-Budget-* headers are omitted for
streaming responses. Clients relying on budget state should poll the budget
API or use a non-streaming request.

SSE wire format (OpenAI-compatible)::

    data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk",
           "choices":[{"index":0,"delta":{"content":"text"},"finish_reason":null}]}\n\n
    data: [DONE]\n\n
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import AsyncIterator, Optional, Callable

logger = logging.getLogger(__name__)

# Sentinel injected when the stream is terminated due to sensitive content.
_TERMINATION_CHUNK_CONTENT = "[STREAM TERMINATED: sensitive content detected]"


class StreamingInspector:
    """
    Accumulates SSE text chunks and inspects them at configurable intervals.

    Inspection layers per the v2.2 constraint matrix:
    - Regex: every chunk (in-band, <1 ms)
    - Classifier: at every inspect-interval boundary
    - LLM: once, after stream end (via ``final_inspect``)

    The ``sensitivity_classifier`` passed in is the same
    ``SensitivityClassifier`` instance used by the buffered path. We call its
    ``_scan_regex`` and ``_scan_classifier`` private helpers directly so that we
    can enforce the per-layer timing constraints without running the full
    three-layer pipeline (which would block on Ollama).

    If ``sensitivity_classifier`` is None the inspector is a no-op pass-through
    and all chunks are forwarded.
    """

    # Sensitivity levels that trigger stream termination (string values from
    # SensitivityLevel enum — compared as strings to avoid circular imports).
    _BLOCKING_LEVELS = {"CONFIDENTIAL", "RESTRICTED"}

    def __init__(
        self,
        sensitivity_classifier,           # SensitivityClassifier | None
        inspect_interval: int = 200,      # chars between classifier checks
        request_id: str = "",
        session_id: str = "",
        agent_id: str = "",
        on_audit: Optional[Callable[[str, dict], None]] = None,
    ) -> None:
        self._classifier = sensitivity_classifier
        self._interval = inspect_interval
        self._request_id = request_id
        self._session_id = session_id
        self._agent_id = agent_id
        self._on_audit = on_audit or (lambda name, data: None)

        # Rolling accumulator — cleared at each interval boundary
        self._window: str = ""
        # Full accumulated text — for final LLM inspection after stream end
        self._full_text: str = ""
        # Chars accumulated since the last classifier interval check
        self._chars_since_last_check: int = 0
        # Set True when a blocking level is detected
        self.terminated: bool = False
        self.termination_trigger: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, chunk_text: str) -> bool:
        """
        Feed a text chunk into the inspector.

        Runs regex on the chunk immediately. If the accumulated buffer has
        grown past ``inspect_interval``, also runs the sklearn classifier.

        Returns:
            True  — chunk is clean; caller may forward it to the client.
            False — blocking level detected; caller must terminate the stream.
        """
        if self.terminated:
            return False

        self._window += chunk_text
        self._full_text += chunk_text
        self._chars_since_last_check += len(chunk_text)

        # Layer 1: regex — always, on the new chunk text alone (fast enough)
        if self._classifier is not None:
            regex_level = self._run_regex(chunk_text)
            if regex_level in self._BLOCKING_LEVELS:
                self._trigger_termination(f"regex:{regex_level}", chunk_text)
                return False

        # Layer 2: Classifier — at interval boundary
        if (
            self._classifier is not None
            and self._chars_since_last_check >= self._interval
        ):
            ft_level = self._run_classifier(self._window)
            if ft_level in self._BLOCKING_LEVELS:
                self._trigger_termination(f"classifier:{ft_level}", self._window)
                return False

            # Clear the window and reset the counter for the next interval
            self._window = ""
            self._chars_since_last_check = 0

        return True

    def final_inspect(self) -> bool:
        """
        Run full three-layer inspection on the complete accumulated text.

        Called once after the upstream ``[DONE]`` sentinel is received.
        This is where the Ollama LLM layer (Layer 3) runs — it is safe to
        block here because the upstream stream is already finished and we
        hold the final chunk before flushing [DONE] to the client.

        Returns:
            True  — content is clean; caller should send [DONE].
            False — blocking level detected; caller should send the
                    termination chunk instead of [DONE].
        """
        if self.terminated or self._classifier is None:
            return not self.terminated

        if not self._full_text:
            return True

        try:
            # F-RT1 (red-team verified 2026-05-30): the final inspect runs on the
            # FULL accumulated text, so decode-before-classify is safe here — an
            # encoded sensitive value streamed back is caught before [DONE].
            # (Incremental per-chunk scans below stay raw-only: partial base64
            # chunks do not decode cleanly.)  getattr keeps no-op/stub classifiers
            # working.
            _classify = getattr(self._classifier, "classify_decoded", self._classifier.classify)
            result = _classify(self._full_text)
            level = result.level.value
            if level in self._BLOCKING_LEVELS:
                self._trigger_termination(f"final:{level}", self._full_text[:200])
                return False
        except Exception as exc:
            logger.warning(
                "StreamingInspector.final_inspect raised: %s (request_id=%s)",
                exc, self._request_id,
            )

        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_regex(self, text: str) -> str:
        """Run Layer 1 regex scan. Returns level string (e.g. 'RESTRICTED')."""
        triggers: list[str] = []
        try:
            level = self._classifier._scan_regex(text, triggers)
            return level.value
        except Exception as exc:
            logger.debug("StreamingInspector regex scan error: %s", exc)
            return "PUBLIC"

    def _run_classifier(self, text: str) -> str:
        """Run Layer 2 classifier scan. Returns level string."""
        triggers: list[str] = []
        try:
            level = self._classifier._scan_classifier(text, triggers)
            return level.value
        except Exception as exc:
            logger.debug("StreamingInspector classifier scan error: %s", exc)
            return "PUBLIC"

    def _trigger_termination(self, trigger: str, snippet: str) -> None:
        self.terminated = True
        self.termination_trigger = trigger
        logger.warning(
            "StreamingInspector: stream terminated trigger=%s request_id=%s",
            trigger, self._request_id,
        )
        audit_payload = {
            "event_type": "STREAM_TERMINATED",
            "trigger": trigger,
            "request_id": self._request_id,
            "session_id": self._session_id,
            "agent_id": self._agent_id,
            "accumulated_chars": len(self._full_text),
            "timestamp": time.time(),
        }
        try:
            self._on_audit("STREAM_TERMINATED", audit_payload)
        except Exception as exc:
            logger.warning("StreamingInspector audit write failed: %s", exc)


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------


def _make_chunk_payload(
    request_id: str,
    model: str,
    content: str,
    finish_reason: Optional[str] = None,
) -> str:
    """Serialize an OpenAI-format SSE chunk to a ``data: ...\n\n`` line."""
    payload = {
        "id": request_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": content},
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(payload)}\n\n"


def _make_done_sentinel() -> str:
    return "data: [DONE]\n\n"


async def stream_response(
    upstream_response,          # httpx.Response in streaming mode
    inspector: StreamingInspector,
    request_id: str,
    model: str,
    *,
    usage_callback: Optional[Callable[[int, int], None]] = None,
) -> AsyncIterator[str]:
    """
    Async generator that reads an Ollama streaming response, inspects chunks,
    and yields SSE-formatted strings to the FastAPI ``StreamingResponse``.

    Parameters
    ----------
    upstream_response
        An ``httpx.Response`` opened with ``stream=True``.  The caller is
        responsible for keeping the ``httpx.AsyncClient`` alive while this
        generator runs (use ``async with client.stream(...) as resp``).
    inspector
        Pre-configured ``StreamingInspector`` for this request.
    request_id
        Correlation ID included in every emitted chunk.
    model
        Model name included in every emitted chunk.
    usage_callback
        Optional coroutine-safe callable invoked once with
        ``(prompt_tokens, completion_tokens)`` when usage data is available.
        Called from the final chunk if the upstream includes a ``usage``
        field, or estimated from char count after stream end.
    """
    total_chars = 0
    prompt_tokens = 0
    completion_tokens = 0

    try:
        async for line in upstream_response.aiter_lines():
            line = line.strip()
            if not line:
                continue

            # Ollama streams newline-delimited JSON objects (not SSE).
            # Each object has a "message.content" field.
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("stream_response: non-JSON line skipped: %r", line[:80])
                continue

            done = obj.get("done", False)
            chunk_text = obj.get("message", {}).get("content", "")

            # Accumulate token counts from the final Ollama chunk
            if done:
                prompt_tokens = obj.get("prompt_eval_count", prompt_tokens)
                completion_tokens = obj.get("eval_count", completion_tokens or (total_chars // 4))

            if chunk_text:
                total_chars += len(chunk_text)
                clean = inspector.feed(chunk_text)
                if not clean:
                    # Inject termination chunk and close
                    yield _make_chunk_payload(
                        request_id, model,
                        _TERMINATION_CHUNK_CONTENT,
                        finish_reason="stop",
                    )
                    yield _make_done_sentinel()
                    return

                yield _make_chunk_payload(request_id, model, chunk_text)

            if done:
                # Run final LLM-layer inspection before flushing [DONE]
                clean = inspector.final_inspect()
                if not clean:
                    yield _make_chunk_payload(
                        request_id, model,
                        _TERMINATION_CHUNK_CONTENT,
                        finish_reason="stop",
                    )
                    yield _make_done_sentinel()
                    return

                yield _make_done_sentinel()
                break

    except Exception as exc:
        logger.error(
            "stream_response: upstream read error request_id=%s: %s",
            request_id, exc,
        )
        # Best-effort: emit an error chunk so the client doesn't hang
        yield _make_chunk_payload(
            request_id, model,
            "[STREAM ERROR: upstream read failed]",
            finish_reason="stop",
        )
        yield _make_done_sentinel()
        return

    # Fallback token estimate when upstream did not emit a done-with-usage chunk
    if completion_tokens == 0 and total_chars > 0:
        completion_tokens = total_chars // 4

    if usage_callback is not None:
        try:
            usage_callback(prompt_tokens, completion_tokens)
        except Exception as exc:
            logger.warning("stream_response: usage_callback raised: %s", exc)
