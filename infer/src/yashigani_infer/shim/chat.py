# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/chat` translation: ollama request/response <-> llama-server.

NOTE (known gap, deliberately out of v1-foundation scope): the council
review's Laura F4 finding (GGUF-embedded `chat_template` injection) calls
for pinning a vetted server-side template family and diffing GGUF-embedded
templates against known-good before this shim goes anywhere near
production traffic. That is a template-registry/config concern layered on
top of this translation function, not built here — flagged so it is not
mistaken for "already handled."
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from yashigani_infer.shim.framing import format_ndjson_line, parse_sse_events

# Ollama `options` -> llama-server native sampling-param names.
_OPTION_MAP: dict[str, str] = {
    "temperature": "temperature",
    "top_p": "top_p",
    "top_k": "top_k",
    "num_predict": "n_predict",
    "num_ctx": "n_ctx",
    "repeat_penalty": "repeat_penalty",
    "seed": "seed",
    "stop": "stop",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def translate_chat_request(ollama_request: dict[str, Any]) -> dict[str, Any]:
    """Translate an ollama `/api/chat` request body into a llama-server request body."""
    messages = ollama_request.get("messages", [])
    llama_request: dict[str, Any] = {
        "messages": list(messages),
        "stream": bool(ollama_request.get("stream", True)),
    }
    options = ollama_request.get("options") or {}
    for ollama_key, llama_key in _OPTION_MAP.items():
        if ollama_key in options:
            llama_request[llama_key] = options[ollama_key]
    return llama_request


def _ndjson_chunk(model: str, content: str, *, done: bool, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "model": model,
        "created_at": _now_iso(),
        "message": {"role": "assistant", "content": content},
        "done": done,
    }
    if extra:
        obj.update(extra)
    return obj


def chat_event_to_ndjson(event: dict[str, Any], model: str) -> tuple[bytes, bool]:
    """Translate ONE decoded llama-server SSE event dict into one ollama NDJSON line.

    Each llama-server event is shaped `{"content": str, "stop": bool,
    "timings": {...}}` (native completion streaming shape). The final event
    (`stop: true`) becomes the ollama `"done": true` line, carrying through
    whatever timing stats llama-server reported (`total_duration`,
    `eval_count`, `eval_duration` — the fields the GPU-pressure dashboard
    and existing consumers read).

    Returns `(ndjson_line_bytes, is_final)` — exposed per-event (rather than
    only as a batch translator) so a true streaming caller (the async HTTP
    app) can forward each line to the client as it arrives, without
    buffering the whole response first.
    """
    stop = bool(event.get("stop", False))
    content = str(event.get("content", ""))
    if not stop:
        return format_ndjson_line(_ndjson_chunk(model, content, done=False)), False

    timings = event.get("timings") or {}
    extra = {
        "done_reason": "stop",
        "total_duration": timings.get("predicted_ms", 0),
        "prompt_eval_count": event.get("tokens_evaluated", 0),
        "eval_count": event.get("tokens_predicted", 0),
        "eval_duration": timings.get("predicted_ms", 0),
    }
    return format_ndjson_line(_ndjson_chunk(model, content, done=True, extra=extra)), True


def translate_chat_events_to_ndjson(events: Iterable[dict[str, Any]], model: str) -> Iterator[bytes]:
    """Translate a sequence of decoded llama-server SSE event dicts into ollama NDJSON lines."""
    for event in events:
        line, is_final = chat_event_to_ndjson(event, model)
        yield line
        if is_final:
            return


def translate_sse_lines_to_ndjson(sse_lines: Iterable[str], model: str) -> Iterator[bytes]:
    """Convenience wrapper: parse raw SSE text lines, then translate to NDJSON bytes."""
    return translate_chat_events_to_ndjson(parse_sse_events(sse_lines), model)


__all__ = [
    "translate_chat_request",
    "chat_event_to_ndjson",
    "translate_chat_events_to_ndjson",
    "translate_sse_lines_to_ndjson",
]
