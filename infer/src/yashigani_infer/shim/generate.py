# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/generate` translation: ollama's prompt-based (non-chat) endpoint.

Same NDJSON-vs-SSE re-framing risk as `/api/chat` (chat.py), but the
response body shape differs: ollama uses a bare `"response"` string field
per chunk instead of a `"message": {"role", "content"}` object.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from yashigani_infer.shim.framing import format_ndjson_line, parse_sse_events

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


def translate_generate_request(ollama_request: dict[str, Any]) -> dict[str, Any]:
    """Translate an ollama `/api/generate` request body into a llama-server request body."""
    llama_request: dict[str, Any] = {
        "prompt": ollama_request.get("prompt", ""),
        "stream": bool(ollama_request.get("stream", True)),
    }
    if ollama_request.get("system"):
        llama_request["system_prompt"] = ollama_request["system"]
    options = ollama_request.get("options") or {}
    for ollama_key, llama_key in _OPTION_MAP.items():
        if ollama_key in options:
            llama_request[llama_key] = options[ollama_key]
    return llama_request


def _ndjson_chunk(model: str, response: str, *, done: bool, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "model": model,
        "created_at": _now_iso(),
        "response": response,
        "done": done,
    }
    if extra:
        obj.update(extra)
    return obj


def generate_event_to_ndjson(event: dict[str, Any], model: str) -> tuple[bytes, bool]:
    """Translate ONE decoded llama-server SSE event into one ollama NDJSON line.

    Returns `(ndjson_line_bytes, is_final)` — see `chat.chat_event_to_ndjson`
    for why this is exposed per-event rather than only as a batch translator.
    """
    stop = bool(event.get("stop", False))
    content = str(event.get("content", ""))
    if not stop:
        return format_ndjson_line(_ndjson_chunk(model, content, done=False)), False

    timings = event.get("timings") or {}
    extra = {
        "done_reason": "stop",
        "context": event.get("tokens_cached_ids", []),
        "total_duration": timings.get("predicted_ms", 0),
        "prompt_eval_count": event.get("tokens_evaluated", 0),
        "eval_count": event.get("tokens_predicted", 0),
        "eval_duration": timings.get("predicted_ms", 0),
    }
    return format_ndjson_line(_ndjson_chunk(model, content, done=True, extra=extra)), True


def translate_generate_events_to_ndjson(events: Iterable[dict[str, Any]], model: str) -> Iterator[bytes]:
    for event in events:
        line, is_final = generate_event_to_ndjson(event, model)
        yield line
        if is_final:
            return


def translate_sse_lines_to_ndjson(sse_lines: Iterable[str], model: str) -> Iterator[bytes]:
    return translate_generate_events_to_ndjson(parse_sse_events(sse_lines), model)


__all__ = [
    "translate_generate_request",
    "generate_event_to_ndjson",
    "translate_generate_events_to_ndjson",
    "translate_sse_lines_to_ndjson",
]
