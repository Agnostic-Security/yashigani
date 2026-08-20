# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Byte-shape framing helpers: llama-server SSE <-> ollama bare NDJSON.

llama-server (like the OpenAI streaming convention it shares) frames each
event as:

    data: {"content": "...", "stop": false}\\n\\n
    ...
    data: {"content": "", "stop": true, "timings": {...}}\\n\\n

Ollama's native `/api/chat`/`/api/generate` instead stream **bare NDJSON**
— one JSON object per line, no `data: ` prefix, no blank-line separators,
no terminal `[DONE]` sentinel; the stream simply ends after the line where
`"done": true`. Getting this framing wrong is silent at the shim layer (the
JSON is still valid) and only breaks at real ollama-API consumers — hence
the council review's insistence on byte-shape assertions in tests, not just
"valid JSON" checks.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Iterable, Iterator

SSE_DONE_SENTINEL = "[DONE]"


class SSEFramingError(ValueError):
    """Raised when an SSE line does not match the expected `data: ...` shape."""


class SSELine(Enum):
    """Non-event outcomes of parsing a single SSE line (see `parse_sse_line`)."""

    SEPARATOR = "separator"  # a blank event-separator line — carries no event, keep reading
    DONE = "done"  # the terminal `data: [DONE]` sentinel — end of stream


def parse_sse_line(raw_line: str) -> dict[str, Any] | SSELine:
    """Parse ONE line of an SSE text stream (the single-line primitive shared by
    both the whole-stream `parse_sse_events` generator and `app.py`'s streaming
    route handlers, so the two can never diverge).

    Returns:
      - the decoded JSON dict for a `data: {...}` event frame;
      - `SSELine.SEPARATOR` for a blank event-separator line (no event — keep
        reading);
      - `SSELine.DONE` for the terminal `data: [DONE]` sentinel (end of stream).

    Raises `SSEFramingError` for a line that is neither blank nor a `data:`
    frame, or a `data:` frame whose payload is not valid JSON — a malformed
    frame fails loudly rather than silently vanishing (the failure mode that
    matters at real ollama-API consumers).
    """
    line = raw_line.rstrip("\r\n")
    if line == "":
        return SSELine.SEPARATOR
    if not line.startswith("data:"):
        raise SSEFramingError(f"expected an SSE 'data:' line, got: {raw_line!r}")
    payload = line[len("data:") :].strip()
    if payload == SSE_DONE_SENTINEL:
        return SSELine.DONE
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SSEFramingError(f"SSE data payload is not valid JSON: {payload!r} ({exc})") from exc


def parse_sse_events(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Parse an SSE byte-stream (as text lines) into decoded JSON event dicts.

    Blank lines (event separators) and the terminal `data: [DONE]` sentinel
    are consumed silently; anything not prefixed `data: ` is refused rather
    than silently dropped (a malformed frame should fail loudly, not vanish).
    Delegates per-line parsing to `parse_sse_line` so the framing rules live in
    exactly one place.
    """
    for raw_line in lines:
        parsed = parse_sse_line(raw_line)
        if parsed is SSELine.SEPARATOR:
            continue
        if parsed is SSELine.DONE:
            return
        yield parsed


def format_sse_event(obj: dict[str, Any]) -> str:
    """Build one `data: {...}\\n\\n` SSE frame (used by tests to build fixtures)."""
    return f"data: {json.dumps(obj)}\n\n"


def format_ndjson_line(obj: dict[str, Any]) -> bytes:
    """Build one bare-NDJSON line: `{...}\\n`, no `data:` prefix, no blank separator."""
    return (json.dumps(obj) + "\n").encode("utf-8")


__all__ = [
    "SSEFramingError",
    "SSELine",
    "SSE_DONE_SENTINEL",
    "parse_sse_line",
    "parse_sse_events",
    "format_sse_event",
    "format_ndjson_line",
]
