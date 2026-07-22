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
from typing import Any, Iterable, Iterator

SSE_DONE_SENTINEL = "[DONE]"


class SSEFramingError(ValueError):
    """Raised when an SSE line does not match the expected `data: ...` shape."""


def parse_sse_events(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Parse an SSE byte-stream (as text lines) into decoded JSON event dicts.

    Blank lines (event separators) and the terminal `data: [DONE]` sentinel
    are consumed silently; anything not prefixed `data: ` is refused rather
    than silently dropped (a malformed frame should fail loudly, not vanish).
    """
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if line == "":
            continue
        if not line.startswith("data:"):
            raise SSEFramingError(f"expected an SSE 'data:' line, got: {raw_line!r}")
        payload = line[len("data:") :].strip()
        if payload == SSE_DONE_SENTINEL:
            return
        try:
            yield json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SSEFramingError(f"SSE data payload is not valid JSON: {payload!r} ({exc})") from exc


def format_sse_event(obj: dict[str, Any]) -> str:
    """Build one `data: {...}\\n\\n` SSE frame (used by tests to build fixtures)."""
    return f"data: {json.dumps(obj)}\n\n"


def format_ndjson_line(obj: dict[str, Any]) -> bytes:
    """Build one bare-NDJSON line: `{...}\\n`, no `data:` prefix, no blank separator."""
    return (json.dumps(obj) + "\n").encode("utf-8")


__all__ = ["SSEFramingError", "SSE_DONE_SENTINEL", "parse_sse_events", "format_sse_event", "format_ndjson_line"]
