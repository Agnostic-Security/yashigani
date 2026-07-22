# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Byte-shape framing tests: llama-server SSE <-> ollama NDJSON — the highest
implementation-risk piece per the council review. Assertions are on exact
byte shape, not just "valid JSON" (a wrong-but-parseable shape is the failure
mode that matters here)."""

from __future__ import annotations

import json

import pytest

from yashigani_infer.shim.framing import (
    SSEFramingError,
    format_ndjson_line,
    format_sse_event,
    parse_sse_events,
)


def test_parse_sse_events_decodes_data_lines() -> None:
    lines = [
        format_sse_event({"content": "hel"}),
        format_sse_event({"content": "lo"}),
        "data: [DONE]\n\n",
    ]
    # format_sse_event returns a full "data: ...\n\n" chunk; split to simulate
    # a real line-oriented reader (blank-line separators included).
    raw_lines = "".join(lines).splitlines()
    events = list(parse_sse_events(raw_lines))
    assert events == [{"content": "hel"}, {"content": "lo"}]


def test_parse_sse_events_stops_at_done_sentinel_and_ignores_trailer() -> None:
    raw_lines = ["data: " + json.dumps({"content": "x"}), "", "data: [DONE]", 'data: {"content": "never"}']
    events = list(parse_sse_events(raw_lines))
    assert events == [{"content": "x"}]


def test_parse_sse_events_rejects_non_data_line() -> None:
    with pytest.raises(SSEFramingError, match="expected an SSE"):
        list(parse_sse_events(["not-a-data-line"]))


def test_parse_sse_events_rejects_malformed_json_payload() -> None:
    with pytest.raises(SSEFramingError, match="not valid JSON"):
        list(parse_sse_events(["data: {not valid json"]))


def test_format_ndjson_line_has_no_data_prefix_and_ends_in_single_newline() -> None:
    line = format_ndjson_line({"done": True})
    assert line == b'{"done": true}\n'
    assert not line.startswith(b"data:")
    assert line.count(b"\n") == 1


def test_ndjson_line_is_directly_json_parseable_without_stripping_anything() -> None:
    line = format_ndjson_line({"model": "x", "done": False})
    parsed = json.loads(line.decode("utf-8").rstrip("\n"))
    assert parsed == {"model": "x", "done": False}
