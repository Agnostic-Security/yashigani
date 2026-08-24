# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Byte-shape framing tests: llama-server SSE <-> ollama NDJSON — the highest
implementation-risk piece per the council review. Assertions are on exact
byte shape, not just "valid JSON" (a wrong-but-parseable shape is the failure
mode that matters here)."""

from __future__ import annotations

import json

import pytest

from kuroshio.shim.framing import (
    SSEFramingError,
    SSELine,
    format_ndjson_line,
    format_sse_event,
    parse_sse_events,
    parse_sse_line,
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


# --- Red-Council Tom F5 (2026-07-29): the single-line parser app.py now shares ---
# app.py previously carried its own weaker inline SSE parser; these assert the
# shared `parse_sse_line` covers exactly the cases app.py's streaming routes hit.


def test_parse_sse_line_decodes_a_data_frame() -> None:
    assert parse_sse_line('data: {"content": "Hi", "stop": false}') == {"content": "Hi", "stop": False}


def test_parse_sse_line_treats_a_blank_separator_line_as_a_no_event_separator() -> None:
    # `format_sse_event` emits `data: {...}\n\n`, so a real line reader yields a
    # trailing blank line after every frame — app.py's loop must skip it.
    assert parse_sse_line("") is SSELine.SEPARATOR
    assert parse_sse_line("\n") is SSELine.SEPARATOR


def test_parse_sse_line_treats_the_done_sentinel_as_end_of_stream() -> None:
    assert parse_sse_line("data: [DONE]") is SSELine.DONE


def test_parse_sse_line_strips_trailing_crlf_before_parsing() -> None:
    assert parse_sse_line('data: {"content": "x"}\r\n') == {"content": "x"}


def test_parse_sse_line_rejects_a_non_data_line_loudly() -> None:
    """The old inline app.py parser silently dropped non-`data:` lines; the
    shared parser fails loud instead (a malformed frame must never vanish)."""
    with pytest.raises(SSEFramingError, match="expected an SSE"):
        parse_sse_line("garbage line")


def test_parse_sse_line_rejects_a_malformed_json_payload_loudly() -> None:
    with pytest.raises(SSEFramingError, match="not valid JSON"):
        parse_sse_line("data: {not valid json")


def test_parse_sse_line_and_parse_sse_events_agree_on_a_full_frame_stream() -> None:
    """The generator is now built on the single-line primitive — driving the
    per-line parser over app.py's exact byte shape reproduces the same events."""
    raw = format_sse_event({"content": "hel"}) + format_sse_event({"content": "lo"}) + "data: [DONE]\n\n"
    lines = raw.splitlines()

    events = [parsed for line in lines if isinstance(parsed := parse_sse_line(line), dict)]
    assert events == list(parse_sse_events(lines)) == [{"content": "hel"}, {"content": "lo"}]


def test_format_ndjson_line_has_no_data_prefix_and_ends_in_single_newline() -> None:
    line = format_ndjson_line({"done": True})
    assert line == b'{"done": true}\n'
    assert not line.startswith(b"data:")
    assert line.count(b"\n") == 1


def test_ndjson_line_is_directly_json_parseable_without_stripping_anything() -> None:
    line = format_ndjson_line({"model": "x", "done": False})
    parsed = json.loads(line.decode("utf-8").rstrip("\n"))
    assert parsed == {"model": "x", "done": False}
