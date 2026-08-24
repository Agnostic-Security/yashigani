# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for `/api/chat` and `/api/generate` translation (request shape +
byte-shape of the streamed NDJSON output)."""

from __future__ import annotations

import json

from kuroshio.shim.chat import chat_event_to_ndjson, translate_chat_request, translate_sse_lines_to_ndjson
from kuroshio.shim.framing import format_sse_event
from kuroshio.shim.generate import (
    generate_event_to_ndjson,
    translate_generate_request,
)
from kuroshio.shim.generate import translate_sse_lines_to_ndjson as translate_generate_sse_lines_to_ndjson


def test_translate_chat_request_maps_messages_and_options() -> None:
    ollama_request = {
        "model": "llama3:8b",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
        "options": {"temperature": 0.7, "num_predict": 128, "seed": 42},
    }
    llama_request = translate_chat_request(ollama_request)
    assert llama_request["messages"] == [{"role": "user", "content": "hi"}]
    assert llama_request["stream"] is True
    assert llama_request["temperature"] == 0.7
    assert llama_request["n_predict"] == 128
    assert llama_request["seed"] == 42


def test_translate_chat_request_defaults_stream_true() -> None:
    llama_request = translate_chat_request({"messages": []})
    assert llama_request["stream"] is True


# --- Red-Council C1 (2026-07-29): cache_prompt must always be explicit ---


def test_translate_chat_request_defaults_cache_prompt_to_false() -> None:
    """Ava's T2: the outgoing llama-server body must contain an explicit
    cache_prompt field — this must never fall through to llama-server's own
    (permissive) default by omission."""
    llama_request = translate_chat_request({"messages": []})
    assert llama_request["cache_prompt"] is False


def test_translate_chat_request_honours_explicit_cache_prompt_true() -> None:
    llama_request = translate_chat_request({"messages": []}, cache_prompt=True)
    assert llama_request["cache_prompt"] is True


def test_chat_event_to_ndjson_intermediate_chunk_shape() -> None:
    line, is_final = chat_event_to_ndjson({"content": "hel", "stop": False}, "llama3:8b")
    assert is_final is False
    obj = json.loads(line.decode("utf-8").rstrip("\n"))
    assert obj["model"] == "llama3:8b"
    assert obj["message"] == {"role": "assistant", "content": "hel"}
    assert obj["done"] is False
    assert "done_reason" not in obj


def test_chat_event_to_ndjson_final_chunk_carries_timings() -> None:
    event = {
        "content": "",
        "stop": True,
        "tokens_evaluated": 12,
        "tokens_predicted": 34,
        "timings": {"predicted_ms": 456.7},
    }
    line, is_final = chat_event_to_ndjson(event, "llama3:8b")
    assert is_final is True
    obj = json.loads(line.decode("utf-8").rstrip("\n"))
    assert obj["done"] is True
    assert obj["done_reason"] == "stop"
    assert obj["eval_count"] == 34
    assert obj["prompt_eval_count"] == 12
    assert obj["total_duration"] == 456.7


def test_translate_sse_lines_to_ndjson_end_to_end_byte_shape() -> None:
    """The full pipeline: real SSE `data: ...\\n\\n` framed text lines in,
    bare NDJSON (no `data:` prefix, one JSON object per line) out."""
    sse_text = (
        format_sse_event({"content": "Hel", "stop": False})
        + format_sse_event({"content": "lo", "stop": False})
        + format_sse_event({"content": "", "stop": True, "timings": {"predicted_ms": 10}})
    )
    raw_lines = sse_text.splitlines()
    ndjson_lines = list(translate_sse_lines_to_ndjson(raw_lines, "llama3:8b"))

    assert len(ndjson_lines) == 3
    for line in ndjson_lines:
        assert not line.startswith(b"data:")
        assert line.endswith(b"\n")
        json.loads(line)  # every line parses standalone

    last = json.loads(ndjson_lines[-1])
    assert last["done"] is True


def test_translate_generate_request_maps_prompt_and_system() -> None:
    ollama_request = {"model": "x", "prompt": "why is the sky blue?", "system": "be concise", "stream": False}
    llama_request = translate_generate_request(ollama_request)
    assert llama_request["prompt"] == "why is the sky blue?"
    assert llama_request["system_prompt"] == "be concise"
    assert llama_request["stream"] is False


def test_translate_generate_request_defaults_cache_prompt_to_false() -> None:
    llama_request = translate_generate_request({"prompt": "x"})
    assert llama_request["cache_prompt"] is False


def test_translate_generate_request_honours_explicit_cache_prompt_true() -> None:
    llama_request = translate_generate_request({"prompt": "x"}, cache_prompt=True)
    assert llama_request["cache_prompt"] is True


def test_generate_event_to_ndjson_uses_response_field_not_message() -> None:
    line, is_final = generate_event_to_ndjson({"content": "tok", "stop": False}, "x")
    obj = json.loads(line.decode("utf-8").rstrip("\n"))
    assert obj["response"] == "tok"
    assert "message" not in obj
    assert is_final is False


def test_generate_final_chunk_carries_context_field() -> None:
    event = {"content": "", "stop": True, "tokens_cached_ids": [1, 2, 3], "timings": {"predicted_ms": 5}}
    line, is_final = generate_event_to_ndjson(event, "x")
    obj = json.loads(line.decode("utf-8").rstrip("\n"))
    assert is_final is True
    assert obj["context"] == [1, 2, 3]


def test_translate_generate_sse_lines_end_to_end() -> None:
    sse_text = format_sse_event({"content": "a", "stop": False}) + format_sse_event(
        {"content": "", "stop": True, "timings": {}}
    )
    lines = list(translate_generate_sse_lines_to_ndjson(sse_text.splitlines(), "x"))
    assert len(lines) == 2
    assert json.loads(lines[0])["response"] == "a"
    assert json.loads(lines[1])["done"] is True
