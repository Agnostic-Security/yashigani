# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the pure-Python GGUF header parser."""

from __future__ import annotations

import struct

import pytest

from tests.fixtures.gguf_builder import build_minimal_gguf
from kuroshio.gguf.header import GGUFParseError, parse_gguf_header


def test_parses_magic_version_and_architecture(minimal_gguf_bytes: bytes) -> None:
    header = parse_gguf_header(minimal_gguf_bytes)
    assert header.version == 3
    assert header.architecture == "llama"
    assert header.name == "tiny-test-model"


# --- Red-Council H4 (2026-07-29): chat_template extraction ---


def test_chat_template_extracts_the_embedded_jinja_template() -> None:
    from tests.fixtures.gguf_builder import DEFAULT_CHAT_TEMPLATE

    data = build_minimal_gguf(chat_template="{{ custom template }}")
    header = parse_gguf_header(data)
    assert header.chat_template == "{{ custom template }}"
    assert header.chat_template != DEFAULT_CHAT_TEMPLATE  # sanity: this fixture overrode the default


def test_chat_template_is_none_when_absent_from_the_header() -> None:
    data = build_minimal_gguf(chat_template=None)
    header = parse_gguf_header(data)
    assert header.chat_template is None


def test_chat_template_is_none_when_blank_or_whitespace_only() -> None:
    data = build_minimal_gguf(chat_template="   ")
    header = parse_gguf_header(data)
    assert header.chat_template is None


def test_total_parameters_and_parameter_size_label() -> None:
    data = build_minimal_gguf(tensors=[("a", (10, 10), 0), ("b", (10, 10), 0)])
    header = parse_gguf_header(data)
    assert header.total_parameters == 200
    assert header.parameter_size_label() == "200"


def test_parameter_size_label_scales_to_millions_and_billions() -> None:
    data = build_minimal_gguf(tensors=[("a", (2_000_000,), 0)])
    header = parse_gguf_header(data)
    assert header.parameter_size_label() == "2.0M"

    data_b = build_minimal_gguf(tensors=[("a", (3_000_000_000,), 0)])
    header_b = parse_gguf_header(data_b)
    assert header_b.parameter_size_label() == "3.0B"


def test_quantization_level_from_file_type() -> None:
    data = build_minimal_gguf(file_type=15)  # Q4_K_M
    header = parse_gguf_header(data)
    assert header.quantization_level == "Q4_K_M"


def test_quantization_level_falls_back_to_majority_tensor_type() -> None:
    data = build_minimal_gguf(
        file_type=None,
        tensors=[("a", (4,), 8), ("b", (4,), 8), ("c", (4,), 1)],  # majority ggml_type 8 = Q8_0
    )
    header = parse_gguf_header(data)
    assert header.quantization_level == "Q8_0"


def test_unknown_file_type_falls_back_to_labelled_unknown() -> None:
    data = build_minimal_gguf(file_type=9999)
    header = parse_gguf_header(data)
    assert header.quantization_level == "UNKNOWN(9999)"


def test_parse_tensors_false_skips_tensor_info() -> None:
    data = build_minimal_gguf()
    header = parse_gguf_header(data, parse_tensors=False)
    assert header.tensors == ()
    assert header.total_parameters == 0


def test_parses_from_path(tmp_path) -> None:
    path = tmp_path / "model.gguf"
    path.write_bytes(build_minimal_gguf())
    header = parse_gguf_header(path)
    assert header.name == "tiny-test-model"


def test_rejects_bad_magic() -> None:
    with pytest.raises(GGUFParseError, match="bad magic"):
        parse_gguf_header(b"NOPE" + b"\x00" * 20)


def test_rejects_unsupported_version() -> None:
    data = b"GGUF" + struct.pack("<I", 99) + struct.pack("<Q", 0) + struct.pack("<Q", 0)
    with pytest.raises(GGUFParseError, match="unsupported GGUF version"):
        parse_gguf_header(data)


def test_rejects_truncated_file() -> None:
    data = build_minimal_gguf()
    with pytest.raises(GGUFParseError, match="unexpected EOF"):
        parse_gguf_header(data[:20])


def test_rejects_kv_count_over_ceiling() -> None:
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 200_000)
    with pytest.raises(GGUFParseError, match="metadata_kv_count"):
        parse_gguf_header(data)


def test_rejects_tensor_count_over_ceiling() -> None:
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 300_000) + struct.pack("<Q", 0)
    with pytest.raises(GGUFParseError, match="tensor_count"):
        parse_gguf_header(data)


def test_rejects_string_length_over_ceiling() -> None:
    # magic+version+tensor_count(0)+kv_count(1) then a key claiming a huge length
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
    data += struct.pack("<Q", 2**31)  # absurd string length, never followed by real bytes
    with pytest.raises(GGUFParseError, match="string length"):
        parse_gguf_header(data)


def test_rejects_tensor_dimension_over_ceiling() -> None:
    data = build_minimal_gguf(tensors=[("huge", (1 << 50,), 0)])
    with pytest.raises(GGUFParseError, match="exceeding ceiling"):
        parse_gguf_header(data)


def test_rejects_non_utf8_string() -> None:
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
    bad_bytes = b"\xff\xfe"
    data += struct.pack("<Q", len(bad_bytes)) + bad_bytes
    with pytest.raises(GGUFParseError, match="not valid utf-8"):
        parse_gguf_header(data)
