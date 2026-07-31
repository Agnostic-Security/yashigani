# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Test-only helper: hand-build tiny, valid GGUF byte blobs.

NOT part of the shipped package (lives under tests/) — no real multi-GB
model is ever required to test the parser; this constructs the smallest
possible valid header + a couple of tiny tensor-info entries by hand,
matching the binary layout documented in
`kuroshio.gguf.header`.
"""

from __future__ import annotations

import struct

MAGIC = b"GGUF"

_T_UINT32 = 4
_T_STRING = 8
_T_UINT64 = 10


def _pack_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def _pack_kv(key: str, value_type: int, value_bytes: bytes) -> bytes:
    return _pack_string(key) + struct.pack("<I", value_type) + value_bytes


#: A minimal, syntactically-valid Jinja chat template — used as the DEFAULT
#: `chat_template` for every fixture GGUF this builder produces, so a real
#: model's GGUF (which virtually always carries one) is the realistic
#: default test shape. Tests that specifically exercise the H4 fail-closed
#: guard (Red-Council 2026-07-29) pass `chat_template=None` explicitly.
DEFAULT_CHAT_TEMPLATE = "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}"


def build_minimal_gguf(
    *,
    architecture: str = "llama",
    name: str = "tiny-test-model",
    file_type: int | None = 15,  # Q4_K_M
    version: int = 3,
    tensors: list[tuple[str, tuple[int, ...], int]] | None = None,
    chat_template: str | None = DEFAULT_CHAT_TEMPLATE,
    license: str | None = None,
) -> bytes:
    """Build a minimal, spec-valid GGUF byte blob (header + KV metadata + tensor
    info only — no tensor payload bytes, since the parser never reads those).

    Args:
        tensors: list of (name, dimensions, ggml_type) tuples. Defaults to
            two small tensors whose element counts sum to a known, easily
            asserted total.
        chat_template: `tokenizer.chat_template` KV value. Defaults to a
            minimal valid template (realistic default — real GGUFs almost
            always carry one); pass `None` to build a fixture that
            deliberately lacks one (Red-Council H4 fail-closed-guard tests).
    """
    if tensors is None:
        tensors = [
            ("token_embd.weight", (32, 8), 0),  # 256 elements, F32
            ("output.weight", (32, 8), 0),  # 256 elements, F32
        ]

    kv_entries = [
        _pack_kv("general.architecture", _T_STRING, _pack_string(architecture)),
        _pack_kv("general.name", _T_STRING, _pack_string(name)),
    ]
    if chat_template is not None:
        kv_entries.append(_pack_kv("tokenizer.chat_template", _T_STRING, _pack_string(chat_template)))
    if license is not None:
        kv_entries.append(_pack_kv("general.license", _T_STRING, _pack_string(license)))
    if file_type is not None:
        kv_entries.append(_pack_kv("general.file_type", _T_UINT32, struct.pack("<I", file_type)))

    tensor_info = b""
    for tensor_name, dims, ggml_type in tensors:
        tensor_info += _pack_string(tensor_name)
        tensor_info += struct.pack("<I", len(dims))
        for dim in dims:
            tensor_info += struct.pack("<Q", dim)
        tensor_info += struct.pack("<I", ggml_type)
        tensor_info += struct.pack("<Q", 0)  # offset (unused by the parser)

    header = MAGIC
    header += struct.pack("<I", version)
    header += struct.pack("<Q", len(tensors))
    header += struct.pack("<Q", len(kv_entries))
    header += b"".join(kv_entries)
    header += tensor_info
    return header


__all__ = ["DEFAULT_CHAT_TEMPLATE", "build_minimal_gguf"]
