# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Pure-Python GGUF header/metadata parser.

GGUF binary layout (spec: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md):

    magic:                b"GGUF"                       4 bytes
    version:              uint32 LE                      (this parser supports v2, v3)
    tensor_count:         uint64 LE
    metadata_kv_count:    uint64 LE
    metadata_kv[metadata_kv_count]:
        key:              gguf_string  (uint64 length + utf-8 bytes)
        value_type:       uint32 (GGUFValueType)
        value:            per value_type
    tensor_info[tensor_count]:
        name:             gguf_string
        n_dimensions:     uint32
        dimensions:       n_dimensions x uint64
        type:             uint32 (ggml_type)
        offset:           uint64

This module reads only the header + metadata + tensor-info sections — never
the tensor payload bytes, which can be many gigabytes. It is intentionally
defensive: GGUF files are untrusted input (imported from Hugging Face, a
user's Ollama/LM-Studio store, or a raw file path), so string/array/kv
counts are bounds-checked against sane ceilings rather than trusted at face
value. This does NOT replace the C++ parser's own CVE-gated hardening in
llama-server (council review Medium finding) — this is a narrow, independent
Python reader used only to synthesize ollama-shim metadata (`/api/tags`,
`/api/show`), so a malformed file fails this parser closed rather than
propagating a bogus/partial result to the shim.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from kuroshio.gguf.quant_types import ftype_name, ggml_type_name

MAGIC = b"GGUF"
SUPPORTED_VERSIONS = (2, 3)

# Defensive ceilings against a malicious/corrupt file — these are generous
# relative to any real GGUF model in the wild, chosen only to bound worst-case
# memory/time on a hostile input, never to reject legitimate models.
MAX_KV_COUNT = 100_000
MAX_TENSOR_COUNT = 200_000
MAX_STRING_LENGTH = 1 << 20  # 1 MiB
MAX_ARRAY_LENGTH = 10_000_000
MAX_DIMENSIONS = 8
# A single tensor axis ceiling — real models never claim a billion-plus
# element single dimension. Bounds `total_parameters`/`parameter_size_label`
# against a hostile file claiming an absurd per-axis size (red-council item
# #6: "bounds-check field sizes/counts, reject oversized/malformed").
MAX_DIMENSION_VALUE = 1 << 40


class GGUFParseError(ValueError):
    """Raised for any malformed, truncated, or out-of-bounds GGUF header."""


# GGUFValueType enum
_T_UINT8 = 0
_T_INT8 = 1
_T_UINT16 = 2
_T_INT16 = 3
_T_UINT32 = 4
_T_INT32 = 5
_T_FLOAT32 = 6
_T_BOOL = 7
_T_STRING = 8
_T_ARRAY = 9
_T_UINT64 = 10
_T_INT64 = 11
_T_FLOAT64 = 12

_SCALAR_STRUCT: dict[int, tuple[str, int]] = {
    _T_UINT8: ("<B", 1),
    _T_INT8: ("<b", 1),
    _T_UINT16: ("<H", 2),
    _T_INT16: ("<h", 2),
    _T_UINT32: ("<I", 4),
    _T_INT32: ("<i", 4),
    _T_FLOAT32: ("<f", 4),
    _T_BOOL: ("<B", 1),
    _T_UINT64: ("<Q", 8),
    _T_INT64: ("<q", 8),
    _T_FLOAT64: ("<d", 8),
}


@dataclass(frozen=True)
class TensorInfo:
    name: str
    dimensions: tuple[int, ...]
    ggml_type: int
    offset: int

    @property
    def element_count(self) -> int:
        n = 1
        for d in self.dimensions:
            n *= d
        return n


@dataclass(frozen=True)
class GGUFHeader:
    """Parsed GGUF header: version, KV metadata, and tensor-info table."""

    version: int
    tensor_count: int
    metadata: dict[str, Any]
    tensors: tuple[TensorInfo, ...] = field(default_factory=tuple)

    @property
    def architecture(self) -> str | None:
        return self.metadata.get("general.architecture")

    @property
    def name(self) -> str | None:
        return self.metadata.get("general.name")

    @property
    def chat_template(self) -> str | None:
        """`tokenizer.chat_template` — the Jinja template llama.cpp uses to
        render an ollama-shim `messages[]` array into the actual prompt
        string sent to the model (Red-Council H4, Ava/Tom, 2026-07-29
        design-review). Missing/blank means llama.cpp falls back to its own
        built-in default (or, for some architectures, produces silently
        mis-rendered role-turns) — a different chat_template FAMILY
        (ChatML/Llama3/Mistral/Gemma) does not error, it produces a subtly
        wrong completion at HTTP 200. This property only EXTRACTS the raw
        field (already present in `metadata` via the generic KV parser above
        — no parser change needed); the fail-closed GUARD that refuses to
        serve a model without one lives at the call site
        (`app.py::_require_chat_template`), not here — this class stays a
        pure, side-effect-free header reader.
        """
        value = self.metadata.get("tokenizer.chat_template")
        return value if isinstance(value, str) and value.strip() else None

    @property
    def license(self) -> str | None:
        """`general.license` (fallback `general.license.name`) — the model's
        self-declared licence id. Pure extraction, like `chat_template`: the
        licence-alert policy (Tiago 2026-07-31, warn-not-block on imports
        whose licence isn't recognised commercial-free) lives in
        :mod:`kuroshio.licensing`, not here.
        """
        for key in ("general.license", "general.license.name"):
            value = self.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @property
    def total_parameters(self) -> int:
        """Sum of element counts across all tensors — an approximation of
        parameter count (real per-architecture accounting can differ
        slightly, e.g. excluding tied embeddings). Good enough for the
        ollama-shim `parameter_size` display field."""
        return sum(t.element_count for t in self.tensors)

    @property
    def quantization_level(self) -> str:
        """Human-readable quantization name for `/api/tags` `details.quantization_level`.

        Prefers the model-declared `general.file_type`; falls back to the
        majority tensor storage type when absent.
        """
        file_type = self.metadata.get("general.file_type")
        if isinstance(file_type, int):
            return ftype_name(file_type)
        if self.tensors:
            counts: dict[int, int] = {}
            for t in self.tensors:
                counts[t.ggml_type] = counts.get(t.ggml_type, 0) + 1
            majority = max(counts.items(), key=lambda kv: kv[1])[0]
            return ggml_type_name(majority)
        return "unknown"

    def parameter_size_label(self) -> str:
        """Human label like Ollama's `details.parameter_size` (e.g. "7.2B")."""
        return _humanize_param_count(self.total_parameters)


def _humanize_param_count(n: int) -> str:
    if n <= 0:
        return "0"
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _read_exact(fh: BinaryIO, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise GGUFParseError(f"unexpected EOF: wanted {n} bytes, got {len(data)}")
    return data


def _read_uint32(fh: BinaryIO) -> int:
    (value,) = struct.unpack("<I", _read_exact(fh, 4))
    return value


def _read_uint64(fh: BinaryIO) -> int:
    (value,) = struct.unpack("<Q", _read_exact(fh, 8))
    return value


def _read_gguf_string(fh: BinaryIO) -> str:
    length = _read_uint64(fh)
    if length > MAX_STRING_LENGTH:
        raise GGUFParseError(f"string length {length} exceeds ceiling {MAX_STRING_LENGTH}")
    raw = _read_exact(fh, length)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GGUFParseError(f"GGUF string is not valid utf-8: {exc}") from exc


def _read_value(fh: BinaryIO, value_type: int, *, _depth: int = 0) -> Any:
    if value_type == _T_STRING:
        return _read_gguf_string(fh)
    if value_type == _T_BOOL:
        (raw,) = struct.unpack("<B", _read_exact(fh, 1))
        return bool(raw)
    if value_type == _T_ARRAY:
        if _depth > 0:
            raise GGUFParseError("nested GGUF arrays are not supported")
        elem_type = _read_uint32(fh)
        length = _read_uint64(fh)
        if length > MAX_ARRAY_LENGTH:
            raise GGUFParseError(f"array length {length} exceeds ceiling {MAX_ARRAY_LENGTH}")
        return [_read_value(fh, elem_type, _depth=_depth + 1) for _ in range(length)]
    fmt = _SCALAR_STRUCT.get(value_type)
    if fmt is None:
        raise GGUFParseError(f"unknown GGUF value_type {value_type}")
    fmt_str, size = fmt
    (value,) = struct.unpack(fmt_str, _read_exact(fh, size))
    return value


def _parse_stream(fh: BinaryIO, *, parse_tensors: bool = True) -> GGUFHeader:
    magic = _read_exact(fh, 4)
    if magic != MAGIC:
        raise GGUFParseError(f"bad magic: expected {MAGIC!r}, got {magic!r}")

    version = _read_uint32(fh)
    if version not in SUPPORTED_VERSIONS:
        raise GGUFParseError(f"unsupported GGUF version {version} (supported: {SUPPORTED_VERSIONS})")

    tensor_count = _read_uint64(fh)
    if tensor_count > MAX_TENSOR_COUNT:
        raise GGUFParseError(f"tensor_count {tensor_count} exceeds ceiling {MAX_TENSOR_COUNT}")

    kv_count = _read_uint64(fh)
    if kv_count > MAX_KV_COUNT:
        raise GGUFParseError(f"metadata_kv_count {kv_count} exceeds ceiling {MAX_KV_COUNT}")

    metadata: dict[str, Any] = {}
    for _ in range(kv_count):
        key = _read_gguf_string(fh)
        value_type = _read_uint32(fh)
        metadata[key] = _read_value(fh, value_type)

    tensors: list[TensorInfo] = []
    if parse_tensors:
        for _ in range(tensor_count):
            name = _read_gguf_string(fh)
            n_dims = _read_uint32(fh)
            if n_dims > MAX_DIMENSIONS:
                raise GGUFParseError(f"tensor {name!r} has {n_dims} dims, exceeds ceiling {MAX_DIMENSIONS}")
            dims = tuple(_read_uint64(fh) for _ in range(n_dims))
            for dim in dims:
                if dim > MAX_DIMENSION_VALUE:
                    raise GGUFParseError(
                        f"tensor {name!r} has a dimension {dim} exceeding ceiling {MAX_DIMENSION_VALUE}"
                    )
            ggml_type = _read_uint32(fh)
            offset = _read_uint64(fh)
            tensors.append(TensorInfo(name=name, dimensions=dims, ggml_type=ggml_type, offset=offset))

    return GGUFHeader(version=version, tensor_count=tensor_count, metadata=metadata, tensors=tuple(tensors))


def parse_gguf_header(source: Path | bytes | BinaryIO, *, parse_tensors: bool = True) -> GGUFHeader:
    """Parse a GGUF file's header/metadata/tensor-info (never the tensor payload).

    Args:
        source: a filesystem `Path`, raw `bytes`, or an already-open binary
            file object positioned at the start of the GGUF file.
        parse_tensors: also parse the tensor-info table (needed for
            `parameter_size`/majority-quantization derivation). Set False
            for a cheap metadata-only read.
    """
    if isinstance(source, Path):
        with open(source, "rb") as fh:
            return _parse_stream(fh, parse_tensors=parse_tensors)
    if isinstance(source, (bytes, bytearray)):
        import io

        return _parse_stream(io.BytesIO(source), parse_tensors=parse_tensors)
    return _parse_stream(source, parse_tensors=parse_tensors)


__all__ = ["GGUFHeader", "GGUFParseError", "TensorInfo", "parse_gguf_header"]
