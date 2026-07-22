# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Convert-to-GGUF adapter — INTERFACE + safety guard only (v2 feature).

Council review §3b: converting safetensors -> GGUF via llama.cpp's
`convert_hf_to_gguf.py` + `llama-quantize` is a v2 feature. This module
exists in v1 only to:

  1. Define the adapter shape (`ConvertAdapter`) so the v2 implementation
     slots into the same source-adapter model as every other import path.
  2. Enforce the **hard security guard now**: accept `safetensors` ONLY.
     PyTorch `.bin`/`.pt`/`.pth`/`.ckpt` pickle files are REFUSED before any
     parse — pickle deserialization is arbitrary-code-execution, and "a
     malicious model" for these formats is an RCE payload, not just bad
     weights (council review §3b, "single most dangerous surface in the
     whole engine").
  3. Abstract the actual conversion invocation behind `ConversionInvoker`,
     stubbed to raise `NotImplementedError` — no llama.cpp conversion
     tooling is invoked by this v1 skeleton, and torch is NOT a runtime
     dependency of this package (see pyproject.toml comment).

The guard runs unconditionally, even when the eventual invocation is a stub,
so a caller cannot accidentally hand a pickle file to whatever v2 wires in
later without going through this refusal path first.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from yashigani_infer.adapters.base import SourceAdapter
from yashigani_infer.models import ResolvedModel

# Extensions that are refused outright (naming-discipline check — see
# ordering note on `guard_safetensors_only`: this runs SECOND, after the
# content-sniff, per red-council item #5 "pickle refused by CONTENT-SNIFF
# not extension"). `.pt`/`.pth`/`.bin` are conventionally pickle
# (`torch.save` default `pickle_module=pickle`); `.ckpt` is the same for
# most training frameworks (Lightning etc).
_REFUSED_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt"})
_ACCEPTED_EXTENSION = ".safetensors"

# A `torch.save` pickle checkpoint is either:
#   - a raw pickle stream, whose first byte is the pickle protocol opcode
#     `\x80` (PROTOCOL) for protocol 2+, or an ASCII opcode for protocol 0;
#   - (modern default) a ZIP container (`torch.save` zipfile format), whose
#     first bytes are the ZIP local-file-header magic `PK\x03\x04`.
_PICKLE_ZIP_MAGIC = b"PK\x03\x04"
_PICKLE_PROTO_OPCODE = b"\x80"

# Bounds ceiling for a safetensors JSON header — real headers are at most a
# few MiB even for huge multi-shard models (one small JSON dict of tensor
# metadata); this ceiling exists purely to bound worst-case parse time/memory
# against a hostile file claiming an absurd header length.
_MAX_SAFETENSORS_HEADER_BYTES = 64 * 1024 * 1024  # 64 MiB

# Red-council item #5: any real v2 conversion invocation that goes through
# HF `transformers` (e.g. `AutoConfig`/`AutoModel.from_pretrained` as part of
# `convert_hf_to_gguf.py`'s tokenizer/config loading) MUST hard-pin
# `trust_remote_code=False` — `trust_remote_code=True` executes arbitrary
# Python shipped in the repo, which is exactly the class of RCE this whole
# guard exists to prevent. This constant is the documented, unbypassable
# contract for whoever wires the real `ConversionInvoker` in v2; it is not
# itself invoked here because no `transformers` call exists in this v1 stub.
TRUST_REMOTE_CODE = False


class PickleRefusedError(ValueError):
    """Raised when a source file is (or looks like) a pickle-based checkpoint.

    This is a hard security refusal, not a warning — pickle deserialization
    is remote/local code execution. There is no sandboxed path in v1; the
    file is rejected outright, before any parse is attempted.
    """


class UnsupportedSourceFormatError(ValueError):
    """Raised for any source format that is neither safetensors nor a refused pickle format."""


def _read_head(path: Path, n: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def guard_safetensors_only(path: Path) -> None:
    """Hard guard: raise unless `path` is a plausible, well-formed safetensors file.

    Red-council item #5: content-sniff is the AUTHORITATIVE check, not the
    file extension — a `.safetensors`-named file whose bytes are actually a
    pickle/ZIP checkpoint is refused regardless of its name, and (as
    defense-in-depth) the extension denylist/allowlist still runs as a
    SECOND, independent check afterwards.

    Order of checks:
      1. content-sniff (ZIP/pickle magic) -> refuse, regardless of extension;
      2. bounds-checked safetensors structural validation (8-byte length
         prefix must not exceed the real file size; the declared header
         must decode as UTF-8 JSON) -> refuse anything structurally invalid;
      3. extension denylist/allowlist -> a final naming-discipline check.
    """
    file_size = path.stat().st_size
    head = _read_head(path, 8)

    # 1. Content-sniff — authoritative, independent of the file's name.
    if head.startswith(_PICKLE_ZIP_MAGIC) or head.startswith(_PICKLE_PROTO_OPCODE):
        raise PickleRefusedError(
            f"{path.name}: file content looks like a pickle/ZIP checkpoint "
            f"(magic bytes {head[:4]!r}) — refused regardless of extension. "
            "Pickle deserialization is arbitrary code execution."
        )

    # 2. Bounds-checked safetensors structural validation.
    if len(head) < 8:
        raise UnsupportedSourceFormatError(f"{path.name}: too small to contain a safetensors header")
    header_len = int.from_bytes(head, byteorder="little", signed=False)
    if header_len <= 0 or header_len > _MAX_SAFETENSORS_HEADER_BYTES:
        raise UnsupportedSourceFormatError(
            f"{path.name}: safetensors header length {header_len} is out of bounds "
            f"(must be 1..{_MAX_SAFETENSORS_HEADER_BYTES})"
        )
    if 8 + header_len > file_size:
        raise UnsupportedSourceFormatError(
            f"{path.name}: safetensors header claims {header_len} bytes but the file is only "
            f"{file_size} bytes total (8 + {header_len} > {file_size}) — malformed/truncated"
        )
    with open(path, "rb") as fh:
        fh.seek(8)
        header_bytes = fh.read(header_len)
    try:
        header_json = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsupportedSourceFormatError(f"{path.name}: safetensors header is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(header_json, dict):
        raise UnsupportedSourceFormatError(f"{path.name}: safetensors header JSON is not an object")

    # 3. Extension denylist/allowlist — final naming-discipline check, run
    # AFTER content validation so it can never be the only gate.
    suffix = path.suffix.lower()
    if suffix in _REFUSED_EXTENSIONS:
        raise PickleRefusedError(
            f"{path.name}: PyTorch pickle-checkpoint extensions ({sorted(_REFUSED_EXTENSIONS)}) are "
            "refused outright even though content-sniff passed — naming discipline requires "
            "'.safetensors'. Convert to safetensors upstream before importing."
        )
    if suffix != _ACCEPTED_EXTENSION:
        raise UnsupportedSourceFormatError(
            f"{path.name}: only {_ACCEPTED_EXTENSION!r} is accepted for convert-to-GGUF (got {suffix!r})"
        )


class ConversionInvoker(ABC):
    """Abstraction over invoking llama.cpp's convert/quantize tooling (v2).

    Design intent (council review §3b): the real implementation shells out
    to `convert_hf_to_gguf.py` + `llama-quantize` inside an isolated,
    ephemeral job — never in the long-running inference-serving process,
    and never with torch as a dependency of this control-plane package.
    """

    @abstractmethod
    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        """Convert a validated safetensors source into a GGUF file, return its path."""
        raise NotImplementedError


class StubConversionInvoker(ConversionInvoker):
    """v1 stub — always refuses. No conversion tooling is wired in this package yet."""

    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        raise NotImplementedError(
            "convert-to-GGUF is a v2 feature (council review §3b): the real invocation "
            "(convert_hf_to_gguf.py + llama-quantize, isolated ephemeral job) is not wired "
            "in this v1 foundation. This adapter only enforces the safetensors-only guard."
        )


class ConvertAdapter(SourceAdapter):
    """Safetensors -> GGUF adapter. v1: guard only; conversion itself is stubbed."""

    def __init__(self, blob_store: Any, invoker: ConversionInvoker | None = None) -> None:
        super().__init__(blob_store)
        self._invoker = invoker or StubConversionInvoker()

    def resolve(self, *, source_path: Path, quant: str = "Q4_K_M", **_: Any) -> ResolvedModel:  # type: ignore[override]
        source_path = Path(source_path)
        if not source_path.is_file():
            raise FileNotFoundError(f"convert source not found: {source_path}")

        # The hard guard runs unconditionally, before the (stubbed) invoker
        # is ever reached — a caller cannot bypass it by swapping invokers.
        guard_safetensors_only(source_path)

        out_dir = self.blob_store.root / "scratch" / "convert"
        out_dir.mkdir(parents=True, exist_ok=True)
        gguf_path = self._invoker.convert(source_path, out_dir=out_dir, quant=quant)
        raise NotImplementedError(
            f"unreachable in v1: invoker.convert() should have raised before producing {gguf_path}"
        )


__all__ = [
    "ConversionInvoker",
    "StubConversionInvoker",
    "ConvertAdapter",
    "PickleRefusedError",
    "UnsupportedSourceFormatError",
    "guard_safetensors_only",
    "TRUST_REMOTE_CODE",
]
