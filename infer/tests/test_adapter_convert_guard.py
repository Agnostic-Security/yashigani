# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the convert-to-GGUF adapter's safetensors-only / pickle-refused guard.

This is the single most security-relevant guard in the package: PyTorch
pickle-based checkpoint formats are refused outright (pickle deserialization
is RCE), before any parse of file contents beyond a small header sniff.
"""

from __future__ import annotations

import struct

import pytest

from kuroshio.adapters.convert import (
    ConvertAdapter,
    PickleRefusedError,
    StubConversionInvoker,
    UnsupportedSourceFormatError,
    guard_safetensors_only,
)
from kuroshio.blobstore.store import BlobStore


def _write(path, data: bytes):
    path.write_bytes(data)
    return path


def _fake_safetensors_bytes() -> bytes:
    header = b'{"__metadata__": {"format": "pt"}}'
    return struct.pack("<Q", len(header)) + header + b"\x00" * 16


@pytest.mark.parametrize("suffix", [".bin", ".pt", ".pth", ".ckpt"])
def test_guard_refuses_pytorch_pickle_extensions(tmp_path, suffix: str) -> None:
    path = _write(tmp_path / f"model{suffix}", b"\x80\x04some pickle bytes")
    with pytest.raises(PickleRefusedError, match="pickle"):
        guard_safetensors_only(path)


def test_guard_refuses_unrelated_extension(tmp_path) -> None:
    path = _write(tmp_path / "model.onnx", b"not relevant")
    with pytest.raises(UnsupportedSourceFormatError):
        guard_safetensors_only(path)


def test_guard_accepts_genuine_safetensors(tmp_path) -> None:
    path = _write(tmp_path / "model.safetensors", _fake_safetensors_bytes())
    guard_safetensors_only(path)  # must not raise


def test_guard_refuses_zip_magic_spoofed_as_safetensors(tmp_path) -> None:
    """A `.safetensors`-named file whose bytes are actually a ZIP (torch.save
    default format) must still be refused — content-sniff is authoritative,
    not the extension (red-council item #5)."""
    path = _write(tmp_path / "sneaky.safetensors", b"PK\x03\x04" + b"\x00" * 32)
    with pytest.raises(PickleRefusedError, match="regardless of extension"):
        guard_safetensors_only(path)


def test_guard_refuses_pickle_protocol_opcode_spoofed_as_safetensors(tmp_path) -> None:
    path = _write(tmp_path / "sneaky2.safetensors", b"\x80\x04\x95" + b"\x00" * 32)
    with pytest.raises(PickleRefusedError, match="regardless of extension"):
        guard_safetensors_only(path)


def test_guard_refuses_pickle_content_even_with_unrelated_extension(tmp_path) -> None:
    """Content-sniff fires BEFORE the extension check even runs — a pickle
    payload named `.onnx` is still refused as pickle, not as 'wrong extension'."""
    path = _write(tmp_path / "sneaky.onnx", b"PK\x03\x04" + b"\x00" * 32)
    with pytest.raises(PickleRefusedError, match="pickle/ZIP"):
        guard_safetensors_only(path)


def test_guard_rejects_oversized_header_length_claim(tmp_path) -> None:
    """Bounds-check: a header claiming to be larger than the file itself is malformed/truncated."""
    import struct

    bogus_len = 10_000  # far bigger than the 4 trailing bytes actually present
    path = _write(tmp_path / "truncated.safetensors", struct.pack("<Q", bogus_len) + b"\x00" * 4)
    with pytest.raises(UnsupportedSourceFormatError, match="malformed/truncated"):
        guard_safetensors_only(path)


def test_guard_rejects_header_that_is_not_valid_json(tmp_path) -> None:
    import struct

    junk = b"not json at all!"
    path = _write(tmp_path / "badheader.safetensors", struct.pack("<Q", len(junk)) + junk)
    with pytest.raises(UnsupportedSourceFormatError, match="not valid UTF-8 JSON"):
        guard_safetensors_only(path)


def test_guard_rejects_header_length_of_zero(tmp_path) -> None:
    import struct

    path = _write(tmp_path / "zero.safetensors", struct.pack("<Q", 0) + b"\x00" * 8)
    with pytest.raises(UnsupportedSourceFormatError, match="out of bounds"):
        guard_safetensors_only(path)


def test_convert_adapter_resolve_refuses_pickle_before_touching_invoker(tmp_blob_store: BlobStore, tmp_path) -> None:
    path = _write(tmp_path / "model.bin", b"\x80\x04pickle")

    class ExplodingInvoker(StubConversionInvoker):
        def convert(self, *args, **kwargs):  # pragma: no cover - must never be called
            raise AssertionError("invoker.convert() must not be reached when the guard refuses")

    adapter = ConvertAdapter(tmp_blob_store, invoker=ExplodingInvoker())
    with pytest.raises(PickleRefusedError):
        adapter.resolve(source_path=path)


def test_convert_adapter_default_stub_refuses_in_serving_process(tmp_blob_store: BlobStore, tmp_path) -> None:
    # The serving process never converts: ConvertAdapter's DEFAULT invoker
    # stays the refusing stub; real conversions go through the ephemeral
    # convert job (kuroshio.convert_job), which wires the subprocess
    # invoker explicitly. Guard still runs first (pickle test above).
    path = _write(tmp_path / "model.safetensors", _fake_safetensors_bytes())
    adapter = ConvertAdapter(tmp_blob_store)
    with pytest.raises(NotImplementedError, match="ephemeral convert job"):
        adapter.resolve(source_path=path)


def test_convert_adapter_resolve_raises_for_missing_source(tmp_blob_store: BlobStore, tmp_path) -> None:
    adapter = ConvertAdapter(tmp_blob_store)
    with pytest.raises(FileNotFoundError):
        adapter.resolve(source_path=tmp_path / "does-not-exist.safetensors")
