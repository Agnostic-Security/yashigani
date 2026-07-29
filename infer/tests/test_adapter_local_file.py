# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the local GGUF file/path adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.gguf_builder import DEFAULT_CHAT_TEMPLATE, build_minimal_gguf
from yashigani_infer.adapters.local_file import LocalFileAdapter, LocalFileAdapterError
from yashigani_infer.blobstore.store import BlobStore, sha256_bytes
from yashigani_infer.models import ProvenanceKind


def test_resolve_imports_a_local_gguf(
    tmp_blob_store: BlobStore, minimal_gguf_file: Path, minimal_gguf_bytes: bytes
) -> None:
    adapter = LocalFileAdapter(tmp_blob_store)
    resolved = adapter.resolve(path=minimal_gguf_file)

    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)
    assert resolved.metadata["family"] == "llama"
    assert resolved.metadata["name"] == "tiny-test-model"
    assert resolved.provenance.kind == ProvenanceKind.LOCAL_FILE
    assert resolved.provenance.operator_supplied is True
    assert resolved.provenance.origin == str(minimal_gguf_file.resolve())


def test_resolve_extracts_chat_template_into_metadata(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    """Red-Council H4 (2026-07-29): chat_template must be extracted so the
    serve-path fail-closed guard (app.py::_require_chat_template) can check
    it without re-parsing the GGUF header at request time."""
    path = tmp_path / "with-template.gguf"
    path.write_bytes(build_minimal_gguf())  # default fixture carries DEFAULT_CHAT_TEMPLATE
    adapter = LocalFileAdapter(tmp_blob_store)
    resolved = adapter.resolve(path=path)
    assert resolved.metadata["chat_template"] == DEFAULT_CHAT_TEMPLATE


def test_resolve_records_none_chat_template_when_gguf_has_no_template(
    tmp_blob_store: BlobStore, tmp_path: Path
) -> None:
    path = tmp_path / "no-template.gguf"
    path.write_bytes(build_minimal_gguf(chat_template=None))
    adapter = LocalFileAdapter(tmp_blob_store)
    resolved = adapter.resolve(path=path)
    assert resolved.metadata["chat_template"] is None


def test_resolve_dedups_identical_bytes(tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes) -> None:
    path_a = tmp_path / "a.gguf"
    path_b = tmp_path / "b.gguf"
    path_a.write_bytes(minimal_gguf_bytes)
    path_b.write_bytes(minimal_gguf_bytes)
    adapter = LocalFileAdapter(tmp_blob_store)

    resolved_a = adapter.resolve(path=path_a)
    resolved_b = adapter.resolve(path=path_b)
    assert resolved_a.sha256 == resolved_b.sha256
    assert resolved_a.blob_path == resolved_b.blob_path


def test_resolve_refuses_missing_file(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    adapter = LocalFileAdapter(tmp_blob_store)
    with pytest.raises(LocalFileAdapterError, match="not a file"):
        adapter.resolve(path=tmp_path / "nope.gguf")


def test_resolve_refuses_non_gguf_bytes(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    bogus = tmp_path / "not-a-model.gguf"
    bogus.write_bytes(b"this is not a gguf file at all")
    adapter = LocalFileAdapter(tmp_blob_store)
    with pytest.raises(LocalFileAdapterError, match="not a valid GGUF"):
        adapter.resolve(path=bogus)
