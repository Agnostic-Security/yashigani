# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the local LM Studio-store adapter (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yashigani_infer.adapters.lmstudio_store import LMStudioStoreAdapter, LMStudioStoreAdapterError
from yashigani_infer.blobstore.store import BlobStore, sha256_bytes
from yashigani_infer.containment.hooks import default_first_parse_jail_hook
from yashigani_infer.models import ProvenanceKind


def test_resolve_imports_nested_gguf(tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes) -> None:
    root = tmp_path / "lmstudio-models"
    nested = root / "TheBloke" / "tiny-model-GGUF"
    nested.mkdir(parents=True)
    gguf_path = nested / "tiny-model.Q4_K_M.gguf"
    gguf_path.write_bytes(minimal_gguf_bytes)

    adapter = LMStudioStoreAdapter(tmp_blob_store)
    resolved = adapter.resolve(relative_path="TheBloke/tiny-model-GGUF/tiny-model.Q4_K_M.gguf", lmstudio_dir=root)

    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)
    assert resolved.provenance.kind == ProvenanceKind.LOCAL_LMSTUDIO
    assert resolved.provenance.operator_supplied is True


def test_resolve_rejects_path_traversal(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    root = tmp_path / "lmstudio-models"
    root.mkdir()
    outside = tmp_path / "secret.gguf"
    outside.write_bytes(b"should never be reachable")

    adapter = LMStudioStoreAdapter(tmp_blob_store)
    # Caught by gate 1 (segment-level '..' rejection) before any join/resolve.
    with pytest.raises(LMStudioStoreAdapterError, match="unsafe relative_path"):
        adapter.resolve(relative_path="../secret.gguf", lmstudio_dir=root)


def test_resolve_rejects_symlink_escape_even_without_dotdot(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Gate 2 (canonicalize-and-contain) independently catches a symlink
    escape that never contains a literal '..' segment."""
    root = tmp_path / "lmstudio-models"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.gguf").write_bytes(minimal_gguf_bytes)
    (root / "escape").symlink_to(outside)

    adapter = LMStudioStoreAdapter(tmp_blob_store)
    with pytest.raises(LMStudioStoreAdapterError, match="no LM Studio GGUF found"):
        adapter.resolve(relative_path="escape/secret.gguf", lmstudio_dir=root)


def test_resolve_rejects_non_gguf_extension(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    root = tmp_path / "lmstudio-models"
    root.mkdir()
    (root / "readme.txt").write_text("not a model")

    adapter = LMStudioStoreAdapter(tmp_blob_store)
    with pytest.raises(LMStudioStoreAdapterError):
        adapter.resolve(relative_path="readme.txt", lmstudio_dir=root)


def test_resolve_raises_when_nothing_found(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    root = tmp_path / "lmstudio-models"
    root.mkdir()
    adapter = LMStudioStoreAdapter(tmp_blob_store)
    with pytest.raises(LMStudioStoreAdapterError, match="no LM Studio GGUF found"):
        adapter.resolve(relative_path="does/not/exist.gguf", lmstudio_dir=root)


# ── first-parse jail wiring (Iris integration-seam audit F3) ────────────────


def test_hook_fires_on_first_load_from_lmstudio_store(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    root = tmp_path / "lmstudio-models"
    nested = root / "TheBloke" / "tiny-model-GGUF"
    nested.mkdir(parents=True)
    gguf_path = nested / "tiny-model.Q4_K_M.gguf"
    gguf_path.write_bytes(minimal_gguf_bytes)
    calls: list[bytes] = []

    def _spy_hook(header_bytes: bytes) -> bytes:
        calls.append(header_bytes)
        return default_first_parse_jail_hook(header_bytes)

    adapter = LMStudioStoreAdapter(tmp_blob_store, first_parse_jail_hook=_spy_hook)
    resolved = adapter.resolve(relative_path="TheBloke/tiny-model-GGUF/tiny-model.Q4_K_M.gguf", lmstudio_dir=root)

    assert len(calls) == 1
    assert calls[0].startswith(b"GGUF")
    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)


def test_hook_fails_closed_on_malformed_gguf_bytes(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    root = tmp_path / "lmstudio-models"
    root.mkdir()
    (root / "bogus.gguf").write_bytes(b"this is not a gguf file at all")

    adapter = LMStudioStoreAdapter(tmp_blob_store)
    with pytest.raises(LMStudioStoreAdapterError, match="not a valid GGUF"):
        adapter.resolve(relative_path="bogus.gguf", lmstudio_dir=root)
