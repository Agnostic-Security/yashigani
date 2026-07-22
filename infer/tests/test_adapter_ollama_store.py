# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the local Ollama-store adapter (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from yashigani_infer.adapters.ollama_store import (
    OllamaStoreAdapter,
    OllamaStoreAdapterError,
    parse_model_ref,
)
from yashigani_infer.blobstore.store import BlobStore, DigestMismatchError, sha256_bytes
from yashigani_infer.models import ProvenanceKind


def _write_ollama_store(
    root: Path, *, model_bytes: bytes, registry="registry.ollama.ai", namespace="library", model="llama3", tag="8b"
) -> Path:
    digest = sha256_bytes(model_bytes)
    blobs_dir = root / "models" / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    (blobs_dir / f"sha256-{digest}").write_bytes(model_bytes)

    manifest_dir = root / "models" / "manifests" / registry / namespace / model
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": f"sha256:{'0' * 64}"},
        "layers": [
            {"mediaType": "application/vnd.ollama.image.model", "digest": f"sha256:{digest}", "size": len(model_bytes)},
            {"mediaType": "application/vnd.ollama.image.license", "digest": f"sha256:{'1' * 64}"},
        ],
    }
    (manifest_dir / tag).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_parse_model_ref_defaults() -> None:
    ref = parse_model_ref("llama3:8b")
    assert ref.registry == "registry.ollama.ai"
    assert ref.namespace == "library"
    assert ref.model == "llama3"
    assert ref.tag == "8b"


def test_parse_model_ref_defaults_tag_to_latest() -> None:
    ref = parse_model_ref("llama3")
    assert ref.tag == "latest"


def test_parse_model_ref_rejects_unsafe_component() -> None:
    with pytest.raises(OllamaStoreAdapterError):
        parse_model_ref("../../etc/passwd:latest")


def test_resolve_imports_from_ollama_store(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes)
    adapter = OllamaStoreAdapter(tmp_blob_store)

    resolved = adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)

    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)
    assert resolved.metadata["family"] == "llama"
    assert resolved.provenance.kind == ProvenanceKind.LOCAL_OLLAMA
    assert resolved.provenance.operator_supplied is True
    assert "manifest_path" in resolved.provenance.extra


def test_resolve_raises_on_missing_manifest(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    ollama_dir = tmp_path / "dot-ollama"
    ollama_dir.mkdir()
    adapter = OllamaStoreAdapter(tmp_blob_store)
    with pytest.raises(OllamaStoreAdapterError, match="no manifest"):
        adapter.resolve(model_ref="nonexistent:latest", ollama_dir=ollama_dir)


def test_resolve_detects_tampered_blob_vs_manifest_digest(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes)
    digest = sha256_bytes(minimal_gguf_bytes)
    # Tamper the blob after the manifest was written referencing its original digest.
    (ollama_dir / "models" / "blobs" / f"sha256-{digest}").write_bytes(b"tampered bytes")

    adapter = OllamaStoreAdapter(tmp_blob_store)
    with pytest.raises(DigestMismatchError):
        adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)


def test_resolve_refuses_blob_that_is_a_symlink(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Red-council item #2: local-store indexing must not follow an escaping
    symlink planted where the blob file is expected."""
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes)
    digest = sha256_bytes(minimal_gguf_bytes)
    blob_path = ollama_dir / "models" / "blobs" / f"sha256-{digest}"

    outside_secret = tmp_path / "outside-secret.gguf"
    outside_secret.write_bytes(minimal_gguf_bytes)  # same bytes so only the symlink-ness matters

    blob_path.unlink()
    blob_path.symlink_to(outside_secret)

    adapter = OllamaStoreAdapter(tmp_blob_store)
    # Caught by the canonicalize-and-contain gate (2nd independent gate) —
    # it refuses ANY symlink at the leaf, regardless of where it resolves.
    with pytest.raises(OllamaStoreAdapterError, match="symlink"):
        adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)


def test_resolve_refuses_blob_symlink_even_when_target_is_inside_root(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Even when a symlink's target legitimately resolves INSIDE the store
    root (so the containment gate alone would pass), the O_NOFOLLOW open
    must still refuse the leaf being a symlink at all."""
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes)
    digest = sha256_bytes(minimal_gguf_bytes)
    blob_path = ollama_dir / "models" / "blobs" / f"sha256-{digest}"

    real_copy = ollama_dir / "models" / "blobs" / "real-copy.gguf"
    real_copy.write_bytes(minimal_gguf_bytes)

    blob_path.unlink()
    blob_path.symlink_to(real_copy)  # target is inside the root — containment gate alone would pass

    adapter = OllamaStoreAdapter(tmp_blob_store)
    with pytest.raises(Exception, match="O_NOFOLLOW|symlink"):
        adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)


def test_resolve_raises_when_manifest_has_no_model_layer(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    ollama_dir = tmp_path / "dot-ollama"
    manifest_dir = ollama_dir / "models" / "manifests" / "registry.ollama.ai" / "library" / "empty"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "latest").write_text(json.dumps({"layers": []}), encoding="utf-8")

    adapter = OllamaStoreAdapter(tmp_blob_store)
    with pytest.raises(OllamaStoreAdapterError, match="no model"):
        adapter.resolve(model_ref="empty:latest", ollama_dir=ollama_dir)
