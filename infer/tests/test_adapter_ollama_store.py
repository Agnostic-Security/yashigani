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
from yashigani_infer.containment.hooks import default_first_parse_jail_hook
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


def test_resolve_names_by_the_ollama_tag_reference_not_the_gguf_vendor_name(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Red-Council H3 (Iris RC-2, 2026-07-29): the GGUF fixture's own
    `general.name` is "tiny-test-model" — this adapter must name the
    resolved model by the ollama-tag reference instead, since that is the
    identifier every existing policy/budget/agent config already uses.
    A regression here silently 404s every migrated customer reference at
    cutover."""
    ollama_dir = _write_ollama_store(
        tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes, namespace="library", model="llama3", tag="8b"
    )
    adapter = OllamaStoreAdapter(tmp_blob_store)

    resolved = adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)

    assert resolved.metadata["name"] == "library/llama3:8b"
    assert resolved.metadata["name"] != "tiny-test-model"  # the GGUF's own general.name must NOT win


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


# ── first-parse jail wiring (Iris integration-seam audit F3) ────────────────


def test_hook_fires_on_first_load_from_ollama_store(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=minimal_gguf_bytes)
    calls: list[bytes] = []

    def _spy_hook(header_bytes: bytes) -> bytes:
        calls.append(header_bytes)
        return default_first_parse_jail_hook(header_bytes)

    adapter = OllamaStoreAdapter(tmp_blob_store, first_parse_jail_hook=_spy_hook)
    resolved = adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)

    assert len(calls) == 1
    assert calls[0].startswith(b"GGUF")
    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)


def test_hook_fails_closed_on_a_malformed_blob(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    ollama_dir = _write_ollama_store(tmp_path / "dot-ollama", model_bytes=b"this is not a gguf file at all")
    adapter = OllamaStoreAdapter(tmp_blob_store)
    with pytest.raises(OllamaStoreAdapterError, match="not a valid GGUF"):
        adapter.resolve(model_ref="llama3:8b", ollama_dir=ollama_dir)
