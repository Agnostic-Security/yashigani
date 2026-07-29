# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for `/api/tags`, `/api/show`, `/api/ps` synthesis from GGUF metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from kuroshio.blobstore.store import BlobStore
from kuroshio.models import Provenance, ProvenanceKind
from kuroshio.shim.ps import PsRow, synthesize_ps
from kuroshio.shim.show import synthesize_show
from kuroshio.shim.tags import synthesize_tag_entry, synthesize_tags


def _ingest(tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes, name: str):
    src = tmp_path / f"{name.replace(':', '_')}.gguf"
    src.write_bytes(minimal_gguf_bytes)
    provenance = Provenance(kind=ProvenanceKind.LOCAL_FILE, origin=str(src), sha256="")
    resolved = tmp_blob_store.put_from_path(
        src,
        metadata={"name": name, "family": "llama", "parameter_size": "1.0K", "quantization_level": "Q4_K_M"},
        provenance=provenance,
    )
    return resolved


def test_synthesize_tags_includes_details_from_gguf_metadata(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "llama3:8b")
    body = synthesize_tags([resolved])
    assert len(body["models"]) == 1
    entry = body["models"][0]
    assert entry["name"] == "llama3:8b"
    assert entry["digest"] == resolved.sha256
    assert entry["details"]["family"] == "llama"
    assert entry["details"]["parameter_size"] == "1.0K"
    assert entry["details"]["quantization_level"] == "Q4_K_M"
    assert entry["details"]["format"] == "gguf"
    assert entry["size"] > 0


def test_synthesize_tag_entry_appends_latest_tag_when_missing(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "untagged-model")
    entry = synthesize_tag_entry(resolved)
    assert entry["name"] == "untagged-model:latest"


def test_synthesize_tags_never_leaves_details_fields_null(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Council review High finding: a null details field silently breaks the
    21 known `/api/tags` call sites — every field must have SOME value."""
    src = tmp_path / "bare.gguf"
    src.write_bytes(minimal_gguf_bytes)
    provenance = Provenance(kind=ProvenanceKind.LOCAL_FILE, origin=str(src), sha256="")
    resolved = tmp_blob_store.put_from_path(src, metadata={}, provenance=provenance)  # no family/param/quant at all

    entry = synthesize_tag_entry(resolved)
    for key in ("family", "parameter_size", "quantization_level", "format"):
        assert entry["details"][key] is not None
        assert entry["details"][key] != ""


def test_synthesize_show_includes_model_info_and_details(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "llama3:8b")
    body = synthesize_show(resolved)
    assert body["details"]["family"] == "llama"
    assert body["model_info"]["name"] == "llama3:8b"
    assert "modelfile" in body


def test_synthesize_ps_carries_num_gpu_and_size_vram(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Council review High finding: `/api/ps` `num_gpu`/`size_vram` feed the
    GPU-pressure dashboard — a missing field makes the dashboard go blind."""
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "llama3:8b")
    row = PsRow(
        model=resolved,
        n_gpu_layers=32,
        vram_bytes=4_000_000_000,
        expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    body = synthesize_ps([row])
    entry = body["models"][0]
    assert entry["num_gpu"] == 32
    assert entry["size_vram"] == 4_000_000_000
    assert entry["expires_at"] == "2026-01-01T00:00:00+00:00"


def test_synthesize_ps_handles_no_expiry() -> None:
    body = synthesize_ps([])
    assert body == {"models": []}
