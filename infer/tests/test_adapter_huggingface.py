# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the Hugging Face pull adapter. NO live network — Downloader is mocked."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tests.conftest import FailingDownloader, FakeDownloader
from yashigani_infer.adapters.huggingface import (
    HuggingFaceAdapter,
    InvalidRepoReferenceError,
    InvalidRevisionError,
)
from yashigani_infer.blobstore.store import BlobStore, DigestMismatchError, sha256_bytes
from yashigani_infer.catalog import CatalogVerificationError, CatalogVerifier, SignedCatalog, SignedCatalogEntry
from yashigani_infer.models import ProvenanceKind

PINNED_REVISION = "a" * 40


def test_resolve_downloads_and_ingests(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)

    resolved = adapter.resolve(
        repo_id="acme/tiny-model",
        revision=PINNED_REVISION,
        filename="tiny-model.Q4_K_M.gguf",
        licence_accepted=True,
    )

    assert resolved.sha256 == sha256_bytes(minimal_gguf_bytes)
    assert resolved.provenance.kind == ProvenanceKind.HUGGINGFACE
    assert resolved.provenance.operator_supplied is False
    assert resolved.provenance.revision == PINNED_REVISION
    assert downloader.requested_urls == [
        f"https://huggingface.co/acme/tiny-model/resolve/{PINNED_REVISION}/tiny-model.Q4_K_M.gguf"
    ]
    # scratch file is cleaned up after ingestion
    assert list((tmp_blob_store.root / "scratch").glob("*.gguf")) == []


def test_resolve_refuses_floating_branch_revision(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(InvalidRevisionError):
        adapter.resolve(repo_id="acme/tiny-model", revision="main", filename="tiny-model.gguf", licence_accepted=True)
    assert downloader.requested_urls == []  # never even attempted


def test_resolve_refuses_unsafe_repo_id(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(InvalidRepoReferenceError):
        adapter.resolve(
            repo_id="../../etc/passwd",
            revision=PINNED_REVISION,
            filename="tiny-model.gguf",
            licence_accepted=True,
        )


def test_resolve_refuses_non_gguf_filename(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(InvalidRepoReferenceError):
        adapter.resolve(
            repo_id="acme/tiny-model",
            revision=PINNED_REVISION,
            filename="../../../etc/passwd",
            licence_accepted=True,
        )


def test_resolve_denies_when_licence_not_accepted(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(PermissionError):
        adapter.resolve(
            repo_id="acme/tiny-model",
            revision=PINNED_REVISION,
            filename="tiny-model.gguf",
            licence_accepted=False,
        )
    assert downloader.requested_urls == []


def test_resolve_verifies_expected_sha256(tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes) -> None:
    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(DigestMismatchError):
        adapter.resolve(
            repo_id="acme/tiny-model",
            revision=PINNED_REVISION,
            filename="tiny-model.gguf",
            licence_accepted=True,
            expected_sha256="0" * 64,
        )


def test_resolve_refuses_downloaded_non_gguf(tmp_blob_store: BlobStore) -> None:
    downloader = FakeDownloader(b"not a gguf file at all")
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader)
    with pytest.raises(InvalidRepoReferenceError, match="not a valid GGUF"):
        adapter.resolve(
            repo_id="acme/tiny-model",
            revision=PINNED_REVISION,
            filename="tiny-model.gguf",
            licence_accepted=True,
        )


def test_resolve_propagates_download_failure(tmp_blob_store: BlobStore) -> None:
    adapter = HuggingFaceAdapter(tmp_blob_store, FailingDownloader())
    with pytest.raises(ConnectionError):
        adapter.resolve(
            repo_id="acme/tiny-model",
            revision=PINNED_REVISION,
            filename="tiny-model.gguf",
            licence_accepted=True,
        )


def _signed_catalog_with(private_key, public_key, *, sha256: str) -> SignedCatalog:
    fields = {
        "repo_id": "acme/tiny-model",
        "revision": PINNED_REVISION,
        "filename": "tiny-model.gguf",
        "sha256": sha256,
        "provenance_tier": "vetted",
        "signer_key_id": "test-key",
    }
    unsigned = SignedCatalogEntry(**fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    entry = SignedCatalogEntry(**fields, signature=signature)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])
    return catalog


def test_resolve_with_catalog_uses_the_signed_sha256_never_re_derived(
    tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    digest = sha256_bytes(minimal_gguf_bytes)
    catalog = _signed_catalog_with(private_key, private_key.public_key(), sha256=digest)

    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader, catalog=catalog)

    resolved = adapter.resolve(
        repo_id="acme/tiny-model", revision=PINNED_REVISION, filename="tiny-model.gguf", licence_accepted=True
    )
    assert resolved.sha256 == digest
    assert resolved.provenance.extra["provenance_tier"] == "vetted"


def test_resolve_with_catalog_refuses_when_download_does_not_match_signed_digest(
    tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    wrong_digest = "f" * 64
    catalog = _signed_catalog_with(private_key, private_key.public_key(), sha256=wrong_digest)

    downloader = FakeDownloader(minimal_gguf_bytes)  # actual bytes hash to something else
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader, catalog=catalog)

    with pytest.raises(DigestMismatchError):
        adapter.resolve(
            repo_id="acme/tiny-model", revision=PINNED_REVISION, filename="tiny-model.gguf", licence_accepted=True
        )


def test_resolve_with_catalog_refuses_unlisted_model_no_override(
    tmp_blob_store: BlobStore, minimal_gguf_bytes: bytes
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    catalog = SignedCatalog(CatalogVerifier(private_key.public_key()))  # empty catalog

    downloader = FakeDownloader(minimal_gguf_bytes)
    adapter = HuggingFaceAdapter(tmp_blob_store, downloader, catalog=catalog)

    with pytest.raises(CatalogVerificationError, match="no override"):
        adapter.resolve(
            repo_id="acme/tiny-model", revision=PINNED_REVISION, filename="tiny-model.gguf", licence_accepted=True
        )
    assert downloader.requested_urls == []  # refused before ever attempting the download
