# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the content-addressed blob store (addressing/dedup/atomicity)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yashigani_infer.blobstore.store import (
    BlobStore,
    BlobTamperError,
    DigestMismatchError,
    ProvenanceDowngradeError,
    sha256_bytes,
    sha256_file,
)
from yashigani_infer.models import Provenance, ProvenanceKind


def _prov(digest: str) -> Provenance:
    return Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="/tmp/whatever.gguf", sha256=digest)


def test_put_from_bytes_addresses_by_sha256(tmp_blob_store: BlobStore) -> None:
    data = b"hello gguf world"
    digest = sha256_bytes(data)
    resolved = tmp_blob_store.put_from_bytes(data, metadata={"family": "llama"}, provenance=_prov(digest))
    assert resolved.sha256 == digest
    assert resolved.blob_path == tmp_blob_store.blob_path(digest)
    assert resolved.blob_path.read_bytes() == data
    # sharded by the first two hex chars
    assert resolved.blob_path.parent.name == digest[:2]


def test_dedup_does_not_rewrite_existing_blob(tmp_blob_store: BlobStore) -> None:
    data = b"same bytes twice"
    digest = sha256_bytes(data)
    first = tmp_blob_store.put_from_bytes(data, metadata={"a": 1}, provenance=_prov(digest))
    mtime_before = first.blob_path.stat().st_mtime_ns
    second = tmp_blob_store.put_from_bytes(data, metadata={"a": 1}, provenance=_prov(digest))
    assert second.blob_path == first.blob_path
    assert second.blob_path.stat().st_mtime_ns == mtime_before


def test_put_from_path_copies_and_verifies(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    src = tmp_path / "source.gguf"
    src.write_bytes(b"payload bytes")
    digest = sha256_file(src)
    resolved = tmp_blob_store.put_from_path(src, metadata={}, provenance=_prov(digest))
    assert resolved.blob_path.read_bytes() == b"payload bytes"
    # caller's original file is untouched (copy, not move)
    assert src.is_file()


def test_expected_sha256_mismatch_raises(tmp_blob_store: BlobStore) -> None:
    data = b"some bytes"
    with pytest.raises(DigestMismatchError):
        tmp_blob_store.put_from_bytes(data, metadata={}, provenance=_prov("0" * 64), expected_sha256="0" * 64)


def test_get_metadata_and_provenance_roundtrip(tmp_blob_store: BlobStore) -> None:
    data = b"roundtrip test"
    digest = sha256_bytes(data)
    provenance = Provenance(
        kind=ProvenanceKind.HUGGINGFACE,
        origin="org/model",
        revision="a" * 40,
        sha256=digest,
        operator_supplied=False,
        extra={"filename": "model.gguf"},
    )
    tmp_blob_store.put_from_bytes(data, metadata={"family": "qwen2"}, provenance=provenance)

    stored_meta = tmp_blob_store.get_metadata(digest)
    assert stored_meta is not None
    assert stored_meta["metadata"]["family"] == "qwen2"

    stored_prov = tmp_blob_store.get_provenance(digest)
    assert stored_prov is not None
    assert stored_prov.kind == ProvenanceKind.HUGGINGFACE
    assert stored_prov.revision == "a" * 40
    assert stored_prov.operator_supplied is False
    assert stored_prov.extra["filename"] == "model.gguf"


def test_exists_and_get_path_for_missing_digest(tmp_blob_store: BlobStore) -> None:
    assert tmp_blob_store.exists("f" * 64) is False
    assert tmp_blob_store.get_path("f" * 64) is None
    assert tmp_blob_store.get_metadata("f" * 64) is None


def test_list_digests_and_list_resolved_models(tmp_blob_store: BlobStore) -> None:
    d1 = sha256_bytes(b"one")
    d2 = sha256_bytes(b"two")
    tmp_blob_store.put_from_bytes(b"one", metadata={"name": "a"}, provenance=_prov(d1))
    tmp_blob_store.put_from_bytes(b"two", metadata={"name": "b"}, provenance=_prov(d2))

    digests = tmp_blob_store.list_digests()
    assert sorted(digests) == sorted([d1, d2])

    models = tmp_blob_store.list_resolved_models()
    assert {m.sha256 for m in models} == {d1, d2}


def test_find_by_name_matches_with_and_without_tag(tmp_blob_store: BlobStore) -> None:
    digest = sha256_bytes(b"named model")
    tmp_blob_store.put_from_bytes(b"named model", metadata={"name": "llama3:8b"}, provenance=_prov(digest))

    assert tmp_blob_store.find_by_name("llama3:8b") is not None
    assert tmp_blob_store.find_by_name("llama3") is not None
    assert tmp_blob_store.find_by_name("does-not-exist") is None


def test_put_from_path_detects_corrupted_existing_blob(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    src = tmp_path / "source.gguf"
    src.write_bytes(b"original content")
    digest = sha256_file(src)
    tmp_blob_store.put_from_path(src, metadata={}, provenance=_prov(digest))

    # Corrupt the stored blob out-of-band, then attempt to (re-)ingest the
    # same source content — the store must notice the on-disk blob no
    # longer matches its own filename digest.
    tmp_blob_store.blob_path(digest).write_bytes(b"corrupted!!")
    with pytest.raises(DigestMismatchError):
        tmp_blob_store.put_from_path(src, metadata={}, provenance=_prov(digest))


def test_put_from_open_file_ingests_without_reopening_source(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    src = tmp_path / "source.gguf"
    src.write_bytes(b"fd-based ingestion payload")
    digest = sha256_file(src)

    with open(src, "rb") as fh:
        resolved = tmp_blob_store.put_from_open_file(fh, metadata={"name": "x"}, provenance=_prov(digest))

    assert resolved.sha256 == digest
    assert resolved.blob_path.read_bytes() == b"fd-based ingestion payload"


def test_put_from_open_file_verifies_expected_sha256(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    src = tmp_path / "source.gguf"
    src.write_bytes(b"some content")
    with open(src, "rb") as fh, pytest.raises(DigestMismatchError):
        tmp_blob_store.put_from_open_file(fh, metadata={}, provenance=_prov("0" * 64), expected_sha256="0" * 64)


def test_dest_symlink_tamper_is_refused(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    data = b"symlink tamper target"
    digest = sha256_bytes(data)
    dest = tmp_blob_store.blob_path(digest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"should never be read/trusted")
    dest.symlink_to(outside)

    with pytest.raises(BlobTamperError):
        tmp_blob_store.put_from_bytes(data, metadata={}, provenance=_prov(digest))


# --- Red-Council H2 (2026-07-29): no silent provenance downgrade on dedup ---


def _signed_prov(digest: str, *, tier: str = "vetted") -> Provenance:
    return Provenance(
        kind=ProvenanceKind.HUGGINGFACE,
        origin="acme/tiny-model",
        sha256=digest,
        operator_supplied=False,
        extra={
            "provenance_tier": tier,
            "signed_manifest": {"provenance_tier": tier, "sha256": digest, "signature": "ZmFrZQ=="},
        },
    )


def test_dedup_refuses_to_downgrade_a_signed_record_to_unsigned(tmp_blob_store: BlobStore) -> None:
    data = b"previously signed bytes"
    digest = sha256_bytes(data)
    tmp_blob_store.put_from_bytes(data, metadata={"name": "vetted-model"}, provenance=_signed_prov(digest))

    # A later write for the SAME digest with no signed_manifest at all (e.g.
    # a LOCAL_FILE re-ingestion, which only needs filesystem access) must be
    # refused — it would silently erase the audit trail this blob was ever
    # verified.
    with pytest.raises(ProvenanceDowngradeError):
        tmp_blob_store.put_from_bytes(data, metadata={"name": "vetted-model"}, provenance=_prov(digest))

    # the original signed record must survive untouched
    stored = tmp_blob_store.get_metadata(digest)
    assert stored is not None
    assert stored["provenance"]["extra"]["signed_manifest"]["provenance_tier"] == "vetted"


def test_dedup_allows_another_signed_record_for_the_same_digest(tmp_blob_store: BlobStore) -> None:
    """Not a downgrade — the incoming write is ALSO signed, so it's allowed
    (e.g. re-admission via a freshly-minted manifest)."""
    data = b"re-signed bytes"
    digest = sha256_bytes(data)
    tmp_blob_store.put_from_bytes(data, metadata={"name": "m"}, provenance=_signed_prov(digest, tier="vetted"))
    tmp_blob_store.put_from_bytes(data, metadata={"name": "m"}, provenance=_signed_prov(digest, tier="vetted"))
    # must not raise


def test_first_write_for_a_digest_is_never_a_downgrade(tmp_blob_store: BlobStore) -> None:
    data = b"brand new bytes, never seen before"
    digest = sha256_bytes(data)
    # No prior record exists — an unsigned first write must be allowed.
    tmp_blob_store.put_from_bytes(data, metadata={"name": "x"}, provenance=_prov(digest))  # must not raise


def test_mkstemp_temp_files_are_same_directory_as_dest(tmp_blob_store: BlobStore) -> None:
    """Temp files must land in the SAME directory as the final blob path —
    same filesystem, so the atomic rename can never hit EXDEV."""
    data = b"same-fs temp check"
    digest = sha256_bytes(data)
    dest = tmp_blob_store.blob_path(digest)
    fd, tmp = tmp_blob_store._mkstemp_in(dest.parent)
    import os as _os

    _os.close(fd)
    try:
        assert tmp.parent == dest.parent
    finally:
        tmp.unlink(missing_ok=True)
