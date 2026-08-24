# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Content-addressed blob store for GGUF files.

Every GGUF blob is stored once, keyed by its sha256 digest. All writes go
through an unpredictable-named temp file, created with `tempfile.mkstemp`
(exclusive-create, no predictable-name race) in the SAME directory as the
final destination (same filesystem — avoids an `EXDEV` break of the atomic
`os.replace` rename), verified, then renamed into place — never a partial/
half-written blob is visible under its final digest-named path. This
mirrors the path-traversal / atomic-write guard the council review called
for on the Hugging Face download path (Laura F2/F3, Nico #1) plus the
red-council hardening pass (item #3): "download to random temp -> verify ->
atomic rename... unpredictable temp names (mkstemp)... re-verify sha256 on
dedup/skip-if-exists... reject symlink at target."
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

from kuroshio.models import Provenance, ResolvedModel

_CHUNK_SIZE = 1024 * 1024  # 1 MiB


class BlobStoreError(Exception):
    """Base error for blob-store operations."""


class DigestMismatchError(BlobStoreError):
    """Raised when computed sha256 does not match an expected/claimed digest."""


class BlobTamperError(BlobStoreError):
    """Raised when an on-disk store entry is not what it claims to be (e.g.
    a symlink planted where a regular blob file is expected)."""


class NameCollisionError(BlobStoreError):
    """Raised when an incoming model's display name collides with a
    DIFFERENT, already-stored model's name (Iris integration-seam audit
    RC-2, 2026-07-29 design-review H3).

    `find_by_name`'s linear scan has no uniqueness guarantee otherwise: two
    imported GGUFs sharing an identical (or uploader-supplied, colliding)
    `general.name` — or, after the H3 fix, two DIFFERENT ollama-tag
    references that happen to collide — would resolve non-deterministically
    to whichever was imported/enumerated first. This is a routing-contract
    gap, not a byte-integrity one (content-addressing already guarantees
    the underlying blob bytes cannot be swapped under a given digest); the
    fix here is to refuse the SECOND write outright rather than let two
    digests silently share one name."""


class ProvenanceDowngradeError(BlobStoreError):
    """Raised when a dedup write would silently replace an existing,
    signed-manifest-backed metadata record with one that carries no signed
    manifest at all (Nico/Tom finding, 2026-07-29 design-review H2).

    `_write_metadata` used to unconditionally `os.replace` the metadata
    sidecar on every dedup hit, with no comparison against what was already
    on record — a blob legitimately admitted via a counter-signed Hugging
    Face pull (`Provenance.extra["signed_manifest"]` populated,
    `provenance_tier` cryptographically bound to the signature) could be
    silently re-labelled by ANY later write for the same digest (e.g. a
    `LOCAL_FILE` re-ingestion, which only needs local filesystem access, not
    a valid signature) with no error, no warning, no audit event. This
    permanently erases the audit trail that the blob was ever verified —
    exploitable the moment anything starts making a policy decision off the
    persisted `provenance_tier` (multi-tenant model allowlists, future
    EU-AI-Act conformity tiering).
    """


def _extract_signed_manifest(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    extra = record.get("provenance", {}).get("extra", {})
    manifest = extra.get("signed_manifest")
    return manifest if isinstance(manifest, dict) else None


def sha256_file(path: Path) -> str:
    """Stream-hash a file. Never loads the whole file into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_stream(fh: BinaryIO) -> str:
    """Stream-hash an already-open binary file object from its current position."""
    h = hashlib.sha256()
    for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
        h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BlobStore:
    """Content-addressed store: `<root>/blobs/<aa>/<sha256>.gguf` + `<root>/meta/<sha256>.json`."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.blobs_dir = self.root / "blobs"
        self.meta_dir = self.root / "meta"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    def blob_path(self, sha256: str) -> Path:
        digest = sha256.lower()
        return self.blobs_dir / digest[:2] / f"{digest}.gguf"

    def _meta_path(self, sha256: str) -> Path:
        return self.meta_dir / f"{sha256.lower()}.json"

    def exists(self, sha256: str) -> bool:
        return self.blob_path(sha256).is_file()

    def get_path(self, sha256: str) -> Path | None:
        p = self.blob_path(sha256)
        return p if p.is_file() else None

    def get_metadata(self, sha256: str) -> dict[str, Any] | None:
        p = self._meta_path(sha256)
        if not p.is_file():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def get_provenance(self, sha256: str) -> Provenance | None:
        record = self.get_metadata(sha256)
        if record is None:
            return None
        return Provenance.from_dict(record["provenance"])

    def list_digests(self) -> list[str]:
        """Enumerate all sha256 digests present in the store (from metadata sidecars)."""
        return sorted(p.stem for p in self.meta_dir.glob("*.json"))

    def get_resolved_model(self, sha256: str) -> ResolvedModel | None:
        """Reconstruct a full `ResolvedModel` from stored metadata + blob path."""
        record = self.get_metadata(sha256)
        blob_path = self.get_path(sha256)
        if record is None or blob_path is None:
            return None
        return ResolvedModel(
            sha256=record["sha256"],
            blob_path=blob_path,
            metadata=record["metadata"],
            provenance=Provenance.from_dict(record["provenance"]),
        )

    def list_resolved_models(self) -> list[ResolvedModel]:
        """Reconstruct every `ResolvedModel` currently in the store."""
        models = []
        for digest in self.list_digests():
            model = self.get_resolved_model(digest)
            if model is not None:
                models.append(model)
        return models

    def find_by_name(self, name: str) -> ResolvedModel | None:
        """Look up a stored model by its display name (`metadata['name']`, with
        or without a `:tag` suffix) — used by the ollama-shim routes, which
        address models by name rather than by raw digest."""
        base_name = name.split(":", 1)[0]
        for model in self.list_resolved_models():
            stored_name = str(model.metadata.get("name") or "")
            if stored_name == name or stored_name == base_name or stored_name.split(":", 1)[0] == base_name:
                return model
        return None

    def _mkstemp_in(self, directory: Path, *, suffix: str = "") -> tuple[int, Path]:
        """Unpredictable-named, exclusively-created temp file in `directory`
        (guaranteed same filesystem as anything else already in that
        directory, so the follow-up `os.replace` cannot hit `EXDEV`)."""
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=suffix)
        return fd, Path(tmp_name)

    def _check_not_symlink(self, path: Path) -> None:
        """Reject a store entry that is a symlink where a regular file is
        expected — a planted symlink at a digest-named path is either
        corruption or tampering, never a legitimate blob."""
        if path.is_symlink():
            raise BlobTamperError(f"refusing to trust {path}: it is a symlink, not a regular blob file")

    def _atomic_write_bytes(self, dest: Path, data: bytes) -> None:
        self._check_not_symlink(dest)
        fd, tmp = self._mkstemp_in(dest.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)

    def _atomic_copy(self, src: Path, dest: Path) -> None:
        self._check_not_symlink(dest)
        fd, tmp = self._mkstemp_in(dest.parent)
        try:
            with open(src, "rb") as src_fh, os.fdopen(fd, "wb") as tmp_fh:
                shutil.copyfileobj(src_fh, tmp_fh)
            os.replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)

    def _atomic_copy_from_fileobj(self, src_fh: BinaryIO, dest: Path) -> None:
        """Copy from an ALREADY-OPEN file object (fd-based ingestion — see
        `put_from_open_file`). Never reopens the source path, closing the
        TOCTOU window between a caller's own containment/verify checks and
        the bytes actually written into the store."""
        self._check_not_symlink(dest)
        src_fh.seek(0)
        fd, tmp = self._mkstemp_in(dest.parent)
        try:
            with os.fdopen(fd, "wb") as tmp_fh:
                shutil.copyfileobj(src_fh, tmp_fh)
            os.replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)

    def _check_no_name_collision(self, sha256: str, metadata: dict[str, Any]) -> None:
        """Refuse a metadata write whose `name` already maps to a DIFFERENT
        digest (see `NameCollisionError`). A write for the SAME digest is
        never a collision (dedup path, not a naming conflict)."""
        name = metadata.get("name")
        if not name:
            return
        for existing_digest in self.list_digests():
            if existing_digest == sha256:
                continue  # same blob — dedup path, not a collision
            existing_record = self.get_metadata(existing_digest)
            if existing_record is None:
                continue
            existing_name = existing_record.get("metadata", {}).get("name")
            if existing_name == name:
                raise NameCollisionError(
                    f"name {name!r} already maps to digest {existing_digest} — refusing to also map it to "
                    f"{sha256} (find_by_name has no uniqueness guarantee otherwise; re-name or remove the "
                    "existing entry first if this is genuinely intended)"
                )

    def _check_no_provenance_downgrade(self, sha256: str, provenance: Provenance) -> None:
        """Refuse a metadata write that would erase a previously-signed
        provenance record with an unsigned one for the SAME digest (see
        `ProvenanceDowngradeError`). A first-ever write for a digest (no
        existing record) is never a downgrade — nothing to protect yet."""
        existing_manifest = _extract_signed_manifest(self.get_metadata(sha256))
        if existing_manifest is None:
            return  # no prior signed record for this digest — nothing to protect
        incoming_manifest = (provenance.extra or {}).get("signed_manifest")
        if isinstance(incoming_manifest, dict):
            return  # incoming write is ALSO signed — not a downgrade, allowed
        raise ProvenanceDowngradeError(
            f"blob {sha256} already has a signed-manifest-backed provenance record "
            f"(existing provenance_tier={existing_manifest.get('provenance_tier')!r}) — refusing to "
            f"overwrite it with an unsigned {provenance.kind.value!r} record; this would silently erase "
            "the audit trail that this blob was ever verified. Remove the existing entry first if this "
            "downgrade is genuinely intended."
        )

    def _write_metadata(self, sha256: str, metadata: dict[str, Any], provenance: Provenance) -> None:
        self._check_no_name_collision(sha256, metadata)
        self._check_no_provenance_downgrade(sha256, provenance)
        record = {"sha256": sha256, "metadata": metadata, "provenance": provenance.to_dict()}
        meta_path = self._meta_path(sha256)
        self._atomic_write_bytes(meta_path, json.dumps(record, indent=2, sort_keys=True).encode("utf-8"))

    def _verify_existing_blob(self, dest: Path, digest: str) -> None:
        """Dedup path: an existing blob is NEVER trusted on filename alone —
        re-verify its digest every time (red-council item #3: "re-verify
        sha256 on dedup/skip-if-exists")."""
        self._check_not_symlink(dest)
        existing = sha256_file(dest)
        if existing != digest:
            raise DigestMismatchError(f"blob-store corruption: {dest} digest is {existing}, expected {digest}")

    def put_from_path(
        self,
        src: Path,
        metadata: dict[str, Any],
        provenance: Provenance,
        expected_sha256: str | None = None,
    ) -> ResolvedModel:
        """Ingest a GGUF file already on local disk. Copies (never moves the caller's file)."""
        digest = sha256_file(src)
        if expected_sha256 is not None and expected_sha256.lower() != digest:
            raise DigestMismatchError(f"expected sha256 {expected_sha256!r} but computed {digest!r} for {src}")
        dest = self.blob_path(digest)
        if dest.is_file():
            self._verify_existing_blob(dest, digest)
        else:
            self._atomic_copy(src, dest)
        self._write_metadata(digest, metadata, provenance)
        return ResolvedModel(sha256=digest, blob_path=dest, metadata=metadata, provenance=provenance)

    def put_from_open_file(
        self,
        fh: BinaryIO,
        metadata: dict[str, Any],
        provenance: Provenance,
        expected_sha256: str | None = None,
    ) -> ResolvedModel:
        """Ingest from an ALREADY-OPEN file object — the TOCTOU-safe path.

        Callers that index an untrusted directory tree (Ollama/LM Studio
        local stores) should open the source file ONCE (ideally via
        `pathsafety.open_no_follow_symlink`), then hash-and-ingest via THIS
        method rather than re-opening the path by string a second time —
        closing the window where the path could be swapped between the
        containment check and the read (red-council item #2).
        """
        fh.seek(0)
        digest = sha256_stream(fh)
        if expected_sha256 is not None and expected_sha256.lower() != digest:
            raise DigestMismatchError(f"expected sha256 {expected_sha256!r} but computed {digest!r}")
        dest = self.blob_path(digest)
        if dest.is_file():
            self._verify_existing_blob(dest, digest)
        else:
            self._atomic_copy_from_fileobj(fh, dest)
        self._write_metadata(digest, metadata, provenance)
        return ResolvedModel(sha256=digest, blob_path=dest, metadata=metadata, provenance=provenance)

    def put_from_bytes(
        self,
        data: bytes,
        metadata: dict[str, Any],
        provenance: Provenance,
        expected_sha256: str | None = None,
    ) -> ResolvedModel:
        """Ingest in-memory GGUF bytes (used by small test fixtures and adapters that already
        hold the full blob in memory). Large downloads should stream via put_from_path instead."""
        digest = sha256_bytes(data)
        if expected_sha256 is not None and expected_sha256.lower() != digest:
            raise DigestMismatchError(f"expected sha256 {expected_sha256!r} but computed {digest!r}")
        dest = self.blob_path(digest)
        if dest.is_file():
            self._verify_existing_blob(dest, digest)
        else:
            self._atomic_write_bytes(dest, data)
        self._write_metadata(digest, metadata, provenance)
        return ResolvedModel(sha256=digest, blob_path=dest, metadata=metadata, provenance=provenance)


__all__ = [
    "BlobStore",
    "BlobStoreError",
    "BlobTamperError",
    "DigestMismatchError",
    "NameCollisionError",
    "ProvenanceDowngradeError",
    "sha256_bytes",
    "sha256_file",
    "sha256_stream",
]
