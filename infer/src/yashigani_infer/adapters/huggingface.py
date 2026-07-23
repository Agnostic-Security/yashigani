# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Hugging Face pull adapter — the only v1 adapter that touches the network.

Council review High finding (supply-chain provenance, Laura F2/F3, Nico #1,
Lu SUPPLY-1): resolving a sha256 live from the same HF repo verifies the
attacker's file against the attacker's own hash. This adapter enforces the
consensus fix at the interface level:

  - **pin by revision commit hash, never a floating branch/tag** — `revision`
    must look like a git commit hash (7-40 hex chars), not `main`/`master`;
  - **allowlist-regex every HF-derived string** (repo_id, filename), PLUS the
    independent segment-level `..` rejection gate (`pathsafety`), before any
    of it is used to build a URL — never build a path from raw external
    input (red-council item #1: regex alone does not reliably block `..`);
  - **download to an unpredictable, exclusively-created temp path
    (`tempfile.mkstemp`) -> verify sha256 -> atomic rename**, handled by the
    injected `Downloader` + the blob store's atomic-write path (never build
    the final path until the digest is verified);
  - **admission for network sources is gated by an optional `SignedCatalog`**
    (`catalog.py`, red-council item #4): when a catalog is wired, THAT
    manifest's sha256 is authoritative — it is never re-derived from what
    was actually downloaded, only verified against it — and there is no
    override flag to skip the check. When no catalog is wired (this v1
    foundation's default — no signing/key-mgmt pipeline exists yet), the
    adapter falls back to recording the downloaded content's own digest
    honestly as `provenance_tier="unverified-dev-mode"`; that fallback is a
    deploy-time gap this class documents loudly, not a silent downgrade.

The `Downloader` is injected (see `downloader.py`) — this adapter's own unit
tests never touch the network; they inject a fake Downloader that writes a
canned fixture to `dest`.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from yashigani_infer.adapters.base import SourceAdapter
from yashigani_infer.adapters.downloader import Downloader
from yashigani_infer.blobstore.store import DigestMismatchError, sha256_file
from yashigani_infer.catalog import SignedCatalog
from yashigani_infer.containment.hooks import FirstParseJailHook
from yashigani_infer.gguf.header import GGUFParseError
from yashigani_infer.models import Provenance, ProvenanceKind, ResolvedModel
from yashigani_infer.pathsafety import PathTraversalError, reject_dotdot_segments

# Pinned-revision guard: a git commit hash (short or full), never a branch
# name like "main". This is deliberately strict — callers that only have a
# branch name must resolve it to a commit hash themselves before calling in.
_REVISION_RE = re.compile(r"^[0-9a-f]{7,40}$")

# repo_id: optional "namespace/" + name, HF's own charset (alnum, dash,
# underscore, dot); filename: no path traversal, must be a `.gguf` file.
_REPO_ID_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,96}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,96}$")
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.gguf$", re.IGNORECASE)


class InvalidRevisionError(ValueError):
    """Raised when a revision is not a pinned commit hash (e.g. a floating branch)."""


class InvalidRepoReferenceError(ValueError):
    """Raised when repo_id or filename fails the allowlist-regex or segment-level guard."""


class HuggingFaceAdapter(SourceAdapter):
    def __init__(
        self,
        blob_store: Any,
        downloader: Downloader,
        *,
        scratch_dir: Path | None = None,
        catalog: SignedCatalog | None = None,
        first_parse_jail_hook: FirstParseJailHook | None = None,
    ) -> None:
        super().__init__(blob_store, first_parse_jail_hook=first_parse_jail_hook)
        self._downloader = downloader
        self._scratch_dir = Path(scratch_dir) if scratch_dir is not None else blob_store.root / "scratch"
        self._catalog = catalog

    def resolve(  # type: ignore[override]
        self,
        *,
        repo_id: str,
        revision: str,
        filename: str,
        expected_sha256: str | None = None,
        licence_accepted: bool = False,
        **_: Any,
    ) -> ResolvedModel:
        if not _REVISION_RE.match(revision):
            raise InvalidRevisionError(
                f"revision {revision!r} is not a pinned commit hash (7-40 hex chars); "
                "floating branches/tags (e.g. 'main') are refused — see council review "
                "High finding on supply-chain provenance"
            )
        if not _REPO_ID_RE.match(repo_id):
            raise InvalidRepoReferenceError(f"repo_id {repo_id!r} failed the allowlist guard")
        if not _FILENAME_RE.match(filename):
            raise InvalidRepoReferenceError(f"filename {filename!r} failed the allowlist guard (must be *.gguf)")
        try:
            reject_dotdot_segments(repo_id)
            reject_dotdot_segments(filename)
        except PathTraversalError as exc:
            raise InvalidRepoReferenceError(f"unsafe path segment: {exc}") from exc
        if not licence_accepted:
            # Council review High finding (Lu LIC-1 / Petra F4): "surface at
            # pull" must be a control, not a notice — deny-on-unresolved.
            raise PermissionError(
                f"licence not recorded as accepted for {repo_id}@{revision}/{filename} — refusing pull"
            )

        # Admission gate (red-council item #4). When a SignedCatalog is
        # wired, ITS sha256 is authoritative and there is no override; when
        # none is wired, fall back to the v1-foundation dev-mode behaviour
        # (record the downloaded content's own digest, honestly labelled).
        required_sha256: str | None
        if self._catalog is not None:
            entry = self._catalog.require(repo_id, revision, filename)  # raises if unsigned/absent — no override
            required_sha256 = entry.sha256
            provenance_tier = entry.provenance_tier
            if expected_sha256 is not None and expected_sha256.lower() != required_sha256.lower():
                raise DigestMismatchError(
                    f"caller-supplied expected_sha256 {expected_sha256!r} conflicts with the signed "
                    f"catalog's {required_sha256!r} for {repo_id}@{revision}/{filename}"
                )
        else:
            required_sha256 = expected_sha256
            provenance_tier = "unverified-dev-mode"

        url = f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
        self._scratch_dir.mkdir(parents=True, exist_ok=True)
        # mkstemp: unpredictable name + O_EXCL exclusive creation (no
        # predictable-name race, no pre-planted symlink at this exact path).
        fd, scratch_name = tempfile.mkstemp(dir=self._scratch_dir, prefix=".download-", suffix=".gguf")
        os.close(fd)
        scratch_path = Path(scratch_name)
        try:
            self._downloader.download(url, scratch_path)
            if not scratch_path.is_file():
                raise RuntimeError(f"downloader reported success but {scratch_path} does not exist")

            digest = sha256_file(scratch_path)
            if required_sha256 is not None and required_sha256.lower() != digest:
                raise DigestMismatchError(
                    f"expected sha256 {required_sha256!r} but downloaded file hashes to {digest!r}"
                )
            # Never re-derive-and-trust when a catalog verified the digest —
            # the catalog's signed value is what gets recorded; the
            # downloaded bytes are only checked AGAINST it, above. Only in
            # dev-mode (no catalog wired) do we fall back to the computed digest.
            final_sha256 = required_sha256 or digest

            try:
                header = self._first_parse_gguf_header(scratch_path)
            except GGUFParseError as exc:
                raise InvalidRepoReferenceError(
                    f"downloaded file from {repo_id}@{revision}/{filename} is not a valid GGUF: {exc}"
                ) from exc

            metadata = {
                "family": header.architecture,
                "name": header.name or filename,
                "parameter_size": header.parameter_size_label(),
                "quantization_level": header.quantization_level,
                "gguf_version": header.version,
            }
            provenance = Provenance(
                kind=ProvenanceKind.HUGGINGFACE,
                origin=repo_id,
                revision=revision,
                sha256=final_sha256,
                operator_supplied=False,
                extra={"filename": filename, "licence_accepted": True, "provenance_tier": provenance_tier},
            )
            return self.blob_store.put_from_path(
                scratch_path, metadata=metadata, provenance=provenance, expected_sha256=final_sha256
            )
        finally:
            scratch_path.unlink(missing_ok=True)


__all__ = ["HuggingFaceAdapter", "InvalidRevisionError", "InvalidRepoReferenceError"]
