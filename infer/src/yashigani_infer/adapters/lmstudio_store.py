# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Local LM Studio-store adapter — index a user's already-downloaded LM Studio GGUF tree.

No network. LM Studio lays out plain GGUF files in HF-style
`<publisher>/<model>/<file>.gguf` directories under `~/.lmstudio/models` (or
the older `~/.cache/lm-studio/models`) — this is just point-and-index, same
low-risk/high-value shape as the Ollama-store adapter (council review §3a).

Red-council hardening (item #2, CRITICAL): `relative_path` is caller-
supplied and used to build a filesystem path — it passes BOTH `pathsafety`
gates (segment-level `..` rejection AND canonicalize-and-contain against
the LM Studio root, which also refuses a leaf symlink outright). The
resolved file is opened exactly ONCE with `O_NOFOLLOW`, and that single fd
is reused for hashing, GGUF parsing, and ingestion
(`BlobStore.put_from_open_file`) — no second open-by-path.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from yashigani_infer.adapters.base import SourceAdapter
from yashigani_infer.blobstore.store import sha256_stream
from yashigani_infer.gguf.header import GGUFParseError, parse_gguf_header
from yashigani_infer.models import Provenance, ProvenanceKind, ResolvedModel
from yashigani_infer.pathsafety import (
    PathTraversalError,
    canonicalize_and_contain,
    open_no_follow_symlink,
    reject_dotdot_segments,
)


class LMStudioStoreAdapterError(ValueError):
    """Raised when an LM Studio local-store import cannot be resolved safely."""


def _default_lmstudio_dirs() -> tuple[Path, ...]:
    home = Path.home()
    return (home / ".lmstudio" / "models", home / ".cache" / "lm-studio" / "models")


class LMStudioStoreAdapter(SourceAdapter):
    def resolve(  # type: ignore[override]
        self,
        *,
        relative_path: str,
        lmstudio_dir: Path | None = None,
        **_: Any,
    ) -> ResolvedModel:
        candidates = (Path(lmstudio_dir),) if lmstudio_dir is not None else _default_lmstudio_dirs()

        try:
            reject_dotdot_segments(relative_path)
        except PathTraversalError as exc:
            raise LMStudioStoreAdapterError(f"unsafe relative_path {relative_path!r}: {exc}") from exc

        if not relative_path.lower().endswith(".gguf"):
            raise LMStudioStoreAdapterError(f"not a .gguf file: {relative_path!r}")

        resolved_target: Path | None = None
        for root in candidates:
            if not root.is_dir():
                continue
            try:
                candidate = canonicalize_and_contain(root, relative_path)
            except PathTraversalError:
                continue
            if candidate.is_file():
                resolved_target = candidate
                break

        if resolved_target is None:
            raise LMStudioStoreAdapterError(
                f"no LM Studio GGUF found for {relative_path!r} under {[str(c) for c in candidates]}"
            )

        # Open EXACTLY ONCE, O_NOFOLLOW, and reuse this one fd for hashing,
        # GGUF parsing, and ingestion — never re-open by path.
        fd = open_no_follow_symlink(resolved_target)
        with os.fdopen(fd, "rb") as fh:
            digest = sha256_stream(fh)
            fh.seek(0)
            try:
                header = parse_gguf_header(fh)
            except GGUFParseError as exc:
                raise LMStudioStoreAdapterError(f"{resolved_target} is not a valid GGUF file: {exc}") from exc

            metadata = {
                "family": header.architecture,
                "name": header.name or resolved_target.stem,
                "parameter_size": header.parameter_size_label(),
                "quantization_level": header.quantization_level,
                "gguf_version": header.version,
            }
            provenance = Provenance(
                kind=ProvenanceKind.LOCAL_LMSTUDIO,
                origin=str(resolved_target),
                sha256=digest,
                operator_supplied=True,
            )
            return self.blob_store.put_from_open_file(
                fh, metadata=metadata, provenance=provenance, expected_sha256=digest
            )


__all__ = ["LMStudioStoreAdapter", "LMStudioStoreAdapterError"]
