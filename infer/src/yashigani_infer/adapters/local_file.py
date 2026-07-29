# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Local GGUF file/path adapter — no network, air-gap-friendly."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yashigani_infer.adapters.base import SourceAdapter
from yashigani_infer.blobstore.store import sha256_file
from yashigani_infer.gguf.header import GGUFParseError
from yashigani_infer.models import Provenance, ProvenanceKind, ResolvedModel


class LocalFileAdapterError(ValueError):
    """Raised when a local-file import is refused (missing, not a GGUF, etc)."""


class LocalFileAdapter(SourceAdapter):
    """Import a GGUF file directly from a filesystem path.

    Provenance is always recorded honestly as `operator_supplied=True` —
    there is no network fetch to pin/counter-sign here; the trust boundary
    is "the operator already has this file on their own disk" (council
    review §3a).
    """

    def resolve(self, *, path: Path, **_: Any) -> ResolvedModel:  # type: ignore[override]
        path = Path(path)
        if not path.is_file():
            raise LocalFileAdapterError(f"not a file: {path}")

        # Parse the header first (cheap — reads only the metadata section,
        # never the whole file), routed through the first-parse jail hook
        # (Iris audit F3 — see `SourceAdapter._first_parse_gguf_header`), to
        # both validate this is really a GGUF and to build normalized
        # metadata for the ollama shim.
        try:
            header = self._first_parse_gguf_header(path)
        except GGUFParseError as exc:
            raise LocalFileAdapterError(f"{path} is not a valid GGUF file: {exc}") from exc

        metadata = {
            "family": header.architecture,
            "name": header.name or path.stem,
            "parameter_size": header.parameter_size_label(),
            "quantization_level": header.quantization_level,
            "gguf_version": header.version,
            # H4 (Red-Council, 2026-07-29): extracted so the serve-path
            # fail-closed guard (app.py::_require_chat_template) can check
            # it without re-parsing the GGUF header at request time.
            "chat_template": header.chat_template,
        }

        digest = sha256_file(path)
        provenance = Provenance(
            kind=ProvenanceKind.LOCAL_FILE,
            origin=str(path.resolve()),
            sha256=digest,
            operator_supplied=True,
        )
        return self.blob_store.put_from_path(path, metadata=metadata, provenance=provenance, expected_sha256=digest)


__all__ = ["LocalFileAdapter", "LocalFileAdapterError"]
