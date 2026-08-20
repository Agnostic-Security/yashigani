# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""SourceAdapter ABC — the shared contract every import source implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, BinaryIO

from kuroshio.blobstore.store import BlobStore
from kuroshio.containment.hooks import FirstParseJailHook, default_first_parse_jail_hook
from kuroshio.gguf.header import GGUFHeader, parse_gguf_header
from kuroshio.models import ResolvedModel

# Bounded prefix read handed to the first-parse jail hook (Iris integration-
# seam audit F3): real GGUF metadata + tensor-info sections are at most a
# few MiB even for huge multi-shard models — this ceiling exists purely to
# bound worst-case memory on a hostile input, mirroring the safetensors
# header ceiling already used by `adapters/convert.py`
# (`_MAX_SAFETENSORS_HEADER_BYTES`). A legitimate file whose header somehow
# exceeds this ceiling fails closed (`GGUFParseError: unexpected EOF`), not
# silently truncated-and-accepted.
FIRST_PARSE_READ_CEILING_BYTES = 64 * 1024 * 1024  # 64 MiB


class SourceAdapter(ABC):
    """A model-import source. `resolve()` produces one universal `ResolvedModel`.

    Concrete adapters (local file, local Ollama store, local LM Studio
    store, Hugging Face pull, convert-to-GGUF) each implement `resolve()`
    with their own inputs, but all funnel into the same content-addressed
    `BlobStore` and produce the same `ResolvedModel` shape — this keeps the
    supervisor, shim, and audit plane source-agnostic.
    """

    def __init__(
        self,
        blob_store: BlobStore,
        *,
        first_parse_jail_hook: FirstParseJailHook | None = None,
    ) -> None:
        self.blob_store = blob_store
        # Iris integration-seam audit F3: every GGUF-parsing adapter routes
        # the raw header bytes through this seam BEFORE its own metadata
        # extraction touches them (see `_first_parse_gguf_header` below and
        # `containment/hooks.py`'s module docstring for the v1-vs-
        # orchestrated split). Defaults to the v1 in-process bounded-parse
        # guard, never to the pure `noop_first_parse_jail_hook` identity
        # passthrough — a caller must explicitly opt into "no guard at all."
        self._first_parse_jail_hook: FirstParseJailHook = first_parse_jail_hook or default_first_parse_jail_hook

    @abstractmethod
    def resolve(self, **kwargs: Any) -> ResolvedModel:
        """Resolve this adapter's source into a stored, provenance-recorded GGUF blob."""
        raise NotImplementedError

    def _first_parse_gguf_header(self, source: Path | BinaryIO) -> GGUFHeader:
        """Read a bounded prefix of `source`, route it through the first-parse
        jail hook, then parse the (hook-cleared) bytes for real.

        This is the call site the Iris integration-seam audit (F3, 2026-07-22)
        found missing: `FirstParseJailHook` existed with zero callers before
        this change — every adapter called `gguf.header.parse_gguf_header`
        directly, in-process, with no seam a future containment mechanism
        could attach to. Fails closed: a malformed/hostile header raises
        `GGUFParseError` before any metadata is extracted or the blob is
        admitted to the store.

        Args:
            source: a filesystem `Path` (local-file / Hugging Face scratch
                download) or an already-open binary file object positioned
                anywhere (Ollama/LM Studio store adapters, which reuse a
                single `O_NOFOLLOW` fd for hashing + parsing + ingestion —
                this method seeks it back to 0 itself, it does not need to
                already be at the start).
        """
        if isinstance(source, Path):
            with open(source, "rb") as fh:
                header_bytes = fh.read(FIRST_PARSE_READ_CEILING_BYTES)
        else:
            source.seek(0)
            header_bytes = source.read(FIRST_PARSE_READ_CEILING_BYTES)
        validated_bytes = self._first_parse_jail_hook(header_bytes)
        return parse_gguf_header(validated_bytes)


__all__ = ["SourceAdapter", "FIRST_PARSE_READ_CEILING_BYTES"]
