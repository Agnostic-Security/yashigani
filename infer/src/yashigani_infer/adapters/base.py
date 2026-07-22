# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""SourceAdapter ABC — the shared contract every import source implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from yashigani_infer.blobstore.store import BlobStore
from yashigani_infer.models import ResolvedModel


class SourceAdapter(ABC):
    """A model-import source. `resolve()` produces one universal `ResolvedModel`.

    Concrete adapters (local file, local Ollama store, local LM Studio
    store, Hugging Face pull, convert-to-GGUF) each implement `resolve()`
    with their own inputs, but all funnel into the same content-addressed
    `BlobStore` and produce the same `ResolvedModel` shape — this keeps the
    supervisor, shim, and audit plane source-agnostic.
    """

    def __init__(self, blob_store: BlobStore) -> None:
        self.blob_store = blob_store

    @abstractmethod
    def resolve(self, **kwargs: Any) -> ResolvedModel:
        """Resolve this adapter's source into a stored, provenance-recorded GGUF blob."""
        raise NotImplementedError


__all__ = ["SourceAdapter"]
