# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Source-adapter layer — the universal-import core abstraction.

One internal model = (GGUF blob by sha256) + normalized metadata +
source-provenance record. Every adapter's `resolve()` produces a
`ResolvedModel`; adapters differ only in how they get there and what
provenance they can honestly assert (council review §3a).
"""

from __future__ import annotations

from yashigani_infer.adapters.base import SourceAdapter
from yashigani_infer.adapters.convert import ConversionInvoker, ConvertAdapter, PickleRefusedError
from yashigani_infer.adapters.downloader import Downloader, HttpxDownloader
from yashigani_infer.adapters.huggingface import HuggingFaceAdapter, InvalidRevisionError
from yashigani_infer.adapters.local_file import LocalFileAdapter
from yashigani_infer.adapters.lmstudio_store import LMStudioStoreAdapter
from yashigani_infer.adapters.ollama_store import OllamaStoreAdapter

__all__ = [
    "SourceAdapter",
    "ConversionInvoker",
    "ConvertAdapter",
    "PickleRefusedError",
    "Downloader",
    "HttpxDownloader",
    "HuggingFaceAdapter",
    "InvalidRevisionError",
    "LocalFileAdapter",
    "LMStudioStoreAdapter",
    "OllamaStoreAdapter",
]
