# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Engine configuration.

Deliberately minimal for the v1 foundation spike. Real deploy-time config
(per-runtime GPU backend selection, Mac loopback token, Caddy front wiring)
is platform-integration work tracked separately
(inference-engine-platform-requirements-20260722.md) and out of scope here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_blob_store_root() -> Path:
    """Resolve the blob-store root, honouring an operator override.

    Defaults under the user's home so unit tests never need root/sudo and
    the same code works identically on macOS and Linux.
    """
    override = os.environ.get("YSG_INFER_BLOB_STORE_ROOT")
    if override:
        return Path(override)
    return Path.home() / ".yashigani" / "infer" / "blobs"


@dataclass(frozen=True)
class EngineConfig:
    """Top-level engine configuration.

    Attributes:
        blob_store_root: Root directory for the content-addressed blob store.
        idle_unload_seconds: Unload a resident (non-pinned) model after this
            many seconds of inactivity.
        max_resident_models: LRU-evict the least-recently-used non-pinned
            model once resident count exceeds this.
        llama_server_binary: Path to the `llama-server` binary. Not resolved
            at import time — the ProcessRunner consumes it lazily, so unit
            tests never require the real binary to exist.
    """

    blob_store_root: Path = field(default_factory=_default_blob_store_root)
    idle_unload_seconds: int = 600
    max_resident_models: int = 3
    llama_server_binary: str = "llama-server"


__all__ = ["EngineConfig"]
