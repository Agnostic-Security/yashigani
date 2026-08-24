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
from typing import Mapping

#: The single override var this default honours — also the source of truth
#: `entrypoint.py`'s env-var contract docstring documents (Iris integration-
#: seam audit F4: this used to be a second, independently-maintained copy of
#: the same var name in `entrypoint._resolve_blob_store_root`).
BLOB_STORE_ROOT_ENV = "YSG_KUROSHIO_BLOB_STORE_ROOT"


def _default_blob_store_root(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the blob-store root, honouring an operator override.

    Defaults under the user's home so unit tests never need root/sudo and
    the same code works identically on macOS and Linux.

    Args:
        env: the mapping to read the override from. Defaults to the real
            `os.environ` (production / `EngineConfig()`'s own default-factory
            use). `entrypoint.py` passes its own injected env mapping here
            instead of touching `os.environ` directly, so its env-parsing
            stays independently unit-testable with a plain `dict` — this is
            the ONE source for "what does an unset
            `YSG_KUROSHIO_BLOB_STORE_ROOT` default to," per Iris F4 (previously
            duplicated, independently, in `entrypoint._resolve_blob_store_root`).
    """
    active_env: Mapping[str, str] = os.environ if env is None else env
    override = active_env.get(BLOB_STORE_ROOT_ENV)
    if override:
        return Path(override)
    return Path.home() / ".yashigani" / "kuroshio" / "blobs"


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
