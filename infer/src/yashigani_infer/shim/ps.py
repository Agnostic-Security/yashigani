# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/ps` synthesis — ollama's resident-model status response.

Council review High finding (Tom #4, Iris F1/F2): `num_gpu` + `size_vram`
feed the GPU-pressure dashboard (`gpu_monitor.py` in the 5.0 gateway tree —
NOT imported here, this package is self-contained); a missing field makes
the dashboard go blind with no error, rather than a visible failure.
`num_gpu` here is the offloaded-layer count (matches the supervisor's
`/healthz` `offloaded_layers` field); `size_vram` is whatever the caller
(app.py, wiring the real supervisor) reports as measured VRAM in use — this
v1 foundation does not itself measure VRAM (that requires a live GPU
backend), so callers pass 0 until real telemetry is wired.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from yashigani_infer.models import ResolvedModel
from yashigani_infer.shim.tags import blob_size, details_dict, display_name


@dataclass(frozen=True)
class PsRow:
    """One resident model's status, joining blob-store metadata with live supervisor state."""

    model: ResolvedModel
    n_gpu_layers: int
    vram_bytes: int
    expires_at: datetime | None = None


def _ps_entry(row: PsRow) -> dict[str, Any]:
    name = display_name(row.model)
    return {
        "name": name,
        "model": name,
        "size": blob_size(row.model),
        "digest": row.model.sha256,
        "details": details_dict(row.model),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "size_vram": row.vram_bytes,
        "num_gpu": row.n_gpu_layers,
    }


def synthesize_ps(rows: list[PsRow]) -> dict[str, Any]:
    """Build the full `/api/ps` response body."""
    return {"models": [_ps_entry(r) for r in rows]}


__all__ = ["PsRow", "synthesize_ps"]
