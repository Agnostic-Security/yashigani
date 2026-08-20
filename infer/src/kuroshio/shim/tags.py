# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/tags` synthesis — ollama's model-list response, built from GGUF metadata.

Council review High finding (Tom #4, Iris F1/F2): `details.{family,
parameter_size,quantization_level,digest}` must come from the GGUF header,
not be left null — a null field silently breaks the 21 known `/api/tags`
call sites, including the GPU-pressure dashboard.
"""

from __future__ import annotations

from typing import Any

from kuroshio.models import ResolvedModel


def display_name(model: ResolvedModel) -> str:
    name = model.metadata.get("name") or model.provenance.origin
    return name if ":" in name else f"{name}:latest"


def blob_size(model: ResolvedModel) -> int:
    try:
        return model.blob_path.stat().st_size
    except OSError:
        return 0


def details_dict(model: ResolvedModel) -> dict[str, Any]:
    """Shared `details.{family,parameter_size,quantization_level,...}` block,
    reused by both `/api/tags` and `/api/show` synthesis (show.py)."""
    family = model.metadata.get("family") or "unknown"
    return {
        "parent_model": "",
        "format": "gguf",
        "family": family,
        "families": [family] if family != "unknown" else [],
        "parameter_size": model.metadata.get("parameter_size") or "unknown",
        "quantization_level": model.metadata.get("quantization_level") or "unknown",
    }


def capabilities_list(model: ResolvedModel) -> list[str]:
    """Ollama emits a `capabilities` array on every model object (see the golden
    `tags.json` / `show.json` fixtures — e.g. ``["completion", "tools"]``).

    Derived from model metadata when the source adapter recorded it, else falls
    back to the universally-true ``["completion"]`` — we never over-claim
    ``tools``/``vision`` support we cannot verify from the GGUF header. Shared by
    both `/api/tags` and `/api/show` synthesis (show.py)."""
    caps = model.metadata.get("capabilities")
    if isinstance(caps, list) and caps:
        return [str(c) for c in caps]
    return ["completion"]


def synthesize_tag_entry(model: ResolvedModel) -> dict[str, Any]:
    """Build one `/api/tags` `models[]` entry from a single ResolvedModel."""
    name = display_name(model)
    return {
        "name": name,
        "model": name,
        "modified_at": model.provenance.recorded_at.isoformat(),
        "size": blob_size(model),
        "digest": model.sha256,
        "details": details_dict(model),
        "capabilities": capabilities_list(model),
    }


def synthesize_tags(models: list[ResolvedModel]) -> dict[str, Any]:
    """Build the full `/api/tags` response body."""
    return {"models": [synthesize_tag_entry(m) for m in models]}


__all__ = [
    "details_dict",
    "display_name",
    "blob_size",
    "capabilities_list",
    "synthesize_tag_entry",
    "synthesize_tags",
]
