# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Shared value types for the source-adapter / blob-store layer.

Design principle (council review §3a): one internal model =
``(GGUF blob by sha256) + normalized metadata + source-provenance record``.
Every :class:`~kuroshio.adapters.base.SourceAdapter` resolves to a
:class:`ResolvedModel`; adapters differ only in how they get there and what
provenance they can honestly assert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class ProvenanceKind(str, Enum):
    """How a GGUF blob entered the store.

    Network sources (HUGGINGFACE) can assert repo+revision+sha256 pinned
    provenance. Local sources (LOCAL_FILE, LOCAL_OLLAMA, LOCAL_LMSTUDIO)
    cannot assert more than "the operator already had this file on disk" —
    recorded honestly as ``operator_supplied``, never faked as counter-signed
    (council review §3a: "audit it honestly as such, don't fake a signature").
    CONVERTED marks a v2 derived artifact (safetensors -> GGUF); the actual
    conversion mechanism is stubbed in this v1 foundation (see
    :mod:`kuroshio.adapters.convert`).
    """

    LOCAL_FILE = "local-file"
    LOCAL_OLLAMA = "local-ollama"
    LOCAL_LMSTUDIO = "local-lmstudio"
    HUGGINGFACE = "huggingface"
    CONVERTED = "converted"


@dataclass(frozen=True)
class Provenance:
    """Source-provenance record for a resolved GGUF blob.

    Attributes:
        kind: Which adapter produced this blob.
        origin: Adapter-specific identifier of where the blob came from
            (a filesystem path, an ``repo_id`` for Hugging Face, an
            ``ollama_model:tag`` reference, etc).
        revision: For network sources, the pinned revision (commit hash,
            NOT a floating branch/tag — council review High finding
            "supply-chain provenance": pin by HF revision commit hash).
        sha256: The digest of the resolved GGUF bytes.
        operator_supplied: True when provenance rests on "the operator
            already had this file" rather than a verifiable, pinned network
            fetch. Local-file/Ollama-store/LM-Studio-store imports are
            ALWAYS operator_supplied=True; Hugging Face pulls are False.
        recorded_at: UTC timestamp the provenance record was created.
        extra: Adapter-specific free-form metadata (e.g. HF ``cardData``
            licence fields, Ollama manifest tag).
    """

    kind: ProvenanceKind
    origin: str
    sha256: str
    revision: str | None = None
    operator_supplied: bool = True
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for the blob-store metadata sidecar (JSON-safe)."""
        return {
            "kind": self.kind.value,
            "origin": self.origin,
            "sha256": self.sha256,
            "revision": self.revision,
            "operator_supplied": self.operator_supplied,
            "recorded_at": self.recorded_at.isoformat(),
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Provenance:
        """Deserialize a metadata sidecar record back into a Provenance."""
        return cls(
            kind=ProvenanceKind(data["kind"]),
            origin=data["origin"],
            sha256=data["sha256"],
            revision=data.get("revision"),
            operator_supplied=bool(data.get("operator_supplied", True)),
            recorded_at=datetime.fromisoformat(data["recorded_at"]),
            extra=dict(data.get("extra", {})),
        )


@dataclass(frozen=True)
class ResolvedModel:
    """The universal output of every :class:`SourceAdapter`.

    Attributes:
        sha256: Content digest of the GGUF blob (the blob store's key).
        blob_path: Path to the GGUF blob inside the content-addressed store.
        metadata: Normalized metadata dict, typically produced by
            :func:`kuroshio.gguf.header.parse_gguf_header` plus
            adapter-derived fields (``display_name`` etc).
        provenance: The source-provenance record.
    """

    sha256: str
    blob_path: Path
    metadata: dict[str, Any]
    provenance: Provenance


__all__ = ["ProvenanceKind", "Provenance", "ResolvedModel"]
