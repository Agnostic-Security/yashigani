# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Local Ollama-store adapter — index a user's already-pulled Ollama models.

No network. This is the low-risk, high-value import path the council review
called out (§3a): the user already trusts these bytes; there is no ToS
question because nothing is being pulled from a registry (Petra, §3a).

Layout (Ollama's on-disk convention, `~/.ollama/models`):
    manifests/<registry-host>/<namespace>/<model>/<tag>   -- JSON manifest
    blobs/sha256-<hex>                                     -- content-addressed layers

We locate the manifest, find the layer whose mediaType is the model layer,
and re-verify its digest ourselves — the manifest's claimed digest is never
trusted without recomputation (the same "don't trust, verify" discipline as
the Hugging Face adapter's expected_sha256 check).

Red-council hardening (item #2, CRITICAL): every path built from `model_ref`
components passes BOTH `pathsafety` gates (segment-level `..` rejection AND
canonicalize-and-contain against the Ollama store root) even though the
reference-component regex already disallows a leading `.`; both gates run
unconditionally, not "only if the regex looks insufficient." The blob file
is opened exactly ONCE with `O_NOFOLLOW`, and that single fd is used for
hashing, GGUF parsing, AND ingestion into the blob store
(`BlobStore.put_from_open_file`) — no second open-by-path, closing the
TOCTOU window where the path could be swapped for a symlink between checks.

Red-Council H3 (Iris, 2026-07-29 design-review — RC-2, HIGH): this adapter
used to build `metadata["name"]` as `header.name or str(ref)` — preferring
the GGUF-embedded, vendor-supplied `general.name` title over the
structured `namespace/model:tag` reference, with the reference used only
as a fallback when the header had no name at all (which it almost always
does). That fallback order is backwards for THIS adapter specifically:
Yashigani's entire existing surface (`/api/chat`, `/api/tags`, Postgres
budget/policy/model-allocation rows, UI dropdowns) addresses models by the
ollama-tag string (`"qwen2.5:3b"`), not by a GGUF's arbitrary vendor title
("Qwen2.5 3B Instruct" — different casing, different separator
convention, no guaranteed match). At cutover, re-importing an already-
resident Ollama model through this adapter would silently rename it away
from the identifier every existing policy/budget/agent config already
references, 404-ing on first post-cutover inference. This adapter now
ALWAYS names by the parsed, structured `ref` — it is migrating FROM a
system that already used that exact string as the addressing key, so it
is authoritative here, not merely a fallback. (The other three adapters —
Hugging Face, LM Studio, local-file — are NOT changed: they have no
pre-existing external addressing convention to preserve; Iris's fix is
scoped to this one adapter.)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kuroshio.adapters.base import SourceAdapter
from kuroshio.blobstore.store import DigestMismatchError, sha256_stream
from kuroshio.gguf.header import GGUFParseError
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.pathsafety import (
    canonicalize_and_contain,
    open_no_follow_symlink,
    reject_dotdot_segments,
)

_MODEL_LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.ollama.image.model",
        "application/vnd.ollama.image.gguf",  # older/alt naming seen in the wild
    }
)

# Ollama-style reference components: registry hostnames, namespaces, model
# names, and tags are all DNS-label-ish / semver-ish. Allowlist-regex, not a
# denylist, before any of these strings are used to build a filesystem path.
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_REGISTRY_HOST = "registry.ollama.ai"
DEFAULT_NAMESPACE = "library"
DEFAULT_TAG = "latest"


class OllamaStoreAdapterError(ValueError):
    """Raised when a local-Ollama-store import cannot be resolved safely."""


@dataclass(frozen=True)
class OllamaModelRef:
    registry: str
    namespace: str
    model: str
    tag: str

    def __str__(self) -> str:
        return f"{self.namespace}/{self.model}:{self.tag}"


def parse_model_ref(ref: str) -> OllamaModelRef:
    """Parse an Ollama-style reference like `llama3:8b` or `library/llama3:latest`."""
    name_part, _, tag = ref.partition(":")
    tag = tag or DEFAULT_TAG
    parts = [p for p in name_part.split("/") if p]
    if not parts:
        raise OllamaStoreAdapterError(f"empty model reference: {ref!r}")
    if len(parts) == 1:
        registry, namespace, model = DEFAULT_REGISTRY_HOST, DEFAULT_NAMESPACE, parts[0]
    elif len(parts) == 2:
        registry, namespace, model = DEFAULT_REGISTRY_HOST, parts[0], parts[1]
    elif len(parts) == 3:
        registry, namespace, model = parts[0], parts[1], parts[2]
    else:
        raise OllamaStoreAdapterError(f"unparseable model reference: {ref!r}")

    for label, value in (("registry", registry), ("namespace", namespace), ("model", model), ("tag", tag)):
        if not _SAFE_COMPONENT.match(value):
            raise OllamaStoreAdapterError(f"unsafe {label} component in reference {ref!r}: {value!r}")
    return OllamaModelRef(registry=registry, namespace=namespace, model=model, tag=tag)


def _default_ollama_dir() -> Path:
    return Path.home() / ".ollama"


class OllamaStoreAdapter(SourceAdapter):
    def resolve(self, *, model_ref: str, ollama_dir: Path | None = None, **_: Any) -> ResolvedModel:  # type: ignore[override]
        base = Path(ollama_dir) if ollama_dir is not None else _default_ollama_dir()
        ref = parse_model_ref(model_ref)

        manifest_relative = f"models/manifests/{ref.registry}/{ref.namespace}/{ref.model}/{ref.tag}"
        try:
            reject_dotdot_segments(manifest_relative)
            manifest_path = canonicalize_and_contain(base, manifest_relative)
        except ValueError as exc:
            raise OllamaStoreAdapterError(f"unsafe manifest path for {ref}: {exc}") from exc

        if not manifest_path.is_file():
            raise OllamaStoreAdapterError(f"no manifest for {ref} at {manifest_path}")

        manifest_fd = open_no_follow_symlink(manifest_path)
        try:
            with os.fdopen(manifest_fd, "rb") as manifest_fh:
                manifest_bytes = manifest_fh.read()
        except OSError as exc:
            raise OllamaStoreAdapterError(f"cannot read manifest at {manifest_path}: {exc}") from exc

        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise OllamaStoreAdapterError(f"malformed manifest at {manifest_path}: {exc}") from exc

        layers = manifest.get("layers", [])
        model_layer = next(
            (layer for layer in layers if layer.get("mediaType") in _MODEL_LAYER_MEDIA_TYPES),
            None,
        )
        if model_layer is None:
            raise OllamaStoreAdapterError(f"manifest {manifest_path} has no model (GGUF) layer")

        claimed_digest = str(model_layer.get("digest", ""))
        prefix = "sha256:"
        if not claimed_digest.startswith(prefix):
            raise OllamaStoreAdapterError(f"unsupported digest scheme: {claimed_digest!r}")
        hex_digest = claimed_digest[len(prefix) :]
        if not _SHA256_HEX.match(hex_digest):
            raise OllamaStoreAdapterError(f"malformed sha256 digest in manifest: {claimed_digest!r}")

        blob_relative = f"models/blobs/sha256-{hex_digest}"
        try:
            reject_dotdot_segments(blob_relative)
            blob_path = canonicalize_and_contain(base, blob_relative)
        except ValueError as exc:
            raise OllamaStoreAdapterError(f"unsafe blob path for digest {hex_digest}: {exc}") from exc

        if not blob_path.is_file():
            raise OllamaStoreAdapterError(f"manifest references missing blob: {blob_path}")

        # Open the blob EXACTLY ONCE, O_NOFOLLOW, and reuse this one fd for
        # hashing, GGUF parsing, and ingestion — never re-open by path.
        blob_fd = open_no_follow_symlink(blob_path)
        with os.fdopen(blob_fd, "rb") as blob_fh:
            actual_digest = sha256_stream(blob_fh)
            if actual_digest != hex_digest:
                raise DigestMismatchError(
                    f"Ollama blob {blob_path} digest is {actual_digest}, manifest claims {hex_digest}"
                )

            try:
                header = self._first_parse_gguf_header(blob_fh)
            except GGUFParseError as exc:
                raise OllamaStoreAdapterError(f"blob {blob_path} is not a valid GGUF file: {exc}") from exc

            metadata = {
                "family": header.architecture,
                # H3: the ollama-tag reference is authoritative for THIS
                # adapter — never the GGUF's own vendor-supplied name (see
                # module docstring). `str(ref)` is always non-empty
                # (`parse_model_ref` guarantees every component is present).
                "name": str(ref),
                "parameter_size": header.parameter_size_label(),
                "quantization_level": header.quantization_level,
                "gguf_version": header.version,
                "chat_template": header.chat_template,
                "license": header.license,
            }
            provenance = Provenance(
                kind=ProvenanceKind.LOCAL_OLLAMA,
                origin=str(ref),
                sha256=actual_digest,
                operator_supplied=True,
                extra={"manifest_path": str(manifest_path)},
            )
            return self.blob_store.put_from_open_file(
                blob_fh, metadata=metadata, provenance=provenance, expected_sha256=actual_digest
            )


__all__ = ["OllamaStoreAdapter", "OllamaStoreAdapterError", "OllamaModelRef", "parse_model_ref"]
