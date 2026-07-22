"""
Yashigani Inspection — Ollama model observed-digest probe (T4a, 5.0).

The A5 verifier compares each model against its pin using OBSERVED digests: the
manifest digest (fast path, from `/api/tags`) and the weights-blob sha256
(primary anchor, computed from disk). This probe populates those observed values
into the two dicts the request path reads
(`_state.model_observed_digests` / `_state.model_observed_weights`).

Design:
  - `probe_manifest_digests()` — GET /api/tags, map model name → manifest digest.
    Pure parsing over the ollama response; live GET is the only non-testable bit.
  - `probe_weights_sha256()` — for each model, resolve its weights blob path in
    the ollama blob store and stream-hash it (compute_blob_sha256). Optional /
    best-effort: on a host where the blob store is not readable it is skipped and
    only the manifest fast-path is enforced.
  - `refresh_into()` — run both and write into the two observed-digest dicts.

Best-effort by contract: any error leaves the observed value absent, and the
verifier treats an absent observed value as "nothing to compare on that axis"
(a populated PIN with no observed value simply cannot mismatch on that axis —
honest, and the other axis still enforces).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from yashigani.inspection.model_integrity import compute_blob_sha256

logger = logging.getLogger(__name__)

# Default ollama blob + manifest stores; overridable for non-standard installs.
_DEFAULT_MODELS_DIR = os.path.expanduser("~/.ollama/models")
_DEFAULT_BLOB_DIR = os.path.join(_DEFAULT_MODELS_DIR, "blobs")
_DEFAULT_MANIFEST_DIR = os.path.join(_DEFAULT_MODELS_DIR, "manifests")
# The ollama media type of the WEIGHTS layer (the model tensors) — the primary
# trust anchor. Other layers (params, template, license) are not the weights.
_WEIGHTS_MEDIA_TYPE = "application/vnd.ollama.image.model"
_DEFAULT_REGISTRY = "registry.ollama.ai"


def probe_manifest_digests(base_url: str, timeout: float = 5.0) -> dict[str, str]:
    """model name → manifest digest from /api/tags. {} on any error."""
    from yashigani.inspection._ollama_transport import ollama_get_json
    data = ollama_get_json(base_url, "/api/tags", timeout=timeout)
    return parse_tags_digests(data)


def parse_tags_digests(data: Optional[dict]) -> dict[str, str]:
    """Pure parse of an /api/tags body → {model_name: digest}. Testable."""
    out: dict[str, str] = {}
    if not data:
        return out
    for m in data.get("models", []) or []:
        name = m.get("name") or m.get("model")
        digest = m.get("digest") or ""
        if name and digest:
            out[str(name)] = str(digest)
    return out


def blob_path_for_digest(digest: str, blob_dir: str = _DEFAULT_BLOB_DIR) -> Optional[str]:
    """Resolve an ollama blob digest ('sha256:<hex>' or 'sha256-<hex>') to its
    on-disk path. Returns None if the file is not present/readable."""
    if not digest:
        return None
    hexpart = digest.split(":", 1)[1] if ":" in digest else digest.split("-", 1)[-1]
    # ollama stores blobs as 'sha256-<hex>'
    candidate = os.path.join(blob_dir, f"sha256-{hexpart}")
    return candidate if os.path.isfile(candidate) else None


def _manifest_path_for_model(
    model: str, manifest_dir: str, registry: str = _DEFAULT_REGISTRY,
) -> Optional[str]:
    """Resolve an ollama model name ('qwen2.5:3b', 'user/model:tag') to its
    on-disk manifest file. Library models live under <registry>/library/."""
    name, _, tag = model.partition(":")
    tag = tag or "latest"
    ns, _, short = name.rpartition("/")
    namespace = ns or "library"
    candidate = os.path.join(manifest_dir, registry, namespace, short, tag)
    if os.path.isfile(candidate):
        return candidate
    # Some installs nest the registry differently; scan for the tag file.
    for root, _dirs, files in os.walk(manifest_dir):
        if os.path.basename(root) == short and tag in files:
            return os.path.join(root, tag)
    return None


def weights_digest_from_manifest(manifest_json: Optional[dict]) -> str:
    """Given a parsed ollama manifest, return the WEIGHTS layer digest (the
    layer whose mediaType is the ollama model type). '' if not found. Testable."""
    if not isinstance(manifest_json, dict):
        return ""
    for layer in manifest_json.get("layers", []) or []:
        if isinstance(layer, dict) and layer.get("mediaType") == _WEIGHTS_MEDIA_TYPE:
            return str(layer.get("digest") or "")
    return ""


def resolve_weights_blob_path(
    model: str,
    manifest_dir: str = _DEFAULT_MANIFEST_DIR,
    blob_dir: str = _DEFAULT_BLOB_DIR,
    registry: str = _DEFAULT_REGISTRY,
) -> Optional[str]:
    """Walk model → manifest → weights layer → on-disk blob path. None if any
    step is unreadable."""
    mpath = _manifest_path_for_model(model, manifest_dir, registry)
    if mpath is None:
        return None
    try:
        with open(mpath, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as exc:
        logger.debug("manifest read failed for %s (%s)", model, exc)
        return None
    wdigest = weights_digest_from_manifest(manifest)
    if not wdigest:
        return None
    return blob_path_for_digest(wdigest, blob_dir)


def probe_weights_sha256(
    manifest_digests: dict[str, str],
    blob_dir: str = _DEFAULT_BLOB_DIR,
    manifest_dir: str = _DEFAULT_MANIFEST_DIR,
    registry: str = _DEFAULT_REGISTRY,
) -> dict[str, str]:
    """For each model, walk its manifest to the WEIGHTS layer blob and stream-
    hash THAT (the primary trust anchor per the pinning design — ollama does not
    re-hash the weights at serve time, so an in-place weights swap is invisible
    to the manifest digest alone). Models whose weights blob is not readable are
    skipped (manifest fast-path still enforces on that axis)."""
    out: dict[str, str] = {}
    for name in manifest_digests:
        path = resolve_weights_blob_path(name, manifest_dir, blob_dir, registry)
        if path is None:
            continue
        try:
            out[name] = compute_blob_sha256(path)
        except OSError as exc:
            logger.debug("weights hash skipped for %s (%s)", name, exc)
    return out


def refresh_into(
    observed_digests: dict, observed_weights: dict,
    base_url: str, blob_dir: str = _DEFAULT_BLOB_DIR,
    manifest_dir: str = _DEFAULT_MANIFEST_DIR, timeout: float = 5.0,
) -> int:
    """Populate the two observed dicts in place. Returns the model count probed.
    Never raises — a probe failure leaves observed values absent (verifier then
    has nothing to mismatch on that axis)."""
    try:
        digests = probe_manifest_digests(base_url, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning("model probe (manifest) failed: %s", exc)
        return 0
    observed_digests.clear()
    observed_digests.update(digests)
    try:
        weights = probe_weights_sha256(digests, blob_dir=blob_dir, manifest_dir=manifest_dir)
        observed_weights.clear()
        observed_weights.update(weights)
    except Exception as exc:  # noqa: BLE001
        logger.warning("model probe (weights) failed: %s", exc)
    logger.info(
        "A5 model probe: %d manifest digest(s), %d weights hash(es)",
        len(observed_digests), len(observed_weights),
    )
    return len(digests)
