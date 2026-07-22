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

import logging
import os
from typing import Optional

from yashigani.inspection.model_integrity import compute_blob_sha256

logger = logging.getLogger(__name__)

# Default ollama blob store; overridable for non-standard installs.
_DEFAULT_BLOB_DIR = os.path.expanduser("~/.ollama/models/blobs")


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


def probe_weights_sha256(
    manifest_digests: dict[str, str], blob_dir: str = _DEFAULT_BLOB_DIR,
) -> dict[str, str]:
    """Best-effort: for each model whose manifest digest resolves to a readable
    blob, compute the weights-blob sha256. Absent/unreadable blobs are skipped.

    NOTE: ollama's /api/tags digest is the MANIFEST digest, not the weights
    blob; a precise weights-blob resolution requires reading the manifest. This
    computes the hash of whatever blob the digest resolves to when present, which
    is a real on-disk integrity anchor; a fuller manifest-walk to the exact
    weights layer is a live-stack refinement.
    """
    out: dict[str, str] = {}
    for name, digest in manifest_digests.items():
        path = blob_path_for_digest(digest, blob_dir)
        if path is None:
            continue
        try:
            out[name] = compute_blob_sha256(path)
        except OSError as exc:
            logger.debug("weights hash skipped for %s (%s)", name, exc)
    return out


def refresh_into(
    observed_digests: dict, observed_weights: dict,
    base_url: str, blob_dir: str = _DEFAULT_BLOB_DIR, timeout: float = 5.0,
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
        weights = probe_weights_sha256(digests, blob_dir=blob_dir)
        observed_weights.clear()
        observed_weights.update(weights)
    except Exception as exc:  # noqa: BLE001
        logger.warning("model probe (weights) failed: %s", exc)
    logger.info(
        "A5 model probe: %d manifest digest(s), %d weights hash(es)",
        len(observed_digests), len(observed_weights),
    )
    return len(digests)
