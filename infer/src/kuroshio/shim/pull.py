# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""`/api/pull` translation — ollama-style progress NDJSON wrapping a source-adapter resolve.

Council review Medium finding (Laura F6, Lu): `/api/pull` must be gated to
an admin-only mesh identity + allowlist regardless of caller. That authz
decision belongs to the HTTP-app layer (Caddy mesh-identity + an allowlist
check before this function is ever invoked) — this module only produces the
ollama-shaped progress stream once a pull has been authorized to proceed.
"""

from __future__ import annotations

from typing import Callable, Iterator

from kuroshio.licensing import licence_verdict_for_model_metadata
from kuroshio.models import ResolvedModel
from kuroshio.shim.framing import format_ndjson_line


def iter_pull_progress(resolve: Callable[[], ResolvedModel]) -> Iterator[bytes]:
    """Wrap a source-adapter `resolve()` call in ollama's `/api/pull` progress shape.

    v1 foundation: the underlying adapters (Hugging Face, in particular)
    don't yet expose incremental byte-progress callbacks, so this emits the
    ollama-shaped start/success/error milestones rather than a granular
    `completed`/`total` byte counter — the shape existing consumers parse
    (`status` field) is present and correct; fine-grained progress can be
    layered in without changing this function's external contract.
    """
    yield format_ndjson_line({"status": "pulling manifest"})
    try:
        resolved = resolve()
    except Exception as exc:  # noqa: BLE001 - deliberately surfaced to the caller as a status event
        yield format_ndjson_line({"status": "error", "error": str(exc)})
        raise
    yield format_ndjson_line({"status": "verifying sha256 digest"})
    # Licence-alert-on-import (Tiago 2026-07-31): warn-not-block. A model
    # whose declared licence isn't recognised commercial-free (or that
    # declares none) still imports, but the stream carries a non-blocking
    # alert event ahead of the success line. Extra keys on a status event
    # are shape-compatible with ollama's NDJSON progress contract —
    # consumers key off `status` only.
    verdict = licence_verdict_for_model_metadata(resolved.metadata)
    if verdict.alert is not None:
        yield format_ndjson_line(
            {
                "status": "licence alert",
                "licence": verdict.raw or "",
                "detail": verdict.alert,
            }
        )
    yield format_ndjson_line({"status": "writing manifest"})
    yield format_ndjson_line({"status": "success", "digest": resolved.sha256})


__all__ = ["iter_pull_progress"]
