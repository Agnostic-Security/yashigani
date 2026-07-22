# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for `/api/embeddings` translation and `/api/pull` progress-NDJSON wrapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from yashigani_infer.models import Provenance, ProvenanceKind, ResolvedModel
from yashigani_infer.shim.embeddings import translate_embeddings_request, translate_embeddings_response
from yashigani_infer.shim.pull import iter_pull_progress


def test_translate_embeddings_request_prefers_input_over_prompt() -> None:
    req = translate_embeddings_request({"model": "x", "prompt": "old-style", "input": "new-style"})
    assert req == {"content": "new-style"}


def test_translate_embeddings_request_falls_back_to_prompt() -> None:
    req = translate_embeddings_request({"model": "x", "prompt": "legacy"})
    assert req == {"content": "legacy"}


def test_translate_embeddings_response_single_object() -> None:
    resp = translate_embeddings_response({"embedding": [0.1, 0.2, 0.3]})
    assert resp == {"embedding": [0.1, 0.2, 0.3]}


def test_translate_embeddings_response_single_item_list() -> None:
    resp = translate_embeddings_response([{"embedding": [1.0, 2.0]}])
    assert resp == {"embedding": [1.0, 2.0]}


def test_translate_embeddings_response_batch_list() -> None:
    resp = translate_embeddings_response([{"embedding": [1.0]}, {"embedding": [2.0]}])
    assert resp == {"embeddings": [[1.0], [2.0]]}


def _fake_resolved_model() -> ResolvedModel:
    return ResolvedModel(
        sha256="a" * 64,
        blob_path=Path("/blobs/a.gguf"),
        metadata={"name": "x"},
        provenance=Provenance(kind=ProvenanceKind.HUGGINGFACE, origin="acme/x", sha256="a" * 64),
    )


def test_iter_pull_progress_success_sequence() -> None:
    resolved = _fake_resolved_model()
    lines = list(iter_pull_progress(lambda: resolved))
    statuses = [json.loads(line)["status"] for line in lines]
    assert statuses == ["pulling manifest", "verifying sha256 digest", "writing manifest", "success"]
    assert json.loads(lines[-1])["digest"] == "a" * 64


def test_iter_pull_progress_surfaces_error_and_reraises() -> None:
    def _boom():
        raise RuntimeError("network unreachable")

    gen = iter_pull_progress(_boom)
    first = json.loads(next(gen))
    assert first["status"] == "pulling manifest"

    second = json.loads(next(gen))
    assert second["status"] == "error"
    assert "network unreachable" in second["error"]

    # the underlying exception still propagates once the generator resumes
    # past the error-status yield — callers (e.g. FastAPI's StreamingResponse
    # iterating this generator) see BOTH the client-visible error status
    # AND the real exception (for server-side logging/alerting), never a
    # silently-swallowed failure.
    with pytest.raises(RuntimeError, match="network unreachable"):
        next(gen)
