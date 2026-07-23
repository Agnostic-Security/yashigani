# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Integration tests for the FastAPI app wiring (`app.py`). Uses FastAPI's
TestClient (in-process, no real sockets) with every network/process boundary
faked — no live ollama, no llama-server binary, no network."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeProcessRunner, FakeUpstreamClient
from yashigani_infer.app import create_app
from yashigani_infer.blobstore.store import BlobStore
from yashigani_infer.models import Provenance, ProvenanceKind, ResolvedModel
from yashigani_infer.shim.framing import format_sse_event
from yashigani_infer.supervisor.supervisor import LoadConfig, ResourceLimits, Supervisor


@pytest.fixture()
def ingested_model(tmp_blob_store: BlobStore, tmp_path, minimal_gguf_bytes: bytes) -> ResolvedModel:
    src = tmp_path / "model.gguf"
    src.write_bytes(minimal_gguf_bytes)
    provenance = Provenance(kind=ProvenanceKind.LOCAL_FILE, origin=str(src), sha256="")
    return tmp_blob_store.put_from_path(
        src, metadata={"name": "llama3:8b", "family": "llama", "quantization_level": "Q4_K_M"}, provenance=provenance
    )


def _build_app(tmp_blob_store, *, sse_lines=None, json_response=None, resource_limits=None, pull_resolver=None):
    supervisor = Supervisor(process_runner=FakeProcessRunner(), resource_limits=resource_limits or ResourceLimits())
    upstream = FakeUpstreamClient(sse_lines=sse_lines or [], json_response=json_response or {})
    app = create_app(blob_store=tmp_blob_store, supervisor=supervisor, upstream=upstream, pull_resolver=pull_resolver)
    return app, supervisor, upstream


def test_healthz_reports_ok_with_no_residents(tmp_blob_store: BlobStore) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "resident_models": []}


def test_healthz_returns_200_when_gpu_expected_and_engaged(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    """Iris integration-seam audit F2: a GPU-tagged deployment that really
    offloaded layers must still report Ready — the fix must not turn every
    GPU deployment unhealthy, only a silent CPU fallback."""
    app, supervisor, _upstream = _build_app(tmp_blob_store)
    supervisor.load(ingested_model, LoadConfig(n_gpu_layers=32, expect_gpu=True))
    client = TestClient(app)

    resp = client.get("/healthz")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["resident_models"][0]["gpu_engaged"] is True


def test_healthz_returns_non_200_when_gpu_expected_but_zero_layers_offloaded(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    """Iris integration-seam audit F2 / Red-Council #6: `/healthz` used to
    always return HTTP 200 regardless of the nested per-model health, so a
    GPU-tagged deployment silently falling back to CPU (0 offloaded layers)
    reported Ready forever to any probe that only checks the status code.
    This must now hard-fail the whole container, not just nest a warning."""
    app, supervisor, _upstream = _build_app(tmp_blob_store)
    supervisor.load(ingested_model, LoadConfig(n_gpu_layers=0, expect_gpu=True))
    client = TestClient(app)

    resp = client.get("/healthz")

    assert resp.status_code != 200
    body = resp.json()
    assert body["status"] == "unhealthy"
    assert body["resident_models"][0]["gpu_engaged"] is False


def test_healthz_stays_200_for_a_cpu_only_deployment_without_gpu_expectation(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    app, supervisor, _upstream = _build_app(tmp_blob_store)
    supervisor.load(ingested_model, LoadConfig(n_gpu_layers=0, expect_gpu=False))
    client = TestClient(app)

    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_tags_lists_ingested_models(tmp_blob_store: BlobStore, ingested_model: ResolvedModel) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.get("/api/tags")
    assert resp.status_code == 200
    names = [m["name"] for m in resp.json()["models"]]
    assert "llama3:8b" in names


def test_api_show_returns_404_for_unknown_model(tmp_blob_store: BlobStore) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.post("/api/show", json={"name": "does-not-exist"})
    assert resp.status_code == 404


def test_api_show_returns_model_details(tmp_blob_store: BlobStore, ingested_model: ResolvedModel) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.post("/api/show", json={"name": "llama3:8b"})
    assert resp.status_code == 200
    assert resp.json()["details"]["family"] == "llama"


def test_api_chat_streams_ndjson_and_spawns_the_process(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    sse_lines = (
        format_sse_event({"content": "Hi", "stop": False})
        + format_sse_event({"content": "", "stop": True, "timings": {"predicted_ms": 5}})
    ).splitlines()
    app, supervisor, upstream = _build_app(tmp_blob_store, sse_lines=sse_lines)
    client = TestClient(app)

    resp = client.post("/api/chat", json={"model": "llama3:8b", "messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 200
    lines = [line for line in resp.text.splitlines() if line]
    assert len(lines) == 2
    assert json.loads(lines[0])["message"]["content"] == "Hi"
    assert json.loads(lines[1])["done"] is True
    assert supervisor.is_loaded(ingested_model.sha256)
    assert upstream.requested_bodies[0]["messages"] == [{"role": "user", "content": "hi"}]
    # slot released after the stream fully drains
    assert supervisor.inflight_count(ingested_model.sha256) == 0


def test_api_chat_returns_404_for_unknown_model(tmp_blob_store: BlobStore) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.post("/api/chat", json={"model": "nope", "messages": []})
    assert resp.status_code == 404


def test_api_chat_returns_429_when_concurrency_ceiling_already_reached(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    app, supervisor, _upstream = _build_app(tmp_blob_store, resource_limits=ResourceLimits(max_concurrent_requests=1))
    client = TestClient(app)
    supervisor.acquire_request_slot(ingested_model.sha256)  # saturate the ceiling directly

    resp = client.post("/api/chat", json={"model": "llama3:8b", "messages": []})
    assert resp.status_code == 429


def test_api_embeddings_translates_and_calls_upstream(tmp_blob_store: BlobStore, ingested_model: ResolvedModel) -> None:
    app, supervisor, upstream = _build_app(tmp_blob_store, json_response={"embedding": [0.1, 0.2]})
    client = TestClient(app)

    resp = client.post("/api/embeddings", json={"model": "llama3:8b", "prompt": "hello"})
    assert resp.status_code == 200
    assert resp.json() == {"embedding": [0.1, 0.2]}
    assert upstream.requested_bodies[0] == {"content": "hello"}
    assert supervisor.inflight_count(ingested_model.sha256) == 0


def test_api_pull_returns_501_without_a_configured_resolver(tmp_blob_store: BlobStore) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.post("/api/pull", json={"repo_id": "acme/x"})
    assert resp.status_code == 501


def test_api_pull_streams_progress_when_resolver_configured(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    def _resolver(_body):
        return ingested_model

    app, _supervisor, _upstream = _build_app(tmp_blob_store, pull_resolver=_resolver)
    client = TestClient(app)
    resp = client.post("/api/pull", json={"repo_id": "acme/x"})
    assert resp.status_code == 200
    statuses = [json.loads(line)["status"] for line in resp.text.splitlines() if line]
    assert statuses[-1] == "success"


def test_v1_passthrough_requires_model_field_with_zero_resident(tmp_blob_store: BlobStore) -> None:
    app, _supervisor, _upstream = _build_app(tmp_blob_store)
    client = TestClient(app)
    resp = client.post("/v1/chat/completions", json={"messages": []})
    assert resp.status_code == 400


def test_v1_passthrough_non_streaming_with_explicit_model(
    tmp_blob_store: BlobStore, ingested_model: ResolvedModel
) -> None:
    app, supervisor, upstream = _build_app(tmp_blob_store, json_response={"choices": [{"message": {"content": "hi"}}]})
    client = TestClient(app)
    resp = client.post("/v1/chat/completions", json={"model": "llama3:8b", "messages": []})
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == "hi"
    assert supervisor.inflight_count(ingested_model.sha256) == 0
