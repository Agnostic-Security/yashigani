# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""HTTP app — wires `/api/*` (ollama shim) + `/v1/*` (OpenAI-compat passthrough)
to the supervisor + blob store.

**NO AUTH OF ITS OWN.** Caddy is the sole auth perimeter (platform-
requirements doc §13 invariant #1 — `mtls_capable:false`). Do not add auth
middleware to this app; enforcement lives in the Caddy front
(`Caddyfile.kuroshio-front`), not here.

This is a v1 foundation skeleton: routes are wired and functionally
correct against the shim's translation layer, but two things are
deliberately NOT implemented yet (both flagged inline below, not silently
dropped): `/api/pull` requires an injected resolver to do anything, and the
`/v1/*` passthrough's model-selection is minimal (explicit `model` field or
"exactly one resident model").
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from kuroshio.blobstore.store import BlobStore
from kuroshio.containment.hooks import OutputInspectionHook, noop_output_inspection_hook
from kuroshio.models import ResolvedModel
from kuroshio.shim.chat import chat_event_to_ndjson, translate_chat_request
from kuroshio.shim.embeddings import translate_embeddings_request, translate_embeddings_response
from kuroshio.shim.framing import SSE_DONE_SENTINEL
from kuroshio.shim.generate import generate_event_to_ndjson, translate_generate_request
from kuroshio.shim.ps import PsRow, synthesize_ps
from kuroshio.shim.pull import iter_pull_progress
from kuroshio.shim.show import synthesize_show
from kuroshio.shim.tags import synthesize_tags
from kuroshio.supervisor.supervisor import LoadConfig, ResourceLimitExceeded, Supervisor
from kuroshio.upstream import UpstreamClient


def _parse_sse_line(raw_line: str) -> dict[str, Any] | None:
    line = raw_line.rstrip("\r\n")
    if not line or not line.startswith("data:"):
        return None
    payload = line[len("data:") :].strip()
    if payload == SSE_DONE_SENTINEL:
        return None
    return json.loads(payload)


def create_app(
    *,
    blob_store: BlobStore,
    supervisor: Supervisor,
    upstream: UpstreamClient,
    default_load_config: LoadConfig | None = None,
    pull_resolver: Callable[[dict[str, Any]], ResolvedModel] | None = None,
    output_inspection_hook: OutputInspectionHook = noop_output_inspection_hook,
) -> FastAPI:
    """Build the yashigani-kuroshio HTTP app.

    Args:
        blob_store: content-addressed GGUF store (model lookup by name/digest).
        supervisor: llama-server process lifecycle supervisor.
        upstream: injectable HTTP client used to reach a resident model's
            llama-server instance (real deploys use `HttpxUpstreamClient`;
            tests inject a fake).
        default_load_config: `LoadConfig` applied when a route auto-loads a
            model that is not yet resident. A real deploy will want
            per-model config resolution (GPU layers, MoE offload rules) —
            out of scope for this foundation; every route uses one config.
        pull_resolver: optional callable turning an `/api/pull` request body
            into a `ResolvedModel` (e.g. wired to `HuggingFaceAdapter.resolve`
            by the caller). If `None`, `/api/pull` responds 501 — no source
            adapter is wired by default, matching "commodity control plane
            only" (no adapter is force-enabled without the deploy explicitly
            wiring one).
        output_inspection_hook: containment seam (see `containment/hooks.py`)
            — a no-op identity passthrough in this package.
    """
    app = FastAPI(title="yashigani-kuroshio", version="0.1.0")
    app.state.blob_store = blob_store
    app.state.supervisor = supervisor
    app.state.upstream = upstream
    load_config = default_load_config or LoadConfig()

    def _base_url(port: int) -> str:
        return f"http://127.0.0.1:{port}"

    def _require_model(name: str) -> ResolvedModel:
        if not name:
            raise HTTPException(status_code=400, detail="request body missing 'model'")
        model = blob_store.find_by_name(name)
        if model is None:
            raise HTTPException(status_code=404, detail=f"model not found: {name}")
        return model

    def _ensure_loaded(model: ResolvedModel):
        return supervisor.load(model, load_config)

    def _require_chat_template(model: ResolvedModel) -> None:
        """Red-Council H4 (Ava/Tom, 2026-07-29 design-review): a GGUF with a
        missing/blank `tokenizer.chat_template` does not error when served —
        it produces a subtly wrong or garbled completion at HTTP 200
        (llama.cpp falls back to its own built-in default, or mis-renders
        role-turns for an architecture it doesn't template-detect
        correctly). Fail closed HERE, before ever loading/forwarding to
        llama-server, rather than serving garbage with a green status code.
        Only wired on the CHAT-shaped routes (`/api/chat`, the OpenAI-compat
        `/v1/chat/completions`) — `/api/generate` and `/api/embeddings` do
        not depend on chat-templating and are unaffected.
        """
        chat_template = model.metadata.get("chat_template")
        if not chat_template or not str(chat_template).strip():
            raise HTTPException(
                status_code=422,
                detail=(
                    f"model {model.metadata.get('name', model.sha256)!r} has no extractable "
                    "tokenizer.chat_template — refusing to serve a chat request against it rather than "
                    "risk silently garbled role-turn rendering"
                ),
            )

    def _clamp_request_params(llama_request: dict[str, Any]) -> None:
        """Red-council item #7: clamp (never silently balloon) resource-shaped
        request params to the supervisor's configured ceilings."""
        if "n_ctx" in llama_request:
            llama_request["n_ctx"] = supervisor.clamp_context_length(llama_request["n_ctx"])
        if "n_predict" in llama_request:
            llama_request["n_predict"] = supervisor.clamp_max_tokens(llama_request["n_predict"])

    def _acquire_slot_or_429(sha256: str) -> None:
        try:
            supervisor.acquire_request_slot(sha256)
        except ResourceLimitExceeded as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """GPU-engaged health contract (Iris integration-seam audit F2 /
        platform-requirements §4.5 / Captain #3 / Red-Council #6).

        `supervisor.healthz()` already computes per-model `gpu_engaged` /
        `unhealthy` correctly (see `supervisor/supervisor.py`) — the gap was
        purely here: this route used to always return HTTP 200 with
        `{"status": "ok", ...}` regardless of what those nested per-model
        healths said, so a GPU-tagged deployment that silently fell back to
        CPU (0 offloaded layers) would report Ready forever to any probe
        that only checks the status code (a plain k8s `httpGet` probe,
        Docker/Podman `HEALTHCHECK`, etc).

        Fix: aggregate across every resident model. If ANY resident is
        GPU-expected but reports zero offloaded layers (or is simply not
        alive), the whole container reports unhealthy via a non-200 status
        — a single-source contract a plain `httpGet` probe can consume with
        no `exec` needed, and the existing compose `HEALTHCHECK` script can
        also key off directly.
        """
        resident_health = [supervisor.healthz(sha) for sha in supervisor.resident_shas]
        unhealthy = any(health.get("status") == "unhealthy" for health in resident_health)
        body: dict[str, Any] = {"status": "unhealthy" if unhealthy else "ok", "resident_models": resident_health}
        return JSONResponse(content=body, status_code=503 if unhealthy else 200)

    @app.get("/api/tags")
    def api_tags() -> dict[str, Any]:
        return synthesize_tags(blob_store.list_resolved_models())

    @app.post("/api/show")
    async def api_show(request: Request) -> dict[str, Any]:
        body = await request.json()
        model = _require_model(body.get("name") or body.get("model", ""))
        return synthesize_show(model)

    @app.get("/api/ps")
    def api_ps() -> dict[str, Any]:
        rows: list[PsRow] = []
        for sha in supervisor.resident_shas:
            model = blob_store.get_resolved_model(sha)
            if model is None:
                continue
            health = supervisor.healthz(sha)
            offloaded = health.get("offloaded_layers", 0)
            n_gpu_layers = offloaded if isinstance(offloaded, int) else 0
            rows.append(PsRow(model=model, n_gpu_layers=n_gpu_layers, vram_bytes=0))
        return synthesize_ps(rows)

    @app.post("/api/chat")
    async def api_chat(request: Request) -> StreamingResponse:
        body = await request.json()
        model = _require_model(body.get("model", ""))
        _require_chat_template(model)
        instance = _ensure_loaded(model)
        llama_request = translate_chat_request(body, cache_prompt=load_config.cache_prompt)
        _clamp_request_params(llama_request)
        model_name = body.get("model", "")

        _acquire_slot_or_429(model.sha256)

        async def event_stream() -> AsyncIterator[bytes]:
            try:
                async for raw_line in upstream.stream_lines(f"{_base_url(instance.port)}/completion", llama_request):
                    event = _parse_sse_line(raw_line)
                    if event is None:
                        continue
                    event = output_inspection_hook(event)
                    line, is_final = chat_event_to_ndjson(event, model_name)
                    yield line
                    if is_final:
                        supervisor.touch(model.sha256)
                        return
            finally:
                supervisor.release_request_slot(model.sha256)

        return StreamingResponse(event_stream(), media_type="application/x-ndjson")

    @app.post("/api/generate")
    async def api_generate(request: Request) -> StreamingResponse:
        body = await request.json()
        model = _require_model(body.get("model", ""))
        instance = _ensure_loaded(model)
        llama_request = translate_generate_request(body, cache_prompt=load_config.cache_prompt)
        _clamp_request_params(llama_request)
        model_name = body.get("model", "")

        _acquire_slot_or_429(model.sha256)

        async def event_stream() -> AsyncIterator[bytes]:
            try:
                async for raw_line in upstream.stream_lines(f"{_base_url(instance.port)}/completion", llama_request):
                    event = _parse_sse_line(raw_line)
                    if event is None:
                        continue
                    event = output_inspection_hook(event)
                    line, is_final = generate_event_to_ndjson(event, model_name)
                    yield line
                    if is_final:
                        supervisor.touch(model.sha256)
                        return
            finally:
                supervisor.release_request_slot(model.sha256)

        return StreamingResponse(event_stream(), media_type="application/x-ndjson")

    @app.post("/api/embeddings")
    async def api_embeddings(request: Request) -> dict[str, Any]:
        body = await request.json()
        model = _require_model(body.get("model", ""))
        instance = _ensure_loaded(model)
        llama_request = translate_embeddings_request(body)

        _acquire_slot_or_429(model.sha256)
        try:
            llama_response = await upstream.request_json(f"{_base_url(instance.port)}/embedding", llama_request)
        finally:
            supervisor.release_request_slot(model.sha256)
        supervisor.touch(model.sha256)
        return translate_embeddings_response(llama_response)

    @app.post("/api/pull")
    async def api_pull(request: Request) -> StreamingResponse:
        # Council review Medium finding (Laura F6, Lu): /api/pull must be
        # gated to an admin-only mesh identity + allowlist regardless of
        # caller. That authz check belongs at the Caddy-front / mesh-identity
        # layer (this engine has no auth of its own) — this route assumes
        # the caller has already been authorized to reach it.
        if pull_resolver is None:
            raise HTTPException(status_code=501, detail="no pull source adapter is configured for this deployment")
        body = await request.json()

        def _resolve() -> ResolvedModel:
            return pull_resolver(body)

        return StreamingResponse(iter_pull_progress(_resolve), media_type="application/x-ndjson")

    @app.api_route("/v1/{path:path}", methods=["GET", "POST"])
    async def v1_passthrough(path: str, request: Request) -> Any:
        """Thin OpenAI-compat passthrough — llama-server serves `/v1/*` natively.

        v1 foundation limitation: with multi-model residency, passthrough
        needs to know which resident instance to target. This picks the
        model named in the request body's `model` field if present,
        otherwise falls back to "exactly one model resident" — a full
        model-routing header/config scheme is a follow-up increment.
        """
        body: dict[str, Any] = {}
        model_name = None
        if request.method == "POST":
            body = await request.json()
            model_name = body.get("model")

        resolved_for_chat_guard: ResolvedModel | None = None
        if model_name:
            model = _require_model(model_name)
            resolved_for_chat_guard = model
            # H4: check BEFORE ever loading/spawning llama-server — only the
            # chat-completions shape depends on chat-templating (`/v1/completions`,
            # `/v1/embeddings`, etc. are unaffected).
            if path == "chat/completions":
                _require_chat_template(model)
            instance = _ensure_loaded(model)
        else:
            resident = supervisor.resident_shas
            if len(resident) != 1:
                raise HTTPException(
                    status_code=400,
                    detail="/v1/* passthrough requires a 'model' field when zero or multiple models are resident",
                )
            instance = supervisor.get_instance(resident[0])
            if instance is None:  # pragma: no cover - defensive, resident_shas guarantees presence
                raise HTTPException(status_code=500, detail="resident model instance vanished mid-request")
            resolved_for_chat_guard = blob_store.get_resolved_model(instance.sha256)
            if path == "chat/completions" and resolved_for_chat_guard is not None:
                _require_chat_template(resolved_for_chat_guard)

        target_url = f"{_base_url(instance.port)}/v1/{path}"
        if request.method != "POST":
            raise HTTPException(status_code=405, detail="only POST is supported by this v1 passthrough foundation")

        if "max_tokens" in body:
            body["max_tokens"] = supervisor.clamp_max_tokens(body["max_tokens"])

        _acquire_slot_or_429(instance.sha256)

        if body.get("stream"):

            async def sse_passthrough() -> AsyncIterator[bytes]:
                try:
                    async for raw_line in upstream.stream_lines(target_url, body):
                        yield (raw_line + "\n").encode("utf-8")
                finally:
                    supervisor.release_request_slot(instance.sha256)

            return StreamingResponse(sse_passthrough(), media_type="text/event-stream")

        try:
            result = await upstream.request_json(target_url, body)
        finally:
            supervisor.release_request_slot(instance.sha256)
        return JSONResponse(result)

    return app


__all__ = ["create_app"]
