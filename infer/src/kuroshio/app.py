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

import asyncio
import contextlib

import httpx
from typing import Any, AsyncIterator, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from kuroshio.blobstore.store import BlobStore
from kuroshio.containment.hooks import OutputInspectionHook, noop_output_inspection_hook
from kuroshio.models import ResolvedModel
from kuroshio.shim.chat import chat_event_to_ndjson, translate_chat_request
from kuroshio.shim.embeddings import (
    translate_embed_response,
    translate_embeddings_request,
    translate_embeddings_response,
)
from kuroshio.shim.framing import parse_sse_line
from kuroshio.shim.generate import generate_event_to_ndjson, translate_generate_request
from kuroshio.shim.ps import PsRow, synthesize_ps
from kuroshio.shim.pull import iter_pull_progress
from kuroshio.shim.show import synthesize_show
from kuroshio.shim.tags import synthesize_tags
from kuroshio.supervisor.supervisor import LoadConfig, ResourceLimitExceeded, Supervisor
from kuroshio.upstream import UpstreamClient


async def _idle_sweep_loop(supervisor: Supervisor, interval_seconds: float) -> None:
    """Drive `Supervisor.idle_unload_sweep()` on a timer (YSG-RISK-300).

    The sweep is synchronous and cheap — it walks the resident dict and
    terminates handles — so it runs inline rather than in an executor. A
    failure must not kill the task and silently stop all future sweeps, so
    exceptions are swallowed per-iteration and the loop continues; the next
    tick retries. Cancellation propagates so shutdown is prompt.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            supervisor.idle_unload_sweep()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed sweep must not stop later sweeps
            continue


def create_app(
    *,
    blob_store: BlobStore,
    supervisor: Supervisor,
    upstream: UpstreamClient,
    default_load_config: LoadConfig | None = None,
    pull_resolver: Callable[[dict[str, Any]], ResolvedModel] | None = None,
    output_inspection_hook: OutputInspectionHook = noop_output_inspection_hook,
    idle_sweep_interval_seconds: float | None = 60.0,
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
        idle_sweep_interval_seconds: how often the background task calls
            `Supervisor.idle_unload_sweep()`. `None` disables the task (the
            unit suite does that so no real timer runs); the default wires it.
    """

    @contextlib.asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # YSG-RISK-300: `idle_unload_sweep()` had ZERO callers anywhere in the
        # tree, so `YSG_KUROSHIO_IDLE_UNLOAD_SECONDS` configured nothing and no
        # model was ever idle-unloaded on any platform. The function was covered
        # by unit tests in isolation, which is exactly why it went unnoticed —
        # the wiring was never tested, only the body.
        sweeper: asyncio.Task[None] | None = None
        if idle_sweep_interval_seconds is not None:
            sweeper = asyncio.create_task(_idle_sweep_loop(supervisor, idle_sweep_interval_seconds))
        try:
            yield
        finally:
            # YSG-RISK-299: nothing unloaded resident instances on shutdown, so
            # every `llama-server` child outlived its supervisor. A container
            # tears the whole process tree down and hides this; launchd
            # reparents the orphan to init and it keeps running, holding a Metal
            # context and a port (compounding YSG-RISK-298).
            #
            # This covers graceful stop — SIGTERM, `launchctl stop`, `docker
            # stop`. It CANNOT cover SIGKILL: no hook runs, in any language, on
            # any platform. The guarantee for that case has to be a
            # next-startup orphan sweep, which needs a process marker the
            # supervisor injects at spawn — filed separately, not smuggled in
            # here.
            if sweeper is not None:
                sweeper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await sweeper
            for sha in supervisor.resident_shas:
                supervisor.unload(sha)
            # YSG-RISK-296: release the pooled upstream client if this one owns
            # connections. Duck-typed on purpose — `UpstreamClient` is a narrow
            # Protocol and test fakes do not implement `aclose`.
            closer = getattr(upstream, "aclose", None)
            if closer is not None:
                await closer()

    app = FastAPI(title="yashigani-kuroshio", version="0.1.0", lifespan=_lifespan)
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

    # YSG-RISK-290. `Supervisor.load()` is synchronous and does genuinely
    # blocking work: the wired `HttpReadinessProbe` polls llama-server's
    # `/health` in a `time.sleep` loop for up to 60s, and a configured
    # `ProvenanceVerifier` re-hashes the blob from disk. Called directly from
    # an `async def` handler — as every route did — that blocks the whole event
    # loop, so one cold model load froze every other in-flight request across
    # every tenant, `/healthz` included. Supervisor state is in-memory, so the
    # process cannot be sharded across uvicorn workers to dilute it.
    #
    # `load()` stays synchronous (its own tests and API are sync) and is
    # offloaded to a worker thread instead. The lock is what makes that safe:
    # `Supervisor`'s `_instances`/`_inflight` dicts have no internal locking
    # and were previously protected only by everything running on the single
    # event-loop thread. Holding an asyncio.Lock means at most one thread is
    # ever inside `load()`, preserving that invariant without touching
    # Supervisor.
    #
    # One lock, not one per model: a cold load of model B still waits behind a
    # cold load of model A, exactly as before. What changes — and what the
    # defect was — is that the event loop is now free throughout, so resident
    # traffic and health probes are served. Per-model locking is a throughput
    # refinement, not part of this fix.
    load_lock = asyncio.Lock()

    async def _ensure_loaded(model: ResolvedModel):
        async with load_lock:
            return await asyncio.to_thread(supervisor.load, model, load_config)

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

    def _resident_display_name(sha256: str) -> str:
        """Best-effort human-readable name for a resident model, for use in the
        ambiguous-`/v1/*` error message. Falls back to the digest if the model
        metadata can't be reconstructed (never raises — this only builds a
        diagnostic string)."""
        model = blob_store.get_resolved_model(sha256)
        if model is None:
            return sha256
        return str(model.metadata.get("name") or sha256)

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
        instance = await _ensure_loaded(model)
        llama_request = translate_chat_request(body, cache_prompt=load_config.cache_prompt)
        _clamp_request_params(llama_request)
        model_name = body.get("model", "")

        _acquire_slot_or_429(model.sha256)

        async def event_stream() -> AsyncIterator[bytes]:
            try:
                async for raw_line in upstream.stream_lines(f"{_base_url(instance.port)}/completion", llama_request):
                    parsed = parse_sse_line(raw_line)
                    if not isinstance(parsed, dict):
                        continue  # blank separator or terminal [DONE] — no event on this line
                    event = output_inspection_hook(parsed)
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
        instance = await _ensure_loaded(model)
        llama_request = translate_generate_request(body, cache_prompt=load_config.cache_prompt)
        _clamp_request_params(llama_request)
        model_name = body.get("model", "")

        _acquire_slot_or_429(model.sha256)

        async def event_stream() -> AsyncIterator[bytes]:
            try:
                async for raw_line in upstream.stream_lines(f"{_base_url(instance.port)}/completion", llama_request):
                    parsed = parse_sse_line(raw_line)
                    if not isinstance(parsed, dict):
                        continue  # blank separator or terminal [DONE] — no event on this line
                    event = output_inspection_hook(parsed)
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
        instance = await _ensure_loaded(model)
        llama_request = translate_embeddings_request(body)

        _acquire_slot_or_429(model.sha256)
        try:
            llama_response = await upstream.request_json(f"{_base_url(instance.port)}/embedding", llama_request)
        finally:
            supervisor.release_request_slot(model.sha256)
        supervisor.touch(model.sha256)
        return translate_embeddings_response(llama_response)

    @app.post("/api/embed")
    async def api_embed(request: Request) -> dict[str, Any]:
        """Newer ollama embeddings endpoint (>= 0.5.x) — YSG-RISK-289.

        This route was missing entirely, and it is the one the Yashigani
        gateway actually calls (`openai_router.py`: POST `/api/embed` with
        `{model, input}`). Without it, repointing `OLLAMA_BASE_URL` at this
        shim 404s here and surfaces as 502 to every `/v1/embeddings` caller —
        which the gateway's own comment predicted. `/api/embeddings` stays for
        legacy callers; the two differ only in response shape.
        """
        body = await request.json()
        model = _require_model(body.get("model", ""))
        instance = await _ensure_loaded(model)
        llama_request = translate_embeddings_request(body)

        _acquire_slot_or_429(model.sha256)
        try:
            llama_response = await upstream.request_json(f"{_base_url(instance.port)}/embedding", llama_request)
        finally:
            supervisor.release_request_slot(model.sha256)
        supervisor.touch(model.sha256)
        return translate_embed_response(llama_response, model=body.get("model", ""))

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

        Model resolution (Red-Council Ava F4, 2026-07-29 design-review): the
        passthrough must know which resident llama-server instance to target.
        The rule is deterministic and fail-closed:

          1. If the request body names a `model`, that model is resolved and
             used (the normal, unambiguous case — an OpenAI-compat client
             ALWAYS sends `model`).
          2. Otherwise, auto-selection applies ONLY when EXACTLY ONE model is
             resident (the trivial single-model dev/test box).
          3. With ZERO or MORE-THAN-ONE resident and no `model` field, the
             request is REJECTED with an explicit 400 — never silently routed
             to an arbitrary resident.

        Case 3 is the realistic gated deploy: a classifier + a chat model are
        BOTH resident, so "no model -> use the single resident" is ambiguous
        and unsafe. The engine has no notion of a "default chat role" to
        disambiguate on the caller's behalf (roles live one layer up, in the
        per-container split), so guessing would risk routing a chat request to
        the classifier (or vice-versa). Requiring an explicit `model` is the
        safe, unambiguous behaviour; the error message says exactly that.
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
            instance = await _ensure_loaded(model)
        else:
            resident = supervisor.resident_shas
            if len(resident) == 0:
                raise HTTPException(
                    status_code=400,
                    detail="/v1/* passthrough requires an explicit 'model' field: no model is resident to auto-select",
                )
            if len(resident) > 1:
                # Realistic gated deploy (classifier + chat both resident):
                # auto-selection is ambiguous, so fail closed rather than route
                # to an arbitrary resident (Red-Council Ava F4).
                resident_names = sorted(_resident_display_name(sha) for sha in resident)
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "/v1/* passthrough requires an explicit 'model' field: "
                        f"{len(resident)} models are resident ({', '.join(resident_names)}) — "
                        "auto-selection only applies when exactly one model is resident"
                    ),
                )
            instance = supervisor.get_instance(resident[0])
            if instance is None:  # pragma: no cover - defensive, resident_shas guarantees presence
                raise HTTPException(status_code=500, detail="resident model instance vanished mid-request")
            resolved_for_chat_guard = blob_store.get_resolved_model(instance.sha256)
            if path == "chat/completions" and resolved_for_chat_guard is not None:
                _require_chat_template(resolved_for_chat_guard)

        # Path-traversal guard. `target_url` is built by interpolation, and
        # httpx.URL NORMALISES `../` — measured:
        #
        #   path="../slots/0"     -> http://host/slots/0        (escapes /v1/)
        #   path="../../slots/0"  -> http://host/slots/0        (escapes /v1/)
        #   path="..%2fslots%2f0" -> http://host/v1/..%2fslots%2f0  (contained)
        #
        # So a caller can walk out of /v1/ and reach llama-server's own control
        # endpoints. Today that is inert: we pass neither `--slots` nor
        # `--slot-save-path`, so those endpoints are off or 501. It stops being
        # inert the moment `--slot-save-path` is enabled for the per-user prompt
        # cache (YSG-RISK-315), because that flag unlocks `save` and `restore` on
        # /slots/{id} — dump one user's KV state, load it into another user's
        # slot. The guard lands BEFORE that flag, not after.
        #
        # Checked post-normalisation rather than by scanning for "..": the
        # encoded forms above are exactly why a substring check on the raw path
        # is the wrong test. Normalise first, then verify containment.
        _base = _base_url(instance.port)
        target_url = str(httpx.URL(f"{_base}/v1/{path}"))
        if not target_url.startswith(f"{_base}/v1/"):
            raise HTTPException(
                status_code=400,
                detail="invalid path: the v1 passthrough may not address anything outside /v1/",
            )
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
