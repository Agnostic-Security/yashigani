"""
Yashigani Backoffice — Model & Alias management routes.

# Last updated: 2026-05-02T09:00:00+01:00

CRUD for model aliases and model allocation to users/groups/orgs.
  GET     /admin/models                  — List all model aliases
  POST    /admin/models                  — Create a model alias (step-up required)
  DELETE  /admin/models/{alias}          — Delete a model alias (step-up required)
  GET     /admin/models/available        — List models from Ollama
  GET     /admin/models/allocations      — List all model allocations
  POST    /admin/models/allocations      — Allocate a model to user/group/org (step-up required)
  DELETE  /admin/models/allocations/{id} — Remove an allocation (step-up required)

LF-STEPUP-AGENT-CREATE (2026-04-27): mutation endpoints now require step-up auth.
Model alias and allocation changes affect routing policy and sensitivity ceilings.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.models.alias_store import ModelAlias

logger = logging.getLogger(__name__)

router = APIRouter()


# ── In-memory fallback for allocations ────────────────────────────────────
# Allocations are not yet Redis-backed; that is a separate future task.

_allocations: list[dict] = []
_alloc_counter = 0


# ── Request / Response models ─────────────────────────────────────────────

class AliasRequest(BaseModel):
    alias: str = Field(min_length=1, max_length=64)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    force_local: bool = False
    sensitivity_ceiling: Optional[str] = None


class AllocationRequest(BaseModel):
    model_alias: str = Field(min_length=1)
    target_type: str = Field(pattern=r"^(user|group|org)$")
    target_id: str = Field(min_length=1)


# ── Internal helper ───────────────────────────────────────────────────────

def _alias_store():
    """
    Return the ModelAliasStore from backoffice state.

    Raises HTTP 503 if the store was not initialised (Redis unavailable at
    boot). This surfaces a clear error rather than silently returning stale
    in-memory data.
    """
    store = backoffice_state.model_alias_store
    if store is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "alias_store_unavailable", "detail": "Redis not connected"},
        )
    return store


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("")
async def list_aliases(session: AdminSession):
    aliases = _alias_store().list_all()
    return {"aliases": [v.to_dict() for v in aliases.values()]}


@router.post("", status_code=201)
async def create_alias(body: AliasRequest, session: StepUpAdminSession):
    store = _alias_store()
    if store.get(body.alias) is not None:
        raise HTTPException(status_code=409, detail={"error": "alias_exists"})
    config = ModelAlias(
        alias=body.alias,
        provider=body.provider,
        model=body.model,
        force_local=body.force_local,
        sensitivity_ceiling=body.sensitivity_ceiling,
    )
    store.set(body.alias, config)
    return {"status": "ok", "alias": body.alias}


@router.delete("/{alias}")
async def delete_alias(alias: str, session: StepUpAdminSession):
    store = _alias_store()
    deleted = store.delete(alias)
    if not deleted:
        raise HTTPException(status_code=404, detail={"error": "alias_not_found"})
    return {"status": "ok"}


@router.get("/available")
async def list_available_models(session: AdminSession):
    """List models available from Ollama."""
    pipeline = backoffice_state.inspection_pipeline
    if pipeline is None:
        return {"models": []}
    try:
        import httpx
        ollama_url = getattr(pipeline, '_classifier', None)
        base_url = "http://ollama:11434"
        if ollama_url and hasattr(ollama_url, '_ollama_base_url'):
            base_url = ollama_url._ollama_base_url
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                return {"models": data.get("models", [])}
    except Exception as exc:
        logger.warning("Failed to list Ollama models: %s", exc)
    return {"models": []}


class PullModelRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


def _ollama_base() -> str:
    return (os.getenv("YASHIGANI_OLLAMA_URL") or os.getenv("OLLAMA_BASE_URL")
            or "http://ollama:11434").rstrip("/")


@router.post("/pull", status_code=202)
async def pull_model(body: PullModelRequest, session: StepUpAdminSession):
    """#25: pull an Ollama model into the local model store (operational complement
    to GET /available). Step-up gated. Consumes Ollama's NDJSON pull stream to
    completion and returns the final status; fail-closed on any error/unreachable."""
    import httpx
    import json as _json
    name = body.name.strip()
    base = _ollama_base()
    last: dict = {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0)) as client:
            async with client.stream("POST", base + "/api/pull",
                                     json={"name": name, "stream": True}) as resp:
                if resp.status_code != 200:
                    raise HTTPException(status_code=502,
                                        detail={"error": "pull_failed", "status": resp.status_code})
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        last = _json.loads(line)
                    except Exception:
                        continue
                    if last.get("error"):
                        raise HTTPException(status_code=502,
                                            detail={"error": "pull_error", "message": last["error"]})
    except httpx.HTTPError as exc:
        logger.warning("model pull failed for %s: %s", name, exc)
        raise HTTPException(status_code=503,
                            detail={"error": "ollama_unreachable", "message": "Could not reach Ollama."})
    logger.info("Admin %s pulled model %s (status=%s)", session.account_id, name, last.get("status"))
    return {"status": "ok", "model": name, "ollama_status": last.get("status", "success")}


@router.get("/allocations")
async def list_allocations(session: AdminSession):
    return {"allocations": _allocations}


@router.post("/allocations", status_code=201)
async def create_allocation(body: AllocationRequest, session: StepUpAdminSession):
    global _alloc_counter
    store = _alias_store()
    if store.get(body.model_alias) is None:
        raise HTTPException(status_code=404, detail={"error": "alias_not_found"})
    _alloc_counter += 1
    alloc = {
        "id": str(_alloc_counter),
        "model_alias": body.model_alias,
        "target_type": body.target_type,
        "target_id": body.target_id,
    }
    _allocations.append(alloc)
    return {"status": "ok", "allocation": alloc}


@router.delete("/allocations/{alloc_id}")
async def delete_allocation(alloc_id: str, session: StepUpAdminSession):
    global _allocations
    before = len(_allocations)
    _allocations = [a for a in _allocations if a["id"] != alloc_id]
    if len(_allocations) == before:
        raise HTTPException(status_code=404, detail={"error": "allocation_not_found"})
    return {"status": "ok"}
