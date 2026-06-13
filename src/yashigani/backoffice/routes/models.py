"""
Yashigani Backoffice — Model & Alias management routes.

# Last updated: 2026-06-13T00:00:00+01:00

CRUD for model aliases and model allocation to users/groups/orgs.
  GET     /admin/models                  — List all model aliases
  POST    /admin/models                  — Create a model alias (step-up required)
  DELETE  /admin/models/{alias}          — Delete a model alias (step-up required)
  GET     /admin/models/available        — List models from Ollama
  POST    /admin/models/pull             — Pull a model from Ollama + auto-add alias (step-up)
  GET     /admin/models/allocations      — List all model allocations
  POST    /admin/models/allocations      — Allocate a model to user/group/org (step-up required)
  DELETE  /admin/models/allocations/{id} — Remove an allocation (step-up required)

LF-STEPUP-AGENT-CREATE (2026-04-27): mutation endpoints now require step-up auth.
Model alias and allocation changes affect routing policy and sensitivity ceilings.

R1 (2.25.5): POST /admin/models/pull now auto-adds an alias for the pulled model
in a single atomic action — idempotent (no-op if the alias already exists).
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.models.alias_store import ModelAlias

logger = logging.getLogger(__name__)

router = APIRouter()


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


def _alloc_store():
    """
    Return the durable ModelAllocationStore from backoffice state.

    Raises HTTP 503 if the store was not initialised (Redis db/3 unavailable at
    boot) — fail-closed: an admin must never believe an allocation persisted
    when it only touched a transient in-memory list.
    """
    store = backoffice_state.model_allocation_store
    if store is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "allocation_store_unavailable", "detail": "Redis db/3 not connected"},
        )
    return store


def _push_allocations_to_opa() -> None:
    """Force-push the live allocation set to OPA after a mutation.

    Mirrors the RBAC force-push: the durable store is authoritative, so an OPA
    push failure is logged but does NOT fail the mutation (the allocation is
    already persisted and will re-sync on the next mutation or on startup
    reconcile). The gateway computes effective-allowed-models from the same
    durable store on the request path, so enforcement is correct even if this
    informational push is briefly stale.
    """
    store = backoffice_state.model_allocation_store
    opa_url = backoffice_state.opa_url
    if store is None or not opa_url:
        return
    try:
        from yashigani.models.opa_push import push_allocations_data
        push_allocations_data(store, opa_url)
    except Exception as exc:  # non-fatal — store remains authoritative
        logger.warning("Allocation OPA push failed (%s) — store remains authoritative", exc)


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


def _model_name_to_alias(name: str) -> str:
    """Derive a safe alias name from a model name string.

    Ollama model names look like 'llama3:8b', 'qwen2.5:3b', 'gemma3:4b', etc.
    The alias is lowercased and non-alphanumeric characters (except '-' and '_')
    are replaced with '-' so they fit the alias field pattern.
    Truncated to 64 chars (alias max_length).

    Examples:
      'llama3:8b'       -> 'llama3-8b'
      'qwen2.5-coder:7b'-> 'qwen2-5-coder-7b'
      'my/model:latest' -> 'my-model-latest'
    """
    import re
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower())
    # Collapse consecutive dashes
    safe = re.sub(r"-{2,}", "-", safe).strip("-")
    return safe[:64] or "model"


@router.post("/pull", status_code=202)
async def pull_model(body: PullModelRequest, session: StepUpAdminSession):
    """R1 (2.25.5): pull an Ollama model and auto-add it to the available-models alias
    list in a single action.

    Behaviour:
    - Streams Ollama's NDJSON pull to completion (fail-closed on error/unreachable).
    - On success, upserts an alias in ModelAliasStore for the pulled model so it
      immediately appears in GET /admin/models without a separate create step.
    - Idempotent: if an alias for this model name already exists, it is left unchanged
      (alias_created=False in the response).
    - If the alias store is unavailable, the pull still succeeds — alias_created=False
      is returned and a warning is logged (non-fatal; operator can create alias manually).

    Step-up gated (#25 / LF-STEPUP-AGENT-CREATE).
    """
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

    # R1: auto-add alias — idempotent (skip if already registered)
    alias_name = _model_name_to_alias(name)
    alias_created = False
    alias_existed = False
    try:
        store = _alias_store()
        if store.get(alias_name) is not None:
            alias_existed = True
            logger.debug("pull_model: alias %r already exists for %s — skipping create", alias_name, name)
        else:
            store.set(alias_name, ModelAlias(
                alias=alias_name,
                provider="ollama",
                model=name,
                force_local=True,
            ))
            alias_created = True
            logger.info("pull_model: auto-created alias %r for %s (admin=%s)", alias_name, name, session.account_id)
    except HTTPException:
        # Alias store unavailable (503) — pull succeeded, alias deferred.
        logger.warning("pull_model: alias store unavailable after pull of %s — alias not created", name)
    except Exception as exc:
        logger.warning("pull_model: alias auto-create failed for %s: %s — alias not created", name, exc)

    return {
        "status": "ok",
        "model": name,
        "ollama_status": last.get("status", "success"),
        "alias": alias_name,
        "alias_created": alias_created,
        "alias_existed": alias_existed,
    }


def _is_admin_group(group: dict) -> bool:
    """R4: a group is 'admin-related' (excluded from allocation targets) if
    'admin' appears in its id or display_name (case-insensitive)."""
    hay = (str(group.get("id", "")) + " " + str(group.get("display_name", ""))).lower()
    return "admin" in hay


@router.get("/allocation-targets")
async def list_allocation_targets(target_type: str, session: AdminSession):
    """R4 (2.25.5): context-dependent dropdown source for Model Allocations.

      target_type=user  -> all NON-admin user accounts (identity_id = email/username)
      target_type=org   -> registered orgs (org_ids that have a budget cap, + 'default')
      target_type=group -> all groups EXCEPT admin-related groups

    Filtering is done server-side so the 'non-admin' / 'except admin groups'
    rules are enforced + unit-testable in one place. Admin-session gated (read).
    """
    tt = (target_type or "").strip().lower()
    if tt not in ("user", "group", "org"):
        raise HTTPException(status_code=400, detail={"error": "invalid_target_type"})

    state = backoffice_state

    if tt == "user":
        if state.auth_service is None:
            return {"target_type": tt, "targets": []}
        accounts = await state.auth_service.list_accounts()
        targets = [
            {"id": (getattr(r, "email", None) or r.username), "label": r.username}
            for r in accounts
            if r.account_tier == "user"
        ]
        return {"target_type": tt, "targets": targets}

    if tt == "group":
        store = state.rbac_store
        if store is None:
            return {"target_type": tt, "targets": []}
        targets = []
        for g in store.list_groups():
            gd = {"id": g.id, "display_name": g.display_name}
            if _is_admin_group(gd):
                continue
            targets.append({"id": g.id, "label": g.display_name})
        return {"target_type": tt, "targets": targets}

    # org — sourced from the org_ids that have a budget cap (the only place orgs
    # are 'registered'), plus the implicit 'default' org. Deduped, sorted.
    org_ids = {"default"}
    try:
        from yashigani.backoffice.routes import budget as _budget_routes
        bstate = getattr(_budget_routes, "_state", None)
        bstore = getattr(bstate, "budget_store", None) if bstate else None
        if bstore is not None:
            caps = await bstore.get_org_caps("00000000-0000-0000-0000-000000000000")
            for c in caps:
                oid = c.get("org_id")
                if oid:
                    org_ids.add(str(oid))
    except Exception as exc:
        logger.warning("allocation-targets org lookup failed: %s", exc)
    targets = [{"id": o, "label": o} for o in sorted(org_ids)]
    return {"target_type": tt, "targets": targets}


@router.get("/allocations")
async def list_allocations(session: AdminSession):
    store = _alloc_store()
    return {"allocations": [a.to_dict() for a in store.list_all()]}


@router.post("/allocations", status_code=201)
async def create_allocation(body: AllocationRequest, session: StepUpAdminSession):
    alias_store = _alias_store()
    if alias_store.get(body.model_alias) is None:
        raise HTTPException(status_code=404, detail={"error": "alias_not_found"})
    store = _alloc_store()
    try:
        alloc = store.add(body.model_alias, body.target_type, body.target_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_allocation", "detail": str(exc)})
    _push_allocations_to_opa()
    logger.info(
        "Admin %s allocated model %s to %s:%s (id=%s)",
        session.account_id, body.model_alias, body.target_type, body.target_id, alloc.id,
    )
    return {"status": "ok", "allocation": alloc.to_dict()}


@router.delete("/allocations/{alloc_id}")
async def delete_allocation(alloc_id: str, session: StepUpAdminSession):
    store = _alloc_store()
    if not store.delete(alloc_id):
        raise HTTPException(status_code=404, detail={"error": "allocation_not_found"})
    _push_allocations_to_opa()
    logger.info("Admin %s removed allocation %s", session.account_id, alloc_id)
    return {"status": "ok"}
