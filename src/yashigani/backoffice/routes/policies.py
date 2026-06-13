"""
Yashigani Backoffice — OPA policy management API.

Surfaces the Rego policy modules currently loaded in the OPA decision service.
Extends the original read-only viewer with:

R8  — Template duplicate + custom-policy edit (Save-As with new name; PUT for edits).
R9  — Core gateway policy editable WITH confirm_danger=true guard + audit.
R10 — Policy lifecycle: draft/staging/production status + POST .../promote.
R12 — Policy dry-run/simulate: POST an admin input scenario → allow/deny + AI why.

OPA Policy API (mTLS, internal CA):
    GET  {opa_url}/v1/policies        — list all loaded modules
    GET  {opa_url}/v1/policies/{id}   — single module (raw Rego + AST)
    PUT  {opa_url}/v1/policies/{id}   — load/update a module
    POST {opa_url}/v1/data/{path}     — query a data path
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.pki.client import internal_httpx_client

router = APIRouter()
_log = logging.getLogger("yashigani.policies")

# Client policy names: lowercase, start with a letter, 2-41 chars.
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_RESERVED = {"yashigani", "rbac", "mcp", "agents", "v1_routing"}

# Core policies (load-bearing gateway policies — R9 danger guard applies to these)
_CORE_POLICY_PREFIXES = ("yashigani", "rbac", "mcp", "agents", "v1_routing")


def _opa_base() -> str:
    return os.getenv("YASHIGANI_OPA_URL", "https://policy:8181").rstrip("/")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _categorize(policy_id: str) -> str:
    """Classify a policy module by its id so the UI can group them."""
    pid = policy_id.lower()
    if "examples/" in pid:
        return "example"
    if pid.startswith("clients/") or "/clients/" in pid:
        return "client"
    if pid.endswith("_test.rego") or "/test" in pid:
        return "test"
    return "core"


# ---------------------------------------------------------------------------
# R10 — Policy lifecycle store (in-memory; draft/staging/production)
# ---------------------------------------------------------------------------
# A lightweight lifecycle envelope stored per client policy name.
# Status transitions: draft -> staging -> production (promote) or draft -> archive.
# Core policies are always "production" by definition.

_POLICY_STATUS_VALID = frozenset({"draft", "staging", "production", "archived"})


class _PolicyLifecycle:
    """Thread-safe in-memory store for policy lifecycle metadata."""

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> dict:
        with self._lock:
            return dict(self._data.get(name, {"status": "draft", "created_at": _now_iso()}))

    def set_status(self, name: str, status: str, promoted_by: str = "") -> dict:
        if status not in _POLICY_STATUS_VALID:
            raise ValueError(f"invalid status: {status!r}")
        with self._lock:
            entry = self._data.get(name, {"created_at": _now_iso()})
            entry = dict(entry)
            entry["status"] = status
            entry["updated_at"] = _now_iso()
            if promoted_by:
                entry["promoted_by"] = promoted_by
            self._data[name] = entry
            return dict(entry)

    def init_if_absent(self, name: str, status: str = "draft") -> dict:
        with self._lock:
            if name not in self._data:
                entry = {"status": status, "created_at": _now_iso()}
                self._data[name] = entry
            return dict(self._data[name])

    def list_all(self) -> list[dict]:
        with self._lock:
            return [{"name": k, **v} for k, v in self._data.items()]


_lifecycle_store = _PolicyLifecycle()


# ---------------------------------------------------------------------------
# Install-default model resolution (shared by R12 and R16)
# ---------------------------------------------------------------------------

async def _resolve_default_model(ollama_url: str) -> tuple[str, list[str]]:
    """Resolve the install-default model: prefer YASHIGANI_OPA_ASSISTANT_MODEL /
    OLLAMA_MODEL env vars; fall back to first available model from /api/tags.
    Returns (model_name, available_names)."""
    pref = os.getenv("YASHIGANI_OPA_ASSISTANT_MODEL") or os.getenv("OLLAMA_MODEL")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            tags_resp = await c.get(ollama_url + "/api/tags")
            avail = [m.get("name") for m in tags_resp.json().get("models", []) if m.get("name")]
    except Exception:
        avail = []
    model = pref if (pref and pref in avail) else (avail[0] if avail else (pref or "qwen2.5:3b"))
    return model, avail


# ---------------------------------------------------------------------------
# Existing endpoints (read-only + save/generate/bind)
# ---------------------------------------------------------------------------

@router.get("")
async def list_policies(session: AdminSession):  # noqa: ARG001 — auth gate
    """List every Rego module loaded in OPA, grouped by category."""
    url = _opa_base() + "/v1/policies"
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            result = resp.json().get("result", [])
    except httpx.HTTPError as exc:
        _log.warning("OPA list policies failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": "Could not reach the policy service."},
        )

    policies = []
    for p in result:
        pid = p.get("id", "")
        pkg = ""
        try:
            path = (p.get("ast") or {}).get("package", {}).get("path", [])
            pkg = ".".join(
                seg.get("value", "") for seg in path if isinstance(seg.get("value"), str)
            )
        except Exception:
            pkg = ""
        name = pid.rsplit("/", 1)[-1]
        if name.endswith(".rego"):
            name = name[: -len(".rego")]
        cat = _categorize(pid)
        # R10: inject lifecycle status
        if cat == "client":
            lc = _lifecycle_store.get(name)
            status = lc.get("status", "draft")
        else:
            status = "production"
        policies.append(
            {
                "id": pid,
                "name": name,
                "package": pkg,
                "category": cat,
                "lifecycle_status": status,
            }
        )
    # examples first (what operators most want to inspect), then core, then tests
    _order = {"example": 0, "core": 1, "test": 2}
    policies.sort(key=lambda x: (_order.get(x["category"], 3), x["id"]))
    return {"policies": policies, "count": len(policies), "opa_url": _opa_base()}


# #16: MUST be registered BEFORE the GET /{policy_id:path} catch-all below, or the
# catch-all matches "bindings" as a policy id and shadows this route (404).
@router.get("/bindings")
async def list_bindings(session: AdminSession):  # noqa: ARG001 — auth gate
    """List all client-policy bindings."""
    store = backoffice_state.binding_store
    if store is None:
        raise HTTPException(status_code=503, detail={"error": "binding_store_unavailable"})
    return {"bindings": [b.to_dict() for b in store.list()], "total": len(store.list())}


# R10: lifecycle status + promote — MUST precede /{policy_id:path} catch-all

@router.get("/lifecycle")
async def list_lifecycle(session: AdminSession):  # noqa: ARG001
    """R10 — List lifecycle status for all client policies tracked in the lifecycle store."""
    return {"lifecycle": _lifecycle_store.list_all()}


@router.get("/lifecycle/{name}")
async def get_lifecycle(name: str, session: AdminSession):  # noqa: ARG001
    """R10 — Get lifecycle status for a single client policy."""
    name = name.strip().lower()
    if not _NAME_RE.match(name):
        raise HTTPException(status_code=400, detail={"error": "invalid_name"})
    entry = _lifecycle_store.get(name)
    return {"name": name, **entry}


@router.post("/lifecycle/{name}/promote")
async def promote_policy(name: str, session: StepUpAdminSession):
    """R10 — Promote a client policy: draft→staging→production (step-up required).

    Transitions: draft → staging, staging → production.
    A policy must be promoted to production before it can be bound to subjects.
    """
    name = name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(status_code=400, detail={"error": "invalid_name"})
    # Policy must exist in OPA before promotion
    if not await _client_policy_loaded(name):
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_loaded",
                    "message": f"clients/{name} is not loaded in OPA — save it first."},
        )
    current = _lifecycle_store.get(name)
    current_status = current.get("status", "draft")
    transition = {"draft": "staging", "staging": "production"}
    next_status = transition.get(current_status)
    if next_status is None:
        raise HTTPException(
            status_code=409,
            detail={"error": "invalid_transition",
                    "message": f"Cannot promote from '{current_status}' — "
                               "already at production or archived."},
        )
    entry = _lifecycle_store.set_status(name, next_status, promoted_by=session.account_id)
    _log.info("Admin %s promoted policy clients/%s: %s → %s",
              session.account_id, name, current_status, next_status)
    return {"status": "ok", "name": name, "previous": current_status, "lifecycle_status": next_status,
            **{k: v for k, v in entry.items() if k not in ("status",)}}


@router.post("/lifecycle/{name}/archive")
async def archive_policy(name: str, session: StepUpAdminSession):
    """R10 — Archive a client policy (removes it from future binding eligibility)."""
    name = name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(status_code=400, detail={"error": "invalid_name"})
    current = _lifecycle_store.get(name)
    current_status = current.get("status", "draft")
    entry = _lifecycle_store.set_status(name, "archived", promoted_by=session.account_id)
    _log.info("Admin %s archived policy clients/%s (was %s)", session.account_id, name, current_status)
    return {"status": "ok", "name": name, "previous": current_status,
            "lifecycle_status": "archived", **{k: v for k, v in entry.items() if k not in ("status",)}}


# R12 — Policy simulate/dry-run (BEFORE the /{policy_id:path} catch-all)

class SimulateRequest(BaseModel):
    policy_id: str = Field(min_length=1, max_length=200,
                           description="OPA policy id (e.g. 'clients/my_policy' or 'examples/gdpr')")
    input_scenario: dict = Field(description="Admin-supplied OPA input document to evaluate against")
    ai_explain: bool = Field(default=True,
                             description="Ask the install-default LLM to explain the decision in plain English")


@router.post("/simulate")
async def simulate_policy(body: SimulateRequest, session: AdminSession):  # noqa: ARG001
    """R12 — Policy dry-run/simulate.

    POST an admin-supplied input scenario → returns whether the policy blocks or
    allows it + the raw deny/obligations sets. Optionally asks the install-default
    LLM to explain the result in plain English (ai_explain=true, default on).

    Does NOT modify any policy or binding — purely evaluative.
    """
    opa_url = _opa_base()
    policy_id = body.policy_id.strip()
    # Derive the data path from the policy id.
    # OPA stores modules as e.g. clients/my_policy and the package is
    # data.clients.my_policy.decision.  We evaluate that path.
    pkg_path = policy_id.replace("/", ".").lstrip(".")
    eval_path = f"/v1/data/{pkg_path.replace('.', '/')}/decision"

    try:
        async with internal_httpx_client(timeout=15.0) as client:
            resp = await client.post(
                opa_url + eval_path,
                json={"input": body.input_scenario},
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        _log.warning("simulate_policy: OPA unreachable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": "Could not reach the policy service."},
        )

    if resp.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found",
                    "message": f"No data at path {eval_path!r}. "
                               "Is the policy loaded and does it declare a 'decision' rule?"},
        )
    if resp.status_code not in (200,):
        raise HTTPException(
            status_code=502,
            detail={"error": "opa_evaluation_error", "status": resp.status_code},
        )

    result = resp.json().get("result")
    if result is None:
        # OPA returns {"result": null} when the rule is undefined for the input
        return {
            "policy_id": policy_id,
            "verdict": "undefined",
            "allow": None,
            "deny": [],
            "obligations": [],
            "explanation": "The policy's decision rule is undefined for this input — it may not match the decision contract.",
            "ai_explanation": None,
        }

    allow = bool(result.get("allow", False))
    deny = sorted(result.get("deny") or [])
    obligations = sorted(result.get("obligations") or [])
    verdict = "allow" if allow else "deny"

    ai_explanation: Optional[str] = None
    if body.ai_explain:
        ollama_url = str(
            getattr(backoffice_state, "ollama_url", None)
            or os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
        ).rstrip("/")
        try:
            model, _ = await _resolve_default_model(ollama_url)
            prompt = (
                "You are an OPA policy analyst. Explain this decision in plain English in 2–3 sentences. "
                "Be concrete about what caused the deny codes or why it was allowed.\n\n"
                f"Policy: {policy_id}\n"
                f"Input: {json.dumps(body.input_scenario, indent=2)[:2000]}\n"
                f"Decision: allow={allow}, deny={deny!r}, obligations={obligations!r}\n\n"
                "Plain-English explanation:"
            )
            async with httpx.AsyncClient(timeout=45.0) as c:
                llm_resp = await c.post(
                    ollama_url + "/api/generate",
                    json={"model": model, "prompt": prompt, "stream": False},
                )
                llm_resp.raise_for_status()
                ai_explanation = (llm_resp.json().get("response") or "").strip()[:1500]
        except Exception as exc:
            _log.info("simulate_policy: AI explanation unavailable (%s)", exc)
            ai_explanation = None

    return {
        "policy_id": policy_id,
        "verdict": verdict,
        "allow": allow,
        "deny": deny,
        "obligations": obligations,
        "explanation": f"Policy {'allows' if allow else 'denies'} this input. "
                       + (f"Deny codes: {deny!r}." if deny else "No deny codes."),
        "ai_explanation": ai_explanation,
    }


# R8 — Template endpoints (BEFORE /{policy_id:path} catch-all)

class DuplicateTemplateRequest(BaseModel):
    template_id: str = Field(min_length=1, max_length=200,
                             description="OPA policy id of the template to duplicate (e.g. 'examples/gdpr')")
    new_name: str = Field(min_length=2, max_length=41,
                          description="Name for the new editable custom policy (e.g. 'my_gdpr_variant')")


@router.post("/templates/duplicate")
async def duplicate_template(body: DuplicateTemplateRequest, session: StepUpAdminSession):
    """R8 — Duplicate (Save-As) a template into an editable custom policy.

    Reads the template's raw Rego from OPA, rewrites the package declaration to
    clients.<new_name>, then saves it as clients/<new_name>. The result is a
    fully editable client policy seeded from the template.
    """
    new_name = body.new_name.strip().lower()
    if not _NAME_RE.match(new_name) or new_name in _RESERVED:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_name",
                    "message": "lowercase letters/digits/underscore, start with a letter; not a reserved name"},
        )

    # Fetch the template's raw Rego from OPA
    src_url = _opa_base() + "/v1/policies/" + body.template_id
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            src_resp = await client.get(src_url)
            if src_resp.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail={"error": "template_not_found",
                            "message": f"Template '{body.template_id}' not found in OPA."},
                )
            src_resp.raise_for_status()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": str(exc)},
        )

    raw_rego = src_resp.json().get("result", {}).get("raw", "")
    if not raw_rego:
        raise HTTPException(
            status_code=422,
            detail={"error": "template_has_no_raw_rego",
                    "message": "Template Rego source not available; cannot duplicate."},
        )

    # Rewrite the package declaration to clients.<new_name>
    rego = re.sub(r"(?m)^\s*package\s+[A-Za-z0-9_.]+", f"package clients.{new_name}", raw_rego, count=1)
    if "package" not in rego:
        rego = f"package clients.{new_name}\n\nimport rego.v1\n\n" + rego

    # Save as clients/<new_name>
    pol_id = f"clients/{new_name}"
    dst_url = _opa_base() + "/v1/policies/" + pol_id
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            put_resp = await client.put(
                dst_url, content=rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": str(exc)},
        )
    if put_resp.status_code == 400:
        try:
            opa_err = put_resp.json()
        except Exception:
            opa_err = {"message": "Rego compile error"}
        raise HTTPException(status_code=400, detail={"error": "invalid_rego", "opa": opa_err})
    if put_resp.status_code not in (200, 204):
        raise HTTPException(
            status_code=500,
            detail={"error": "opa_put_failed", "status": put_resp.status_code},
        )

    # Initialise lifecycle as draft
    _lifecycle_store.init_if_absent(new_name, status="draft")

    _log.info("Admin %s duplicated template '%s' → clients/%s",
              session.account_id, body.template_id, new_name)
    return {
        "status": "ok",
        "source_template": body.template_id,
        "id": pol_id,
        "name": new_name,
        "category": "client",
        "lifecycle_status": "draft",
        "message": (
            f"Template duplicated as clients/{new_name} (draft). "
            "Edit the Rego with PUT /admin/policies/custom/<name>/rego, "
            "then promote through lifecycle before binding."
        ),
    }


class EditCustomPolicyRequest(BaseModel):
    rego: str = Field(min_length=1, max_length=64_000, description="Updated Rego source")
    check_only: bool = False
    confirm_warnings: bool = False


@router.put("/custom/{name}/rego")
async def edit_custom_policy_rego(
    name: str,
    body: EditCustomPolicyRequest,
    session: StepUpAdminSession,
):
    """R8 — Edit an existing custom (client) policy's Rego source.

    Only works on policies in clients/ namespace (not core/example policies).
    Runs sanity check before save; step-up required.
    """
    name = name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_name",
                    "message": "Can only edit client policies (not reserved core names)."},
        )
    if "package" not in body.rego:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_package",
                    "message": f"policy must declare a package (e.g. 'package clients.{name}')"},
        )

    from yashigani.opa_assistant.sanity import static_sanity_check
    sanity = await static_sanity_check(body.rego, name)
    if not sanity["compiled"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_rego", "opa": sanity.get("compile_error") or "Rego compile error"},
        )
    warnings = list(sanity["warnings"])
    high = [w for w in warnings if w.get("severity") == "high"]
    if body.check_only:
        return {"status": "checked", "name": name, "warnings": warnings, "ok": not high}
    if high and not body.confirm_warnings:
        return JSONResponse(status_code=409, content={
            "error": "sanity_warnings",
            "message": "High-severity warnings. Re-submit with confirm_warnings=true to save.",
            "warnings": warnings,
        })

    pol_id = f"clients/{name}"
    url = _opa_base() + "/v1/policies/" + pol_id
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.put(
                url, content=body.rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": str(exc)},
        )
    if resp.status_code == 400:
        try:
            opa_err = resp.json()
        except Exception:
            opa_err = {"message": "Rego compile error"}
        raise HTTPException(status_code=400, detail={"error": "invalid_rego", "opa": opa_err})
    if resp.status_code not in (200, 204):
        raise HTTPException(
            status_code=500,
            detail={"error": "opa_put_failed", "status": resp.status_code},
        )
    # On successful edit, demote to draft (needs re-promotion to production)
    _lifecycle_store.init_if_absent(name, status="draft")

    _log.info("Admin %s edited Rego for clients/%s (%d warnings, confirmed=%s)",
              session.account_id, name, len(warnings), body.confirm_warnings)
    return {
        "status": "ok",
        "id": pol_id,
        "name": name,
        "category": "client",
        "lifecycle_status": _lifecycle_store.get(name).get("status", "draft"),
        "warnings": warnings,
        "message": "Updated in OPA. Lifecycle reset to draft — re-promote before binding.",
    }


# R9 — Core policy edit with confirm_danger guard

class EditCorePolicyRequest(BaseModel):
    rego: str = Field(min_length=1, max_length=64_000, description="Updated Rego source for the core policy")
    confirm_danger: bool = Field(
        default=False,
        description="REQUIRED: must be true to edit a load-bearing core policy. "
                    "This is a server-side safety guard, not a UI-only warning.",
    )
    reason: str = Field(default="", max_length=500,
                        description="Mandatory justification for editing a core policy.")


@router.put("/core/{policy_id:path}")
async def edit_core_policy(
    policy_id: str,
    body: EditCorePolicyRequest,
    session: StepUpAdminSession,
):
    """R9 — Edit a core (load-bearing) gateway policy — DANGEROUS.

    Requires confirm_danger=true in the request body. A missing or false flag
    returns 409 regardless of session state. Also requires step-up (TOTP). Both
    are server-side guards — the UI may show a warning dialog but this endpoint
    enforces independently.

    The policy_id may be a bare name ('yashigani') or a full OPA path ('yashigani/main').
    All edits are audited with the admin account id and the supplied reason.
    """
    # Server-side danger guard — never skip this
    if not body.confirm_danger:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "confirm_danger_required",
                "message": (
                    "Editing a core policy requires confirm_danger=true. "
                    "Core policies are load-bearing — an error may disrupt the gateway. "
                    "Re-submit with confirm_danger=true and a reason."
                ),
            },
        )
    if not body.reason.strip():
        raise HTTPException(
            status_code=400,
            detail={"error": "reason_required",
                    "message": "A justification reason is required when editing core policies."},
        )

    # Only allow editing known core policy namespaces
    pid = policy_id.strip().lstrip("/")
    is_core = any(pid == p or pid.startswith(p + "/") for p in _CORE_POLICY_PREFIXES)
    if not is_core:
        raise HTTPException(
            status_code=400,
            detail={"error": "not_a_core_policy",
                    "message": (
                        f"'{pid}' is not a recognised core policy. "
                        "Use PUT /admin/policies/custom/<name>/rego for client policies."
                    )},
        )
    if "package" not in body.rego:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_package", "message": "policy must declare a package"},
        )

    # Sanity check before touching a core policy
    from yashigani.opa_assistant.sanity import static_sanity_check
    name_slug = re.sub(r"[^a-z0-9_]", "_", pid.replace("/", "_").lower())
    sanity = await static_sanity_check(body.rego, name_slug)
    if not sanity["compiled"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_rego",
                    "opa": sanity.get("compile_error") or "Rego compile error"},
        )

    url = _opa_base() + "/v1/policies/" + pid
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.put(
                url, content=body.rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": str(exc)},
        )
    if resp.status_code == 400:
        try:
            opa_err = resp.json()
        except Exception:
            opa_err = {"message": "Rego compile error"}
        raise HTTPException(status_code=400, detail={"error": "invalid_rego", "opa": opa_err})
    if resp.status_code not in (200, 204):
        raise HTTPException(
            status_code=500,
            detail={"error": "opa_put_failed", "status": resp.status_code},
        )

    _log.warning(
        "CORE POLICY EDIT: admin=%s policy=%s reason=%r (danger confirmed)",
        session.account_id, pid, body.reason,
    )
    return {
        "status": "ok",
        "id": pid,
        "category": "core",
        "warnings": sanity.get("warnings", []),
        "message": (
            f"Core policy '{pid}' updated in OPA. This change takes effect immediately. "
            "Audit trail: see server logs. Ensure the policy bundle is updated "
            "to persist this change across redeploys."
        ),
    }


# ---------------------------------------------------------------------------
# Existing read endpoints (unchanged)
# ---------------------------------------------------------------------------

@router.get("/{policy_id:path}")
async def get_policy(policy_id: str, session: AdminSession):  # noqa: ARG001 — auth gate
    """Return a single policy module's raw Rego source (read-only)."""
    url = _opa_base() + "/v1/policies/" + policy_id
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail={"error": "policy_not_found"})
            resp.raise_for_status()
            result = resp.json().get("result", {})
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        _log.warning("OPA get policy failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"error": "opa_unreachable", "message": "Could not reach the policy service."},
        )
    cat = _categorize(policy_id)
    name = policy_id.rsplit("/", 1)[-1]
    if name.endswith(".rego"):
        name = name[: -len(".rego")]
    lifecycle_status = "production" if cat != "client" else _lifecycle_store.get(name).get("status", "draft")
    return {
        "id": result.get("id", policy_id),
        "raw": result.get("raw", ""),
        "package": ".".join(
            seg.get("value", "")
            for seg in ((result.get("ast") or {}).get("package", {}).get("path", []))
            if isinstance(seg.get("value"), str)
        ),
        "category": cat,
        "lifecycle_status": lifecycle_status,
    }


# ---------------------------------------------------------------------------
# Existing mutation endpoints (save / generate / activate / bind / unbind)
# ---------------------------------------------------------------------------

class SavePolicyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=41)
    rego: str = Field(min_length=1, max_length=64_000)
    # #17 (OPA Phase 3a) sanity check:
    check_only: bool = False        # run sanity check, return warnings, do NOT save
    confirm_warnings: bool = False  # save despite HIGH warnings (deny-all/never-allow)
    run_llm_review: bool = False    # also run the advisory LLM review pass


@router.post("/save")
async def save_policy(body: SavePolicyRequest, session: StepUpAdminSession):  # noqa: ARG001
    """
    Create/update an editable CLIENT policy copy — loaded into OPA, usable now.

    Templates (the examples) are immutable; the operator edits a copy and saves it
    under a new name -> stored as clients/<name> in OPA. High-value mutation ->
    step-up. OPA compiles on PUT, so invalid Rego is rejected with the compile
    error (basic sanity; full loop / block-everything LLM checks are a follow-up).
    """
    name = body.name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_name",
                    "message": "lowercase letters/digits/underscore, start with a letter; not a reserved core name"},
        )
    if "package" not in body.rego:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_package",
                    "message": f"policy must declare a package (e.g. 'package clients.{name}')"},
        )

    # #17 (OPA Phase 3a): behavioural sanity check in a throwaway sandbox BEFORE
    # the live PUT. Compile error -> 400 invalid_rego. HIGH warnings (deny-all /
    # never-allow / undefined) -> 409 unless confirm_warnings. check_only -> return
    # the warnings without mutating live state. Advisory LLM review on request.
    from yashigani.opa_assistant.sanity import static_sanity_check, llm_review
    sanity = await static_sanity_check(body.rego, name)
    if not sanity["compiled"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_rego",
                            "opa": sanity.get("compile_error") or "Rego compile error"})
    warnings = list(sanity["warnings"])
    if body.run_llm_review:
        warnings += await llm_review(body.rego)
    high = [w for w in warnings if w.get("severity") == "high"]
    if body.check_only:
        _log.info("Admin %s sanity-checked client policy clients/%s (%d warning(s))",
                  session.account_id, name, len(warnings))
        return {"status": "checked", "name": name, "warnings": warnings, "ok": not high}
    if high and not body.confirm_warnings:
        return JSONResponse(status_code=409, content={
            "error": "sanity_warnings",
            "message": "This policy has high-severity warnings. Re-submit with confirm_warnings=true to save anyway.",
            "warnings": warnings,
        })

    pol_id = f"clients/{name}"
    url = _opa_base() + "/v1/policies/" + pol_id
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.put(
                url, content=body.rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
    except httpx.HTTPError as exc:
        _log.warning("OPA save policy failed: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "opa_unreachable",
                            "message": "Could not reach the policy service."})
    if resp.status_code == 400:
        try:
            opa_err = resp.json()
        except Exception:
            opa_err = {"message": "Rego compile error"}
        raise HTTPException(status_code=400, detail={"error": "invalid_rego", "opa": opa_err})
    if resp.status_code not in (200, 204):
        raise HTTPException(status_code=500, detail={"error": "opa_put_failed", "status": resp.status_code})

    # R10: initialise lifecycle as draft on new save
    _lifecycle_store.init_if_absent(name, status="draft")

    _log.info("Admin %s saved client policy %s (%d warning(s), confirmed=%s)",
              session.account_id, pol_id, len(warnings), body.confirm_warnings)
    return {
        "status": "ok",
        "id": pol_id,
        "name": name,
        "category": "client",
        "lifecycle_status": "draft",
        "warnings": warnings,  # #17: surfaced even on save (e.g. info-level LLM notes)
        "message": "Saved and loaded into OPA (usable now). To persist across a full redeploy, add it to your policy bundle.",
    }


class GeneratePolicyRequest(BaseModel):
    prompt: str = Field(min_length=4, max_length=2000)
    name: str = Field(default="generated", max_length=41)


# Few-shot system prompt. Small local models can't infer the decision contract
# from a terse instruction, so we give them the contract, the input vocabulary,
# AND a concrete working exemplar to copy. {name} is substituted via .replace
# (NOT str.format) because the embedded Rego contains literal { } braces.
_REGO_GEN_SYSTEM = """You are an OPA Rego policy author for the Yashigani AI security gateway.
Write ONE Rego policy module for the operator's requirement, copying the structure
of the EXAMPLE below exactly.

Decision contract (every gateway policy is a decision document):
  data.clients.<name>.decision = {"allow": bool, "deny": set of strings, "obligations": set of strings}
  - default-deny: allow is true ONLY when count(deny) == 0
  - deny       = short machine-readable violation codes
  - obligations = actions the gateway must perform (audit / redact / ...)

Inputs the gateway supplies (use what's relevant):
  input.identity.{agent,role,clearance,groups}
  input.request.{purpose,lawful_basis}
  input.routing_decision.{route,provider,model}
  input.tool, input.method, input.path, input.data_tags[]

EXAMPLE — copy this structure:
----
package clients.example_agent_email
import rego.v1

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# Forbid the delete/trash email tools for this agent.
deny contains "email_delete_forbidden" if {
	input.identity.agent == "openclaw"
	input.tool in {"email.delete", "email.trash"}
}

obligations contains "audit_email_access" if startswith(input.tool, "email.")
----

Now write the policy:
- start with: package clients.{name}
- import rego.v1
- use `deny contains "code" if { ... }` rules; allow = count(deny) == 0
- Output ONLY valid Rego. No prose. No markdown fences."""


@router.post("/generate")
async def generate_policy(body: GeneratePolicyRequest, session: AdminSession):  # noqa: ARG001
    """
    NL -> Rego draft via the internal LLM (Ollama). Returns a draft the operator
    reviews/edits in the policy editor, then saves (which OPA-compiles it). The
    draft is NOT auto-applied. (LLM loop/over-block sanity checks are a follow-up.)
    """
    name = re.sub(r"[^a-z0-9_]", "", (body.name or "generated").strip().lower()) or "generated"
    ollama_url = str(
        getattr(backoffice_state, "ollama_url", None)
        or os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
    ).rstrip("/")
    model, _ = await _resolve_default_model(ollama_url)
    prompt = (
        _REGO_GEN_SYSTEM.replace("{name}", name)
        + f"\n\nRequirement: {body.prompt}\n\nRego policy (package clients.{name}):\n"
    )
    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                ollama_url + "/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            raw = (resp.json().get("response") or "").strip()
    except httpx.HTTPError as exc:
        _log.warning("policy generate: LLM error: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "llm_unavailable",
                            "message": "Could not reach the policy-assistant LLM."})
    # Strip markdown fences if the model wrapped the output.
    rego = raw
    if rego.startswith("```"):
        parts = rego.split("\n")
        if parts and parts[-1].strip().startswith("```"):
            parts = parts[:-1]
        rego = "\n".join(parts[1:])
    rego = rego.strip()
    if "package" not in rego:
        rego = f"package clients.{name}\n\nimport rego.v1\n\n# NOTE: LLM omitted package — review carefully.\n\n" + rego

    # #17 (OPA Phase 3a): one-shot compile-repair — if the draft fails to compile,
    # feed OPA's error back to the LLM ONCE for a corrected draft. Then run the
    # behavioural sanity check. Nothing is auto-applied; warnings are advisory.
    from yashigani.opa_assistant.sanity import compile_repair_once, static_sanity_check

    async def _regenerate(err_text: str) -> str:
        rprompt = prompt + f"\n\nThe previous attempt failed to compile with this OPA error:\n{err_text}\nReturn ONLY corrected Rego.\n"
        async with httpx.AsyncClient(timeout=90.0) as c:
            rr = await c.post(ollama_url + "/api/generate", json={"model": model, "prompt": rprompt, "stream": False})
            rr.raise_for_status()
            fixed = (rr.json().get("response") or "").strip()
        if fixed.startswith("```"):
            ps = fixed.split("\n")
            if ps and ps[-1].strip().startswith("```"):
                ps = ps[:-1]
            fixed = "\n".join(ps[1:]).strip()
        if "package" not in fixed:
            fixed = f"package clients.{name}\n\nimport rego.v1\n\n" + fixed
        return fixed

    repaired = False
    repair_error = None
    warnings: list = []
    try:
        rep = await compile_repair_once(rego, name, _regenerate)
        rego = rep["rego"]
        repaired = rep["repaired"]
        repair_error = rep["repair_error"]
        if not repair_error:
            sc = await static_sanity_check(rego, name)
            warnings = sc.get("warnings", [])
    except Exception as exc:  # noqa: BLE001 — generation already succeeded; repair/sanity advisory
        _log.info("policy generate: repair/sanity skipped (%s)", exc)

    return {
        "status": "ok",
        "name": name,
        "rego": rego,
        "model": model,
        "repaired": repaired,
        "repair_error": repair_error,
        "warnings": warnings,
        "note": "AI-generated draft — review and edit before saving. Saving runs an OPA compile + sanity check.",
    }


# ---------------------------------------------------------------------------
# #16 (OPA Phase 2) — client-policy activation + bindings (API).
# Parity requirement: the WebUI Bindings panel mirrors these endpoints exactly.
# ---------------------------------------------------------------------------

class BindRequest(BaseModel):
    policy_name: str = Field(min_length=2, max_length=41)
    scope_kind: str = Field(min_length=1, max_length=20)
    scope_id: str = Field(default="", max_length=200)
    direction: str = Field(min_length=1, max_length=10)


class ActivateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=41)


async def _client_policy_loaded(name: str) -> bool:
    """True if clients/<name> is loaded in OPA (GET /v1/policies/clients/<name>)."""
    url = _opa_base() + "/v1/policies/clients/" + name
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            resp = await client.get(url)
        return resp.status_code == 200
    except httpx.HTTPError as exc:
        _log.warning("OPA policy-exists check failed for %s: %s", name, exc)
        raise HTTPException(status_code=503, detail={"error": "opa_unreachable",
                            "message": "Could not reach the policy service."})


async def _push_bindings() -> None:
    """Push the binding document to OPA off the event loop (sync httpx client)."""
    import asyncio
    from yashigani.policy_bindings.opa_push import push_bindings_data
    store = backoffice_state.binding_store
    try:
        await asyncio.to_thread(push_bindings_data, store, backoffice_state.opa_url)
    except Exception as exc:  # noqa: BLE001 — surface as 503; the mutation already persisted
        _log.warning("OPA bindings push failed: %s", exc)
        raise HTTPException(status_code=503, detail={"error": "opa_push_failed",
                            "message": "Binding saved but OPA sync failed; it will retry on next mutation/restart."})


@router.post("/activate")
async def activate_policy(body: ActivateRequest, session: StepUpAdminSession):  # noqa: ARG001
    """Confirm a saved client policy is loaded in OPA and ready to bind. Idempotent."""
    name = body.name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(status_code=400, detail={"error": "invalid_name",
                            "message": "not a valid client-policy name"})
    if not await _client_policy_loaded(name):
        raise HTTPException(status_code=404, detail={"error": "policy_not_loaded",
                            "message": f"clients/{name} is not loaded in OPA — save it first."})
    _log.info("Admin %s activated client policy clients/%s", session.account_id, name)
    return {"status": "ok", "name": name, "loaded": True}


@router.post("/bind")
async def bind_policy(body: BindRequest, session: StepUpAdminSession):
    """Bind an activated client policy to a subject scope + direction. Step-up gated."""
    from yashigani.policy_bindings.store import PolicyBinding
    store = backoffice_state.binding_store
    if store is None:
        raise HTTPException(status_code=503, detail={"error": "binding_store_unavailable"})
    name = body.policy_name.strip().lower()
    if not _NAME_RE.match(name) or name in _RESERVED:
        raise HTTPException(status_code=400, detail={"error": "invalid_policy_name",
                            "message": "bind a saved client policy, not a reserved core policy"})
    # Fail-closed: never bind a policy that isn't loaded in OPA (would be a dangling
    # binding -> the aggregator emits bound_policy_missing and denies).
    if not await _client_policy_loaded(name):
        raise HTTPException(status_code=404, detail={"error": "policy_not_loaded",
                            "message": f"clients/{name} is not loaded in OPA — save+activate it first."})
    try:
        binding = store.add(PolicyBinding(
            policy_name=name,
            scope_kind=body.scope_kind.strip().lower(),
            scope_id=body.scope_id.strip(),
            direction=body.direction.strip().lower(),
        ))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_binding", "message": str(exc)})
    await _push_bindings()
    _log.info("Admin %s bound clients/%s -> %s (%s)", session.account_id, name,
              binding.scope_key(), binding.direction)
    return {"status": "ok", "binding": binding.to_dict()}


@router.delete("/bind/{binding_id}")
async def unbind_policy(binding_id: str, session: StepUpAdminSession):
    """Remove a client-policy binding. Step-up gated."""
    store = backoffice_state.binding_store
    if store is None:
        raise HTTPException(status_code=503, detail={"error": "binding_store_unavailable"})
    if not store.remove(binding_id):
        raise HTTPException(status_code=404, detail={"error": "binding_not_found"})
    await _push_bindings()
    _log.info("Admin %s removed binding %s", session.account_id, binding_id)
    return {"status": "ok", "removed": binding_id}
