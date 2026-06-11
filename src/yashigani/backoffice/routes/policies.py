"""
Yashigani Backoffice — OPA policy viewer (read-only).

Surfaces the Rego policy modules currently loaded in the OPA decision service
so admins can see exactly which policies are active — the loaded examples
(gdpr, eu_ai_act, health_hipaa, …) as well as the core Yashigani policies
(yashigani, rbac, mcp, agents, v1_routing).

Read-only by design: policies are deployed declaratively (policy bundle /
install-time load), not edited from the admin UI. This page answers the
operational question "which OPAs are live right now and what do they say?".

OPA Policy API (mTLS, internal CA):
    GET {opa_url}/v1/policies        — list all loaded modules
    GET {opa_url}/v1/policies/{id}   — single module (raw Rego + AST)
"""
from __future__ import annotations

import logging
import os
import re

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


def _opa_base() -> str:
    return os.getenv("YASHIGANI_OPA_URL", "https://policy:8181").rstrip("/")


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


class SavePolicyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=41)
    rego: str = Field(min_length=1, max_length=64_000)
    # #17 (OPA Phase 3a) sanity check:
    check_only: bool = False        # run sanity check, return warnings, do NOT save
    confirm_warnings: bool = False  # save despite HIGH warnings (deny-all/never-allow)
    run_llm_review: bool = False    # also run the advisory LLM review pass


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
        policies.append(
            {
                "id": pid,
                "name": name,
                "package": pkg,
                "category": _categorize(pid),
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
    return {
        "id": result.get("id", policy_id),
        "raw": result.get("raw", ""),
        "package": ".".join(
            seg.get("value", "")
            for seg in ((result.get("ast") or {}).get("package", {}).get("path", []))
            if isinstance(seg.get("value"), str)
        ),
        "category": _categorize(policy_id),
    }


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
    _log.info("Admin %s saved client policy %s (%d warning(s), confirmed=%s)",
              session.account_id, pol_id, len(warnings), body.confirm_warnings)
    return {
        "status": "ok",
        "id": pol_id,
        "name": name,
        "category": "client",
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
    ollama_url = (getattr(backoffice_state, "ollama_url", None)
                  or os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")).rstrip("/")
    # Use a model that's actually loaded — the configured one if present, else the
    # first available (the demo may run gemma3:4b, others qwen2.5:3b, etc.).
    _pref = os.getenv("YASHIGANI_OPA_ASSISTANT_MODEL") or os.getenv("OLLAMA_MODEL")
    try:
        async with httpx.AsyncClient(timeout=10.0) as _c:
            _tags = (await _c.get(ollama_url + "/api/tags")).json().get("models", [])
        _avail = [m.get("name") for m in _tags if m.get("name")]
    except Exception:
        _avail = []
    model = _pref if (_pref and _pref in _avail) else (_avail[0] if _avail else (_pref or "qwen2.5:3b"))
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
            if ps and ps[-1].strip().startswith("```"): ps = ps[:-1]
            fixed = "\n".join(ps[1:]).strip()
        if "package" not in fixed:
            fixed = f"package clients.{name}\n\nimport rego.v1\n\n" + fixed
        return fixed

    repaired = False
    repair_error = None
    warnings: list = []
    try:
        rep = await compile_repair_once(rego, name, _regenerate)
        rego = rep["rego"]; repaired = rep["repaired"]; repair_error = rep["repair_error"]
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
