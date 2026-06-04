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

import httpx
from fastapi import APIRouter, HTTPException

from yashigani.backoffice.middleware import AdminSession
from yashigani.pki.client import internal_httpx_client

router = APIRouter()
_log = logging.getLogger("yashigani.policies")


def _opa_base() -> str:
    return os.getenv("YASHIGANI_OPA_URL", "https://policy:8181").rstrip("/")


def _categorize(policy_id: str) -> str:
    """Classify a policy module by its id so the UI can group them."""
    pid = policy_id.lower()
    if "examples/" in pid:
        return "example"
    if pid.endswith("_test.rego") or "/test" in pid:
        return "test"
    return "core"


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
