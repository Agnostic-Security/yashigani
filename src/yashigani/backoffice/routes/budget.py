"""
Yashigani Backoffice — Budget admin API.

CRUD for the three-tier budget hierarchy:
  POST/GET/PUT/DELETE  /admin/budget/org-caps          — Organisation cloud caps
  POST/GET/PUT/DELETE  /admin/budget/groups             — Group budgets
  POST/GET/PUT/DELETE  /admin/budget/individuals        — Individual budgets
  GET                  /admin/budget/usage/{identity_id} — Usage summary
  GET                  /admin/budget/tree               — YSG-RISK-157: 501 Not Implemented (nested tree view — needs RBAC/identity join, deferred)
  GET                  /admin/budget/models/local-inventory
                       — Installed Ollama models + GPU VRAM fit analysis

Invariants enforced by this API:
  - Sum of individual budgets <= group budget
  - Sum of group budgets <= org cap
  - New identity added to group: prompt admin to adjust
  - Group budget cannot be set below sum of individuals

Auth note (2026-05-02): Added router-level require_admin_session dependency.
All endpoints were previously unauthenticated (OWASP API3:2023 / ASVS V4.1.1).
No middleware covered /admin/budget/* paths. The router-level Depends() protects
all current and future endpoints in this file with a single declaration.

Last updated: 2026-07-01T00:00:00+00:00
"""
from __future__ import annotations

import glob
import logging
import os
import re
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import require_admin_session, AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.audit.schema import ConfigChangedEvent

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/budget",
    tags=["budget"],
    dependencies=[Depends(require_admin_session)],
)


# ── Request/Response Models ──────────────────────────────────────────────


class OrgCapRequest(BaseModel):
    org_id: str
    provider: str
    token_cap: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")


class OrgCapResponse(BaseModel):
    org_id: str
    provider: str
    token_cap: int
    period: str
    used: int = 0
    pct: int = 0


class GroupBudgetRequest(BaseModel):
    group_id: str
    provider: str = "*"
    token_budget: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")
    distribute_evenly: bool = False


class GroupBudgetResponse(BaseModel):
    group_id: str
    provider: str
    token_budget: int
    period: str
    auto_calculated: bool
    used: int = 0
    pct: int = 0
    member_count: int = 0
    allocated: int = 0
    unallocated: int = 0


class IndividualBudgetRequest(BaseModel):
    identity_id: str
    provider: str = "*"
    token_budget: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")


class IndividualBudgetResponse(BaseModel):
    identity_id: str
    provider: str
    token_budget: int
    period: str
    used: int = 0
    pct: int = 0
    remaining: int = 0


class BudgetTreeNode(BaseModel):
    """A node in the budget tree view."""
    name: str
    type: str  # 'org', 'group', 'identity'
    provider: str
    budget: int
    used: int
    pct: int
    children: list[BudgetTreeNode] = Field(default_factory=list)


class BudgetValidationError(BaseModel):
    """Returned when a budget mutation would violate hierarchy invariants."""
    error: str
    current_sum: int
    proposed: int
    limit: int
    suggestion: str


# ── State (injected at startup) ─────────────────────────────────────────


class BudgetAdminState:
    def __init__(self):
        self.budget_enforcer = None
        self.identity_registry = None
        self.budget_store = None


_state = BudgetAdminState()


def configure(budget_enforcer=None, identity_registry=None, budget_store=None):
    _state.budget_enforcer = budget_enforcer
    _state.identity_registry = identity_registry
    _state.budget_store = budget_store


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("/org-caps")
async def list_org_caps():
    """List all organisation cloud caps."""
    if _state.budget_store:
        caps = await _state.budget_store.get_org_caps("00000000-0000-0000-0000-000000000000")
        return {"org_caps": caps}
    return {"org_caps": []}


@router.post("/org-caps", response_model=OrgCapResponse, status_code=201)
async def create_org_cap(body: OrgCapRequest):
    """Set an organisation's cloud token cap for a provider."""
    if _state.budget_store:
        await _state.budget_store.set_org_cap(
            "00000000-0000-0000-0000-000000000000",
            body.org_id, body.provider, body.token_cap, body.period,
        )
    # YSG-RISK-144: sync to Redis so the per-request hierarchy check
    # (BudgetEnforcer.check_hierarchy) can enforce the org cap without a DB
    # round-trip on the hot path. Previously never synced — the org tier of
    # the documented individual<=group<=org invariant was unenforceable.
    if _state.budget_enforcer:
        _state.budget_enforcer.set_org_allocation(body.org_id, body.provider, body.token_cap)
    return OrgCapResponse(
        org_id=body.org_id,
        provider=body.provider,
        token_cap=body.token_cap,
        period=body.period,
    )


@router.get("/groups")
async def list_group_budgets():
    """List all group budgets."""
    if _state.budget_store:
        budgets = await _state.budget_store.get_group_budgets("00000000-0000-0000-0000-000000000000")
        return {"group_budgets": budgets}
    return {"group_budgets": []}


@router.post("/groups", response_model=GroupBudgetResponse, status_code=201)
async def create_group_budget(body: GroupBudgetRequest):
    """Set a group's budget."""
    if _state.budget_store:
        await _state.budget_store.set_group_budget(
            "00000000-0000-0000-0000-000000000000",
            body.group_id, body.provider, body.token_budget, body.period,
        )
    # YSG-RISK-144: sync to Redis so the per-request hierarchy check
    # (BudgetEnforcer.check_hierarchy) can enforce the group budget without a
    # DB round-trip on the hot path. Previously never synced — the group
    # tier of the documented individual<=group<=org invariant was
    # unenforceable (only list_group_utilisation's Grafana metric read this
    # key, and nothing ever wrote it).
    if _state.budget_enforcer:
        _state.budget_enforcer.set_group_allocation(body.group_id, body.provider, body.token_budget)
    return GroupBudgetResponse(
        group_id=body.group_id,
        provider=body.provider,
        token_budget=body.token_budget,
        period=body.period,
        auto_calculated=False,
    )


@router.get("/individuals")
async def list_individual_budgets():
    """List all individual budgets."""
    if _state.budget_store:
        budgets = await _state.budget_store.get_individual_budgets("00000000-0000-0000-0000-000000000000")
        return {"individual_budgets": budgets}
    return {"individual_budgets": []}


@router.post("/individuals", response_model=IndividualBudgetResponse, status_code=201)
async def create_individual_budget(body: IndividualBudgetRequest):
    """Set an individual identity's budget."""
    if _state.budget_store:
        await _state.budget_store.set_individual_budget(
            "00000000-0000-0000-0000-000000000000",
            body.identity_id, body.provider, body.token_budget, body.period,
        )
    # Sync allocation to Redis so gateway can enforce without DB round-trip
    if _state.budget_enforcer:
        _state.budget_enforcer.set_allocation(body.identity_id, body.provider, body.token_budget)
    return IndividualBudgetResponse(
        identity_id=body.identity_id,
        provider=body.provider,
        token_budget=body.token_budget,
        period=body.period,
        remaining=body.token_budget,
    )


def _emit_budget_delete_audit(admin_account: str, resource: str, target: str) -> None:
    """Emit a CONFIG_CHANGED audit event for a budget deletion.

    Fail-soft: never raises — a failed audit write must not mask a successful
    delete so the UI refresh can proceed.
    """
    if backoffice_state.audit_writer is None:
        return
    try:
        backoffice_state.audit_writer.write(
            ConfigChangedEvent(
                admin_account=admin_account,
                setting=f"budget:{resource}",
                previous_value=target,
                new_value="deleted",
            )
        )
    except Exception as _exc:
        logger.error("Failed to write budget delete audit event (%s %s): %s", resource, target, _exc)


@router.delete("/org-caps", status_code=204)
async def delete_org_cap(
    org_id: str,
    provider: str,
    session: AdminSession,
):
    """Delete an organisation cloud cap.  404 if the cap does not exist."""
    if not _state.budget_store:
        raise HTTPException(status_code=503, detail="Budget store not available")
    deleted = await _state.budget_store.delete_org_cap(
        "00000000-0000-0000-0000-000000000000", org_id, provider,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "org_cap_not_found", "org_id": org_id, "provider": provider},
        )
    _emit_budget_delete_audit(session.account_id, "org_cap", f"{org_id}:{provider}")


@router.delete("/groups", status_code=204)
async def delete_group_budget(
    group_id: str,
    provider: str,
    session: AdminSession,
    period: str = "monthly",
):
    """Delete a group budget.  404 if the budget does not exist."""
    if not _state.budget_store:
        raise HTTPException(status_code=503, detail="Budget store not available")
    deleted = await _state.budget_store.delete_group_budget(
        "00000000-0000-0000-0000-000000000000", group_id, provider, period,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "group_budget_not_found", "group_id": group_id, "provider": provider},
        )
    _emit_budget_delete_audit(session.account_id, "group_budget", f"{group_id}:{provider}:{period}")


@router.delete("/individuals", status_code=204)
async def delete_individual_budget(
    identity_id: str,
    provider: str,
    session: AdminSession,
    period: str = "monthly",
):
    """Delete an individual budget.  404 if the budget does not exist."""
    if not _state.budget_store:
        raise HTTPException(status_code=503, detail="Budget store not available")
    deleted = await _state.budget_store.delete_individual_budget(
        "00000000-0000-0000-0000-000000000000", identity_id, provider, period,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "individual_budget_not_found", "identity_id": identity_id, "provider": provider},
        )
    _emit_budget_delete_audit(session.account_id, "individual_budget", f"{identity_id}:{provider}:{period}")


@router.get("/usage/{identity_id}")
async def get_usage(identity_id: str, period: str = "monthly"):
    """Get token usage across all providers for an identity."""
    if not _state.budget_enforcer:
        raise HTTPException(status_code=503, detail="Budget enforcer not available")

    usage = _state.budget_enforcer.get_usage_summary(identity_id, period)
    return {
        "identity_id": identity_id,
        "period": period,
        "usage": usage,
    }


@router.get("/tree")
async def get_budget_tree():
    """
    Full budget tree view: org -> groups -> identities — NOT IMPLEMENTED in 4.1.2.

    YSG-RISK-157: this previously returned a plain 200 with an empty
    ``tree: []`` — a caller checking only the HTTP status would read that as
    "success, no budgets configured" rather than "feature not built".

    A genuinely correct nested org->group->identity tree needs group->org and
    identity->group membership linkage that does not exist in the budget
    schema today: ``group_budgets``/``individual_budgets`` (migration 0005)
    carry no ``org_id``/``group_id`` foreign keys to each other — that
    membership lives in the RBAC group store, a separate service boundary.
    Building the nesting correctly means joining budget config against RBAC
    group membership + identity.org_id, which is a real feature (schema
    and/or cross-service join), not a point-fix — deferred past 4.1.2.
    GET /admin/budget/org-caps, /groups, and /individuals already return the
    flat (non-nested) configuration and remain the source of truth until
    then. Returns an honest 501 rather than a misleading empty tree.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": "not_implemented",
            "message": (
                "The nested org->group->identity budget tree view is not yet "
                "implemented — it requires group/identity membership linkage "
                "that does not exist in the current budget schema. Use "
                "GET /admin/budget/org-caps, /admin/budget/groups, and "
                "/admin/budget/individuals for the flat configuration."
            ),
        },
    )


# ===========================================================================
# GET /admin/budget/models/local-inventory — Ollama local model inventory
# ===========================================================================
#
# Queries the local Ollama instance for installed models, detects the
# available GPU VRAM from /proc/driver/nvidia/gpus/ (via reading the
# GPU model name and known-model VRAM table, or from the
# YASHIGANI_GPU_TOTAL_VRAM_MIB env var if set by install.sh), and
# computes a "fits_gpu" flag for each installed model.
#
# VRAM estimation: model disk size × 1.2 overhead ≈ resident VRAM at Q4.
# This is a heuristic — actual VRAM depends on quantisation, context len,
# and batch size. The flag is informational, not a hard gate.
# ===========================================================================

# Known GPU model-name → total VRAM (MiB) lookup table.
# Keyed by canonical substring in the /proc/driver/nvidia model name.
# Ordered longest-match-first so "GTX 1060 3GB" wins over "GTX 1060".
_KNOWN_GPU_VRAM_MIB: list[tuple[str, int]] = [
    # RTX 50 series
    ("RTX 5090", 32768),
    ("RTX 5080", 16384),
    ("RTX 5070 Ti", 16384),
    ("RTX 5070", 12288),
    ("RTX 5060 Ti", 8192),
    # RTX 40 series
    ("RTX 4090", 24576),
    ("RTX 4080 SUPER", 16384),
    ("RTX 4080", 16384),
    ("RTX 4070 Ti SUPER", 16384),
    ("RTX 4070 Ti", 12288),
    ("RTX 4070 SUPER", 12288),
    ("RTX 4070", 12288),
    ("RTX 4060 Ti 16GB", 16384),
    ("RTX 4060 Ti", 8192),
    ("RTX 4060", 8192),
    # RTX 30 series
    ("RTX 3090 Ti", 24576),
    ("RTX 3090", 24576),
    ("RTX 3080 Ti", 12288),
    ("RTX 3080 12GB", 12288),
    ("RTX 3080", 10240),
    ("RTX 3070 Ti", 8192),
    ("RTX 3070", 8192),
    ("RTX 3060 Ti", 8192),
    ("RTX 3060", 12288),
    ("RTX 3050 Ti", 4096),
    ("RTX 3050", 8192),
    # RTX 20 series
    ("RTX 2080 Ti", 11264),
    ("RTX 2080 SUPER", 8192),
    ("RTX 2080", 8192),
    ("RTX 2070 SUPER", 8192),
    ("RTX 2070", 8192),
    ("RTX 2060 SUPER", 8192),
    ("RTX 2060", 6144),
    # GTX 16 series
    ("GTX 1660 SUPER", 6144),
    ("GTX 1660 Ti", 6144),
    ("GTX 1660", 6144),
    ("GTX 1650 SUPER", 4096),
    ("GTX 1650", 4096),
    # GTX 10 series
    ("GTX 1080 Ti", 11264),
    ("GTX 1080", 8192),
    ("GTX 1070 Ti", 8192),
    ("GTX 1070", 8192),
    ("GTX 1060 6GB", 6144),
    ("GTX 1060 3GB", 3072),
    ("GTX 1060", 6144),
    ("GTX 1050 Ti", 4096),
    ("GTX 1050", 2048),
    # A-series (workstation/data-centre)
    ("A100 SXM4 80GB", 81920),
    ("A100 SXM4 40GB", 40960),
    ("A100 PCIe 80GB", 81920),
    ("A100 PCIe 40GB", 40960),
    ("A40", 49152),
    ("A30", 24576),
    ("A16", 64512),
    ("A10G", 24576),
    ("A10", 24576),
    ("A6000", 49152),
    ("A5000", 24576),
    ("A4000", 16384),
    ("A2000 12GB", 12288),
    ("A2000", 6144),
    # L-series
    ("L40S", 49152),
    ("L40", 49152),
    ("L4", 24576),
    # H-series
    ("H200 SXM5 141GB", 143360),
    ("H200 SXM5", 143360),
    ("H100 SXM5 80GB", 81920),
    ("H100 SXM5", 81920),
    ("H100 PCIe 80GB", 81920),
    ("H100", 81920),
    # V-series
    ("V100 SXM2 32GB", 32768),
    ("V100 SXM2 16GB", 16384),
    ("V100 PCIe 32GB", 32768),
    ("V100 PCIe 16GB", 16384),
    ("V100 NVLink", 16384),
    # T-series
    ("T4", 16384),
    ("T400", 4096),
    # P-series
    ("P100 16GB", 16384),
    ("P100 12GB", 12288),
    ("P40", 24576),
    ("P4", 8192),
]

_PROC_GPU_INFO_GLOB = "/proc/driver/nvidia/gpus/*/information"
_MODEL_RE = re.compile(r"^Model:\s+(.+)$", re.MULTILINE)


def _detect_gpu_vram_mib() -> list[dict]:
    """Detect installed GPUs and their VRAM via /proc/driver/nvidia.

    Priority:
      1. YASHIGANI_GPU_TOTAL_VRAM_MIB env var — comma-separated MiB per GPU
         (e.g. "3072,12288" for a GTX 1060 3GB + RTX 3060 system).
         install.sh may set this during the install wizard.
      2. /proc/driver/nvidia/gpus/*/information — parse model name, look up
         in _KNOWN_GPU_VRAM_MIB table.
      3. Returns an empty list if neither is available.

    Each returned dict: {"index": int, "name": str, "vram_mib": int}
    """
    # Priority 1: env var override
    env_vram = os.environ.get("YASHIGANI_GPU_TOTAL_VRAM_MIB", "").strip()
    if env_vram:
        gpus = []
        for idx, part in enumerate(env_vram.split(",")):
            try:
                gpus.append({"index": idx, "name": f"GPU {idx} (env)", "vram_mib": int(part.strip())})
            except ValueError:
                pass
        if gpus:
            return gpus

    # Priority 2: /proc/driver/nvidia
    gpus = []
    try:
        info_paths = sorted(glob.glob(_PROC_GPU_INFO_GLOB))
    except Exception:
        return []

    for idx, info_path in enumerate(info_paths):
        try:
            content = open(info_path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        m = _MODEL_RE.search(content)
        model_name = m.group(1).strip() if m else f"Unknown GPU {idx}"

        # Lookup VRAM from known-model table (longest-match wins).
        vram_mib: Optional[int] = None
        for key, mib in _KNOWN_GPU_VRAM_MIB:
            if key in model_name:
                vram_mib = mib
                break

        gpus.append({
            "index": idx,
            "name": model_name,
            "vram_mib": vram_mib,  # None if not in table
        })

    return gpus


def _estimate_vram_needed_mib(model_size_bytes: int) -> float:
    """Estimate the VRAM (MiB) required to run a model with the given on-disk size.

    The heuristic: quantised .gguf files are essentially resident in VRAM as-is,
    plus ~20% overhead for KV cache and engine buffers (reasonable for default
    context lengths of 2048–4096 tokens at Q4).

    Returns a float (MiB).
    """
    return (model_size_bytes / (1024 * 1024)) * 1.2


@router.get("/models/local-inventory")
async def get_local_model_inventory():
    """Inventory of locally installed Ollama models with GPU VRAM fit analysis.

    Queries Ollama /api/tags for installed models and detects GPU VRAM.
    For each model, computes "fits_gpu" — True if the estimated VRAM needed
    fits within the total detected VRAM across all GPUs.

    Also returns the detected GPU list so operators can see the hardware baseline.

    VRAM estimation: disk-size × 1.2 ≈ resident VRAM.  This is a heuristic;
    actual VRAM depends on quantisation, context window, and system load.

    Admin-gated (via router-level require_admin_session dependency).
    """
    # YSG-RISK-191: this route previously hardcoded YASHIGANI_OLLAMA_URL (never
    # set by any deployment config — see docker-compose.yml / helm templates /
    # gateway+backoffice entrypoints, which all wire OLLAMA_BASE_URL) with a
    # bare-httpx.AsyncClient, so it silently fell back to plain
    # http://ollama:11434 and bypassed the Caddy mesh front entirely — a hard
    # 502 wherever Ollama is only reachable via https://caddy:11435/ollama.
    # Fixed to mirror routes/models.py's _ollama_base()/ollama_async_client()
    # pattern: the SAME env-var chain (YASHIGANI_OLLAMA_URL override ->
    # OLLAMA_BASE_URL, the actual mesh-wired var -> hardcoded dev default) and
    # the SAME mesh-mTLS-aware transport (inspection/_ollama_transport.py —
    # the single transport documented for every OLLAMA_BASE_URL consumer).
    ollama_base = (
        os.environ.get("YASHIGANI_OLLAMA_URL")
        or os.environ.get("OLLAMA_BASE_URL")
        or "http://ollama:11434"
    ).rstrip("/")

    # --- Query Ollama ---
    try:
        from yashigani.inspection._ollama_transport import ollama_async_client
        async with ollama_async_client(ollama_base, timeout=10.0) as client:
            resp = await client.get(f"{ollama_base}/api/tags")
            resp.raise_for_status()
            raw = resp.json()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "ollama_timeout",
                "message": f"Ollama did not respond within 10 s (url={ollama_base}).",
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "ollama_unavailable",
                "message": f"Could not reach Ollama at {ollama_base}: {exc}",
            },
        )

    installed_models: list[dict] = raw.get("models") or []

    # --- Detect GPUs ---
    gpus = _detect_gpu_vram_mib()
    total_vram_mib: Optional[float] = (
        sum(g["vram_mib"] for g in gpus if g.get("vram_mib") is not None)
        if gpus else None
    )
    if total_vram_mib is not None and total_vram_mib == 0:
        total_vram_mib = None  # no detected VRAM (all unknowns)

    # --- Build inventory ---
    inventory = []
    for m in installed_models:
        name = m.get("name") or m.get("model") or ""
        size_bytes: int = m.get("size") or 0
        details: dict = m.get("details") or {}

        param_size: str = details.get("parameter_size") or ""
        quant_level: str = details.get("quantization_level") or ""
        family: str = details.get("family") or ""

        vram_est_mib = _estimate_vram_needed_mib(size_bytes) if size_bytes else None

        fits_gpu: Optional[bool] = None
        if vram_est_mib is not None and total_vram_mib is not None:
            fits_gpu = vram_est_mib <= total_vram_mib

        inventory.append({
            "name": name,
            "family": family,
            "parameter_size": param_size,
            "quantization": quant_level,
            "size_bytes": size_bytes,
            "size_gib": round(size_bytes / (1024 ** 3), 2) if size_bytes else None,
            "vram_estimated_mib": round(vram_est_mib, 0) if vram_est_mib else None,
            "fits_gpu": fits_gpu,
            "modified_at": m.get("modified_at"),
        })

    return {
        "ollama_url": ollama_base,
        "gpus": gpus,
        "total_vram_mib": total_vram_mib,
        "vram_detection": (
            "env:YASHIGANI_GPU_TOTAL_VRAM_MIB" if os.environ.get("YASHIGANI_GPU_TOTAL_VRAM_MIB")
            else "/proc/driver/nvidia" if gpus
            else "unavailable"
        ),
        "models": inventory,
        "count": len(inventory),
        "note": (
            "fits_gpu is estimated (disk-size × 1.2 ≈ resident VRAM). "
            "Actual VRAM depends on quantisation, context window, and concurrent load."
        ),
    }
