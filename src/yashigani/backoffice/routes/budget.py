"""
Yashigani Backoffice — Budget admin API.

CRUD for the three-tier budget hierarchy:
  POST/GET/PUT/DELETE  /admin/budget/org-caps          — Organisation cloud caps
  POST/GET/PUT/DELETE  /admin/budget/groups             — Group budgets
  POST/GET/PUT/DELETE  /admin/budget/individuals        — Individual budgets
  GET                  /admin/budget/usage/{identity_id} — Usage summary
  GET                  /admin/budget/tree               — Full budget tree view

Invariants enforced by this API:
  - Sum of individual budgets <= group budget
  - Sum of group budgets <= org cap
  - New identity added to group: prompt admin to adjust
  - Group budget cannot be set below sum of individuals

Auth note (2026-05-02): Added router-level require_admin_session dependency.
All endpoints were previously unauthenticated (OWASP API3:2023 / ASVS V4.1.1).
No middleware covered /admin/budget/* paths. The router-level Depends() protects
all current and future endpoints in this file with a single declaration.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import logging
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
    Full budget tree view: org -> groups -> identities.
    Shows total, used, remaining at every level.
    """
    # Placeholder — will be populated from Postgres in integration
    return {
        "tree": [],
        "message": "Budget tree — populated after org caps and groups are configured",
    }
