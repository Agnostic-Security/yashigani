"""
Yashigani 4.0 — Admin workflow-oversight API.

Admin read + disable across ALL users' workflows (cross-user view).
The /user/workflows* routes are BOLA-scoped per owner; these routes
intentionally bypass that scope for admin oversight.

Routes:

  GET    /admin/workflows                  — paginated list of all users' workflows
  GET    /admin/workflows/{wf_id}          — full spec (cross-user)
  GET    /admin/workflows/{wf_id}/runs     — run history (cross-user)
  PATCH  /admin/workflows/{wf_id}          — enable/disable; audit on disable

Auth:
  GET endpoints  → AdminSession
  PATCH          → StepUpAdminSession (EU AI Act Art.14 — disabling a governed
                   workflow is a consequential admin action)

Redis namespaces:
  DB 3 — wf:meta:{wf_id}, wf:workflows:{account_id}  (backoffice metadata)
  DB 6 — wf:spec:{wf_id}, wf:sched:index             (gateway scheduler)

When disabling a workflow the PATCH writes to BOTH DBs so the change takes
effect in the scheduler immediately (no gateway restart required).

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

# Shared helpers — import from the modules that define them to avoid
# any forward-import chaining.
from yashigani.backoffice.routes.user_agents import (
    _decode_hash,
    _get_redis,
)
from yashigani.backoffice.routes.user_workflows import (
    _get_wf_redis,
    _now_iso,
    _run_to_dict,
    _serialise_workflow,
    _wf_key,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AdminPatchWorkflowBody(BaseModel):
    """Body for PATCH /admin/workflows/{wf_id}.

    Only enabled is accepted on the admin plane — name/description edits are
    the owner's prerogative (user-plane PATCH).  The admin surface is
    oversight only: read + disable.
    """
    enabled: Optional[bool] = Field(
        default=None,
        description=(
            "Set to false to disable (suspend) the workflow. "
            "Set to true to re-enable. "
            "Null / absent means no change."
        ),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _scan_all_wf_ids(r) -> list[str]:
    """Return sorted list of all wf_ids across all users via SCAN on DB 3.

    Scans for all ``wf:workflows:*`` set keys and collects members.
    O(N) in the number of workflows — acceptable for admin-plane use.
    """
    all_ids: list[str] = []
    try:
        for raw_key in r.scan_iter(b"wf:workflows:*", count=100):
            key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            raw_ids = r.smembers(key)
            for raw_id in raw_ids:
                wf_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                all_ids.append(wf_id)
    except Exception as exc:
        logger.warning("admin_workflows: SCAN wf:workflows:* failed: %s", exc)
    all_ids.sort()
    return all_ids


def _get_wf_meta_or_404(r, wf_id: str) -> dict:
    """Fetch wf:meta hash for any wf_id; raise 404 if missing."""
    raw = r.hgetall(_wf_key(wf_id))
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    return _decode_hash(raw)


# ===========================================================================
# GET /admin/workflows — paginated list of all users' workflows
# ===========================================================================

@router.get("/admin/workflows")
async def admin_list_workflows(
    session: AdminSession,
    page: int = 1,
    page_size: int = 50,
):
    """List all workflows across all users, paginated.

    Returns compact records (no spec) to keep the response size bounded.
    Use GET /admin/workflows/{wf_id} to fetch the full spec for a specific
    workflow.

    page      — 1-based page number (default 1)
    page_size — records per page (1–200, default 50)
    """
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_page", "message": "page must be >= 1"},
        )
    if page_size < 1 or page_size > 200:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_page_size",
                    "message": "page_size must be 1–200"},
        )

    r = _get_redis()
    all_ids = _scan_all_wf_ids(r)
    total = len(all_ids)

    offset = (page - 1) * page_size
    page_ids = all_ids[offset : offset + page_size]

    workflows = []
    for wf_id in page_ids:
        raw = r.hgetall(_wf_key(wf_id))
        if not raw:
            continue
        meta = _decode_hash(raw)
        workflows.append(_serialise_workflow(wf_id, meta, include_spec=False))

    return {
        "workflows": workflows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


# ===========================================================================
# GET /admin/workflows/{wf_id} — full spec (cross-user)
# ===========================================================================

@router.get("/admin/workflows/{wf_id}")
async def admin_get_workflow(wf_id: str, session: AdminSession):
    """Get any workflow by ID, including the full executor spec.

    No BOLA restriction — the admin plane is an oversight surface.
    """
    r = _get_redis()
    meta = _get_wf_meta_or_404(r, wf_id)
    return _serialise_workflow(wf_id, meta, include_spec=True)


# ===========================================================================
# GET /admin/workflows/{wf_id}/runs — run history (cross-user)
# ===========================================================================

@router.get("/admin/workflows/{wf_id}/runs")
async def admin_list_workflow_runs(
    wf_id: str,
    session: AdminSession,
    limit: int = 50,
):
    """List run history for any workflow (admin cross-user view).

    Reads from the gateway scheduler's Redis DB 6.  Returns 503 if the
    scheduler store is unavailable.

    limit — number of records (1–100, default 50)
    """
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_limit", "message": "limit must be 1–100"},
        )

    # Verify workflow exists in DB 3 first
    r_meta = _get_redis()
    _get_wf_meta_or_404(r_meta, wf_id)

    # Read runs from DB 6 (scheduler namespace)
    r_sched = _get_wf_redis()
    from yashigani.gateway.workflow_scheduler import _redis_list_runs
    runs = _redis_list_runs(r_sched, wf_id, limit=limit)

    return {
        "workflow_id": wf_id,
        "runs": [_run_to_dict(run) for run in runs],
    }


# ===========================================================================
# PATCH /admin/workflows/{wf_id} — enable/disable (StepUp)
# ===========================================================================

@router.patch("/admin/workflows/{wf_id}")
async def admin_patch_workflow(
    wf_id: str,
    body: AdminPatchWorkflowBody,
    session: StepUpAdminSession,
):
    """Enable or disable any user's workflow.

    Requires a fresh step-up TOTP event (ASVS V6.8.4).
    Disabling is the consequential action (EU AI Act Art.14 human-in-the-loop):
    stopping a governed AI workflow is a privileged decision that must be
    explicitly attributed to an authenticated admin with re-confirmed identity.

    On disable:
    1. Writes enabled=0 to DB 3 (wf:meta — admin + user views).
    2. Removes the workflow from the scheduler's sched index in DB 6 so that
       the gateway picks up the change without a restart.
    3. Emits WorkflowAdminDisabledEvent to the tamper-evident audit chain.
    """
    if body.enabled is None:
        # No-op — return early without touching Redis or audit
        return {"workflow_id": wf_id, "updated": []}

    r = _get_redis()
    meta = _get_wf_meta_or_404(r, wf_id)

    # --- Write to DB 3 (metadata) ---
    updates: dict[bytes, bytes] = {
        b"enabled": b"1" if body.enabled else b"0",
        b"updated_at": _now_iso().encode(),
    }
    r.hset(_wf_key(wf_id), mapping=updates)

    # --- Sync to DB 6 (scheduler) on disable so change is immediate ---
    if not body.enabled:
        try:
            r_sched = _get_wf_redis()
            from yashigani.gateway.workflow_scheduler import (
                _redis_get_spec,
                _redis_set_spec,
            )
            spec = _redis_get_spec(r_sched, wf_id)
            if spec is not None:
                spec.enabled = False
                _redis_set_spec(r_sched, spec)
                logger.info(
                    "admin_workflows: scheduler sync — wf_id=%s removed from sched index",
                    wf_id,
                )
        except HTTPException:
            # Scheduler DB 6 unavailable — DB 3 update still applied.
            # The scheduler will respect the enabled=False on its next
            # reload (restart or manual reload_from_redis call).
            logger.warning(
                "admin_workflows: scheduler DB unavailable; DB3 updated, "
                "scheduler sync deferred for wf_id=%s",
                wf_id,
            )
        except Exception as exc:
            logger.warning(
                "admin_workflows: scheduler sync failed for wf_id=%s: %s",
                wf_id, exc,
            )

    # --- Audit on disable ---
    if not body.enabled:
        aw = getattr(backoffice_state, "audit_writer", None)
        if aw is not None:
            try:
                from yashigani.audit.schema import WorkflowAdminDisabledEvent
                aw.write(WorkflowAdminDisabledEvent(
                    admin_account_id=session.account_id,
                    workflow_id=wf_id,
                    owner_identity_id=meta.get(
                        "owner_identity_id", meta.get("account_id", "")
                    ),
                    workflow_name=meta.get("name", "")[:64],
                ))
            except Exception as exc:
                logger.warning(
                    "WorkflowAdminDisabledEvent audit write failed: %s", exc
                )

    action = "disabled" if not body.enabled else "enabled"
    logger.info(
        "admin_workflows: admin=%s %s wf_id=%s (owner=%s)",
        session.account_id, action, wf_id,
        meta.get("owner_identity_id", meta.get("account_id", "?")),
    )
    return {"workflow_id": wf_id, "updated": ["enabled"]}
