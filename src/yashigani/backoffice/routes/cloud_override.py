"""#25 — dual-admin cloud-LLM risk-accepted override (backoffice API).

Two-person control: one admin POSTs /propose (with the specific cloud LLM, a
mandatory justification, and a TTL); a DIFFERENT admin POSTs /approve within the
5-minute window to activate. The OptimizationEngine then permits that cloud LLM
for P1 (CONFIDENTIAL/RESTRICTED) traffic until the TTL expires or /revoke. Scope
is ONLY cloud-vs-local routing for the named LLM — auth/RBAC/inspection unchanged.

API <-> WebUI parity: the dashboard Cloud-Override panel mirrors these endpoints.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.optimization.cloud_override import (
    CloudOverrideError,
    JustificationRequiredError,
    TTLRangeError,
    ApprovalError,
)

router = APIRouter()
_log = logging.getLogger("yashigani.cloud_override")


class ProposeRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    justification: str = Field(min_length=4, max_length=2000)  # ticket #, contract #, CEO email…
    ttl_hours: int = Field(default=4, ge=1, le=72)


def _mgr():
    m = backoffice_state.cloud_override_manager
    if m is None:
        raise HTTPException(status_code=503, detail={"error": "cloud_override_unavailable"})
    return m


@router.get("/status")
async def cloud_override_status(session: AdminSession):  # noqa: ARG001 — auth gate
    return _mgr().status()


@router.post("/propose")
async def cloud_override_propose(body: ProposeRequest, session: StepUpAdminSession):
    """Admin 1 proposes the override (PENDING). A DIFFERENT admin must /approve."""
    try:
        state = _mgr().propose(
            initiator_id=session.account_id,
            provider=body.provider, model=body.model,
            justification=body.justification, ttl_hours=body.ttl_hours,
        )
    except (JustificationRequiredError, TTLRangeError, CloudOverrideError) as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_proposal", "message": str(exc)})
    _log.warning("Admin %s PROPOSED cloud override %s/%s (ttl=%dh) — awaiting 2nd admin",
                 session.account_id, body.provider, body.model, body.ttl_hours)
    return {"status": "pending_approval", "state": state}


@router.post("/approve")
async def cloud_override_approve(session: StepUpAdminSession):
    """Admin 2 approves -> ACTIVE. Must be a different admin from the proposer."""
    try:
        state = _mgr().approve(session.account_id)
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail={"error": "approval_failed", "message": str(exc)})
    _log.warning("Admin %s APPROVED cloud override (now ACTIVE)", session.account_id)
    return {"status": "active", "state": state}


@router.post("/revoke")
async def cloud_override_revoke(session: StepUpAdminSession):
    """Revoke an active or pending override immediately."""
    _mgr().revoke(session.account_id)
    _log.warning("Admin %s REVOKED cloud override", session.account_id)
    return {"status": "revoked"}
