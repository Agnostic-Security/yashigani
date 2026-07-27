"""
YSG-RISK-150/132 — break-glass emergency access (backoffice API).

BreakGlassManager (auth/break_glass.py) was instantiated at startup but no
route ever reached activate/approve/revoke/status — the feature (and its
dual-control) was completely unreachable. This router wires it up.

Two-person control, mirroring the working cloud_override.py sibling: one
admin POSTs /activate (TTL only); a DIFFERENT admin POSTs /approve within
the 5-minute window to bring the session ACTIVE. /revoke ends an active or
pending session immediately. All four routes require a fresh step-up
(StepUpAdminSession) — break-glass is emergency root-equivalent access, a
materially higher blast radius than the cloud-override sibling, so /status
is also step-up gated here (cloud_override's /status only requires a plain
admin session; break-glass intentionally does not extend that same latitude).

SECURE BY DEFAULT (no new privilege — this only makes an existing shipped
control reachable and closes its insecure default):
  - /activate ALWAYS calls the manager with require_second_approver=True.
    This is hardcoded here and is never read from the request body, so a
    caller cannot downgrade to immediate single-admin ACTIVE access via this
    route. (auth/break_glass.py's own default was also flipped to True —
    see that module — as defence in depth for any other caller.)
  - The distinct-admin check compares the SAME canonical identity on both
    sides: session.account_id at /activate time is what gets stored as
    "initiated_by"; session.account_id at /approve time is what the manager
    compares it against (auth/break_glass.py:~203). No free-text field is
    ever trusted for this comparison — mirrors the YSG-RISK-128 fix applied
    to permissions.py::approve_declaration and cloud_override.py::approve.
  - A same-admin self-approval attempt fails closed (403).

Note — no per-activation {id} in these routes: BreakGlassManager is a single
global Redis-backed pending/active record (yashigani:break_glass:state), not
a collection of concurrently-trackable sessions — same singleton shape as
CloudLlmOverrideManager. Introducing a multi-instance id would be new
surface the manager does not support; these routes match its actual shape,
mirroring cloud_override.py's own id-less /propose /approve /revoke /status.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.auth.break_glass import (
    AlreadyActiveError,
    ApprovalExpiredError,
    BreakGlassError,
    NotActiveError,
    TTLRangeError,
)
from yashigani.backoffice.middleware import StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

router = APIRouter()
_log = logging.getLogger("yashigani.break_glass")


class ActivateBreakGlassRequest(BaseModel):
    ttl_hours: int = Field(default=4, ge=1, le=72)


def _mgr():
    m = backoffice_state.break_glass_manager
    if m is None:
        raise HTTPException(status_code=503, detail={"error": "break_glass_unavailable"})
    return m


@router.get("/status")
async def break_glass_status(session: StepUpAdminSession):  # noqa: ARG001 — auth gate
    return _mgr().get_break_glass_status()


@router.post("/activate")
async def break_glass_activate(body: ActivateBreakGlassRequest, session: StepUpAdminSession):
    """Admin 1 activates -> PENDING_APPROVAL. A DIFFERENT admin must /approve.

    require_second_approver is hardcoded True — see module docstring.
    """
    try:
        state = _mgr().activate_break_glass(
            user_id=session.account_id,
            ttl_hours=body.ttl_hours,
            require_second_approver=True,
        )
    except TTLRangeError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_ttl", "message": str(exc)})
    except AlreadyActiveError as exc:
        raise HTTPException(status_code=409, detail={"error": "already_active", "message": str(exc)})
    _log.warning(
        "Admin %s ACTIVATED break-glass request (ttl=%dh) — PENDING, awaiting 2nd admin approval",
        session.account_id, body.ttl_hours,
    )
    return {"status": "pending_approval", "state": state}


@router.post("/approve")
async def break_glass_approve(session: StepUpAdminSession):
    """Admin 2 approves -> ACTIVE. Must be a DIFFERENT admin from the one who
    activated the pending request (see module docstring — distinct-admin
    identity source). Self-approval fails closed (403).
    """
    try:
        state = _mgr().approve_break_glass(session.account_id)
    except ApprovalExpiredError as exc:
        raise HTTPException(status_code=409, detail={"error": "approval_expired", "message": str(exc)})
    except NotActiveError as exc:
        raise HTTPException(status_code=409, detail={"error": "no_pending_session", "message": str(exc)})
    except BreakGlassError as exc:
        # Same-admin self-approval reject (distinct-admin check,
        # auth/break_glass.py:~203).
        raise HTTPException(status_code=403, detail={"error": "self_approval_rejected", "message": str(exc)})
    _log.warning("Admin %s APPROVED break-glass (now ACTIVE)", session.account_id)
    return {"status": "active", "state": state}


@router.post("/revoke")
async def break_glass_revoke(session: StepUpAdminSession):
    """Revoke an active or pending break-glass session immediately. Any admin
    may revoke (no distinct-admin requirement on the way out — only on the
    way in), mirroring cloud_override.py's revoke.
    """
    try:
        _mgr().revoke_break_glass(session.account_id)
    except NotActiveError as exc:
        raise HTTPException(status_code=409, detail={"error": "not_active", "message": str(exc)})
    _log.warning("Admin %s REVOKED break-glass", session.account_id)
    return {"status": "revoked"}
