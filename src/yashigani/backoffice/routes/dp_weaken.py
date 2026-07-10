"""
Yashigani Backoffice — Dual-Admin Data-Protection Maker-Checker (LAURA-V400-R2-001).

Implements a TWO-PERSON (dual-admin) approval flow for the three data-protection
WEAKEN directions:
  pii_config       — setting PII mode to pass or log (not enforcing)
  pii_cloud_bypass — enabling cloud bypass (PII reaches cloud LLMs)
  doc_enforcement  — disabling document enforcement

Design:
  Maker (admin A) submits a weaken request via POST .../weaken-requests (step-up).
  The change is NOT applied — it sits in DpWeakenPendingStore (Redis db/3).
  Checker (admin B) approves via POST .../weaken-requests/{id}/approve (step-up).
  Distinct-admin check is enforced server-side: the maker cannot approve their
  own request (403 returned).
  Any admin (step-up) can reject via POST .../weaken-requests/{id}/reject.
  STRENGTHEN direction (tightening) is NOT routed here — applied immediately
  by the pii.py / documents.py routes with single-admin step-up.

Fail-closed:
  If fewer than 2 active (non-disabled) admin accounts exist, the weaken request
  is REFUSED at submission time with 409 (conflict — cannot guarantee a second
  approver exists).  This prevents a solo-admin from submitting a request that
  can never be approved.

Routes (mounted under /admin/data-protection):
  GET  /status                             — current state of all three controls
  GET  /weaken-requests                    — list pending requests
  POST /weaken-requests                    — maker submits (StepUpAdminSession)
  POST /weaken-requests/{id}/approve       — checker approves (StepUpAdminSession)
  POST /weaken-requests/{id}/reject        — checker rejects (StepUpAdminSession)

Audit:
  Every lifecycle event (requested, approved, rejected) emits a tamper-evident
  audit-chain event (DataProtectionWeakenRequestedEvent etc.).
  The applied config change also emits a ConfigChangedEvent so the change
  appears in both chains.

Security properties:
  - Maker CANNOT approve own request (distinct-admin check, server-side).
  - <2 active admins → refuse to create pending request (fail-closed).
  - All mutation endpoints require StepUpAdminSession (fresh TOTP).
  - Pending requests expire after 24h TTL (no stale approvals).
  - Store returns 503 if DpWeakenPendingStore is not wired (fail-closed).
  - Config changes are applied in-process to backoffice_state (same target
    as the direct pii/documents routes — consistent, no race).

Last updated: 2026-07-02T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.pii.detector import PiiMode, PiiType

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# PII mode classification helpers
# ---------------------------------------------------------------------------

_NON_ENFORCING_MODES = frozenset({"pass", "log"})   # weakened state
_ENFORCING_MODES = frozenset({"redact", "pseudonymize", "block"})


def _pii_mode_is_weakened(mode: str) -> bool:
    """True when the mode provides no active data-protection (pass or log)."""
    return mode in _NON_ENFORCING_MODES


def _pii_mode_is_enforcing(mode: str) -> bool:
    return mode in _ENFORCING_MODES


# ---------------------------------------------------------------------------
# Store / tenant helpers (fail-closed)
# ---------------------------------------------------------------------------

def _install_tenant() -> str:
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


def _dp_store():
    """Return the wired DpWeakenPendingStore or 503 (fail-closed)."""
    store = backoffice_state.dp_weaken_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "dp_weaken_store_unavailable",
                "message": (
                    "Data-protection weaken store not initialised "
                    "(Redis db/3 unavailable)."
                ),
            },
        )
    return store


async def _require_at_least_two_active_admins() -> None:
    """Raise 409 if fewer than 2 active admin accounts exist.

    Fail-closed: if the auth_service is not wired we refuse rather than
    allowing a solo-admin to submit unapprovable weaken requests."""
    auth_svc = backoffice_state.auth_service
    if auth_svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "auth_service_unavailable",
                "message": "Cannot verify active admin count — auth service not ready.",
            },
        )
    active = await auth_svc.active_admin_count()
    if active < 2:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "insufficient_active_admins",
                "active_admins": active,
                "required": 2,
                "message": (
                    f"Dual-admin approval requires at least 2 active admin accounts. "
                    f"Only {active} active admin(s) found. "
                    "Add a second admin before submitting data-protection weaken requests."
                ),
            },
        )


def _write_audit(event: Any) -> None:
    """Best-effort audit write — never blocks the mutation."""
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(event)
        except Exception as exc:
            logger.error(
                "dp_weaken: audit write failed event_type=%s: %s",
                getattr(event, "event_type", "?"), exc,
            )
    else:
        logger.warning(
            "dp_weaken: no audit_writer — %s NOT written",
            getattr(event, "event_type", "?"),
        )


# ---------------------------------------------------------------------------
# Apply helpers (called on approve — apply the config to backoffice_state)
# ---------------------------------------------------------------------------

def _apply_pii_config(to_state: dict) -> None:
    """Apply a pending pii_config to backoffice_state."""
    backoffice_state.pii_config = {  # type: ignore[attr-defined]
        "mode": to_state["mode"],
        "enabled_types": to_state.get("enabled_types", [t.value for t in PiiType]),
    }


def _apply_pii_cloud_bypass(to_state: dict) -> None:
    """Apply a pending pii_cloud_bypass to backoffice_state."""
    backoffice_state.pii_cloud_bypass = bool(to_state.get("enabled", True))  # type: ignore[attr-defined]


def _apply_doc_enforcement(to_state: dict) -> None:
    """Apply a pending doc_enforcement change to backoffice_state."""
    backoffice_state.document_enforcement_enabled = bool(to_state.get("enabled", False))  # type: ignore[attr-defined]


def _apply_change(control: str, to_state: dict) -> None:
    """Dispatch apply to the correct helper."""
    if control == "pii_config":
        _apply_pii_config(to_state)
    elif control == "pii_cloud_bypass":
        _apply_pii_cloud_bypass(to_state)
    elif control == "doc_enforcement":
        _apply_doc_enforcement(to_state)
    else:
        raise ValueError(f"Unknown control: {control!r}")


# ---------------------------------------------------------------------------
# Current-state helpers (for status endpoint and from_state capture)
# ---------------------------------------------------------------------------

def _current_pii_config() -> dict:
    cfg = getattr(backoffice_state, "pii_config", None)
    if cfg is None:
        from yashigani.pii.detector import PiiMode, PiiType
        cfg = {
            "mode": PiiMode.LOG.value,
            "enabled_types": [t.value for t in PiiType],
        }
    return {"mode": cfg.get("mode", "log"), "enabled_types": cfg.get("enabled_types", [])}


def _current_pii_cloud_bypass() -> dict:
    enabled = bool(getattr(backoffice_state, "pii_cloud_bypass", False))
    return {"enabled": enabled}


def _current_doc_enforcement() -> dict:
    override = getattr(backoffice_state, "document_enforcement_enabled", None)
    if override is not None:
        enabled = bool(override)
    else:
        from yashigani.documents.config import is_document_enforcement_enabled
        enabled = is_document_enforcement_enabled()
    return {"enabled": enabled}


def _is_pii_config_weakened(state: dict) -> bool:
    return _pii_mode_is_weakened(state.get("mode", "log"))


def _is_pii_bypass_weakened(state: dict) -> bool:
    return bool(state.get("enabled", False))


def _is_doc_enforcement_weakened(state: dict) -> bool:
    return not bool(state.get("enabled", True))


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class WeakenRequestBody(BaseModel):
    """Maker submits one of three weaken requests.

    The control names exactly what the requester wants to change.
    The to_state payload describes the desired (weakened) configuration.
    """
    control: str = Field(
        description=(
            "Which data-protection control to weaken. One of: "
            "pii_config | pii_cloud_bypass | doc_enforcement"
        ),
        pattern=r"^(pii_config|pii_cloud_bypass|doc_enforcement)$",
    )
    # For pii_config:     {"mode": "pass"|"log", "enabled_types": [...]}
    # For pii_cloud_bypass: {"enabled": true}
    # For doc_enforcement: {"enabled": false}
    to_state: dict = Field(
        description="Desired weakened configuration payload for the named control.",
    )


# ---------------------------------------------------------------------------
# Status endpoint (no step-up; read-only — for dashboard warning banner)
# ---------------------------------------------------------------------------

@router.get("/status")
async def data_protection_status(session: AdminSession):
    """Return the current state of all three data-protection controls.

    Used by the dashboard warning banner to identify any weakened states.
    GET — no step-up required (read-only).
    """
    pii_cfg = _current_pii_config()
    pii_bypass = _current_pii_cloud_bypass()
    doc_enf = _current_doc_enforcement()

    warnings = []
    if _is_pii_config_weakened(pii_cfg):
        warnings.append({
            "control": "pii_config",
            "message": f"PII scanning is DISABLED (mode={pii_cfg['mode']!r})",
        })
    if _is_pii_bypass_weakened(pii_bypass):
        warnings.append({
            "control": "pii_cloud_bypass",
            "message": "Cloud bypass ENABLED — PII may reach cloud LLMs",
        })
    if _is_doc_enforcement_weakened(doc_enf):
        warnings.append({
            "control": "doc_enforcement",
            "message": "Document enforcement OFF",
        })

    # Pending count for the badge
    try:
        store = _dp_store()
        pending_count = store.count_for_tenant(_install_tenant())
    except HTTPException:
        pending_count = 0

    return {
        "pii_config": {**pii_cfg, "weakened": _is_pii_config_weakened(pii_cfg)},
        "pii_cloud_bypass": {**pii_bypass, "weakened": _is_pii_bypass_weakened(pii_bypass)},
        "doc_enforcement": {**doc_enf, "weakened": _is_doc_enforcement_weakened(doc_enf)},
        "any_weakened": len(warnings) > 0,
        "warnings": warnings,
        "pending_weaken_requests": pending_count,
    }


# ---------------------------------------------------------------------------
# List pending weaken requests
# ---------------------------------------------------------------------------

@router.get("/weaken-requests")
async def list_weaken_requests(session: AdminSession):
    """List all pending data-protection weaken requests for this tenant.

    Always 200; empty list means nothing is pending."""
    store = _dp_store()
    return {"pending": store.list_for_tenant(_install_tenant())}


# ---------------------------------------------------------------------------
# Submit weaken request (MAKER — admin A, step-up required)
# ---------------------------------------------------------------------------

@router.post("/weaken-requests", status_code=202)
async def submit_weaken_request(
    body: WeakenRequestBody,
    session: StepUpAdminSession,
):
    """Submit a data-protection weaken request (maker step).

    The change is NOT applied immediately. It becomes a PENDING request
    that a DIFFERENT admin (checker) must approve with step-up TOTP.

    Fail-closed: if fewer than 2 active admin accounts exist, the request
    is refused (409) — there is no second admin to approve it.

    The requester CANNOT approve their own request (enforced server-side
    on the approve endpoint).

    Validates that the to_state is actually a weakening:
      - pii_config: mode must be pass or log
      - pii_cloud_bypass: enabled must be true
      - doc_enforcement: enabled must be false
    """
    # Fail-closed: need at least 2 active admins.
    await _require_at_least_two_active_admins()

    control = body.control
    to_state = body.to_state

    # Validate the to_state actually represents a weakening.
    if control == "pii_config":
        mode = to_state.get("mode", "")
        if mode not in _NON_ENFORCING_MODES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "not_a_weaken",
                    "message": (
                        f"pii_config mode {mode!r} is enforcing, not weakening. "
                        "Use PUT /admin/pii/config directly for strengthening."
                    ),
                },
            )
    elif control == "pii_cloud_bypass":
        if not bool(to_state.get("enabled", False)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "not_a_weaken",
                    "message": (
                        "pii_cloud_bypass enabled=false is a strengthen. "
                        "Use PUT /admin/pii/cloud-bypass directly."
                    ),
                },
            )
    elif control == "doc_enforcement":
        if bool(to_state.get("enabled", True)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "not_a_weaken",
                    "message": (
                        "doc_enforcement enabled=true is a strengthen. "
                        "Use PUT /admin/documents/enforcement directly."
                    ),
                },
            )

    # Capture current (enforcing) state.
    if control == "pii_config":
        from_state = _current_pii_config()
    elif control == "pii_cloud_bypass":
        from_state = _current_pii_cloud_bypass()
    else:
        from_state = _current_doc_enforcement()

    store = _dp_store()
    row = store.create_request(
        tenant_id=_install_tenant(),
        requester_id=session.account_id,
        control=control,
        from_state=from_state,
        to_state=to_state,
    )

    # Audit: DATA_PROTECTION_WEAKEN_REQUESTED
    from yashigani.audit.schema import DataProtectionWeakenRequestedEvent
    _write_audit(DataProtectionWeakenRequestedEvent(
        admin_account=session.account_id,
        request_id=row["request_id"],
        control=control,
        from_state=from_state,
        to_state=to_state,
    ))

    logger.warning(
        "dp_weaken REQUESTED: id=%s control=%s requester=%s "
        "from=%s to=%s — awaiting second-admin approval",
        row["request_id"], control, session.account_id,
        from_state, to_state,
    )

    return {
        "status": "pending",
        "request_id": row["request_id"],
        "control": control,
        "from_state": from_state,
        "to_state": to_state,
        "requested_at": row["requested_at"],
        "expires_at": row["expires_at"],
        "message": (
            "Weaken request created and is PENDING approval by a second admin. "
            "The change has NOT been applied. A different admin must approve "
            "via POST /admin/data-protection/weaken-requests/"
            f"{row['request_id']}/approve with step-up TOTP."
        ),
    }


# ---------------------------------------------------------------------------
# Approve (CHECKER — admin B, step-up, distinct-admin enforced server-side)
# ---------------------------------------------------------------------------

@router.post("/weaken-requests/{request_id}/approve")
async def approve_weaken_request(
    request_id: str,
    session: StepUpAdminSession,
):
    """Approve a pending data-protection weaken request (checker step).

    SECURITY:
    - Requires step-up TOTP (StepUpAdminSession).
    - DISTINCT-ADMIN ENFORCED: the maker (requester) CANNOT approve their
      own request. Returns 403 if the session account_id == requester_id.
    - The config change is applied and audited atomically (best-effort audit).
    - On success, the pending request is consumed from the store.
    """
    store = _dp_store()
    tenant = _install_tenant()

    row = store.get(request_id, tenant)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "weaken_request_not_found",
                "message": (
                    "No pending weaken request found with this ID "
                    "(may have expired or already been resolved)."
                ),
            },
        )

    # DISTINCT-ADMIN CHECK — server-side; must not trust any client header.
    requester_id = row["requester_id"]
    if session.account_id == requester_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "self_approval_forbidden",
                "message": (
                    "The requester cannot approve their own weaken request. "
                    "A DIFFERENT admin must perform the approval."
                ),
            },
        )

    control = row["control"]
    from_state = row["from_state"]
    to_state = row["to_state"]

    # Audit FIRST (before apply — so the audit record exists even if apply fails).
    from yashigani.audit.schema import DataProtectionWeakenApprovedEvent
    _write_audit(DataProtectionWeakenApprovedEvent(
        admin_account=session.account_id,
        requester_id=requester_id,
        request_id=request_id,
        control=control,
        from_state=from_state,
        to_state=to_state,
    ))

    # Apply the config change.
    try:
        _apply_change(control, to_state)
    except Exception as exc:
        logger.error(
            "dp_weaken APPROVE: apply failed for %s control=%s: %s",
            request_id, control, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "apply_failed",
                "message": "Config change could not be applied — request remains pending.",
            },
        ) from exc

    # Emit ConfigChangedEvent so the change appears in both chains.
    from yashigani.audit.schema import ConfigChangedEvent
    _write_audit(ConfigChangedEvent(
        admin_account=session.account_id,
        setting=control,
        previous_value=str(from_state),
        new_value=str(to_state),
    ))

    # Consume the pending entry.
    store.resolve(request_id, tenant)

    logger.warning(
        "dp_weaken APPROVED + APPLIED: id=%s control=%s "
        "requester=%s approver=%s from=%s to=%s",
        request_id, control, requester_id, session.account_id,
        from_state, to_state,
    )

    return {
        "status": "approved_and_applied",
        "request_id": request_id,
        "control": control,
        "from_state": from_state,
        "to_state": to_state,
        "approved_by": session.account_id,
        "message": (
            f"Weaken request approved. {control!r} has been set to "
            f"{to_state!r}. The change is now active."
        ),
    }


# ---------------------------------------------------------------------------
# Reject (CHECKER — any other admin, step-up required)
# ---------------------------------------------------------------------------

@router.post("/weaken-requests/{request_id}/reject")
async def reject_weaken_request(
    request_id: str,
    session: StepUpAdminSession,
):
    """Reject a pending data-protection weaken request.

    Any admin (with step-up) can reject — including the maker themselves.
    No config change is applied; the protection control remains in its
    current enforcing state.  The pending entry is consumed.
    """
    store = _dp_store()
    tenant = _install_tenant()

    row = store.get(request_id, tenant)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "weaken_request_not_found",
                "message": (
                    "No pending weaken request found with this ID "
                    "(may have expired or already been resolved)."
                ),
            },
        )

    control = row["control"]
    requester_id = row["requester_id"]
    from_state = row["from_state"]
    to_state = row["to_state"]

    # Audit.
    from yashigani.audit.schema import DataProtectionWeakenRejectedEvent
    _write_audit(DataProtectionWeakenRejectedEvent(
        admin_account=session.account_id,
        requester_id=requester_id,
        request_id=request_id,
        control=control,
        from_state=from_state,
        to_state=to_state,
    ))

    # Consume the pending entry.
    store.resolve(request_id, tenant)

    logger.warning(
        "dp_weaken REJECTED: id=%s control=%s requester=%s rejector=%s",
        request_id, control, requester_id, session.account_id,
    )

    return {
        "status": "rejected",
        "request_id": request_id,
        "control": control,
        "rejected_by": session.account_id,
        "message": (
            f"Weaken request rejected. {control!r} remains in its "
            "current enforcing state. No change was applied."
        ),
    }
