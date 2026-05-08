"""
Yashigani Backoffice — Admin-triggered secret rotation (v2.23.3).

POST /api/v1/admin/secrets/rotate

Step-up TOTP required (ASVS V6.8.4).
Audit events: SECRET_ROTATION_REQUESTED, SECRET_ROTATION_SUCCEEDED,
              SECRET_ROTATION_FAILED (immutable floor: masking_applied=True).

Supported secrets:
  postgres_password | redis_password | jwt_signing_key | hmac_key | all

Failure model: if the rotation fails mid-way, the rotator reverts to the old
secret. The audit event records whether revert succeeded or failed.

Last updated: 2026-05-07T00:00:00+01:00

ASVS: V6.8.4 (step-up), V7.1.2 (audit log on every rotation), V12.4.1 (secret mgmt).
"""
from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from yashigani.backoffice.middleware import StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.audit.schema import (
    SecretRotationRequestedEvent,
    SecretRotationSucceededEvent,
    SecretRotationFailedEvent,
)
from yashigani.secrets.rotator import SecretName, SecretRotator

router = APIRouter(prefix="/api/v1/admin/secrets", tags=["secrets"])
_log = logging.getLogger("yashigani.backoffice.secrets")

# Allowed secret name literals (also validated via SecretName enum)
_VALID_SECRETS = {s.value for s in SecretName}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class RotateRequest(BaseModel):
    secret: str

    @field_validator("secret")
    @classmethod
    def _validate_secret_name(cls, v: str) -> str:
        if v not in _VALID_SECRETS:
            raise ValueError(
                f"Invalid secret name '{v}'. Allowed: {sorted(_VALID_SECRETS)}"
            )
        return v


class ChildRotationResult(BaseModel):
    secret: str
    success: bool
    rotated_at: str
    error: str | None = None
    reverted: bool = False
    revert_failed: bool = False


class RotateResponse(BaseModel):
    request_id: str
    secret: str
    success: bool
    rotated_at: str
    error: str | None = None
    reverted: bool = False
    revert_failed: bool = False
    child_results: list[ChildRotationResult] = []
    warning: str | None = None


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/rotate", response_model=RotateResponse)
async def rotate_secret(
    body: RotateRequest,
    session: StepUpAdminSession,
) -> RotateResponse:
    """
    Admin-triggered secret rotation.

    Requires fresh step-up TOTP (ASVS V6.8.4).
    Writes audit events for request, success, and failure.
    Secret values are NEVER written to audit logs.
    """
    request_id = str(uuid.uuid4())
    secret_name = SecretName(body.secret)
    admin = session.account_id
    audit_writer = backoffice_state.audit_writer

    # --- Audit: REQUEST ---
    if audit_writer:
        try:
            audit_writer.write(
                SecretRotationRequestedEvent(
                    admin_account=admin,
                    secret_name=body.secret,
                    request_id=request_id,
                )
            )
        except Exception as exc:
            _log.error("Audit write failed for SECRET_ROTATION_REQUESTED: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "audit_failure",
                    "message": "Cannot proceed: audit log write failed (fail-closed)",
                },
            )

    # --- Execute rotation ---
    rotator = SecretRotator()
    result = await rotator.rotate(secret_name)

    # --- Audit: SUCCEEDED or FAILED ---
    if audit_writer:
        if result.success:
            try:
                audit_writer.write(
                    SecretRotationSucceededEvent(
                        admin_account=admin,
                        secret_name=result.secret,
                        request_id=request_id,
                        rotated_at=result.rotated_at,
                    )
                )
            except Exception as exc:
                _log.error("Audit write failed for SECRET_ROTATION_SUCCEEDED: %s", exc)
                # Rotation already completed — log and continue
        else:
            try:
                audit_writer.write(
                    SecretRotationFailedEvent(
                        admin_account=admin,
                        secret_name=result.secret,
                        request_id=request_id,
                        failure_reason=result.error or "unknown",
                        reverted=result.reverted,
                        revert_failed=result.revert_failed,
                        severity="CRITICAL" if result.revert_failed else "",
                    )
                )
            except Exception as exc:
                _log.error("Audit write failed for SECRET_ROTATION_FAILED: %s", exc)

    # Log revert-failed at CRITICAL level for alerting
    if result.revert_failed:
        _log.critical(
            "SECRET ROTATION REVERT FAILED for '%s' (request_id=%s admin=%s) — "
            "manual intervention required: the new password was written to the DB "
            "but the secret file may be inconsistent.",
            result.secret, request_id, admin,
        )

    # Build response — HTTP 200 even on rotation failure (caller inspects success field)
    warning: str | None = None
    if result.revert_failed:
        warning = (
            "CRITICAL: rotation failed AND secret revert failed. "
            "Manual intervention required — services may be in inconsistent state."
        )
    elif result.reverted and not result.revert_failed:
        warning = "Rotation failed; old secret has been restored."

    return RotateResponse(
        request_id=request_id,
        secret=result.secret,
        success=result.success,
        rotated_at=result.rotated_at,
        error=result.error,
        reverted=result.reverted,
        revert_failed=result.revert_failed,
        child_results=[
            ChildRotationResult(
                secret=c.secret,
                success=c.success,
                rotated_at=c.rotated_at,
                error=c.error,
                reverted=c.reverted,
                revert_failed=c.revert_failed,
            )
            for c in result.child_results
        ],
        warning=warning,
    )
