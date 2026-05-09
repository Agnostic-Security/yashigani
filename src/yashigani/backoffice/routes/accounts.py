"""
Yashigani Backoffice — Admin account management routes.
Enforces: min 2 total (delete guard), min 2 active (disable guard).
High-value mutating actions (delete, disable, force-reset) require
step-up TOTP re-verification (ASVS V6.8.4).

BOPLA note (issue #90): list_admins and create_admin use explicit
response_model= declarations backed by AdminAccountPublic /
AdminCreateResponse to guarantee that password_hash, totp_secret,
recovery_codes, and lockout counters are never leaked in list responses.
"""

# Last updated: 2026-05-09T00:00:00+01:00
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.backoffice.schemas.bopla import AdminAccountPublic, AdminCreateResponse

router = APIRouter()


class CreateAdminRequest(BaseModel):
    # v0.2.0: admin username must be an email address — used as Grafana alert contact
    username: str = Field(
        min_length=5,
        max_length=254,
        pattern=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    )


class ForceResetRequest(BaseModel):
    action: str = Field(pattern=r"^(password_reset|totp_reprovision)$")


@router.get("")
async def list_admins(session: AdminSession):
    # BOPLA allowlist (#90): AdminAccountPublic strips password_hash, totp_secret,
    # recovery_codes, failed_attempts, locked_until, totp_failed/backoff fields.
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    all_accounts = await state.auth_service.list_accounts()
    accounts = [
        AdminAccountPublic(
            username=r.username,
            account_id=r.account_id,
            email=getattr(r, "email", None),
            disabled=r.disabled,
            force_password_change=r.force_password_change,
            force_totp_provision=r.force_totp_provision,
            created_at=r.created_at,
        ).model_dump()
        for r in all_accounts
        if r.account_tier == "admin"
    ]
    total = await state.auth_service.total_admin_count()
    active = await state.auth_service.active_admin_count()
    return {
        "accounts": accounts,
        "total": total,
        "active": active,
        "min_total": state.admin_min_total,
        "min_active": state.admin_min_active,
        "soft_target": state.admin_soft_target,
        "below_soft_target": total < state.admin_soft_target,
    }


@router.post("")
async def create_admin(body: CreateAdminRequest, session: AdminSession):
    """
    Create an admin account. Server generates a 36-char temporary password
    and a TOTP secret. Both are returned once — caller shares them
    out-of-band. Admin must change password and provision TOTP at first login.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Enforce license tier admin seat limit
    from yashigani.licensing.enforcer import check_admin_seat_limit, LicenseLimitExceeded

    try:
        check_admin_seat_limit(await state.auth_service.total_admin_count())
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "admin_seat_limit_exceeded", "limit": exc.max_val, "current": exc.current},
        )

    if await state.auth_service.get_account(body.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "username_taken"},
        )
    record, temp_password = await state.auth_service.create_admin(
        username=body.username,
        auto_generate=True,
    )

    # Generate TOTP secret for provisioning — installer-privileged path
    # because another admin is onboarding this account out-of-band.
    from yashigani.auth.totp import generate_provisioning

    totp = generate_provisioning(account_name=body.username, issuer="Yashigani")
    await state.auth_service.set_totp_secret_direct(body.username, totp.secret_b32)
    record.totp_secret = totp.secret_b32
    record.force_totp_provision = False  # pre-provisioned

    state.audit_writer.write(_config_event(session.account_id, "admin_account_created", "", body.username))
    # BOPLA allowlist (#90): AdminCreateResponse is the ONLY response type
    # permitted to include totp_secret/temporary_password. This is an explicit
    # one-time-delivery exception documented in bopla-allowlist.md.
    return AdminCreateResponse(
        status="ok",
        account_id=record.account_id,
        username=record.username,
        temporary_password=temp_password,
        totp_secret=totp.secret_b32,
        totp_uri=totp.provisioning_uri,
    ).model_dump()


@router.delete("/{username}")
async def delete_admin(username: str, session: StepUpAdminSession):
    """Delete an admin account. Blocked if total would drop below 2."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    # Guard: min 2 total (ADMIN_MINIMUM_VIOLATION)
    if await state.auth_service.total_admin_count() <= state.admin_min_total:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "ADMIN_MINIMUM_VIOLATION",
                "message": f"Cannot delete: minimum {state.admin_min_total} admin accounts required",
            },
        )

    await state.auth_service.delete_account(username)
    state.audit_writer.write(_config_event(session.account_id, "admin_account_deleted", username, ""))
    return {"status": "ok"}


@router.post("/{username}/disable")
async def disable_admin(username: str, session: StepUpAdminSession):
    """Disable account. Blocked if active count would drop below 2."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})
    if record.disabled:
        return {"status": "ok", "message": "already_disabled"}

    # Guard: min 2 active (ADMIN_ACTIVE_MINIMUM_VIOLATION)
    if await state.auth_service.active_admin_count() <= state.admin_min_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "ADMIN_ACTIVE_MINIMUM_VIOLATION",
                "message": f"Cannot disable: minimum {state.admin_min_active} active admin accounts required",
            },
        )

    await state.auth_service.disable(username)
    state.session_store.invalidate_all_for_account(record.account_id)
    # LF-DISABLE-PARTIAL: suspend identity-registry entries for this admin.
    _suspend_identity_registry_for_account(record.account_id)
    state.audit_writer.write(_config_event(session.account_id, "admin_account_disabled", username, "disabled"))
    return {"status": "ok"}


@router.post("/{username}/enable")
async def enable_admin(username: str, session: AdminSession):
    """
    Re-enable a disabled admin account.

    Iris MISSING-04 / GROUP-2-6: enforce admin seat limit before re-enabling.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Check admin seat limit before re-enable.
    from yashigani.licensing.enforcer import (
        check_admin_seat_limit,
        LicenseLimitExceeded,
        license_limit_exceeded_response,
    )

    try:
        check_admin_seat_limit(await state.auth_service.total_admin_count())
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=license_limit_exceeded_response(exc),
        )

    if not await state.auth_service.enable(username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})
    state.audit_writer.write(_config_event(session.account_id, "admin_account_enabled", username, "enabled"))
    return {"status": "ok"}


@router.post("/{username}/force-reset")
async def force_reset(username: str, body: ForceResetRequest, session: StepUpAdminSession):
    """Force password reset or TOTP reprovision for an admin account."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    if body.action == "password_reset":
        await state.auth_service.force_password_change(username)
        state.session_store.invalidate_all_for_account(record.account_id)
    elif body.action == "totp_reprovision":
        await state.auth_service.force_totp_reprovision(username)
        state.session_store.invalidate_all_for_account(record.account_id)

    state.audit_writer.write(_config_event(session.account_id, f"admin_{body.action}", username, "forced"))
    return {"status": "ok"}


def _suspend_identity_registry_for_account(account_id: str) -> None:
    """Suspend all identity-registry entries owned by account_id.

    LF-DISABLE-PARTIAL (2026-04-27): mirrors users.py equivalent.
    SEC-240-7: now uses suspend_owned_by() — O(1) index lookup instead of
    full registry scan.
    Fail-soft on registry unavailability.
    """
    registry = backoffice_state.identity_registry
    if registry is None:
        import logging as _log

        _log.getLogger(__name__).warning(
            "LF-DISABLE-PARTIAL: identity_registry not available — API keys for account %s NOT suspended",
            account_id,
        )
        return
    try:
        suspended = registry.suspend_owned_by(account_id)
        import logging as _log

        _log.getLogger(__name__).info(
            "LF-DISABLE-PARTIAL: suspended %d identity-registry entries for account %s",
            suspended,
            account_id,
        )
    except Exception as exc:
        import logging as _log

        _log.getLogger(__name__).error(
            "LF-DISABLE-PARTIAL: failed to suspend identity-registry entries for account %s: %s",
            account_id,
            exc,
        )


def _config_event(admin_id: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import ConfigChangedEvent

    return ConfigChangedEvent(
        account_tier="admin",
        admin_account=admin_id,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )
