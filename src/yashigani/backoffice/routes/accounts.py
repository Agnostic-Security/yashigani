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

    # SoD-001: reject admin creation if a user-tier account or user identity
    # already exists with the same username/email. Admins and users MUST remain
    # in strictly separate identity stores. Same username = collapsed boundary.
    # This replaces the simple "username_taken" check with tier-aware logic:
    #   - existing record, account_tier == "user"  → SoD-001 collision (HTTP 409 admin_user_collision)
    #   - existing record, account_tier == "admin" → username taken (HTTP 409 username_taken)
    #   - no record by username, but email collision in user store → SoD-001 collision
    # NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    _sod001_existing = await state.auth_service.get_account(body.username)
    if _sod001_existing is not None:
        if _sod001_existing.account_tier == "user":
            # SoD-001: existing user-tier account with same username/email
            state.audit_writer.write(_sod001_collision_event(
                acting_admin_account_id=session.account_id,
                rejected_username=body.username,
                collision_store="user_accounts",
            ))
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "admin_user_collision",
                    "message": (
                        "A user-tier account already exists with this username/email. "
                        "Admin and user identities must be strictly separate. "
                        "The admin must use a different username."
                    ),
                },
            )
        else:
            # Existing admin account — username taken
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "username_taken"},
            )

    # Also check by email column (admin usernames are emails but the email column
    # may contain a different-format record in the user store).
    # get_account_by_email may not exist on all auth backends (fail open; SoD-005 cron catches it).
    try:
        _sod001_by_email = await state.auth_service.get_account_by_email(body.username)
        if _sod001_by_email is not None and _sod001_by_email.account_tier == "user":
            state.audit_writer.write(_sod001_collision_event(
                acting_admin_account_id=session.account_id,
                rejected_username=body.username,
                collision_store="user_accounts",
            ))
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "admin_user_collision",
                    "message": (
                        "A user-tier account already exists with this email address. "
                        "Admin and user identities must be strictly separate. "
                        "The admin must use a different email."
                    ),
                },
            )
    except HTTPException:
        raise
    except Exception:
        pass  # fail open — SoD-005 cron catches residual collisions

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

    state.audit_writer.write(_config_event(session.account_id, "admin_account_created", "", body.username, account_tier=session.account_tier))
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
    state.audit_writer.write(_config_event(session.account_id, "admin_account_deleted", username, "", account_tier=session.account_tier))
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
    state.audit_writer.write(_config_event(session.account_id, "admin_account_disabled", username, "disabled", account_tier=session.account_tier))
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
    state.audit_writer.write(_config_event(session.account_id, "admin_account_enabled", username, "enabled", account_tier=session.account_tier))
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

    state.audit_writer.write(_config_event(session.account_id, f"admin_{body.action}", username, "forced", account_tier=session.account_tier))
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


def _config_event(admin_id: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import ConfigChangedEvent

    return ConfigChangedEvent(
        account_tier=account_tier,
        admin_account=admin_id,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _sod001_collision_event(acting_admin_account_id: str, rejected_username: str, collision_store: str):
    """SoD-001: audit event for admin creation rejection due to user collision."""
    from yashigani.audit.schema import AdminCreateRejectedUserExistsEvent

    return AdminCreateRejectedUserExistsEvent(
        acting_admin_account_id=acting_admin_account_id,
        rejected_username=rejected_username,
        collision_store=collision_store,
    )
