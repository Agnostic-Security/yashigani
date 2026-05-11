"""
Yashigani Backoffice — User/Operator account management routes.
Full reset requires admin TOTP re-verification (ASVS V2.8).
Delete/disable/full-reset require step-up TOTP (ASVS V6.8.4).
Delete blocked if last user (USER_MINIMUM_VIOLATION).

BOPLA note (issue #90): list_users and create_user use explicit
response construction via UserAccountPublic / UserCreateResponse to
guarantee that password_hash, totp_secret, recovery_codes, and lockout
counters are never leaked in list responses.
"""

# Last updated: 2026-05-09T00:00:00+01:00
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.auth.totp import generate_provisioning
from yashigani.backoffice.schemas.bopla import UserAccountPublic, UserCreateResponse

router = APIRouter()


class FullResetRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: Optional[str] = Field(
        default=None,
        max_length=254,
        pattern=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    )


@router.get("")
async def list_users(session: AdminSession):
    # BOPLA allowlist (#90): UserAccountPublic strips password_hash, totp_secret,
    # recovery_codes, failed_attempts, locked_until, totp_failed/backoff fields.
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    accounts = await state.auth_service.list_accounts()
    users = [
        UserAccountPublic(
            username=r.username,
            account_id=r.account_id,
            email=getattr(r, "email", None),
            disabled=r.disabled,
            force_password_change=r.force_password_change,
            force_totp_provision=r.force_totp_provision,
            created_at=r.created_at,
        ).model_dump()
        for r in accounts
        if r.account_tier == "user"
    ]
    return {
        "users": users,
        "total": await state.auth_service.total_user_count(),
        "min_total": state.user_min_total,
    }


@router.post("")
async def create_user(body: CreateUserRequest, session: AdminSession):
    """
    Create a user account. Server generates a 16-char temporary password
    and a TOTP secret. Both are returned once — admin shares them
    out-of-band with the user. User must change password and provision
    TOTP at first login.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Enforce license tier end-user limit
    from yashigani.licensing.enforcer import check_end_user_limit, LicenseLimitExceeded

    try:
        check_end_user_limit(await state.auth_service.total_user_count())
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "end_user_limit_exceeded", "limit": exc.max_val, "current": exc.current},
        )

    if await state.auth_service.get_account(body.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "username_taken"},
        )

    from yashigani.auth.password import generate_password

    temp_password = generate_password(36)
    record = await state.auth_service.create_user(body.username, temp_password)
    if body.email:
        await state.auth_service.set_email(body.username, body.email)
        record.email = body.email

    # Generate TOTP secret for provisioning — installer-privileged path
    # because the admin is performing an out-of-band TOTP delivery.
    totp = generate_provisioning(account_name=body.username, issuer="Yashigani")
    await state.auth_service.set_totp_secret_direct(body.username, totp.secret_b32)
    record.totp_secret = totp.secret_b32
    record.force_totp_provision = False  # pre-provisioned, user just needs the URI

    state.audit_writer.write(_config_event(session.account_id, "user_account_created", "", body.username))
    # BOPLA allowlist (#90): UserCreateResponse is the ONLY response type
    # permitted to include totp_secret/temporary_password. This is an explicit
    # one-time-delivery exception documented in bopla-allowlist.md.
    return UserCreateResponse(
        status="ok",
        account_id=record.account_id,
        username=body.username,
        temporary_password=temp_password,
        totp_secret=totp.secret_b32,
        totp_uri=totp.provisioning_uri,
    ).model_dump()


@router.delete("/{username}")
async def delete_user(username: str, session: StepUpAdminSession):
    """Delete a user. Blocked if last user (USER_MINIMUM_VIOLATION)."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "user":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    if await state.auth_service.total_user_count() <= state.user_min_total:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "USER_MINIMUM_VIOLATION",
                "message": "Cannot delete the last user account",
            },
        )

    await state.auth_service.delete_account(username)
    state.session_store.invalidate_all_for_account(record.account_id)
    state.audit_writer.write(_config_event(session.account_id, "user_account_deleted", username, ""))
    return {"status": "ok"}


@router.post("/{username}/full-reset")
async def full_reset_user(
    username: str,
    body: FullResetRequest,
    session: StepUpAdminSession,
):
    """
    Full reset a user account. Requires admin TOTP re-verification.
    Strips all RBAC roles, sessions, API keys, TOTP, password.
    Retains: username, UUID, audit history.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Resolve admin record for TOTP verification
    admin_record = await state.auth_service.get_account_by_id(session.account_id)

    if admin_record is None or not admin_record.totp_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "admin_totp_not_configured"})

    # full_reset_user handles admin-TOTP verification + target reset atomically
    # inside a single tenant_transaction, using the Postgres-backed replay cache.
    success, reason = await state.auth_service.full_reset_user(
        username,
        admin_totp_secret=admin_record.totp_secret,
        admin_totp_code=body.totp_code,
    )
    if not success:
        if reason == "invalid_admin_totp":
            state.audit_writer.write(_full_reset_totp_failure(admin_record.username, username))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "invalid_admin_totp"},
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": reason},
        )

    target = await state.auth_service.get_account(username)
    if target is not None:
        state.session_store.invalidate_all_for_account(target.account_id)

    state.audit_writer.write(_full_reset_event(admin_record.username, username))
    return {"status": "ok", "message": "User account fully reset"}


@router.post("/{username}/disable")
async def disable_user(username: str, session: StepUpAdminSession):
    # V8.3.2 — authz change propagation: fetch record before disabling so we
    # can immediately invalidate all live sessions for the affected account.
    # LF-DISABLE-PARTIAL fix: also suspend any identity-registry entries
    # (API keys / agent tokens) registered under the same account_id.
    # Mirrors disable_admin in accounts.py.
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "user":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})
    if record.disabled:
        return {"status": "ok", "message": "already_disabled"}
    await state.auth_service.disable(username)
    state.session_store.invalidate_all_for_account(record.account_id)
    # LF-DISABLE-PARTIAL: suspend all identity-registry entries for this account.
    _suspend_identity_registry_for_account(record.account_id)
    state.audit_writer.write(_config_event(session.account_id, "user_account_disabled", username, "disabled"))
    return {"status": "ok"}


@router.post("/{username}/enable")
async def enable_user(username: str, session: AdminSession):
    """
    Re-enable a disabled user account.

    Iris MISSING-04 / GROUP-2-6: enforce end-user seat limit before re-enabling.
    A disabled user is not counted in the canonical end-user count, so re-enabling
    one could push the deployment over the licensed seat limit.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Check seat limit before re-enable — same limit as new user creation.
    from yashigani.licensing.enforcer import (
        check_end_user_limit,
        count_canonical_end_users,
        LicenseLimitExceeded,
        license_limit_exceeded_response,
    )

    try:
        check_end_user_limit(count_canonical_end_users())
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=license_limit_exceeded_response(exc),
        )

    if not await state.auth_service.enable(username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})
    state.audit_writer.write(_config_event(session.account_id, "user_account_enabled", username, "enabled"))
    return {"status": "ok"}


def _suspend_identity_registry_for_account(account_id: str) -> None:
    """Suspend all identity-registry entries owned by account_id.

    LF-DISABLE-PARTIAL (2026-04-27): disable_user must suspend API keys /
    agent tokens registered under the same account, not only browser sessions.
    This prevents a disabled user's API key from remaining usable.

    SEC-240-7: now delegates to suspend_owned_by() — O(1) org_id index lookup
    instead of a full registry scan + Python filter.

    Fail-soft: if identity_registry is unavailable (e.g. community tier with
    no IdentityRegistry wired), log a warning and continue — the session
    invalidation has already executed.
    """
    state = backoffice_state
    registry = state.identity_registry
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


def _full_reset_event(admin_username: str, target: str):
    from yashigani.audit.schema import UserFullResetEvent

    return UserFullResetEvent(
        account_tier="admin",
        admin_account=admin_username,
        admin_totp_verified=True,
        target_user_handle=target,
    )


def _full_reset_totp_failure(admin_username: str, target: str):
    from yashigani.audit.schema import FullResetTotpFailureEvent

    return FullResetTotpFailureEvent(
        account_tier="admin",
        admin_account=admin_username,
        target_user_handle=target,
        failure_reason="invalid",
    )
