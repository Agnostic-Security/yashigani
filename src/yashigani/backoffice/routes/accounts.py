"""
Yashigani Backoffice — Admin account management routes.
Enforces: min 2 total (delete guard), min 2 active (disable guard).
High-value mutating actions (delete, disable, force-reset) require
step-up TOTP re-verification (ASVS V6.8.4).

BOPLA note (issue #90): list_admins and create_admin use explicit
response_model= declarations backed by AdminAccountPublic /
AdminCreateResponse to guarantee that password_hash, totp_secret,
recovery_codes, and lockout counters are never leaked in list responses.

N1 enforcement (2.25.5): GET /admin/accounts/enforcement exposes the live
admin-count state and whether the system is below the minimum floor.
The UI consumes this to surface "you must add a second admin" banners.
All mutation guards (delete, disable, PUT disable) are also wired here.
"""

# Last updated: 2026-08-04T00:00:00+01:00
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.backoffice.schemas.bopla import AdminAccountPublic, AdminCreateResponse

router = APIRouter()

# Shared admin-email/username shape (v0.2.0: "admin usernames are emails" —
# used as the Grafana alert contact). Reused by CreateAdminRequest.username's
# Pydantic pattern AND by update_admin()'s handler-level validation below —
# see FIND-P-EMAIL for why UpdateAdminRequest.email itself no longer enforces
# this at the Pydantic field level.
_ADMIN_EMAIL_PATTERN = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
_ADMIN_EMAIL_RE = re.compile(_ADMIN_EMAIL_PATTERN)


class CreateAdminRequest(BaseModel):
    # v0.2.0: admin username must be an email address — used as Grafana alert contact
    username: str = Field(
        min_length=5,
        max_length=254,
        pattern=_ADMIN_EMAIL_PATTERN,
    )


class ForceResetRequest(BaseModel):
    action: str = Field(pattern=r"^(password_reset|totp_reprovision)$")


class UpdateAdminRequest(BaseModel):
    """R5 (2.25.5): editable admin-account fields.

    email   — admin usernames are emails; this updates the contact/email column
              (used as the Grafana alert contact). Optional; omit to leave as-is.
    disabled — set the active/disabled status. Optional; omit to leave as-is.
               Honours the same min-active guard as POST /{username}/disable.

    NOTE (SoD-001): account_tier / role is deliberately NOT editable here. Admin
    and user identities are strictly separate by design (separate stores +
    collision guards in create_admin/create_user); flipping a tier in place would
    collapse that boundary. A tier change must go through delete + recreate in the
    correct store. Flagged for design review if in-place role change is wanted.

    FIND-P-EMAIL (LOW, 2026-08-04): the `email` field used to enforce the
    strict admin-email-shape pattern (and a 5-char minimum) directly at the
    Pydantic level. install.sh's random-word bootstrap admin usernames
    (e.g. "wolf" — see install.sh:_gen_admin_usernames) are NOT email-shaped,
    and PostgresLocalAuthService.create_admin() historically defaulted the
    email column to that same bare username — so a bootstrap admin's own
    ORIGINAL seed value could never pass this field's own pattern, making it
    impossible for an operator to revert the email back to its pre-edit
    state (Laura's pentest: admin2 edited admin1's email, then a revert to
    "wolf" 422'd). The strict shape check now happens in the route handler
    below, which ALSO permits reverting to the account's own current
    username verbatim (the exact bootstrap-default state) even when that
    username isn't email-shaped — this is additive (still rejects any OTHER
    non-email garbage), not a general loosening. See also: create_admin()'s
    synthetic "<username>@yashigani.local" seed (pg_auth.py) which prevents
    this from recurring for FRESH bootstraps going forward.
    """
    email: Optional[str] = Field(
        default=None,
        max_length=254,
    )
    disabled: Optional[bool] = None


@router.get("/enforcement")
async def get_enforcement_status(session: AdminSession):
    """N1 (2.25.5): Return the live admin-count enforcement state.

    Designed to be polled by the UI on login and on the Accounts page to surface
    the 'you must add a second admin' banner when total < min_total.

    Response fields:
      total          — total admin accounts (enabled + disabled)
      active         — active (non-disabled) admin accounts
      min_total      — hard floor for total admins (delete guard threshold)
      min_active     — hard floor for active admins (disable guard threshold)
      soft_target    — recommended target for separation of duties
      below_minimum  — True when total < min_total (system is not safe to operate)
      below_active_minimum — True when active < min_active
      below_soft_target    — True when total < soft_target (advisory, not enforced)
      action_required      — True when any hard minimum is unmet

    NIST AC-2, NIST AC-5 / SOC 2 CC6.2 / ASVS V2.1.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    total = await state.auth_service.total_admin_count()
    active = await state.auth_service.active_admin_count()
    below_minimum = total < state.admin_min_total
    below_active_minimum = active < state.admin_min_active
    return {
        "total": total,
        "active": active,
        "min_total": state.admin_min_total,
        "min_active": state.admin_min_active,
        "soft_target": state.admin_soft_target,
        "below_minimum": below_minimum,
        "below_active_minimum": below_active_minimum,
        "below_soft_target": total < state.admin_soft_target,
        "action_required": below_minimum or below_active_minimum,
    }


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
async def create_admin(body: CreateAdminRequest, session: StepUpAdminSession):
    """
    Create an admin account. Server generates a 36-char temporary password
    and a TOTP secret. Both are returned once — caller shares them
    out-of-band. Admin must change password and provision TOTP at first login.

    LAURA-V400-NEW-001 (ASVS V6.8.4): step-up TOTP required — account creation
    is a high-value mutation that a stolen session must not be able to perform
    without fresh TOTP verification. Step-up is checked BEFORE the license-limit
    guard to ensure 401 (step_up_required) is always returned before 402.
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
    # Phase 13: admin tier → SHA-512/8-digit TOTP.
    from yashigani.auth.totp import (
        generate_provisioning,
        TOTP_ALGO_SHA512,
        TOTP_DIGITS_ADMIN,
    )

    totp = generate_provisioning(
        account_name=body.username,
        issuer="Yashigani",
        algorithm=TOTP_ALGO_SHA512,
        digits=TOTP_DIGITS_ADMIN,
    )
    await state.auth_service.set_totp_secret_direct(
        body.username, totp.secret_b32, algorithm=TOTP_ALGO_SHA512
    )
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
async def enable_admin(username: str, session: StepUpAdminSession):
    """
    Re-enable a disabled admin account.

    Iris MISSING-04 / GROUP-2-6: enforce admin seat limit before re-enabling.
    LAURA-V400-NEW-001 (ASVS V6.8.4): step-up TOTP required — re-enabling a
    disabled backdoor account is equivalent in impact to creating one.
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


@router.put("/{username}")
async def update_admin(username: str, body: UpdateAdminRequest, session: StepUpAdminSession):
    """R5 (2.25.5): edit an admin account's email and/or active status.

    Step-up (TOTP) gated, modelled on the other mutating admin routes
    (delete/disable/force-reset). Status changes honour the min-active guard.
    Tier/role is NOT editable here (SoD-001 — see UpdateAdminRequest docstring).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    changed: list[str] = []

    # Email update — guard against colliding with an existing user-tier identity
    # (SoD-001: admin/user identities must stay disjoint).
    if body.email is not None and body.email != getattr(record, "email", None):
        # FIND-P-EMAIL: enforce the admin-email shape here (moved off the
        # Pydantic field so we can also allow reverting to the account's OWN
        # current username verbatim — the exact bootstrap-default state for
        # install.sh's random-word admin usernames, which are not
        # email-shaped). Anything else must still be a well-formed email.
        if body.email != record.username and not _ADMIN_EMAIL_RE.fullmatch(body.email):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "invalid_email",
                    "message": (
                        "email must be a valid email address, or exactly match "
                        "this account's own username (to revert to its default)."
                    ),
                },
            )
        try:
            collision = await state.auth_service.get_account_by_email(body.email)
        except Exception:
            collision = None
        if collision is not None and collision.account_tier == "user":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "admin_user_collision",
                    "message": "A user-tier account already uses this email. "
                               "Admin and user identities must be strictly separate.",
                },
            )
        await state.auth_service.set_email(username, body.email)
        state.audit_writer.write(_config_event(session.account_id, "admin_email_changed", getattr(record, "email", "") or "", body.email, account_tier=session.account_tier))
        changed.append("email")

    # Status update — reuse the enable/disable paths + min-active guard.
    if body.disabled is not None and body.disabled != record.disabled:
        if body.disabled:
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
            _suspend_identity_registry_for_account(record.account_id)
            state.audit_writer.write(_config_event(session.account_id, "admin_account_disabled", username, "disabled", account_tier=session.account_tier))
        else:
            from yashigani.licensing.enforcer import check_admin_seat_limit, LicenseLimitExceeded
            try:
                check_admin_seat_limit(await state.auth_service.total_admin_count())
            except LicenseLimitExceeded as exc:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail={"error": "admin_seat_limit_exceeded", "limit": exc.max_val, "current": exc.current},
                )
            await state.auth_service.enable(username)
            state.audit_writer.write(_config_event(session.account_id, "admin_account_enabled", username, "enabled", account_tier=session.account_tier))
        changed.append("disabled")

    return {"status": "ok", "changed": changed}


def _suspend_identity_registry_for_account(account_id: str) -> None:
    """Suspend the identity-registry entry linked to account_id.

    LF-DISABLE-PARTIAL (2026-04-27): mirrors users.py equivalent.

    FIND-IRIS-SUSPEND-ORGID (2026-08-04): previously delegated to
    registry.suspend_owned_by(account_id) (SEC-240-7) — a BULK op keyed on
    identity:index:org:{org_id} ("suspend every identity under this org"),
    not on account_id. org_id and account_id are different axes: local-auth
    HUMAN identities always register with org_id="" (never populated for
    account_tier="admin" in the first place — admins never register a HUMAN
    identity at all, per auth.py:_register_human_identity_on_login), so this
    call was a no-op regardless. Fixed to resolve the account's own identity
    via the account_id link (identity:account:{account_id} -> identity_id,
    IdentityRegistry.link_account_id()) and suspend just that one identity —
    see users.py's twin function for the full root-cause writeup. For admin
    accounts specifically this remains a no-op in practice (no HUMAN identity
    is ever registered for admin-tier accounts), same observable behaviour as
    before, just for the documented, correct reason instead of a broken
    org_id lookup.

    Fail-soft on registry unavailability or no linked identity.
    """
    import logging as _log

    registry = backoffice_state.identity_registry
    if registry is None:
        _log.getLogger(__name__).warning(
            "LF-DISABLE-PARTIAL: identity_registry not available — API keys for account %s NOT suspended",
            account_id,
        )
        return
    try:
        identity = registry.get_by_account_id(account_id)
        if identity is None:
            _log.getLogger(__name__).info(
                "LF-DISABLE-PARTIAL: no identity-registry entry linked to account %s "
                "— nothing to suspend",
                account_id,
            )
            return
        identity_id = identity["identity_id"]
        if identity.get("status") == "active":
            registry.suspend(identity_id)
            _log.getLogger(__name__).info(
                "LF-DISABLE-PARTIAL: suspended identity %s for account %s "
                "(FIND-IRIS-SUSPEND-ORGID fix — account_id link, not org_id)",
                identity_id, account_id,
            )
        else:
            _log.getLogger(__name__).info(
                "LF-DISABLE-PARTIAL: identity %s for account %s already non-active "
                "(status=%s) — no change",
                identity_id, account_id, identity.get("status"),
            )
    except Exception as exc:
        _log.getLogger(__name__).error(
            "LF-DISABLE-PARTIAL: failed to suspend identity-registry entry for account %s: %s",
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
