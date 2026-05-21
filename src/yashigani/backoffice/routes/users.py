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

# Last updated: 2026-05-15T00:00:00+01:00
from __future__ import annotations

import logging as _log_mod
from typing import Optional

import re as _re

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, model_validator

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.auth.totp import generate_provisioning
from yashigani.backoffice.schemas.bopla import UserAccountPublic, UserCreateResponse

router = APIRouter()
_log = _log_mod.getLogger(__name__)


# ---------------------------------------------------------------------------
# Q1 / v2.23.4 — Username derivation algorithm (Tiago 2026-05-15)
#
# Algorithm:
#   Given email  <local>@<host>:
#   1. Local-part: keep as-is but strip chars outside [a-zA-Z0-9_\-]
#      (plus-tag content KEPT — only the literal '+' is stripped because
#       Tiago verbatim example "aliceworkx (keep)" means alice+work@x.com
#       yields "aliceworkx": strip '+', keep "work", concat with first label "x")
#   2. First domain label: everything before the first '.' in host. Hyphens kept.
#      my-co.com → "my-co"; example.co.uk → "example"; x.com → "x"
#   3. Concatenate: <sanitised-local><first-label>, lowercase
#   4. Truncate to 64 chars
#   5. Residual collision on DB UNIQUE → 409 (handled in create_user handler)
#
# Tiago verbatim examples (2026-05-15):
#   alice@domain.com   → alicedomain
#   alice@my-co.com    → alicemy-co
#   alice+work@x.com   → aliceworkx  (strip '+', keep "work", concat "x")
#   a@x.co.uk          → ax
# ---------------------------------------------------------------------------

_DERIVE_STRIP_RE = _re.compile(r"[^a-zA-Z0-9_\-]")


def _derive_username_from_email(email: str) -> str:
    """
    Derive a username from an email address per Q1 / v2.23.4 algorithm.

    Steps:
      1. Split on '@' to get local-part and host.
      2. Strip unsupported chars from local-part (keep alphanumeric / _ / -;
         strip '+' and any other special char — the content after '+' is
         preserved because stripping '+' only removes the delimiter, not the tag).
      3. Take the first label of the host (before the first '.').
      4. Concatenate, lowercase, truncate to 64 chars.

    Returns the derived username (never empty — at minimum a single char from
    a 1-char local + 1-char TLD will survive; callers are responsible for
    downstream uniqueness enforcement).
    """
    local, _, host = email.partition("@")
    # Step 1 — sanitise local part: strip anything outside [a-zA-Z0-9_\-]
    # This removes '+' (delimiter) while keeping what follows it.
    clean_local = _DERIVE_STRIP_RE.sub("", local)
    # Step 2 — first domain label (before first '.')
    first_label = host.split(".")[0]
    # Step 3 — concatenate, lowercase, truncate
    username = (clean_local + first_label).lower()[:64]
    return username


class FullResetRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ReactivateRequest(BaseModel):
    """Optional reason for the reactivate audit trail."""
    reason: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Optional admin-supplied reason for this reactivation (audit log).",
    )


class CreateUserRequest(BaseModel):
    """
    Gap 1 / v2.23.4 arch-completion: email-as-username for user-tier accounts.

    `email` is now REQUIRED for user-tier account creation (Tiago design intent:
    "email as the username for normal users"). The canonical identity for a user
    is their email address — `username` is a derived convenience alias.

    If `username` is not supplied, it is derived using _derive_username_from_email()
    (Q1 / v2.23.4 algorithm: <sanitised-local><first-domain-label>, lowercase,
    max 64 chars). If supplied explicitly it is accepted as-is (max 64 chars) for
    backward compatibility with older callers.

    Admin records are unchanged — admin usernames are already emails (set at
    create_admin() time in local_auth.py:161 / pg_auth.py:99).
    """
    email: EmailStr = Field(
        description="Email address for the new user (required). Used as the canonical identity.",
    )
    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=64,
        description=(
            "Optional username override. If omitted, derived from email using the "
            "Q1 algorithm: <sanitised-local><first-domain-label>, lowercase, max 64 chars."
        ),
    )

    @model_validator(mode="after")
    def _derive_username_if_absent(self) -> "CreateUserRequest":
        """
        If username is not supplied, derive it from email using the Q1 algorithm.

        Uses model_validator (post-field-validation) so self.email is guaranteed
        to be a valid EmailStr value at this point.
        """
        if self.username is None:
            self.username = _derive_username_from_email(str(self.email))
        return self


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

    Gap 1 / v2.23.4: email is now the canonical identity for user-tier
    accounts. The `email` field is REQUIRED. `username` is derived from
    the email local part if not supplied.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Gap 1: email is required and is the canonical identity.
    # body.email is validated as EmailStr by Pydantic — guaranteed non-None here.
    effective_email = str(body.email)
    # Resolve the effective username (may have been derived from email in validator).
    # _derive_username_if_absent model_validator guarantees non-None; assert for mypy.
    assert body.username is not None, "username must be non-None after model validation"
    effective_username: str = body.username

    # Enforce license tier end-user limit
    from yashigani.licensing.enforcer import check_end_user_limit, LicenseLimitExceeded

    try:
        check_end_user_limit(await state.auth_service.total_user_count())
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "end_user_limit_exceeded", "limit": exc.max_val, "current": exc.current},
        )

    # Check username uniqueness (email-as-username also checked via set_email below).
    if await state.auth_service.get_account(effective_username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "username_taken"},
        )

    from yashigani.auth.password import generate_password

    temp_password = generate_password(36)
    try:
        record = await state.auth_service.create_user(effective_username, temp_password)
    except Exception as exc:
        # Q1: catch DB UNIQUE constraint violation on derived username.
        # asyncpg raises asyncpg.UniqueViolationError (subclass of
        # asyncpg.PostgresError); the message includes "unique" and the
        # constraint name. We catch broadly here and re-raise non-uniqueness
        # errors so we don't swallow unexpected failures.
        exc_str = str(exc).lower()
        if "unique" in exc_str or "duplicate" in exc_str:
            _log.info(
                "Q1 username collision on derived username %r for email %r — returning 409",
                effective_username,
                effective_email,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "username_collision",
                    "message": (
                        f"The username '{effective_username}' derived from email '{effective_email}' "
                        "collides with an existing record. Supply an explicit `username` in the request."
                    ),
                    "derived_username": effective_username,
                },
            ) from exc
        raise
    # Always set email — it is required for user-tier accounts (Gap 1).
    await state.auth_service.set_email(effective_username, effective_email)
    record.email = effective_email

    # Generate TOTP secret for provisioning — installer-privileged path
    # because the admin is performing an out-of-band TOTP delivery.
    totp = generate_provisioning(account_name=effective_username, issuer="Yashigani")
    await state.auth_service.set_totp_secret_direct(effective_username, totp.secret_b32)
    record.totp_secret = totp.secret_b32
    record.force_totp_provision = False  # pre-provisioned, user just needs the URI

    state.audit_writer.write(_config_event(session.account_id, "user_account_created", "", effective_username, account_tier=session.account_tier))
    # BOPLA allowlist (#90): UserCreateResponse is the ONLY response type
    # permitted to include totp_secret/temporary_password. This is an explicit
    # one-time-delivery exception documented in bopla-allowlist.md.
    return UserCreateResponse(
        status="ok",
        account_id=record.account_id,
        username=effective_username,
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
    state.audit_writer.write(_config_event(session.account_id, "user_account_deleted", username, "", account_tier=session.account_tier))
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
            state.audit_writer.write(_full_reset_totp_failure(admin_record.username, username, account_tier=session.account_tier))
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

    state.audit_writer.write(_full_reset_event(admin_record.username, username, account_tier=session.account_tier))
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
    state.audit_writer.write(_config_event(session.account_id, "user_account_disabled", username, "disabled", account_tier=session.account_tier))
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
    state.audit_writer.write(_config_event(session.account_id, "user_account_enabled", username, "enabled", account_tier=session.account_tier))
    return {"status": "ok"}


@router.post("/{username}/reactivate")
async def reactivate_user(username: str, body: ReactivateRequest, session: StepUpAdminSession):
    """
    Reactivate a suspended HUMAN identity for a user-tier account.

    Q3 / v2.23.4 arch-completion: auto-reactivate on login was reverted (Tiago
    directive 2026-05-15 — "admin-action-only, audit-logged"). This endpoint is
    the sole reactivation path.

    Requirements:
      - Caller: admin tier + fresh StepUp (StepUpAdminSession, TOTP within 5 min).
      - Target: must exist, must be account_tier == "user" (404 if admin).
      - Resolves target's HUMAN identity via slug; calls registry.reactivate().
      - Audit-logged with admin actor + target user + optional reason.

    Returns 200 with reactivated identity metadata on success.
    Returns 404 if user not found or not user-tier.
    Returns 404 if no HUMAN identity exists in registry (user never logged in).
    Returns 409 if identity is already active (idempotent — callers may retry).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "user":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    registry = getattr(state, "identity_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "user_identity_registry_unavailable",
                "message": "Identity registry not available on this deployment tier.",
            },
        )

    # Resolve HUMAN identity by slug
    from yashigani.backoffice.routes.auth import _auth_email_to_slug
    email = record.email or f"{record.username}@yashigani.local"
    slug = _auth_email_to_slug(email)
    identity = registry.get_by_slug(slug)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "identity_not_found",
                "message": (
                    f"No HUMAN identity found for user '{username}'. "
                    "Ensure the user has logged in at least once to register their identity."
                ),
            },
        )

    identity_id = identity["identity_id"]
    current_status = identity.get("status", "active")

    if current_status == "active":
        # Idempotent: already active — return success without re-writing Redis.
        return {
            "status": "ok",
            "identity_id": identity_id,
            "identity_status": "active",
            "message": "Identity is already active. No change required.",
        }

    # Reactivate the suspended/inactive identity.
    registry.reactivate(identity_id)

    # Audit log — admin actor + target + reason
    from yashigani.audit.schema import IdentityReactivatedEvent
    state.audit_writer.write(IdentityReactivatedEvent(
        acting_admin_account_id=session.account_id,
        target_username=username,
        target_identity_id=identity_id,
        reason=body.reason or "",
    ))

    _log.info(
        "Q3 admin reactivate: admin=%s target=%s identity_id=%s was_status=%s reason=%r",
        session.account_id,
        username,
        identity_id,
        current_status,
        body.reason,
    )

    return {
        "status": "ok",
        "identity_id": identity_id,
        "identity_status": "active",
        "username": username,
        "message": f"Identity reactivated. User '{username}' can now access /v1/*.",
    }


@router.post("/{username}/api-key")
async def admin_issue_user_api_key(username: str, session: StepUpAdminSession):
    """
    Admin override — issue or rotate a target user's API key.

    Requirements:
      - Caller: admin tier + fresh StepUp (StepUpAdminSession).
      - Target: must exist, must be account_tier == "user".
      - 30-second grace window on the prior token (client transition window).

    Returns plaintext_token ONCE — admin must deliver securely to the user.
    Audit-logged with acting admin identity.

    Gap 4 / v2.23.4 arch-completion — mirrors admin override for agents
    (agents/token_rotation.py pattern).
    """
    state = backoffice_state
    assert state.auth_service is not None
    assert state.audit_writer is not None

    # Resolve target user record
    record = await state.auth_service.get_account(username)
    if record is None or record.account_tier != "user":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    # Registry availability
    registry = getattr(state, "identity_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "user_identity_registry_unavailable",
                "message": "Identity registry not available on this deployment tier.",
            },
        )

    # Resolve target HUMAN identity by slug
    from yashigani.backoffice.routes.auth import _auth_email_to_slug
    email = record.email or f"{record.username}@yashigani.local"
    slug = _auth_email_to_slug(email)
    identity = registry.get_by_slug(slug)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "identity_not_found",
                "message": (
                    f"No HUMAN identity found for user '{username}'. "
                    "Ensure the user has logged in at least once to register their identity."
                ),
            },
        )

    identity_id = identity["identity_id"]

    # Admin rotation: 30-second grace window for client transition
    # (mirrors agents/token_rotation.py grace_period_hours pattern scaled to seconds)
    _ADMIN_GRACE_SECONDS = 30
    plaintext_token = registry.rotate_key(identity_id, grace_seconds=_ADMIN_GRACE_SECONDS)
    key_last4 = plaintext_token[-4:]

    # Audit — acting admin identity logged for forensic trail
    from yashigani.audit.schema import AdminUserApiKeyIssuedEvent
    state.audit_writer.write(AdminUserApiKeyIssuedEvent(
        admin_account_id=session.account_id,
        target_username=username,
        target_identity_id=identity_id,
        key_last4=key_last4,
        grace_seconds=_ADMIN_GRACE_SECONDS,
    ))

    import logging as _log
    _log.getLogger(__name__).info(
        "Admin API key issued for user: admin=%s target=%s identity_id=%s grace=%ds",
        session.account_id, username, identity_id, _ADMIN_GRACE_SECONDS,
    )

    # Read back expires_at for response
    reg_data = registry.get(identity_id) or {}
    expires_at = reg_data.get("api_key_expires_at", "")

    return {
        "plaintext_token": plaintext_token,
        "shown_once": True,
        "expires_at": expires_at,
        "grace_seconds": _ADMIN_GRACE_SECONDS,
        "message": "Deliver this token securely to the user. It will not be shown again.",
    }


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


def _full_reset_event(admin_username: str, target: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import UserFullResetEvent

    return UserFullResetEvent(
        account_tier=account_tier,
        admin_account=admin_username,
        admin_totp_verified=True,
        target_user_handle=target,
    )


def _full_reset_totp_failure(admin_username: str, target: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import FullResetTotpFailureEvent

    return FullResetTotpFailureEvent(
        account_tier=account_tier,
        admin_account=admin_username,
        target_user_handle=target,
        failure_reason="invalid",
    )
