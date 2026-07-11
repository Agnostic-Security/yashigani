"""
Yashigani Backoffice — WebAuthn/FIDO2 user-tier routes (3.1).

POST /api/v1/user/webauthn/register/start    — begin registration (requires user session)
POST /api/v1/user/webauthn/register/finish   — complete registration (requires user session)
POST /api/v1/user/webauthn/login/start       — begin authentication (PUBLIC)
POST /api/v1/user/webauthn/login/finish      — complete authentication, issue user session (PUBLIC)
GET  /api/v1/user/webauthn/credentials       — list credentials (requires user session)
DELETE /api/v1/user/webauthn/credentials/{id} — revoke credential (requires user session)

Mirror of webauthn_v1.py for the user tier.  Key differences:
  - Registration requires a user-tier session (account_tier == "user").
  - Login resolves usernames against admin_accounts WHERE account_tier = 'user'.
  - login_finish issues account_tier="user" session cookies (_USER_SESSION_COOKIE).
  - Credential lookup uses the same user_id TEXT column (account UUID string).

Recovery: if all FIDO2 keys are lost, use password + TOTP on the user login page.
Password+TOTP is never disabled while WebAuthn is configured.

OWASP ASVS V2.8: sign_count replay protection + challenge single-use.
Same per-IP brute-force throttle as the admin WebAuthn and password login routes.

Audit events emitted:
  WEBAUTHN_USER_CREDENTIAL_REGISTERED — successful registration
  WEBAUTHN_USER_LOGIN_SUCCESS          — successful WebAuthn user login
  WEBAUTHN_USER_LOGIN_FAILURE          — failed assertion
  WEBAUTHN_USER_CREDENTIAL_REVOKED     — credential deleted by user

Last updated: 2026-07-01T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import (
    UserSession,
    _USER_SESSION_COOKIE,
    get_session_store,
)
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

# Re-use the per-IP throttle and blocklist helpers from the auth module.
# Unauthenticated public login endpoints MUST be rate-limited identically to
# the password login route — same attack surface, same mitigation (LAURA-3X-001).
from yashigani.backoffice.routes.auth import (
    _check_ip_access,
    _apply_auth_throttle,
    _record_auth_failure,
    _reset_ip_auth_failures,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class UserRegisterStartRequest(BaseModel):
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
        description="Human-readable label for this credential (e.g. 'YubiKey 5 Nano').",
    )


class UserRegisterFinishRequest(BaseModel):
    credential_response: dict[str, Any]
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
    )


class UserLoginStartRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
        description="User username (email). Used to look up registered credentials.",
    )


class UserLoginFinishRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    credential_response: dict[str, Any]


# ---------------------------------------------------------------------------
# Registration (requires authenticated user session)
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/user/webauthn/register/start",
    tags=["webauthn-user"],
    summary="Begin WebAuthn credential registration (user tier)",
)
async def user_register_start(
    body: UserRegisterStartRequest,
    session: UserSession,
    request: Request,
):
    """
    Start the WebAuthn registration ceremony for a new FIDO2 credential.
    Returns PublicKeyCredentialCreationOptions for the browser.
    Caller must have a valid user-tier session cookie.
    """
    svc = _get_pg_service()
    try:
        options_json = await svc.begin_registration(
            user_id=session.account_id,
            user_name=session.account_id,
        )
    except Exception as exc:
        logger.error("WebAuthn user register/start error for %s: %s", session.account_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_start_failed"},
        )

    return {"status": "ok", "options": options_json}


@router.post(
    "/api/v1/user/webauthn/register/finish",
    tags=["webauthn-user"],
    summary="Complete WebAuthn credential registration (user tier)",
)
async def user_register_finish(
    body: UserRegisterFinishRequest,
    session: UserSession,
    request: Request,
):
    """
    Complete WebAuthn registration, verify attestation, and persist credential.
    Audit event: WEBAUTHN_USER_CREDENTIAL_REGISTERED.
    """
    svc = _get_pg_service()
    origin = _expected_origin(request)

    try:
        credential = await svc.complete_registration(
            user_id=session.account_id,
            credential_response=body.credential_response,
            expected_origin=origin,
            credential_name=body.credential_name,
        )
    except ValueError as exc:
        logger.warning(
            "WebAuthn user register/finish failed for %s: %s", session.account_id, exc
        )
        _write_user_audit(
            session.account_id,
            "WEBAUTHN_USER_CREDENTIAL_REGISTERED",
            outcome="failure",
            detail=str(exc),
        )
        payload, _ = safe_error_envelope(
            exc, public_message="webauthn registration failed", status=400
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=payload)
    except Exception as exc:
        logger.error("WebAuthn user register/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_finish_failed"},
        )

    _write_user_audit(
        session.account_id,
        "WEBAUTHN_USER_CREDENTIAL_REGISTERED",
        outcome="success",
        detail=f"credential_id={credential.id} name={credential.name}",
    )
    return {
        "status": "ok",
        "credential_id": credential.id,
        "name": credential.name,
        "aaguid": credential.aaguid,
        "created_at": credential.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Authentication (PUBLIC — user not yet authenticated)
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/user/webauthn/login/start",
    tags=["webauthn-user"],
    summary="Begin WebAuthn authentication for user tier (public endpoint)",
)
async def user_login_start(
    body: UserLoginStartRequest, request: Request, response: Response
):
    """
    Begin the WebAuthn authentication ceremony for a user-tier account.
    PUBLIC endpoint — does not require a session cookie.

    Looks up the user's account_id by username (account_tier = 'user'),
    then issues a challenge.

    Applies the same per-IP blocklist + progressive-delay throttle as the
    password login and admin WebAuthn login routes.  An unauthenticated
    DB-query endpoint without a rate gate enables username enumeration at scale.
    """
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)
    _apply_auth_throttle(client_ip, response)

    user_id = await _resolve_user_id(body.username)
    if user_id is None:
        # Enumerate-safe: do not reveal whether the user or the credentials exist
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )

    svc = _get_pg_service()
    try:
        options_json = await svc.begin_authentication(user_id=user_id)
    except ValueError:
        # "No registered credentials" — not a server error
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )
    except Exception as exc:
        logger.error("WebAuthn user login/start error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_start_failed"},
        )

    return {"status": "ok", "options": options_json, "user_id": user_id}


@router.post(
    "/api/v1/user/webauthn/login/finish",
    tags=["webauthn-user"],
    summary="Complete WebAuthn authentication and issue user session (public endpoint)",
)
async def user_login_finish(
    body: UserLoginFinishRequest, request: Request, response: Response
):
    """
    Complete the WebAuthn authentication ceremony for a user-tier account.
    PUBLIC endpoint — does not require a session cookie.

    On success: verifies assertion, creates user session cookie (_USER_SESSION_COOKIE),
    returns 200.
    On failure: WEBAUTHN_USER_LOGIN_FAILURE audit event + 401.

    The issued session has account_tier = 'user'.
    Redirect target: /app/webui (same as password+TOTP login).
    """
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)
    _apply_auth_throttle(client_ip, response)

    user_id = await _resolve_user_id(body.username)
    if user_id is None:
        _record_auth_failure(client_ip)
        _write_user_audit(
            body.username,
            "WEBAUTHN_USER_LOGIN_FAILURE",
            outcome="failure",
            detail="unknown_username",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )

    svc = _get_pg_service()
    origin = _expected_origin(request)

    try:
        verified_user_id = await svc.complete_authentication(
            user_id=user_id,
            credential_response=body.credential_response,
            expected_origin=origin,
        )
    except ValueError as exc:
        logger.warning(
            "WebAuthn user login/finish failed for %s: %s", body.username, exc
        )
        _record_auth_failure(client_ip)
        _write_user_audit(
            user_id,
            "WEBAUTHN_USER_LOGIN_FAILURE",
            outcome="failure",
            detail=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )
    except Exception as exc:
        logger.error("WebAuthn user login/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_finish_failed"},
        )

    # Success — clear failure counter, issue user session.
    _reset_ip_auth_failures(client_ip)

    store = get_session_store()
    session_obj = store.create(
        account_id=user_id,
        account_tier="user",
        client_ip=client_ip,
    )
    token = session_obj.token

    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,  # 4-hour absolute cap — matches admin WebAuthn and password login
        path="/",
    )

    _write_user_audit(
        user_id,
        "WEBAUTHN_USER_LOGIN_SUCCESS",
        outcome="success",
        detail=f"username={body.username}",
    )

    return {"status": "ok", "account_id": user_id, "redirect_to": "/app/webui"}


# ---------------------------------------------------------------------------
# Credential management (requires user session)
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/user/webauthn/credentials",
    tags=["webauthn-user"],
    summary="List registered WebAuthn credentials (user tier)",
)
async def user_list_credentials(session: UserSession):
    """List all WebAuthn credentials registered for the authenticated user."""
    svc = _get_pg_service()
    credentials = await svc.list_credentials(user_id=session.account_id)
    return {
        "credentials": [
            {
                "id": c.id,
                "name": c.name,
                "aaguid": c.aaguid,
                "sign_count": c.sign_count,
                "created_at": c.created_at.isoformat(),
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in credentials
        ],
        "total": len(credentials),
        "recovery_note": (
            "If all WebAuthn credentials are lost, use password + TOTP on the "
            "user sign-in page. Password+TOTP cannot be disabled while WebAuthn "
            "is configured."
        ),
    }


@router.delete(
    "/api/v1/user/webauthn/credentials/{credential_id}",
    tags=["webauthn-user"],
    summary="Revoke a WebAuthn credential (user tier)",
)
async def user_revoke_credential(
    credential_id: str,
    session: UserSession,
):
    """
    Revoke a WebAuthn credential by UUID.
    Requires a valid user session. The credential must belong to the calling user.
    Audit event: WEBAUTHN_USER_CREDENTIAL_REVOKED.
    """
    svc = _get_pg_service()
    deleted = await svc.delete_credential(
        user_id=session.account_id,
        credential_uuid=credential_id,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "credential_not_found"},
        )

    _write_user_audit(
        session.account_id,
        "WEBAUTHN_USER_CREDENTIAL_REVOKED",
        outcome="success",
        detail=f"credential_id={credential_id}",
    )
    return {"status": "ok", "credential_id": credential_id}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_pg_service():
    """Return the PgWebAuthnService from backoffice state, or raise 503."""
    svc = getattr(backoffice_state, "pg_webauthn_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "webauthn_not_configured"},
        )
    return svc


def _expected_origin(request: Request) -> str:
    """Derive expected WebAuthn origin from the incoming request."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}"


def _client_ip(request: Request) -> str:
    """
    Real client IP for rate-limiting.
    Reads X-Real-IP (set by Caddy to the real TCP peer) in preference to
    X-Forwarded-For (which Caddy appends, making the first element attacker-
    controlled).  See auth.py _real_client_ip for full rationale.
    """
    xri = request.headers.get("x-real-ip", "").strip()
    if xri:
        return xri.split(",")[0].strip()
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"  # nosec B104 — label, not bind address


async def _resolve_user_id(username: str) -> Optional[str]:
    """
    Look up a user-tier account by username.
    Returns account_id as string, or None if not found / disabled / not user tier.

    Deliberately restricted to account_tier = 'user' so that admin accounts
    cannot be authenticated via the user-tier WebAuthn endpoints (tier isolation).
    """
    from yashigani.db.postgres import tenant_transaction

    try:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT account_id FROM admin_accounts "
                "WHERE username = $1 AND disabled = false AND account_tier = 'user'",
                username,
            )
        return str(row["account_id"]) if row else None
    except Exception as exc:
        logger.error(
            "Failed to resolve user_id for username %s: %s", username, exc
        )
        return None


def _write_user_audit(
    account_id: str,
    event_label: str,
    outcome: str,
    detail: str,
) -> None:
    """Write a user-tier WebAuthn audit event (best-effort, never raises)."""
    state = backoffice_state
    if state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import (
            WebAuthnUserLoginSuccessEvent,
            WebAuthnUserLoginFailureEvent,
            WebAuthnUserCredentialRegisteredEvent,
            WebAuthnUserCredentialRevokedEvent,
        )
        from yashigani.audit.schema import AuditEvent as _AuditEvent

        event: _AuditEvent
        if event_label == "WEBAUTHN_USER_CREDENTIAL_REGISTERED":
            event = WebAuthnUserCredentialRegisteredEvent(
                user_account=account_id,
                outcome=outcome,
                credential_name=detail,
            )
        elif event_label == "WEBAUTHN_USER_LOGIN_SUCCESS":
            event = WebAuthnUserLoginSuccessEvent(
                user_account=account_id,
            )
        elif event_label == "WEBAUTHN_USER_LOGIN_FAILURE":
            event = WebAuthnUserLoginFailureEvent(
                user_account=account_id,
                failure_reason=detail,
            )
        elif event_label == "WEBAUTHN_USER_CREDENTIAL_REVOKED":
            event = WebAuthnUserCredentialRevokedEvent(
                user_account=account_id,
                credential_uuid=detail.replace("credential_id=", ""),
            )
        else:
            return
        state.audit_writer.write(event)
    except Exception as exc:
        logger.error(
            "Failed to write user WebAuthn audit event %s: %s", event_label, exc
        )
