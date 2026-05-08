"""
Yashigani Backoffice — WebAuthn/FIDO2 v1 API routes.

POST /api/v1/admin/webauthn/register/start    — begin registration (requires session)
POST /api/v1/admin/webauthn/register/finish   — complete registration (requires session)
POST /api/v1/admin/webauthn/login/start       — begin authentication (PUBLIC — no session)
POST /api/v1/admin/webauthn/login/finish      — complete authentication, issue session (PUBLIC)
DELETE /api/v1/admin/webauthn/credentials/<id> — revoke credential (session + step-up)
GET /api/v1/admin/webauthn/credentials        — list credentials (requires session)

OWASP ASVS V2.8: sign_count replay protection + challenge single-use.
OWASP ASVS V6.8.4: DELETE requires step-up (TOTP re-auth within 5 min).

Recovery: if all WebAuthn credentials are lost, admin falls back to
password + TOTP (the existing /auth/login endpoint is never disabled).

Login flow detail:
  1. Admin POSTs username to /api/v1/admin/webauthn/login/start
     → backend looks up user by username, issues challenge, returns options
  2. Browser calls navigator.credentials.get(options)
  3. Admin POSTs credential response + username to /api/v1/admin/webauthn/login/finish
     → backend verifies assertion, creates admin session, sets cookie

Audit events emitted:
  WEBAUTHN_CREDENTIAL_REGISTERED — successful registration
  WEBAUTHN_LOGIN_SUCCESS          — successful WebAuthn login
  WEBAUTHN_LOGIN_FAILURE          — failed assertion (wrong key, sign_count rollback, etc.)
  WEBAUTHN_CREDENTIAL_REVOKED     — credential deleted by admin

Last updated: 2026-05-08T00:00:00+00:00
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import (
    AdminSession,
    StepUpAdminSession,
    _SESSION_COOKIE,
    get_session_store,
)
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope
# W20 fix (Iris PR #62): import auth throttle helpers so that the public
# login/start and login/finish endpoints are guarded by the same per-IP
# blocklist + progressive-delay throttle as the password login route.
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

class RegisterStartRequest(BaseModel):
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
        description="Human-readable label for this credential (e.g. 'YubiKey 5 Nano work').",
    )


class RegisterFinishRequest(BaseModel):
    credential_response: dict[str, Any]
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
    )


class LoginStartRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
        description="Admin username (email). Used to look up registered credentials.",
    )


class LoginFinishRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    credential_response: dict[str, Any]


# ---------------------------------------------------------------------------
# Registration (requires authenticated admin session)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/admin/webauthn/register/start",
    tags=["webauthn"],
    summary="Begin WebAuthn credential registration",
)
async def register_start(
    body: RegisterStartRequest,
    session: AdminSession,
    request: Request,
):
    """
    Start the WebAuthn registration ceremony for a new FIDO2 credential.
    Returns PublicKeyCredentialCreationOptions for the browser.
    Caller must be authenticated (admin session cookie required).
    """
    svc = _get_pg_service()
    try:
        options_json = await svc.begin_registration(
            user_id=session.account_id,
            user_name=session.account_id,  # use account_id as display name
        )
    except Exception as exc:
        logger.error(
            "WebAuthn register/start error for admin %s: %s", session.account_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_start_failed"},
        )

    return {"status": "ok", "options": options_json}


@router.post(
    "/api/v1/admin/webauthn/register/finish",
    tags=["webauthn"],
    summary="Complete WebAuthn credential registration",
)
async def register_finish(
    body: RegisterFinishRequest,
    session: AdminSession,
    request: Request,
):
    """
    Complete WebAuthn registration, verify attestation, and persist credential.
    Audit event: WEBAUTHN_CREDENTIAL_REGISTERED.
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
            "WebAuthn register/finish failed for admin %s: %s", session.account_id, exc
        )
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_REGISTERED",
            outcome="failure",
            detail=str(exc),
        )
        payload, _ = safe_error_envelope(
            exc, public_message="webauthn registration failed", status=400
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=payload)
    except Exception as exc:
        logger.error("WebAuthn register/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_finish_failed"},
        )

    _write_audit(
        session.account_id,
        "WEBAUTHN_CREDENTIAL_REGISTERED",
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
# Authentication (PUBLIC — admin not yet authenticated)
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/admin/webauthn/login/start",
    tags=["webauthn"],
    summary="Begin WebAuthn authentication (public endpoint)",
)
async def login_start(body: LoginStartRequest, request: Request, response: Response):
    """
    Begin the WebAuthn authentication ceremony.
    PUBLIC endpoint — does not require a session cookie.

    Looks up the admin's account_id by username, then generates a challenge.
    Returns allow_credentials list and challenge for navigator.credentials.get().

    W20 (Iris PR #62): applies the same per-IP blocklist + progressive-delay
    throttle as the password login route.  An unauthenticated DB-query endpoint
    without a rate gate is an invitation to enumerate admin usernames at scale.
    """
    # W20: apply per-IP blocklist + throttle BEFORE any DB query.
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)
    _apply_auth_throttle(client_ip, response)

    # Resolve username → account_id via Postgres
    admin_id = await _resolve_admin_id(body.username)
    if admin_id is None:
        # Return a generic error — do not reveal whether the user exists
        # ASVS V2.1.5: enumerate-safe response
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )

    svc = _get_pg_service()
    try:
        options_json = await svc.begin_authentication(user_id=admin_id)
    except ValueError as exc:
        # "No registered credentials" — not a server error, tell the client
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )
    except Exception as exc:
        logger.error("WebAuthn login/start error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_start_failed"},
        )

    return {"status": "ok", "options": options_json, "user_id": admin_id}


@router.post(
    "/api/v1/admin/webauthn/login/finish",
    tags=["webauthn"],
    summary="Complete WebAuthn authentication and issue session (public endpoint)",
)
async def login_finish(body: LoginFinishRequest, request: Request, response: Response):
    """
    Complete the WebAuthn authentication ceremony.
    PUBLIC endpoint — does not require a session cookie.

    On success: verifies assertion, creates admin session cookie, returns 200.
    On failure: WEBAUTHN_LOGIN_FAILURE audit event + 401.

    Audit events: WEBAUTHN_LOGIN_SUCCESS | WEBAUTHN_LOGIN_FAILURE.

    W20 (Iris PR #62): applies the same per-IP blocklist + progressive-delay
    throttle as login/start and the password login route.  Records auth failure
    on bad assertion (sign_count rollback, wrong key, bad challenge) so that
    automated probing accumulates throttle delay across attempts.
    """
    # W20: apply per-IP blocklist + throttle BEFORE any DB query or assertion.
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)
    _apply_auth_throttle(client_ip, response)

    # Resolve username → account_id
    admin_id = await _resolve_admin_id(body.username)
    if admin_id is None:
        _record_auth_failure(client_ip)
        _write_audit(
            body.username,
            "WEBAUTHN_LOGIN_FAILURE",
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
            user_id=admin_id,
            credential_response=body.credential_response,
            expected_origin=origin,
        )
    except ValueError as exc:
        logger.warning(
            "WebAuthn login/finish failed for %s: %s", body.username, exc
        )
        _record_auth_failure(client_ip)
        _write_audit(
            admin_id,
            "WEBAUTHN_LOGIN_FAILURE",
            outcome="failure",
            detail=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )
    except Exception as exc:
        logger.error("WebAuthn login/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_finish_failed"},
        )

    # Success: clear failure counter for this IP before issuing session.
    _reset_ip_auth_failures(client_ip)

    # Issue admin session
    store = get_session_store()
    ip_addr = _client_ip(request)
    session_obj = store.create(
        account_id=admin_id,
        account_tier="admin",
        client_ip=ip_addr,
    )
    token = session_obj.token

    response.set_cookie(
        key=_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,  # 4-hour absolute cap (matches SessionStore)
        path="/",
    )

    _write_audit(
        admin_id,
        "WEBAUTHN_LOGIN_SUCCESS",
        outcome="success",
        detail=f"username={body.username}",
    )

    return {"status": "ok", "account_id": admin_id}


# ---------------------------------------------------------------------------
# Credential management (requires session; DELETE also requires step-up)
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/admin/webauthn/credentials",
    tags=["webauthn"],
    summary="List registered WebAuthn credentials",
)
async def list_credentials(session: AdminSession):
    """List all WebAuthn credentials registered for the authenticated admin."""
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
            "If all WebAuthn credentials are lost, use password + TOTP login at /admin/login. "
            "Password+TOTP cannot be disabled while WebAuthn is configured."
        ),
    }


@router.delete(
    "/api/v1/admin/webauthn/credentials/{credential_id}",
    tags=["webauthn"],
    summary="Revoke a WebAuthn credential (step-up required)",
)
async def revoke_credential(
    credential_id: str,
    session: StepUpAdminSession,  # ASVS V6.8.4: requires fresh TOTP step-up
):
    """
    Revoke a WebAuthn credential by UUID.
    Requires a fresh TOTP step-up (within YASHIGANI_STEPUP_TTL_SECONDS, default 5 min).

    Recovery: password + TOTP login is always available as a fallback.
    Audit event: WEBAUTHN_CREDENTIAL_REVOKED.
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

    _write_audit(
        session.account_id,
        "WEBAUTHN_CREDENTIAL_REVOKED",
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
    """Extract client IP, respecting X-Forwarded-For from trusted reverse proxy."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


async def _resolve_admin_id(username: str) -> Optional[str]:
    """
    Look up an admin account by username and return its account_id.
    Returns None if not found or account is disabled.
    """
    from yashigani.db.postgres import tenant_transaction
    try:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT account_id FROM admin_accounts "
                "WHERE username = $1 AND disabled = false AND account_tier = 'admin'",
                username,
            )
        return str(row["account_id"]) if row else None
    except Exception as exc:
        logger.error("Failed to resolve admin_id for username %s: %s", username, exc)
        return None


def _write_audit(
    account_id: str,
    event_label: str,
    outcome: str,
    detail: str,
) -> None:
    """Write a WebAuthn audit event (best-effort, never raises)."""
    state = backoffice_state
    if state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import (
            WebAuthnCredentialRegisteredEvent,
            WebAuthnLoginSuccessEvent,
            WebAuthnLoginFailureEvent,
            WebAuthnCredentialRevokedEvent,
        )
        from yashigani.audit.schema import AuditEvent as _AuditEvent

        # B5 fix (Iris audit): use v2.23.3 event classes with correct wire-format
        # event_type values. The v0.9.0 classes (WebAuthnCredentialUsedEvent,
        # WebAuthnCredentialDeletedEvent) carried WEBAUTHN_CREDENTIAL_USED and
        # WEBAUTHN_CREDENTIAL_DELETED — not the semantically correct labels for
        # login and revocation events.
        event: _AuditEvent
        if event_label == "WEBAUTHN_CREDENTIAL_REGISTERED":
            event = WebAuthnCredentialRegisteredEvent(
                admin_account=account_id,
                outcome=outcome,
                credential_name=detail,
            )
        elif event_label == "WEBAUTHN_LOGIN_SUCCESS":
            event = WebAuthnLoginSuccessEvent(
                admin_account=account_id,
            )
        elif event_label == "WEBAUTHN_LOGIN_FAILURE":
            event = WebAuthnLoginFailureEvent(
                admin_account=account_id,
                failure_reason=detail,
            )
        elif event_label == "WEBAUTHN_CREDENTIAL_REVOKED":
            event = WebAuthnCredentialRevokedEvent(
                admin_account=account_id,
                credential_uuid=detail.replace("credential_id=", ""),
            )
        else:
            return
        state.audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write WebAuthn audit event %s: %s", event_label, exc)
