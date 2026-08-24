"""
Yashigani Backoffice — WebAuthn/Passkey routes.
POST /auth/webauthn/register/begin           — start registration ceremony
POST /auth/webauthn/register/complete        — complete registration ceremony
POST /auth/webauthn/authenticate/begin       — start authentication ceremony
POST /auth/webauthn/authenticate/complete    — complete authentication ceremony
GET  /admin/settings/webauthn/credentials   — list user's registered credentials
DELETE /admin/settings/webauthn/credentials/{id} — delete a credential

OWASP ASVS V2.8: sign_count replay protection enforced per credential.

Last updated: 2026-05-03
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class WebAuthnRegisterBeginRequest(BaseModel):
    user_name: str = Field(min_length=1, max_length=64)
    credential_name: Optional[str] = Field(
        default="Passkey", min_length=1, max_length=64
    )


class WebAuthnRegisterCompleteRequest(BaseModel):
    credential_response: dict[str, Any]
    credential_name: Optional[str] = Field(
        default="Passkey", min_length=1, max_length=64
    )


class WebAuthnAuthBeginRequest(BaseModel):
    # user_id is inferred from session — this body is intentionally empty
    # but kept as a model for consistency and future extension
    pass


class WebAuthnAuthCompleteRequest(BaseModel):
    credential_response: dict[str, Any]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@router.post("/auth/webauthn/register/begin")
async def register_begin(
    body: WebAuthnRegisterBeginRequest,
    session: AdminSession,
    request: Request,
):
    """
    Start WebAuthn credential registration.
    Returns PublicKeyCredentialCreationOptions for the browser.
    """
    service = _get_service()
    try:
        options_json = service.begin_registration(
            user_id=session.account_id,
            user_name=body.user_name,
        )
    except Exception as exc:
        logger.error("WebAuthn register begin error for %s: %s", session.account_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_begin_failed"},
        )

    return {"status": "ok", "options": options_json}


@router.post("/auth/webauthn/register/complete")
async def register_complete(
    body: WebAuthnRegisterCompleteRequest,
    session: AdminSession,
    request: Request,
):
    """
    Complete WebAuthn credential registration.
    Verifies attestation and stores the new credential.
    """
    service = _get_service()
    origin = _expected_origin(request)

    try:
        credential = service.complete_registration(
            user_id=session.account_id,
            credential_response=body.credential_response,
            expected_origin=origin,
            credential_name=body.credential_name or "Passkey",
        )
    except ValueError as exc:
        logger.warning(
            "WebAuthn registration failed for %s: %s", session.account_id, exc
        )
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_REGISTERED",
            outcome="failure",
            detail=type(exc).__name__,
        )
        payload, _ = safe_error_envelope(exc, public_message="webauthn registration failed", status=400)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=payload,
        )
    except Exception as exc:
        logger.error("WebAuthn registration error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_complete_failed"},
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
# Authentication
# ---------------------------------------------------------------------------

@router.post("/auth/webauthn/authenticate/begin")
async def authenticate_begin(
    session: AdminSession,
    request: Request,
):
    """
    Start WebAuthn authentication ceremony.
    Returns PublicKeyCredentialRequestOptions for the browser.
    """
    service = _get_service()
    try:
        options_json = service.begin_authentication(user_id=session.account_id)
    except Exception as exc:
        logger.error(
            "WebAuthn authenticate begin error for %s: %s", session.account_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_authenticate_begin_failed"},
        )

    return {"status": "ok", "options": options_json}


@router.post("/auth/webauthn/authenticate/complete")
async def authenticate_complete(
    body: WebAuthnAuthCompleteRequest,
    session: AdminSession,
    request: Request,
):
    """
    Complete WebAuthn authentication assertion.
    Verifies assertion and updates sign_count for replay protection.
    """
    service = _get_service()
    origin = _expected_origin(request)

    try:
        verified_user_id = service.complete_authentication(
            user_id=session.account_id,
            credential_response=body.credential_response,
            expected_origin=origin,
        )
    except ValueError as exc:
        logger.warning(
            "WebAuthn authentication failed for %s: %s", session.account_id, exc
        )
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_USED",
            outcome="failure",
            detail=type(exc).__name__,
        )
        payload, _ = safe_error_envelope(exc, public_message="webauthn authentication failed", status=401)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=payload,
        )
    except Exception as exc:
        logger.error("WebAuthn authentication error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_authenticate_complete_failed"},
        )

    _write_audit(
        session.account_id,
        "WEBAUTHN_CREDENTIAL_USED",
        outcome="success",
        detail=f"user_id={verified_user_id}",
    )
    return {"status": "ok", "user_id": verified_user_id}


# ---------------------------------------------------------------------------
# Credential management
# ---------------------------------------------------------------------------

@router.get("/admin/settings/webauthn/credentials")
async def list_credentials(session: AdminSession):
    """List all WebAuthn credentials registered for the current admin account."""
    service = _get_service()
    credentials = service.list_credentials(user_id=session.account_id)
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
    }


@router.delete(
    "/admin/settings/webauthn/credentials/{credential_id}",
    deprecated=True,
    summary="DEPRECATED — use DELETE /api/v1/admin/webauthn/credentials/{credential_id}",
)
async def delete_credential(credential_id: str, session: StepUpAdminSession):
    """
    Delete a WebAuthn credential by its UUID. Only the owner can delete it.

    YSG-RISK-201 (fixed 2026-08-07) — ASVS V6.8.4. This route took a plain
    ``AdminSession`` while the hardened v1 route
    (``DELETE /api/v1/admin/webauthn/credentials/{id}``) correctly required
    ``StepUpAdminSession``. Two surfaces existed for one operation and only one
    was hardened, so an attacker holding a hijacked-but-not-step-upped admin
    session could strip a target's passkeys here — removing their strongest
    authenticator — and then fall back to password+TOTP. Proven live on BOTH
    runtimes by YTF Tier-B ``test_wa_revoke_04_without_stepup_returns_401``:
    ``DELETE without step-up returned 200, expected 401``. The test was right
    and had been sitting in the failure noise.

    Now requires a fresh TOTP step-up, identical to v1. Marked deprecated: two
    surfaces for one privileged operation is how this drifted in the first
    place, and the duplicate should be retired once callers have migrated.
    """
    service = _get_service()
    deleted = service.delete_credential(
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
        "WEBAUTHN_CREDENTIAL_DELETED",
        outcome="success",
        detail=f"credential_id={credential_id}",
    )
    return {"status": "ok", "credential_id": credential_id}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_service():
    """Return the WebAuthnService from backoffice state, or raise 503."""
    svc = getattr(backoffice_state, "webauthn_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "webauthn_not_configured"},
        )
    return svc


def _expected_origin(request: Request) -> str:
    """Derive the expected origin from the incoming request."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}"


def _write_audit(
    account_id: str,
    event_label: str,
    outcome: str,
    detail: str,
) -> None:
    """Write a typed WebAuthn audit event as a best-effort record."""
    state = backoffice_state
    if state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import (
            WebAuthnCredentialRegisteredEvent,
            WebAuthnCredentialUsedEvent,
            WebAuthnCredentialDeletedEvent,
        )
        from yashigani.audit.schema import AuditEvent as _AuditEvent
        event: _AuditEvent
        if event_label == "WEBAUTHN_CREDENTIAL_REGISTERED":
            event = WebAuthnCredentialRegisteredEvent(
                admin_account=account_id,
                outcome=outcome,
                credential_name=detail,
            )
        elif event_label == "WEBAUTHN_CREDENTIAL_USED":
            event = WebAuthnCredentialUsedEvent(
                admin_account=account_id,
                outcome=outcome,
                failure_reason=detail if outcome == "failure" else "",
            )
        elif event_label == "WEBAUTHN_CREDENTIAL_DELETED":
            event = WebAuthnCredentialDeletedEvent(
                admin_account=account_id,
                credential_uuid=detail.replace("credential_id=", ""),
            )
        else:
            return  # unknown event label — do not write
        state.audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write WebAuthn audit event: %s", exc)
