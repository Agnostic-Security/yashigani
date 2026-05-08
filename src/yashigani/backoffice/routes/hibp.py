"""
Yashigani Backoffice — HIBP API key management routes.

GET    /api/v1/admin/auth/hibp/status  — key status (configured/source/masked)
PUT    /api/v1/admin/auth/hibp/key     — set key [step-up TOTP required]
DELETE /api/v1/admin/auth/hibp/key     — clear key [step-up TOTP required]

Audit events:
  HIBP_API_KEY_UPDATED  — PUT (key value never logged; masked hint only)
  HIBP_API_KEY_CLEARED  — DELETE

Resolution priority (documented for operators):
  1. Admin-panel key (this store) — highest precedence, immediate effect.
  2. Env var YASHIGANI_HIBP_API_KEY — fallback.
  3. None (anonymous k-Anonymity range request) — final fallback.

Security invariants:
  - The API key is NEVER returned in any response (masked_value only).
  - The API key is NEVER written to any log (not even DEBUG).
  - PUT and DELETE require step-up TOTP (ASVS V6.8.4).

ASVS: V2.1.7 (breach check config), V6.8.4 (step-up for sensitive config),
      V7.1.2 (audit log on mutating operations), V7.1.3 (no secrets in logs).

Last updated: 2026-05-07T01:00:00+01:00
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.auth.hibp_config import (
    get_hibp_key_status,
    mask_hibp_key,
    validate_hibp_key_format,
)

router = APIRouter()
_log = logging.getLogger("yashigani.backoffice.hibp")

_SETTINGS_KEY = "hibp_api_key"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class HibpKeyRequest(BaseModel):
    """Body for PUT /key. The key value is never logged or echoed back."""
    api_key: str = Field(
        min_length=0,
        max_length=128,
        description=(
            "HIBP API key for rate-limit lift or mirror auth. "
            "Empty string clears the stored key (prefer DELETE instead). "
            "Alphanumeric + hyphens only, 8–128 chars."
        ),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_settings_store():
    """Return the AuthSettingsStore from backoffice state, or raise 503."""
    store = getattr(backoffice_state, "auth_settings_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "settings_store_unavailable",
                "message": (
                    "Auth settings store is not available. "
                    "This usually means the database connection failed at startup. "
                    "Check container logs."
                ),
            },
        )
    return store


def _get_audit_writer():
    """Return the audit writer (None is acceptable — audit is best-effort here)."""
    return getattr(backoffice_state, "audit_writer", None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status")
async def hibp_key_status(session: AdminSession):
    """
    Return HIBP API key configuration status.

    Response never includes the full key value — only a masked hint
    (first 3 + '…' + last 3 chars) when a key is configured.
    """
    store = _get_settings_store()
    status_data = await get_hibp_key_status(settings_store=store)
    return status_data


@router.put("/key", status_code=status.HTTP_200_OK)
async def set_hibp_key(body: HibpKeyRequest, session: StepUpAdminSession):
    """
    Set (or update) the HIBP API key stored in the admin panel.

    Requires step-up TOTP (ASVS V6.8.4). The key is encrypted at rest using
    pgp_sym_encrypt with the deployment AES key.

    Audit event HIBP_API_KEY_UPDATED is written. The key value is NOT written
    to the audit log — only the masked hint (first 3 + '…' + last 3 chars).

    Returns the new status (same shape as GET /status).
    """
    # Validate key format before touching DB
    api_key = body.api_key.strip()
    try:
        validate_hibp_key_format(api_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_key_format", "message": str(exc)},
        )

    store = _get_settings_store()

    # If empty string submitted via PUT, treat as clear (idempotent)
    await store.set_setting(_SETTINGS_KEY, api_key, updated_by=session.account_id)

    # Audit — key value NEVER in the log; masked hint only
    masked = mask_hibp_key(api_key) if api_key else None
    _log.info(
        "HIBP_API_KEY_UPDATED admin=%r masked_hint=%r",
        session.account_id,
        masked,
    )

    # Audit is best-effort: if write() raises (e.g. audit sink unavailable) we
    # must NOT propagate the exception — the key was already written to the DB.
    # W4 fix: wrap in try/except consistent with _write_audit() in webauthn.py.
    audit_writer = _get_audit_writer()
    if audit_writer is not None:
        try:
            from yashigani.audit.schema import HibpApiKeyUpdatedEvent
            audit_writer.write(HibpApiKeyUpdatedEvent(
                admin_account=session.account_id,
                masked_key_hint=masked or "",
            ))
        except Exception as _exc:
            _log.error("HIBP audit write failed (best-effort, key was saved): %s", _exc)

    # Return updated status
    status_data = await get_hibp_key_status(settings_store=store)
    return {"status": "ok", "hibp_key": status_data}


@router.delete("/key", status_code=status.HTTP_200_OK)
async def clear_hibp_key(session: StepUpAdminSession):
    """
    Clear the HIBP API key stored in the admin panel.

    Falls back to env var YASHIGANI_HIBP_API_KEY, then anonymous (no key).
    Requires step-up TOTP (ASVS V6.8.4).

    Audit event HIBP_API_KEY_CLEARED is written.
    """
    store = _get_settings_store()

    # Write empty string = cleared / not configured
    await store.set_setting(_SETTINGS_KEY, "", updated_by=session.account_id)

    _log.info("HIBP_API_KEY_CLEARED admin=%r", session.account_id)

    # Audit is best-effort: same pattern as PUT /key above.
    audit_writer = _get_audit_writer()
    if audit_writer is not None:
        try:
            from yashigani.audit.schema import HibpApiKeyClearedEvent
            audit_writer.write(HibpApiKeyClearedEvent(
                admin_account=session.account_id,
            ))
        except Exception as _exc:
            _log.error("HIBP audit write failed (best-effort, key was cleared): %s", _exc)

    # Return updated status
    status_data = await get_hibp_key_status(settings_store=store)
    return {"status": "ok", "hibp_key": status_data}
