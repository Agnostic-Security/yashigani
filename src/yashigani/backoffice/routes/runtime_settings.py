"""
Yashigani Backoffice — Runtime settings admin API.

GET  /admin/runtime-settings          — list all settings (AdminSession)
GET  /admin/runtime-settings/{key}    — single setting (AdminSession)
PUT  /admin/runtime-settings/{key}    — update (StepUpAdminSession + audit)
POST /admin/runtime-settings/{key}/reset — reset to default (StepUpAdminSession)

admin-surfaces-all-runtime-settings rule / v2.24.1.
CMMC AU.L2-3.3.1 / SOC 2 CC6.2 / ISO 27001 A.5.15.

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RuntimeSettingUpdateRequest(BaseModel):
    """Body for PUT /admin/runtime-settings/{key}."""
    value: float | int | bool | str

    @field_validator("value", mode="before")
    @classmethod
    def value_not_none(cls, v):
        if v is None:
            raise ValueError("value must not be null")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_service():
    svc = getattr(backoffice_state, "runtime_settings", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "runtime_settings_not_initialised"},
        )
    return svc


def _get_known_key(key: str):
    """Raise 404 if key not in KNOWN_SETTINGS_BY_KEY."""
    from yashigani.runtime_settings.keys import KNOWN_SETTINGS_BY_KEY

    if key not in KNOWN_SETTINGS_BY_KEY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "unknown_setting_key", "key": key},
        )
    return KNOWN_SETTINGS_BY_KEY[key]


def _emit_audit(session, key: str, old_value, new_value, source: str) -> None:
    if backoffice_state.audit_writer is None:
        return
    from yashigani.audit.schema import RuntimeSettingChangedEvent
    backoffice_state.audit_writer.write(
        RuntimeSettingChangedEvent(
            account_tier=session.account_tier,
            setting_key=key,
            old_value=json.dumps(old_value),
            new_value=json.dumps(new_value),
            changed_by=session.account_id,
            source=source,
        )
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_runtime_settings(session: AdminSession):
    """
    List all known runtime settings with current value, source, and audit
    metadata.  Returns defaults for settings not yet in DB.
    """
    svc = _get_service()
    items = await svc.list_all()
    return {"settings": items}


@router.get("/{key:path}")
async def get_runtime_setting(key: str, session: AdminSession):
    """Return a single runtime setting by key."""
    _get_known_key(key)
    svc = _get_service()
    record = await svc.get_one(key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "unknown_setting_key", "key": key},
        )
    return record


@router.put("/{key:path}")
async def update_runtime_setting(
    key: str,
    body: RuntimeSettingUpdateRequest,
    session: StepUpAdminSession,
):
    """
    Update a runtime setting value.

    Requires StepUpAdminSession (fresh TOTP within YASHIGANI_STEPUP_TTL_SECONDS).
    Emits RUNTIME_SETTING_CHANGED audit event.
    Publishes yashigani:settings:changed pub/sub so gateway consumers reload.
    """
    meta = _get_known_key(key)
    svc = _get_service()

    # Fetch previous value for audit record
    prev_record = await svc.get_one(key)
    old_value = prev_record["value"] if prev_record else meta.class_default

    record = await svc.set(
        key=key,
        value=body.value,
        changed_by=session.account_id,
        source="api",
    )

    _emit_audit(session, key, old_value, record["value"], source="api")

    logger.info(
        "runtime_setting changed: key=%r old=%r new=%r by=%s",
        key, old_value, record["value"], session.account_id,
    )
    return record


@router.post("/{key:path}/reset")
async def reset_runtime_setting_to_default(
    key: str,
    session: StepUpAdminSession,
):
    """
    Reset a runtime setting to its install-time class default.

    Requires StepUpAdminSession. Emits RUNTIME_SETTING_CHANGED audit event.
    """
    meta = _get_known_key(key)
    svc = _get_service()

    prev_record = await svc.get_one(key)
    old_value = prev_record["value"] if prev_record else meta.class_default

    record = await svc.reset_to_default(key=key, changed_by=session.account_id, source="api")

    _emit_audit(session, key, old_value, record["value"], source="api")

    logger.info(
        "runtime_setting reset to default: key=%r old=%r default=%r by=%s",
        key, old_value, meta.class_default, session.account_id,
    )
    return record
