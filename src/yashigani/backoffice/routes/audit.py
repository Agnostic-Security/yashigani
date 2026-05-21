"""
Yashigani Backoffice — Audit log management routes.
GET    /audit/export/raw             — stream full unfiltered NDJSON/CSV log export (no row cap)
GET    /audit/masking/scope          — current masking scope config
PUT    /audit/masking/scope          — update masking scope (default + overrides)
POST   /audit/masking/scope/agent    — set per-agent masking override
DELETE /audit/masking/scope/agent/{agent_id}  — remove per-agent override
POST   /audit/masking/scope/user     — set per-user masking override
DELETE /audit/masking/scope/user/{handle}     — remove per-user override
POST   /audit/masking/scope/component — set per-component masking override
DELETE /audit/masking/scope/component/{component} — remove per-component override
GET    /audit/siem                   — list SIEM targets
POST   /audit/siem                   — add a SIEM target
DELETE /audit/siem/{name}            — remove a SIEM target
POST   /audit/siem/{name}/test       — send a test event to a SIEM target

Path note (2026-05-02): Renamed /export → /export/raw to resolve path collision
with audit_search.py's filtered /export endpoint. Both routers mount at prefix
/admin/audit. The audit_search filtered export (10k row cap, full filter suite)
is the canonical user-facing export at /admin/audit/export. This unfiltered
streaming export is now at /admin/audit/export/raw for operator/compliance dumps.

Last updated: 2026-05-03
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from yashigani.audit.writer import validate_siem_url
from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.backoffice.schemas.bopla import SiemTargetPublic
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()

_VALID_SIEM_TYPES = {"webhook", "splunk_hec", "elastic_opensearch"}
_VALID_AUTH_HEADERS = {"Authorization", "X-Splunk-HEC-Token", "X-API-Key"}


def _audit_writer():
    """Return the audit writer; assert non-None (set unconditionally at startup)."""
    writer = backoffice_state.audit_writer
    assert writer is not None  # set unconditionally at startup
    return writer


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class MaskingScopeDefaultRequest(BaseModel):
    mask_all_by_default: bool


class AgentOverrideRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    mask: bool


class UserOverrideRequest(BaseModel):
    user_handle: str = Field(min_length=1, max_length=128)
    mask: bool


class ComponentOverrideRequest(BaseModel):
    component: str = Field(min_length=1, max_length=64)
    mask: bool


class SiemTargetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    target_type: str = Field(pattern=r"^(webhook|splunk_hec|elastic_opensearch)$")
    url: str = Field(min_length=8, max_length=512)
    auth_header: str = Field(default="Authorization", max_length=64)
    auth_value: str = Field(min_length=1, max_length=512)
    enabled: bool = True

    @field_validator("url", mode="before")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Enforce SSRF-safe URL on registration (YSG-RISK-007.C #3ax, CWE-918)."""
        return validate_siem_url(v)


# ---------------------------------------------------------------------------
# Log export
# ---------------------------------------------------------------------------


@router.get("/export/raw")
async def export_audit_log(
    session: AdminSession,
    output_format: str = Query(default="ndjson", pattern=r"^(ndjson|csv)$"),
    date_from: Optional[str] = Query(default=None, description="ISO 8601 prefix, e.g. 2025-01"),
    date_to: Optional[str] = Query(default=None, description="ISO 8601 prefix, e.g. 2025-03"),
):
    """Stream the audit log as NDJSON or CSV. Never buffers the full file in memory.

    AVA-2026-04-29-002 fix (ASVS V7.1.3):
    - AuditLogExporter.export() is the canonical method; export_ndjson() / export_csv()
      never existed and caused AttributeError mid-stream (HTTP 200 then 502 cascade).
    - ndjson maps to AuditLogExporter format 'json' (newline-delimited JSON).
    - Mid-stream exceptions are caught inside the generator and logged; the response
      is closed cleanly so keep-alive connections are not corrupted.
    """
    from yashigani.audit.export import AuditLogExporter

    exporter = AuditLogExporter(_audit_writer()._config)

    # AuditLogExporter.export() accepts 'json' (NDJSON) or 'csv'.
    # The route accepts 'ndjson' or 'csv' for user-facing clarity — map here.
    internal_format = "json" if output_format == "ndjson" else "csv"

    if output_format == "csv":
        media_type = "text/csv"
        filename = "yashigani-audit.csv"
    else:
        media_type = "application/x-ndjson"
        filename = "yashigani-audit.ndjson"

    # Resolve date range (both endpoints accept None = unbounded).
    _date_from = date_from or "0000-01-01"
    _date_to = date_to or "9999-12-31"

    async def stream():
        """Wrap exporter with mid-stream exception guard (AVA-2026-04-29-002).

        If export() raises after the HTTP 200 header is sent, we catch it here,
        log it, and return without yielding further — the generator closes cleanly.
        A corrupted partial body is far less harmful than a dangling connection
        that triggers keep-alive 502 cascades on subsequent admin requests.
        """
        try:
            async for chunk in exporter.export(_date_from, _date_to, format=internal_format):
                yield chunk
        except Exception as exc:  # pragma: no cover — defence-in-depth catch
            logger.error(
                "audit export stream error (format=%s, from=%s, to=%s): %s",
                internal_format,
                _date_from,
                _date_to,
                exc,
            )
            # Do NOT re-raise — just stop yielding. The HTTP response is already
            # open (200 sent); re-raising here would leave the ASGI connection in
            # an undefined state on some Uvicorn/Starlette versions. Log + close is
            # the safest path (closes the generator, Starlette closes the socket).

    return StreamingResponse(
        stream(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Masking scope — global default
# ---------------------------------------------------------------------------


@router.get("/masking/scope")
async def get_masking_scope(session: AdminSession):
    """Return the current masking scope configuration."""
    scope = _audit_writer()._masking_scope
    return {
        "mask_all_by_default": scope.mask_all_by_default,
        "agent_overrides": scope.agent_overrides,
        "user_overrides": scope.user_overrides,
        "component_overrides": scope.component_overrides,
    }


@router.put("/masking/scope")
async def set_masking_default(body: MaskingScopeDefaultRequest, session: AdminSession):
    """Update the global masking default (mask all vs mask none by default)."""
    writer = _audit_writer()
    prev = writer._masking_scope.mask_all_by_default
    writer._masking_scope.mask_all_by_default = body.mask_all_by_default

    writer.write(
        _masking_config_event(
            session.account_id,
            "masking.default",
            str(prev),
            str(body.mask_all_by_default),
            account_tier=session.account_tier,
        )
    )
    return {"status": "ok", "mask_all_by_default": body.mask_all_by_default}


# ---------------------------------------------------------------------------
# Masking scope — per-agent
# ---------------------------------------------------------------------------


@router.post("/masking/scope/agent")
async def set_agent_override(body: AgentOverrideRequest, session: AdminSession):
    writer = _audit_writer()
    writer._masking_scope.agent_overrides[body.agent_id] = body.mask
    writer.write(
        _masking_config_event(
            session.account_id,
            f"masking.agent.{body.agent_id}",
            "",
            str(body.mask),
            account_tier=session.account_tier,
        )
    )
    return {"status": "ok"}


@router.delete("/masking/scope/agent/{agent_id}")
async def remove_agent_override(agent_id: str, session: AdminSession):
    writer = _audit_writer()
    removed = writer._masking_scope.agent_overrides.pop(agent_id, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "override_not_found"})
    writer.write(_masking_config_event(session.account_id, f"masking.agent.{agent_id}", str(removed), "removed", account_tier=session.account_tier))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Masking scope — per-user
# ---------------------------------------------------------------------------


@router.post("/masking/scope/user")
async def set_user_override(body: UserOverrideRequest, session: AdminSession):
    writer = _audit_writer()
    writer._masking_scope.user_overrides[body.user_handle] = body.mask
    writer.write(
        _masking_config_event(
            session.account_id,
            f"masking.user.{body.user_handle}",
            "",
            str(body.mask),
            account_tier=session.account_tier,
        )
    )
    return {"status": "ok"}


@router.delete("/masking/scope/user/{handle}")
async def remove_user_override(handle: str, session: AdminSession):
    writer = _audit_writer()
    removed = writer._masking_scope.user_overrides.pop(handle, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "override_not_found"})
    writer.write(_masking_config_event(session.account_id, f"masking.user.{handle}", str(removed), "removed", account_tier=session.account_tier))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Masking scope — per-component
# ---------------------------------------------------------------------------


@router.post("/masking/scope/component")
async def set_component_override(body: ComponentOverrideRequest, session: AdminSession):
    writer = _audit_writer()
    writer._masking_scope.component_overrides[body.component] = body.mask
    writer.write(
        _masking_config_event(
            session.account_id,
            f"masking.component.{body.component}",
            "",
            str(body.mask),
            account_tier=session.account_tier,
        )
    )
    return {"status": "ok"}


@router.delete("/masking/scope/component/{component}")
async def remove_component_override(component: str, session: AdminSession):
    writer = _audit_writer()
    removed = writer._masking_scope.component_overrides.pop(component, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "override_not_found"})
    writer.write(_masking_config_event(session.account_id, f"masking.component.{component}", str(removed), "removed", account_tier=session.account_tier))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# SIEM targets
# ---------------------------------------------------------------------------


@router.get("/siem")
async def list_siem_targets(session: AdminSession):
    # BOPLA allowlist (#90): SiemTargetPublic explicitly excludes auth_value
    # (bearer token / HEC token / API key — write-only credential, never returned).
    targets = [
        SiemTargetPublic(
            name=t.name,
            target_type=t.target_type,
            url=t.url,
            auth_header=t.auth_header,
            enabled=t.enabled,
        ).model_dump()
        for t in _audit_writer()._siem_targets
    ]
    return {"siem_targets": targets, "total": len(targets)}


@router.post("/siem")
async def add_siem_target(body: SiemTargetRequest, session: AdminSession):
    from yashigani.audit.writer import SiemTarget

    writer = _audit_writer()

    existing_names = {t.name for t in writer._siem_targets}
    if body.name in existing_names:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "siem_target_name_taken"},
        )

    target = SiemTarget(
        name=body.name,
        target_type=body.target_type,
        url=body.url,
        auth_header=body.auth_header,
        auth_value=body.auth_value,
        enabled=body.enabled,
    )
    writer.add_siem_target(target)

    writer.write(_config_event(session.account_id, "siem_target_added", "", body.name, account_tier=session.account_tier))
    return {"status": "ok", "name": body.name}


@router.delete("/siem/{name}")
async def remove_siem_target(name: str, session: AdminSession):
    writer = _audit_writer()
    targets = writer._siem_targets
    idx = next((i for i, t in enumerate(targets) if t.name == name), None)
    if idx is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "siem_target_not_found"})

    targets.pop(idx)
    writer.write(_config_event(session.account_id, "siem_target_removed", name, "", account_tier=session.account_tier))
    return {"status": "ok"}


@router.post("/siem/{name}/test")
async def test_siem_target(name: str, session: AdminSession):
    """Send a synthetic test event to the named SIEM target."""
    import json
    import datetime
    import urllib.request
    import urllib.error

    writer = _audit_writer()
    targets = writer._siem_targets
    target = next((t for t in targets if t.name == name), None)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "siem_target_not_found"})

    test_payload = json.dumps(
        {
            "event_type": "SIEM_CONNECTION_TEST",
            "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            "source": "yashigani_backoffice",
            "target_name": name,
        }
    )

    body_str, content_type = writer._format_for_target(test_payload, target)

    # Re-validate target URL at test-fire time — defence-in-depth against a
    # stored target whose URL pre-dates the SSRF validator (YSG-RISK-007.C #3ax).
    try:
        validate_siem_url(target.url)
    except ValueError as exc:
        payload, _ = safe_error_envelope(exc, public_message="siem url blocked", status=422)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=payload,
        )

    req = urllib.request.Request(
        url=target.url,
        data=body_str.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": content_type,
            target.auth_header: target.auth_value,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            http_status = resp.status
    except urllib.error.HTTPError as exc:
        payload, _ = safe_error_envelope(exc, public_message="siem test failed", status=502)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={**payload, "http_status": exc.code},
        )
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="siem test failed", status=502)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=payload,
        )

    writer.write(_config_event(session.account_id, "siem_connection_test", name, f"http_{http_status}", account_tier=session.account_tier))
    return {"status": "ok", "http_status": http_status}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _masking_config_event(admin_id: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import MaskingConfigChangedEvent

    return MaskingConfigChangedEvent(
        account_tier=account_tier,
        admin_account=admin_id,
        change_target=setting,
        target_identifier="",
        previous_value=prev,
        new_value=new,
    )
