"""
Admin API for audit sink configuration.

GET    /admin/audit/sinks            — list all sinks + last write timestamp
GET    /admin/audit/siem/config      — get current SIEM backend config
PUT    /admin/audit/siem/config      — update SIEM backend config [step-up required]
POST   /admin/audit/siem/config/test — send a test event to the configured SIEM backend
DELETE /admin/audit/sinks/queue      — drain the audit queue (admin flush)

Path note (2026-05-02): The three SIEM backend-config endpoints were renamed
from /admin/audit/siem (GET/PUT) and /admin/audit/siem/test (POST) to
/admin/audit/siem/config and /admin/audit/siem/config/test respectively.

Reason: audit.py (mounted at prefix /admin/audit) registers GET /siem for the
named SIEM target list. When audit_sinks_router (no prefix — full paths baked
in) also registered GET /admin/audit/siem, FastAPI silently resolved to the
sinks handler (registered later in app.py), leaving the audit.py target-list
handler as unreachable dead code. The two endpoints serve different purposes:
  - /admin/audit/siem       (audit.py)        — CRUD for named SIEM targets
  - /admin/audit/siem/config (audit_sinks.py) — single active backend config

SIEM endpoint URL changes still require step-up TOTP (ASVS V6.8.4).

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

from yashigani.backoffice._ssrf import assert_safe_outbound_url
from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session

logger = logging.getLogger(__name__)
audit_sinks_router = APIRouter(tags=["audit-sinks"])


class SiemConfigRequest(BaseModel):
    backend: Literal["none", "splunk", "elasticsearch", "wazuh"]
    endpoint: Optional[str] = None
    token_secret_key: Optional[str] = None  # KMS key name for token/API key
    wazuh_auto_deploy: Optional[bool] = False


class SiemConfigResponse(BaseModel):
    backend: str
    endpoint: Optional[str]
    wazuh_auto_deploy: bool


@audit_sinks_router.get("/admin/audit/sinks")
async def list_sinks(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    audit_writer = backoffice_state.audit_writer
    if hasattr(audit_writer, "status"):
        status = await audit_writer.status()
    else:
        status = {"file": {"last_write": None}}
    return {"sinks": status}


@audit_sinks_router.get("/admin/audit/siem/config", response_model=SiemConfigResponse)
async def get_siem_config(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    state = backoffice_state
    return SiemConfigResponse(
        backend=getattr(state, "siem_backend", "none"),
        endpoint=getattr(state, "siem_endpoint", None),
        wazuh_auto_deploy=getattr(state, "siem_wazuh_auto_deploy", False),
    )


@audit_sinks_router.put("/admin/audit/siem/config")
async def update_siem_config(
    body: SiemConfigRequest,
    session=Depends(require_stepup_admin_session),
):
    from yashigani.backoffice.state import backoffice_state

    if body.backend != "none" and not body.endpoint:
        raise HTTPException(status_code=422, detail="endpoint required for non-none backend")

    # FIND-3.0-001: validate endpoint URL against SSRF targets before storing.
    # Rejects loopback, link-local (incl. cloud IMDS 169.254.169.254), RFC-1918,
    # multicast, and non-http(s) schemes (file://, gopher://, …).
    # Operator-allowlisted internal SIEM hosts (YASHIGANI_SIEM_HOSTNAMES) bypass
    # the IP-category check — same pattern as agent upstream_url.
    if body.endpoint:
        try:
            assert_safe_outbound_url(
                body.endpoint,
                allowlist_env="YASHIGANI_SIEM_HOSTNAMES",
                label="siem_endpoint",
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "ssrf_rejected", "message": str(exc)},
            ) from exc

    backoffice_state.siem_backend = body.backend
    backoffice_state.siem_endpoint = body.endpoint
    backoffice_state.siem_wazuh_auto_deploy = body.wazuh_auto_deploy or False

    logger.info(
        "SIEM config updated: backend=%s endpoint=%s auto_deploy=%s",
        body.backend, body.endpoint, body.wazuh_auto_deploy,
    )
    return {"status": "updated", "backend": body.backend}


@audit_sinks_router.post("/admin/audit/siem/config/test")
async def test_siem(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    from yashigani.audit.sinks import SiemSink

    backend = getattr(backoffice_state, "siem_backend", "none")
    endpoint = getattr(backoffice_state, "siem_endpoint", None)

    if backend == "none" or not endpoint:
        raise HTTPException(status_code=400, detail="No SIEM backend configured")

    # Retrieve token from KMS
    token = ""
    kms = backoffice_state.kms_provider
    try:
        token = kms.get_secret(f"{backend}_api_key") or ""
    except Exception:
        pass

    sink = SiemSink(siem_type=backend, endpoint=endpoint, token=token)
    test_event = {
        "event_type": "SIEM_TEST",
        "action": "TEST",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "message": "Yashigani SIEM connectivity test",
    }
    await sink.write(test_event)
    return {"status": "test_sent", "backend": backend}
