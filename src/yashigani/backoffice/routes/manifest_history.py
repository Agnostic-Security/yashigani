"""
Yashigani Backoffice — Manifest registration history routes (LU-AMEND-02/03).

Routes:
  GET  /admin/manifest-registrations            — paginated list (tenant filter)
  GET  /admin/manifest-registrations/{id}       — single record detail
  POST /admin/manifest-registrations/ceremony   — record a signing ceremony
                                                   (step-up required)

All routes require AdminSession.
The ceremony endpoint additionally requires StepUpAdminSession (fresh TOTP)
matching the LU-AMEND-04 onboard endpoint pattern.

Compliance:
  NIST AU-2/AU-3/AU-12/SR-4/SR-4(3) + CMMC AU.L2-3.3.1/2 / SR.L2-3.11.2
  SOC 2 CC6.2/6.3/CC8.1 + ISO 42001 A.6.1.2/A.6.2.6
  ISO 27001 A.5.21/A.5.23 / LU-AMEND-02+03 / v2.24.1

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

_log = logging.getLogger("yashigani.manifest_history")

router = APIRouter()

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# Pool helper (lazy — pool may not exist in unit tests that mock it away)
# ---------------------------------------------------------------------------

def _get_pool():
    from yashigani.db import get_pool
    pool = get_pool()
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "database_unavailable"},
        )
    return pool


def _get_registry_service():
    """Return a ManifestRegistryService backed by the shared pool."""
    from yashigani.manifest_registry import ManifestRegistryService
    return ManifestRegistryService(pool=_get_pool())


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ManifestRegistrationSummary(BaseModel):
    """Paginated list item — excludes the full YAML blob to keep list responses small."""
    id: int
    tenant_id: str
    agent_id: str
    manifest_sha256: str
    registered_by_operator_identity: str
    registered_at: datetime.datetime
    previous_manifest_sha256: Optional[str]
    has_signature_provenance: bool


class ManifestRegistrationDetail(BaseModel):
    """Full record including YAML blob and provenance."""
    id: int
    tenant_id: str
    agent_id: str
    manifest_sha256: str
    manifest_yaml_blob: str
    registered_by_operator_identity: str
    registered_at: datetime.datetime
    previous_manifest_sha256: Optional[str]
    signature_provenance: Optional[dict]


class ManifestRegistrationListResponse(BaseModel):
    items: list[ManifestRegistrationSummary]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Ceremony request/response models (LU-AMEND-03)
# ---------------------------------------------------------------------------

class CeremonyRequest(BaseModel):
    """
    POST /admin/manifest-registrations/ceremony

    The client (yashigani-manifest.py CLI) submits the full ceremony JSON.
    The server validates, writes to manifest_registrations, and writes a
    MANIFEST_CEREMONY_RECORDED audit event.
    """
    tenant_id: str = Field(..., min_length=1, max_length=256)
    agent_id: str = Field(..., min_length=1, max_length=256)
    manifest_yaml: str = Field(..., min_length=1)
    operator_identity: str = Field(..., min_length=1, max_length=512)
    # Ceremony provenance
    manifest_sha256: str = Field(..., min_length=64, max_length=64,
                                  description="hex SHA-256 of manifest_yaml")
    confirmed_at: str = Field(..., description="ISO-8601 UTC timestamp of the ack")
    ack_text_shown: str = Field(..., min_length=1, max_length=2048,
                                 description="The exact acknowledgement text shown to the operator")
    ack_response: str = Field(..., min_length=1, max_length=4,
                               description="Must be 'Y' — anything else is an error")
    signature_provenance: dict = Field(
        default_factory=dict,
        description="Ceremony signing provenance: alg, signer, sig",
    )


class CeremonyResponse(BaseModel):
    manifest_registration_id: int
    manifest_sha256: str
    audit_event_id: str
    recorded_at: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/admin/manifest-registrations",
    response_model=ManifestRegistrationListResponse,
    summary="List manifest registrations for a tenant (LU-AMEND-02)",
    tags=["manifest-registry"],
)
async def list_manifest_registrations(
    session: AdminSession,
    tenant: Optional[str] = Query(
        default=None,
        description="Tenant ID filter. Defaults to the platform tenant.",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    Paginated list of manifest registrations for a tenant, newest first.

    Returns summary objects (no YAML blob) to keep list responses small.
    Use GET /admin/manifest-registrations/{id} for the full record including blob.

    Requires an active admin session (AdminSession).
    """
    tenant_id = tenant or _PLATFORM_TENANT_ID
    svc = _get_registry_service()

    records = await svc.history(tenant_id=tenant_id, limit=limit, offset=offset)
    # Total count — separate query
    pool = _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS n FROM manifest_registrations WHERE tenant_id = $1",
            tenant_id,
        )
    total: int = row["n"] if row else 0

    items = [
        ManifestRegistrationSummary(
            id=r.id,
            tenant_id=r.tenant_id,
            agent_id=r.agent_id,
            manifest_sha256=r.manifest_sha256,
            registered_by_operator_identity=r.registered_by_operator_identity,
            registered_at=r.registered_at,
            previous_manifest_sha256=r.previous_manifest_sha256,
            has_signature_provenance=(r.signature_provenance is not None),
        )
        for r in records
    ]
    return ManifestRegistrationListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/admin/manifest-registrations/{record_id}",
    response_model=ManifestRegistrationDetail,
    summary="Get a single manifest registration record (LU-AMEND-02)",
    tags=["manifest-registry"],
)
async def get_manifest_registration(
    record_id: int,
    session: AdminSession,
):
    """
    Return the full manifest registration record including the YAML blob and
    signature_provenance JSON.

    Requires an active admin session (AdminSession).
    """
    svc = _get_registry_service()
    record = await svc.show(record_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "record_not_found", "id": record_id},
        )
    return ManifestRegistrationDetail(
        id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        manifest_sha256=record.manifest_sha256,
        manifest_yaml_blob=record.manifest_yaml_blob,
        registered_by_operator_identity=record.registered_by_operator_identity,
        registered_at=record.registered_at,
        previous_manifest_sha256=record.previous_manifest_sha256,
        signature_provenance=record.signature_provenance,
    )


@router.post(
    "/admin/manifest-registrations/ceremony",
    response_model=CeremonyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a manifest signing ceremony (LU-AMEND-03)",
    tags=["manifest-registry"],
)
async def record_ceremony(
    body: CeremonyRequest,
    session: StepUpAdminSession,
):
    """
    Record a manifest signing ceremony.

    The CLI (yashigani-manifest.py) calls this after:
    1. Computing manifest_sha256 from the YAML blob.
    2. Showing the SHA-256 + summary to the operator.
    3. Capturing an explicit 'Y' acknowledgement.
    4. Signing the ceremony JSON with the SPIFFE internal HMAC key.

    Server-side:
    1. Validates ack_response == "Y" (fail-closed).
    2. Validates manifest_sha256 matches the submitted manifest_yaml.
    3. Writes to manifest_registrations.
    4. Writes MANIFEST_CEREMONY_RECORDED to audit_events.

    Requires StepUpAdminSession (AdminSession + fresh TOTP step-up).
    Matches the LU-AMEND-04 onboard endpoint step-up pattern.
    """
    # -- Validate ack
    if body.ack_response != "Y":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "ceremony_ack_required",
                "message": "ack_response must be 'Y' — ceremony was not completed",
            },
        )

    # -- Validate SHA-256 matches submitted YAML
    expected_sha = hashlib.sha256(body.manifest_yaml.encode("utf-8")).hexdigest()
    if expected_sha != body.manifest_sha256:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "manifest_sha256_mismatch",
                "computed": expected_sha,
                "submitted": body.manifest_sha256,
            },
        )

    # -- Write to manifest_registrations
    svc = _get_registry_service()
    try:
        record_id = await svc.register(
            tenant_id=body.tenant_id,
            agent_id=body.agent_id,
            manifest_yaml=body.manifest_yaml,
            operator_identity=body.operator_identity,
            signature_provenance=body.signature_provenance,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "manifest_rejected", "detail": str(exc)},
        )
    except Exception as exc:
        _log.exception("Failed to write manifest registration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        )

    # -- Write MANIFEST_CEREMONY_RECORDED to audit_events
    now_iso = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    audit_event_id: str = ""
    prov = body.signature_provenance or {}
    sig_full = prov.get("sig", "")
    sig_prefix = sig_full[:16] if sig_full else ""

    try:
        from yashigani.audit.schema import ManifestCeremonyEvent
        event = ManifestCeremonyEvent(
            manifest_sha256=body.manifest_sha256,
            operator_identity=body.operator_identity,
            confirmed_at=body.confirmed_at,
            ack_text_shown=body.ack_text_shown,
            ack_response=body.ack_response,
            signature_alg=prov.get("alg", ""),
            signer_spiffe_id=prov.get("signer", ""),
            signature_hex_prefix=sig_prefix,
            manifest_registration_id=record_id,
        )
        audit_event_id = event.audit_event_id
        writer = backoffice_state.audit_writer
        if writer is not None:
            writer.write(event)
        else:
            _log.warning(
                "audit_writer not initialised — MANIFEST_CEREMONY_RECORDED "
                "event %s not delivered to audit sinks (record_id=%d still written)",
                audit_event_id,
                record_id,
            )
    except Exception as exc:
        # Non-fatal: the manifest_registrations row is already committed.
        # Log the failure so auditors can identify the missing event.
        _log.error(
            "Failed to write MANIFEST_CEREMONY_RECORDED audit event for "
            "record_id=%d: %s",
            record_id,
            exc,
            exc_info=True,
        )

    return CeremonyResponse(
        manifest_registration_id=record_id,
        manifest_sha256=body.manifest_sha256,
        audit_event_id=audit_event_id,
        recorded_at=now_iso,
    )
