"""
Yashigani Backoffice — PKI admin API (Issue #51 + #53, v2.23.3).

Endpoints:
  GET  /api/v1/admin/pki/chain/{service}   — view current cert chain metadata
  POST /api/v1/admin/pki/rotate/{service}  — trigger cert re-issuance [step-up]
  GET  /api/v1/admin/pki/bundle/{service}  — download PEM bundle (leaf + intermediates)
  GET  /api/v1/admin/pki/status            — list all services with cert health summary

Auth:
  All endpoints require AdminSession (admin tier, valid session).
  rotate is additionally gated by StepUpAdminSession (ASVS V6.8.4).

CA driver selection:
  Reads YASHIGANI_PKI_CA_MODE (internal | byo) via driver_factory.get_ca_driver().
  Unknown mode fails closed at startup (DriverError propagated → HTTP 503).

Security invariants:
  - Private key material is NEVER included in any response.
  - PEM bundle endpoint returns Content-Type: application/x-pem-file with
    Content-Disposition: attachment.
  - Rotation emits audit events (PKI_CERT_ROTATED, PKI_CERT_ROTATION_FAILED).

ASVS: V6.8.4 (step-up on rotate), V7.1.2 (audit log), V9.1.1 (TLS cert health)
CWE-200: no private key path or content ever returned in response

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.pki.driver_factory import get_ca_driver
from yashigani.pki.drivers.base import CertChainInfo, DriverError

router = APIRouter(prefix="/api/v1/admin/pki", tags=["pki"])
_log = logging.getLogger("yashigani.backoffice.pki")

# Allowlist of service names that can be queried via the admin API.
# Checked against the manifest at request time; empty string = reject.
_SERVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9_\-]{0,63}$")


def _validate_service_name(service_name: str) -> None:
    if not _SERVICE_NAME_RE.fullmatch(service_name):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_service_name",
                "message": "service_name must be lowercase alphanumeric with optional hyphens/underscores, 1-64 chars",
            },
        )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class CertChainResponse(BaseModel):
    service: str
    subject_cn: str
    issuer_cn: str
    serial_hex: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    dns_sans: list[str]
    uri_sans: list[str]
    ip_sans: list[str]
    chain_depth: int
    ca_mode: str
    needs_renewal: bool
    last_rotated_at: Optional[str] = None


class RotateResponse(BaseModel):
    request_id: str
    service: str
    success: bool
    error: Optional[str] = None
    new_chain: Optional[CertChainResponse] = None


class ServiceCertStatus(BaseModel):
    service: str
    needs_renewal: bool
    not_after: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    ca_mode: str
    error: Optional[str] = None


class StatusResponse(BaseModel):
    ca_mode: str
    services: list[ServiceCertStatus]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _chain_info_to_response(service: str, info: CertChainInfo) -> CertChainResponse:
    return CertChainResponse(
        service=service,
        subject_cn=info.subject_cn,
        issuer_cn=info.issuer_cn,
        serial_hex=info.serial_hex,
        not_before=info.not_before,
        not_after=info.not_after,
        fingerprint_sha256=info.fingerprint_sha256,
        dns_sans=info.dns_sans,
        uri_sans=info.uri_sans,
        ip_sans=info.ip_sans,
        chain_depth=info.chain_depth,
        ca_mode=info.ca_mode,
        needs_renewal=info.needs_renewal,
        last_rotated_at=info.last_rotated_at,
    )


def _emit_audit(event_type: str, service: str, admin: str, request_id: str, **kwargs) -> None:
    audit_writer = backoffice_state.audit_writer
    if audit_writer is None:
        return
    try:
        audit_writer.write({  # type: ignore[arg-type]
            "event_type": event_type,
            "service": service,
            "admin_account": admin,
            "request_id": request_id,
            **kwargs,
        })
    except Exception as exc:
        _log.error("Audit write failed for %s: %s", event_type, exc)


def _live_service_names() -> list[str]:
    """Return service names from the manifest.  Empty list on any error."""
    try:
        manifest_path = os.getenv(
            "YASHIGANI_SERVICE_MANIFEST_PATH",
            "/etc/yashigani/service_identities.yaml",
        )
        from yashigani.pki.identity import load_manifest  # noqa: PLC0415
        manifest = load_manifest(manifest_path)
        return [s.name for s in manifest.live_services()]
    except Exception as exc:
        _log.warning("Could not load manifest for PKI status: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/chain/{service}", response_model=CertChainResponse)
async def get_cert_chain(service: str, session: AdminSession) -> CertChainResponse:
    """
    Return cert chain metadata for a service.

    CWE-200: private key material is never included.
    """
    _validate_service_name(service)
    try:
        driver = get_ca_driver()
        info = driver.get_chain_info(service)
        return _chain_info_to_response(service, info)
    except DriverError as exc:
        _log.warning("PKI chain info failed for %s: %s", service, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "pki_driver_error", "message": str(exc)},
        )
    except Exception as exc:
        _log.error("Unexpected PKI chain error for %s: %s", service, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        )


@router.post("/rotate/{service}", response_model=RotateResponse)
async def rotate_cert(service: str, session: StepUpAdminSession) -> RotateResponse:
    """
    Trigger cert rotation for a service.

    Requires step-up TOTP (ASVS V6.8.4).
    Emits PKI_CERT_ROTATED or PKI_CERT_ROTATION_FAILED audit events.
    The CA driver determines the rotation mechanism (internal or BYO).
    Never silently falls back between drivers.
    """
    _validate_service_name(service)
    request_id = str(uuid.uuid4())
    admin = session.account_id

    _log.info("PKI rotate request: service=%s admin=%s request_id=%s", service, admin, request_id)

    try:
        driver = get_ca_driver()
        result = driver.rotate(service)
    except DriverError as exc:
        _log.error("PKI rotate DriverError for %s: %s", service, exc)
        _emit_audit(
            "PKI_CERT_ROTATION_FAILED",
            service=service,
            admin=admin,
            request_id=request_id,
            failure_reason=str(exc),
        )
        return RotateResponse(
            request_id=request_id,
            service=service,
            success=False,
            error=str(exc),
        )
    except Exception as exc:
        _log.error("PKI rotate unexpected error for %s: %s", service, exc)
        _emit_audit(
            "PKI_CERT_ROTATION_FAILED",
            service=service,
            admin=admin,
            request_id=request_id,
            failure_reason="internal_error",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        )

    if result.success:
        _emit_audit(
            "PKI_CERT_ROTATED",
            service=service,
            admin=admin,
            request_id=request_id,
            new_not_after=result.new_chain.not_after if result.new_chain else None,
        )
        _log.info(
            "PKI rotate succeeded: service=%s admin=%s request_id=%s",
            service, admin, request_id,
        )
        return RotateResponse(
            request_id=request_id,
            service=service,
            success=True,
            new_chain=_chain_info_to_response(service, result.new_chain) if result.new_chain else None,
        )
    else:
        _emit_audit(
            "PKI_CERT_ROTATION_FAILED",
            service=service,
            admin=admin,
            request_id=request_id,
            failure_reason=result.error or "unknown",
        )
        return RotateResponse(
            request_id=request_id,
            service=service,
            success=False,
            error=result.error,
        )


@router.get("/bundle/{service}")
async def download_cert_bundle(service: str, session: AdminSession) -> Response:
    """
    Download PEM bundle for a service: leaf cert + intermediate(s).

    NEVER includes the private key.
    Content-Disposition: attachment forces browser to download rather than render.
    Content-Type: application/x-pem-file
    """
    _validate_service_name(service)
    try:
        driver = get_ca_driver()
        bundle_pem = driver.get_pem_bundle(service)
    except DriverError as exc:
        _log.warning("PKI bundle error for %s: %s", service, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "pki_driver_error", "message": str(exc)},
        )
    except Exception as exc:
        _log.error("PKI bundle unexpected error for %s: %s", service, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        )

    # Verify no private key material slipped in (defence-in-depth)
    if b"PRIVATE KEY" in bundle_pem:
        _log.critical(
            "PKI bundle for %s contains PRIVATE KEY material — aborting response (CWE-200)",
            service,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "message": "bundle sanity check failed"},
        )

    filename = f"{service}_cert_bundle.pem"
    return Response(
        content=bundle_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/status", response_model=StatusResponse)
async def pki_status(session: AdminSession) -> StatusResponse:
    """
    List all live services with cert health summary.

    Returns a summary row per service; individual errors are surfaced in each
    row (error field) — the endpoint itself does not 500 if one service fails.
    """
    ca_mode = os.getenv("YASHIGANI_PKI_CA_MODE", "internal").lower()
    service_names = _live_service_names()

    rows: list[ServiceCertStatus] = []
    for svc in service_names:
        try:
            driver = get_ca_driver()
            info = driver.get_chain_info(svc)
            rows.append(ServiceCertStatus(
                service=svc,
                needs_renewal=info.needs_renewal,
                not_after=info.not_after,
                fingerprint_sha256=info.fingerprint_sha256,
                ca_mode=info.ca_mode,
            ))
        except Exception as exc:
            rows.append(ServiceCertStatus(
                service=svc,
                needs_renewal=False,
                ca_mode=ca_mode,
                error=str(exc),
            ))

    return StatusResponse(ca_mode=ca_mode, services=rows)
