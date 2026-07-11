"""
Yashigani Backoffice — Cloud provider API key management.

Store/retrieve cloud-provider API keys (OpenAI, Anthropic) via the KMS
backend so the gateway can route to cloud models. Keys are NEVER stored
plaintext in the DB — they go into KMS only.

Routes:
  GET  /admin/cloud-keys   — list supported providers + whether each key is set
  PUT  /admin/cloud-keys   — store/update a provider API key (step-up required)

Gateway consumption:
  The gateway (openai_router.py) reads cloud keys from KMS via
  ``kms_provider.get_secret("{provider}_api_key")`` when building upstream
  request headers for cloud providers.  The key name convention is:
    openai    → ``openai_api_key``
    anthropic → ``anthropic_api_key``

Security:
  - PUT requires step-up TOTP (ASVS V6.8.4 — mutating secret operation).
  - GET reveals ONLY whether a key is set (bool), never the key value.
  - api_key value is validated: non-empty, max 512 chars.

Last updated: 2026-06-16T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.audit.schema import AdminCloudKeySetEvent

_log = logging.getLogger("yashigani.backoffice.cloud_keys")

router = APIRouter(prefix="/admin/cloud-keys", tags=["cloud-keys"])

# Supported providers and their KMS key names.
_PROVIDERS: dict[str, str] = {
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
}


class CloudKeySetRequest(BaseModel):
    provider: Literal["openai", "anthropic"]
    api_key: str = Field(min_length=1, max_length=512)


@router.get("")
async def list_cloud_keys(session: AdminSession):  # noqa: ARG001 — auth gate
    """Return whether each cloud provider API key is configured (never the value)."""
    kms = backoffice_state.kms_provider
    providers = []
    for provider, kms_key in _PROVIDERS.items():
        configured = False
        if kms is not None:
            try:
                val = kms.get_secret(kms_key)
                configured = bool(val)
            except Exception:
                configured = False
        providers.append({"provider": provider, "configured": configured})
    return {"providers": providers}


@router.put("")
async def set_cloud_key(body: CloudKeySetRequest, session: StepUpAdminSession):
    """Store or update a cloud provider API key via KMS. Step-up required."""
    kms = backoffice_state.kms_provider
    if kms is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "kms_unavailable",
                    "message": "KMS backend is not configured. Cannot store secrets securely."},
        )
    kms_key = _PROVIDERS[body.provider]
    try:
        kms.set_secret(kms_key, body.api_key)
    except Exception as exc:
        _log.error("cloud_keys: KMS set_secret failed for provider=%s: %s", body.provider, exc)
        raise HTTPException(
            status_code=500,
            detail={"error": "kms_write_failed",
                    "message": f"Could not store API key: {type(exc).__name__}"},
        )

    _log.warning(
        "Admin %s stored %s API key via KMS (key=%s)",
        session.account_id, body.provider, kms_key,
    )

    # Audit — compliance event must go into the hash-chain ledger.
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                AdminCloudKeySetEvent(
                    admin_account=session.account_id,
                    provider=body.provider,
                    kms_key=kms_key,
                )
            )
        except Exception as exc:
            _log.error("cloud_keys: failed to write AdminCloudKeySetEvent: %s", exc)

    return {"status": "stored", "provider": body.provider, "kms_key": kms_key}
