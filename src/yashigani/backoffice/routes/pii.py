"""
Yashigani Backoffice — PII configuration and test routes (v2.2).

ENT-001 (2026-06-14): PII detection (LOG / REDACT / BLOCK) is available on ALL tiers
including Community/free.  There is no license gate on PII.  The _require_pii_feature()
helper is retained as a no-op stub so call-sites need no change, but it no longer raises.

Routes:
  GET  /admin/pii/config          — current PII config (mode, enabled types)
  PUT  /admin/pii/config          — update mode and enabled types
  POST /admin/pii/test            — test PII detection against sample text
                                    (findings returned; nothing written to audit)
  GET  /admin/pii/cloud-bypass    — current cloud bypass setting
  PUT  /admin/pii/cloud-bypass    — toggle cloud bypass (requires admin session)

Cloud bypass (OFF by default):
  When enabled, PII filtering is skipped for cloud-routed requests only.
  Local (Ollama) traffic is ALWAYS filtered regardless of this setting.
  This is an explicit admin opt-in to allow PII to reach cloud LLMs.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
# ENT-001: LicenseFeatureGated / require_feature no longer used in this module
#          (PII is always available); imports removed to keep ruff clean.
from yashigani.pii.detector import PiiDetector, PiiMode, PiiType

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Module-level config store (in-process; persisted to backoffice_state attrs)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict = {
    "mode": PiiMode.LOG.value,
    "enabled_types": [t.value for t in PiiType],
}

# Cloud bypass is a separate flag — stored independently from mode/types config.
_DEFAULT_CLOUD_BYPASS: bool = False


def _get_config() -> dict:
    return getattr(backoffice_state, "pii_config", _DEFAULT_CONFIG.copy())


def _set_config(cfg: dict) -> None:
    backoffice_state.pii_config = cfg  # type: ignore[attr-defined]


def _get_cloud_bypass() -> bool:
    return getattr(backoffice_state, "pii_cloud_bypass", _DEFAULT_CLOUD_BYPASS)


def _set_cloud_bypass(enabled: bool) -> None:
    backoffice_state.pii_cloud_bypass = enabled  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class PiiConfigRequest(BaseModel):
    mode: str = Field(
        description="Detection mode: log | redact | block",
        pattern=r"^(log|redact|block)$",
    )
    enabled_types: list[str] = Field(
        description="List of PiiType values to enable. Empty list enables all.",
        default_factory=list,
    )

    @field_validator("enabled_types")
    @classmethod
    def validate_types(cls, values: list[str]) -> list[str]:
        valid = {t.value for t in PiiType}
        bad = [v for v in values if v not in valid]
        if bad:
            raise ValueError(f"Unknown PII types: {bad}. Valid: {sorted(valid)}")
        return values


class PiiTestRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    mode: Optional[str] = Field(
        default=None,
        description="Override mode for this test call (log | redact | block). "
                    "Defaults to the currently configured mode.",
        pattern=r"^(log|redact|block)$",
    )


class PiiCloudBypassRequest(BaseModel):
    enabled: bool = Field(
        description=(
            "When true, PII filtering is skipped for cloud-routed requests. "
            "Local (Ollama) traffic is ALWAYS filtered regardless of this flag. "
            "Enabling this is an explicit opt-in to allow PII to reach cloud LLMs."
        )
    )


# ---------------------------------------------------------------------------
# License helpers
# ---------------------------------------------------------------------------

def _require_pii_feature(mode: str) -> None:  # noqa: ARG001
    """No-op stub (ENT-001, 2026-06-14).

    PII detection is available on ALL tiers including Community.  This function
    previously raised HTTP 402 for tiers below Professional Plus; that gate is
    removed.  The stub is retained so call-sites in this module need no change.
    """
    # require_feature("pii_log"/"pii_redact") now short-circuits in enforcer.py
    # via _ALWAYS_AVAILABLE_FEATURES and will never raise LicenseFeatureGated —
    # but calling it here is equally correct.  We keep the body empty to make the
    # intent explicit: this is intentionally a no-op.


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_pii_config(session: AdminSession):
    """Return the current PII detection configuration."""
    _require_pii_feature("log")  # reading config also requires at minimum pii_log
    cfg = _get_config()
    return {
        "mode": cfg["mode"],
        "enabled_types": cfg.get("enabled_types", [t.value for t in PiiType]),
        "all_types": [t.value for t in PiiType],
    }


@router.put("/config")
async def update_pii_config(
    body: PiiConfigRequest,
    session: AdminSession,
):
    """Update PII detection mode and enabled types."""
    _require_pii_feature(body.mode)

    enabled = body.enabled_types if body.enabled_types else [t.value for t in PiiType]
    cfg = {"mode": body.mode, "enabled_types": enabled}
    _set_config(cfg)

    # Audit the config change
    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="pii_config",
                previous_value="(previous)",
                new_value=f"mode={body.mode} types={enabled}",
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for pii_config: %s", exc)

    return {"status": "ok", "mode": body.mode, "enabled_types": enabled}


@router.post("/test")
async def test_pii_detection(
    body: PiiTestRequest,
    session: AdminSession,
):
    """Test PII detection against a sample text.

    Uses the currently configured (or override) mode.
    Results are returned to the caller; nothing is written to audit logs.
    Raw matched values are NEVER returned — only masked_value is included.
    """
    cfg = _get_config()
    test_mode_str = body.mode or cfg["mode"]
    _require_pii_feature(test_mode_str)

    try:
        test_mode = PiiMode(test_mode_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_mode", "mode": test_mode_str},
        )

    enabled_type_values: list[str] = cfg.get("enabled_types", [t.value for t in PiiType])
    enabled_set: set[PiiType] = {PiiType(v) for v in enabled_type_values}

    detector = PiiDetector(mode=test_mode, enabled_types=enabled_set)
    output_text, result = detector.process(body.text)

    findings_out = [
        {
            "pii_type": f.pii_type.value,
            "start": f.start,
            "end": f.end,
            "masked_value": f.masked_value,  # raw value never returned
        }
        for f in result.findings
    ]

    return {
        "detected": result.detected,
        "action_taken": result.action_taken,
        "mode": result.mode.value,
        "finding_count": len(findings_out),
        "findings": findings_out,
        # Return redacted text only in REDACT mode so admins can preview output.
        "output_text": output_text if test_mode == PiiMode.REDACT else None,
    }


@router.get("/cloud-bypass")
async def get_pii_cloud_bypass(session: AdminSession):
    """Return the current PII cloud bypass setting.

    When cloud bypass is enabled, PII filtering is skipped for cloud-routed
    requests. Local (Ollama) traffic is always filtered.
    """
    _require_pii_feature("log")
    return {
        "cloud_bypass_enabled": _get_cloud_bypass(),
        "warning": (
            "When enabled, PII may reach cloud LLM providers. "
            "Local (Ollama) traffic is always filtered regardless of this setting."
        ),
    }


@router.put("/cloud-bypass")
async def update_pii_cloud_bypass(
    body: PiiCloudBypassRequest,
    session: AdminSession,
):
    """Toggle the PII cloud bypass setting.

    ENT-001: no license gate — PII bypass is available on all tiers.

    Local (Ollama) traffic is NEVER affected — it is always filtered.
    This setting only controls whether PII filtering runs for requests
    that the optimization engine routes to cloud providers.
    """
    _require_pii_feature("redact" if body.enabled else "log")  # no-op (ENT-001)

    previous = _get_cloud_bypass()
    _set_cloud_bypass(body.enabled)

    logger.info(
        "PII cloud bypass changed: %s -> %s (admin=%s)",
        previous,
        body.enabled,
        session.account_id,
    )

    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="pii_cloud_bypass",
                previous_value=str(previous),
                new_value=str(body.enabled),
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for pii_cloud_bypass: %s", exc)

    return {
        "status": "ok",
        "cloud_bypass_enabled": body.enabled,
        "warning": (
            "PII may now reach cloud LLM providers. "
            "Local (Ollama) traffic remains filtered at all times."
        ) if body.enabled else None,
    }
