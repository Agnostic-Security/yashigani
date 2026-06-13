"""
Yashigani Backoffice — License admin routes.

All routes require an active admin session.

Routes:
  GET    /admin/license                — current license status + usage across all dimensions
  GET    /admin/license/status         — machine-readable expiry status (authenticated admin)
  GET    /admin/license/entitlements   — R23: tier-gated features + current tier entitlements
  POST   /admin/license/activate       — activate a new license key
  DELETE /admin/license                — revert to community license
"""
# Last updated: 2026-06-13T00:00:00+01:00 (v2.25.5 R23: /admin/license/entitlements)
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session

logger = logging.getLogger(__name__)
license_router = APIRouter(tags=["license"])

_LICENSE_SECRET_PATH = "/run/secrets/license_key"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ActivateRequest(BaseModel):
    license_content: Optional[str] = None


class RevertRequest(BaseModel):
    confirm: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _limit_block(current: int, maximum: int) -> dict:
    return {
        "current": current,
        "maximum": maximum if maximum != -1 else None,
        "unlimited": maximum == -1,
    }


def get_license_banner_context(now: Optional[datetime] = None) -> dict:
    """
    Return a context dict suitable for injection into every Jinja2 template.

    Keys:
      license_mode      — str value of LicenseExpiryMode (e.g. "active", "warning")
      license_days      — int | None (days remaining; negative = past expiry; None = perpetual)
      license_expires   — ISO-8601 string | None
      license_banner    — dict with keys: show (bool), severity (str), message (str)

    This helper is safe to call before the licence is fully loaded (returns ACTIVE defaults
    if the licensing module is unavailable).
    """
    try:
        from yashigani.licensing import get_license
        from yashigani.licensing.model import LicenseExpiryMode  # noqa: F401 — used in _build_banner
    except ImportError:
        return _banner_defaults()

    try:
        lic = get_license()
    except Exception:
        return _banner_defaults()

    if now is None:
        now = datetime.now(timezone.utc)

    mode = lic.expiry_mode(now=now)
    days = lic.days_remaining(now=now)
    expires_at_str = lic.expires_at.isoformat() if lic.expires_at is not None else None

    banner = _build_banner(mode, days)

    return {
        "license_mode": mode.value,
        "license_days": days,
        "license_expires": expires_at_str,
        "license_banner": banner,
    }


def _banner_defaults() -> dict:
    from yashigani.licensing.model import LicenseExpiryMode
    return {
        "license_mode": LicenseExpiryMode.ACTIVE.value,
        "license_days": None,
        "license_expires": None,
        "license_banner": {"show": False, "severity": "none", "message": ""},
    }


def _build_banner(mode, days: Optional[int]) -> dict:
    """Build the banner payload for a given mode and days-remaining value."""
    from yashigani.licensing.model import LicenseExpiryMode

    if mode == LicenseExpiryMode.ACTIVE:
        return {"show": False, "severity": "none", "message": ""}

    if mode == LicenseExpiryMode.WARNING:
        return {
            "show": True,
            "severity": "warning",
            "message": (
                f"Yashigani licence expires in {days} day{'s' if days != 1 else ''} — "
                "renew to avoid service interruption."
            ),
        }

    if mode == LicenseExpiryMode.CRITICAL:
        return {
            "show": True,
            "severity": "critical",
            "message": (
                f"Yashigani licence expires in {days} day{'s' if days != 1 else ''} — "
                "renew now: sales@agnosticsec.com."
            ),
        }

    if mode == LicenseExpiryMode.EXPIRED:
        days_since = -days if days is not None else "?"
        from yashigani.licensing.model import GRACE_PERIOD_DAYS
        grace_left = GRACE_PERIOD_DAYS - days_since if isinstance(days_since, int) else "?"
        return {
            "show": True,
            "severity": "expired",
            "message": (
                f"Yashigani licence has expired. {grace_left} day{'s' if grace_left != 1 else ''} "
                "of grace period remain. Renew now: sales@agnosticsec.com."
            ),
        }

    if mode == LicenseExpiryMode.READONLY:
        return {
            "show": True,
            "severity": "readonly",
            "message": (
                "Yashigani licence expired. Gateway is in read-only mode — "
                "configuration changes and new agent-runs are blocked. "
                "Renew now: sales@agnosticsec.com."
            ),
        }

    # BLOCKED
    return {
        "show": True,
        "severity": "blocked",
        "message": (
            "Yashigani licence expired more than 30 days ago. Gateway is blocked. "
            "Renew at https://agnosticsec.com/pricing or contact sales@agnosticsec.com."
        ),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@license_router.get("")
async def get_license_status(session=Depends(require_admin_session)):
    from yashigani.licensing import get_license
    from yashigani.backoffice.state import backoffice_state

    lic = get_license()

    # Agent count
    current_agents = 0
    registry = backoffice_state.agent_registry
    if registry is not None:
        try:
            current_agents = registry.count("all")
        except Exception:
            current_agents = 0

    # End user count — non-admin accounts in auth_service.
    # NOTE: previously called `auth.count_users(admin=False)` which doesn't
    # exist on LocalAuthService — the AttributeError was swallowed by the
    # except clause and current_end_users silently reported 0, disagreeing
    # with the enforcer which uses total_user_count() correctly (QA Wave 2
    # Issue D).
    current_end_users = 0
    auth = backoffice_state.auth_service
    if auth is not None:
        try:
            current_end_users = await auth.total_user_count()
        except Exception:
            current_end_users = 0

    # Admin seat count — same bug, same fix.
    current_admin_seats = 0
    if auth is not None:
        try:
            current_admin_seats = await auth.total_admin_count()
        except Exception:
            current_admin_seats = 0

    # Org count (single-org in non-Enterprise deployments)
    current_orgs = 1

    expires_at = lic.expires_at.isoformat() if lic.expires_at is not None else None

    return {
        "tier": lic.tier.value,
        "org_domain": lic.org_domain,
        "valid": lic.valid,
        "expires_at": expires_at,
        "license_id": lic.license_id,
        "limits": {
            "agents":       _limit_block(current_agents,      lic.max_agents),
            "end_users":    _limit_block(current_end_users,   lic.max_end_users),
            "admin_seats":  _limit_block(current_admin_seats, lic.max_admin_seats),
            "orgs":         _limit_block(current_orgs,        lic.max_orgs),
        },
        "features": {
            "oidc": lic.has_feature("oidc"),
            "saml": lic.has_feature("saml"),
            "scim": lic.has_feature("scim"),
        },
        "upgrade_url": "https://agnosticsec.com/pricing",
    }


@license_router.get("/status", summary="Machine-readable expiry status")
async def get_license_expiry_status(session=Depends(require_admin_session)):
    """
    GET /admin/license/status

    Returns a machine-readable summary of licence expiry state.  Also available
    as GET /api/v1/license/status (mounted separately in app.py).

    Response shape (v2.23.3):
      {
        "valid": bool,
        "expires_at": "ISO-8601" | null,
        "days_remaining": int | null,
        "grace_period_active": bool,
        "mode": "active" | "warning" | "critical" | "expired" | "readonly" | "blocked"
      }

    Authentication: admin session required (same as all /admin/* routes).

    mode semantics:
      active   — >30 days until expiry, or no expiry date
      warning  — 7–30 days remaining (yellow banner)
      critical — 1–7 days remaining (orange banner)
      expired  — within 14-day grace period (red banner, continues serving)
      readonly — 14–30 days past expiry (admin view-only; new runs blocked)
      blocked  — 30+ days past expiry (HTTP 503 on data-plane)
    """
    from yashigani.licensing import get_license
    from yashigani.licensing.model import LicenseExpiryMode

    lic = get_license()
    now = datetime.now(timezone.utc)
    mode = lic.expiry_mode(now=now)
    days = lic.days_remaining(now=now)
    expires_at_str = lic.expires_at.isoformat() if lic.expires_at is not None else None

    grace_period_active = mode == LicenseExpiryMode.EXPIRED

    return {
        "valid": lic.valid,
        "expires_at": expires_at_str,
        "days_remaining": days,
        "grace_period_active": grace_period_active,
        "mode": mode.value,
    }


@license_router.get("/entitlements", summary="R23: Tier-gated features and current tier entitlements")
async def get_license_entitlements(session=Depends(require_admin_session)):
    """
    GET /admin/license/entitlements

    R23 — Returns which features are tier-gated and whether the current tier
    grants them. Suitable for UI feature-lock / upgrade-prompt logic.

    Response shape:
      {
        "current_tier": str,              # e.g. "community"
        "entitlements": [
          {
            "feature": str,               # feature key, e.g. "oidc"
            "label": str,                 # human-readable name
            "description": str,           # what the feature enables
            "available": bool,            # true if current tier includes it
            "required_tier": str,         # minimum tier that unlocks it
            "required_tier_label": str,   # display name for the required tier
            "upgrade_url": str | null,    # upgrade URL when not available
          },
          ...
        ]
      }

    Sources from licensing/enforcer.py and licensing/model.py — the single
    source of truth for tier/feature gating.
    """
    from yashigani.licensing import get_license
    from yashigani.licensing.model import LicenseTier

    lic = get_license()

    # Canonical feature catalogue: (feature_key, label, description, min_tier)
    # Ordered by tier requirement (lowest first).
    _FEATURE_CATALOGUE = [
        (
            "oidc",
            "OIDC / OAuth2 SSO",
            (
                "Single Sign-On via OpenID Connect or OAuth2 identity providers "
                "(e.g. Google Workspace, Microsoft Entra, Okta). Lets users log "
                "in to the gateway via their corporate IdP."
            ),
            LicenseTier.STARTER,
        ),
        (
            "saml",
            "SAML 2.0 SSO",
            (
                "Enterprise Single Sign-On via SAML 2.0 identity providers. "
                "Required for organisations using on-premises IdPs such as "
                "Active Directory Federation Services (ADFS)."
            ),
            LicenseTier.PROFESSIONAL,
        ),
        (
            "scim",
            "SCIM User Provisioning",
            (
                "Automated user and group provisioning via SCIM 2.0. Allows your "
                "IdP to push user lifecycle events (create / update / deprovision) "
                "directly to Yashigani without manual admin intervention."
            ),
            LicenseTier.PROFESSIONAL,
        ),
        (
            "pii_log",
            "PII Detection (Log mode)",
            (
                "Detects personally identifiable information in LLM payloads and "
                "records findings in the audit log. Payloads are not modified; "
                "this is an observability-only mode for compliance reporting."
            ),
            LicenseTier.PROFESSIONAL_PLUS,
        ),
        (
            "pii_redact",
            "PII Redaction / Blocking",
            (
                "Detects PII in LLM payloads and either redacts sensitive fields "
                "before forwarding to the model, or blocks the request entirely. "
                "Requires pii_log to be available on the same tier."
            ),
            LicenseTier.PROFESSIONAL_PLUS,
        ),
    ]

    # Tier ordering for the 'available' check (lower index = lower tier)
    _TIER_ORDER = [
        LicenseTier.COMMUNITY,
        LicenseTier.IGNITER,
        LicenseTier.STARTER,
        LicenseTier.PROFESSIONAL,
        LicenseTier.PROFESSIONAL_PLUS,
        LicenseTier.ENTERPRISE,
        LicenseTier.ACADEMIC_NONPROFIT,
    ]

    def _tier_gte(current: LicenseTier, required: LicenseTier) -> bool:
        """True if current tier is >= required tier."""
        # Enterprise and academic_nonprofit always qualify
        if current in (LicenseTier.ENTERPRISE, LicenseTier.ACADEMIC_NONPROFIT):
            return True
        try:
            return _TIER_ORDER.index(current) >= _TIER_ORDER.index(required)
        except ValueError:
            return False

    _TIER_DISPLAY: dict[LicenseTier, str] = {
        LicenseTier.COMMUNITY:          "Community",
        LicenseTier.IGNITER:            "Igniter",
        LicenseTier.STARTER:            "Starter",
        LicenseTier.PROFESSIONAL:       "Professional",
        LicenseTier.PROFESSIONAL_PLUS:  "Professional Plus",
        LicenseTier.ENTERPRISE:         "Enterprise",
        LicenseTier.ACADEMIC_NONPROFIT: "Academic / Non-profit",
        LicenseTier.CANARY:             "Canary (internal)",
    }

    entitlements = []
    for feature_key, label, description, required_tier in _FEATURE_CATALOGUE:
        available = lic.has_feature(feature_key) or _tier_gte(lic.tier, required_tier)
        entitlements.append({
            "feature": feature_key,
            "label": label,
            "description": description,
            "available": available,
            "required_tier": required_tier.value,
            "required_tier_label": _TIER_DISPLAY.get(required_tier, required_tier.value),
            "upgrade_url": None if available else "https://agnosticsec.com/pricing",
        })

    return {
        "current_tier": lic.tier.value,
        "current_tier_label": _TIER_DISPLAY.get(lic.tier, lic.tier.value),
        "entitlements": entitlements,
        "upgrade_url": "https://agnosticsec.com/pricing",
    }


@license_router.post("/activate")
async def activate_license(
    license_content: Optional[str] = Form(default=None),
    license_file: Optional[UploadFile] = File(default=None),
    session=Depends(require_stepup_admin_session),
):
    from yashigani.licensing import set_license
    from yashigani.licensing.verifier import verify_license

    content: Optional[str] = None
    if license_file is not None:
        raw = await license_file.read()
        content = raw.decode("utf-8").strip()
    elif license_content is not None:
        content = license_content.strip()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "MISSING_LICENSE_CONTENT", "detail": "Provide license_content or license_file"},
        )

    # M-05 / LAURA-V231-002 follow-on: verify_license() is guarded here so that
    # a crafted malformed license file (null seat fields, garbage bytes, truncated
    # content, malformed JSON) cannot crash the backoffice worker with an
    # unhandled exception → 500 (DoS on admin plane, authenticated session required).
    # The route responds with a clean 4xx to the admin, logs the rejection, and
    # does NOT re-raise.
    try:
        new_lic = verify_license(content)
    except Exception as exc:
        logger.warning(
            "License activation rejected — verify_license raised unexpectedly "
            "(M-05 / LAURA-V231-002): %s",
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": "malformed_license_content"},
        )

    if not new_lic.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": new_lic.error},
        )

    # LAURA-LICENSE-01 / GROUP-2-1: cross-tenant activate check.
    # A domain-bound license must match this deployment's YASHIGANI_TLS_DOMAIN.
    # Without this check an admin could activate a license issued to a different
    # org's domain — it would load but be rejected at the loader level after
    # restart, causing silent Community downgrade. Reject explicitly here.
    if new_lic.org_domain != "*":
        from yashigani.licensing.loader import _normalise_domain
        runtime_domain = os.environ.get("YASHIGANI_TLS_DOMAIN", "")
        if not runtime_domain:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "domain_mismatch",
                    "detail": (
                        "License is domain-bound but YASHIGANI_TLS_DOMAIN is not set. "
                        "Set YASHIGANI_TLS_DOMAIN to match the license org_domain."
                    ),
                },
            )
        if _normalise_domain(runtime_domain) != _normalise_domain(new_lic.org_domain):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "domain_mismatch",
                    "detail": (
                        f"License is bound to '{new_lic.org_domain}' but this "
                        f"deployment's YASHIGANI_TLS_DOMAIN is '{runtime_domain}'. "
                        "Activate a license issued for this deployment's domain."
                    ),
                },
            )

    set_license(new_lic)

    try:
        with open(_LICENSE_SECRET_PATH, "w") as fh:
            fh.write(content)
    except OSError:
        logger.debug("License key secret path not writable (%s) — skipping persist", _LICENSE_SECRET_PATH)

    expires_at = new_lic.expires_at.isoformat() if new_lic.expires_at is not None else None

    logger.info(
        "License activated by %s: tier=%s org_domain=%s agents=%s end_users=%s admin_seats=%s",
        session.account_id,
        new_lic.tier.value,
        new_lic.org_domain,
        new_lic.max_agents,
        new_lic.max_end_users,
        new_lic.max_admin_seats,
    )

    return {
        "status": "activated",
        "tier": new_lic.tier.value,
        "org_domain": new_lic.org_domain,
        "expires_at": expires_at,
        "limits": {
            "agents":      new_lic.max_agents      if new_lic.max_agents      != -1 else "unlimited",
            "end_users":   new_lic.max_end_users   if new_lic.max_end_users   != -1 else "unlimited",
            "admin_seats": new_lic.max_admin_seats if new_lic.max_admin_seats != -1 else "unlimited",
            "orgs":        new_lic.max_orgs        if new_lic.max_orgs        != -1 else "unlimited",
        },
    }


@license_router.delete("")
async def revert_license(body: RevertRequest, session=Depends(require_stepup_admin_session)):
    from yashigani.licensing import COMMUNITY_LICENSE, set_license

    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "CONFIRM_REQUIRED", "detail": "Set confirm=true to revert to community license"},
        )

    set_license(COMMUNITY_LICENSE)

    try:
        if os.path.exists(_LICENSE_SECRET_PATH):
            os.remove(_LICENSE_SECRET_PATH)
    except OSError as exc:
        logger.warning("Could not remove license key secret file: %s", exc)

    logger.info("License reverted to community by %s", session.account_id)

    return {"status": "reverted", "tier": "community"}
