"""License model — tiers, state, community defaults."""
# Last updated: 2026-05-07T00:00:00+01:00 (v2.23.3 expiry UX: LicenseExpiryMode + expiry_status())
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Union


class LicenseTier(str, Enum):
    COMMUNITY          = "community"
    IGNITER            = "igniter"
    STARTER            = "starter"
    PROFESSIONAL       = "professional"
    PROFESSIONAL_PLUS  = "professional_plus"
    ENTERPRISE         = "enterprise"
    ACADEMIC_NONPROFIT = "academic_nonprofit"
    # v2.23.2 GROUP-5-3: canary sentinel — never issued to customers.
    # If verify_license() accepts a CANARY token, the verifier has been patched
    # to remove tier filtering. Tested by canary-token integration test.
    CANARY             = "canary"


class LicenseExpiryMode(str, Enum):
    """
    Operational mode derived from licence expiry state.

    v2.23.3 expiry UX — canonical thresholds:
      ACTIVE    — more than 30 days until expiry (or no expiry date)
      WARNING   — 7–30 days remaining (yellow banner)
      CRITICAL  — 1–7 days remaining (orange banner)
      EXPIRED   — expired, within 14-day grace period (red banner, continues serving)
      READONLY  — 14–30 days past expiry (admin view-only; new agent-runs blocked)
      BLOCKED   — more than 30 days past expiry (HTTP 503)
    """
    ACTIVE   = "active"
    WARNING  = "warning"
    CRITICAL = "critical"
    EXPIRED  = "expired"    # grace period active (days 0–14 past expiry)
    READONLY = "readonly"   # read-only mode (days 14–30 past expiry)
    BLOCKED  = "blocked"    # full block (day 30+ past expiry)


# Grace-period configuration (v2.23.3).
# Days past expiry before mode escalates.
GRACE_PERIOD_DAYS: int = 14         # EXPIRED → READONLY transition
READONLY_PERIOD_DAYS: int = 30      # READONLY → BLOCKED transition

# Warning window thresholds (days remaining, inclusive boundary).
WARN_YELLOW_DAYS: int = 30          # >7 and <=30 days remaining
WARN_ORANGE_DAYS: int = 7           # >0 and <=7 days remaining


def compute_expiry_mode(expires_at: Optional[datetime], now: Optional[datetime] = None) -> LicenseExpiryMode:
    """
    Compute the operational mode for a given expiry timestamp.

    Args:
        expires_at: UTC datetime when the licence expires; None means perpetual (ACTIVE).
        now:        UTC datetime representing 'now'; defaults to datetime.now(timezone.utc).
                    Injected in tests to avoid time-dependent failures.

    Returns:
        LicenseExpiryMode appropriate for the current instant.

    This function is pure (no I/O, no state) and safe to call from any context.
    """
    if expires_at is None:
        return LicenseExpiryMode.ACTIVE

    if now is None:
        now = datetime.now(timezone.utc)

    delta = expires_at - now
    days_remaining = delta.days  # negative when past expiry

    if days_remaining > WARN_YELLOW_DAYS:
        return LicenseExpiryMode.ACTIVE
    if days_remaining > WARN_ORANGE_DAYS:
        return LicenseExpiryMode.WARNING
    if days_remaining >= 0:
        return LicenseExpiryMode.CRITICAL
    # Past expiry — days_remaining is negative; days_since_expiry is positive
    days_since_expiry = -days_remaining
    if days_since_expiry <= GRACE_PERIOD_DAYS:
        return LicenseExpiryMode.EXPIRED
    if days_since_expiry <= READONLY_PERIOD_DAYS:
        return LicenseExpiryMode.READONLY
    return LicenseExpiryMode.BLOCKED


class LicenseFeature(str, Enum):
    OIDC       = "oidc"
    SAML       = "saml"
    SCIM       = "scim"
    # v2.2 — PII detection (Professional Plus+)
    PII_LOG    = "pii_log"      # LOG mode: detect and record findings only
    PII_REDACT = "pii_redact"   # REDACT and BLOCK modes: mutate or block payloads


@dataclass(frozen=True)
class LicenseState:
    tier: LicenseTier
    org_domain: str                       # "*" means any domain (community)
    max_agents: int                       # -1 = unlimited
    max_end_users: int                    # end users proxied through gateway, -1 = unlimited
    max_admin_seats: int                  # backoffice admin accounts, -1 = unlimited
    max_orgs: int                         # -1 = unlimited
    features: frozenset[LicenseFeature]   # typed feature set; verifier coerces strings on load
    issued_at: datetime
    expires_at: Optional[datetime]
    license_id: Optional[str]
    valid: bool
    error: Optional[str]

    def has_feature(self, feature: Union[LicenseFeature, str]) -> bool:
        if isinstance(feature, str):
            try:
                feature = LicenseFeature(feature)
            except ValueError:
                return False
        return feature in self.features

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def expiry_mode(self, now: Optional[datetime] = None) -> LicenseExpiryMode:
        """Return the current LicenseExpiryMode for this licence."""
        return compute_expiry_mode(self.expires_at, now=now)

    def days_remaining(self, now: Optional[datetime] = None) -> Optional[int]:
        """
        Days remaining until expiry, or None if the licence has no expiry date.
        Negative values indicate days past expiry.
        """
        if self.expires_at is None:
            return None
        if now is None:
            now = datetime.now(timezone.utc)
        return (self.expires_at - now).days


# Per-tier limit defaults — used by verifier for backwards-compat with
# v1/v2 license payloads that pre-date the max_end_users / max_admin_seats fields.
# Source of truth: README §8 Feature Matrix by Tier (mirrors agnosticsec.com/pricing).
TIER_DEFAULTS: dict[str, dict] = {
    "community":          {"max_agents": 20,    "max_end_users": 5,      "max_admin_seats": 2,   "max_orgs": 1},
    "igniter":            {"max_agents": 200,   "max_end_users": 50,     "max_admin_seats": 5,   "max_orgs": 1},
    "starter":            {"max_agents": 400,   "max_end_users": 100,    "max_admin_seats": 10,  "max_orgs": 1},
    "professional":       {"max_agents": 2000,  "max_end_users": 500,    "max_admin_seats": 25,  "max_orgs": 1},
    "professional_plus":  {"max_agents": 16000, "max_end_users": 4000,   "max_admin_seats": 100, "max_orgs": 5},
    "enterprise":         {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
    # Per README §8 / pricing page: Non-profit & Education = Unlimited everything.
    "academic_nonprofit": {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
    # canary: community limits (this tier is never legitimately issued)
    "canary":             {"max_agents": 20,    "max_end_users": 5,      "max_admin_seats": 2,   "max_orgs": 1},
}


# Community hardcoded defaults — no license file needed
# v2.23.2 canonical: 20 agents / 5 end users / 2 admin seats / 1 org
COMMUNITY_LICENSE = LicenseState(
    tier=LicenseTier.COMMUNITY,
    org_domain="*",
    max_agents=20,
    max_end_users=5,
    max_admin_seats=2,
    max_orgs=1,
    features=frozenset(),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)

# Academic / non-profit hardcoded defaults — requires a signed license file.
# Per README §8 / pricing page: Non-profit & Education has Unlimited everything.
ACADEMIC_NONPROFIT_LICENSE = LicenseState(
    tier=LicenseTier.ACADEMIC_NONPROFIT,
    org_domain="*",
    max_agents=-1,
    max_end_users=-1,
    max_admin_seats=-1,
    max_orgs=-1,
    features=frozenset(),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)
