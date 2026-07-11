"""
Feature gate enforcement.

The active license is loaded once at startup and cached in module state.
All gate functions are synchronous — called from FastAPI route handlers.
"""
from __future__ import annotations

import logging

from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseState, LicenseTier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level license state
# ---------------------------------------------------------------------------

_license: LicenseState = COMMUNITY_LICENSE


def set_license(lic: LicenseState) -> None:
    """Set the active license. Called once at startup."""
    global _license
    _license = lic


def get_license() -> LicenseState:
    """Return the currently active license."""
    return _license


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LicenseFeatureGated(Exception):
    def __init__(self, feature: str, tier: LicenseTier) -> None:
        self.feature = feature
        self.tier = tier
        super().__init__(f"Feature '{feature}' is not available on {tier.value} tier")


class LicenseLimitExceeded(Exception):
    def __init__(self, limit_name: str, current: int, max_val: int) -> None:
        self.limit_name = limit_name
        self.current = current
        self.max_val = max_val
        super().__init__(
            f"License limit exceeded: {limit_name} ({current}/{max_val})"
        )


# ---------------------------------------------------------------------------
# Features that are always available regardless of tier (ENT-001, 2026-06-14)
# ---------------------------------------------------------------------------
# PII detection (LOG / REDACT / BLOCK) is available on every tier including
# Community/free.  This aligns with README §8 Feature Matrix (only OIDC/SAML/SCIM
# are tier-gated) and the product narrative "PII filtering runs on all traffic,
# by default".  The LicenseFeature enum values are kept for back-compat with
# license payloads issued under v2.2 that carry pii_log/pii_redact in their
# features claim — but those claims are never *required* at gate time.

_ALWAYS_AVAILABLE_FEATURES: frozenset[str] = frozenset({"pii_log", "pii_redact"})


# ---------------------------------------------------------------------------
# Gate functions
# ---------------------------------------------------------------------------

def require_feature(feature: str) -> None:
    """Raise LicenseFeatureGated if feature not in active license.

    Features listed in _ALWAYS_AVAILABLE_FEATURES are unconditionally permitted
    regardless of tier or what the license payload carries.
    """
    if feature in _ALWAYS_AVAILABLE_FEATURES:
        return  # ENT-001: PII is always available
    if not _license.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=_license.tier)


def check_agent_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_agents (and max != -1)."""
    if _license.max_agents == -1:
        return
    if current_count >= _license.max_agents:
        raise LicenseLimitExceeded(
            limit_name="max_agents",
            current=current_count,
            max_val=_license.max_agents,
        )


def check_end_user_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_end_users (and max != -1)."""
    if _license.max_end_users == -1:
        return
    if current_count >= _license.max_end_users:
        raise LicenseLimitExceeded(
            limit_name="max_end_users",
            current=current_count,
            max_val=_license.max_end_users,
        )


def check_admin_seat_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_admin_seats (and max != -1)."""
    if _license.max_admin_seats == -1:
        return
    if current_count >= _license.max_admin_seats:
        raise LicenseLimitExceeded(
            limit_name="max_admin_seats",
            current=current_count,
            max_val=_license.max_admin_seats,
        )


def check_org_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_orgs (and max != -1)."""
    if _license.max_orgs == -1:
        return
    if current_count >= _license.max_orgs:
        raise LicenseLimitExceeded(
            limit_name="max_orgs",
            current=current_count,
            max_val=_license.max_orgs,
        )


# ---------------------------------------------------------------------------
# Canonical end-user count (GROUP-2-3 / v2.23.2)
# ---------------------------------------------------------------------------

def count_canonical_end_users() -> int:
    """
    Return the canonical end-user count as the union of three pools,
    deduplicated by lowercase email address.

    Pools:
      1. auth_service — Postgres users table (non-admin accounts)
      2. IdentityRegistry — Redis identity:index:kind:human members
      3. RBAC store — all group members via RBACStore.list_groups()

    Design note (2026-05-05): canonical count = union(auth_service users,
    IdentityRegistry HUMAN, RBAC users), deduped by lowercase email.

    Async caveat: auth_service uses async Postgres. When called from within a
    running asyncio event loop (FastAPI route handlers) we cannot use
    run_until_complete(). In that context the auth_service pool is skipped
    and only the synchronous Redis pools (identity_registry + RBAC) are counted.
    The caller (check_end_user_limit) is still called with the result; the count
    may be an undercount in that context but it is never zero for a non-empty
    deployment, and the atomicity of the Lua scripts in IdentityRegistry/
    AgentRegistry provides the primary enforcement barrier.

    Never raises — returns 0 on any error (fail-open for count, fail-closed for
    limit enforcement in the Lua scripts).
    """
    try:
        from yashigani.backoffice.state import backoffice_state
    except Exception:
        return 0

    emails: set[str] = set()

    # Pool 1: IdentityRegistry HUMAN members (synchronous Redis SMEMBERS)
    try:
        registry = getattr(backoffice_state, "identity_registry", None)
        if registry is not None:
            r = getattr(registry, "_r", None)
            if r is not None:
                members = r.smembers("identity:index:kind:human")
                for identity_id_raw in (members or []):
                    identity_id = (
                        identity_id_raw.decode("utf-8")
                        if isinstance(identity_id_raw, bytes)
                        else identity_id_raw
                    )
                    # Slug is not the email; use name as proxy or identity_id as fallback.
                    # We need the email field from the hash — not always present for
                    # HUMAN identities provisioned via SSO (email only in audit logs).
                    # Fall back to identity_id as a unique key — prevents double-counting
                    # entries without email fields.
                    try:
                        email_raw = r.hget(f"identity:reg:{identity_id}", "email")
                        if email_raw:
                            email = (
                                email_raw.decode("utf-8")
                                if isinstance(email_raw, bytes)
                                else email_raw
                            )
                            emails.add(email.strip().lower())
                        else:
                            # No email field — use identity_id as surrogate key
                            emails.add(f"__idnt__{identity_id}")
                    except Exception:
                        emails.add(f"__idnt__{identity_id}")
    except Exception as exc:
        logger.debug("count_canonical_end_users: identity_registry pool error: %s", exc)

    # Pool 2: RBAC store group members
    try:
        rbac = getattr(backoffice_state, "rbac_store", None)
        if rbac is not None:
            groups = rbac.list_groups()
            for group in (groups or []):
                for member_raw in (group.members if hasattr(group, "members") else []):
                    member = member_raw.strip().lower() if isinstance(member_raw, str) else ""
                    if member:
                        emails.add(member)
    except Exception as exc:
        logger.debug("count_canonical_end_users: rbac_store pool error: %s", exc)

    # Pool 3: auth_service (async — skip if event loop is running)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if not loop.is_running():
            auth = getattr(backoffice_state, "auth_service", None)
            if auth is not None:
                # total_user_count is an async method; run it synchronously here
                count = loop.run_until_complete(auth.total_user_count())
                # We cannot enumerate emails from auth_service without an async
                # iteration that we cannot do here. Use a surrogate set to add
                # 'count' unique keys so the union at least captures the count.
                for i in range(count):
                    emails.add(f"__auth__{i}")
    except Exception as exc:
        logger.debug("count_canonical_end_users: auth_service pool error: %s", exc)

    return len(emails)


# ---------------------------------------------------------------------------
# FastAPI exception handler helpers
# ---------------------------------------------------------------------------

# Which tier unlocks each feature — used in upgrade messages.
# ENT-001 (2026-06-14): pii_log/pii_redact removed — PII is always available
# and will never reach this lookup via license_feature_gated_response().
_FEATURE_UPGRADE_TIER: dict[str, str] = {
    "oidc":  "Starter",
    "saml":  "Professional",
    "scim":  "Professional",
}


def license_feature_gated_response(exc: LicenseFeatureGated) -> dict:
    upgrade_tier = _FEATURE_UPGRADE_TIER.get(exc.feature, "Professional")
    return {
        "error": "LICENSE_FEATURE_GATED",
        "feature": exc.feature,
        "tier": exc.tier.value,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": f"{exc.feature.upper()} requires {upgrade_tier} or higher",
    }


def license_limit_exceeded_response(exc: LicenseLimitExceeded) -> dict:
    tier = _license.tier.value
    limit_label = {
        "max_agents":      "Agent",
        "max_end_users":   "End user",
        "max_admin_seats": "Admin seat",
        "max_orgs":        "Organization",
    }.get(exc.limit_name, exc.limit_name)
    return {
        "error": "LICENSE_LIMIT_EXCEEDED",
        "limit": exc.limit_name,
        "current": exc.current,
        "maximum": exc.max_val,
        "tier": tier,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": (
            f"{limit_label} limit reached ({exc.current}/{exc.max_val}). "
            f"Upgrade your license at yashigani.io/pricing."
        ),
    }
