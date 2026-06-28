"""
Yashigani Capability Policy — Resolution logic.

Resolution is per-capability (user may override only one capability and
inherit the rest):

    1. User override    — if explicitly set for this capability
    2. Group override   — most-restrictive across user's groups that override
                          this capability.
                          Ordering: off (0) < self (1) < allow_list (2) — lowest wins.
    3. Org policy       — the policy stored for the principal's org
                          (cap_policy:org:{org_id} in Redis)
    4. BASELINE         — immutable hardcoded fallback (default_policy(); self×5)
                          used only when no org policy exists for the org

Unauthenticated callers (email=None or "") → org policy (not baseline),
so operators can restrict unauthenticated sessions at the org level.

DEFAULT_ORG_ID is read from YASHIGANI_ORG_ID (default "default").  In
single-instance deployments every principal belongs to this one org.

Enterprise multi-org seam:
    Pass an explicit org_id to resolve_policy(), or override _lookup_org() to
    derive the org from the principal's attributes (e.g. via the RBAC store).
    No other change required — the per-capability loop already falls through
    cleanly from group → org → baseline.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from yashigani.capability_policy.model import (
    CapabilitySetting,
    CapabilityPolicySet,
    CAPABILITY_NAMES,
    default_policy,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default org configuration
# ---------------------------------------------------------------------------

#: The org ID used when no explicit org_id is passed to resolve_policy().
#: Set YASHIGANI_ORG_ID in the environment to override (e.g. for multi-org
#: Enterprise where the caller must always supply an explicit org_id).
DEFAULT_ORG_ID: str = os.getenv("YASHIGANI_ORG_ID", "default")


def _lookup_org(email: Optional[str], rbac_store) -> str:
    """
    Return the org_id for *email*.

    In single-instance: always returns DEFAULT_ORG_ID.
    Enterprise multi-org seam: override this function (or pass org_id
    explicitly to resolve_policy) to derive the org from the RBAC store or
    a directory attribute.
    """
    # single-instance: constant default org
    return DEFAULT_ORG_ID


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

def resolve_policy(
    email: Optional[str],
    rbac_store,    # RBACStore | None  (typed Any to avoid circular import)
    policy_store,  # CapabilityPolicyStore
    org_id: Optional[str] = None,
) -> CapabilityPolicySet:
    """
    Resolve the full Permissions-Policy for *email*.

    Precedence per capability (highest → lowest):
        user > most-restrictive group > org(of principal) > BASELINE

    Always returns a complete CapabilityPolicySet (all 5 capabilities).
    Falls back gracefully on any internal error — never propagates exceptions
    to the caller (middleware must not blow up a response that has already
    been produced by the route handler).

    Parameters
    ----------
    email:
        Principal email.  None or "" → unauthenticated; org policy is returned
        (group and user tiers are skipped).
    rbac_store:
        RBACStore instance used for group membership lookup.  None → group
        tier is skipped.
    policy_store:
        CapabilityPolicyStore instance.
    org_id:
        Explicit org identifier.  None → derived via _lookup_org() which
        returns DEFAULT_ORG_ID in single-instance deployments.
    """
    try:
        effective_org_id: str = org_id if org_id is not None else _lookup_org(email, rbac_store)
        org_policy: CapabilityPolicySet = policy_store.get_org(effective_org_id)

        # Unauthenticated → org policy (already contains all 5 capabilities)
        if not email:
            return org_policy

        user_overrides: dict[str, CapabilitySetting] = policy_store.get_user(email)

        # Collect per-capability group settings
        group_settings_by_cap: dict[str, list[CapabilitySetting]] = {
            cap: [] for cap in CAPABILITY_NAMES
        }
        if rbac_store is not None:
            try:
                groups = rbac_store.get_user_groups(email)
                for group in groups:
                    grp_policy = policy_store.get_group(group.id)
                    for cap, setting in grp_policy.items():
                        group_settings_by_cap[cap].append(setting)
            except Exception as grp_exc:
                logger.warning(
                    "cap_policy: group lookup failed for %s: %s", email, grp_exc
                )

        result: CapabilityPolicySet = {}
        for cap in CAPABILITY_NAMES:
            # Tier 1 — explicit user override
            if cap in user_overrides:
                result[cap] = user_overrides[cap]
                continue

            # Tier 2 — most-restrictive group override
            candidates = group_settings_by_cap[cap]
            if candidates:
                most_restrictive = min(candidates, key=lambda s: s.restrictiveness())
                result[cap] = most_restrictive
                continue

            # Tier 3 — org policy (operator-configurable)
            result[cap] = org_policy[cap]
            # Tier 4 (BASELINE) is already merged into org_policy by get_org(),
            # so no explicit baseline lookup is needed here.

        return result

    except Exception as exc:
        logger.error(
            "cap_policy: resolve_policy failed for %s — using org policy: %s",
            email, exc,
        )
        try:
            effective_org_id = org_id if org_id is not None else DEFAULT_ORG_ID
            return policy_store.get_org(effective_org_id)
        except Exception:
            return default_policy()
