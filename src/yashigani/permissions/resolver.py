"""
Yashigani Permissions — Unified org-ceiling resolver.

Semantics (Tiago-decided, firm):

DENY BY DEFAULT (blast-radius types)
    A resource is denied unless the org-level grant explicitly allows it.
    A lower-level (group, user) allow with no org grant has NO effect.

ORG IS THE CEILING — most-restrictive-wins
    Group and user grants can only NARROW within the org ceiling, never widen.

    boolean (mcp_server / external_api / cloud_model / agent):
        effective_allow = org_allows
                          AND NOT (any group grant is allow=False)
                          AND NOT (user grant is allow=False)

    browser_capability (tri-state off=0 < self=1 < allow_list=2):
        effective_setting = most-restrictive of {org, group, user}
        where "most-restrictive" = min by restrictiveness rank
        Fallback: immutable baseline (self×5) when org has no setting for this capability.

Unauthenticated principals (email=None/"")
    Group and user tiers are skipped.  The org-level setting (or baseline) applies.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from yashigani.permissions.model import (
    ResourceType,
    BLAST_RADIUS_TYPES,
    BooleanGrantValue,
)
from yashigani.permissions.store import PermissionStore

# Browser-capability types stay in their canonical module.
from yashigani.capability_policy.model import (
    CapabilitySetting,
    CapabilityPolicySet,
    CAPABILITY_NAMES,
    default_policy,
)

logger = logging.getLogger(__name__)

DEFAULT_ORG_ID: str = os.getenv("YASHIGANI_ORG_ID", "default")


# ---------------------------------------------------------------------------
# Boolean grant resolver  (blast-radius resource types)
# ---------------------------------------------------------------------------

def resolve_boolean_grant(
    resource_type: ResourceType,
    resource_id: str,
    *,
    org_id: str,
    group_ids: list[str],
    user_email: Optional[str],
    store: PermissionStore,
) -> bool:
    """
    Resolve the effective allow/deny for a blast-radius resource.

    Returns True only when:
      1. The org-level grant for (resource_type, resource_id) is allow=True.
      2. No group grant for any of the user's groups is allow=False.
      3. The user grant (if any) is not allow=False.

    Any exception falls closed to False (DENIED).

    Parameters
    ----------
    resource_type:  Must be a BLAST_RADIUS_TYPE.
    resource_id:    Server ID / API ID / model name / agent ID.
    org_id:         The principal's org (org ceiling).
    group_ids:      List of group IDs the principal belongs to.
    user_email:     Principal email.  None / "" → group and user tiers skipped.
    store:          PermissionStore instance.
    """
    if resource_type not in BLAST_RADIUS_TYPES:
        raise ValueError(
            f"resolve_boolean_grant called with non-blast-radius type {resource_type!r}"
        )
    try:
        # INV-1  DENY BY DEFAULT — org must grant allow=True
        org_grant: Optional[BooleanGrantValue] = store.get_boolean_grant(
            resource_type, "org", org_id, resource_id
        )
        if org_grant is None or not org_grant.allow:
            return False  # No org grant or org explicitly denies → ceiling blocks

        if not user_email:
            # Unauthenticated — org allows and there's no group/user context
            return True

        # INV-3  Groups can only narrow
        for group_id in group_ids:
            group_grant: Optional[BooleanGrantValue] = store.get_boolean_grant(
                resource_type, "group", group_id, resource_id
            )
            if group_grant is not None and not group_grant.allow:
                return False  # Group explicitly denies → narrowing kicks in

        # INV-3  User can only narrow
        user_grant: Optional[BooleanGrantValue] = store.get_boolean_grant(
            resource_type, "user", user_email, resource_id
        )
        if user_grant is not None and not user_grant.allow:
            return False  # User explicitly denies → narrowing kicks in

        return True  # Org allows; no group/user denial

    except Exception as exc:
        logger.error(
            "perm: resolve_boolean_grant(%s, %s) for org=%s user=%s — "
            "fail-closed to DENIED: %s",
            resource_type.value, resource_id, org_id, user_email, exc,
        )
        return False  # Fail closed


# ---------------------------------------------------------------------------
# Browser-capability resolver  (tri-state most-restrictive-wins)
# ---------------------------------------------------------------------------

def resolve_browser_capability_set(
    *,
    org_id: str,
    group_ids: list[str],
    user_email: Optional[str],
    store: PermissionStore,
) -> CapabilityPolicySet:
    """
    Resolve the full browser Permissions-Policy for a principal.

    ORG IS THE CEILING.  The effective setting per capability is the
    most-restrictive (lowest restrictiveness rank) across:
      { org setting, all group settings, user setting }

    Restrictiveness rank: off=0 < self=1 < allow_list=2.

    A user or group can only make a capability MORE restrictive than the org
    setting, never LESS restrictive.  If org sets camera="self" and the user
    preference is "allow_list", the effective value is "self" (org caps).

    Falls back to the immutable baseline (self×5) if an exception occurs.
    Always returns a complete CapabilityPolicySet (all 5 capabilities).

    Parameters
    ----------
    org_id:      The principal's org (org ceiling).
    group_ids:   Group IDs the principal belongs to.
    user_email:  Principal email.  None / "" → group and user tiers skipped.
    store:       PermissionStore instance.
    """
    try:
        org_policy: CapabilityPolicySet = store.get_browser_cap_org_policy(org_id)
        # org_policy always has all 5 capabilities (get_browser_cap_org_policy merges
        # with the baseline, so even if no org key exists, we get self×5).

        if not user_email:
            # Unauthenticated — org policy (or baseline) is the effective policy.
            return org_policy

        result: CapabilityPolicySet = {}
        for cap in CAPABILITY_NAMES:
            candidates: list[CapabilitySetting] = [org_policy[cap]]

            # Group tier — accumulate all group settings for this capability
            for group_id in group_ids:
                group_partial = store.get_browser_cap_partial("group", group_id)
                if cap in group_partial:
                    candidates.append(group_partial[cap])

            # User tier
            user_partial = store.get_browser_cap_partial("user", user_email)
            if cap in user_partial:
                candidates.append(user_partial[cap])

            # Most-restrictive wins (min by restrictiveness rank).
            # This enforces org-ceiling: a user "allow_list" will never beat
            # an org "self" because min(self=1, allow_list=2) = 1 = "self".
            result[cap] = min(candidates, key=lambda s: s.restrictiveness())

        return result

    except Exception as exc:
        logger.error(
            "perm: resolve_browser_capability_set(org=%s, user=%s) failed "
            "— falling back to baseline: %s",
            org_id, user_email, exc,
        )
        try:
            return store.get_browser_cap_org_policy(org_id)
        except Exception:
            return default_policy()
