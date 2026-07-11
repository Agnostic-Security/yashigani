"""
Yashigani Capability Policy — Resolution logic (Phase 2: org-ceiling semantics).

Delegates to yashigani.permissions.resolver.resolve_browser_capability_set which
enforces:

    ORG IS THE CEILING — most-restrictive-wins.

    Effective setting per capability = most-restrictive of {org, group, user}
    where off=0 < self=1 < allow_list=2.

    A lower-level (group, user) grant can only make a capability MORE
    restrictive than the org setting, never less restrictive.

Phase 2 behaviour change vs Phase 1
-------------------------------------
    BEFORE (Phase 1):
        Precedence was user > most-restrictive group > org > baseline.
        A user-level setting could WIDEN above the org (e.g. user="allow_list"
        overrides org="self").

    AFTER (Phase 2, this module):
        Most-restrictive-wins across all tiers.  Org is the ceiling.
        User "allow_list" is capped at org "self" → effective = "self".
        User "off" still works (narrows below org "self" → effective = "off").

DEFAULT_ORG_ID is read from YASHIGANI_ORG_ID (default "default").

Identity boundary — user_id, never email
    The inbound caller identifier (user_id) is the stable slug from the identity
    registry (set by Caddy forward_auth as X-Forwarded-User / x-yashigani-user-id).
    Email is used only for password reset — it is not the authz key here.

Unauthenticated callers (user_id=None or "")
    Group and user tiers are skipped; org policy (or baseline) is returned.

Last updated: 2026-07-03T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from yashigani.capability_policy.model import (
    CapabilityPolicySet,
    default_policy,
)

logger = logging.getLogger(__name__)

#: The org ID used when no explicit org_id is passed to resolve_policy().
DEFAULT_ORG_ID: str = os.getenv("YASHIGANI_ORG_ID", "default")


def _lookup_org(user_id: Optional[str], rbac_store) -> str:
    """
    Return the org_id for *user_id*.

    Single-instance: always returns DEFAULT_ORG_ID.
    Enterprise multi-org seam: override this or pass org_id explicitly to
    resolve_policy() to derive the org from a directory attribute.
    """
    return DEFAULT_ORG_ID


def resolve_policy(
    user_id: Optional[str],
    rbac_store,
    policy_store,
    org_id: Optional[str] = None,
) -> CapabilityPolicySet:
    """
    Resolve the full Permissions-Policy for *user_id* using org-ceiling semantics.

    Delegates to yashigani.permissions.resolver.resolve_browser_capability_set.

    Always returns a complete CapabilityPolicySet (all 5 capabilities).
    Falls back gracefully on any internal error.

    Parameters
    ----------
    user_id:
        Stable principal identifier (slug from identity registry).
        NOT email — email is only for password reset, not authz.
        None or "" → unauthenticated; group and user tiers are skipped;
        org policy (or baseline) is returned.
    rbac_store:
        RBACStore instance for group-membership lookup.  None → group tier
        is skipped.
    policy_store:
        CapabilityPolicyStore (or the underlying PermissionStore).
    org_id:
        Explicit org identifier.  None → derived via _lookup_org().
    """
    from yashigani.permissions.resolver import resolve_browser_capability_set

    try:
        effective_org_id: str = (
            org_id if org_id is not None else _lookup_org(user_id, rbac_store)
        )

        # Resolve group membership for the principal.
        # rbac_store is keyed by identity_id (idnt_{12hex}) after the 3.1 UID
        # unification migration.  user_id here is the resolved identity_id from
        # the gateway boundary resolver (request.state.ysg_principal.identity_id).
        group_ids: list[str] = []
        if user_id and rbac_store is not None:
            try:
                groups = rbac_store.get_user_groups(user_id)
                group_ids = [g.id for g in groups]
            except Exception as grp_exc:
                logger.warning(
                    "cap_policy: group lookup failed for %s: %s", user_id, grp_exc
                )

        # Delegate to the unified resolver which enforces org-ceiling.
        perm_store = getattr(policy_store, "perm_store", policy_store)
        return resolve_browser_capability_set(
            org_id=effective_org_id,
            group_ids=group_ids,
            principal_scope="user" if user_id else None,
            principal_id=user_id if user_id else None,
            store=perm_store,
        )

    except Exception as exc:
        logger.error(
            "cap_policy: resolve_policy failed for %s — using org policy: %s",
            user_id, exc,
        )
        try:
            effective_org_id = org_id if org_id is not None else DEFAULT_ORG_ID
            return policy_store.get_org(effective_org_id)
        except Exception:
            return default_policy()
