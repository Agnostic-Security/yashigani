"""
Yashigani Capability Policy — Redis-backed store (thin adapter over PermissionStore).

This module provides CapabilityPolicyStore, which is the public interface used
by the backoffice admin API routes and the Permissions-Policy middleware.  It
delegates all persistence to the unified PermissionStore (yashigani.permissions)
for resource_type=browser_capability.

Effective key schema (managed by PermissionStore, "perm:" prefix):
    perm:browser_cap:org:{org_id}      — all 5 capabilities (org-level policy)
    perm:browser_cap:group:{group_id}  — partial overrides (group)
    perm:browser_cap:user:{email}      — partial overrides (user)

Scope precedence (highest → lowest, resolved in resolver.py via org-ceiling):
    most-restrictive of {user, group, org} ≥ immutable BASELINE (self×5)
    Org is the ceiling.  Group and user can only narrow, never widen.

The BASELINE (default_policy()) is hardcoded in model.py and is NOT stored in
Redis.  The org policy IS operator-configurable.

Enterprise multi-org: add additional org_ids via set_org(org_id, policy).

Phase 2 note: This adapter keeps the existing interface (get/set/delete_org,
get/set/delete_group, get/set/delete_user) fully intact so the admin API and
middleware continue working without change.  Full unification of the admin API
and UI is Phase 8.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import logging

from yashigani.capability_policy.model import (
    CapabilitySetting,
    CapabilityPolicySet,
    default_policy,
    CAPABILITY_NAMES,
)

logger = logging.getLogger(__name__)


class CapabilityPolicyStore:
    """
    Admin interface to browser Permissions-Policy grants.

    Delegates all persistence to PermissionStore (resource_type=browser_capability).
    The public interface is identical to the pre-Phase-2 version so no callers
    need updating.

    default_org_id should match YASHIGANI_ORG_ID (defaults to "default").
    """

    def __init__(self, redis_client, *, default_org_id: str = "default") -> None:
        # Lazy import to break the permissions ↔ capability_policy circular dependency.
        from yashigani.permissions.store import PermissionStore
        self._perm_store = PermissionStore(redis_client, default_org_id=default_org_id)
        self._default_org_id = default_org_id

    # Expose the underlying PermissionStore for the unified resolver.
    @property
    def perm_store(self):  # -> PermissionStore (lazy import; annotation omitted to avoid circular)
        return self._perm_store

    # ------------------------------------------------------------------
    # Org policy (full — all 5 capabilities)
    # ------------------------------------------------------------------

    def get_org(self, org_id: str) -> CapabilityPolicySet:
        """
        Return the org policy for *org_id* (all 5 capabilities guaranteed).

        Falls back to the immutable BASELINE on Redis error or missing key.
        """
        return self._perm_store.get_browser_cap_org_policy(org_id)

    def set_org(self, org_id: str, policy: CapabilityPolicySet) -> None:
        """
        Overwrite the org policy for *org_id*.
        Caller must have validated that all 5 capabilities are present.
        """
        self._perm_store.set_browser_cap_org_policy(org_id, policy)

    def delete_org(self, org_id: str) -> bool:
        """
        Delete the org policy for *org_id*.
        Returns True if the key existed.
        After deletion, the resolver falls back to the immutable BASELINE.
        """
        return self._perm_store.delete_browser_cap_org_policy(org_id)

    # ------------------------------------------------------------------
    # Group overrides (partial)
    # ------------------------------------------------------------------

    def get_group(self, group_id: str) -> dict[str, CapabilitySetting]:
        """Return the partial group override.  Returns {} if none exists."""
        return self._perm_store.get_browser_cap_partial("group", group_id)

    def set_group(self, group_id: str, policy: dict[str, CapabilitySetting]) -> None:
        """Set (or replace) the partial group override."""
        self._perm_store.set_browser_cap_partial("group", group_id, policy)

    def delete_group(self, group_id: str) -> bool:
        """Delete the group override.  Returns True if it existed."""
        return self._perm_store.delete_browser_cap_partial("group", group_id)

    # ------------------------------------------------------------------
    # User overrides (partial)
    # ------------------------------------------------------------------

    def get_user(self, email: str) -> dict[str, CapabilitySetting]:
        """Return the partial user override.  Returns {} if none exists."""
        return self._perm_store.get_browser_cap_partial("user", email)

    def set_user(self, email: str, policy: dict[str, CapabilitySetting]) -> None:
        """Set (or replace) the partial user override."""
        self._perm_store.set_browser_cap_partial("user", email, policy)

    def delete_user(self, email: str) -> bool:
        """Delete the user override.  Returns True if it existed."""
        return self._perm_store.delete_browser_cap_partial("user", email)
