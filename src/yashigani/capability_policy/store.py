"""
Yashigani Capability Policy — Redis-backed store.

Key schema (Redis db/3, shared with RBAC — disjoint key prefix "cap_policy:"):
    cap_policy:org:{org_id}  — JSON of all 5 capabilities (org-level policy)
    cap_policy:group:{group_id} — JSON of overridden capabilities only (partial)
    cap_policy:user:{email}     — JSON of overridden capabilities only (partial)

All values are JSON dicts: {capability_name: {value: ..., allow_list: [...]}}.
Partial dicts (group / user) may contain any subset of the 5 capabilities.
The org dict must always contain all 5 (enforced at the API layer).

Scope precedence (highest → lowest):
    user override  >  most-restrictive group override  >  org policy  >  BASELINE

The BASELINE (default_policy()) is hardcoded in model.py and is NOT stored in
Redis.  The org policy IS operator-configurable and IS stored in Redis.

The store is initialised with a default_org_id (read from YASHIGANI_ORG_ID env
var by the entrypoint; default "default").  On first use, the default org's key
is seeded with the BASELINE values (idempotent — existing config wins).

Enterprise multi-org: add additional org_ids via set_org(org_id, policy).
The resolver already accepts an explicit org_id; only the single default org
is created at startup, so no extra seeding is needed for Enterprise.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging

from yashigani.capability_policy.model import (
    CapabilitySetting,
    CapabilityPolicySet,
    default_policy,
    CAPABILITY_NAMES,
)

logger = logging.getLogger(__name__)

_KEY_ORG   = "cap_policy:org:{}"    # .format(org_id)
_KEY_GROUP = "cap_policy:group:{}"  # .format(group_id)
_KEY_USER  = "cap_policy:user:{}"   # .format(email)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _deserialise(raw: bytes | str | None) -> dict[str, CapabilitySetting]:
    """Deserialise raw Redis bytes/str into a partial capability dict."""
    if raw is None:
        return {}
    try:
        d = json.loads(raw)
        result: dict[str, CapabilitySetting] = {}
        for k, v in d.items():
            if k in CAPABILITY_NAMES:
                result[k] = CapabilitySetting.from_dict(v)
        return result
    except Exception as exc:
        logger.error("cap_policy: deserialise failed: %s", exc)
        return {}


def _serialise(policy: dict[str, CapabilitySetting]) -> str:
    return json.dumps({k: v.to_dict() for k, v in policy.items()})


# ---------------------------------------------------------------------------
# Store class
# ---------------------------------------------------------------------------

class CapabilityPolicyStore:
    """
    Thread-safe Permissions-Policy store backed by Redis db/3.

    Org policy (all 5 capabilities) is seeded from the BASELINE on first use
    (idempotent — existing config wins).  Per-group and per-user overrides are
    stored as partial dicts: only the capabilities that have an explicit
    override are stored.

    The store is shared with the RBAC store on the same Redis db/3 instance
    (key prefix "cap_policy:" is disjoint from "rbac:").

    default_org_id should match YASHIGANI_ORG_ID (defaults to "default").
    Enterprise multi-org: call set_org(org_id, policy) for each org at
    provisioning time; the resolver passes the principal's org_id explicitly.
    """

    def __init__(self, redis_client, *, default_org_id: str = "default") -> None:
        self._redis = redis_client
        self._default_org_id = default_org_id
        self._seed_org_defaults()

    # ------------------------------------------------------------------
    # Startup seeding
    # ------------------------------------------------------------------

    def _seed_org_defaults(self) -> None:
        """Write the built-in baseline policy for the default org if the key is absent."""
        try:
            key = _KEY_ORG.format(self._default_org_id)
            if self._redis.get(key) is None:
                self._redis.set(key, _serialise(default_policy()))
                logger.info(
                    "cap_policy: org '%s' defaults seeded "
                    "(all 5 capabilities = self)",
                    self._default_org_id,
                )
        except Exception as exc:
            logger.error(
                "cap_policy: failed to seed org '%s' defaults: %s",
                self._default_org_id, exc,
            )

    # ------------------------------------------------------------------
    # Org policy (full — all 5 capabilities)
    # ------------------------------------------------------------------

    def get_org(self, org_id: str) -> CapabilityPolicySet:
        """
        Return the org policy for *org_id* (all 5 capabilities guaranteed).

        Falls back to the immutable BASELINE on Redis error or missing key so
        that the resolver always has a complete policy set to work from.
        """
        try:
            raw = self._redis.get(_KEY_ORG.format(org_id))
            parsed = _deserialise(raw)
            # Merge over the baseline so all 5 are always present
            result = default_policy()
            result.update(parsed)
            return result
        except Exception as exc:
            logger.error("cap_policy: get_org(%s) failed: %s", org_id, exc)
            return default_policy()

    def set_org(self, org_id: str, policy: CapabilityPolicySet) -> None:
        """
        Overwrite the org policy for *org_id*.
        Caller must have validated that all 5 capabilities are present.
        """
        self._redis.set(_KEY_ORG.format(org_id), _serialise(policy))

    def delete_org(self, org_id: str) -> bool:
        """
        Delete the org policy for *org_id*.
        Returns True if the key existed, False otherwise.
        After deletion, the resolver falls back to the immutable BASELINE.
        """
        n: int = self._redis.delete(_KEY_ORG.format(org_id))
        return n > 0

    # ------------------------------------------------------------------
    # Group overrides (partial)
    # ------------------------------------------------------------------

    def get_group(self, group_id: str) -> dict[str, CapabilitySetting]:
        """
        Return the partial group override.
        Returns {} if no override exists or on error.
        """
        try:
            raw = self._redis.get(_KEY_GROUP.format(group_id))
            return _deserialise(raw)
        except Exception as exc:
            logger.error("cap_policy: get_group(%s) failed: %s", group_id, exc)
            return {}

    def set_group(self, group_id: str, policy: dict[str, CapabilitySetting]) -> None:
        """Set (or replace) the partial group override."""
        self._redis.set(_KEY_GROUP.format(group_id), _serialise(policy))

    def delete_group(self, group_id: str) -> bool:
        """
        Delete the group override.
        Returns True if the key existed, False otherwise.
        """
        n: int = self._redis.delete(_KEY_GROUP.format(group_id))
        return n > 0

    # ------------------------------------------------------------------
    # User overrides (partial)
    # ------------------------------------------------------------------

    def get_user(self, email: str) -> dict[str, CapabilitySetting]:
        """
        Return the partial user override.
        Returns {} if no override exists or on error.
        """
        try:
            raw = self._redis.get(_KEY_USER.format(email))
            return _deserialise(raw)
        except Exception as exc:
            logger.error("cap_policy: get_user(%s) failed: %s", email, exc)
            return {}

    def set_user(self, email: str, policy: dict[str, CapabilitySetting]) -> None:
        """Set (or replace) the partial user override."""
        self._redis.set(_KEY_USER.format(email), _serialise(policy))

    def delete_user(self, email: str) -> bool:
        """
        Delete the user override.
        Returns True if the key existed, False otherwise.
        """
        n: int = self._redis.delete(_KEY_USER.format(email))
        return n > 0
