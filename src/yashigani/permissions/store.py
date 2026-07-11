"""
Yashigani Permissions — Unified Redis-backed grant store.

Key schema (Redis db/3, "perm:" prefix — disjoint from "rbac:" and "cap_policy:"):

    Browser capability (batch JSON per scope level):
        perm:browser_cap:org:{org_id}         → JSON {cap: {value, allow_list}}
        perm:browser_cap:group:{group_id}     → JSON {cap: {value, allow_list}} (partial)
        perm:browser_cap:user:{identity_id}   → JSON {cap: {value, allow_list}} (partial)
                                                # identity_id = idnt_{12hex} UID from identity registry. NOT email. NOT slug.

    Boolean blast-radius grants (one JSON blob per grant):
        perm:grant:{resource_type}:org:{org_id}:{resource_id}     → JSON {allow, opa_policy_ref}
        perm:grant:{resource_type}:group:{group_id}:{resource_id} → JSON {allow, opa_policy_ref}
        perm:grant:{resource_type}:user:{identity_id}:{resource_id} → JSON {allow, opa_policy_ref}
                                                                      # identity_id = idnt_{12hex} UID. NOT email. NOT slug.
        perm:grant:{resource_type}:agent:{agent_id}:{resource_id} → JSON {allow, opa_policy_ref}

    Resource-id indexes (Redis SET — for listing all grants per subject):
        perm:idx:{resource_type}:org:{org_id}         → SADD resource_id ...
        perm:idx:{resource_type}:group:{group_id}     → SADD resource_id ...
        perm:idx:{resource_type}:user:{identity_id}   → SADD resource_id ...
                                                # identity_id = idnt_{12hex} UID. NOT email. NOT slug.
        perm:idx:{resource_type}:agent:{agent_id}     → SADD resource_id ...

All data lives in db/3 (shared with RBAC, cap_policy — disjoint prefixes).

Startup seeding: on init, the default org's browser_capability policy is seeded
from the immutable baseline (self×5) if the key is absent.  This mirrors the
RBAC startup re-push pattern.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from yashigani.permissions.model import (
    BooleanGrantValue,
    BLAST_RADIUS_TYPES,
    ResourceType,
    SubjectKind,
    validate_boolean_grant,
    GrantValidationError,
)

# Import browser-capability types from their canonical home (capability_policy/model.py)
# The adapter wraps this store; the model types stay in capability_policy.
from yashigani.capability_policy.model import (
    CapabilitySetting,
    CapabilityPolicySet,
    CAPABILITY_NAMES,
    default_policy,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

_BROWSER_CAP_ORG = "perm:browser_cap:org:{}"
_BROWSER_CAP_GROUP = "perm:browser_cap:group:{}"
_BROWSER_CAP_USER = "perm:browser_cap:user:{}"

_GRANT = "perm:grant:{}:{}:{}:{}"      # resource_type, scope_kind, scope_id, resource_id
_GRANT_IDX = "perm:idx:{}:{}:{}"       # resource_type, scope_kind, scope_id


def _browser_cap_key(scope_kind: str, scope_id: str) -> str:
    if scope_kind == "org":
        return _BROWSER_CAP_ORG.format(scope_id)
    elif scope_kind == "group":
        return _BROWSER_CAP_GROUP.format(scope_id)
    elif scope_kind == "user":
        return _BROWSER_CAP_USER.format(scope_id)
    else:
        raise ValueError(f"Unsupported scope_kind for browser_cap: {scope_kind!r}")


def _grant_key(resource_type: str, scope_kind: str, scope_id: str, resource_id: str) -> str:
    return _GRANT.format(resource_type, scope_kind, scope_id, resource_id)


def _grant_idx_key(resource_type: str, scope_kind: str, scope_id: str) -> str:
    return _GRANT_IDX.format(resource_type, scope_kind, scope_id)


# ---------------------------------------------------------------------------
# Serialisation helpers — browser capability
# ---------------------------------------------------------------------------

def _deserialise_browser_cap(raw: bytes | str | None) -> dict[str, CapabilitySetting]:
    """Deserialise raw Redis value into a partial capability dict."""
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
        logger.error("perm: browser_cap deserialise failed: %s", exc)
        return {}


def _serialise_browser_cap(policy: dict[str, CapabilitySetting]) -> str:
    return json.dumps({k: v.to_dict() for k, v in policy.items()})


# ---------------------------------------------------------------------------
# Serialisation helpers — boolean grants
# ---------------------------------------------------------------------------

def _deserialise_boolean_grant(raw: bytes | str | None) -> Optional[BooleanGrantValue]:
    """Deserialise raw Redis value into a BooleanGrantValue, or None if absent."""
    if raw is None:
        return None
    try:
        d = json.loads(raw)
        return BooleanGrantValue.from_dict(d)
    except Exception as exc:
        logger.error("perm: boolean_grant deserialise failed: %s", exc)
        return None


def _serialise_boolean_grant(value: BooleanGrantValue) -> str:
    return json.dumps(value.to_dict())


# ---------------------------------------------------------------------------
# PermissionStore
# ---------------------------------------------------------------------------

class PermissionStore:
    """
    Unified, Redis-backed grant store for all resource_types.

    Startup seeding
    ---------------
    On __init__, the default org's browser_capability policy is seeded from the
    immutable baseline (self×5) if the key is absent.  Existing config wins
    (idempotent).

    Thread safety
    -------------
    Relies on Redis's atomic SET/GET/SADD operations.  No local state beyond
    the Redis client and the default_org_id.

    Multi-org
    ---------
    default_org_id should match YASHIGANI_ORG_ID.  Additional orgs are seeded
    by calling set_browser_cap_org_policy(org_id, ...) at provisioning time.
    """

    def __init__(self, redis_client, *, default_org_id: str = "default") -> None:
        self._redis = redis_client
        self._default_org_id = default_org_id
        self._seed_browser_cap_defaults()

    # ------------------------------------------------------------------
    # Startup seeding
    # ------------------------------------------------------------------

    def _seed_browser_cap_defaults(self) -> None:
        """Seed the default org's browser_capability policy from the baseline if absent."""
        try:
            key = _browser_cap_key("org", self._default_org_id)
            if self._redis.get(key) is None:
                self._redis.set(key, _serialise_browser_cap(default_policy()))
                logger.info(
                    "perm: org '%s' browser_cap defaults seeded (all=self)",
                    self._default_org_id,
                )
        except Exception as exc:
            logger.error(
                "perm: failed to seed browser_cap org '%s': %s",
                self._default_org_id, exc,
            )

    # ------------------------------------------------------------------
    # Browser capability — org-level (full 5-capability policy)
    # ------------------------------------------------------------------

    def get_browser_cap_org_policy(self, org_id: str) -> CapabilityPolicySet:
        """
        Return the full browser-capability policy for *org_id*.

        Falls back to the immutable baseline on Redis error or missing key so
        the resolver always has a complete policy set.
        """
        try:
            raw = self._redis.get(_browser_cap_key("org", org_id))
            parsed = _deserialise_browser_cap(raw)
            result = default_policy()
            result.update(parsed)
            return result
        except Exception as exc:
            logger.error("perm: get_browser_cap_org_policy(%s) failed: %s", org_id, exc)
            return default_policy()

    def set_browser_cap_org_policy(
        self, org_id: str, policy: dict[str, CapabilitySetting]
    ) -> None:
        """Write (overwrite) the browser-capability policy for *org_id*."""
        self._redis.set(_browser_cap_key("org", org_id), _serialise_browser_cap(policy))

    def delete_browser_cap_org_policy(self, org_id: str) -> bool:
        """Delete the org browser-capability policy.  Returns True if key existed."""
        n: int = self._redis.delete(_browser_cap_key("org", org_id))
        return n > 0

    # ------------------------------------------------------------------
    # Browser capability — group/user partial overrides
    # ------------------------------------------------------------------

    def get_browser_cap_partial(self, scope_kind: str, scope_id: str) -> dict[str, CapabilitySetting]:
        """
        Return the partial browser-capability override for a group or user.
        Returns {} if no override is stored or on error.
        scope_kind: "group" | "user"
        """
        try:
            raw = self._redis.get(_browser_cap_key(scope_kind, scope_id))
            return _deserialise_browser_cap(raw)
        except Exception as exc:
            logger.error(
                "perm: get_browser_cap_partial(%s, %s) failed: %s",
                scope_kind, scope_id, exc,
            )
            return {}

    def set_browser_cap_partial(
        self, scope_kind: str, scope_id: str, policy: dict[str, CapabilitySetting]
    ) -> None:
        """Write a partial browser-capability override for a group or user."""
        self._redis.set(
            _browser_cap_key(scope_kind, scope_id),
            _serialise_browser_cap(policy),
        )

    def delete_browser_cap_partial(self, scope_kind: str, scope_id: str) -> bool:
        """Delete a partial browser-capability override.  Returns True if key existed."""
        n: int = self._redis.delete(_browser_cap_key(scope_kind, scope_id))
        return n > 0

    # ------------------------------------------------------------------
    # Boolean grants — get / set / delete
    # ------------------------------------------------------------------

    def get_boolean_grant(
        self,
        resource_type: ResourceType,
        scope_kind: str,
        scope_id: str,
        resource_id: str,
    ) -> Optional[BooleanGrantValue]:
        """
        Return the boolean grant for (resource_type, scope, resource_id), or None
        if no grant is stored.

        scope_kind: "org" | "group" | "user" | "agent"
        """
        try:
            raw = self._redis.get(
                _grant_key(resource_type.value, scope_kind, scope_id, resource_id)
            )
            return _deserialise_boolean_grant(raw)
        except Exception as exc:
            logger.error(
                "perm: get_boolean_grant(%s/%s/%s/%s) failed: %s",
                resource_type.value, scope_kind, scope_id, resource_id, exc,
            )
            return None

    def set_boolean_grant(
        self,
        resource_type: ResourceType,
        scope_kind: str,
        scope_id: str,
        resource_id: str,
        value: BooleanGrantValue,
    ) -> None:
        """
        Write a boolean grant.  Validates INV-2 before writing.

        scope_kind: "org" | "group" | "user" | "agent"

        Raises GrantValidationError on constraint violation (caller converts to HTTP 422).
        """
        validate_boolean_grant(resource_type, value)
        key = _grant_key(resource_type.value, scope_kind, scope_id, resource_id)
        idx_key = _grant_idx_key(resource_type.value, scope_kind, scope_id)
        self._redis.set(key, _serialise_boolean_grant(value))
        self._redis.sadd(idx_key, resource_id)

    def delete_boolean_grant(
        self,
        resource_type: ResourceType,
        scope_kind: str,
        scope_id: str,
        resource_id: str,
    ) -> bool:
        """
        Delete a boolean grant.  Returns True if the grant existed.
        Also removes resource_id from the index.
        """
        key = _grant_key(resource_type.value, scope_kind, scope_id, resource_id)
        idx_key = _grant_idx_key(resource_type.value, scope_kind, scope_id)
        n: int = self._redis.delete(key)
        if n > 0:
            self._redis.srem(idx_key, resource_id)
            return True
        return False

    def list_boolean_grants(
        self,
        resource_type: ResourceType,
        scope_kind: str,
        scope_id: str,
    ) -> list[tuple[str, BooleanGrantValue]]:
        """
        Return all boolean grants for (resource_type, scope) as a list of
        (resource_id, BooleanGrantValue) tuples.

        Uses the SADD index.  If the index is absent, returns [].
        """
        idx_key = _grant_idx_key(resource_type.value, scope_kind, scope_id)
        try:
            resource_ids = self._redis.smembers(idx_key) or set()
            results: list[tuple[str, BooleanGrantValue]] = []
            for rid_bytes in resource_ids:
                rid = rid_bytes.decode() if isinstance(rid_bytes, bytes) else rid_bytes
                grant = self.get_boolean_grant(resource_type, scope_kind, scope_id, rid)
                if grant is not None:
                    results.append((rid, grant))
            return sorted(results, key=lambda t: t[0])
        except Exception as exc:
            logger.error(
                "perm: list_boolean_grants(%s/%s/%s) failed: %s",
                resource_type.value, scope_kind, scope_id, exc,
            )
            return []

    def delete_all_boolean_grants(
        self,
        resource_type: ResourceType,
        scope_kind: str,
        scope_id: str,
    ) -> int:
        """
        Delete all boolean grants for (resource_type, scope).
        Returns the count of grants deleted.
        """
        idx_key = _grant_idx_key(resource_type.value, scope_kind, scope_id)
        try:
            resource_ids = self._redis.smembers(idx_key) or set()
            deleted = 0
            for rid_bytes in resource_ids:
                rid = rid_bytes.decode() if isinstance(rid_bytes, bytes) else rid_bytes
                key = _grant_key(resource_type.value, scope_kind, scope_id, rid)
                deleted += self._redis.delete(key)
            if resource_ids:
                self._redis.delete(idx_key)
            return deleted
        except Exception as exc:
            logger.error(
                "perm: delete_all_boolean_grants(%s/%s/%s) failed: %s",
                resource_type.value, scope_kind, scope_id, exc,
            )
            return 0

    # ------------------------------------------------------------------
    # Pending declarations — declare→approve flow (Phase 8 admin API)
    # ------------------------------------------------------------------
    #
    # Key schema:
    #   perm:pending:{resource_type}:{resource_id}  → JSON blob
    #   perm:pending_idx:{resource_type}            → SADD resource_id
    #
    # "Pending" means: declared but not yet approved at org level.
    # The approval step (POST /declarations/.../approve) creates the org-level
    # grant and removes the declaration from the pending queue.

    def declare_pending(
        self,
        resource_type: ResourceType,
        resource_id: str,
        *,
        declared_by: str,
        justification: str,
        declared_at: str,
    ) -> None:
        """
        Record a pending declaration for (resource_type, resource_id).

        declared_by:   identity that submitted the declaration
                       (e.g. "agent:my-agent" or admin account_id)
        justification: short human-readable reason
        declared_at:   ISO-8601 UTC timestamp
        """
        key = "perm:pending:{}:{}".format(resource_type.value, resource_id)
        idx = "perm:pending_idx:{}".format(resource_type.value)
        self._redis.set(key, json.dumps({
            "resource_type": resource_type.value,
            "resource_id": resource_id,
            "declared_by": declared_by,
            "justification": justification,
            "declared_at": declared_at,
        }))
        self._redis.sadd(idx, resource_id)

    def get_pending_declarations(
        self,
        resource_type: Optional[ResourceType] = None,
    ) -> list[dict]:
        """
        Return all pending declarations.

        If resource_type is given, returns only that type.
        Otherwise returns all types across all ResourceType values.

        Each entry is a dict with keys:
            resource_type, resource_id, declared_by, justification, declared_at
        """
        types_to_query = [resource_type] if resource_type is not None else list(ResourceType)
        results: list[dict] = []
        try:
            for rt in types_to_query:
                idx = "perm:pending_idx:{}".format(rt.value)
                resource_ids = self._redis.smembers(idx) or set()
                for rid_bytes in resource_ids:
                    rid = rid_bytes.decode() if isinstance(rid_bytes, bytes) else rid_bytes
                    key = "perm:pending:{}:{}".format(rt.value, rid)
                    raw = self._redis.get(key)
                    if raw is not None:
                        try:
                            results.append(json.loads(raw))
                        except Exception:
                            pass
        except Exception as exc:
            logger.error("perm: get_pending_declarations failed: %s", exc)
        return sorted(results, key=lambda d: (d.get("resource_type", ""), d.get("resource_id", "")))

    def remove_pending_declaration(
        self,
        resource_type: ResourceType,
        resource_id: str,
    ) -> bool:
        """
        Remove a pending declaration.  Returns True if the declaration existed.
        """
        key = "perm:pending:{}:{}".format(resource_type.value, resource_id)
        idx = "perm:pending_idx:{}".format(resource_type.value)
        n: int = self._redis.delete(key)
        if n > 0:
            self._redis.srem(idx, resource_id)
            return True
        return False
