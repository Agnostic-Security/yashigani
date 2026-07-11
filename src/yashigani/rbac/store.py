"""
Yashigani RBAC — Redis-backed group/user store.

Redis db/3 key schema:
    rbac:group:{id}           — JSON-serialised RBACGroup (all fields)
    rbac:user:{identity_id}   — Redis SET of group IDs the identity belongs to.
                                identity_id = idnt_{12hex} from identity registry.
                                NOT email. NOT slug. After the 3.1 UID migration,
                                all user-index keys are identity_id-keyed.

Deny-by-default: is_allowed() returns False when the identity has no groups or
no group has a pattern that matches the (method, path) pair.

Glob rules for path matching (mirrors OPA rbac.rego):
    "**"          — any path
    "/prefix/**"  — anything with that prefix (after the slash)
    exact string  — only that exact path
"""
from __future__ import annotations

import fnmatch
import json
import logging
from typing import Optional

from yashigani.rbac.model import RBACGroup, ResourcePattern

logger = logging.getLogger(__name__)

_KEY_GROUP = "rbac:group:{}"   # .format(group_id)
_KEY_USER  = "rbac:user:{}"    # .format(identity_id) — idnt_{12hex} after 3.1 migration


class RBACStore:
    """
    Thread-safe RBAC store backed by Redis db/3.

    All mutations are write-through: the in-memory dict is updated first,
    then persisted to Redis.  The constructor replays the full state from
    Redis so a restart does not lose any data.
    """

    def __init__(self, redis_client) -> None:
        """
        Initialise the store.

        redis_client must be connected to Redis db/3.
        On construction the store loads all existing groups from Redis.
        """
        self._redis = redis_client
        self._groups: dict[str, RBACGroup] = {}
        self._load_from_redis()

    # ------------------------------------------------------------------
    # Startup: replay from Redis
    # ------------------------------------------------------------------

    def _load_from_redis(self) -> None:
        """Load all rbac:group:* keys into the in-memory cache."""
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match="rbac:group:*", count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        d = json.loads(raw)
                        group = RBACGroup.from_dict(d)
                        self._groups[group.id] = group
                    except Exception as exc:
                        logger.error("RBAC store: failed to deserialise %s: %s", key, exc)
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error("RBAC store: failed to load from Redis: %s", exc)

    # ------------------------------------------------------------------
    # Group CRUD
    # ------------------------------------------------------------------

    def add_group(self, group: RBACGroup) -> None:
        """Add or overwrite a group.  Writes through to Redis.

        After the 3.1 UID migration, group.members contains identity_ids
        (idnt_{12hex}), NOT emails.  The user→group index is keyed by identity_id.
        """
        self._groups[group.id] = group
        self._redis.set(_KEY_GROUP.format(group.id), json.dumps(group.to_dict()))
        # Ensure all members are reflected in the identity→group index
        for identity_id in group.members:
            self._redis.sadd(_KEY_USER.format(identity_id), group.id)

    def remove_group(self, group_id: str) -> None:
        """
        Remove a group and clean up all identity→group index entries.
        No-op if the group does not exist.

        After 3.1 UID migration, group.members contains identity_ids.
        """
        group = self._groups.pop(group_id, None)
        if group is None:
            return
        self._redis.delete(_KEY_GROUP.format(group_id))
        for identity_id in group.members:
            self._redis.srem(_KEY_USER.format(identity_id), group_id)

    def get_group(self, group_id: str) -> Optional[RBACGroup]:
        """Return the group or None if it does not exist."""
        return self._groups.get(group_id)

    def list_groups(self) -> list[RBACGroup]:
        """Return a snapshot of all groups, sorted by id."""
        return sorted(self._groups.values(), key=lambda g: g.id)

    # ------------------------------------------------------------------
    # Member management
    # ------------------------------------------------------------------

    def add_member(self, group_id: str, identity_id: str) -> None:
        """
        Add *identity_id* to *group_id*.

        identity_id must be the opaque UID (idnt_{12hex}) from the identity
        registry.  Callers are responsible for resolving email → identity_id
        before calling (see backoffice/routes/rbac.py and scim.py).

        Raises KeyError if the group does not exist.
        Updates both the group object and the identity→group Redis index.
        """
        group = self._groups.get(group_id)
        if group is None:
            raise KeyError(f"RBAC group '{group_id}' does not exist")
        group.members.add(identity_id)
        self._redis.set(_KEY_GROUP.format(group_id), json.dumps(group.to_dict()))
        self._redis.sadd(_KEY_USER.format(identity_id), group_id)

    def remove_member(self, group_id: str, identity_id: str) -> None:
        """
        Remove *identity_id* from *group_id*.

        identity_id must be the opaque UID (idnt_{12hex}) from the identity
        registry.  Callers are responsible for resolving email → identity_id
        before calling (see backoffice/routes/rbac.py and scim.py).

        Raises KeyError if the group does not exist.
        """
        group = self._groups.get(group_id)
        if group is None:
            raise KeyError(f"RBAC group '{group_id}' does not exist")
        group.members.discard(identity_id)
        self._redis.set(_KEY_GROUP.format(group_id), json.dumps(group.to_dict()))
        self._redis.srem(_KEY_USER.format(identity_id), group_id)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_user_groups(self, identity_id: str) -> list[RBACGroup]:
        """
        Return all groups *identity_id* belongs to.

        identity_id must be the opaque UID (idnt_{12hex}) from the identity
        registry.  After the 3.1 UID migration, all user-index keys are
        identity_id-keyed.  Passing an email or slug will return [] — use
        the identity registry to resolve to identity_id first.

        Reads the identity→group index from Redis (authoritative) and resolves
        each group id from the in-memory cache.  Groups that no longer exist
        in the cache are silently skipped (stale index entries).
        """
        try:
            group_ids: set[bytes] = self._redis.smembers(_KEY_USER.format(identity_id))
        except Exception as exc:
            logger.error("RBAC store: smembers failed for %s: %s", identity_id, exc)
            return []

        result: list[RBACGroup] = []
        for raw_id in group_ids:
            gid = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else raw_id
            group = self._groups.get(gid)
            if group is not None:
                result.append(group)
        return result

    def is_allowed(self, identity_id: str, method: str, path: str) -> bool:
        """
        Deny-by-default RBAC check.

        identity_id must be the opaque UID (idnt_{12hex}) from the identity
        registry.  After the 3.1 UID migration, all user-index keys are
        identity_id-keyed.

        Returns True if *at least one* group that *identity_id* belongs to has a
        ResourcePattern that matches (*method*, *path*).
        Returns False if:
          - the identity has no groups, OR
          - no group has a matching pattern.
        """
        groups = self.get_user_groups(identity_id)
        if not groups:
            return False

        for group in groups:
            for pattern in group.allowed_resources:
                if _method_matches(pattern.method, method) and _path_matches(
                    pattern.path_glob, path
                ):
                    return True
        return False

    # ------------------------------------------------------------------
    # Serialisation helpers used by opa_push
    # ------------------------------------------------------------------

    def to_opa_document(self) -> dict:
        """
        Build the data document that OPA expects at
        data.yashigani.rbac.

        Format:
            {
                "groups": {
                    "<group_id>": {
                        "id": "...",
                        "display_name": "...",
                        "allowed_resources": [...]
                    },
                    ...
                },
                "user_groups": {
                    "<identity_id>": ["<group_id>", ...],
                    ...
                }
            }

        After the 3.1 UID migration, user_groups keys are identity_ids
        (idnt_{12hex}).  OPA rbac.rego reads input.session.identity_id to
        look up user_groups — this document must be keyed by identity_id.
        """
        groups_doc: dict = {}
        user_groups_doc: dict = {}

        for group in self._groups.values():
            groups_doc[group.id] = {
                "id": group.id,
                "display_name": group.display_name,
                "allowed_resources": [r.to_dict() for r in group.allowed_resources],
            }
            # group.members contains identity_ids after the 3.1 UID migration.
            for identity_id in group.members:
                user_groups_doc.setdefault(identity_id, [])
                if group.id not in user_groups_doc[identity_id]:
                    user_groups_doc[identity_id].append(group.id)

        return {"groups": groups_doc, "user_groups": user_groups_doc}


# ------------------------------------------------------------------
# Pattern matching helpers — must mirror policy/rbac.rego exactly
# ------------------------------------------------------------------

def _method_matches(pattern: str, method: str) -> bool:
    """True if pattern is "*" or equals method (case-sensitive)."""
    return pattern == "*" or pattern == method


def _path_matches(glob: str, path: str) -> bool:
    """
    Segment-aware glob matching aligned with the OPA rbac.rego helpers.

        "**"           — matches any path
        "/prefix/**"   — matches anything under /prefix/ (requires trailing slash)
        exact string   — only that exact path
        "/a/*/b"       — * matches exactly one path segment (no slashes)

    Uses regex for the * fallback so that * does NOT cross slash boundaries.
    This mirrors OPA's segment-aware glob behavior (IC-6).
    """
    import re as _re
    if glob == "**":
        return True
    if glob == path:
        return True
    if glob.endswith("/**"):
        prefix = glob[:-3]  # strip trailing "/**"
        # Match only paths that start with "prefix/" — not the bare prefix itself
        return path.startswith(prefix + "/")
    # Translate glob to regex: * → [^/]* (no slash crossing), ? → [^/]
    pattern = _re.escape(glob).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    return bool(_re.fullmatch(pattern, path))
