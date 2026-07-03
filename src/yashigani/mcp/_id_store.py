"""
Yashigani MCP — stable mcp_id registry (v4.0 Item B).

Problem (pre-4.0)
-----------------
MCP server grants were keyed by ``agent_name`` (the human-readable display name
from YASHIGANI_MCP_SERVERS).  Renaming a server entry orphaned all its grants:
  perm:grant:mcp_server:org:{org}:{old_name}  → lost on rename
  perm:grant:mcp_server:org:{org}:{new_name}  → new key, empty = deny-by-default

Fix (4.0)
---------
Every MCP server is assigned a stable UUID (``mcp_id``) on its FIRST appearance.
Grants, capability-envelopes, and approvals are keyed by ``mcp_id``, NOT by
``agent_name``.  The display name becomes a mutable label stored separately.

Redis key schema
----------------
  mcp:name_to_id:{agent_name}    → mcp_id  (fast name→id lookup; updated on
                                             rename via reconcile_name_mapping)
  mcp:id_registry:{mcp_id}       → JSON blob with agent_name, created_at,
                                   last_seen_at (for audit / rename tracking)

Startup reconcile (idempotent)
-------------------------------
On each gateway startup, for every entry in YASHIGANI_MCP_SERVERS:
  1. ``get_or_mint(agent_name)`` → returns existing mcp_id OR mints a new UUID.
  2. ``reconcile_grants(perm_store, org_id, agent_name, mcp_id)`` → if a grant
     exists at the old ``agent_name`` key but NOT at ``mcp_id``, copy it over.
  3. McpBroker._check_connection_permit() uses mcp_id as the grant key.

After one startup cycle, ALL grant checks use mcp_id.  Old name-keyed grants
are preserved as a transition fallback (they are not deleted); the mcp_id-keyed
copy is the canonical enforcement key going forward.

Rename survivability
--------------------
If an operator renames ``filesystem-mcp`` → ``filesystem`` in YASHIGANI_MCP_SERVERS:
  - ``get_or_mint("filesystem")`` will NOT find an existing mcp_id for "filesystem"
    → mints a new UUID (new server).
  - The old entry is gone; its grants at the old mcp_id are no longer referenced.

To survive a rename WITHOUT orphaning grants, the operator must add
``"mcp_id": "<previous_mcp_id>"`` to the new entry in YASHIGANI_MCP_SERVERS.
When ``mcp_id`` is present in the config entry, it is used DIRECTLY (no mint).
This gives operators full control over identity continuity.

Last updated: 2026-07-03T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_KEY_NAME_TO_ID = "mcp:name_to_id:{}"
_KEY_ID_REGISTRY = "mcp:id_registry:{}"


class McpIdStore:
    """
    Stable mcp_id registry — backed by a Redis client (db/3, key prefix mcp:*).

    Usage::

        store = McpIdStore(redis_client)

        # On startup per YASHIGANI_MCP_SERVERS entry:
        mcp_id = store.get_or_mint(agent_name)

        # Optional: after building the permission store, reconcile old name-key grants.
        count = store.reconcile_grants(perm_store, org_id, agent_name, mcp_id)
    """

    def __init__(self, redis_client: Any) -> None:
        if redis_client is None:
            raise RuntimeError(
                "McpIdStore requires a non-None Redis client.  "
                "Ensure Redis is available before constructing McpIdStore."
            )
        self._redis = redis_client

    # ------------------------------------------------------------------
    # Core — get_or_mint
    # ------------------------------------------------------------------

    def get_or_mint(
        self,
        agent_name: str,
        *,
        override_mcp_id: Optional[str] = None,
    ) -> str:
        """Return the stable mcp_id for ``agent_name``, minting one if absent.

        Parameters
        ----------
        agent_name:
            The human-readable server name from YASHIGANI_MCP_SERVERS.
        override_mcp_id:
            If the operator has pinned an explicit mcp_id in the config entry
            (``"mcp_id": "<uuid>"``), pass it here.  It is stored as canonical
            and returned directly (no new UUID is minted).  Idempotent: if the
            same override is passed on every startup, the stored value is the same.

        Returns
        -------
        str
            The stable mcp_id UUID string for this server.
        """
        if not agent_name:
            raise ValueError("agent_name must be a non-empty string")

        name_key = _KEY_NAME_TO_ID.format(agent_name)

        if override_mcp_id:
            # Operator-pinned mcp_id: store (or re-affirm) the mapping and return.
            self._redis.set(name_key, override_mcp_id)
            self._upsert_registry(override_mcp_id, agent_name, is_new=False)
            return override_mcp_id

        # Look up existing mapping.
        existing = self._redis.get(name_key)
        if existing is not None:
            if isinstance(existing, bytes):
                existing = existing.decode("utf-8", errors="replace")
            # Refresh last_seen_at in registry.
            self._upsert_registry(existing, agent_name, is_new=False)
            return existing

        # Mint a new stable UUID.
        new_id = str(uuid.uuid4())
        self._redis.set(name_key, new_id)
        self._upsert_registry(new_id, agent_name, is_new=True)
        logger.info(
            "mcp-id-store: minted mcp_id=%s for agent_name=%r (new registration)",
            new_id, agent_name,
        )
        return new_id

    def _upsert_registry(
        self,
        mcp_id: str,
        agent_name: str,
        *,
        is_new: bool,
    ) -> None:
        """Write / update mcp:id_registry:{mcp_id}."""
        try:
            reg_key = _KEY_ID_REGISTRY.format(mcp_id)
            now_iso = datetime.now(tz=timezone.utc).isoformat()
            existing_raw = self._redis.get(reg_key)
            if existing_raw is not None:
                try:
                    existing_data = json.loads(
                        existing_raw if isinstance(existing_raw, str)
                        else existing_raw.decode("utf-8", errors="replace")
                    )
                except Exception:
                    existing_data = {}
                existing_data["agent_name"] = agent_name
                existing_data["last_seen_at"] = now_iso
                self._redis.set(reg_key, json.dumps(existing_data))
            else:
                self._redis.set(reg_key, json.dumps({
                    "mcp_id": mcp_id,
                    "agent_name": agent_name,
                    "created_at": now_iso,
                    "last_seen_at": now_iso,
                    "is_new_mint": is_new,
                }))
        except Exception as exc:
            # Registry upsert failure is non-fatal — the name→id mapping is
            # the load-bearing key; the registry is metadata only.
            logger.warning(
                "mcp-id-store: registry upsert failed for mcp_id=%s: %s",
                mcp_id, exc,
            )

    # ------------------------------------------------------------------
    # Reconcile — copy name-keyed grants to mcp_id-keyed grants
    # ------------------------------------------------------------------

    def reconcile_grants(
        self,
        perm_store: Any,      # PermissionStore — typed as Any to avoid circular import
        org_id: str,
        agent_name: str,
        mcp_id: str,
    ) -> int:
        """Copy name-keyed MCP grants to mcp_id-keyed grants (idempotent backfill).

        On first startup after 4.0 upgrade, an existing deployment may have
        MCP server grants stored at ``perm:grant:mcp_server:org:{org_id}:{agent_name}``.
        The broker now uses ``mcp_id`` as the key; without this reconcile the
        org grant would be absent under the new key → deny-by-default.

        Backfill: if a grant exists at ``agent_name`` but NOT at ``mcp_id``,
        copy it to ``mcp_id``.  If ``mcp_id`` already has a grant, no-op
        (the mcp_id key is canonical; never overwrite it).

        Returns
        -------
        int
            Number of grant scopes copied (0 = already reconciled or no source grant).
        """
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        import json as _json

        if not org_id or not agent_name or not mcp_id:
            return 0
        if agent_name == mcp_id:
            return 0  # Already using mcp_id as the name (no backfill needed)

        copied = 0
        try:
            rt = ResourceType.MCP_SERVER
            # Check if mcp_id key already has a grant (canonical key wins; no-op).
            existing_by_id = perm_store.get_boolean_grant(rt, "org", org_id, mcp_id)
            if existing_by_id is not None:
                logger.debug(
                    "mcp-id-store: reconcile skip (mcp_id key already has grant) "
                    "agent=%r mcp_id=%s org=%s",
                    agent_name, mcp_id, org_id,
                )
                return 0

            # Look for the old name-keyed grant.
            grant_by_name = perm_store.get_boolean_grant(rt, "org", org_id, agent_name)
            if grant_by_name is None:
                logger.debug(
                    "mcp-id-store: no source grant to reconcile "
                    "agent=%r mcp_id=%s org=%s",
                    agent_name, mcp_id, org_id,
                )
                return 0

            # Copy name-keyed grant → mcp_id key.
            perm_store.set_boolean_grant(
                resource_type=rt,
                scope_kind="org",
                scope_id=org_id,
                resource_id=mcp_id,
                value=grant_by_name,
            )
            copied += 1
            logger.info(
                "mcp-id-store: reconciled grant agent=%r → mcp_id=%s (org=%s allow=%s)",
                agent_name, mcp_id, org_id, grant_by_name.allow,
            )
        except Exception as exc:
            logger.error(
                "mcp-id-store: reconcile_grants FAILED agent=%r mcp_id=%s org=%s: %s",
                agent_name, mcp_id, org_id, exc,
            )
        return copied

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get_mcp_id_for_name(self, agent_name: str) -> Optional[str]:
        """Look up the mcp_id for a given agent_name.  Returns None if not found."""
        if not agent_name:
            return None
        raw = self._redis.get(_KEY_NAME_TO_ID.format(agent_name))
        if raw is None:
            return None
        return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)

    def get_registry_entry(self, mcp_id: str) -> Optional[dict]:
        """Return the registry metadata dict for a mcp_id, or None."""
        if not mcp_id:
            return None
        raw = self._redis.get(_KEY_ID_REGISTRY.format(mcp_id))
        if raw is None:
            return None
        try:
            return json.loads(raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace"))
        except Exception:
            return None
