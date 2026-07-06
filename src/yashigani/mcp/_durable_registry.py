"""
Yashigani MCP — durable broker-registry store (v4.1 Phase 2a / SEAM-1d-07).

Problem (Iris SEAM-1d-07)
-------------------------
The gateway's McpBrokerRegistry is populated ONLY from the boot-time
``YASHIGANI_MCP_SERVERS`` env var.  The v4.1 approve transaction
(backoffice/mcp_onboard.py) mints the leaf, writes the Caddy-front wrap and
commits the durable envelope — but never updates the broker registry.  The
wrap exists, verify-mcp admits it, and the broker never dials it until an
operator edits the gateway env and recreates the container.

Fix
---
The approve transaction durably registers the onboarded MCP's broker
descriptor here (Redis, same db/3 the permission/id stores use), keyed on the
canonical ``<tenant>:<server>`` — the SAME key the envelope row, the Caddy
route, the minted leaf SPIFFE path and /auth/verify-mcp all agree on
(iris-phase1d-audit.md §1).  The gateway's McpBrokerRegistry consults this
store on a lookup MISS (lazy load — see registry.py) and builds the broker on
first use: ``/mcp/<server>`` routes WITHOUT a gateway reboot, and the
registration survives reboots (Redis-persisted; the boot env stays authoritative
for boot-time entries and is never mutated).

Descriptor shape (JSON)::

    {
      "agent_name":          "<server_id>",        # registry key == path param
      "upstream_url":        "https://caddy:<mesh_port>/mcp/<tenant>/<server>",
      "tenant_id":           "<tenant>",
      "is_filesystem_agent": bool,
      "is_git_agent":        bool,
      "mcp_id":              "",                    # minted lazily gateway-side
      "cert_fingerprint":    "sha256:<hex>",        # per-instance leaf fp
      "spiffe_id":           "spiffe://.../agents/<t>/<s>/<nhi>",
      "svid_instance_id":    "nhi_<hex>",
      "registered_at":       "<ISO 8601 UTC>",
    }

Failure posture: every read path degrades to None (registry miss → 404, the
pre-existing behaviour).  Write paths raise — the approve transaction treats
a failed registration as a step failure and rolls back (fail-closed; a wrap
the broker can never dial is a partial onboarding).

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_KEY_SERVER = "mcp:broker:server:{tenant}:{server}"
_KEY_INDEX = "mcp:broker:server_index"


def canonical_server_key(tenant_id: str, server_id: str) -> str:
    """The canonical ``<tenant>:<server>`` key (== envelope provenance_id)."""
    return f"{tenant_id}:{server_id}"


class DurableMcpRegistryStore:
    """Redis-backed store of onboarded MCP broker descriptors.

    Written by the backoffice approve transaction; read by the gateway
    McpBrokerRegistry lazy-load path.  Both sides share Redis db/3.
    """

    def __init__(self, redis_client: Any) -> None:
        if redis_client is None:
            raise RuntimeError(
                "DurableMcpRegistryStore requires a non-None Redis client."
            )
        self._redis = redis_client

    # ── write side (approve transaction) ─────────────────────────────────

    def put(self, tenant_id: str, server_id: str, descriptor: dict) -> None:
        """Durably register (or update) the broker descriptor.

        Raises on any Redis failure — the caller (approve transaction) must
        treat that as a step failure and roll back.
        """
        if not tenant_id or not server_id:
            raise ValueError("tenant_id and server_id must be non-empty")
        desc = dict(descriptor)
        desc.setdefault("agent_name", server_id)
        desc.setdefault("tenant_id", tenant_id)
        desc.setdefault(
            "registered_at", datetime.now(tz=timezone.utc).isoformat()
        )
        key = canonical_server_key(tenant_id, server_id)
        self._redis.set(_KEY_SERVER.format(tenant=tenant_id, server=server_id),
                        json.dumps(desc))
        self._redis.sadd(_KEY_INDEX, key)
        logger.info(
            "mcp-durable-registry: registered %s (upstream=%r)",
            key, desc.get("upstream_url"),
        )

    def delete(self, tenant_id: str, server_id: str) -> None:
        """Remove a registration (approve-transaction rollback / offboard)."""
        key = canonical_server_key(tenant_id, server_id)
        try:
            self._redis.delete(
                _KEY_SERVER.format(tenant=tenant_id, server=server_id)
            )
            self._redis.srem(_KEY_INDEX, key)
            logger.info("mcp-durable-registry: deleted %s", key)
        except Exception as exc:  # noqa: BLE001 — rollback path is best-effort
            logger.error("mcp-durable-registry: delete %s failed: %s", key, exc)

    # ── read side (gateway lazy load) ─────────────────────────────────────

    def get(self, tenant_id: str, server_id: str) -> Optional[dict]:
        """Return the descriptor for ``<tenant>:<server>``, or None."""
        try:
            raw = self._redis.get(
                _KEY_SERVER.format(tenant=tenant_id, server=server_id)
            )
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-durable-registry: get %s:%s failed: %s",
                tenant_id, server_id, exc,
            )
            return None
        return self._decode(raw)

    def get_by_agent_name(self, agent_name: str) -> Optional[dict]:
        """Return the descriptor whose server component == ``agent_name``.

        The runtime route is ``/mcp/<agent_name>`` (single segment); the
        onboard transaction enforces ``metadata.name == server_id`` so the
        path param equals the server component of the canonical key.  The
        index is scanned (small N — one entry per onboarded MCP); an ambiguous
        name (same server_id under two tenants) returns None and logs — the
        caller falls through to a 404 rather than guessing a tenant.
        """
        if not agent_name:
            return None
        try:
            members = self._redis.smembers(_KEY_INDEX) or set()
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-durable-registry: index read failed for %r: %s",
                agent_name, exc,
            )
            return None
        matches = []
        for m in members:
            key = m.decode("utf-8", errors="replace") if isinstance(m, bytes) else str(m)
            tenant, sep, server = key.partition(":")
            if sep and server == agent_name:
                matches.append((tenant, server))
        if not matches:
            return None
        if len(matches) > 1:
            logger.error(
                "mcp-durable-registry: agent_name=%r is ambiguous across "
                "tenants %s — refusing to guess (404)",
                agent_name, sorted(t for t, _ in matches),
            )
            return None
        tenant, server = matches[0]
        return self.get(tenant, server)

    def list_all(self) -> list[dict]:
        """Return every registered descriptor (health probes / admin views)."""
        out: list[dict] = []
        try:
            members = self._redis.smembers(_KEY_INDEX) or set()
        except Exception as exc:  # noqa: BLE001
            logger.warning("mcp-durable-registry: list_all failed: %s", exc)
            return out
        for m in members:
            key = m.decode("utf-8", errors="replace") if isinstance(m, bytes) else str(m)
            tenant, sep, server = key.partition(":")
            if not sep:
                continue
            desc = self.get(tenant, server)
            if desc is not None:
                out.append(desc)
        return out

    @staticmethod
    def _decode(raw: Any) -> Optional[dict]:
        if raw is None:
            return None
        try:
            data = json.loads(
                raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
            )
        except Exception:  # noqa: BLE001 — corrupt entry degrades to miss
            logger.error("mcp-durable-registry: corrupt descriptor JSON — treated as miss")
            return None
        return data if isinstance(data, dict) else None


__all__ = ["DurableMcpRegistryStore", "canonical_server_key"]
