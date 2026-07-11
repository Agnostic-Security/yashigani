"""
Yashigani Permissions — MCP + external_api grant seeder.

Auto-seeds org-level boolean grants for registered MCP servers AND approved
external API connections on gateway startup (3.1 Phase 3+4 / decision B1:
auto-seed from manifest, non-breaking; 4.0 Item A: external_api now ENFORCED).

Seeding semantics
-----------------
For each server_id in ``server_ids``, write:
    perm:grant:mcp_server:org:{org_id}:{server_id}  →  allow=True

For each host in ``external_api_hosts``, write:
    perm:grant:external_api:org:{org_id}:{host}  →  allow=True

Both give the org-level "allow" required by INV-1 (deny-by-default).
Without the org grant, ``resolve_boolean_grant`` returns False for any caller
trying to reach the resource (even "gateway:orchestrator"), which is exactly
the right deny-by-default posture for unregistered servers/hosts.

Note (v4.0 Item A): external_api grants are now ENFORCED at runtime by
``orchestrator._execute_api_call()`` via ``resolve_boolean_grant``.  Seeding
is NOT merely informational — without the seed, the org grant is absent and
all api__ tool calls to that host are blocked.  Revoking a seeded grant
(DELETE /admin/permissions/org/external_api/{host}) immediately blocks
all subsequent orchestrated calls to that host.

"gateway:orchestrator" is implicitly covered by the org-level grant because
``resolve_boolean_grant`` is called with ``principal_scope=None, principal_id=None``
for the connection allow-list check (org-level only; no group/user narrowing
for the orchestrator).  4.1 SEC-GAP-1: user_email removed from authz path.

Idempotency
-----------
``PermissionStore.set_boolean_grant`` performs a Redis SET (overwrite); calling
this function multiple times with the same inputs is safe and produces the same
result.  Callers should call it at every startup — the cost is O(N) Redis writes
where N = len(server_ids) + len(external_api_hosts).

Last updated: 2026-07-03T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Optional

from yashigani.permissions.model import BooleanGrantValue, ResourceType
from yashigani.permissions.store import PermissionStore

logger = logging.getLogger(__name__)


def seed_mcp_grants(
    perm_store: PermissionStore,
    server_ids: list[str],
    org_id: str,
    *,
    external_api_hosts: Optional[list[str]] = None,
) -> None:
    """
    Seed org-level grants for the given MCP server IDs (and optionally external
    API hosts) into the permission store.

    This function is idempotent and safe to call at every gateway startup.

    Parameters
    ----------
    perm_store:
        Initialised PermissionStore instance.
    server_ids:
        List of MCP server IDs to grant org-level access to.
        Typically the ``agent_name`` values from YASHIGANI_MCP_SERVERS.
    org_id:
        Organisation ID to seed the grant for (must match the ``org_id`` used
        in ``resolve_boolean_grant`` at enforcement time).
    external_api_hosts:
        Optional list of external API host names (grant keys — stable DNS
        hostnames, not display names) from ``YASHIGANI_EXTERNAL_APIS`` env or
        agent manifest ``spec.network.egress_allow[].host`` declarations.
        When provided, org-level ``external_api`` grants are seeded alongside
        MCP server grants.
        NOTE (v4.0 Item A): these grants are ENFORCED at runtime by
        ``orchestrator._execute_api_call()``.  Without a seed, all api__ calls
        to the host are blocked (deny-by-default).
    """
    if not server_ids and not external_api_hosts:
        logger.debug("perm-seeder: no server_ids or external_api_hosts to seed — no-op")
        return

    seeded = 0
    failed = 0

    # ── MCP server grants ──────────────────────────────────────────────────────
    for server_id in server_ids:
        if not server_id:
            continue
        try:
            perm_store.set_boolean_grant(
                resource_type=ResourceType.MCP_SERVER,
                scope_kind="org",
                scope_id=org_id,
                resource_id=server_id,
                value=BooleanGrantValue(allow=True),
            )
            logger.debug(
                "perm-seeder: seeded mcp_server org-grant org=%s server=%s",
                org_id, server_id,
            )
            seeded += 1
        except Exception as exc:
            logger.error(
                "perm-seeder: failed to seed mcp_server grant "
                "org=%s server=%s: %s",
                org_id, server_id, exc,
            )
            failed += 1

    # ── External API grants (optional, informational in 3.1) ──────────────────
    for host in (external_api_hosts or []):
        if not host:
            continue
        try:
            perm_store.set_boolean_grant(
                resource_type=ResourceType.EXTERNAL_API,
                scope_kind="org",
                scope_id=org_id,
                resource_id=host,
                value=BooleanGrantValue(allow=True),
            )
            logger.debug(
                "perm-seeder: seeded external_api org-grant org=%s host=%s",
                org_id, host,
            )
            seeded += 1
        except Exception as exc:
            logger.error(
                "perm-seeder: failed to seed external_api grant "
                "org=%s host=%s: %s",
                org_id, host, exc,
            )
            failed += 1

    logger.info(
        "perm-seeder: seeded %d grant(s) for org=%s (%d MCP servers, %d ext APIs); "
        "%d failure(s)",
        seeded, org_id, len(server_ids), len(external_api_hosts or []), failed,
    )
    if failed > 0:
        logger.warning(
            "perm-seeder: %d grant(s) failed to seed — "
            "deny-by-default applies for affected servers",
            failed,
        )
