"""
Yashigani Gateway — RBAC / Agent-registry / Capability-Policy / Permission-store
Redis stack builder.

YSG-RISK-131: extracted from ``entrypoint._build_app()`` so the EXACT SAME
construction logic can be invoked from two places:

  1. Startup (``entrypoint._build_app()``), inside a bounded 1/2/4/8/16s
     backoff loop (mirrors backoffice's YSG-RISK-122 fix) — safe to block
     with ``time.sleep()`` here since this runs at module-import time,
     before uvicorn starts accepting connections.
  2. Lazy, bounded, request-time reconnect (``gateway/redis_selfheal.py``),
     needed because the startup loop's ~31s retry budget can still be
     exhausted on k8s when ``yashigani-redis`` Service-DNS is not yet
     resolvable at that instant (Iris, live k8s @ 4.1.2, 17h uptime / 0
     restarts / permanently degraded — see
     ``testing_runs/yashigani/v412-e2e-latest-20260727/iris/remediation_map.md``).
     Previously, once the startup loop gave up, ``rbac_store``,
     ``agent_registry``, ``capability_policy_store``, and ``permission_store``
     stayed ``None`` for the container's entire lifetime — chat requests
     returned ``agent_registry_unavailable`` forever, even after Redis became
     reachable, because nothing ever tried again.

Building this as a free function (not inline in ``_build_app()``) is what
makes reuse possible, exactly as backoffice's ``rbac_stack.py`` does.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GatewayRBACAgentStack:
    """Every store built against the shared gateway Redis db/3 connection."""

    rbac_store: Any
    agent_registry: Any
    capability_policy_store: Any
    permission_store: Any
    # The raw client itself — exposed so callers that need to build ADDITIONAL
    # db/3-backed objects sharing this exact connection (entrypoint.py's
    # identity_registry + MCP id_store/durable_store) can reuse it instead of
    # opening a second connection, matching pre-extraction behaviour exactly.
    redis_client: Any


def build_rbac_agent_stack(redis_rbac_url: str) -> GatewayRBACAgentStack:
    """Construct the RBAC store, agent registry, capability-policy store, and
    permission store (all backed by the same gateway Redis db/3 connection).

    Raises on any failure — the caller (startup retry loop or the lazy
    reconnect gate in ``redis_selfheal.py``) decides retry policy. Fail-closed
    is preserved: a genuine Redis outage still raises here, and every existing
    ``if X is None: ...`` degrade-path in the gateway is untouched. This
    function only changes WHO gets to try again and WHEN.
    """
    import redis as _redis
    from yashigani.rbac.store import RBACStore
    from yashigani.agents.registry import AgentRegistry

    redis_rbac_client = _redis.from_url(redis_rbac_url, decode_responses=False)
    redis_rbac_client.ping()

    rbac_store = RBACStore(redis_client=redis_rbac_client)
    logger.info(
        "Gateway RBAC store ready: %d group(s)", len(rbac_store.list_groups())
    )

    # Agent registry shares the same Redis db/3 instance (different key
    # namespace). Unlike backoffice's AgentRegistry, the gateway does not wire
    # a durable_store here — the gateway lifespan (proxy.py) independently
    # reconciles from the Postgres durable mirror once the app starts
    # (ISSUE-AGENT-REG-DURABILITY), so constructing this without durable_store
    # matches pre-fix behaviour exactly.
    agent_registry = AgentRegistry(redis_client=redis_rbac_client)
    logger.info(
        "Gateway agent registry ready: %d agent(s)", agent_registry.count("all")
    )

    # 3.0 — Capability policy store shares Redis db/3 (key prefix cap_policy:*)
    from yashigani.capability_policy.store import CapabilityPolicyStore as _CapPolStore
    _cap_pol_org_id = os.getenv("YASHIGANI_ORG_ID", "default").strip() or "default"
    capability_policy_store = _CapPolStore(
        redis_client=redis_rbac_client,
        default_org_id=_cap_pol_org_id,
    )
    logger.info(
        "Gateway capability policy store ready (Permissions-Policy, 3.0, org=%s)",
        _cap_pol_org_id,
    )

    # 3.1 Phase 4 / 4.1 SEC-GAP-1 — Permission Store is the inner perm_store
    # of capability_policy_store (same Redis backing, same default_org_id) —
    # exactly ONE PermissionStore instance, matching entrypoint.py's original
    # wiring (avoids the getattr(rbac_store, "_perm_store") dead-migration
    # pattern from the discarded 3fb42f51 restore attempt).
    permission_store = capability_policy_store.perm_store
    logger.info(
        "Gateway permission store ready (Phase 4 MCP allow-list, org=%s)",
        _cap_pol_org_id,
    )

    return GatewayRBACAgentStack(
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        capability_policy_store=capability_policy_store,
        permission_store=permission_store,
        redis_client=redis_rbac_client,
    )
