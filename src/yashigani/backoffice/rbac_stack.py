"""
Yashigani Backoffice — RBAC / Agent-registry Redis stack builder.

YSG-RISK-122: extracted from entrypoint._bootstrap() so the EXACT SAME
construction logic can be invoked from two places:

  1. Startup (entrypoint.py `_bootstrap()`), inside its existing 5-attempt
     1/2/4/8/16s backoff loop. This runs at MODULE IMPORT time, before
     uvicorn starts accepting connections, so blocking `time.sleep()` there
     is safe (see entrypoint.py comment above the loop).
  2. Lazy, bounded, request-time reconnect (`redis_selfheal.py`), added
     because the startup loop's ~31s retry budget can still be exhausted on
     k8s when the `yashigani-redis-0` pod is scheduled after
     `yashigani-backoffice` (headless-Service DNS is not populated until the
     Redis pod IP registers with kube-dns) — Ava, live docker-desktop k8s
     @ ca720724. Previously, once the startup loop gave up, every field this
     builder returns stayed `None` for the container's entire lifetime, even
     after Redis became reachable — permanently disabling RBAC, agent
     registry, permission store (capability_policy_store backs
     backoffice/routes/permissions.py), and the document/envelope/dp-weaken
     stores that share this same Redis db/3 connection.

Building this as a free function (not a closure inside `_bootstrap()`) is
what makes reuse possible: `_bootstrap()` and its module-level side effects
(credential printing, `app = create_backoffice_app()`) run once at import.
Route modules must NEVER import `entrypoint.py` to reach this logic — that
would re-run bootstrap. `redis_selfheal.py` imports ONLY this module.

Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RBACAgentStack:
    """Every store built against the shared backoffice Redis db/3 connection."""

    rbac_store: Any
    agent_registry: Any
    binding_store: Any
    document_policy_store: Any
    document_set_store: Any
    envelope_pending_store: Any
    dp_weaken_store: Any
    capability_policy_store: Any


def build_rbac_agent_stack(redis_rbac_url: str) -> RBACAgentStack:
    """Construct the full RBAC/Agent/Binding/.../CapabilityPolicy stack.

    Raises on any failure — the caller (startup retry loop or the lazy
    reconnect gate in `redis_selfheal.py`) decides retry policy. Fail-closed
    is preserved: a genuine Redis outage still raises here, and callers still
    surface 503 to the API layer. This function only changes WHO gets to try
    again and WHEN — not whether a real outage is denied.
    """
    import redis as _redis
    from yashigani.rbac.store import RBACStore
    from yashigani.agents.registry import AgentRegistry

    redis_rbac_client = _redis.from_url(redis_rbac_url, decode_responses=False)

    rbac_store = RBACStore(redis_client=redis_rbac_client)
    logger.info(
        "RBAC store initialised: %d group(s) loaded from Redis",
        len(rbac_store.list_groups()),
    )

    # Agent registry shares the same Redis db/3 instance (different key namespace).
    # ISSUE-AGENT-REG-DURABILITY (Iris, 2026-06-10): wire the durable Postgres
    # mirror so register/update/deactivate dual-write to agent_registry. Redis
    # db/3 has no persistence (appendonly no / save ""), so a redis recreate
    # wipes the registry; the durable store + startup reconciler (lifespan)
    # restore it. Constructed only when a usable (non-templated) DSN is
    # present; otherwise the registry stays Redis-only as before. The store
    # uses its own sync psycopg2 conn at write time, so it does not depend on
    # the asyncpg pool being open yet.
    _durable_agent_store = None
    try:
        from yashigani.agents.durable_store import AgentDurableStore, _direct_dsn
        if _direct_dsn() and "${POSTGRES_PASSWORD}" not in _direct_dsn():
            _durable_agent_store = AgentDurableStore()
            logger.info("Agent durable store (Postgres mirror) wired")
        else:
            logger.warning(
                "Agent durable store NOT wired — no usable Postgres DSN; "
                "agent registrations will NOT survive a redis recreate"
            )
    except Exception as _ds_exc:
        logger.warning("Agent durable store init skipped (%s)", _ds_exc)

    agent_registry = AgentRegistry(
        redis_client=redis_rbac_client,
        durable_store=_durable_agent_store,
    )
    logger.info(
        "Agent registry initialised: %d agent(s) in index",
        agent_registry.count("all"),
    )

    # #16 — client-policy BindingStore shares the same Redis db/3 instance
    # (key prefix ysgbind:*, disjoint from rbac:* and the agent registry).
    from yashigani.policy_bindings.store import BindingStore as _BindingStore
    binding_store = _BindingStore(redis_client=redis_rbac_client)
    logger.info(
        "Binding store initialised: %d client-policy binding(s) loaded",
        len(binding_store.list()),
    )

    # Document-enforcement policy store (2.26) shares Redis db/3 (key
    # namespace "document:"); same persistence + startup-OPA-re-push pattern
    # as the RBAC store. Seed the demo matrix on first boot only.
    from yashigani.documents.policy_store import DocumentPolicyStore
    document_policy_store = DocumentPolicyStore(redis_client=redis_rbac_client)
    document_policy_store.seed_defaults()
    logger.info(
        "Document policy store initialised: %d policy(ies) loaded from Redis",
        len(document_policy_store.list_policies()),
    )

    # Document-SET store (2.26 set-scoped-salt) shares Redis db/3 (key
    # namespace "document:set:"); holds the opaque per-set salt for
    # operator-defined cross-file correlation sets. No seeding — sets are
    # operator-created (default stays per-file isolation).
    from yashigani.documents.set_store import DocumentSetStore
    document_set_store = DocumentSetStore(redis_client=redis_rbac_client)
    logger.info(
        "Document set store initialised: %d set(s) loaded from Redis",
        len(document_set_store.list_sets()),
    )

    # Capability-envelope PENDING re-approval store (3.0 / YSG-RISK-060) shares
    # Redis db/3 (key namespace "mcp_envelope_pending:"). Holds the candidate
    # (refreshed) tool surface for every BLOCKED imported-MCP refresh so the
    # re-approval admin SPA can show the diff vs the ORIGINAL baseline and
    # mint it on step-up approve. No seeding — entries are created by the
    # broker when it latches a block.
    from yashigani.mcp.envelope_pending_store import EnvelopePendingStore
    envelope_pending_store = EnvelopePendingStore(redis_client=redis_rbac_client)
    logger.info(
        "Capability-envelope pending store initialised: %d pending re-approval(s)",
        len(envelope_pending_store.list_for_tenant(
            os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"
        )),
    )

    # 4.0 — Data-protection weaken pending store (LAURA-V400-R2-001). Shares
    # Redis db/3 (key namespace "dp_weaken:"). Holds pending maker-checker
    # weaken requests for pii_config, pii_cloud_bypass, and doc_enforcement
    # until a second admin approves or rejects. No seeding — entries are
    # created on-demand via the admin API.
    from yashigani.protection.weaken_pending_store import DpWeakenPendingStore as _DpWeakenStore
    dp_weaken_store = _DpWeakenStore(redis_client=redis_rbac_client)
    logger.info(
        "Data-protection weaken store initialised (dual-admin maker-checker, 4.0): "
        "%d pending request(s)",
        dp_weaken_store.count_for_tenant(
            os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"
        ),
    )

    # 3.0 — browser Permissions-Policy store (Redis db/3, prefix cap_policy:*)
    from yashigani.capability_policy.store import CapabilityPolicyStore as _CapPolStore
    cap_pol_org_id = os.getenv("YASHIGANI_ORG_ID", "default").strip() or "default"
    capability_policy_store = _CapPolStore(
        redis_client=redis_rbac_client,
        default_org_id=cap_pol_org_id,
    )
    logger.info(
        "Capability policy store initialised (browser Permissions-Policy, 3.0, org=%s)",
        cap_pol_org_id,
    )

    return RBACAgentStack(
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        binding_store=binding_store,
        document_policy_store=document_policy_store,
        document_set_store=document_set_store,
        envelope_pending_store=envelope_pending_store,
        dp_weaken_store=dp_weaken_store,
        capability_policy_store=capability_policy_store,
    )
