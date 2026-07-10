"""
Startup reconciler: Postgres agent_registry → Redis db/3 (ISSUE-AGENT-REG-DURABILITY).

# Last updated: 2026-06-10T00:00:00+01:00

Mirrors the OPA store→OPA re-push reconciler (commit 2ce1033, see
project_yashigani_opa_rbac_not_persisted): a fast non-durable store (here Redis
db/3, which runs `appendonly no` / `save ""`) loses all state on a container
recreate, and the durable source (Postgres ``agent_registry``) must be re-pushed
on every boot so the registry self-heals WITHOUT re-running install or any admin
auth.

Behaviour
---------
  * Idempotent — safe to run every backoffice/gateway boot.
  * Restores ONLY agents present in Postgres but MISSING from Redis db/3 (an
    existing Redis entry is authoritative for the request path and is left
    untouched — we never overwrite a live registration with a possibly-older
    durable copy).
  * Restores the EXACT stored bcrypt token_hash, so existing agent PSKs keep
    working — no token rotation, no new agent_id.
  * Fail-LOUD: if reconciliation cannot run (no DB pool, query error) it logs at
    WARNING/ERROR with a clear operator message. It does NOT silently leave
    agents missing without a signal — that silence is the exact failure mode this
    fix exists to eliminate.

Direct, no admin API
--------------------
Runs entirely in-process against the asyncpg pool + the Redis client — no call
to /admin/agents, no admin password, no service account. So it self-heals even
on a stack where the install-path service account was never seeded.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("yashigani.agents.reconciler")


async def reconcile_agents_from_durable(agent_registry, durable_store) -> int:
    """Re-push durable Postgres registrations into Redis db/3 if missing.

    Returns the number of agents restored (0 if Redis was already in sync).
    Never raises — failures are logged loudly and swallowed so a transient DB
    blip cannot block backoffice/gateway startup (the agents already in Redis
    keep working; the next boot retries).
    """
    if agent_registry is None or durable_store is None:
        logger.warning(
            "AGENT-RECONCILE: skipped — agent_registry or durable_store not wired "
            "(agent registrations will NOT auto-restore after a redis recreate)"
        )
        return 0

    try:
        durable_rows = await durable_store.list_all()
    except Exception as exc:
        logger.error(
            "AGENT-RECONCILE: could not read durable agent_registry from Postgres (%s) — "
            "agents will NOT auto-restore this boot; investigate the DB before the next "
            "redis recreate", exc,
        )
        return 0

    if not durable_rows:
        # First boot after this fix landed: the durable store is empty but Redis
        # db/3 may already hold agents registered at install (e.g. letta/langflow)
        # before the dual-write existed. Back-fill Postgres from Redis ONCE so
        # those pre-existing agents become durable too. WITHOUT this, the very
        # next redis recreate (before any new registration) would still wipe them.
        backfilled = _backfill_durable_from_redis(agent_registry, durable_store)
        if backfilled:
            logger.warning(
                "AGENT-RECONCILE: durable store was empty — back-filled %d existing "
                "Redis agent(s) into Postgres so they survive the next redis recreate",
                backfilled,
            )
        else:
            logger.info(
                "AGENT-RECONCILE: durable store empty and no Redis agents to back-fill"
            )
        return 0

    # Current Redis db/3 view (request-time source of truth).
    try:
        existing_ids = {a["agent_id"] for a in agent_registry.list_all()}
    except Exception as exc:
        logger.error(
            "AGENT-RECONCILE: could not read Redis agent index (%s) — aborting reconcile "
            "this boot", exc,
        )
        return 0

    restored = 0
    skipped = 0
    for row in durable_rows:
        agent_id = row.get("agent_id")
        token_hash = row.get("token_hash")
        if not agent_id or not token_hash:
            logger.warning(
                "AGENT-RECONCILE: durable row missing agent_id/token_hash (%r) — skipping",
                {k: row.get(k) for k in ("agent_id", "name")},
            )
            continue
        if agent_id in existing_ids:
            skipped += 1
            continue
        try:
            agent_registry.restore_from_durable(row, token_hash)
            restored += 1
        except Exception as exc:
            logger.error(
                "AGENT-RECONCILE: failed to restore %s (%s) into Redis (%s) — this agent "
                "remains unreachable until re-registered",
                agent_id, row.get("name", "?"), exc,
            )

    if restored:
        logger.warning(
            "AGENT-RECONCILE: restored %d agent(s) into Redis db/3 from durable Postgres "
            "store (Redis had been wiped/recreated); %d already present",
            restored, skipped,
        )
    else:
        logger.info(
            "AGENT-RECONCILE: Redis db/3 already in sync with durable store "
            "(%d agent(s) present, 0 restored)", skipped,
        )
    return restored


def _backfill_durable_from_redis(agent_registry, durable_store) -> int:
    """Seed the durable Postgres store from agents that ONLY exist in Redis.

    One-shot migration path for agents registered before the dual-write existed.
    Reads each Redis agent + its stored bcrypt token_hash and upserts it to
    Postgres. Best-effort per agent — a single failure is logged and does not
    abort the rest. Returns the number of agents successfully back-filled.
    """
    try:
        agents = agent_registry.list_all()
    except Exception as exc:
        logger.error("AGENT-RECONCILE: back-fill could not read Redis agents (%s)", exc)
        return 0

    count = 0
    for agent in agents:
        agent_id = agent.get("agent_id")
        if not agent_id:
            continue
        token_hash = agent_registry.get_token_hash(agent_id)
        if not token_hash:
            logger.warning(
                "AGENT-RECONCILE: back-fill skipping %s (%s) — no token_hash in Redis",
                agent_id, agent.get("name", "?"),
            )
            continue
        try:
            durable_store.upsert(agent, token_hash=token_hash)
            count += 1
        except Exception as exc:
            logger.error(
                "AGENT-RECONCILE: back-fill upsert FAILED for %s (%s) — will retry next "
                "boot: %s", agent_id, agent.get("name", "?"), exc,
            )
    return count
