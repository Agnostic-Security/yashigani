"""
Startup reconciler: Postgres user_agents / user_memory_blocks / user_workflows
→ Redis db/3 (ISSUE-USER-PLANE-DURABILITY).

# Last updated: 2026-06-27T00:00:00+00:00

Mirrors agents/reconciler.py for the user-plane stores.

Behaviour
---------
  * Idempotent — safe to run every backoffice boot.
  * Restores ONLY entities MISSING from Redis db/3 (an existing Redis entry is
    authoritative and is left untouched).
  * Fail-LOUD but non-raising: any error is logged at ERROR and swallowed so
    a transient DB blip cannot block backoffice startup.
  * For enabled workflows with a scheduler spec, also pushes wf:spec:{wf_id}
    into db/6 if available; on failure, logs a warning and skips (the scheduler
    re-loads from db/3 on its next tick).

Returns (agents_restored, memories_restored, workflows_restored).
"""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("yashigani.agents.user_plane_reconciler")


async def reconcile_user_plane_from_durable(
    redis_client,
    durable_store,
) -> tuple[int, int, int]:
    """Restore user agents, memory blocks, and workflows from Postgres into Redis db/3.

    Parameters
    ----------
    redis_client:
        A synchronous redis.Redis client connected to db/3 (same client used
        by the user_agents routes — accessed via identity_registry._r).
    durable_store:
        A ``UserPlaneDurableStore`` instance (already wired in backoffice_state).

    Returns
    -------
    tuple[int, int, int]
        (agents_restored, memories_restored, workflows_restored)
        — the number of entities pushed back into Redis because they were absent.
    """
    if redis_client is None or durable_store is None:
        logger.warning(
            "USER-PLANE-RECONCILE: skipped — redis_client or durable_store not wired "
            "(user agents/memories/workflows will NOT auto-restore after a Redis wipe)"
        )
        return 0, 0, 0

    agents_restored = await _reconcile_agents(redis_client, durable_store)
    memories_restored = await _reconcile_memories(redis_client, durable_store)
    workflows_restored = await _reconcile_workflows(redis_client, durable_store)

    return agents_restored, memories_restored, workflows_restored


# ---------------------------------------------------------------------------
# Agent reconcile
# ---------------------------------------------------------------------------

async def _reconcile_agents(redis_client, durable_store) -> int:
    try:
        rows = await durable_store.list_all_agents()
    except Exception as exc:
        logger.error(
            "USER-PLANE-RECONCILE: could not read user_agents from Postgres (%s) — "
            "user agents will NOT auto-restore this boot", exc,
        )
        return 0

    if not rows:
        logger.info("USER-PLANE-RECONCILE: no durable user_agents rows — nothing to restore")
        return 0

    restored = 0
    for row in rows:
        ua_id = row.get("ua_id")
        if not ua_id:
            continue
        meta_key = f"ua:meta:{ua_id}"
        try:
            if redis_client.exists(meta_key):
                continue  # Redis entry is authoritative; leave it
            account_id = row.get("account_id", "")
            # Rebuild the Redis hash from durable columns
            mapping: dict[bytes, bytes] = {
                b"account_id":       (account_id or "").encode(),
                b"name":             (row.get("name") or "").encode(),
                b"description":      (row.get("description") or "").encode(),
                b"alias":            (row.get("alias") or "").encode(),
                b"kind":             (row.get("kind") or "agent").encode(),
                b"personality":      _json_col(row.get("personality")),
                b"effective_skills": _json_col(row.get("effective_skills")),
                b"declared_skills":  _json_col(row.get("declared_skills")),
                b"graph":            (row.get("graph") or "").encode(),
                b"graph_hash":       (row.get("graph_hash") or "").encode(),
                b"letta_agent_id":   (row.get("letta_agent_id") or "").encode(),
                b"nhi_id":           (row.get("nhi_id") or "").encode(),
                b"created_at":       _ts(row.get("created_at")),
                b"updated_at":       _ts(row.get("updated_at")),
            }
            pipe = redis_client.pipeline()
            pipe.hset(meta_key, mapping=mapping)
            pipe.sadd(f"ua:agents:{account_id}", ua_id.encode())
            alias = row.get("alias") or ""
            if alias:
                pipe.hset(f"ua:alias:{account_id}", mapping={alias: ua_id})
            pipe.execute()
            restored += 1
        except Exception as exc:
            logger.error(
                "USER-PLANE-RECONCILE: failed to restore agent %s into Redis (%s)",
                ua_id, exc,
            )

    # Also restore memory links for all restored (or already-present) agents
    _reconcile_memory_links_sync(redis_client, durable_store, rows)

    if restored:
        logger.warning(
            "USER-PLANE-RECONCILE: restored %d user agent(s) into Redis db/3 "
            "(Redis had been wiped/recreated)", restored,
        )
    else:
        logger.info(
            "USER-PLANE-RECONCILE: Redis db/3 already in sync for user agents "
            "(%d durable row(s))", len(rows),
        )
    return restored


def _reconcile_memory_links_sync(redis_client, durable_store, agent_rows: list[dict]) -> None:
    """Push ua:mem:agent:{ua_id} sets from the durable links table.

    This is called synchronously from within the async reconciler; the
    durable_store read is done synchronously via a direct psycopg2 query here
    (avoiding an extra async roundtrip) since we are already inside the agent
    reconcile loop and link counts are small.
    """
    for row in agent_rows:
        ua_id = row.get("ua_id")
        if not ua_id:
            continue
        link_key = f"ua:mem:agent:{ua_id}"
        try:
            if redis_client.exists(link_key):
                continue  # already populated — leave it
            # Sync read of links for this agent
            block_ids = _sync_list_memory_links(durable_store, ua_id)
            if block_ids:
                redis_client.sadd(link_key, *[bid.encode() for bid in block_ids])
        except Exception as exc:
            logger.error(
                "USER-PLANE-RECONCILE: failed to restore memory links for agent %s (%s)",
                ua_id, exc,
            )


def _sync_list_memory_links(durable_store, ua_id: str) -> list[str]:
    """Read memory links for ua_id using a direct sync psycopg2 query."""
    try:
        conn = durable_store._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT block_id FROM user_agent_memory_links WHERE ua_id = %s",
                    (ua_id,),
                )
                return [r[0] for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as exc:
        logger.error(
            "USER-PLANE-RECONCILE: _sync_list_memory_links FAILED for %s (%s)", ua_id, exc,
        )
        return []


# ---------------------------------------------------------------------------
# Memory reconcile
# ---------------------------------------------------------------------------

async def _reconcile_memories(redis_client, durable_store) -> int:
    try:
        rows = await durable_store.list_all_memories()
    except Exception as exc:
        logger.error(
            "USER-PLANE-RECONCILE: could not read user_memory_blocks from Postgres (%s) — "
            "memory blocks will NOT auto-restore this boot", exc,
        )
        return 0

    if not rows:
        logger.info("USER-PLANE-RECONCILE: no durable user_memory_blocks rows — nothing to restore")
        return 0

    restored = 0
    for row in rows:
        block_id = row.get("block_id")
        if not block_id:
            continue
        meta_key = f"ua:mem:meta:{block_id}"
        try:
            if redis_client.exists(meta_key):
                continue
            account_id = row.get("account_id", "")
            mapping: dict[bytes, bytes] = {
                b"account_id":     (account_id or "").encode(),
                b"label":          (row.get("label") or "").encode(),
                b"value":          (row.get("value") or "").encode(),
                b"letta_block_id": (row.get("letta_block_id") or "").encode(),
                b"created_at":     _ts(row.get("created_at")),
                b"updated_at":     _ts(row.get("updated_at")),
            }
            pipe = redis_client.pipeline()
            pipe.hset(meta_key, mapping=mapping)
            pipe.sadd(f"ua:mem:all:{account_id}", block_id.encode())
            pipe.execute()
            restored += 1
        except Exception as exc:
            logger.error(
                "USER-PLANE-RECONCILE: failed to restore memory block %s into Redis (%s)",
                block_id, exc,
            )

    if restored:
        logger.warning(
            "USER-PLANE-RECONCILE: restored %d memory block(s) into Redis db/3", restored,
        )
    else:
        logger.info(
            "USER-PLANE-RECONCILE: Redis db/3 already in sync for memory blocks "
            "(%d durable row(s))", len(rows),
        )
    return restored


# ---------------------------------------------------------------------------
# Workflow reconcile
# ---------------------------------------------------------------------------

async def _reconcile_workflows(redis_client, durable_store) -> int:
    try:
        rows = await durable_store.list_all_workflows()
    except Exception as exc:
        logger.error(
            "USER-PLANE-RECONCILE: could not read user_workflows from Postgres (%s) — "
            "workflows will NOT auto-restore this boot", exc,
        )
        return 0

    if not rows:
        logger.info("USER-PLANE-RECONCILE: no durable user_workflows rows — nothing to restore")
        return 0

    restored = 0
    # Best-effort db/6 client for scheduler spec re-push
    _wf_r6 = _try_get_db6_redis()

    for row in rows:
        wf_id = row.get("wf_id")
        if not wf_id:
            continue
        meta_key = f"wf:meta:{wf_id}"
        try:
            if redis_client.exists(meta_key):
                continue
            account_id = row.get("account_id", "")
            enabled = row.get("enabled", True)
            spec_val = row.get("spec")
            spec_json: str
            if spec_val is None:
                spec_json = "{}"
            elif isinstance(spec_val, str):
                spec_json = spec_val
            else:
                spec_json = json.dumps(spec_val)
            mapping: dict[bytes, bytes] = {
                b"account_id":        (account_id or "").encode(),
                b"owner_identity_id": (row.get("owner_identity_id") or account_id or "").encode(),
                b"name":              (row.get("name") or "").encode(),
                b"description":       (row.get("description") or "").encode(),
                b"spec":              spec_json.encode(),
                b"spec_hash":         (row.get("spec_hash") or "").encode(),
                b"enabled":           b"1" if enabled else b"0",
                b"created_at":        _ts(row.get("created_at")),
                b"updated_at":        _ts(row.get("updated_at")),
            }
            pipe = redis_client.pipeline()
            pipe.hset(meta_key, mapping=mapping)
            pipe.sadd(f"wf:workflows:{account_id}", wf_id.encode())
            pipe.execute()
            restored += 1

            # Re-push scheduler spec into db/6 if enabled and client available
            if enabled and _wf_r6 is not None:
                _try_push_scheduler_spec(wf_id, row, spec_json, _wf_r6)

        except Exception as exc:
            logger.error(
                "USER-PLANE-RECONCILE: failed to restore workflow %s into Redis (%s)",
                wf_id, exc,
            )

    if restored:
        logger.warning(
            "USER-PLANE-RECONCILE: restored %d workflow(s) into Redis db/3", restored,
        )
    else:
        logger.info(
            "USER-PLANE-RECONCILE: Redis db/3 already in sync for workflows "
            "(%d durable row(s))", len(rows),
        )
    return restored


def _try_get_db6_redis():
    """Try to get a Redis client for db/6 (workflow scheduler namespace).

    Returns None (not raises) if db/6 is unavailable — the reconciler
    skips the scheduler spec push in that case and logs a warning.
    """
    try:
        import redis as _redis
        from yashigani.gateway._redis_url import build_redis_url

        secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
        url = build_redis_url(
            6,
            use_tls=redis_use_tls,
            secrets_dir=secrets_dir,
            client_cert_name="gateway_client",
        )
        r = _redis.from_url(url, decode_responses=False)
        r.ping()
        return r
    except Exception as exc:
        logger.warning(
            "USER-PLANE-RECONCILE: db/6 Redis not available (%s) — "
            "scheduler spec re-push skipped; scheduler will reload on next tick", exc,
        )
        return None


def _try_push_scheduler_spec(wf_id: str, row: dict, spec_json: str, r6) -> None:
    """Push the workflow spec into db/6 for the scheduler, best-effort."""
    try:
        from yashigani.gateway.workflow_scheduler import _redis_set_spec, WorkflowSpec

        # Build a minimal WorkflowSpec from the Postgres row + spec JSON
        try:
            spec_data = json.loads(spec_json) if spec_json else {}
        except json.JSONDecodeError:
            spec_data = {}

        steps = spec_data.get("steps", [])
        schedule = spec_data.get("schedule", {"kind": "none"})

        spec = WorkflowSpec(
            workflow_id=wf_id,
            owner_identity_id=row.get("owner_identity_id") or row.get("account_id") or "",
            enabled=bool(row.get("enabled", True)),
            steps=steps,
            schedule=schedule,
        )
        _redis_set_spec(r6, wf_id, spec)
        logger.debug("USER-PLANE-RECONCILE: pushed scheduler spec for workflow %s", wf_id)
    except Exception as exc:
        logger.warning(
            "USER-PLANE-RECONCILE: scheduler spec push failed for %s (%s) — "
            "scheduler will reload on next tick", wf_id, exc,
        )


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _json_col(val) -> bytes:
    """Serialise an asyncpg JSON column value to bytes for Redis storage.

    asyncpg can return JSON columns as dicts (when decoded) or as strings.
    We normalise to JSON string bytes, or b"{}" / b"[]" if falsy.
    """
    if val is None:
        return b"{}"
    if isinstance(val, (dict, list)):
        return json.dumps(val).encode()
    if isinstance(val, (str, bytes)):
        return val.encode() if isinstance(val, str) else val
    return b"{}"


def _ts(val) -> bytes:
    """Convert a datetime/string timestamp column value to ISO-8601 bytes."""
    if val is None:
        return b""
    if hasattr(val, "isoformat"):
        return val.isoformat().encode()
    return str(val).encode()
