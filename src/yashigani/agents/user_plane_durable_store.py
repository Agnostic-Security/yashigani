"""
Durable Postgres mirror for user-plane stores (ISSUE-USER-PLANE-DURABILITY).

# Last updated: 2026-06-27T00:00:00+00:00

Why this exists
---------------
ua:* and wf:* keys in Redis db/3 run with NO persistence (appendonly no /
save ""). A Redis db/3 wipe (container recreate, volume deletion) loses all
user agents, memory blocks, memory-block attachment records, and workflow
definitions with zero operator signal.

This module extends the existing AgentRegistry durable-mirror pattern
(agents/durable_store.py) to the user-plane stores.

Tables mirrored
---------------
  user_agents            — full ua:meta hash fields
  user_memory_blocks     — full ua:mem:meta hash fields
  user_agent_memory_links — ua:mem:agent:{ua_id} attachment set
  user_workflows         — full wf:meta hash fields

Transport choice (mirrors durable_store.py)
-------------------------------------------
Writes use a short-lived **sync psycopg2** connection. This keeps route
mutation handlers (which are async FastAPI handlers) able to call the store
synchronously — the writes are rare user-initiated operations, never a hot
path, so a per-write connection is acceptable and avoids event-loop
entanglement.

Reads (for the startup reconciler) use the already-open asyncpg pool via
tenant_transaction. The user-plane tables have NO RLS; we use
tenant_transaction with the platform tenant_id for consistency (the session
variable the tables don't use is a no-op but keeps the call-pattern identical
to AgentDurableStore.list_all()).

BOLA columns present: account_id on all four tables. Application-layer BOLA
is enforced by the routes; this store does not add a second layer — it mirrors
what Redis already holds.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Platform tenant — same constant used by AgentDurableStore and budget/webauthn/jwt.
_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _direct_dsn() -> str:
    """DSN for the durable user-plane store.

    Prefer YASHIGANI_DB_DSN_DIRECT (bypasses pgbouncer) so DDL/config behaves
    predictably; fall back to YASHIGANI_DB_DSN for single-replica compose.
    """
    return os.environ.get("YASHIGANI_DB_DSN_DIRECT") or os.environ.get("YASHIGANI_DB_DSN", "")


class UserPlaneDurableStore:
    """Sync psycopg2-backed durable mirror of the user-plane Redis stores."""

    def __init__(self, dsn: Optional[str] = None) -> None:
        # Resolved lazily so the env is read at call time (DSN may not be set
        # when the store is constructed during some test paths).
        self._dsn = dsn

    def _dsn_or_raise(self) -> str:
        dsn = self._dsn or _direct_dsn()
        if not dsn or "${POSTGRES_PASSWORD}" in dsn:
            raise RuntimeError(
                "UserPlaneDurableStore: no usable Postgres DSN "
                "(YASHIGANI_DB_DSN_DIRECT / YASHIGANI_DB_DSN unset or templated)"
            )
        return dsn

    def _connect(self):
        """Open a short-lived sync psycopg2 connection (autocommit=False)."""
        from yashigani.db.postgres import connect_with_retry_sync

        conn = connect_with_retry_sync(self._dsn_or_raise(), max_attempts=3, backoff_s=2.0)
        conn.autocommit = False
        return conn

    # ── Writes (dual-write targets) ─────────────────────────────────────────

    def upsert_agent(self, agent: dict) -> None:
        """Insert-or-update the durable row for a user agent.

        ``agent`` must contain at least ``account_id`` and ``ua_id``.
        All other fields are optional and default to empty/null.

        Best-effort callers wrap this in try/except; this method re-raises on
        failure (the caller decides how loud to be).
        """
        ua_id = agent["ua_id"]
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_agents
                        (account_id, ua_id, name, description, alias, kind,
                         personality, effective_skills, declared_skills,
                         graph, graph_hash, letta_agent_id, nhi_id, updated_at)
                    VALUES
                        (%s, %s, %s, %s, %s, %s,
                         %s::jsonb, %s::jsonb, %s::jsonb,
                         %s, %s, %s, %s, now())
                    ON CONFLICT (ua_id) DO UPDATE SET
                        account_id       = EXCLUDED.account_id,
                        name             = EXCLUDED.name,
                        description      = EXCLUDED.description,
                        alias            = EXCLUDED.alias,
                        kind             = EXCLUDED.kind,
                        personality      = EXCLUDED.personality,
                        effective_skills = EXCLUDED.effective_skills,
                        declared_skills  = EXCLUDED.declared_skills,
                        graph            = EXCLUDED.graph,
                        graph_hash       = EXCLUDED.graph_hash,
                        letta_agent_id   = EXCLUDED.letta_agent_id,
                        nhi_id           = EXCLUDED.nhi_id,
                        updated_at       = now()
                    """,
                    (
                        agent.get("account_id", ""),
                        ua_id,
                        agent.get("name", ""),
                        agent.get("description", ""),
                        agent.get("alias", ""),
                        agent.get("kind", "agent"),
                        _dumps_or_null(agent.get("personality")),
                        _dumps_or_null(agent.get("effective_skills")),
                        _dumps_or_null(agent.get("declared_skills")),
                        agent.get("graph") or None,
                        agent.get("graph_hash") or None,
                        agent.get("letta_agent_id") or None,
                        agent.get("nhi_id") or None,
                    ),
                )
            conn.commit()
            logger.debug("UserPlaneDurableStore: upserted agent %s", ua_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: upsert_agent FAILED for %s", ua_id)
            raise
        finally:
            conn.close()

    def delete_agent(self, ua_id: str) -> None:
        """Delete the durable row for a user agent (CASCADE removes links)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_agents WHERE ua_id = %s", (ua_id,))
            conn.commit()
            logger.debug("UserPlaneDurableStore: deleted agent %s", ua_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: delete_agent FAILED for %s", ua_id)
            raise
        finally:
            conn.close()

    def upsert_memory(self, block: dict) -> None:
        """Insert-or-update the durable row for a user memory block.

        ``block`` must contain at least ``account_id`` and ``block_id``.
        """
        block_id = block["block_id"]
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_memory_blocks
                        (account_id, block_id, label, value, letta_block_id, updated_at)
                    VALUES
                        (%s, %s, %s, %s, %s, now())
                    ON CONFLICT (block_id) DO UPDATE SET
                        account_id     = EXCLUDED.account_id,
                        label          = EXCLUDED.label,
                        value          = EXCLUDED.value,
                        letta_block_id = EXCLUDED.letta_block_id,
                        updated_at     = now()
                    """,
                    (
                        block.get("account_id", ""),
                        block_id,
                        block.get("label", ""),
                        block.get("value", ""),
                        block.get("letta_block_id") or None,
                    ),
                )
            conn.commit()
            logger.debug("UserPlaneDurableStore: upserted memory block %s", block_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: upsert_memory FAILED for %s", block_id)
            raise
        finally:
            conn.close()

    def delete_memory(self, block_id: str) -> None:
        """Delete the durable row for a memory block (CASCADE removes links)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_memory_blocks WHERE block_id = %s", (block_id,))
            conn.commit()
            logger.debug("UserPlaneDurableStore: deleted memory block %s", block_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: delete_memory FAILED for %s", block_id)
            raise
        finally:
            conn.close()

    def set_memory_link(self, ua_id: str, block_id: str, attached: bool) -> None:
        """Add or remove a memory-block attachment link.

        ``attached=True``  → INSERT ON CONFLICT DO NOTHING (idempotent attach).
        ``attached=False`` → DELETE (idempotent detach).
        """
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                if attached:
                    cur.execute(
                        """
                        INSERT INTO user_agent_memory_links (ua_id, block_id)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (ua_id, block_id),
                    )
                else:
                    cur.execute(
                        "DELETE FROM user_agent_memory_links WHERE ua_id = %s AND block_id = %s",
                        (ua_id, block_id),
                    )
            conn.commit()
            logger.debug(
                "UserPlaneDurableStore: memory link ua=%s block=%s attached=%s",
                ua_id, block_id, attached,
            )
        except Exception:
            conn.rollback()
            logger.exception(
                "UserPlaneDurableStore: set_memory_link FAILED ua=%s block=%s attached=%s",
                ua_id, block_id, attached,
            )
            raise
        finally:
            conn.close()

    def upsert_workflow(self, wf: dict) -> None:
        """Insert-or-update the durable row for a user workflow.

        ``wf`` must contain at least ``account_id`` and ``wf_id``.
        """
        wf_id = wf["wf_id"]
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_workflows
                        (account_id, wf_id, owner_identity_id, name, description,
                         spec, spec_hash, enabled, updated_at)
                    VALUES
                        (%s, %s, %s, %s, %s,
                         %s::jsonb, %s, %s, now())
                    ON CONFLICT (wf_id) DO UPDATE SET
                        account_id        = EXCLUDED.account_id,
                        owner_identity_id = EXCLUDED.owner_identity_id,
                        name              = EXCLUDED.name,
                        description       = EXCLUDED.description,
                        spec              = EXCLUDED.spec,
                        spec_hash         = EXCLUDED.spec_hash,
                        enabled           = EXCLUDED.enabled,
                        updated_at        = now()
                    """,
                    (
                        wf.get("account_id", ""),
                        wf_id,
                        wf.get("owner_identity_id", ""),
                        wf.get("name", ""),
                        wf.get("description", ""),
                        _dumps_or_null(wf.get("spec")),
                        wf.get("spec_hash") or None,
                        bool(wf.get("enabled", True)),
                    ),
                )
            conn.commit()
            logger.debug("UserPlaneDurableStore: upserted workflow %s", wf_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: upsert_workflow FAILED for %s", wf_id)
            raise
        finally:
            conn.close()

    def delete_workflow(self, wf_id: str) -> None:
        """Delete the durable row for a workflow."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM user_workflows WHERE wf_id = %s", (wf_id,))
            conn.commit()
            logger.debug("UserPlaneDurableStore: deleted workflow %s", wf_id)
        except Exception:
            conn.rollback()
            logger.exception("UserPlaneDurableStore: delete_workflow FAILED for %s", wf_id)
            raise
        finally:
            conn.close()

    # ── Reads (reconciler) ──────────────────────────────────────────────────

    async def list_all_agents(self, account_id: Optional[str] = None) -> list[dict]:
        """Return all durable user-agent rows.

        Async — uses the open asyncpg pool via tenant_transaction.
        If ``account_id`` is given, filters to that account only.
        """
        from yashigani.db import tenant_transaction

        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            if account_id:
                records = await conn.fetch(
                    "SELECT * FROM user_agents WHERE account_id = $1 ORDER BY ua_id",
                    account_id,
                )
            else:
                records = await conn.fetch("SELECT * FROM user_agents ORDER BY ua_id")
        return [dict(r) for r in records]

    async def list_all_memories(self, account_id: Optional[str] = None) -> list[dict]:
        """Return all durable user-memory-block rows.

        Async — uses the open asyncpg pool via tenant_transaction.
        If ``account_id`` is given, filters to that account only.
        """
        from yashigani.db import tenant_transaction

        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            if account_id:
                records = await conn.fetch(
                    "SELECT * FROM user_memory_blocks WHERE account_id = $1 ORDER BY block_id",
                    account_id,
                )
            else:
                records = await conn.fetch("SELECT * FROM user_memory_blocks ORDER BY block_id")
        return [dict(r) for r in records]

    async def list_memory_links(self, ua_id: str) -> list[str]:
        """Return block_ids attached to the given ua_id in the durable store."""
        from yashigani.db import tenant_transaction

        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            records = await conn.fetch(
                "SELECT block_id FROM user_agent_memory_links WHERE ua_id = $1",
                ua_id,
            )
        return [r["block_id"] for r in records]

    async def list_all_workflows(self, account_id: Optional[str] = None) -> list[dict]:
        """Return all durable user-workflow rows.

        Async — uses the open asyncpg pool via tenant_transaction.
        If ``account_id`` is given, filters to that account only.
        """
        from yashigani.db import tenant_transaction

        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            if account_id:
                records = await conn.fetch(
                    "SELECT * FROM user_workflows WHERE account_id = $1 ORDER BY wf_id",
                    account_id,
                )
            else:
                records = await conn.fetch("SELECT * FROM user_workflows ORDER BY wf_id")
        return [dict(r) for r in records]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _dumps_or_null(val) -> Optional[str]:
    """Serialise a value to JSON string, or return None if value is falsy/None."""
    if val is None:
        return None
    if isinstance(val, str):
        # Already serialised (e.g. a Redis string field)
        return val if val.strip() else None
    try:
        return json.dumps(val)
    except Exception:
        return None
