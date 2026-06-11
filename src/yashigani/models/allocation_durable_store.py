"""
Durable Postgres mirror of the model-allocation store (Track B1).

Why this exists
---------------
Model allocations live in Redis db/3, which runs with NO persistence
(`appendonly no`, `save ""`). A `docker compose up -d redis` recreate OR a redis
restart WIPES every allocation → model RBAC silently stops enforcing until the
next admin mutation. This is the SAME drift class as the agent-registry
durability bug (migration 0017) and the OPA-store re-push bug (commit 2ce1033).

Fix shape (mirrors AgentDurableStore)
-------------------------------------
  * Durable source of truth: the Postgres ``model_allocations`` table (migration
    0019).
  * Fast request-time lookup: Redis db/3 — UNCHANGED. The gateway hot path
    (resolve_effective_allowed_models) still reads Redis only.
  * Dual-write: ModelAllocationStore.add/delete also write through this store.
  * Startup reconcile: on boot, if Redis db/3 is empty but Postgres has rows,
    re-push Postgres → Redis db/3 (reconcile_allocations_from_durable).

Transport: short-lived sync psycopg2 connections (same pattern as
AgentDurableStore) — allocations are rare admin operations, never a hot path.
RLS: ``model_allocations`` is FORCE RLS on ``app.tenant_id`` — every connection
SETs the platform tenant before touching the table.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _direct_dsn() -> str:
    """Prefer the direct (non-pgbouncer) DSN for predictable RLS SET LOCAL."""
    return os.environ.get("YASHIGANI_DB_DSN_DIRECT") or os.environ.get("YASHIGANI_DB_DSN", "")


class AllocationDurableStore:
    """Sync psycopg2-backed durable mirror of the model-allocation store."""

    def __init__(self, dsn: Optional[str] = None) -> None:
        self._dsn = dsn

    def _dsn_or_raise(self) -> str:
        dsn = self._dsn or _direct_dsn()
        if not dsn or "${POSTGRES_PASSWORD}" in dsn:
            raise RuntimeError(
                "AllocationDurableStore: no usable Postgres DSN "
                "(YASHIGANI_DB_DSN_DIRECT / YASHIGANI_DB_DSN unset or templated)"
            )
        return dsn

    def _connect(self):
        from yashigani.db.postgres import connect_with_retry_sync

        conn = connect_with_retry_sync(self._dsn_or_raise(), max_attempts=3, backoff_s=2.0)
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, false)", (_PLATFORM_TENANT_ID,))
        return conn

    # ── Writes (dual-write target) ──────────────────────────────────────────

    def upsert(self, alloc_id: str, model_alias: str, target_type: str, target_id: str) -> None:
        """Insert-or-update the durable row for one allocation.

        Fail-loud: durability is the whole point — any failure re-raises after
        logging so the caller decides whether to surface it.
        """
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO model_allocations
                        (tenant_id, alloc_id, model_alias, target_type, target_id, updated_at)
                    VALUES (%s, %s, %s, %s, %s, now())
                    ON CONFLICT (tenant_id, alloc_id) DO UPDATE SET
                        model_alias = EXCLUDED.model_alias,
                        target_type = EXCLUDED.target_type,
                        target_id   = EXCLUDED.target_id,
                        updated_at  = now()
                    """,
                    (_PLATFORM_TENANT_ID, alloc_id, model_alias, target_type, target_id),
                )
            conn.commit()
            logger.info("AllocationDurableStore: upserted allocation %s into Postgres", alloc_id)
        except Exception:
            conn.rollback()
            logger.exception("AllocationDurableStore: upsert FAILED for %s", alloc_id)
            raise
        finally:
            conn.close()

    def delete(self, alloc_id: str) -> None:
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM model_allocations WHERE tenant_id = %s AND alloc_id = %s",
                    (_PLATFORM_TENANT_ID, alloc_id),
                )
            conn.commit()
            logger.info("AllocationDurableStore: deleted allocation %s from Postgres", alloc_id)
        except Exception:
            conn.rollback()
            logger.exception("AllocationDurableStore: delete FAILED for %s", alloc_id)
            raise
        finally:
            conn.close()

    # ── Reconcile read (durable -> Redis) ───────────────────────────────────

    def list_all(self) -> list[dict]:
        """Return every durable allocation row (for the startup reconciler)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT alloc_id, model_alias, target_type, target_id "
                    "FROM model_allocations WHERE tenant_id = %s",
                    (_PLATFORM_TENANT_ID,),
                )
                rows = cur.fetchall()
            return [
                {"id": r[0], "model_alias": r[1], "target_type": r[2], "target_id": r[3]}
                for r in rows
            ]
        finally:
            conn.close()


def reconcile_allocations_from_durable(alloc_store, durable: AllocationDurableStore) -> int:
    """Re-push Postgres allocations into Redis db/3 if the Redis set is missing rows.

    Idempotent: existing Redis allocations (matched by the scope+alias tuple) are
    left as-is; only durable rows absent from Redis are restored. Returns the
    number of allocations restored.

    Mirrors reconcile_agents_from_durable: a redis recreate/restart wipes Redis
    db/3, so this re-hydrates the allocation set on every boot. Best-effort —
    a Postgres blip logs and returns 0 rather than blocking startup.
    """
    if alloc_store is None or durable is None:
        return 0
    try:
        durable_rows = durable.list_all()
    except Exception as exc:
        logger.warning("ALLOC-RECONCILE: durable list failed (%s) — skipping", exc)
        return 0

    # Existing Redis allocations by (alias, type, id).
    existing = {
        (a.model_alias, a.target_type, a.target_id)
        for a in alloc_store.list_all()
    }
    restored = 0
    for row in durable_rows:
        key = (row["model_alias"], row["target_type"], row["target_id"])
        if key in existing:
            continue
        try:
            # restore() keeps the ORIGINAL alloc_id and does NOT dual-write back
            # to Postgres — avoids minting a duplicate durable row (which would
            # collide on the (alias,type,id) UNIQUE constraint).
            alloc_store.restore(
                row["id"], row["model_alias"], row["target_type"], row["target_id"]
            )
            restored += 1
        except Exception as exc:
            logger.warning(
                "ALLOC-RECONCILE: failed to restore %s -> %s:%s (%s)",
                row["model_alias"], row["target_type"], row["target_id"], exc,
            )
    if restored:
        logger.info("ALLOC-RECONCILE: restored %d allocation(s) from Postgres → Redis db/3", restored)
    return restored
