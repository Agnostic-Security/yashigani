"""
Durable Postgres mirror of the agent registry (ISSUE-AGENT-REG-DURABILITY).

# Last updated: 2026-06-10T00:00:00+01:00

Why this exists
---------------
@agent registrations live in Redis db/3, which runs with NO persistence
(`appendonly no`, `save ""`). Any `docker compose up -d redis` recreate wipes
every registration → every @agent returns `agent_not_found` with no operator
signal, and register_agent_bundles() only runs at install so the registry never
self-heals. This is the SAME drift class as the OPA-store-not-re-pushed bug
(commit 2ce1033): a fast in-memory/non-durable store with no startup reconcile
against a durable source.

Fix shape (mirrors the OPA fix)
-------------------------------
  * Durable source of truth: the Postgres ``agent_registry`` table (repurposed
    by migration 0017 to carry the full registration shape).
  * Fast request-time lookup: Redis db/3 — UNCHANGED. The gateway hot path
    (openai_router list_all / AgentRegistry.get) still reads Redis only.
  * Dual-write: AgentRegistry.register/update/deactivate also write through this
    store so Postgres always reflects the live registry.
  * Startup reconcile: on boot, if Redis db/3 is empty/stale but Postgres has
    rows, re-push Postgres → Redis db/3 (see AgentReconciler).

Transport choice
----------------
Writes use a short-lived **sync psycopg2** connection (same pattern as the
bootstrap advisory-lock path in backoffice/app.py). This keeps AgentRegistry's
mutation methods synchronous — they are called from async route handlers but the
registry itself is a sync class with a Lua-script Redis path. Registrations are
rare admin operations, never a hot path, so a per-write connection is fine and
avoids any sync/async event-loop entanglement.

Reads (for the reconciler) use the already-open asyncpg pool.

RLS
---
``agent_registry`` has a tenant_isolation RLS policy keyed on
``current_setting('app.tenant_id')``. Every connection here SETs the platform
tenant before touching the table, exactly like tenant_transaction().
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Platform tenant — agents are platform-scoped (no per-customer tenant split in
# the compose/community deployment). Same constant used by budget/webauthn/jwt.
_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _direct_dsn() -> str:
    """DSN for the durable agent store.

    Prefer YASHIGANI_DB_DSN_DIRECT (bypasses pgbouncer — set in the K8s Helm
    chart) so DDL/RLS SET LOCAL behaves predictably; fall back to
    YASHIGANI_DB_DSN for single-replica compose.
    """
    return os.environ.get("YASHIGANI_DB_DSN_DIRECT") or os.environ.get("YASHIGANI_DB_DSN", "")


class AgentDurableStore:
    """Sync psycopg2-backed durable mirror of the agent registry."""

    def __init__(self, dsn: Optional[str] = None) -> None:
        # Resolve lazily on each write so the env is read at call time (the DSN
        # may not be set when the registry is constructed in some test paths).
        self._dsn = dsn

    def _dsn_or_raise(self) -> str:
        dsn = self._dsn or _direct_dsn()
        if not dsn or "${POSTGRES_PASSWORD}" in dsn:
            raise RuntimeError(
                "AgentDurableStore: no usable Postgres DSN "
                "(YASHIGANI_DB_DSN_DIRECT / YASHIGANI_DB_DSN unset or templated)"
            )
        return dsn

    def _connect(self):
        from yashigani.db.postgres import connect_with_retry_sync

        conn = connect_with_retry_sync(self._dsn_or_raise(), max_attempts=3, backoff_s=2.0)
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('app.tenant_id', %s, false)",
                (_PLATFORM_TENANT_ID,),
            )
        return conn

    # ── Writes (dual-write target) ──────────────────────────────────────────

    def upsert(self, agent: dict, token_hash: Optional[str] = None) -> None:
        """Insert-or-update the durable row for ``agent``.

        ``agent`` is the AgentRegistry hash dict (agent_id, name, upstream_url,
        protocol, status, groups, allowed_caller_groups, allowed_paths,
        allowed_cidrs, kind, sensitivity_ceiling, allowed_tools, and — for
        ``kind == "nhi"`` — template_id, owner_identity_id, allowed_models,
        budget_cap, svid_issued, pids_limit, memory_mb, spiffe_id, scope_hash).
        ``token_hash`` is supplied on initial registration and on token
        rotation; on metadata-only updates it is None and the existing hash
        (if any) is preserved.

        YSG-RISK-155: this is ALWAYS a single INSERT ... ON CONFLICT DO UPDATE.
        The previous shape branched on ``token_hash is None`` into either an
        INSERT (token_hash supplied) or a bare ``UPDATE ... WHERE agent_id=%s``
        (token_hash None) — for a BRAND-NEW row with no existing durable entry,
        the UPDATE-only branch matched zero rows and silently dropped the
        registration. ``register_nhi()`` always calls this with
        ``token_hash=None`` (an NHI's bearer token is a one-time secret, never
        durably persisted — see register_nhi's docstring), so every new NHI
        hit exactly that dead branch. A single upsert statement has no such
        branch: the INSERT always fires for a new agent_id, and
        ``token_hash IS NOT NULL`` in agent_registry's schema is now only
        required for kind='agent' rows (migration 0030) so a NULL token_hash
        on a brand-new NHI INSERT succeeds.

        Fail-loud: durability is the whole point of this store, so any failure
        re-raises after logging — the caller decides whether to surface it.
        """
        agent_id = agent["agent_id"]
        name = agent.get("name", "")
        upstream_url = agent.get("upstream_url", "")
        protocol = agent.get("protocol") or "openai"
        status = agent.get("status") or "active"
        is_active = status == "active"
        groups = json.dumps(agent.get("groups", []))
        allowed_caller_groups = json.dumps(agent.get("allowed_caller_groups", []))
        allowed_paths = json.dumps(agent.get("allowed_paths", []))
        allowed_cidrs = json.dumps(agent.get("allowed_cidrs", []))
        kind = agent.get("kind") or "agent"
        sensitivity_ceiling = agent.get("sensitivity_ceiling") or ""
        allowed_tools = json.dumps(agent.get("allowed_tools") or [])
        template_id = agent.get("template_id") or ""
        owner_identity_id = agent.get("owner_identity_id") or ""
        allowed_models = json.dumps(agent.get("allowed_models") or [])
        budget_cap = json.dumps(agent.get("budget_cap") or {})
        svid_issued = bool(agent.get("svid_issued") or False)
        pids_limit = int(agent.get("pids_limit") or 64)
        memory_mb = int(agent.get("memory_mb") or 512)
        spiffe_id = agent.get("spiffe_id") or ""
        scope_hash = agent.get("scope_hash") or ""

        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO agent_registry
                        (tenant_id, agent_id, agent_name, upstream_url, token_hash,
                         protocol, status, is_active, groups, allowed_caller_groups,
                         allowed_paths, allowed_cidrs, kind, sensitivity_ceiling,
                         allowed_tools, template_id, owner_identity_id, allowed_models,
                         budget_cap, svid_issued, pids_limit, memory_mb, spiffe_id,
                         scope_hash, updated_at)
                    VALUES
                        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                         %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
                        agent_name             = EXCLUDED.agent_name,
                        upstream_url           = EXCLUDED.upstream_url,
                        -- Metadata-only writes pass token_hash=NULL: keep the
                        -- existing hash rather than clobbering it. A real
                        -- rotation/new registration always passes a value.
                        token_hash              = COALESCE(EXCLUDED.token_hash, agent_registry.token_hash),
                        protocol                = EXCLUDED.protocol,
                        status                  = EXCLUDED.status,
                        is_active               = EXCLUDED.is_active,
                        groups                  = EXCLUDED.groups,
                        allowed_caller_groups   = EXCLUDED.allowed_caller_groups,
                        allowed_paths           = EXCLUDED.allowed_paths,
                        allowed_cidrs           = EXCLUDED.allowed_cidrs,
                        kind                    = EXCLUDED.kind,
                        sensitivity_ceiling     = EXCLUDED.sensitivity_ceiling,
                        allowed_tools           = EXCLUDED.allowed_tools,
                        template_id             = EXCLUDED.template_id,
                        owner_identity_id       = EXCLUDED.owner_identity_id,
                        allowed_models          = EXCLUDED.allowed_models,
                        budget_cap              = EXCLUDED.budget_cap,
                        svid_issued             = EXCLUDED.svid_issued,
                        pids_limit              = EXCLUDED.pids_limit,
                        memory_mb               = EXCLUDED.memory_mb,
                        spiffe_id               = EXCLUDED.spiffe_id,
                        scope_hash              = EXCLUDED.scope_hash,
                        updated_at              = now()
                    """,
                    (
                        _PLATFORM_TENANT_ID, agent_id, name, upstream_url, token_hash,
                        protocol, status, is_active, groups, allowed_caller_groups,
                        allowed_paths, allowed_cidrs, kind, sensitivity_ceiling,
                        allowed_tools, template_id, owner_identity_id, allowed_models,
                        budget_cap, svid_issued, pids_limit, memory_mb, spiffe_id,
                        scope_hash,
                    ),
                )
            conn.commit()
            logger.info(
                "AgentDurableStore: upserted %s (%s, kind=%s) into Postgres",
                agent_id, name, kind,
            )
        except Exception:
            conn.rollback()
            logger.exception("AgentDurableStore: upsert FAILED for %s", agent_id)
            raise
        finally:
            conn.close()

    def set_status(self, agent_id: str, status: str) -> None:
        """Mirror a status change (e.g. deactivate) into the durable store."""
        is_active = status == "active"
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE agent_registry
                    SET status = %s, is_active = %s, updated_at = now()
                    WHERE tenant_id = %s AND agent_id = %s
                    """,
                    (status, is_active, _PLATFORM_TENANT_ID, agent_id),
                )
            conn.commit()
            logger.info("AgentDurableStore: set status=%s for %s", status, agent_id)
        except Exception:
            conn.rollback()
            logger.exception("AgentDurableStore: set_status FAILED for %s", agent_id)
            raise
        finally:
            conn.close()

    # ── Reads (reconciler) ──────────────────────────────────────────────────

    async def list_all(self) -> list[dict]:
        """Return every durable agent row as an AgentRegistry-shaped dict.

        Async — uses the open asyncpg pool. Used by the startup reconciler to
        re-push Postgres → Redis db/3. ``token_hash`` is included so the
        reconciler can restore the bcrypt hash directly into Redis without a
        token rotation (existing tokens keep working) — it is legitimately
        NULL for ``kind == "nhi"`` rows (migration 0030); the reconciler
        handles that case separately (an NHI's bearer token is a one-time
        secret, never durably persisted).

        YSG-RISK-155: also SELECTs ``kind`` and the NHI-specific columns
        (template_id, owner_identity_id, allowed_models, budget_cap,
        svid_issued, pids_limit, memory_mb, spiffe_id, scope_hash) plus the
        generic 4.0 Phase 5 additive columns (sensitivity_ceiling,
        allowed_tools). Previously these were not selected at all, so
        ``AgentRegistry.restore_from_durable()``'s ``if kind == "nhi":``
        branch always saw ``kind == "agent"`` (the dataclass default) and
        never fired — an NHI restored after a Redis wipe came back as a plain
        agent with none of its NHI fields.
        """
        from yashigani.db import tenant_transaction

        rows: list[dict] = []
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            records = await conn.fetch(
                """
                SELECT agent_id, agent_name, upstream_url, token_hash, protocol,
                       status, groups, allowed_caller_groups, allowed_paths,
                       allowed_cidrs, created_at, last_seen_at, kind,
                       sensitivity_ceiling, allowed_tools, template_id,
                       owner_identity_id, allowed_models, budget_cap,
                       svid_issued, pids_limit, memory_mb, spiffe_id, scope_hash
                FROM agent_registry
                WHERE agent_id IS NOT NULL
                ORDER BY agent_id
                """
            )
        for r in records:
            rows.append(
                {
                    "agent_id": r["agent_id"],
                    "name": r["agent_name"],
                    "upstream_url": r["upstream_url"],
                    "token_hash": r["token_hash"],
                    "protocol": r["protocol"] or "openai",
                    "status": r["status"] or "active",
                    "groups": _as_list(r["groups"]),
                    "allowed_caller_groups": _as_list(r["allowed_caller_groups"]),
                    "allowed_paths": _as_list(r["allowed_paths"]),
                    "allowed_cidrs": _as_list(r["allowed_cidrs"]),
                    "created_at": r["created_at"].isoformat() if r["created_at"] else "",
                    "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else "",
                    "kind": r["kind"] or "agent",
                    "sensitivity_ceiling": r["sensitivity_ceiling"] or "",
                    "allowed_tools": _as_list(r["allowed_tools"]),
                    "template_id": r["template_id"] or "",
                    "owner_identity_id": r["owner_identity_id"] or "",
                    "allowed_models": _as_list(r["allowed_models"]),
                    "budget_cap": _as_dict(r["budget_cap"]),
                    "svid_issued": bool(r["svid_issued"]),
                    "pids_limit": r["pids_limit"] if r["pids_limit"] is not None else 64,
                    "memory_mb": r["memory_mb"] if r["memory_mb"] is not None else 512,
                    "spiffe_id": r["spiffe_id"] or "",
                    "scope_hash": r["scope_hash"] or "",
                }
            )
        return rows


def _as_list(val) -> list:
    """asyncpg returns JSON columns as str (or already-decoded); normalise to list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, (str, bytes)):
        try:
            decoded = json.loads(val)
            return decoded if isinstance(decoded, list) else []
        except Exception:
            return []
    return []


def _as_dict(val) -> dict:
    """asyncpg returns JSON columns as str (or already-decoded); normalise to dict."""
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, (str, bytes)):
        try:
            decoded = json.loads(val)
            return decoded if isinstance(decoded, dict) else {}
        except Exception:
            return {}
    return {}
