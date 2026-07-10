"""
Integration tests — v2.25.2 Lu wire-sink-gate PART B: least-privilege runtime
DB role (yashigani_app demoted to NOSUPERUSER + non-owner; FORCE RLS on audit
tables; UPDATE/DELETE on audit tables revoked).

Tiago decision 2026-06-04 (combined B+C "irrevocable audit" remediation).

Requires a live Postgres with migrations applied (alembic head, incl. 0015) and
TWO credentials:
  - YASHIGANI_DB_DSN        -> connects as the demoted runtime role yashigani_app
  - YASHIGANI_DB_DSN_ADMIN  -> connects as the admin superuser yashigani_admin

Proves (PART B):
  (B-a) all app DB operations SUCCEED under the demoted yashigani_app role
        (functional test over operational tables — no privilege errors).
  (B-b) UPDATE / DELETE on audit_events as yashigani_app are DENIED, and
        FORCE ROW LEVEL SECURITY is confirmed ON for the audit tables; the
        runtime role is NOT a superuser and does NOT own the audit tables.
  (B-c) migrations are applied (alembic_version present; the audit grant matrix
        + CHECK constraint from 0015 exist) — i.e. the admin successfully ran DDL.

Skipped when the DSNs are not set (CI without a live DB).

Run manually:
    YASHIGANI_DB_DSN=postgresql://yashigani_app:PW@localhost:5432/yashigani \\
    YASHIGANI_DB_DSN_ADMIN=postgresql://yashigani_admin:PW@localhost:5432/yashigani \\
    pytest src/tests/integration/test_least_priv_runtime_role.py -v

Last updated: 2026-06-04T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest

pytestmark = pytest.mark.integration

_APP_DSN = os.getenv("YASHIGANI_DB_DSN", "")
_ADMIN_DSN = os.getenv("YASHIGANI_DB_DSN_ADMIN", "")
_TENANT_ID = "00000000-0000-0000-0000-000000000000"

_NEEDS_DB = pytest.mark.skipif(
    not _APP_DSN or "${POSTGRES_PASSWORD}" in _APP_DSN,
    reason="YASHIGANI_DB_DSN not set — skipping least-priv runtime-role integration tests",
)

_AUDIT_TABLES = ("audit_events", "inference_events", "audit_chain_checkpoints")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _connect(dsn):
    import asyncpg
    return await asyncpg.connect(dsn)


# ---------------------------------------------------------------------------
# (B-a) all app DB operations SUCCEED under the demoted yashigani_app role
# ---------------------------------------------------------------------------

@_NEEDS_DB
def test_app_role_operational_dml_succeeds():
    async def _t():
        conn = await _connect(_APP_DSN)
        try:
            # RLS reads app.tenant_id via current_setting; set_config(..., true) is
            # transaction-scoped, so run the writes inside one transaction.
            async with conn.transaction():
                await conn.execute("SELECT set_config('app.tenant_id', $1, true)", _TENANT_ID)
                # INSERT into an operational table the runtime writes
                # (anomaly_thresholds upsert path) — full DML must work for the
                # demoted role.
                await conn.execute(
                    """
                    INSERT INTO anomaly_thresholds
                        (tenant_id, window_seconds, call_count_n, payload_threshold_bytes)
                    VALUES ($1, 60, 10, 256)
                    ON CONFLICT (tenant_id) DO UPDATE
                      SET window_seconds = EXCLUDED.window_seconds, updated_at = now()
                    """,
                    uuid.UUID(_TENANT_ID),
                )
                row = await conn.fetchrow(
                    "SELECT window_seconds FROM anomaly_thresholds WHERE tenant_id = $1",
                    uuid.UUID(_TENANT_ID),
                )
                assert row is not None and row["window_seconds"] == 60
                # UPDATE on an operational table must succeed (not an audit table).
                await conn.execute(
                    "UPDATE anomaly_thresholds SET call_count_n = 11 WHERE tenant_id = $1",
                    uuid.UUID(_TENANT_ID),
                )
                # INSERT into an audit table must SUCCEED (SELECT+INSERT granted)
                # — with chain hashes populated (CHECK constraint requires them).
                await conn.execute(
                    """
                    INSERT INTO audit_events
                        (tenant_id, event_type, action, prev_hash, event_hash)
                    VALUES ($1, 'TEST', 'PROXY', 'p'||repeat('0',95), 'e'||repeat('0',95))
                    """,
                    uuid.UUID(_TENANT_ID),
                )
        finally:
            await conn.close()

    _run(_t())


# ---------------------------------------------------------------------------
# (B-b) UPDATE / DELETE on audit_events DENIED + FORCE RLS confirmed + not super
# ---------------------------------------------------------------------------

@_NEEDS_DB
def test_app_role_cannot_update_or_delete_audit_events():
    import asyncpg

    async def _t():
        conn = await _connect(_APP_DSN)
        try:
            # Privilege denial (ACL) is evaluated before RLS, so no tenant context
            # is needed — UPDATE/DELETE are simply not granted to yashigani_app.
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "UPDATE audit_events SET action = 'TAMPER' WHERE tenant_id = $1",
                    uuid.UUID(_TENANT_ID),
                )
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "DELETE FROM audit_events WHERE tenant_id = $1",
                    uuid.UUID(_TENANT_ID),
                )
        finally:
            await conn.close()

    _run(_t())


@_NEEDS_DB
def test_app_role_is_not_superuser_and_not_audit_owner():
    async def _t():
        conn = await _connect(_APP_DSN)
        try:
            # Demoted role: NOT a superuser.
            is_super = await conn.fetchval(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
            )
            assert is_super is False, "yashigani_app must NOT be a superuser"
            assert (await conn.fetchval("SELECT current_user")) == "yashigani_app"

            # Demoted role does NOT own the audit tables (owner bypasses ACL/RLS).
            for tbl in _AUDIT_TABLES:
                owner = await conn.fetchval(
                    """
                    SELECT t.tableowner FROM pg_tables t
                    WHERE t.schemaname = 'public' AND t.tablename = $1
                    """,
                    tbl,
                )
                assert owner != "yashigani_app", f"{tbl} must NOT be owned by yashigani_app (got {owner})"
        finally:
            await conn.close()

    _run(_t())


@_NEEDS_DB
def test_force_rls_on_audit_tables():
    """relforcerowsecurity must be TRUE for the audit tables so even the owner
    is subject to RLS (FORCE ROW LEVEL SECURITY — migration 0015)."""
    async def _t():
        conn = await _connect(_ADMIN_DSN or _APP_DSN)
        try:
            for tbl in _AUDIT_TABLES:
                forced = await conn.fetchval(
                    "SELECT relforcerowsecurity FROM pg_class WHERE relname = $1",
                    tbl,
                )
                assert forced is True, f"FORCE RLS not set on {tbl}"
                rls = await conn.fetchval(
                    "SELECT relrowsecurity FROM pg_class WHERE relname = $1",
                    tbl,
                )
                assert rls is True, f"RLS not enabled on {tbl}"
        finally:
            await conn.close()

    _run(_t())


# ---------------------------------------------------------------------------
# (B-c) migrations applied as admin — 0015 artefacts present
# ---------------------------------------------------------------------------

@_NEEDS_DB
def test_migration_0015_artefacts_present():
    async def _t():
        conn = await _connect(_ADMIN_DSN or _APP_DSN)
        try:
            # alembic_version exists (migrations ran).
            ver = await conn.fetchval(
                "SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1"
            )
            assert ver is not None, "alembic_version not populated — migrations did not run"

            # The CHECK constraint from 0015 (irrevocable chain) exists.
            cons = await conn.fetchval(
                """
                SELECT conname FROM pg_constraint
                WHERE conname = 'audit_events_chain_not_null'
                """
            )
            assert cons == "audit_events_chain_not_null", \
                "0015 CHECK constraint audit_events_chain_not_null missing"
        finally:
            await conn.close()

    _run(_t())


@_NEEDS_DB
def test_unchained_insert_rejected_at_db_when_enforced():
    """The 0015 CHECK is NOT VALID (skips historical rows) but enforces NEW
    inserts: an INSERT with NULL prev_hash/event_hash must be rejected at the DB
    once the constraint is validated.  We test the enforced-for-new-rows
    behaviour: a NULL-hash INSERT raises a check_violation.

    NOTE: a NOT VALID constraint IS enforced for new INSERT/UPDATE; it only
    skips validation of pre-existing rows.  So a fresh NULL-hash insert is
    rejected even though the constraint is NOT VALID."""
    import asyncpg

    async def _t():
        conn = await _connect(_APP_DSN)
        try:
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", _TENANT_ID)
                    await conn.execute(
                        """
                        INSERT INTO audit_events (tenant_id, event_type, action,
                                                  prev_hash, event_hash)
                        VALUES ($1, 'TEST', 'PROXY', NULL, NULL)
                        """,
                        uuid.UUID(_TENANT_ID),
                    )
        finally:
            await conn.close()

    _run(_t())
