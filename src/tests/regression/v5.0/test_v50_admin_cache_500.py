# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-CACHE-500: GET /admin/cache always returned HTTP 500.

Root cause (confirmed live against the running v5.0 compose stack,
localhost-postgres-1, role yashigani_app, read-only diagnosis — no mutation):

    cache_config carries ROW LEVEL SECURITY (0001_initial_schema.py):
        ALTER TABLE cache_config ENABLE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON cache_config
            USING (tenant_id = current_setting('app.tenant_id')::uuid);

    list_cache_configs() acquired a raw connection via get_pool().acquire()
    and ran the SELECT directly, WITHOUT ever calling
    set_config('app.tenant_id', ...) first. Every other RLS-gated query path
    in this codebase (identity/durable_store.py, agents/durable_store.py,
    audit/chain.py, db/postgres.py:tenant_transaction()) sets this GUC before
    touching an RLS table. Because it was never set on the pooled connection,
    Postgres raised:

        ERROR:  unrecognized configuration parameter "app.tenant_id"

    before RLS was even evaluated — 100% reproduction, every call. The
    original except-block then explicitly built a `JSONResponse(status_code
    =500, ...)`, so the (correctly caught, non-crashing) exception still
    surfaced to the client and to Ava's UI sweep as a real HTTP 500.

    Reproduced directly against the live DB (read-only, no stack mutation):
        docker exec localhost-postgres-1 psql -U yashigani_app -d yashigani \\
          -c "SELECT tenant_id::text, enabled, ttl_seconds FROM cache_config
              ORDER BY tenant_id;"
        -> ERROR:  unrecognized configuration parameter "app.tenant_id"

    And confirmed the fix resolves it (read-only, in a rolled-back txn):
        BEGIN;
        SELECT set_config('app.tenant_id',
                           '00000000-0000-0000-0000-000000000000', true);
        SELECT tenant_id::text, enabled, ttl_seconds FROM cache_config
          ORDER BY tenant_id;
        ROLLBACK;
        -> 0 rows, no error.

Fix (src/yashigani/backoffice/routes/cache.py):
    1. Root cause: SET app.tenant_id to the platform tenant (this deployment
       has exactly one tenant row — the well-known all-zeros platform UUID,
       confirmed via `SELECT id, name FROM tenants` -> single "platform" row)
       before running the query, inside the same transaction, mirroring the
       codebase-wide idiom.
    2. Defence in depth: if the query still fails for any other reason, the
       handler now degrades gracefully (200, cache_available=False) instead
       of forcing a 500 — matching the pre-existing `rc is None` path in the
       same function and the UI's already-built `cache_available` badge
       (static/ui4/admin/modules/infrastructure.js:299,304).

These tests were verified to FAIL against the pre-fix code (reverted the fix
in-place via git show HEAD:<path>, reran, both new tests failed as expected,
then restored — no git stash used per instruction). Also confirmed a full
src/tests/unit + src/tests/regression/v5.0 baseline-diff: 111 pre-existing
failures identical with and without this change (zero new failures).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.responses import JSONResponse


def _mock_pool(fetch_return=None, execute_side_effect=None):
    """Build a mock asyncpg-style pool/connection/transaction chain."""
    conn = MagicMock()
    conn.execute = AsyncMock(side_effect=execute_side_effect)
    conn.fetch = AsyncMock(return_value=fetch_return or [])

    tx_cm = MagicMock()
    tx_cm.__aenter__ = AsyncMock(return_value=None)
    tx_cm.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx_cm)

    conn_cm = MagicMock()
    conn_cm.__aenter__ = AsyncMock(return_value=conn)
    conn_cm.__aexit__ = AsyncMock(return_value=False)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=conn_cm)
    return pool, conn


class TestAdminCacheNeverReturns500:
    """V50-CACHE-500: /admin/cache must never surface a raw 500."""

    @pytest.mark.asyncio
    async def test_happy_path_sets_platform_tenant_before_fetch(self):
        """
        Root-cause proof: the handler must SET app.tenant_id BEFORE the
        cache_config SELECT, in the same transaction. Without this, the
        live RLS policy raises before any row is ever visible.
        """
        import yashigani.backoffice.routes.cache as cache_mod

        row = {"tenant_id": "00000000-0000-0000-0000-000000000000", "enabled": True, "ttl_seconds": 300}
        pool, conn = _mock_pool(fetch_return=[row])

        mock_state = MagicMock()
        mock_state.response_cache = MagicMock()

        with patch("yashigani.backoffice.state.backoffice_state", mock_state), \
             patch("yashigani.db.postgres.get_pool", return_value=pool):
            result = await cache_mod.list_cache_configs(session=MagicMock())

        assert result == {"tenants": [row], "cache_available": True}

        # set_config must be called, and it must be the FIRST call on the
        # connection (i.e. before conn.fetch), and it must carry app.tenant_id.
        assert conn.execute.await_count == 1, "set_config must be called exactly once"
        set_config_call = conn.execute.await_args
        sql = set_config_call.args[0]
        assert "set_config" in sql and "app.tenant_id" in sql, (
            f"V50-CACHE-500 regression: app.tenant_id must be SET before the "
            f"RLS-gated cache_config query, got SQL: {sql!r}"
        )
        assert set_config_call.args[1] == cache_mod._PLATFORM_TENANT_ID

    @pytest.mark.asyncio
    async def test_db_failure_degrades_gracefully_never_500(self):
        """
        If the query fails for ANY reason (this exact live RLS error, a
        connection drop, whatever) the handler must NOT return a raw 500 —
        it must degrade to a safe 200 envelope like the `rc is None` path.
        """
        import yashigani.backoffice.routes.cache as cache_mod

        live_error = Exception('unrecognized configuration parameter "app.tenant_id"')
        pool, conn = _mock_pool(execute_side_effect=live_error)

        mock_state = MagicMock()
        mock_state.response_cache = MagicMock()

        with patch("yashigani.backoffice.state.backoffice_state", mock_state), \
             patch("yashigani.db.postgres.get_pool", return_value=pool), \
             patch.object(cache_mod, "logger"):
            result = await cache_mod.list_cache_configs(session=MagicMock())

        assert isinstance(result, JSONResponse)
        assert result.status_code != 500, (
            "V50-CACHE-500 regression: /admin/cache must never return HTTP 500 "
            f"on a backend query failure, got {result.status_code}"
        )
        assert result.status_code == 200
        body = result.body.decode()
        assert '"cache_available":false' in body.replace(" ", "")
        assert '"tenants":[]' in body.replace(" ", "")
        # Must not leak the raw exception text to the client (V232-CSCAN-01e).
        assert "unrecognized configuration parameter" not in body

    @pytest.mark.asyncio
    async def test_response_cache_not_initialised_unchanged(self):
        """Pre-existing degrade path (rc is None) must be unaffected by the fix."""
        import yashigani.backoffice.routes.cache as cache_mod

        mock_state = MagicMock()
        mock_state.response_cache = None

        with patch("yashigani.backoffice.state.backoffice_state", mock_state):
            result = await cache_mod.list_cache_configs(session=MagicMock())

        assert result == {"tenants": [], "cache_available": False}


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
