# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-028: /admin/jwt/config queried jwt_config without ever
setting app.tenant_id, defeating RLS before it was even evaluated.

Part of the RLS-sweep class audit (see also test_v50_admin_cache_500.py,
test_v50_rls_tenant_set_static_guard.py, test_v50_budget_store_rls_tenant_set.py,
test_v50_jwt_inspector_rls_tenant_set.py).

jwt_config carries ROW LEVEL SECURITY (0001_initial_schema.py):
    ALTER TABLE jwt_config ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON jwt_config
        USING (tenant_id = current_setting('app.tenant_id')::uuid
               OR tenant_id = '00000000-0000-0000-0000-000000000000'::uuid);

Three offenders, all in backoffice/routes/jwt_config.py, none of which ever
called set_config('app.tenant_id', ...):

  1. list_jwt_configs() (GET) — SILENT-EMPTY. The exception was caught by a
     broad `except Exception` that logged a bare `logger.warning` (no stack
     trace) and returned `configs: []` at HTTP 200 — indistinguishable from
     "no config saved yet". This is the WORSE class per the brief: an admin
     staring at "No JWT configs." has no signal that the query never actually
     ran. /admin/jwt/config never listed a saved config, ever.

  2. set_jwt_config() (PUT) — hard 500 on every save attempt.

  3. delete_jwt_config() (DELETE) — hard 500 on every delete attempt.

Fix: set_config('app.tenant_id', ...) inside an explicit `conn.transaction()`
before every query — platform sentinel for the list (matches the RLS policy's
OR-platform clause and the established single-tenant-community-deployment
idiom used elsewhere), the actual `tenant_id` being written/deleted for
set/delete (required for the INSERT's implicit WITH CHECK — derived from
USING, since no separate WITH CHECK is defined on this policy — to accept a
real per-tenant SaaS row rather than only the platform sentinel).

Also: GET now returns an `available: bool` field (mirrors `cache_available`
in routes/cache.py) so a genuine backend failure is distinguishable from an
empty config table.

Verified to FAIL against the pre-fix code (temporarily reverted the three
handlers, reran — all three tests below failed as expected, then restored;
no git stash used).
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _mock_pool(fetch_return=None, fetchrow_return=None, execute_return=None, execute_side_effect=None):
    """Build a mock asyncpg-style pool/connection/transaction chain."""
    conn = MagicMock()
    conn.execute = AsyncMock(return_value=execute_return, side_effect=execute_side_effect)
    conn.fetch = AsyncMock(return_value=fetch_return or [])
    conn.fetchrow = AsyncMock(return_value=fetchrow_return)

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


class TestListJwtConfigsSetsTenantAndSurfacesFailure:
    async def test_happy_path_sets_platform_tenant_before_fetch(self):
        import yashigani.backoffice.routes.jwt_config as jwt_mod

        row = {
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "jwks_url": "https://idp.example.com/.well-known/jwks.json",
            "issuer": "https://idp.example.com/",
            "audience": "yashigani",
            "fail_closed": True,
            "scope": "platform",
        }
        pool, conn = _mock_pool(fetch_return=[row])

        with patch("yashigani.db.postgres.get_pool", return_value=pool):
            result = await jwt_mod.list_jwt_configs(session=MagicMock())

        assert result["available"] is True
        assert len(result["configs"]) == 1
        assert result["configs"][0]["tenant_id"] == row["tenant_id"]

        # set_config must run FIRST on the connection, before conn.fetch, and
        # must carry app.tenant_id set to the platform sentinel.
        assert conn.execute.await_count == 1
        set_config_call = conn.execute.await_args
        sql = set_config_call.args[0]
        assert "set_config" in sql and "app.tenant_id" in sql, (
            f"V50-028 regression: app.tenant_id must be SET before the "
            f"RLS-gated jwt_config SELECT, got SQL: {sql!r}"
        )
        assert set_config_call.args[1] == jwt_mod.PLATFORM_TENANT_ID
        conn.fetch.assert_awaited_once()

    async def test_db_failure_reported_via_available_flag_not_silent_empty(self):
        """
        A backend failure (this exact live RLS error, a connection drop,
        whatever) must be OBSERVABLE — `available: False` — not silently
        indistinguishable from an empty, unconfigured table.
        """
        import yashigani.backoffice.routes.jwt_config as jwt_mod

        live_error = Exception('unrecognized configuration parameter "app.tenant_id"')
        pool, conn = _mock_pool(execute_side_effect=live_error)

        with patch("yashigani.db.postgres.get_pool", return_value=pool), \
             patch.object(jwt_mod, "logger"):
            result = await jwt_mod.list_jwt_configs(session=MagicMock())

        assert result["configs"] == []
        assert result["available"] is False, (
            "V50-028 regression: a genuine query failure must set "
            "available=False, not silently look like an empty config table"
        )


class TestSetJwtConfigSetsTenantBeforeInsert:
    async def test_sets_body_tenant_id_before_insert_not_platform(self):
        """
        The RLS policy's WITH CHECK (derived from USING) requires the new
        row's tenant_id to equal current_setting('app.tenant_id') OR the
        platform sentinel. A per-tenant SaaS write must SET the real tenant,
        not hardcode platform, or the INSERT itself would be rejected by RLS
        for any non-platform tenant_id.
        """
        import yashigani.backoffice.routes.jwt_config as jwt_mod

        real_tenant = str(uuid.uuid4())
        pool, conn = _mock_pool()
        body = jwt_mod.JWTConfigRequest(
            tenant_id=real_tenant,
            jwks_url="https://idp.example.com/jwks.json",
            issuer="https://idp.example.com/",
            audience="yashigani",
            scope="tenant",
        )

        with patch("yashigani.db.postgres.get_pool", return_value=pool), \
             patch("os.getenv", side_effect=lambda k, d=None: "saas" if k == "YASHIGANI_DEPLOYMENT_STREAM" else d):
            result = await jwt_mod.set_jwt_config(body=body, session=MagicMock())

        assert result == {"status": "updated", "tenant_id": real_tenant, "scope": "tenant"}
        # First call must be set_config carrying the REAL tenant, not platform.
        assert conn.execute.await_count == 2
        set_config_call = conn.execute.await_args_list[0]
        assert "set_config" in set_config_call.args[0]
        assert set_config_call.args[1] == real_tenant, (
            "V50-028 regression: PUT /admin/jwt/config must SET the tenant "
            "being written, not a hardcoded platform sentinel"
        )
        insert_call = conn.execute.await_args_list[1]
        assert "INSERT INTO jwt_config" in insert_call.args[0]


class TestDeleteJwtConfigSetsTenantBeforeDelete:
    async def test_sets_path_tenant_id_before_delete(self):
        import yashigani.backoffice.routes.jwt_config as jwt_mod

        target_tenant = str(uuid.uuid4())
        pool, conn = _mock_pool()

        with patch("yashigani.db.postgres.get_pool", return_value=pool):
            result = await jwt_mod.delete_jwt_config(tenant_id=target_tenant, session=MagicMock())

        assert result == {"status": "deleted", "tenant_id": target_tenant}
        assert conn.execute.await_count == 2
        set_config_call = conn.execute.await_args_list[0]
        assert "set_config" in set_config_call.args[0]
        assert set_config_call.args[1] == target_tenant
        delete_call = conn.execute.await_args_list[1]
        assert "DELETE FROM jwt_config" in delete_call.args[0]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
