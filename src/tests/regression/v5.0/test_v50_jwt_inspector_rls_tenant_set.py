# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-RLS-SWEEP: JWTInspector._load_tenant_config() (the RUNTIME
JWT-validation lookup, gateway/jwt_inspector.py) queried jwt_config without
ever setting app.tenant_id.

Part of the RLS-sweep class audit alongside test_v50_028_jwt_config_rls_
tenant_set.py (the ADMIN config CRUD in the same table) and
test_v50_admin_cache_500.py.

This is the most severe finding in the sweep: jwt_config has RLS
(0001_initial_schema.py, USING (tenant_id = current_setting('app.tenant_id')
::uuid OR tenant_id = platform-sentinel)). _load_tenant_config() never SET
app.tenant_id, so every lookup raised "unrecognized configuration parameter"
— caught and logged as a bare warning, returning None. _resolve_config()'s
waterfall (tenant config -> platform config -> YASHIGANI_JWKS_URL env var ->
"no_jwks_configured") then silently fell through: a JWKS/issuer/audience
configured via the documented primary path (the jwt_config table, module
docstring line 9-10) NEVER actually took effect for any inbound bearer token
— every request behaved as if JWT introspection were unconfigured, unless the
YASHIGANI_JWKS_URL env-var fallback happened to also be set. No 500, no
visible error anywhere — the feature just silently never worked.

Fix: SELECT set_config('app.tenant_id', $1, true) inside an explicit
conn.transaction(), before the SELECT, using the SAME tenant_id being looked
up (the platform sentinel for scope='platform' calls, the real tenant for
scope='tenant' calls) — this satisfies the RLS policy for both lookup kinds.

Verified to FAIL against the pre-fix code (temporarily reverted
_load_tenant_config, reran — test failed as expected, then restored; no git
stash used).
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _mock_pool(fetchrow_return=None, execute_side_effect=None):
    conn = MagicMock()
    conn.execute = AsyncMock(side_effect=execute_side_effect)
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


class TestLoadTenantConfigSetsTenantBeforeFetchrow:
    async def test_platform_scope_lookup_sets_platform_tenant_before_query(self):
        import yashigani.gateway.jwt_inspector as insp_mod

        row = {
            "jwks_url": "https://idp.example.com/jwks.json",
            "issuer": "https://idp.example.com/",
            "audience": "yashigani",
            "fail_closed": True,
            "scope": "platform",
        }
        pool, conn = _mock_pool(fetchrow_return=row)
        inspector = insp_mod.JWTInspector()

        with patch("yashigani.db.postgres.get_pool", return_value=pool):
            config = await inspector._load_tenant_config(insp_mod.PLATFORM_TENANT_ID, "platform")

        assert config is not None
        assert config.jwks_url == row["jwks_url"]

        assert conn.execute.await_count == 1, "set_config must be called exactly once"
        set_config_call = conn.execute.await_args
        assert "set_config" in set_config_call.args[0] and "app.tenant_id" in set_config_call.args[0], (
            f"V50-RLS-SWEEP regression: app.tenant_id must be SET before the "
            f"RLS-gated jwt_config lookup, got SQL: {set_config_call.args[0]!r}"
        )
        assert set_config_call.args[1] == insp_mod.PLATFORM_TENANT_ID
        conn.fetchrow.assert_awaited_once()

    async def test_tenant_scope_lookup_sets_real_tenant_before_query(self):
        import yashigani.gateway.jwt_inspector as insp_mod

        real_tenant = str(uuid.uuid4())
        pool, conn = _mock_pool(fetchrow_return=None)
        inspector = insp_mod.JWTInspector()

        with patch("yashigani.db.postgres.get_pool", return_value=pool):
            config = await inspector._load_tenant_config(real_tenant, "tenant")

        assert config is None  # no row found — but the query must have run cleanly
        set_config_call = conn.execute.await_args
        assert set_config_call.args[1] == real_tenant, (
            "V50-RLS-SWEEP regression: a per-tenant lookup must SET the real "
            "tenant being queried, not a hardcoded platform sentinel"
        )

    async def test_rls_missing_param_error_no_longer_reachable(self):
        """
        Before the fix, EVERY call hit the live RLS error below and was
        swallowed into a bare `logger.warning`. This test documents that the
        exact error string that reproduced against the live DB is no longer
        what fails the query — the mock's execute() (the set_config call) now
        succeeds by construction, proving the SET happens where Postgres
        would have needed it.
        """
        import yashigani.gateway.jwt_inspector as insp_mod

        pool, conn = _mock_pool(fetchrow_return=None, execute_side_effect=None)
        inspector = insp_mod.JWTInspector()

        with patch("yashigani.db.postgres.get_pool", return_value=pool), \
             patch.object(insp_mod, "logger") as mock_logger:
            await inspector._load_tenant_config(insp_mod.PLATFORM_TENANT_ID, "platform")

        mock_logger.warning.assert_not_called()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
