# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-RLS-SWEEP: BudgetStore (billing/budget_store.py) queried
org_cloud_caps, group_budgets, individual_budgets, and model_aliases — all
four RLS-protected (0005_identity_budget_routing.py:
  USING (tenant_id = current_setting('app.tenant_id')::uuid)
) — without EVER calling set_config('app.tenant_id', ...). Every single
method in the class had this bug; it was the largest single offender found
in the RLS-sweep (see also test_v50_admin_cache_500.py,
test_v50_028_jwt_config_rls_tenant_set.py,
test_v50_jwt_inspector_rls_tenant_set.py).

Blast radius (confirmed by reading, not live-reproduced — no stack mutation
per the audit brief):

  * routes/budget.py — GET /org-caps, /groups, /individuals and
    POST/DELETE on all three have NO try/except around the budget_store
    call. Every one of these 9 endpoints unconditionally 500'd.
  * routes/dashboard.py — the three budget-count reads are wrapped in a bare
    `except Exception: pass`, so the admin dashboard silently always showed
    org_caps_count / group_budgets_count / individual_budgets_count == 0,
    indistinguishable from "nothing configured".

Fix: every RLS-table method now opens an explicit `async with
conn.transaction():` (required — asyncpg's `set_config(..., is_local=true)`
only survives to the following statement inside an explicit transaction;
two bare `await conn.fetch()` calls each auto-commit their own implicit
transaction and the SET is discarded before the query runs) and calls the
new `_set_tenant(conn, tenant_id)` helper — using the tenant_id ALREADY
PASSED IN to every method, not a hardcoded sentinel — before the query.
get_model_pricing() is untouched: model_pricing carries no RLS (no
tenant_id column, global reference data).

This is a single parametrized test asserting the invariant for every
RLS-gated method on BudgetStore: set_config('app.tenant_id', <the same
tenant_id argument>) must be the FIRST statement executed on the connection,
before the actual query/mutation.

Verified to FAIL against the pre-fix code (temporarily reverted
billing/budget_store.py, reran — every parametrized case failed as expected,
then restored; no git stash used).
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest


def _mock_pool(fetch_return=None, fetchval_return=None, execute_return="INSERT 0 1"):
    conn = MagicMock()
    conn.execute = AsyncMock(return_value=execute_return)
    conn.fetch = AsyncMock(return_value=fetch_return or [])
    conn.fetchval = AsyncMock(return_value=fetchval_return)

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


# (method_name, args-after-tenant_id, is_read) — every method takes
# tenant_id as its FIRST argument, matching the RLS "current tenant" value
# that must be SET before the query.
_RLS_METHOD_CASES = [
    ("get_org_caps", ()),
    ("set_org_cap", ("org-1", "anthropic", 10000, "monthly")),
    ("delete_org_cap", ("org-1", "anthropic")),
    ("get_group_budgets", ()),
    ("set_group_budget", ("group-1", "anthropic", 5000, "monthly", False)),
    ("delete_group_budget", ("group-1", "anthropic")),
    ("get_individual_budgets", ()),
    ("set_individual_budget", ("identity-1", "anthropic", 1000, "monthly")),
    ("delete_individual_budget", ("identity-1", "anthropic")),
    ("get_model_aliases", ()),
]


class TestBudgetStoreSetsTenantBeforeEveryRlsQuery:
    @pytest.mark.parametrize("method_name,extra_args", _RLS_METHOD_CASES)
    async def test_set_config_precedes_query(self, method_name, extra_args):
        from yashigani.billing.budget_store import BudgetStore

        tenant_id = str(uuid.uuid4())
        pool, conn = _mock_pool()
        store = BudgetStore(pool=pool)

        method = getattr(store, method_name)
        await method(tenant_id, *extra_args)

        # set_config must be the FIRST statement on the connection.
        assert conn.execute.await_count >= 1, (
            f"V50-RLS-SWEEP regression: {method_name} never called "
            f"conn.execute — set_config('app.tenant_id', ...) is missing"
        )
        first_call = conn.execute.await_args_list[0]
        sql = first_call.args[0]
        assert "set_config" in sql and "app.tenant_id" in sql, (
            f"V50-RLS-SWEEP regression: {method_name}'s first statement must "
            f"be SELECT set_config('app.tenant_id', ...), got: {sql!r}"
        )
        assert first_call.args[1] == tenant_id, (
            f"V50-RLS-SWEEP regression: {method_name} must SET the SAME "
            f"tenant_id it was called with, got {first_call.args[1]!r} "
            f"instead of {tenant_id!r}"
        )
        # And it must run inside an explicit transaction — otherwise
        # set_config(..., is_local=true) does not survive to the next
        # statement under asyncpg/pgbouncer transaction-pool mode.
        assert conn.transaction.called, (
            f"V50-RLS-SWEEP regression: {method_name} must wrap set_config + "
            f"query in an explicit conn.transaction()"
        )

    async def test_no_pool_short_circuits_before_any_query(self):
        """Pre-existing graceful-degrade path (pool=None) must be unaffected."""
        from yashigani.billing.budget_store import BudgetStore

        store = BudgetStore(pool=None)
        assert await store.get_org_caps("t") == []
        assert await store.delete_org_cap("t", "o", "p") is False

    async def test_model_pricing_untouched_no_set_config(self):
        """model_pricing has no RLS — get_model_pricing must NOT set_config."""
        from yashigani.billing.budget_store import BudgetStore

        pool, conn = _mock_pool(fetch_return=[])
        store = BudgetStore(pool=pool)
        await store.get_model_pricing()
        conn.execute.assert_not_called()
        conn.fetch.assert_awaited_once()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
