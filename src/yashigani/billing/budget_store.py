"""
Yashigani Billing — Postgres-backed budget store.

Persists budget configuration (org caps, group budgets, individual budgets)
in Postgres. Hot counters remain in budget-redis for performance.

DB tables (from migration 0005):
  org_cloud_caps       — per-provider organisation caps
  group_budgets        — per-group token allocation
  individual_budgets   — per-identity token allocation
  model_pricing        — cost per 1K tokens per model
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class BudgetStore:
    """
    Postgres-backed budget configuration store.

    Uses asyncpg pool for async queries. Falls back gracefully
    if the DB pool is not available (budget enforcement still works
    via Redis counters, just no persistent config).
    """

    def __init__(self, pool=None) -> None:
        self._pool = pool
        if pool:
            logger.info("BudgetStore: Postgres pool connected")
        else:
            logger.warning("BudgetStore: no Postgres pool — budget config not persisted")

    async def get_org_caps(self, tenant_id: str) -> list[dict]:
        """Get all org cloud caps for a tenant."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT org_id, provider, token_cap, period FROM org_cloud_caps WHERE tenant_id = $1",
                tenant_id,
            )
            return [dict(r) for r in rows]

    async def set_org_cap(self, tenant_id: str, org_id: str, provider: str, token_cap: int, period: str = "monthly") -> dict:
        """Create or update an org cloud cap."""
        if not self._pool:
            return {"org_id": org_id, "provider": provider, "token_cap": token_cap, "period": period}
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO org_cloud_caps (tenant_id, org_id, provider, token_cap, period)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, org_id, provider) DO UPDATE SET token_cap = $4, updated_at = now()
            """, tenant_id, org_id, provider, token_cap, period)
            return {"org_id": org_id, "provider": provider, "token_cap": token_cap, "period": period}

    async def get_group_budgets(self, tenant_id: str) -> list[dict]:
        """Get all group budgets for a tenant."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT group_id, provider, token_budget, period, auto_calculated FROM group_budgets WHERE tenant_id = $1",
                tenant_id,
            )
            return [dict(r) for r in rows]

    async def set_group_budget(self, tenant_id: str, group_id: str, provider: str, token_budget: int, period: str = "monthly", auto_calculated: bool = False) -> dict:
        """Create or update a group budget."""
        if not self._pool:
            return {"group_id": group_id, "provider": provider, "token_budget": token_budget, "period": period}
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO group_budgets (tenant_id, group_id, provider, token_budget, period, auto_calculated)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (tenant_id, group_id, provider, period) DO UPDATE SET token_budget = $4, auto_calculated = $6, updated_at = now()
            """, tenant_id, group_id, provider, token_budget, period, auto_calculated)
            return {"group_id": group_id, "provider": provider, "token_budget": token_budget, "period": period}

    async def get_individual_budgets(self, tenant_id: str) -> list[dict]:
        """Get all individual budgets for a tenant."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT identity_id, provider, token_budget, period FROM individual_budgets WHERE tenant_id = $1",
                tenant_id,
            )
            return [dict(r) for r in rows]

    async def set_individual_budget(self, tenant_id: str, identity_id: str, provider: str, token_budget: int, period: str = "monthly") -> dict:
        """Create or update an individual budget."""
        if not self._pool:
            return {"identity_id": identity_id, "provider": provider, "token_budget": token_budget, "period": period}
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO individual_budgets (tenant_id, identity_id, provider, token_budget, period)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, identity_id, provider, period) DO UPDATE SET token_budget = $4, updated_at = now()
            """, tenant_id, identity_id, provider, token_budget, period)
            return {"identity_id": identity_id, "provider": provider, "token_budget": token_budget, "period": period}

    async def get_model_pricing(self) -> list[dict]:
        """Get all model pricing entries."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT provider, model_name, input_cost_per_1k, output_cost_per_1k, is_local FROM model_pricing ORDER BY provider, model_name"
            )
            return [dict(r) for r in rows]

    async def delete_org_cap(self, tenant_id: str, org_id: str, provider: str) -> bool:
        """Delete an org cap.  Returns True if a row was deleted, False if absent."""
        if not self._pool:
            return False
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM org_cloud_caps WHERE tenant_id = $1 AND org_id = $2 AND provider = $3",
                tenant_id, org_id, provider,
            )
            return result.endswith("1")

    async def delete_group_budget(
        self, tenant_id: str, group_id: str, provider: str, period: str = "monthly",
    ) -> bool:
        """Delete a group budget.  Returns True if a row was deleted, False if absent."""
        if not self._pool:
            return False
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM group_budgets WHERE tenant_id = $1 AND group_id = $2 AND provider = $3 AND period = $4",
                tenant_id, group_id, provider, period,
            )
            return result.endswith("1")

    async def delete_individual_budget(
        self, tenant_id: str, identity_id: str, provider: str, period: str = "monthly",
    ) -> bool:
        """Delete an individual budget.  Returns True if a row was deleted, False if absent."""
        if not self._pool:
            return False
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM individual_budgets WHERE tenant_id = $1 AND identity_id = $2 AND provider = $3 AND period = $4",
                tenant_id, identity_id, provider, period,
            )
            return result.endswith("1")

    async def get_model_aliases(self, tenant_id: str) -> list[dict]:
        """Get all model aliases for a tenant."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT alias, provider, model_name, force_local, description FROM model_aliases WHERE tenant_id = $1",
                tenant_id,
            )
            return [dict(r) for r in rows]
