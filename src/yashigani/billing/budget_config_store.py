"""
Yashigani Billing — Redis-backed budget *configuration* store (B3 fix, 2.25.5).

Persists the three-tier budget configuration (org caps, group budgets,
individual budgets) in Redis db/3 — the same durable, no-eviction admin store
used by model allocations and client-policy bindings.

Why not the Postgres ``BudgetStore``?
  The Postgres tables (migration 0005 ``org_cloud_caps`` / ``group_budgets`` /
  ``individual_budgets``) are guarded by row-level security keyed on
  ``current_setting('app.tenant_id')`` AND carry hard foreign keys to
  ``tenants(id)`` / ``rbac_groups(id)`` / ``identities(identity_id)``. The admin
  UI writes free-text org/group/identity strings (e.g. ``default``,
  ``engineering``, ``user@example.com``) which are NOT UUIDs in those tables, so
  every INSERT FK-violates — and ``BudgetStore`` was never even constructed or
  wired via ``budget.configure()`` at startup. The net effect (found live
  2026-06-12, build sheet B3): adding a cap returned HTTP 201 but persisted
  NOTHING, and the list endpoints always returned ``[]`` — caps "didn't save or
  render back".

This store fixes the write path AND the read-back path with the exact same
interface the budget routes already call (``get_org_caps`` / ``set_org_cap`` /
``get_group_budgets`` / ``set_group_budget`` / ``get_individual_budgets`` /
``set_individual_budget``), so no route or UI shape changes are needed. It is
``async`` to match the routes' ``await`` call sites; Redis ops are sync under
the hood (db/3 sync client, same as the allocation store) which is fine for the
low-frequency admin config path.

Redis key schema (db/3):
    budget:config:orgcap:{org_id}:{provider}            -> JSON
    budget:config:group:{group_id}:{provider}:{period}  -> JSON
    budget:config:individual:{identity_id}:{provider}:{period} -> JSON

The ``tenant_id`` argument the routes pass (a fixed all-zeros UUID in the
single-tenant compose/Helm deploy) is accepted for signature-compatibility and
folded into the key prefix so a future multi-tenant deploy stays isolated.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

_PREFIX = "budget:config"
_ORGCAP = _PREFIX + ":orgcap:{tenant}:{org}:{provider}"
_GROUP = _PREFIX + ":group:{tenant}:{group}:{provider}:{period}"
_INDIV = _PREFIX + ":individual:{tenant}:{identity}:{provider}:{period}"

_SCAN_ORGCAP = _PREFIX + ":orgcap:{tenant}:*"
_SCAN_GROUP = _PREFIX + ":group:{tenant}:*"
_SCAN_INDIV = _PREFIX + ":individual:{tenant}:*"


class BudgetConfigStore:
    """
    Redis db/3-backed budget configuration store.

    Synchronous Redis client wrapped in async methods so it is a drop-in for the
    Postgres ``BudgetStore`` the budget admin routes were written against.
    """

    def __init__(self, redis_client) -> None:
        self._r = redis_client
        logger.info("BudgetConfigStore: Redis db/3 connected")

    # ── helpers ──────────────────────────────────────────────────────────────

    def _scan(self, pattern: str) -> list[dict]:
        out: list[dict] = []
        try:
            for key in self._r.scan_iter(match=pattern, count=200):
                raw = self._r.get(key)
                if raw is None:
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    out.append(json.loads(raw))
                except (ValueError, TypeError):
                    continue
        except Exception as exc:  # fail-soft on read — never 500 the admin list
            logger.warning("BudgetConfigStore scan failed (%s): %s", pattern, exc)
        return out

    def _put(self, key: str, doc: dict) -> None:
        self._r.set(key, json.dumps(doc))

    # ── org caps ─────────────────────────────────────────────────────────────

    async def get_org_caps(self, tenant_id: str) -> list[dict]:
        return self._scan(_SCAN_ORGCAP.format(tenant=tenant_id))

    async def set_org_cap(
        self, tenant_id: str, org_id: str, provider: str,
        token_cap: int, period: str = "monthly",
    ) -> dict:
        doc = {"org_id": org_id, "provider": provider,
               "token_cap": int(token_cap), "period": period}
        self._put(_ORGCAP.format(tenant=tenant_id, org=org_id, provider=provider), doc)
        return doc

    # ── group budgets ────────────────────────────────────────────────────────

    async def get_group_budgets(self, tenant_id: str) -> list[dict]:
        return self._scan(_SCAN_GROUP.format(tenant=tenant_id))

    async def set_group_budget(
        self, tenant_id: str, group_id: str, provider: str,
        token_budget: int, period: str = "monthly", auto_calculated: bool = False,
    ) -> dict:
        doc = {"group_id": group_id, "provider": provider,
               "token_budget": int(token_budget), "period": period,
               "auto_calculated": bool(auto_calculated)}
        self._put(
            _GROUP.format(tenant=tenant_id, group=group_id, provider=provider, period=period),
            doc,
        )
        return doc

    # ── individual budgets ───────────────────────────────────────────────────

    async def get_individual_budgets(self, tenant_id: str) -> list[dict]:
        return self._scan(_SCAN_INDIV.format(tenant=tenant_id))

    async def set_individual_budget(
        self, tenant_id: str, identity_id: str, provider: str,
        token_budget: int, period: str = "monthly",
    ) -> dict:
        doc = {"identity_id": identity_id, "provider": provider,
               "token_budget": int(token_budget), "period": period}
        self._put(
            _INDIV.format(tenant=tenant_id, identity=identity_id, provider=provider, period=period),
            doc,
        )
        return doc

    # ── pricing / aliases (parity stubs — not used by the admin UI) ──────────

    async def get_model_pricing(self) -> list[dict]:
        return []

    async def get_model_aliases(self, tenant_id: str) -> list[dict]:
        return []
