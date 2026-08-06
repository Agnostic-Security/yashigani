"""
Regression tests — YSG-RISK-141 (self-heal reconnect never re-triggers the
Postgres->Redis agent reconcile; dispatched as a v4.1.2 chat-blocker
follow-up to YSG-RISK-131).

## The finding

`reconcile_agents_from_durable()` (`yashigani/agents/reconciler.py`) re-pushes
the durable Postgres `agent_registry` mirror into Redis db/3 so a Redis wipe
(`appendonly no` / `save ""` in the historical default, `FLUSHDB`, or a fast
recreate) does not permanently disable every `@agent`. Before this fix it was
wired into exactly ONE call-site per process: the gateway/backoffice
`lifespan` startup hook (`gateway/proxy.py`, `backoffice/app.py`), which runs
ONCE, before uvicorn starts accepting connections.

YSG-RISK-131/122 added a SEPARATE lazy, cooldown-gated, request-time
reconnect path (`gateway/redis_selfheal.py::ensure_rbac_agent_stack` /
`backoffice/redis_selfheal.py::ensure_rbac_stack`) for the case where Redis
becomes reachable again mid-life. That path rebuilds a brand-new
`AgentRegistry` wrapping whatever is CURRENTLY in Redis db/3 — but never
called `reconcile_agents_from_durable()` again. If Redis db/3 lost its agent
data mid-life while the TCP connection itself recovered fast enough that the
in-process `agent_registry` object briefly went `None` and was rebuilt by the
self-heal path (rather than the process restarting, which would re-run the
one-shot lifespan reconcile), the rebuilt registry stays permanently EMPTY —
every `@agent` returns `agent_not_found` — even though the durable Postgres
`agent_registry` table still holds every registration and a fresh process
restart would have healed it.

Live-verified during the v4.1.2 x8x Docker e2e dispatch (2026-07-29): the
gateway's ONE-SHOT lifespan reconcile logged "durable store empty and no
Redis agents to back-fill" at boot (expected — this ran before
`install.sh`'s `register_agent_bundles()` step registered the 3 bundle
agents seconds later, which dual-writes directly to the SAME live Redis
db/3 the gateway already holds a connection to, so no reconcile was actually
needed for that case). Direct live inspection of Postgres
(`agent_registry` table, tenant_id `00000000-0000-0000-0000-00000000000`,
3 rows) and Redis db/3 (`agent:index:all`, 3 members, all `active`) via
`docker exec` confirmed BOTH stores were correctly populated and in sync at
request time — the originally-hypothesized "reconciler queries a different
tenant" theory does NOT reproduce: `AgentDurableStore.list_all()` and
`AgentDurableStore.upsert()` both hard-code the SAME `_PLATFORM_TENANT_ID`
sentinel (`00000000-0000-0000-0000-000000000000`), confirmed identical via a
raw-SQL replay of the exact query as the `yashigani_app` role (no RLS
bypass) against the live container, returning all 3 rows. The REAL, still-
open gap in this exact code area is the self-heal-never-reconciles gap this
file closes.

## The fix

`gateway/redis_selfheal.py::maybe_selfheal()` and
`backoffice/redis_selfheal.py::maybe_selfheal()` now re-run
`reconcile_agents_from_durable()` immediately after `ensure_rbac_agent_stack`
/ `ensure_rbac_stack` succeeds a lazy reconnect — back on the event loop
(never inside the `asyncio.to_thread` builder worker, since
`reconcile_agents_from_durable` reads the loop-bound asyncpg pool).

Last updated: 2026-07-29T00:00:00+00:00
"""
from __future__ import annotations


import pytest


# ---------------------------------------------------------------------------
# 1. reconcile_agents_from_durable() itself — proves the "not durable store
#    empty" claim: N durable rows + an agent_registry with none of them
#    present must restore all N into Redis db/3.
# ---------------------------------------------------------------------------

class _FakeDurableStore:
    def __init__(self, rows):
        self._rows = rows

    async def list_all(self):
        return self._rows


class _FakeAgentRegistry:
    """Stands in for AgentRegistry: list_all() reads the live Redis index;
    restore_from_durable() re-materialises one durable row."""

    def __init__(self, existing_ids=()):
        self._existing = [{"agent_id": i} for i in existing_ids]
        self.restored = []

    def list_all(self):
        return self._existing

    def restore_from_durable(self, row, token_hash):
        self.restored.append((row["agent_id"], token_hash))


def _durable_row(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "name": agent_id.replace("agnt_", "agent_"),
        "upstream_url": f"https://caddy/agents/default/{agent_id}",
        "token_hash": f"$2b$12$fakehash-{agent_id}",
        "protocol": "openai",
        "status": "active",
        "groups": [],
        "allowed_caller_groups": [],
        "allowed_paths": [],
        "allowed_cidrs": [],
        "created_at": "2026-07-29T18:14:43+00:00",
        "last_seen_at": "",
    }


@pytest.mark.asyncio
async def test_reconcile_backfills_all_durable_rows_when_redis_empty():
    """Given N durable rows under the canonical tenant + an EMPTY Redis-view
    agent_registry, the reconciler backfills all N (never logs the "durable
    store empty" no-op branch — that branch only fires when Postgres itself
    has zero rows, not when Redis is merely missing them)."""
    from yashigani.agents.reconciler import reconcile_agents_from_durable

    rows = [_durable_row("agnt_aaa"), _durable_row("agnt_bbb"), _durable_row("agnt_ccc")]
    durable = _FakeDurableStore(rows)
    registry = _FakeAgentRegistry(existing_ids=())  # Redis db/3 empty

    restored = await reconcile_agents_from_durable(registry, durable)

    assert restored == 3
    assert sorted(registry.restored) == [
        ("agnt_aaa", "$2b$12$fakehash-agnt_aaa"),
        ("agnt_bbb", "$2b$12$fakehash-agnt_bbb"),
        ("agnt_ccc", "$2b$12$fakehash-agnt_ccc"),
    ]


@pytest.mark.asyncio
async def test_reconcile_skips_rows_already_present_in_redis():
    """Redis is authoritative for rows it already has — only the MISSING
    durable rows get restored (never overwrites a live registration with a
    possibly-older durable copy)."""
    from yashigani.agents.reconciler import reconcile_agents_from_durable

    rows = [_durable_row("agnt_aaa"), _durable_row("agnt_bbb")]
    durable = _FakeDurableStore(rows)
    registry = _FakeAgentRegistry(existing_ids=("agnt_aaa",))

    restored = await reconcile_agents_from_durable(registry, durable)

    assert restored == 1
    assert registry.restored == [("agnt_bbb", "$2b$12$fakehash-agnt_bbb")]


@pytest.mark.asyncio
async def test_reconcile_first_boot_empty_durable_is_a_harmless_noop():
    """The historical false lead: an empty durable store (genuine first-boot,
    before any registration has ever happened) must NOT be confused with a
    tenant-scoping bug — it's an explicit, harmless, logged no-op."""
    from yashigani.agents.reconciler import reconcile_agents_from_durable

    durable = _FakeDurableStore([])
    registry = _FakeAgentRegistry(existing_ids=())

    restored = await reconcile_agents_from_durable(registry, durable)

    assert restored == 0
    assert registry.restored == []


# ---------------------------------------------------------------------------
# 2. Gateway self-heal wiring — maybe_selfheal() must re-run the reconcile
#    after ensure_rbac_agent_stack() rebuilds an (empty) registry.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_gateway_state():
    from yashigani.common import redis_selfheal as common_selfheal
    from yashigani.gateway import openai_router as oai
    from yashigani.gateway import egress_proxy
    from yashigani.gateway.state import GatewayFallbackState, gateway_fallback_state

    fields = [
        "agent_registry", "rbac_store", "permission_store", "identity_registry",
        "budget_enforcer", "optimization_engine", "model_allocation_store",
        "model_alias_store", "ddos_protector", "audit_writer",
    ]
    for f in fields:
        setattr(oai._state, f, None)
    fresh_fallback = GatewayFallbackState()
    for f in fresh_fallback.__dataclass_fields__:
        setattr(gateway_fallback_state, f, getattr(fresh_fallback, f))
    egress_proxy._state.egress_limit_enforcer = None
    common_selfheal.reset_cooldowns()
    yield
    for f in fields:
        setattr(oai._state, f, None)
    for f in fresh_fallback.__dataclass_fields__:
        setattr(gateway_fallback_state, f, getattr(fresh_fallback, f))
    egress_proxy._state.egress_limit_enforcer = None
    common_selfheal.reset_cooldowns()


@pytest.mark.asyncio
async def test_gateway_selfheal_reconciles_agents_after_reconnect(monkeypatch):
    """THE core regression: Redis db/3 lost its agent data mid-life; the
    connection recovers (agent_registry goes None -> rebuilt-but-EMPTY) via
    ensure_rbac_agent_stack(); maybe_selfheal() must then re-run
    reconcile_agents_from_durable() so the durable Postgres rows repopulate
    Redis db/3 — pre-fix, this NEVER happened and every @agent stayed
    agent_not_found until the whole gateway process restarted."""
    from yashigani.gateway import redis_selfheal as gw_selfheal
    from yashigani.gateway import openai_router as oai
    from yashigani.gateway import egress_proxy

    # Mark every OTHER subsystem already-healthy so only rbac_agent_stack
    # dispatches (matches the established maybe_selfheal() test convention —
    # see test_maybe_selfheal_dispatches_only_unhealthy_subsystems — and
    # avoids real network attempts from the unrelated ensure_*() builders).
    oai._state.identity_registry = "already-healthy"
    oai._state.budget_enforcer = "already-healthy"
    oai._state.model_allocation_store = "already-healthy"
    oai._state.model_alias_store = "already-healthy"
    oai._state.ddos_protector = "already-healthy"
    egress_proxy._state.egress_limit_enforcer = "already-healthy"

    class _FakeRebuiltRegistry:
        pass

    fake_registry = _FakeRebuiltRegistry()

    def _fake_ensure_rbac_agent_stack(app_state, cooldown_s=15.0):
        # Simulates ensure_rbac_agent_stack() rebuilding the stack after a
        # reconnect: agent_registry goes from None to a live-but-EMPTY object.
        oai._state.agent_registry = fake_registry
        app_state["agent_registry"] = fake_registry
        return True

    monkeypatch.setattr(
        gw_selfheal, "ensure_rbac_agent_stack", _fake_ensure_rbac_agent_stack
    )

    reconcile_calls = []

    async def _fake_reconcile(agent_registry, durable_store):
        reconcile_calls.append((agent_registry, durable_store))
        return 3

    monkeypatch.setattr(
        "yashigani.agents.reconciler.reconcile_agents_from_durable", _fake_reconcile
    )

    assert oai._state.agent_registry is None  # pre-condition: unhealthy

    app_state: dict = {
        "rate_limiter": "already-healthy",
        "endpoint_rate_limiter": "already-healthy",
        "response_cache": "already-healthy",
        "jwt_inspector": "already-healthy",
        "workflow_scheduler": "already-healthy",
    }
    await gw_selfheal.maybe_selfheal(app_state)

    assert oai._state.agent_registry is fake_registry
    assert len(reconcile_calls) == 1
    assert reconcile_calls[0][0] is fake_registry


@pytest.mark.asyncio
async def test_gateway_selfheal_skips_reconcile_when_already_healthy(monkeypatch):
    """No reconnect needed -> no reconcile call. The reconcile is gated
    behind an actual ensure_rbac_agent_stack() dispatch, not run
    unconditionally on every request."""
    from yashigani.gateway import redis_selfheal as gw_selfheal
    from yashigani.gateway import openai_router as oai
    from yashigani.gateway import egress_proxy

    oai._state.agent_registry = "already-healthy"
    oai._state.identity_registry = "already-healthy"
    oai._state.budget_enforcer = "already-healthy"
    oai._state.model_allocation_store = "already-healthy"
    oai._state.model_alias_store = "already-healthy"
    oai._state.ddos_protector = "already-healthy"
    egress_proxy._state.egress_limit_enforcer = "already-healthy"

    reconcile_calls = []

    async def _fake_reconcile(agent_registry, durable_store):
        reconcile_calls.append((agent_registry, durable_store))
        return 0

    monkeypatch.setattr(
        "yashigani.agents.reconciler.reconcile_agents_from_durable", _fake_reconcile
    )

    app_state: dict = {
        "rate_limiter": "already-healthy",
        "endpoint_rate_limiter": "already-healthy",
        "response_cache": "already-healthy",
        "jwt_inspector": "already-healthy",
        "workflow_scheduler": "already-healthy",
    }
    await gw_selfheal.maybe_selfheal(app_state)

    assert reconcile_calls == []


# ---------------------------------------------------------------------------
# 3. Backoffice self-heal wiring — the same gap, same fix, backoffice side.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_backoffice_state():
    from yashigani.backoffice import redis_selfheal as bo_selfheal
    from yashigani.backoffice.state import BackofficeState, backoffice_state

    fresh = BackofficeState()
    for field in fresh.__dataclass_fields__:
        setattr(backoffice_state, field, getattr(fresh, field))
    bo_selfheal._last_attempt_monotonic.clear()
    yield
    for field in fresh.__dataclass_fields__:
        setattr(backoffice_state, field, getattr(fresh, field))
    bo_selfheal._last_attempt_monotonic.clear()


@pytest.mark.asyncio
async def test_backoffice_selfheal_reconciles_agents_after_reconnect(monkeypatch):
    from yashigani.backoffice import redis_selfheal as bo_selfheal
    from yashigani.backoffice.state import backoffice_state

    class _FakeRebuiltRegistry:
        pass

    fake_registry = _FakeRebuiltRegistry()

    def _fake_ensure_rbac_stack(cooldown_s=15.0):
        backoffice_state.agent_registry = fake_registry
        return True

    monkeypatch.setattr(bo_selfheal, "ensure_rbac_stack", _fake_ensure_rbac_stack)

    reconcile_calls = []

    async def _fake_reconcile(agent_registry, durable_store):
        reconcile_calls.append((agent_registry, durable_store))
        return 3

    monkeypatch.setattr(
        "yashigani.agents.reconciler.reconcile_agents_from_durable", _fake_reconcile
    )

    assert backoffice_state.agent_registry is None  # pre-condition: unhealthy

    await bo_selfheal.maybe_selfheal()

    assert backoffice_state.agent_registry is fake_registry
    assert len(reconcile_calls) == 1
    assert reconcile_calls[0][0] is fake_registry


@pytest.mark.asyncio
async def test_backoffice_selfheal_skips_reconcile_when_already_healthy(monkeypatch):
    from yashigani.backoffice import redis_selfheal as bo_selfheal
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.agent_registry = "already-healthy"

    reconcile_calls = []

    async def _fake_reconcile(agent_registry, durable_store):
        reconcile_calls.append((agent_registry, durable_store))
        return 0

    monkeypatch.setattr(
        "yashigani.agents.reconciler.reconcile_agents_from_durable", _fake_reconcile
    )

    await bo_selfheal.maybe_selfheal()

    assert reconcile_calls == []
