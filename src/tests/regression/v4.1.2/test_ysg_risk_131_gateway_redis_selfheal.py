"""
Regression tests — YSG-RISK-131 (Iris systemic review, following the
live-reproduced 4.1.2 k8s chat blocker):

## The finding

Both `yashigani-gateway-*` pods, 17h uptime, 0 restarts, permanently
degraded: `gateway/entrypoint.py` builds `rbac_store` / `agent_registry` /
`capability_policy_store` / `permission_store` (plus 9 further Redis-backed
subsystems — rate_limiter, endpoint_rate_limiter, response_cache,
jwt_inspector, identity_registry, budget_enforcer, cloud_override_getter,
model_allocation_store, model_alias_store, workflow_scheduler,
ddos_protector, egress_limit_enforcer) in one-shot try/except blocks at cold
boot. On k8s, `yashigani-redis` Service-DNS is not always resolvable at that
exact instant (Redis Pod scheduled after the gateway Pod) — a single failed
connection attempt then left every one of these `None` for the pod's ENTIRE
lifetime, since nothing at request time ever retried. Chat requests returned
`agent_registry_unavailable` (and, for the direct-model path, degraded
model-alias resolution) the whole time. docker/podman compose ordering
(`depends_on: condition: service_healthy`) hides this class entirely, which
is why it shipped unnoticed until a live k8s deployment reproduced it.

## The fix

1. `yashigani.common.redis_selfheal` — a shared, cooldown-gated,
   at-most-one-attempt-per-window bounded-reconnect primitive (mirrors the
   backoffice YSG-RISK-122 shape without duplicating its bookkeeping a
   second time).
2. `gateway/rbac_stack.build_rbac_agent_stack()` — the RBAC/Agent/
   Capability-Policy/Permission-store construction logic, extracted from
   `entrypoint._build_app()` so the SAME code runs at both the bounded
   startup retry (1/2/4/8/16s x5) AND the lazy request-time reconnect.
3. `gateway/redis_selfheal.py` — one `ensure_*()` per Redis-backed gateway
   subsystem, each writing the rebuilt object into every live-state
   container its real consumers already read (`openai_router._state`,
   `proxy.py`'s per-app `_state` dict exposed via
   `app.state.internal_state`, `egress_proxy._state`), plus
   `maybe_selfheal()` — the async orchestrator dispatching only the
   currently-unhealthy subsystems.
4. `gateway/state.py` — a tiny fallback singleton for the two consumers that
   snapshot a value at construction instead of reading live state
   (`AgentAuthMiddleware._registry`).
5. `gateway/proxy.py` wires a `gateway_redis_selfheal_middleware` that calls
   `maybe_selfheal()` before every non-`/healthz`/`/metrics` request.

Each test below proves the client reconnects after an initial
unavailable -> later-available Redis transition. Every test would FAIL
against the pre-fix code, where a single failed attempt left the relevant
field `None` forever with no retry path.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import sys
import time

import pytest

from yashigani.common import redis_selfheal as common_selfheal
from yashigani.gateway import redis_selfheal as gw_selfheal
from yashigani.gateway import openai_router as oai  # noqa: F401 - see _gw_oai()
from yashigani.gateway import egress_proxy
from yashigani.gateway.state import GatewayFallbackState, gateway_fallback_state


def _gw_oai():
    """Resolve the LIVE ``yashigani.gateway.openai_router`` module via
    ``sys.modules`` rather than trusting the frozen collection-time binding
    (``oai`` above, kept only so the module import itself is visible).

    FIND-0813-012 wired all of ``src/tests/regression/`` into one Tier-A
    pytest session (previously it was referenced by no tier at all, so this
    was invisible). In that shared session,
    ``v2.25.4/test_obs_pin_and_forwarded_user.py``'s ``_load_router_with_env()``
    does ``del sys.modules["yashigani.gateway.openai_router"]`` +
    ``importlib.import_module(...)`` to get itself an isolated fresh module
    per test case, and never restores the original entry afterwards -- so
    for the rest of the session ``sys.modules["yashigani.gateway.openai_router"]``
    points at a DIFFERENT module object than the one this file bound at
    collection time (`import` binds once; collection for every file happens
    before any test body runs).

    ``gateway/redis_selfheal.py``'s ``ensure_*()``/``maybe_selfheal()``
    functions all resolve ``openai_router`` via a function-LOCAL import at
    CALL time (by design -- see that module's docstring: it must always
    read/write the live singleton). Call time is after the swap, so those
    functions correctly dual-write into the swapped-in module -- the
    self-heal code is not broken. A test file that instead asserts against
    a stale collection-time ``oai`` reference is checking the WRONG object
    and fails even though the product code behaved correctly. In the real
    running gateway process nothing ever reloads this module, so this
    divergence cannot occur outside a shared-process, multi-file pytest
    session -- it is a Tier-A test-harness hazard, not a product regression
    (see per-test docstrings/report for the confirmed repro + isolation
    proof). Resolving fresh here, at the point each test/fixture actually
    needs it, keeps every assertion in this file pinned to the SAME object
    the production code under test is currently writing into, regardless of
    what any sibling file does to ``sys.modules`` -- without changing what
    is asserted.
    """
    return sys.modules["yashigani.gateway.openai_router"]


@pytest.fixture(autouse=True)
def _reset_gateway_selfheal_state():
    """Isolate every test: fresh openai_router._state fields this suite
    touches, fresh gateway_fallback_state, fresh egress_proxy._state, and a
    fresh module-level cooldown-gate map (shared across ALL call-sites of the
    common primitive, so tests must not leak timing state into each other).

    Resolves openai_router via ``_gw_oai()`` (not the frozen ``oai`` import)
    so this reset targets whichever module object is CURRENTLY live -- see
    ``_gw_oai()`` docstring for why a frozen reference is unsafe in the
    shared Tier-A session."""
    _fields = [
        "agent_registry", "rbac_store", "permission_store", "identity_registry",
        "budget_enforcer", "optimization_engine", "model_allocation_store",
        "model_alias_store", "ddos_protector", "audit_writer",
    ]
    for f in _fields:
        setattr(_gw_oai()._state, f, None)

    fresh_fallback = GatewayFallbackState()
    for f in fresh_fallback.__dataclass_fields__:
        setattr(gateway_fallback_state, f, getattr(fresh_fallback, f))

    egress_proxy._state.egress_limit_enforcer = None

    common_selfheal.reset_cooldowns()
    yield
    for f in _fields:
        setattr(_gw_oai()._state, f, None)
    for f in fresh_fallback.__dataclass_fields__:
        setattr(gateway_fallback_state, f, getattr(fresh_fallback, f))
    egress_proxy._state.egress_limit_enforcer = None
    common_selfheal.reset_cooldowns()


@pytest.fixture
def app_state():
    """Stand-in for proxy.py's per-app `_state` dict (exposed via
    `app.state.internal_state`) — every key gateway/redis_selfheal.py writes
    into for the proxy.py-consumed subsystems."""
    return {}


# ---------------------------------------------------------------------------
# 1. The shared primitive (yashigani.common.redis_selfheal.ensure)
# ---------------------------------------------------------------------------

def test_shared_primitive_stays_unhealthy_on_persistent_failure():
    calls = {"n": 0}

    def _build():
        calls["n"] += 1
        raise ConnectionError("redis unreachable (simulated boot race)")

    healthy = {"v": False}
    result = common_selfheal.ensure(
        "test_stays_unhealthy",
        is_healthy=lambda: healthy["v"],
        build=_build,
        on_success=lambda v: healthy.__setitem__("v", True),
        cooldown_s=0.01,
        unavailable_msg="unavailable",
        recovered_msg="recovered",
    )
    assert result is False
    assert healthy["v"] is False
    assert calls["n"] == 1


def test_shared_primitive_reconnects_once_dependency_becomes_available():
    """THE core regression shape: initial-unavailable -> later-available.
    Pre-fix, nothing would ever call build() a second time."""
    calls = {"n": 0}

    def _build():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable (simulated boot race)")
        return "reconnected-object"

    state = {"v": None}
    is_healthy = lambda: state["v"] is not None  # noqa: E731

    # Attempt 1: still down.
    assert common_selfheal.ensure(
        "test_reconnects", is_healthy=is_healthy, build=_build,
        on_success=lambda v: state.__setitem__("v", v),
        cooldown_s=0.01, unavailable_msg="unavailable", recovered_msg="recovered",
    ) is False
    assert state["v"] is None

    time.sleep(0.02)  # bounded cooldown must elapse before a second attempt

    # Attempt 2: now reachable.
    assert common_selfheal.ensure(
        "test_reconnects", is_healthy=is_healthy, build=_build,
        on_success=lambda v: state.__setitem__("v", v),
        cooldown_s=0.01, unavailable_msg="unavailable", recovered_msg="recovered",
    ) is True
    assert state["v"] == "reconnected-object"
    assert calls["n"] == 2


def test_shared_primitive_healthy_path_never_calls_builder():
    calls = {"n": 0}

    def _build():
        calls["n"] += 1
        return "should-not-happen"

    assert common_selfheal.ensure(
        "test_healthy_noop", is_healthy=lambda: True, build=_build,
        on_success=lambda v: None, cooldown_s=0.01,
        unavailable_msg="unavailable", recovered_msg="recovered",
    ) is True
    assert calls["n"] == 0


def test_shared_primitive_reconnect_is_cooldown_bounded():
    calls = {"n": 0}

    def _build():
        calls["n"] += 1
        raise ConnectionError("still down")

    for _ in range(3):
        common_selfheal.ensure(
            "test_cooldown_bounded", is_healthy=lambda: False, build=_build,
            on_success=lambda v: None, cooldown_s=60.0,
            unavailable_msg="unavailable", recovered_msg="recovered",
        )
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# 2. #1 (P0, confirmed live blocker) — rbac_store / agent_registry /
#    capability_policy_store / permission_store
# ---------------------------------------------------------------------------

class _FakeGatewayRBACAgentStack:
    def __init__(self, tag: str):
        self.rbac_store = f"rbac_store::{tag}"
        self.agent_registry = f"agent_registry::{tag}"
        self.capability_policy_store = f"capability_policy_store::{tag}"
        self.permission_store = f"permission_store::{tag}"
        self.redis_client = f"redis_client::{tag}"


def test_rbac_agent_stack_reconnects_and_populates_every_consumer(monkeypatch, app_state):
    """THE core regression for the live-reproduced bug: agent_registry stays
    None after a failed cold-boot attempt, then a later-available Redis must
    populate EVERY consumer this finding's live evidence showed broken —
    openai_router._state (chat_completions' `agent_registry_unavailable`
    check reads this live), gateway_fallback_state (AgentAuthMiddleware's
    fallback), and app_state (proxy.py's `_state` dict, exposed via
    app.state.internal_state to every other proxy.py consumer)."""
    oai = _gw_oai()  # live module — see _gw_oai() docstring
    calls = {"n": 0}

    def _fails_then_succeeds(url):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable (simulated k8s DNS race)")
        return _FakeGatewayRBACAgentStack("reconnected")

    monkeypatch.setattr(
        "yashigani.gateway.rbac_stack.build_rbac_agent_stack", _fails_then_succeeds
    )
    monkeypatch.setattr(
        "yashigani.gateway._redis_url.build_redis_url", lambda *a, **k: "redis://fake"
    )
    monkeypatch.setattr(oai, "_load_token_role_map", lambda registry: None)

    # Pre-fix shape: chat_completions's exact live gate — "agent_registry_unavailable".
    assert oai._state.agent_registry is None

    # Attempt 1 — Redis still down (mirrors t=0..31s of the k8s boot race,
    # after the startup retry loop already gave up).
    assert gw_selfheal.ensure_rbac_agent_stack(app_state, cooldown_s=0.01) is False
    assert oai._state.agent_registry is None

    time.sleep(0.02)

    # Attempt 2 — Redis now reachable (mirrors t=31s+epsilon, redis Pod up).
    assert gw_selfheal.ensure_rbac_agent_stack(app_state, cooldown_s=0.01) is True

    # The confirmed blocker: chat's live gate is now satisfied.
    assert oai._state.agent_registry == "agent_registry::reconnected"
    assert oai._state.rbac_store == "rbac_store::reconnected"
    assert oai._state.permission_store == "permission_store::reconnected"

    # AgentAuthMiddleware's fallback (gateway/agent_auth.py).
    assert gateway_fallback_state.agent_registry == "agent_registry::reconnected"
    assert gateway_fallback_state.rbac_store == "rbac_store::reconnected"

    # proxy.py's per-app state dict (security_headers, rate limiter RBAC
    # override lookup, etc. all read this live).
    assert app_state["rbac_store"] == "rbac_store::reconnected"
    assert app_state["agent_registry"] == "agent_registry::reconnected"
    assert app_state["capability_policy_store"] == "capability_policy_store::reconnected"
    assert app_state["permission_store"] == "permission_store::reconnected"

    assert calls["n"] == 2


def test_rbac_agent_stack_healthy_path_never_calls_builder(monkeypatch, app_state):
    oai = _gw_oai()  # live module — see _gw_oai() docstring
    calls = {"n": 0}

    def _should_never_run(url):
        calls["n"] += 1
        return _FakeGatewayRBACAgentStack("should-not-happen")

    monkeypatch.setattr(
        "yashigani.gateway.rbac_stack.build_rbac_agent_stack", _should_never_run
    )
    oai._state.agent_registry = "already-healthy"

    assert gw_selfheal.ensure_rbac_agent_stack(app_state, cooldown_s=0.01) is True
    assert calls["n"] == 0


def test_build_rbac_agent_stack_against_real_fakeredis(mock_redis, monkeypatch):
    """Docker/podman parity check: when Redis IS reachable (the normal case —
    compose ordering via depends_on), build_rbac_agent_stack() must construct
    every store exactly as before, with no regression from the extraction out
    of entrypoint._build_app()."""
    from yashigani.gateway.rbac_stack import build_rbac_agent_stack

    monkeypatch.setattr("redis.from_url", lambda *a, **k: mock_redis)

    stack = build_rbac_agent_stack("redis://fake:6379/3")

    assert stack.rbac_store is not None
    assert stack.agent_registry is not None
    assert stack.capability_policy_store is not None
    assert stack.permission_store is not None
    assert stack.redis_client is mock_redis


# ---------------------------------------------------------------------------
# 3. AgentAuthMiddleware fallback (gateway/agent_auth.py)
# ---------------------------------------------------------------------------

def test_agent_auth_middleware_falls_back_to_gateway_fallback_state():
    """Pre-fix: AgentAuthMiddleware snapshots agent_registry BY VALUE at
    __init__ time. If cold-boot construction failed (registry=None), every
    /agents/* request 503'd forever, even after redis_selfheal.py repopulated
    every OTHER consumer, because this middleware never re-read anything.
    Post-fix: the middleware falls back to gateway_fallback_state.agent_registry,
    which redis_selfheal.py keeps updated independently."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
    from yashigani.gateway.agent_auth import AgentAuthMiddleware

    class _FakeRegistry:
        def verify_token(self, agent_id, token):
            return agent_id == "caller-1" and token == "good-token"

        def get(self, agent_id):
            # FIND-0813-013: the middleware requires an ACTIVE registration in
            # addition to a verifying token, and defaults to reject when the
            # status field is absent. This stub models a real active agent so
            # the test still exercises what it is actually about — the
            # gateway_fallback_state recovery path — rather than tripping the
            # status gate before it gets there.
            return {"status": "active", "allowed_cidrs": []}

    async def handler(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/agents/target-1/do-thing", handler)])

    # Constructed with agent_registry=None — the exact pre-fix cold-boot-failed shape.
    app.add_middleware(AgentAuthMiddleware, agent_registry=None, audit_writer=None)
    client = TestClient(app)

    # Before self-heal: registry_unavailable (503) is correct fail-closed behaviour.
    resp = client.get(
        "/agents/target-1/do-thing",
        headers={
            "authorization": "Bearer good-token",
            "x-yashigani-caller-agent-id": "caller-1",
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"] == "AGENT_REGISTRY_UNAVAILABLE"

    # redis_selfheal.py reconnects and populates the fallback singleton —
    # simulates ensure_rbac_agent_stack()'s on_success callback firing.
    gateway_fallback_state.agent_registry = _FakeRegistry()

    # Same middleware instance, same (still-None) constructor snapshot — the
    # NEXT request must now succeed via the fallback, proving no restart is
    # needed for this consumer to recover either.
    resp2 = client.get(
        "/agents/target-1/do-thing",
        headers={
            "authorization": "Bearer good-token",
            "x-yashigani-caller-agent-id": "caller-1",
        },
    )
    assert resp2.status_code == 200


# ---------------------------------------------------------------------------
# 4. Representative siblings (findings #2-13) — proves the pattern
#    generalises, not just the P0 row.
# ---------------------------------------------------------------------------

def test_ensure_rate_limiter_reconnects(monkeypatch, app_state):
    """#2 — proxy.py-only consumer (app_state dict)."""
    calls = {"n": 0}

    class _FakeRateLimiter:
        pass

    def _fails_then_succeeds():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable")
        return _FakeRateLimiter()

    monkeypatch.setattr(gw_selfheal, "_build_rate_limiter", _fails_then_succeeds)

    assert gw_selfheal.ensure_rate_limiter(app_state, cooldown_s=0.01) is False
    assert app_state.get("rate_limiter") is None
    time.sleep(0.02)
    assert gw_selfheal.ensure_rate_limiter(app_state, cooldown_s=0.01) is True
    assert isinstance(app_state["rate_limiter"], _FakeRateLimiter)


def test_ensure_egress_limit_enforcer_reconnects(monkeypatch):
    """#13 — its own module-level state (egress_proxy._state), independent
    of both openai_router._state and proxy.py's app_state dict."""
    calls = {"n": 0}

    def _fails_then_succeeds():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable")
        return "egress_limit_enforcer::reconnected"

    monkeypatch.setattr(gw_selfheal, "_build_egress_limit_enforcer", _fails_then_succeeds)

    assert egress_proxy._state.egress_limit_enforcer is None
    assert gw_selfheal.ensure_egress_limit_enforcer(cooldown_s=0.01) is False
    time.sleep(0.02)
    assert gw_selfheal.ensure_egress_limit_enforcer(cooldown_s=0.01) is True
    assert egress_proxy._state.egress_limit_enforcer == "egress_limit_enforcer::reconnected"


def test_ensure_ddos_protector_dual_writes_both_consumers(monkeypatch, app_state):
    """#12 — dual-consumer: openai_router._state.ddos_protector AND
    proxy.py's app_state["ddos_protector"] must BOTH get the rebuilt object."""
    oai = _gw_oai()  # live module — see _gw_oai() docstring
    def _build():
        return "ddos_protector::reconnected"

    monkeypatch.setattr(gw_selfheal, "_build_ddos_protector", _build)

    assert gw_selfheal.ensure_ddos_protector(app_state, cooldown_s=0.01) is True
    assert oai._state.ddos_protector == "ddos_protector::reconnected"
    assert app_state["ddos_protector"] == "ddos_protector::reconnected"


# ---------------------------------------------------------------------------
# 5. maybe_selfheal() orchestrator — async dispatch + workflow_scheduler's
#    deferred .start() (must run on the event loop, never inside the
#    asyncio.to_thread worker thread the builder executes in).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_maybe_selfheal_dispatches_only_unhealthy_subsystems(monkeypatch, app_state):
    oai = _gw_oai()  # live module — see _gw_oai() docstring
    call_log: list[str] = []

    def _mk(tag, value):
        def _fn(*a, **k):
            call_log.append(tag)
            return True
        return _fn

    # Mark everything except rbac_agent_stack as already healthy so only ONE
    # dispatch should fire.
    oai._state.identity_registry = "already-healthy"
    oai._state.budget_enforcer = "already-healthy"
    oai._state.model_allocation_store = "already-healthy"
    oai._state.model_alias_store = "already-healthy"
    oai._state.ddos_protector = "already-healthy"
    egress_proxy._state.egress_limit_enforcer = "already-healthy"
    app_state["rate_limiter"] = "already-healthy"
    app_state["endpoint_rate_limiter"] = "already-healthy"
    app_state["response_cache"] = "already-healthy"
    app_state["jwt_inspector"] = "already-healthy"
    app_state["workflow_scheduler"] = "already-healthy"

    monkeypatch.setattr(gw_selfheal, "ensure_rbac_agent_stack", _mk("rbac_agent_stack", True))

    await gw_selfheal.maybe_selfheal(app_state)

    assert call_log == ["rbac_agent_stack"]


@pytest.mark.asyncio
async def test_maybe_selfheal_starts_workflow_scheduler_on_event_loop(monkeypatch, app_state):
    """WorkflowScheduler.start() calls asyncio.ensure_future() and MUST run on
    the event loop — never inside the asyncio.to_thread() worker thread the
    builder executes in (that would raise "no running event loop"). This
    proves maybe_selfheal() defers the actual .start() call to the coroutine
    itself, after the (thread-dispatched) ensure_workflow_scheduler() call
    returns, rather than calling it inside the builder.
    """
    oai = _gw_oai()  # live module — see _gw_oai() docstring
    # Every OTHER subsystem already healthy so only workflow_scheduler dispatches.
    oai._state.agent_registry = "already-healthy"
    oai._state.identity_registry = "already-healthy"
    oai._state.budget_enforcer = "already-healthy"
    oai._state.model_allocation_store = "already-healthy"
    oai._state.model_alias_store = "already-healthy"
    oai._state.ddos_protector = "already-healthy"
    egress_proxy._state.egress_limit_enforcer = "already-healthy"
    app_state["rate_limiter"] = "already-healthy"
    app_state["endpoint_rate_limiter"] = "already-healthy"
    app_state["response_cache"] = "already-healthy"
    app_state["jwt_inspector"] = "already-healthy"

    started_from_thread = {"v": None}

    class _FakeScheduler:
        def start(self):
            try:
                asyncio.get_running_loop()
                started_from_thread["v"] = False
            except RuntimeError:
                started_from_thread["v"] = True

    def _fake_ensure_workflow_scheduler(app_state, cooldown_s=15.0):
        app_state["workflow_scheduler"] = _FakeScheduler()
        return True

    monkeypatch.setattr(
        gw_selfheal, "ensure_workflow_scheduler", _fake_ensure_workflow_scheduler
    )

    await gw_selfheal.maybe_selfheal(app_state)

    assert isinstance(app_state["workflow_scheduler"], _FakeScheduler)
    # .start() must have run WITH a running event loop available (i.e. on
    # the coroutine, not inside the to_thread worker thread).
    assert started_from_thread["v"] is False
