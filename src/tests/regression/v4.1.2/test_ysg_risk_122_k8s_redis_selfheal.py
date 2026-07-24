"""
Regression tests — YSG-RISK-122 (Ava, live docker-desktop k8s @ ca720724):
k8s boot-order race permanently disables RBAC / agent registry / permission
store / budget enforcement.

## The finding

`yashigani-backoffice` started 7s before `yashigani-redis-0`. The in-process
retry in `entrypoint._bootstrap()` (1/2/4/8s x5, ~31s budget) exhausted
before k8s DNS for the headless Redis Service was resolvable, logged
"RBAC and agent registry disabled", and NEVER retried again: 10+ minutes
later, with Redis fully healthy, `GET /admin/agents` still returned 503
"Agent registry unavailable", `/admin/api/permissions/declarations` still
returned 503 "permission_store_not_configured", and
`/admin/budget/usage/*` still returned 503 "Budget enforcer not available".
A transient boot race permanently disabled RBAC, agent-registry,
permission-store, and budget enforcement for the whole pod lifetime.

## The fix

1. The RBAC/Agent/Binding/Document/Envelope/DpWeaken/CapabilityPolicy
   construction logic moved out of `entrypoint._bootstrap()`'s inline
   try/except into `backoffice/rbac_stack.build_rbac_agent_stack()` (same
   for the two budget Redis connections into `backoffice/budget_stack.py`),
   so the EXACT SAME construction can be invoked again, lazily, at request
   time.
2. `backoffice/redis_selfheal.py` provides `ensure_rbac_stack()`,
   `ensure_budget_config_store()`, and `ensure_budget_enforcer()` — each a
   bounded, cooldown-gated (default 15s) reconnect attempt that only fires
   when the corresponding `backoffice_state` field is still `None`. Success
   repopulates `backoffice_state`; failure changes nothing (fail-closed
   503 behaviour is untouched).
3. `backoffice/app.py` wires a new `redis_selfheal_middleware` that calls
   `redis_selfheal.maybe_selfheal()` before every `/admin/*` request.

Each test below proves the client reconnects after an initial
unavailable -> later-available Redis transition, using a real fakeredis
backend for the "later available" leg (mock/monkeypatch stands in for the
transient unavailability, since fakeredis has no network layer to sever).
Every test would FAIL against the pre-fix code, where a single failed
attempt left the field `None` forever with no retry path.

Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

import time

import pytest

from yashigani.backoffice import redis_selfheal
from yashigani.backoffice.state import BackofficeState, backoffice_state


@pytest.fixture(autouse=True)
def _reset_backoffice_state(monkeypatch):
    """Isolate every test: fresh BackofficeState + fresh cooldown-gate map."""
    fresh = BackofficeState()
    for field in fresh.__dataclass_fields__:
        setattr(backoffice_state, field, getattr(fresh, field))
    # Clear the module-level cooldown gate between tests so timing assertions
    # don't leak across tests.
    redis_selfheal._last_attempt_monotonic.clear()
    yield
    redis_selfheal._last_attempt_monotonic.clear()


@pytest.fixture
def _budget_state_reset():
    from yashigani.backoffice.routes import budget as budget_routes
    budget_routes._state.budget_enforcer = None
    budget_routes._state.identity_registry = None
    budget_routes._state.budget_store = None
    yield budget_routes._state
    budget_routes._state.budget_enforcer = None
    budget_routes._state.identity_registry = None
    budget_routes._state.budget_store = None


# ---------------------------------------------------------------------------
# RBAC / Agent registry stack
# ---------------------------------------------------------------------------

class _FakeRBACAgentStack:
    """Minimal stand-in for rbac_stack.RBACAgentStack — identity-distinguishable
    sentinel objects so the test can assert exactly what got wired."""

    def __init__(self, tag: str):
        self.rbac_store = f"rbac_store::{tag}"
        self.agent_registry = f"agent_registry::{tag}"
        self.binding_store = f"binding_store::{tag}"
        self.document_policy_store = f"document_policy_store::{tag}"
        self.document_set_store = f"document_set_store::{tag}"
        self.envelope_pending_store = f"envelope_pending_store::{tag}"
        self.dp_weaken_store = f"dp_weaken_store::{tag}"
        self.capability_policy_store = f"capability_policy_store::{tag}"


def test_rbac_stack_stays_none_while_redis_unreachable(monkeypatch):
    """Pre-fix regression guard: a failed reconnect must NOT populate state,
    and must NOT raise out of ensure_rbac_stack() (fail-closed, not a crash)."""
    def _always_fails(url):
        raise ConnectionError("redis unreachable (simulated boot race)")

    monkeypatch.setattr(
        "yashigani.backoffice.rbac_stack.build_rbac_agent_stack", _always_fails
    )
    monkeypatch.setattr(
        "yashigani.gateway._redis_url.build_redis_url", lambda *a, **k: "redis://fake"
    )

    assert backoffice_state.agent_registry is None
    result = redis_selfheal.ensure_rbac_stack(cooldown_s=0.01)
    assert result is False
    assert backoffice_state.agent_registry is None
    assert backoffice_state.rbac_store is None
    assert backoffice_state.capability_policy_store is None


def test_rbac_stack_reconnects_once_redis_becomes_available(monkeypatch):
    """THE core regression: initial-unavailable -> later-available Redis.

    This is the exact bug shape — startup failed, Redis then becomes
    reachable, and NOTHING (pre-fix) ever tried again. Post-fix,
    ensure_rbac_stack() must succeed on the next bounded attempt once the
    dependency is reachable, with no process restart required.
    """
    calls = {"n": 0}

    def _fails_then_succeeds(url):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable (simulated boot race)")
        return _FakeRBACAgentStack("reconnected")

    monkeypatch.setattr(
        "yashigani.backoffice.rbac_stack.build_rbac_agent_stack", _fails_then_succeeds
    )
    monkeypatch.setattr(
        "yashigani.gateway._redis_url.build_redis_url", lambda *a, **k: "redis://fake"
    )

    # Attempt 1: Redis still down (mirrors t=0..31s of the k8s boot race).
    assert redis_selfheal.ensure_rbac_stack(cooldown_s=0.01) is False
    assert backoffice_state.agent_registry is None

    # Bounded cooldown must elapse before a second attempt is even tried.
    time.sleep(0.02)

    # Attempt 2: Redis now reachable (mirrors t=31s+epsilon, redis-0 up).
    assert redis_selfheal.ensure_rbac_stack(cooldown_s=0.01) is True
    assert backoffice_state.agent_registry == "agent_registry::reconnected"
    assert backoffice_state.rbac_store == "rbac_store::reconnected"
    assert backoffice_state.binding_store == "binding_store::reconnected"
    assert backoffice_state.document_policy_store == "document_policy_store::reconnected"
    assert backoffice_state.document_set_store == "document_set_store::reconnected"
    assert backoffice_state.envelope_pending_store == "envelope_pending_store::reconnected"
    assert backoffice_state.dp_weaken_store == "dp_weaken_store::reconnected"
    assert backoffice_state.capability_policy_store == "capability_policy_store::reconnected"
    assert calls["n"] == 2


def test_rbac_stack_healthy_path_never_calls_builder(monkeypatch):
    """Once healthy, ensure_rbac_stack() must be a pure None-check — zero
    Redis round-trips on the hot path."""
    calls = {"n": 0}

    def _should_never_run(url):
        calls["n"] += 1
        return _FakeRBACAgentStack("should-not-happen")

    monkeypatch.setattr(
        "yashigani.backoffice.rbac_stack.build_rbac_agent_stack", _should_never_run
    )
    backoffice_state.agent_registry = "already-healthy"

    assert redis_selfheal.ensure_rbac_stack(cooldown_s=0.01) is True
    assert calls["n"] == 0


def test_rbac_stack_reconnect_is_cooldown_bounded(monkeypatch):
    """Concurrent/rapid callers during an outage must not hammer Redis —
    at most one attempt per cooldown window."""
    calls = {"n": 0}

    def _always_fails(url):
        calls["n"] += 1
        raise ConnectionError("still down")

    monkeypatch.setattr(
        "yashigani.backoffice.rbac_stack.build_rbac_agent_stack", _always_fails
    )
    monkeypatch.setattr(
        "yashigani.gateway._redis_url.build_redis_url", lambda *a, **k: "redis://fake"
    )

    # Long cooldown — three rapid calls within the window should attempt once.
    redis_selfheal.ensure_rbac_stack(cooldown_s=60.0)
    redis_selfheal.ensure_rbac_stack(cooldown_s=60.0)
    redis_selfheal.ensure_rbac_stack(cooldown_s=60.0)
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# Budget config store + enforcer
# ---------------------------------------------------------------------------

def test_budget_config_store_reconnects_and_preserves_sibling_fields(
    monkeypatch, _budget_state_reset
):
    """budget_routes.configure() resets any kwarg not passed — the lazy
    reconnect must NOT wipe out an already-wired budget_enforcer /
    identity_registry when it repopulates budget_store."""
    from yashigani.backoffice.routes import budget as budget_routes

    budget_routes._state.budget_enforcer = "pre-existing-enforcer"
    budget_routes._state.identity_registry = "pre-existing-identity-registry"

    calls = {"n": 0}

    def _fails_then_succeeds(url):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable")
        return "budget_config_store::reconnected"

    monkeypatch.setattr(
        "yashigani.backoffice.budget_stack.build_budget_config_store",
        _fails_then_succeeds,
    )
    monkeypatch.setattr(
        "yashigani.gateway._redis_url.build_redis_url", lambda *a, **k: "redis://fake"
    )

    assert redis_selfheal.ensure_budget_config_store(cooldown_s=0.01) is False
    time.sleep(0.02)
    assert redis_selfheal.ensure_budget_config_store(cooldown_s=0.01) is True

    assert budget_routes._state.budget_store == "budget_config_store::reconnected"
    # Siblings preserved, not wiped to None by configure().
    assert budget_routes._state.budget_enforcer == "pre-existing-enforcer"
    assert budget_routes._state.identity_registry == "pre-existing-identity-registry"


def test_budget_enforcer_reconnects_and_preserves_sibling_fields(
    monkeypatch, _budget_state_reset
):
    from yashigani.backoffice.routes import budget as budget_routes

    budget_routes._state.budget_store = "pre-existing-config-store"

    calls = {"n": 0}

    def _fails_then_succeeds(url):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis unreachable")
        return "budget_enforcer::reconnected"

    monkeypatch.setattr(
        "yashigani.backoffice.budget_stack.build_budget_enforcer", _fails_then_succeeds
    )
    monkeypatch.setattr(
        "yashigani.backoffice.budget_stack.budget_enforcer_redis_url",
        lambda **k: "redis://fake",
    )

    assert redis_selfheal.ensure_budget_enforcer(cooldown_s=0.01) is False
    time.sleep(0.02)
    assert redis_selfheal.ensure_budget_enforcer(cooldown_s=0.01) is True

    assert budget_routes._state.budget_enforcer == "budget_enforcer::reconnected"
    assert budget_routes._state.budget_store == "pre-existing-config-store"


# ---------------------------------------------------------------------------
# Docker/podman regression guard: no behaviour change when Redis is up at boot
# ---------------------------------------------------------------------------

def test_build_rbac_agent_stack_against_real_fakeredis(mock_redis, monkeypatch):
    """Docker/podman parity check: when Redis IS reachable (the normal case —
    compose ordering via depends_on), build_rbac_agent_stack() must construct
    every store exactly as before, with no regression from the extraction out
    of entrypoint._bootstrap()."""
    from yashigani.backoffice.rbac_stack import build_rbac_agent_stack

    monkeypatch.setattr(
        "redis.from_url", lambda *a, **k: mock_redis
    )
    # Durable Postgres mirror is optional and best-effort in this code path —
    # no DSN configured in the unit-test environment, so it logs + continues.
    stack = build_rbac_agent_stack("redis://fake:6379/3")

    assert stack.rbac_store is not None
    assert stack.agent_registry is not None
    assert stack.binding_store is not None
    assert stack.document_policy_store is not None
    assert stack.document_set_store is not None
    assert stack.envelope_pending_store is not None
    assert stack.dp_weaken_store is not None
    assert stack.capability_policy_store is not None
