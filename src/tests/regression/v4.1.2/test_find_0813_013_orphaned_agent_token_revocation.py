"""FIND-0813-013 / SEC-001 — orphaned agent tokens remain valid after
deactivate() (red panel finding, Nico, 2026-08-13).

Chain (see red-sec001-nico.md):
  a) Migration 0017 deliberately drops UNIQUE (tenant_id, agent_name)
     (MUST-FIX-2, Iris 2026-06-10) — agent_id is the only unique key, so a
     re-registration under a colliding name creates a SECOND active row
     under a NEW agent_id while the old row/token stays live.
  b) AgentRegistry.deactivate() (registry.py) — the ONLY documented manual
     remediation ("deactivate the stale one") — flipped status + index
     membership but never deleted agent:token:{agent_id}, so the bcrypt
     hash kept verifying.
  c) AgentAuthMiddleware.dispatch() (gateway/agent_auth.py) called pure
     registry.verify_token() and never consulted `status` at all — so even
     if an operator noticed and deactivated the stale row by hand, the
     token authenticated exactly as before.

This file proves the fix in both directions against the REAL AgentRegistry
+ REAL AgentAuthMiddleware (fakeredis, no mocks of the thing under test):
  1. A deactivated agent's token no longer authenticates (401).
  2. An active agent's token is unaffected (200) — the regression risk.
  3. The Redis token key (agent:token:{agent_id}) is actually gone after
     deactivate(), not just the index/status flip.

Each behavioural test is written to demonstrably FAIL against the pre-fix
code (YTF §4: "a check that cannot fail is not a check") — see the inline
notes on exactly which pre-fix line each assertion pins.
"""
from __future__ import annotations

import pytest

fakeredis = pytest.importorskip("fakeredis")

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from yashigani.agents.registry import AgentRegistry  # noqa: E402
from yashigani.gateway.agent_auth import AgentAuthMiddleware  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def _redis():
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    client.flushall()


@pytest.fixture
def _license(monkeypatch):
    """Stub the licence enforcer so register() does not need a real licence."""
    class _Lic:
        max_agents = -1  # unlimited

    monkeypatch.setattr("yashigani.licensing.enforcer.get_license", lambda: _Lic())


def _build_app(registry):
    app = FastAPI()
    received_state: dict = {}

    @app.post("/agents/target-agent/v1/chat/completions")
    async def agent_route(request: Request):
        received_state["agent_id"] = getattr(request.state, "agent_id", None)
        return {"ok": True}

    app.add_middleware(AgentAuthMiddleware, agent_registry=registry, audit_writer=None)
    return app, received_state


def _call(app, token: str, caller_agent_id: str):
    client = TestClient(app, raise_server_exceptions=False)
    return client.post(
        "/agents/target-agent/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Yashigani-Caller-Agent-Id": caller_agent_id,
        },
        json={"model": "x", "messages": []},
    )


# ---------------------------------------------------------------------------
# 1. Deactivated agent's token must no longer authenticate.
# ---------------------------------------------------------------------------

def test_deactivated_agent_token_rejected_end_to_end(_redis, _license):
    """The manual remediation an operator is told to use ("deactivate the
    stale one") must actually revoke the credential end-to-end through the
    real middleware, not just flip a status field nothing reads.

    Pre-fix this FAILS: registry.py:451-469's verify_token() is pure
    bcrypt.checkpw against agent:token:{agent_id}, which deactivate()
    (pre-fix registry.py:347-365) never deleted; agent_auth.py:140 called
    only verify_token() and never checked status — so the request would
    return 200, not 401.
    """
    registry = AgentRegistry(redis_client=_redis)
    agent_id, plaintext_token = registry.register(
        name="stale-agent",
        upstream_url="http://stale.internal:8080",
        groups=[],
        allowed_caller_groups=[],
        allowed_paths=["**"],
    )

    # Token works before deactivation (sanity — proves this isn't a broken fixture).
    app, _ = _build_app(registry)
    resp_before = _call(app, plaintext_token, agent_id)
    assert resp_before.status_code == 200

    registry.deactivate(agent_id)

    app2, _ = _build_app(registry)
    resp_after = _call(app2, plaintext_token, agent_id)
    assert resp_after.status_code == 401, (
        f"deactivated agent's PSK still authenticated end-to-end -- "
        f"got {resp_after.status_code}: {resp_after.text}"
    )
    assert resp_after.json().get("reason") in ("invalid_token", "caller_agent_inactive")


def test_orphaned_row_from_name_collision_is_revocable(_redis, _license):
    """The EXACT chain from the finding: migration 0017 lets a second
    register() under the SAME name mint a second, independent agent_id +
    token while the first stays 'active' by default. Deactivating the
    superseded (first) row must revoke ONLY that row's token, leaving the
    new registration's token untouched -- and must actually work, proving
    part (a)+(b) of the chain are both closed by this fix.
    """
    registry = AgentRegistry(redis_client=_redis)

    old_id, old_token = registry.register(
        name="dup-agent", upstream_url="http://a:1", groups=[],
        allowed_caller_groups=[], allowed_paths=["**"],
    )
    new_id, new_token = registry.register(
        name="dup-agent", upstream_url="http://b:2", groups=[],
        allowed_caller_groups=[], allowed_paths=["**"],
    )
    assert old_id != new_id  # migration 0017: name collision allowed by design

    # Both rows verify before remediation.
    assert registry.verify_token(old_id, old_token) is True
    assert registry.verify_token(new_id, new_token) is True

    # Operator remediation: deactivate the stale (old) row.
    registry.deactivate(old_id)

    app_old, _ = _build_app(registry)
    resp_old = _call(app_old, old_token, old_id)
    assert resp_old.status_code == 401, "orphaned duplicate-name row's token must be revoked"

    app_new, _ = _build_app(registry)
    resp_new = _call(app_new, new_token, new_id)
    assert resp_new.status_code == 200, "the SURVIVING registration must be unaffected"


# ---------------------------------------------------------------------------
# 2. Active agent's token must be unaffected — the regression risk.
# ---------------------------------------------------------------------------

def test_active_agent_token_still_authenticates(_redis, _license):
    """The core regression risk named in the brief: the new status-aware
    check must not lock out a normal, never-deactivated agent.

    This assertion could not have failed pre-fix (status wasn't checked at
    all) -- its job is to fail if the NEW check is implemented too
    aggressively (e.g. rejecting on a missing/blank field for a real,
    freshly-registered agent).
    """
    registry = AgentRegistry(redis_client=_redis)
    agent_id, plaintext_token = registry.register(
        name="healthy-agent",
        upstream_url="http://healthy.internal:8080",
        groups=["engineering"],
        allowed_caller_groups=["engineering"],
        allowed_paths=["**"],
    )

    app, received_state = _build_app(registry)
    resp = _call(app, plaintext_token, agent_id)
    assert resp.status_code == 200, (
        f"active agent's PSK must still authenticate -- got {resp.status_code}: {resp.text}"
    )
    assert received_state["agent_id"] == agent_id


def test_reactivating_is_not_in_scope_but_wrong_token_still_rejected(_redis, _license):
    """Sanity guard: the new status check must not become a substitute for
    token verification -- a WRONG token for an active agent is still 401
    (this would also catch an accidental 'any token + active agent = pass'
    regression)."""
    registry = AgentRegistry(redis_client=_redis)
    agent_id, _plaintext_token = registry.register(
        name="healthy-agent-2",
        upstream_url="http://healthy2.internal:8080",
        groups=[], allowed_caller_groups=[], allowed_paths=["**"],
    )
    app, _ = _build_app(registry)
    resp = _call(app, "wrong" * 20, agent_id)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. The Redis token key must actually be deleted by deactivate().
# ---------------------------------------------------------------------------

def test_deactivate_deletes_redis_token_key(_redis, _license):
    """Direct proof at the storage layer, independent of the middleware:
    deactivate() must DELETE agent:token:{agent_id}, not merely flip status.

    Pre-fix this FAILS: registry.py:347-365's deactivate() only called
    hset(status=inactive) + srem on the index sets -- GET agent:token:{id}
    would still return the bcrypt hash unchanged.
    """
    registry = AgentRegistry(redis_client=_redis)
    agent_id, plaintext_token = registry.register(
        name="key-check-agent",
        upstream_url="http://kc.internal:8080",
        groups=[], allowed_caller_groups=[], allowed_paths=["**"],
    )
    token_key = f"agent:token:{agent_id}"
    assert _redis.get(token_key) is not None  # present pre-deactivate (sanity)

    registry.deactivate(agent_id)

    assert _redis.get(token_key) is None, (
        "deactivate() left agent:token:{agent_id} in place -- the PSK "
        "material was not actually revoked, only the status flag was flipped"
    )
    # And the index-level bookkeeping the pre-fix code DID do is still correct.
    agent = registry.get(agent_id)
    assert agent["status"] == "inactive"
    assert agent_id not in {a["agent_id"] for a in registry.list_active()}

    # bcrypt.checkpw against a deleted key must also fail-closed at the
    # registry layer directly (not just via the middleware).
    assert registry.verify_token(agent_id, plaintext_token) is False


def test_deactivate_deletes_grace_token_key(_redis, _license):
    """token_rotation.py's grace-period hash (agent:token:grace:{agent_id})
    is the same credential family (previous PSK, still bcrypt-verifiable
    during the rotation grace window) -- deactivate() must clear it too so a
    recently-rotated-then-deactivated agent's OLD token cannot be used as a
    fallback credential.
    """
    from yashigani.agents.token_rotation import rotate_agent_token

    registry = AgentRegistry(redis_client=_redis)
    agent_id, _first_token = registry.register(
        name="grace-check-agent",
        upstream_url="http://gc.internal:8080",
        groups=[], allowed_caller_groups=[], allowed_paths=["**"],
    )
    rotate_agent_token(agent_id, registry, grace_period_hours=1)

    grace_key = f"agent:token:grace:{agent_id}"
    assert _redis.get(grace_key) is not None  # grace hash present (sanity)

    registry.deactivate(agent_id)

    assert _redis.get(grace_key) is None, (
        "deactivate() left the grace-period token hash in place"
    )


def test_reconcile_does_not_resurrect_a_revoked_token(_redis, _license):
    """Adjacent gap closed alongside deactivate(): restore_from_durable()
    (the startup Postgres->Redis reconciler) must not blindly re-materialise
    a revoked agent's token key. AgentDurableStore.set_status() mirrors the
    status flip into Postgres but retains the historical token_hash column
    (audit trail) -- if the reconciler restored it unconditionally, a Redis
    db/3 wipe (appendonly no / save "") followed by reconcile would silently
    un-revoke a deliberately deactivated agent.
    """
    import asyncio

    class _FakeDurableStore:
        def __init__(self):
            self.rows: dict[str, dict] = {}

        def upsert(self, agent, token_hash=None):
            aid = agent["agent_id"]
            existing = self.rows.get(aid, {})
            row = dict(agent)
            row["token_hash"] = token_hash if token_hash is not None else existing.get("token_hash")
            self.rows[aid] = row

        def set_status(self, agent_id, status):
            if agent_id in self.rows:
                self.rows[agent_id]["status"] = status

        async def list_all(self):
            return [dict(r) for r in self.rows.values()]

    from yashigani.agents.reconciler import reconcile_agents_from_durable

    durable = _FakeDurableStore()
    registry = AgentRegistry(redis_client=_redis, durable_store=durable)
    agent_id, plaintext_token = registry.register(
        name="reconcile-revoke-agent",
        upstream_url="http://rr.internal:8080",
        groups=[], allowed_caller_groups=[], allowed_paths=["**"],
    )
    registry.deactivate(agent_id)
    assert registry.verify_token(agent_id, plaintext_token) is False

    # Simulate a Redis db/3 wipe + startup reconcile from the durable store,
    # which still holds the historical token_hash for this (now inactive) row.
    _redis.flushall()
    asyncio.run(reconcile_agents_from_durable(registry, durable))

    assert registry.verify_token(agent_id, plaintext_token) is False, (
        "reconcile resurrected a revoked agent's token after a redis wipe"
    )
    assert _redis.get(f"agent:token:{agent_id}") is None
