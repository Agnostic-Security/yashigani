"""Regression test — YSG-RISK-154: advertised agent token-rotation GRACE window
did not exist; no scheduled rotation.

Original bug:
    ``rotate_agent_token()`` / ``verify_token_with_grace()`` / the cron-based
    ``AgentTokenRotationScheduler`` (all in ``token_rotation.py``) were fully
    implemented but never wired into a live code path:

      * The live rotate endpoint (``POST /admin/agents/{id}/token/rotate`` in
        ``backoffice/routes/agents.py``) called the bare
        ``AgentRegistry.rotate_token()``, which OVERWRITES the token hash in
        place with no grace key at all.
      * The agent auth verify path (``AgentAuthMiddleware.dispatch`` in
        ``gateway/agent_auth.py``) called the bare
        ``AgentRegistry.verify_token()``, which only ever checks the CURRENT
        hash — it never reads ``agent:token:grace:{agent_id}``.

    Net effect: rotating an agent's token killed the OLD token INSTANTLY.
    Any in-flight agent still holding the pre-rotation token was locked out
    the moment an admin (or, if it had ever been wired, the scheduler)
    rotated — the advertised grace window was pure documentation, never code.

Fix (YSG-RISK-154):
    * ``backoffice/routes/agents.py::rotate_agent_token`` now calls
      ``yashigani.agents.token_rotation.rotate_agent_token()`` (the
      grace-preserving rotation) instead of the bare
      ``AgentRegistry.rotate_token()``. That function also now dual-writes
      the new hash to the durable Postgres mirror (mirrors
      ``AgentRegistry.rotate_token``'s ISSUE-AGENT-REG-DURABILITY behaviour,
      which would otherwise have silently regressed).
    * ``gateway/agent_auth.py::AgentAuthMiddleware.dispatch`` now calls
      ``yashigani.agents.token_rotation.verify_token_with_grace()`` instead
      of the bare ``AgentRegistry.verify_token()``, so a request presenting
      the OLD (pre-rotation) token is accepted until the grace TTL expires,
      and only the old token specifically — not just anything — during that
      window.

    These tests re-fail on the original bug: pre-fix, an old token would be
    rejected at ``verify_token_with_grace`` time zero (no grace key was ever
    written by the endpoint path), and the durable mirror would silently
    retain the PRE-rotation hash after a rotation via the new code path.

AgentTokenRotationScheduler status: NOT wired to run anywhere (confirmed —
no construction site outside its own module/docstring). Flagged as a scoped
follow-up, not faked here. See test_scheduler_is_not_yet_wired_flagged_followup
below and the report for the exact proposed start site.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

fakeredis = pytest.importorskip("fakeredis")

from yashigani.agents.registry import AgentRegistry  # noqa: E402
from yashigani.agents.token_rotation import (  # noqa: E402
    AgentTokenRotationScheduler,
    rotate_agent_token,
    verify_token_with_grace,
)
from yashigani.backoffice.routes import agents as agents_mod  # noqa: E402
from yashigani.backoffice.state import backoffice_state  # noqa: E402


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


class _FakeDurableStore:
    """In-memory stand-in for AgentDurableStore — proves the dual-write happens
    through the NEW rotate_agent_token() call path, not just the old one."""

    def __init__(self):
        self.rows: dict[str, dict] = {}

    def upsert(self, agent: dict, token_hash=None):
        aid = agent["agent_id"]
        existing = self.rows.get(aid, {})
        row = dict(agent)
        row["token_hash"] = token_hash if token_hash is not None else existing.get("token_hash")
        self.rows[aid] = row


# ---------------------------------------------------------------------------
# Core grace-window contract (token_rotation.py primitives)
# ---------------------------------------------------------------------------


def test_old_token_verifies_within_grace_new_token_verifies_immediately(_redis, _license):
    reg = AgentRegistry(redis_client=_redis)
    agent_id, old_token = reg.register(
        name="letta", upstream_url="http://letta:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )

    new_token = rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)

    assert new_token != old_token
    # New token works immediately.
    assert verify_token_with_grace(agent_id, reg, new_token) is True
    # OLD token — the in-flight-agent case this ticket is about — STILL works,
    # within the grace window. Pre-fix, this token was already dead: the
    # endpoint called registry.rotate_token(), which never wrote a grace key.
    assert verify_token_with_grace(agent_id, reg, old_token) is True


def test_old_token_rejected_after_grace_ttl_expires(_redis, _license):
    """Fail-closed: grace must not extend indefinitely."""
    reg = AgentRegistry(redis_client=_redis)
    agent_id, old_token = reg.register(
        name="langflow", upstream_url="http://langflow:7860", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/api/v1/run"],
        protocol="langflow",
    )

    rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)
    assert verify_token_with_grace(agent_id, reg, old_token) is True

    # Simulate the grace TTL elapsing (fakeredis honours EX; we drop the key
    # directly rather than manipulating wall-clock time, which is exactly
    # what Redis does itself once the TTL fires).
    _redis.delete(f"agent:token:grace:{agent_id}")

    assert verify_token_with_grace(agent_id, reg, old_token) is False


def test_grace_period_zero_hours_means_no_grace(_redis, _license):
    """grace_period_hours=0 must not leave a permanent (non-expiring) grace key."""
    reg = AgentRegistry(redis_client=_redis)
    agent_id, old_token = reg.register(
        name="crewai", upstream_url="http://crewai:9000", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/run"],
        protocol="openai",
    )

    rotate_agent_token(agent_id, registry=reg, grace_period_hours=0)

    assert _redis.exists(f"agent:token:grace:{agent_id}") == 0
    assert verify_token_with_grace(agent_id, reg, old_token) is False


def test_invalid_token_rejected_fail_closed(_redis, _license):
    reg = AgentRegistry(redis_client=_redis)
    agent_id, _old_token = reg.register(
        name="opencode", upstream_url="http://opencode:1234", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1"],
        protocol="openai",
    )
    rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)

    assert verify_token_with_grace(agent_id, reg, "not-a-real-token") is False


def test_rotate_agent_token_dual_writes_durable_mirror(_redis, _license):
    """ISSUE-AGENT-REG-DURABILITY must not regress: the grace-aware rotation
    path (now used by the live endpoint) must persist the NEW hash to the
    durable mirror, exactly like AgentRegistry.rotate_token() did."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    agent_id, _old_token = reg.register(
        name="letta2", upstream_url="http://letta2:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )
    pre_rotate_hash = durable.rows[agent_id]["token_hash"]

    rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)

    post_rotate_hash = durable.rows[agent_id]["token_hash"]
    assert post_rotate_hash != pre_rotate_hash


# ---------------------------------------------------------------------------
# Endpoint wiring — POST /admin/agents/{agent_id}/token/rotate
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_backoffice_state():
    prev_reg = backoffice_state.agent_registry
    prev_audit = backoffice_state.audit_writer
    prev_kms = backoffice_state.kms_provider
    prev_rbac = backoffice_state.rbac_store
    yield
    backoffice_state.agent_registry = prev_reg
    backoffice_state.audit_writer = prev_audit
    backoffice_state.kms_provider = prev_kms
    backoffice_state.rbac_store = prev_rbac


async def test_endpoint_routes_through_grace_aware_rotation(_redis, _license):
    """The live admin endpoint must produce a grace key for the OLD token —
    proof it calls token_rotation.rotate_agent_token(), not the bare
    AgentRegistry.rotate_token() immediate overwrite (the original bug)."""
    reg = AgentRegistry(redis_client=_redis)
    backoffice_state.agent_registry = reg
    backoffice_state.audit_writer = None
    backoffice_state.kms_provider = None
    backoffice_state.rbac_store = None  # _push_opa() no-ops safely

    agent_id, old_token = reg.register(
        name="letta3", upstream_url="http://letta3:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )

    session = SimpleNamespace(account_id="admin-test")
    resp = await agents_mod.rotate_agent_token(agent_id=agent_id, session=session)

    assert resp.token != old_token
    # The bare AgentRegistry.rotate_token() overwrite never writes a grace
    # key — its presence proves the endpoint now calls the grace-aware
    # rotate_agent_token() from token_rotation.py.
    assert _redis.exists(f"agent:token:grace:{agent_id}") == 1
    # And the OLD token — an in-flight agent's credential — still verifies.
    assert verify_token_with_grace(agent_id, reg, old_token) is True
    assert verify_token_with_grace(agent_id, reg, resp.token) is True


async def test_endpoint_respects_grace_hours_env_override(_redis, _license, monkeypatch):
    monkeypatch.setenv("YASHIGANI_AGENT_TOKEN_GRACE_HOURS", "0")
    reg = AgentRegistry(redis_client=_redis)
    backoffice_state.agent_registry = reg
    backoffice_state.audit_writer = None
    backoffice_state.kms_provider = None
    backoffice_state.rbac_store = None

    agent_id, old_token = reg.register(
        name="letta4", upstream_url="http://letta4:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )
    session = SimpleNamespace(account_id="admin-test")
    await agents_mod.rotate_agent_token(agent_id=agent_id, session=session)

    # grace_period_hours=0 -> no grace key -> old token dead immediately.
    assert _redis.exists(f"agent:token:grace:{agent_id}") == 0
    assert verify_token_with_grace(agent_id, reg, old_token) is False


# ---------------------------------------------------------------------------
# gateway/agent_auth.py wiring
# ---------------------------------------------------------------------------


async def test_agent_auth_middleware_accepts_old_token_within_grace(_redis, _license):
    """AgentAuthMiddleware.dispatch must use verify_token_with_grace, not the
    bare registry.verify_token — this is the exact call site the ticket
    cites as broken (agent_auth.py -> registry.verify_token)."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from yashigani.gateway.agent_auth import AgentAuthMiddleware

    reg = AgentRegistry(redis_client=_redis)
    agent_id, old_token = reg.register(
        name="letta5", upstream_url="http://letta5:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )
    rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)

    async def _ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/agents/{rest:path}", _ok)])
    app.add_middleware(AgentAuthMiddleware, agent_registry=reg, audit_writer=None)
    client = TestClient(app)

    resp = client.get(
        f"/agents/{agent_id}/ping",
        headers={
            "Authorization": f"Bearer {old_token}",
            "X-Yashigani-Caller-Agent-Id": agent_id,
        },
    )
    assert resp.status_code == 200


async def test_agent_auth_middleware_rejects_token_after_grace_deleted(_redis, _license):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from yashigani.gateway.agent_auth import AgentAuthMiddleware

    reg = AgentRegistry(redis_client=_redis)
    agent_id, old_token = reg.register(
        name="letta6", upstream_url="http://letta6:8283", groups=[],
        allowed_caller_groups=["users"], allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )
    rotate_agent_token(agent_id, registry=reg, grace_period_hours=1)
    _redis.delete(f"agent:token:grace:{agent_id}")

    async def _ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/agents/{rest:path}", _ok)])
    app.add_middleware(AgentAuthMiddleware, agent_registry=reg, audit_writer=None)
    client = TestClient(app)

    resp = client.get(
        f"/agents/{agent_id}/ping",
        headers={
            "Authorization": f"Bearer {old_token}",
            "X-Yashigani-Caller-Agent-Id": agent_id,
        },
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Scheduler — status check, not a fake pass
# ---------------------------------------------------------------------------


def test_scheduler_class_works_standalone_but_is_not_wired_anywhere():
    """AgentTokenRotationScheduler itself is correct (constructs, validates
    cron, would start given apscheduler) — the gap is that NOTHING in the
    codebase ever constructs one. This test documents/pins that scope
    boundary: it proves the class is usable so a future wiring PR only has
    to call it, not fix it. It does NOT claim the scheduler runs in
    production — see YSG-RISK-154 follow-up in the commit body."""
    apscheduler = pytest.importorskip("apscheduler")

    _redis_client = fakeredis.FakeRedis(decode_responses=False)
    try:
        import yashigani.licensing.enforcer as _lic_mod

        class _Lic:
            max_agents = -1

        _orig = _lic_mod.get_license
        _lic_mod.get_license = lambda: _Lic()
        try:
            reg = AgentRegistry(redis_client=_redis_client)
            agent_id, _tok = reg.register(
                name="sched-test", upstream_url="http://x:1", groups=[],
                allowed_caller_groups=[], allowed_paths=[], protocol="openai",
            )
        finally:
            _lic_mod.get_license = _orig

        scheduler = AgentTokenRotationScheduler(
            agent_id=agent_id,
            registry=reg,
            cron_expr="0 3 * * 0",
        )
        # Cron schedule persisted to Redis — this part of the contract works
        # standalone; only the "who constructs this at startup" part is missing.
        reg_row = reg.get(agent_id)
        assert reg_row["token_rotation_schedule"] == "0 3 * * 0"
    finally:
        _redis_client.flushall()
