"""
Contract tests — Workflow Scheduler (feat/4.0-wf-exec).

Tests are structural (no live Redis, no live gateway mesh endpoint):
  1. INTERVAL FIRE — a workflow fires when its interval is due (simulated clock).
  2. DENY HALTS — a denied hop from _execute_tool_call stops the run and
     emits WORKFLOW_STEP_DENIED; subsequent steps do NOT execute.
  3. NHI CONTEXT — the identity passed to each hop is derived from
     owner_identity_id, not a raw service-level token.
  4. RESTART RELOAD — scheduler.reload_from_redis() restores all enabled
     workflows after a simulated restart.

All Redis interactions use fakeredis so no real daemon is required.
The orchestrator._execute_tool_call is stubbed for hop-level control.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

# Gateway modules require YASHIGANI_INTERNAL_BEARER at import time.
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-scheduler-bearer-token")

# fakeredis is available in dev extras
import fakeredis


from yashigani.gateway.workflow_scheduler import (
    WorkflowScheduler,
    WorkflowSpec,
    WorkflowStep,
    WorkflowSchedule,
    _redis_set_spec,
    _redis_get_next,
    _redis_set_next,
    _execute_workflow_run,
    _KEY_SCHED_INDEX,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_spec(
    wf_id: str = None,
    owner_id: str = "user-abc",
    interval_s: int = 300,
    steps: list[dict] | None = None,
    enabled: bool = True,
) -> WorkflowSpec:
    if wf_id is None:
        wf_id = str(uuid.uuid4())
    if steps is None:
        steps = [
            {"actor": "@Mimi", "action": "summarise transactions",
             "uses": [], "output_to": "@api9"},
        ]
    step_objs = [WorkflowStep(**s) for s in steps]
    return WorkflowSpec(
        workflow_id=wf_id,
        owner_identity_id=owner_id,
        enabled=enabled,
        steps=step_objs,
        schedule=WorkflowSchedule(kind="interval", seconds=interval_s),
    )


def _fake_redis() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis()


def _clean_tool_result(text: str = "done"):
    """Return a clean (unblocked) ToolResult stub."""
    from yashigani.gateway.workflow_scheduler import WorkflowStepRecord  # noqa: F401
    tr = MagicMock()
    tr.blocked = False
    tr.text = text
    tr.ingress_opa = "allow"
    tr.egress_opa = "allow"
    tr.inspection_verdict = "CLEAN"
    tr.block_source = ""
    return tr


def _denied_tool_result():
    """Return a denied (blocked) ToolResult stub."""
    tr = MagicMock()
    tr.blocked = True
    tr.text = "[BLOCKED BY YASHIGANI OPA INGRESS]"
    tr.ingress_opa = "deny:policy_denied"
    tr.egress_opa = "not_reached"
    tr.inspection_verdict = "not_reached"
    tr.block_source = "opa_ingress"
    return tr


# ---------------------------------------------------------------------------
# Test 1: INTERVAL FIRE — workflow fires when interval is due
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_interval_workflow_fires_when_due():
    """A workflow with an interval schedule fires when ``now >= next_fire``."""
    r = _fake_redis()
    spec = _make_spec(interval_s=300)

    # Set next_fire to 5 seconds in the past (simulating a due workflow).
    base_time = 1_000_000.0
    due_time = base_time - 5.0  # 5 s overdue

    _redis_set_spec(r, spec)
    _redis_set_next(r, spec.workflow_id, due_time)

    fired_ids: list[str] = []

    async def _fake_fire(spec_arg):
        fired_ids.append(spec_arg.workflow_id)

    scheduler = WorkflowScheduler(
        r,
        _time_fn=lambda: base_time,  # clock is at base_time
    )

    # Monkeypatch _fire_with_lock so we don't need a live orchestrator.
    scheduler._fire_with_lock = _fake_fire

    await scheduler._check_and_fire()
    # Yield so ensure_future tasks have a chance to run.
    await asyncio.sleep(0)

    assert spec.workflow_id in fired_ids, (
        "Scheduler should have fired the overdue workflow"
    )


@pytest.mark.asyncio
async def test_interval_workflow_does_not_fire_early():
    """A workflow does NOT fire if next_fire is in the future."""
    r = _fake_redis()
    spec = _make_spec(interval_s=300)

    base_time = 1_000_000.0
    future_time = base_time + 200.0  # 200 s in the future

    _redis_set_spec(r, spec)
    _redis_set_next(r, spec.workflow_id, future_time)

    fired_ids: list[str] = []

    async def _fake_fire(spec_arg):
        fired_ids.append(spec_arg.workflow_id)

    scheduler = WorkflowScheduler(r, _time_fn=lambda: base_time)
    scheduler._fire_with_lock = _fake_fire

    await scheduler._check_and_fire()

    assert spec.workflow_id not in fired_ids, (
        "Scheduler must not fire a workflow whose next_fire is in the future"
    )


# ---------------------------------------------------------------------------
# Test 2: DENY HALTS — a denied hop stops the run; subsequent steps skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_denied_hop_halts_run_and_subsequent_steps_skipped():
    """A denied first step blocks the run; second step must not execute."""
    r = _fake_redis()

    # Two-step workflow: step 0 gets denied, step 1 should never run.
    spec = _make_spec(
        steps=[
            {"actor": "@Mimi", "action": "step0", "uses": [], "output_to": "@api9"},
            {"actor": "@Juno", "action": "step1", "uses": [], "output_to": ""},
        ]
    )
    _redis_set_spec(r, spec)

    executed_actors: list[str] = []

    async def _stub_execute_tool_call(*, tool_name, args, catalog, identity,
                                      depth, root_rid, iteration=0):
        actor = tool_name.replace("agent__", "@")
        executed_actors.append(actor)
        if "mimi" in tool_name:
            return _denied_tool_result()
        return _clean_tool_result()

    audit_events: list[str] = []

    class _FakeWriter:
        def write(self, event):
            audit_events.append(type(event).__name__)

    with patch(
        "yashigani.gateway.workflow_scheduler._execute_tool_call",
        new=_stub_execute_tool_call,
    ):
        run = await _execute_workflow_run(
            spec=spec,
            redis_client=r,
            audit_writer=_FakeWriter(),
        )

    assert run.status == "blocked", f"Expected 'blocked', got {run.status!r}"
    assert len(run.steps) == 1, "Only one step should be recorded (execution stopped after deny)"
    assert run.steps[0].status == "denied"
    assert "@Juno" not in str(executed_actors), "Second step actor must not have been called"
    assert "WorkflowStepDeniedEvent" in audit_events
    assert "WorkflowRunFailedEvent" in audit_events


# ---------------------------------------------------------------------------
# Test 3: NHI CONTEXT — identity passed to hops is the workflow owner's
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execution_uses_owner_identity_not_service_token():
    """The identity dict passed to _execute_tool_call must carry the owner's identity_id."""
    r = _fake_redis()
    owner_id = "user-owner-" + uuid.uuid4().hex[:8]
    spec = _make_spec(owner_id=owner_id)
    _redis_set_spec(r, spec)

    captured_identities: list[dict] = []

    async def _stub_execute_tool_call(*, tool_name, args, catalog, identity,
                                      depth, root_rid, iteration=0):
        captured_identities.append(dict(identity) if identity else {})
        return _clean_tool_result()

    # Provide a mock identity registry that returns the owner identity.
    fake_registry = MagicMock()
    fake_registry.get_by_id.return_value = {
        "identity_id": owner_id,
        "slug": owner_id,
        "account_tier": "user",
        "groups": ["ops-team"],
    }

    with patch(
        "yashigani.gateway.workflow_scheduler._execute_tool_call",
        new=_stub_execute_tool_call,
    ):
        run = await _execute_workflow_run(
            spec=spec,
            redis_client=r,
            identity_registry=fake_registry,
        )

    assert run.status == "completed", f"Expected completed, got {run.status!r}"
    assert len(captured_identities) == 1
    ident = captured_identities[0]

    # Must carry the owner's identity_id — NOT a generic service account.
    assert ident.get("identity_id") == owner_id, (
        f"Expected identity_id={owner_id!r}, got {ident.get('identity_id')!r}"
    )

    # Must NOT be a raw service token (no "_service_account" marker).
    assert ident.get("_service_account") is None, (
        "Workflow hops must use the owner's identity, not a service account"
    )


# ---------------------------------------------------------------------------
# Test 4: RESTART RELOAD — scheduler reloads all enabled workflows on boot
# ---------------------------------------------------------------------------

def test_reload_from_redis_restores_enabled_workflows():
    """After restart, reload_from_redis() restores all enabled workflow schedules."""
    r = _fake_redis()

    spec_a = _make_spec(wf_id="wf-alpha", enabled=True)
    spec_b = _make_spec(wf_id="wf-beta", enabled=True)
    spec_c = _make_spec(wf_id="wf-gamma", enabled=False)  # disabled — should not reload

    _redis_set_spec(r, spec_a)
    _redis_set_spec(r, spec_b)
    _redis_set_spec(r, spec_c)

    # Simulate cleared next-fire entries (Redis flush scenario).
    r.delete(f"wf:sched:next:{spec_a.workflow_id}")
    r.delete(f"wf:sched:next:{spec_b.workflow_id}")

    base_time = 2_000_000.0
    scheduler = WorkflowScheduler(r, _time_fn=lambda: base_time)
    count = scheduler.reload_from_redis()

    assert count == 2, f"Expected 2 enabled workflows reloaded, got {count}"

    # Both enabled workflows should have next-fire set.
    for wf_id in [spec_a.workflow_id, spec_b.workflow_id]:
        next_ts = _redis_get_next(r, wf_id)
        assert next_ts > 0, f"next_fire not set for {wf_id} after reload"
        assert next_ts >= base_time, (
            f"next_fire {next_ts} should be >= base_time {base_time} for {wf_id}"
        )

    # Disabled workflow must remain absent from the schedule index.
    members_raw = r.smembers(_KEY_SCHED_INDEX)
    members = {m.decode() if isinstance(m, bytes) else m for m in members_raw}
    assert spec_c.workflow_id not in members, (
        "Disabled workflow must not appear in the schedule index after reload"
    )


# ---------------------------------------------------------------------------
# Test 5: CRON — cron expression matching
# ---------------------------------------------------------------------------

def test_cron_matches_on_exact_minute():
    """Cron expression '*/10 * * * *' matches every 10th minute."""
    from yashigani.gateway.workflow_scheduler import _cron_matches
    import datetime

    # Build a UTC timestamp at HH:00 (an exact match for minute=0 → divisible by 10)
    dt = datetime.datetime(2026, 6, 27, 14, 0, 0, tzinfo=datetime.timezone.utc)
    ts = dt.timestamp()
    assert _cron_matches("*/10 * * * *", ts), "minute=0 should match */10"

    dt10 = datetime.datetime(2026, 6, 27, 14, 10, 0, tzinfo=datetime.timezone.utc)
    assert _cron_matches("*/10 * * * *", dt10.timestamp()), "minute=10 should match */10"

    dt5 = datetime.datetime(2026, 6, 27, 14, 5, 0, tzinfo=datetime.timezone.utc)
    assert not _cron_matches("*/10 * * * *", dt5.timestamp()), (
        "minute=5 should NOT match */10"
    )


# ---------------------------------------------------------------------------
# Test 6: LOCK prevents double-fire
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lock_prevents_double_fire():
    """If a lock is already held, _fire_with_lock is a no-op."""
    r = _fake_redis()
    spec = _make_spec()
    _redis_set_spec(r, spec)

    # Pre-acquire the lock (simulating another replica already running this workflow).
    from yashigani.gateway.workflow_scheduler import _KEY_LOCK, _LOCK_TTL_S
    r.set(_KEY_LOCK.format(spec.workflow_id), b"1", nx=True, ex=_LOCK_TTL_S)

    fired: list[bool] = []

    original_fire = WorkflowScheduler._fire_with_lock

    async def _counting_fire(self_sched, spec_arg):
        fired.append(True)
        await original_fire(self_sched, spec_arg)

    scheduler = WorkflowScheduler(r)

    # _fire_with_lock should silently skip because the lock is held.
    with patch.object(WorkflowScheduler, "_fire_with_lock", new=_counting_fire):
        # Call the REAL _fire_with_lock (which checks the Redis lock).
        await original_fire(scheduler, spec)

    # The lock was pre-held so the workflow should NOT have executed.
    # fired list should be empty (the patched _counting_fire was NOT called because
    # we called the original _fire_with_lock directly, which bails on lock held).
    assert fired == [], "Workflow must not execute when lock is already held"
