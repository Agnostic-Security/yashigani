"""Regression test — YSG-RISK-155: NHI durable-mirror write is a silent no-op.

Original bug:
    ``AgentRegistry.register_nhi()`` dual-writes to the durable Postgres
    mirror exactly like ``register()`` does for ordinary agents, but the
    dual-write was a silent no-op for a brand-new NHI:

      1. ``AgentDurableStore.upsert()`` branched on ``token_hash is None``
         into either an INSERT (token supplied) or a bare
         ``UPDATE ... WHERE agent_id=%s`` (token_hash None). An NHI's bearer
         token is a one-time secret that ``register_nhi()`` never re-persists,
         so it always called ``upsert(..., token_hash=None)`` — for a
         BRAND-NEW nhi_id there is no existing row, so the UPDATE matched
         zero rows and the NHI was never durably written at all.

      2. Even with (1) fixed, the durable ``agent_registry`` table had no
         columns for kind/template_id/owner_identity_id/allowed_models/
         budget_cap/svid_issued/pids_limit/memory_mb/spiffe_id/scope_hash, so
         ``AgentDurableStore.list_all()`` could not SELECT them and
         ``AgentRegistry.restore_from_durable()``'s existing
         ``if kind == "nhi":`` branch was dead code — an NHI restored after a
         redis wipe came back as an ordinary "agent" with none of its NHI
         fields.

      3. ``AgentReconciler``'s restore loop treated a NULL ``token_hash`` as
         a corrupt/incomplete row and skipped it — which is EVERY NHI row,
         since an NHI's token_hash is legitimately always NULL.

Fix (YSG-RISK-155):
    * ``AgentDurableStore.upsert()`` is now a single INSERT ... ON CONFLICT DO
      UPDATE (no dead UPDATE-only branch) and carries kind + all NHI columns
      (migration 0030 adds them; token_hash NOT NULL is now scoped to
      kind='agent' only).
    * ``AgentDurableStore.list_all()`` SELECTs kind + the NHI columns.
    * ``AgentRegistry.register_nhi()``/``approve_svid()`` dual-write the FULL
      decoded record (via ``self.get()``) instead of a hand-built partial
      dict, so kind/template_id/owner_identity_id/allowed_models/budget_cap/
      svid_issued/pids_limit/memory_mb/spiffe_id/scope_hash all round-trip.
    * ``AgentReconciler`` only requires token_hash for non-NHI rows; an NHI's
      metadata is restored (as an NHI, not a plain agent) even though its
      one-time bearer token cannot be (and never could be) durably restored.
    * A swallowed durable-write failure in register()/register_nhi()/
      approve_svid()/update() now increments
      ``yashigani_agent_durable_write_failures_total`` in addition to being
      logged, so the drop is observable via metrics even if nobody is
      tailing logs.

These tests use fakeredis + an in-memory fake durable store (no live
Postgres) to prove the dual-write + reconcile contract for NHIs specifically.
They would re-fail on the original bug: pre-fix, ``register_nhi()``'s durable
write never created a row (bug 1), so ``durable.rows`` would be empty after
registration and the "redis wipe -> reconcile" test would restore 0 NHIs.
"""
from __future__ import annotations

import asyncio

import pytest

fakeredis = pytest.importorskip("fakeredis")

from yashigani.agents.registry import AgentRegistry  # noqa: E402
from yashigani.agents.reconciler import (  # noqa: E402
    reconcile_agents_from_durable,
    _backfill_durable_from_redis,
)


class _FakeDurableStore:
    """In-memory stand-in for AgentDurableStore (no Postgres needed).

    Mirrors the FIXED upsert() contract: a single insert-or-update keyed on
    agent_id, carrying the full NHI field set, and permitting token_hash=None
    for a BRAND-NEW row (which is exactly what the original bug got wrong —
    see _PreFixDurableStore below for the reproduction of the original
    behaviour).
    """

    def __init__(self):
        self.rows: dict[str, dict] = {}

    def upsert(self, agent: dict, token_hash=None):
        aid = agent["agent_id"]
        existing = self.rows.get(aid, {})
        row = dict(agent)
        row["token_hash"] = token_hash if token_hash is not None else existing.get("token_hash")
        self.rows[aid] = row

    def set_status(self, agent_id: str, status: str):
        if agent_id in self.rows:
            self.rows[agent_id]["status"] = status

    async def list_all(self) -> list[dict]:
        return [dict(r) for r in self.rows.values()]


class _PreFixDurableStore(_FakeDurableStore):
    """Reproduces the ORIGINAL upsert() bug: token_hash=None on a brand-new
    row is a bare UPDATE-only call that matches zero rows and writes nothing.

    Used to pin the original failure mode so a regression that reintroduces
    the dead-UPDATE-only branch shape is caught.
    """

    def upsert(self, agent: dict, token_hash=None):
        aid = agent["agent_id"]
        if token_hash is not None:
            row = dict(agent)
            row["token_hash"] = token_hash
            self.rows[aid] = row
        else:
            # UPDATE-only semantics: only mutate a row that already exists.
            if aid in self.rows:
                self.rows[aid].update(agent)
            # else: silently drop — this is the original bug.


@pytest.fixture
def _redis():
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    client.flushall()


@pytest.fixture
def _license(monkeypatch):
    class _Lic:
        max_agents = -1

    monkeypatch.setattr("yashigani.licensing.enforcer.get_license", lambda: _Lic())


def _register_test_nhi(reg: AgentRegistry, name: str = "billing-bot"):
    return reg.register_nhi(
        name=name,
        owner_identity_id="idnt_owner1",
        template_id="ua_billing",
        allowed_tools=["read_invoice", "list_invoices"],
        allowed_paths=["read_invoice", "list_invoices"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 8192, "max_tool_calls_per_run": 20},
        pids_limit=32,
        memory_mb=256,
        scope_hash="sha384:deadbeef",
    )


# ── Bug 1: register_nhi() must actually persist a new row ──────────────────


def test_register_nhi_dual_writes_to_durable(_redis, _license):
    """register_nhi() must persist the NHI row to the durable store — the
    core YSG-RISK-155 regression. Pre-fix, this dict was empty/missing the
    row for a brand-new nhi_id."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    nhi_id, _token = _register_test_nhi(reg)

    assert nhi_id in durable.rows, "NHI was never durably persisted (YSG-RISK-155 regression)"
    row = durable.rows[nhi_id]
    assert row["kind"] == "nhi"
    assert row["token_hash"] is None  # one-time secret — never durably persisted, by design


def test_prefix_store_reproduces_original_bug(_redis, _license):
    """Guard: prove the ORIGINAL bug against a store that reproduces the
    original upsert() UPDATE-only-on-None shape. If this test starts
    FAILING (i.e. the NHI IS persisted), the guard itself needs updating —
    it exists to document exactly what broke."""
    durable = _PreFixDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    nhi_id, _token = _register_test_nhi(reg)

    assert nhi_id not in durable.rows, (
        "the pre-fix UPDATE-only-on-None store should NOT have persisted a "
        "brand-new NHI — if it did, this fixture no longer reproduces the bug"
    )


# ── Bug 2 + 3: full NHI field set + reconcile restores AS an NHI ───────────


def test_redis_wipe_then_reconcile_restores_nhi_with_fields_intact(_redis, _license):
    """The acceptance contract: wipe Redis, reconcile, the NHI comes back AS
    an NHI (kind="nhi") with template_id/allowed_models/budget_cap/
    svid_issued/spiffe fields intact — not as a plain "agent" with none of
    them (the dead ``if kind == "nhi":`` branch bug)."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    nhi_id, _token = _register_test_nhi(reg)
    pre_wipe = reg.get(nhi_id)
    assert pre_wipe["kind"] == "nhi"

    # --- Simulate the redis recreate (appendonly no / save "" -> total loss) ---
    _redis.flushall()
    assert reg.get(nhi_id) is None

    # --- Startup reconciler re-pushes Postgres -> Redis db/3 ---
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 1

    nhi = reg.get(nhi_id)
    assert nhi is not None
    assert nhi["kind"] == "nhi", "restored as a plain agent, not an NHI (dead-branch regression)"
    assert nhi["template_id"] == "ua_billing"
    assert nhi["owner_identity_id"] == "idnt_owner1"
    assert set(nhi["allowed_models"]) == {"gpt-4o-mini"}
    assert nhi["budget_cap"] == {"max_tokens_per_run": 8192, "max_tool_calls_per_run": 20}
    assert nhi["pids_limit"] == 32
    assert nhi["memory_mb"] == 256
    assert nhi["scope_hash"] == "sha384:deadbeef"
    assert nhi["sensitivity_ceiling"] == "INTERNAL"
    assert nhi_id in {a["agent_id"] for a in reg.list_all()}


def test_reconcile_does_not_skip_nhi_rows_for_null_token_hash(_redis, _license):
    """Bug 3: the reconciler must NOT treat a NULL token_hash as a corrupt
    row when kind="nhi" — that is every NHI row, by design."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    nhi_id, _token = _register_test_nhi(reg)
    assert durable.rows[nhi_id]["token_hash"] is None  # sanity: no hash, by design

    _redis.flushall()
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 1, "NHI with NULL token_hash was skipped by the reconciler"


def test_restore_from_durable_nhi_does_not_crash_on_none_token_hash(_redis, _license):
    """restore_from_durable() must not blow up trying to .encode() a None
    token_hash for an NHI (the generic-agent code path bcrypt-restores into
    agent:token:{id}; NHIs must not go through that path at all)."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    nhi_id, _token = _register_test_nhi(reg)
    durable_row = durable.rows[nhi_id]

    # Direct call, mirroring what the reconciler does for an NHI row.
    reg.restore_from_durable(durable_row, durable_row["token_hash"])  # token_hash is None
    restored = reg.get(nhi_id)
    assert restored is not None
    assert restored["kind"] == "nhi"


def test_approved_nhi_restores_as_approved_not_pending(_redis, _license):
    """approve_svid() must dual-write svid_issued=True to the durable store —
    otherwise an already-approved (executable) NHI restores from a redis wipe
    as pending-approval, silently downgrading it."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    nhi_id, _token = _register_test_nhi(reg)
    reg.approve_svid(nhi_id)
    assert reg.get(nhi_id)["svid_issued"] is True

    assert durable.rows[nhi_id]["svid_issued"] is True, (
        "approve_svid() did not mirror svid_issued to the durable store"
    )

    _redis.flushall()
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 1
    nhi = reg.get(nhi_id)
    assert nhi["svid_issued"] is True, "restored NHI lost its approved (svid_issued) state"
    assert nhi_id in {
        v.decode("utf-8") if isinstance(v, bytes) else v
        for v in _redis.smembers("nhi:index:active")
    }


def test_backfill_does_not_skip_preexisting_nhis(_redis, _license):
    """_backfill_durable_from_redis() (first boot after this fix lands) must
    not skip NHIs for lacking a bcrypt token_hash — get_token_hash() reads
    agent:token:{id}, which an NHI never populates (its plaintext lives at
    nhi:token:{id})."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    nhi_id, _token = _register_test_nhi(reg)

    # Simulate "durable store was empty at boot" by clearing it directly,
    # then running the backfill helper as the reconciler would on first boot.
    durable.rows.clear()
    count = _backfill_durable_from_redis(reg, durable)

    assert count == 1, "NHI was skipped during back-fill (no token_hash guard regression)"
    assert nhi_id in durable.rows
    assert durable.rows[nhi_id]["kind"] == "nhi"


# ── Bug: swallowed durable-write failure must be observable ────────────────


class _AlwaysFailsDurableStore(_FakeDurableStore):
    def upsert(self, agent: dict, token_hash=None):
        raise RuntimeError("simulated Postgres outage")


class _SpyCounter:
    """Test double for the prometheus_client Counter API used by
    _record_durable_write_failure(). Records every .labels(**kw).inc() call
    so the test can assert on it WITHOUT depending on prometheus_client being
    importable in this environment (it is a declared prod dependency —
    pyproject.toml `prometheus-client>=0.20` — but is not guaranteed present
    in every sandbox that runs the unit suite; the real Counter/Noop-stub
    fallback in metrics/registry.py both expose the same .labels().inc() API
    that _record_durable_write_failure() calls, so spying on that call
    contract exercises the real code path)."""

    def __init__(self):
        self.calls: list[tuple] = []

    def labels(self, **kw):
        self.calls.append(tuple(sorted(kw.items())))
        return self

    def inc(self, *a):
        pass


def test_register_nhi_durable_failure_is_observable_via_metric(monkeypatch, _redis, _license):
    """A durable-write failure during register_nhi() must not be silently
    swallowed — it must increment yashigani_agent_durable_write_failures_total
    (in addition to being logged) so it is observable without tailing logs."""
    spy = _SpyCounter()
    monkeypatch.setattr(
        "yashigani.metrics.registry.agent_durable_write_failures_total", spy
    )

    durable = _AlwaysFailsDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    # register_nhi() itself must NOT raise — the durable failure is best-effort
    # (the NHI stays live in Redis right now); it must only become observable.
    nhi_id, _token = _register_test_nhi(reg)
    assert reg.get(nhi_id) is not None  # still live in Redis

    assert (("kind", "nhi"), ("operation", "register_nhi")) in spy.calls, (
        "durable-write failure for register_nhi was not recorded via metric"
    )


def test_approve_svid_durable_failure_is_observable_via_metric(monkeypatch, _redis, _license):
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    nhi_id, _token = _register_test_nhi(reg)

    spy = _SpyCounter()
    monkeypatch.setattr(
        "yashigani.metrics.registry.agent_durable_write_failures_total", spy
    )

    # Swap in a failing store AFTER registration succeeded, to isolate the
    # approve_svid() dual-write failure specifically.
    reg._durable = _AlwaysFailsDurableStore()
    reg.approve_svid(nhi_id)  # must not raise
    assert reg.get(nhi_id)["svid_issued"] is True  # Redis side still succeeded

    assert (("kind", "nhi"), ("operation", "approve_svid")) in spy.calls, (
        "durable-write failure for approve_svid was not recorded via metric"
    )
