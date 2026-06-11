"""Regression test — ISSUE-AGENT-REG-DURABILITY (Iris, 2026-06-10).

Original bug:
    @agent registrations lived ONLY in Redis db/3, which runs with no
    persistence (appendonly no / save ""). A `docker compose up -d redis`
    recreate wiped every registration; the gateway then returned
    agent_not_found for every @agent with zero operator signal, and
    register_agent_bundles() only ran at install so the registry never
    self-healed.

Fix (mirrors the OPA store→OPA re-push, commit 2ce1033):
    * AgentRegistry.register/update/deactivate/rotate_token dual-write to a
      durable Postgres mirror (agent_registry table, migration 0017).
    * A startup reconciler re-pushes Postgres → Redis db/3 on every boot.

These tests use fakeredis + an in-memory fake durable store (no live Postgres)
to prove the dual-write + reconcile contract WITHOUT the DB. They would re-fail
on the original bug: pre-fix, register() did not call the durable store and the
reconciler did not exist, so a flushed Redis would leave the agent gone.
"""
from __future__ import annotations

import asyncio

import pytest

fakeredis = pytest.importorskip("fakeredis")

from yashigani.agents.registry import AgentRegistry  # noqa: E402
from yashigani.agents.reconciler import reconcile_agents_from_durable  # noqa: E402


class _FakeDurableStore:
    """In-memory stand-in for AgentDurableStore (no Postgres needed).

    Mirrors the sync upsert/set_status write API and the async list_all read
    API. Stores the full agent dict + token_hash exactly as the real store does.
    """

    def __init__(self):
        self.rows: dict[str, dict] = {}

    # sync write API (called from AgentRegistry mutation methods)
    def upsert(self, agent: dict, token_hash=None):
        aid = agent["agent_id"]
        existing = self.rows.get(aid, {})
        row = dict(agent)
        row["token_hash"] = token_hash if token_hash is not None else existing.get("token_hash")
        self.rows[aid] = row

    def set_status(self, agent_id: str, status: str):
        if agent_id in self.rows:
            self.rows[agent_id]["status"] = status

    # async read API (called by the reconciler)
    async def list_all(self) -> list[dict]:
        return [dict(r) for r in self.rows.values()]


class _NameUniqueDurableStore(_FakeDurableStore):
    """Durable store that models the LEGACY UNIQUE (tenant_id, agent_name).

    This reproduces the pre-fix Postgres shape: a second agent that reuses an
    existing NAME (allowed by the Redis register path, which is unique on
    agent_id only) raised a unique-violation on agent_name that the
    ``ON CONFLICT (tenant_id, agent_id)`` upsert clause could not catch.

    MUST-FIX-2 (migration 0017/0018) drops that legacy constraint, so the
    durable upsert must NOT raise on a name collision. We model the FIXED shape:
    uniqueness is keyed on agent_id ONLY. A store that still enforced the name
    constraint (set ``enforce_name_unique=True``) re-fails the original bug.
    """

    def __init__(self, enforce_name_unique: bool = False):
        super().__init__()
        self._enforce_name_unique = enforce_name_unique

    def upsert(self, agent: dict, token_hash=None):
        if self._enforce_name_unique:
            name = agent.get("name")
            for aid, row in self.rows.items():
                if aid != agent["agent_id"] and row.get("name") == name:
                    # Mirror psycopg2's UniqueViolation on agent_name.
                    raise ValueError(
                        "duplicate key value violates unique constraint "
                        '"agent_registry_tenant_id_agent_name_key"'
                    )
        super().upsert(agent, token_hash=token_hash)


def test_name_collision_stays_durable(_redis, _license):
    """MUST-FIX-2: two agents with the SAME name, different ids, BOTH persist durably.

    Pre-fix, the legacy UNIQUE (tenant_id, agent_name) made the second agent's
    durable INSERT raise — the agent stayed live in Redis but was silently
    non-durable and lost on the next redis recreate. After dropping the
    constraint (migration 0017/0018), the durable store keys on agent_id only,
    so both rows persist and both survive a redis wipe + reconcile.
    """
    durable = _NameUniqueDurableStore(enforce_name_unique=False)
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    id1, tok1 = reg.register(
        name="dup", upstream_url="http://a:1", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="openai",
    )
    # Second agent, SAME name, different id — must not raise, must persist.
    id2, tok2 = reg.register(
        name="dup", upstream_url="http://b:2", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="openai",
    )
    assert id1 != id2
    assert id1 in durable.rows and id2 in durable.rows  # BOTH durable

    # redis wipe + reconcile → BOTH agents reconcile back, tokens intact.
    _redis.flushall()
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 2
    assert reg.verify_token(id1, tok1) is True
    assert reg.verify_token(id2, tok2) is True


def test_legacy_name_constraint_would_lose_durability(_redis, _license):
    """Guard: prove the ORIGINAL bug — a name-unique store loses the 2nd agent.

    If the legacy UNIQUE (tenant_id, agent_name) constraint were still present,
    the second same-name agent's durable write raises and (because the dual-write
    is best-effort/logged) the agent is live in Redis but absent from the durable
    store → lost on redis wipe. This test pins that failure mode so a regression
    that re-introduces the constraint is caught.
    """
    durable = _NameUniqueDurableStore(enforce_name_unique=True)
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    id1, _ = reg.register(
        name="dup", upstream_url="http://a:1", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="openai",
    )
    # Best-effort dual-write swallows the unique-violation → agent NOT durable.
    id2, _ = reg.register(
        name="dup", upstream_url="http://b:2", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="openai",
    )
    assert id1 in durable.rows
    assert id2 not in durable.rows  # the silent-durability-loss the fix removes


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


def test_register_dual_writes_to_durable(_redis, _license):
    """register() must persist the agent (with token_hash) to the durable store."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    agent_id, _token = reg.register(
        name="letta",
        upstream_url="http://letta:8283",
        groups=[],
        allowed_caller_groups=["users"],
        allowed_paths=["/v1/chat/completions"],
        protocol="letta",
    )

    # Durable mirror has the row, including a non-null bcrypt token_hash.
    assert agent_id in durable.rows
    row = durable.rows[agent_id]
    assert row["name"] == "letta"
    assert row["upstream_url"] == "http://letta:8283"
    assert row["protocol"] == "letta"
    assert row["token_hash"] and row["token_hash"].startswith("$2")


def test_redis_wipe_then_reconcile_restores_agent(_redis, _license):
    """The acceptance contract: wipe Redis, reconcile, agent is back — same id+token."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)

    agent_id, plaintext = reg.register(
        name="langflow",
        upstream_url="http://langflow:7860",
        groups=[],
        allowed_caller_groups=["users"],
        allowed_paths=["/v1/chat/completions"],
        protocol="langflow",
    )
    # Token verifies before the wipe.
    assert reg.verify_token(agent_id, plaintext) is True

    # --- Simulate the redis recreate (appendonly no / save "" → total loss) ---
    _redis.flushall()
    assert reg.get(agent_id) is None  # agent_not_found territory — the original bug

    # --- Startup reconciler re-pushes Postgres → Redis db/3 ---
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 1

    # Agent is back with the SAME id (no new agent minted).
    agent = reg.get(agent_id)
    assert agent is not None
    assert agent["name"] == "langflow"
    assert agent["upstream_url"] == "http://langflow:7860"
    assert agent_id in {a["agent_id"] for a in reg.list_all()}

    # CRITICAL: the EXACT stored token still verifies — the caller's PSK was not
    # invalidated. This is what restore_from_durable() guarantees over a fresh
    # register() (which would mint a new token).
    assert reg.verify_token(agent_id, plaintext) is True


def test_reconcile_is_idempotent_and_preserves_live_entries(_redis, _license):
    """Reconcile must not overwrite an in-sync Redis entry, and is safe every boot."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    reg.register(
        name="letta", upstream_url="http://letta:8283", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="letta",
    )

    # Redis already in sync → reconcile restores nothing.
    restored = asyncio.run(reconcile_agents_from_durable(reg, durable))
    assert restored == 0
    # Second run is also a no-op (idempotent).
    assert asyncio.run(reconcile_agents_from_durable(reg, durable)) == 0


def test_reconcile_without_durable_store_is_safe(_redis):
    """A registry with no durable store must not crash the reconciler (fail-soft)."""
    reg = AgentRegistry(redis_client=_redis, durable_store=None)
    # durable_store=None → reconciler logs a warning and returns 0, never raises.
    assert asyncio.run(reconcile_agents_from_durable(reg, None)) == 0


def test_deactivate_mirrors_status_to_durable(_redis, _license):
    """deactivate() must mirror the status change so the durable copy stays accurate."""
    durable = _FakeDurableStore()
    reg = AgentRegistry(redis_client=_redis, durable_store=durable)
    agent_id, _ = reg.register(
        name="letta", upstream_url="http://letta:8283", groups=[],
        allowed_caller_groups=[], allowed_paths=[], protocol="letta",
    )
    reg.deactivate(agent_id)
    assert durable.rows[agent_id]["status"] == "inactive"
