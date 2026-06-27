"""
Regression test: user-plane Redis wipe → Postgres reconcile restores data.

v4.0 / ISSUE-USER-PLANE-DURABILITY

Scenario:
  1. Build fake user-agent, memory-block, and workflow data in a fake Postgres store.
  2. Start with an empty fake Redis (simulating a Redis db/3 wipe).
  3. Run reconcile_user_plane_from_durable() with the fake store + fake Redis.
  4. Assert all three entity types are present in Redis with the correct keys.

No live DB, Redis, or network required. Marked plain (no pytest.mark.integration).
"""
from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# Minimal fake Redis (same shape as in test_user_plane_durable.py)
# ---------------------------------------------------------------------------

class FakeRedis:
    def __init__(self):
        self._data: dict[str, bool] = {}
        self._sets: dict[str, set] = {}
        self._hashes: dict[str, dict] = {}

    def exists(self, key: str) -> bool:
        return key in self._data or key in self._hashes

    def hset(self, key: str, mapping: dict | None = None, **kwargs):
        if mapping is not None:
            self._hashes[key] = dict(mapping)
        else:
            self._hashes.setdefault(key, {}).update(kwargs)

    def sadd(self, key: str, *values):
        self._sets.setdefault(key, set()).update(values)

    def pipeline(self):
        return FakePipeline(self)

    def ping(self):
        return True


class FakePipeline:
    def __init__(self, redis: FakeRedis):
        self._r = redis
        self._cmds: list = []

    def hset(self, key: str, mapping: dict | None = None, **kwargs):
        self._cmds.append(("hset", key, mapping, kwargs))
        return self

    def sadd(self, key: str, *values):
        self._cmds.append(("sadd", key, values))
        return self

    def execute(self):
        for cmd in self._cmds:
            if cmd[0] == "hset":
                self._r.hset(cmd[1], mapping=cmd[2], **cmd[3])
            elif cmd[0] == "sadd":
                self._r.sadd(cmd[1], *cmd[2])
        self._cmds.clear()
        return []


class FakeDurableStore:
    """Fake UserPlaneDurableStore pre-seeded with fixture data."""

    def __init__(self):
        from unittest.mock import MagicMock
        self._agents = [
            {
                "ua_id":            "uag_regression1",
                "account_id":       "acc_regression",
                "name":             "Regression Agent",
                "description":      "A test agent for regression",
                "alias":            "regression_agent",
                "kind":             "agent",
                "personality":      {"persona": "helpful", "system_prompt": ""},
                "effective_skills": ["skill_a"],
                "declared_skills":  ["skill_a", "skill_b"],
                "graph":            None,
                "graph_hash":       None,
                "letta_agent_id":   None,
                "nhi_id":           None,
                "created_at":       None,
                "updated_at":       None,
            }
        ]
        self._memories = [
            {
                "block_id":       "umb_regression1",
                "account_id":     "acc_regression",
                "label":          "Regression Memory",
                "value":          "some persistent memory value",
                "letta_block_id": None,
                "created_at":     None,
                "updated_at":     None,
            }
        ]
        self._workflows = [
            {
                "wf_id":             "wfl_regression1",
                "account_id":        "acc_regression",
                "owner_identity_id": "acc_regression",
                "name":              "Regression Workflow",
                "description":       "Workflow that must survive a Redis wipe",
                "spec":              {"steps": [], "schedule": {"kind": "none"}},
                "spec_hash":         "sha384:regression",
                "enabled":           False,  # disabled — skips db/6 push
                "created_at":        None,
                "updated_at":        None,
            }
        ]

        # _connect() called for memory-link reconcile — return a no-op mock
        _mock = MagicMock()
        _cur = MagicMock()
        _cur.__enter__ = lambda s: s
        _cur.__exit__ = MagicMock(return_value=False)
        _cur.fetchall.return_value = []  # no links for this agent
        _mock.cursor.return_value = _cur
        self._mock_conn = _mock

    def _connect(self):
        return self._mock_conn

    async def list_all_agents(self, account_id=None):
        return self._agents

    async def list_all_memories(self, account_id=None):
        return self._memories

    async def list_all_workflows(self, account_id=None):
        return self._workflows


# ---------------------------------------------------------------------------
# Regression test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wipe_restore_full_user_plane():
    """After a Redis wipe, all three entity types are restored from Postgres."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_redis = FakeRedis()   # empty — simulates a fresh Redis after wipe
    fake_store = FakeDurableStore()

    ua, mem, wf = await reconcile_user_plane_from_durable(fake_redis, fake_store)

    # --- Agents ---
    assert ua == 1, f"Expected 1 agent restored, got {ua}"
    assert "ua:meta:uag_regression1" in fake_redis._hashes, \
        "Agent meta key missing from Redis after reconcile"
    assert b"uag_regression1" in fake_redis._sets.get("ua:agents:acc_regression", set()), \
        "Agent not in account index after reconcile"

    # Verify the name was written correctly
    meta = fake_redis._hashes["ua:meta:uag_regression1"]
    name_val = meta.get(b"name", b"")
    assert name_val == b"Regression Agent", f"Agent name mismatch: {name_val!r}"

    # --- Memories ---
    assert mem == 1, f"Expected 1 memory restored, got {mem}"
    assert "ua:mem:meta:umb_regression1" in fake_redis._hashes, \
        "Memory meta key missing from Redis after reconcile"
    assert b"umb_regression1" in fake_redis._sets.get("ua:mem:all:acc_regression", set()), \
        "Memory block not in account index after reconcile"

    # --- Workflows ---
    assert wf == 1, f"Expected 1 workflow restored, got {wf}"
    assert "wf:meta:wfl_regression1" in fake_redis._hashes, \
        "Workflow meta key missing from Redis after reconcile"
    assert b"wfl_regression1" in fake_redis._sets.get("wf:workflows:acc_regression", set()), \
        "Workflow not in account index after reconcile"

    # Verify enabled flag is written as b"0" (disabled)
    wf_meta = fake_redis._hashes["wf:meta:wfl_regression1"]
    enabled_val = wf_meta.get(b"enabled", b"?")
    assert enabled_val == b"0", f"Workflow enabled flag mismatch: {enabled_val!r}"


@pytest.mark.asyncio
async def test_idempotent_second_reconcile():
    """Running reconcile twice is idempotent — existing keys are not overwritten."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_redis = FakeRedis()
    fake_store = FakeDurableStore()

    # First reconcile
    ua1, mem1, wf1 = await reconcile_user_plane_from_durable(fake_redis, fake_store)
    assert ua1 == 1 and mem1 == 1 and wf1 == 1

    # Second reconcile — everything is already present, nothing restored
    ua2, mem2, wf2 = await reconcile_user_plane_from_durable(fake_redis, fake_store)
    assert ua2 == 0 and mem2 == 0 and wf2 == 0


@pytest.mark.asyncio
async def test_reconcile_skips_none_inputs():
    """Passing None for either argument returns (0,0,0) without raising."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    result = await reconcile_user_plane_from_durable(None, None)
    assert result == (0, 0, 0)

    result = await reconcile_user_plane_from_durable(FakeRedis(), None)
    assert result == (0, 0, 0)
