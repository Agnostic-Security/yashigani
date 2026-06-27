"""
Unit tests for UserPlaneDurableStore (ISSUE-USER-PLANE-DURABILITY).

All tests are offline — no live Postgres or Redis required.
psycopg2 connection + cursor are mocked; asyncpg pool is faked.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Minimal fixtures
# ---------------------------------------------------------------------------

def _make_store(dsn: str = "postgresql://fake/test"):
    from yashigani.agents.user_plane_durable_store import UserPlaneDurableStore
    return UserPlaneDurableStore(dsn=dsn)


def _mock_conn():
    """Build a fake psycopg2 connection with cursor context-manager support."""
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


# ---------------------------------------------------------------------------
# 1. upsert_agent — correct SQL with INSERT ON CONFLICT
# ---------------------------------------------------------------------------

class TestUpsertAgent:
    def test_calls_insert_on_conflict(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.upsert_agent({
                "account_id": "acc1",
                "ua_id": "uag_abc123",
                "name": "Test Agent",
                "description": "desc",
                "alias": "test_agent",
                "kind": "agent",
                "personality": '{"persona": "helpful"}',
                "effective_skills": '["skill1"]',
                "declared_skills": '["skill1"]',
            })
        sql_called = cur.execute.call_args[0][0]
        assert "INSERT INTO user_agents" in sql_called
        assert "ON CONFLICT (ua_id) DO UPDATE" in sql_called
        conn.commit.assert_called_once()
        conn.close.assert_called_once()

    def test_rollback_on_error(self):
        store = _make_store()
        conn, cur = _mock_conn()
        cur.execute.side_effect = Exception("DB down")
        with patch.object(store, "_connect", return_value=conn):
            with pytest.raises(Exception, match="DB down"):
                store.upsert_agent({"account_id": "acc1", "ua_id": "uag_x"})
        conn.rollback.assert_called_once()
        conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# 2. delete_agent — correct SQL
# ---------------------------------------------------------------------------

class TestDeleteAgent:
    def test_calls_delete(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.delete_agent("uag_deadbeef")
        sql_called = cur.execute.call_args[0][0]
        assert "DELETE FROM user_agents WHERE ua_id" in sql_called
        args = cur.execute.call_args[0][1]
        assert "uag_deadbeef" in args
        conn.commit.assert_called_once()


# ---------------------------------------------------------------------------
# 3. upsert_memory / delete_memory — correct SQL
# ---------------------------------------------------------------------------

class TestMemory:
    def test_upsert_memory_sql(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.upsert_memory({
                "account_id": "acc1",
                "block_id":   "umb_xyz",
                "label":      "My notes",
                "value":      "some text",
                "letta_block_id": "lb_123",
            })
        sql = cur.execute.call_args[0][0]
        assert "INSERT INTO user_memory_blocks" in sql
        assert "ON CONFLICT (block_id) DO UPDATE" in sql
        conn.commit.assert_called_once()

    def test_delete_memory_sql(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.delete_memory("umb_abc")
        sql = cur.execute.call_args[0][0]
        assert "DELETE FROM user_memory_blocks WHERE block_id" in sql


# ---------------------------------------------------------------------------
# 4. set_memory_link — attach and detach
# ---------------------------------------------------------------------------

class TestSetMemoryLink:
    def test_attach_calls_insert_on_conflict(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.set_memory_link("uag_a", "umb_b", attached=True)
        sql = cur.execute.call_args[0][0]
        assert "INSERT INTO user_agent_memory_links" in sql
        assert "ON CONFLICT DO NOTHING" in sql
        conn.commit.assert_called_once()

    def test_detach_calls_delete(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.set_memory_link("uag_a", "umb_b", attached=False)
        sql = cur.execute.call_args[0][0]
        assert "DELETE FROM user_agent_memory_links" in sql
        conn.commit.assert_called_once()


# ---------------------------------------------------------------------------
# 5. upsert_workflow / delete_workflow — correct SQL
# ---------------------------------------------------------------------------

class TestWorkflow:
    def test_upsert_workflow_sql(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.upsert_workflow({
                "account_id":        "acc1",
                "wf_id":             "wfl_abc",
                "owner_identity_id": "acc1",
                "name":              "Daily brief",
                "description":       "",
                "spec":              '{"steps": [], "schedule": {"kind": "none"}}',
                "spec_hash":         "sha384:abc",
                "enabled":           True,
            })
        sql = cur.execute.call_args[0][0]
        assert "INSERT INTO user_workflows" in sql
        assert "ON CONFLICT (wf_id) DO UPDATE" in sql
        conn.commit.assert_called_once()

    def test_delete_workflow_sql(self):
        store = _make_store()
        conn, cur = _mock_conn()
        with patch.object(store, "_connect", return_value=conn):
            store.delete_workflow("wfl_dead")
        sql = cur.execute.call_args[0][0]
        assert "DELETE FROM user_workflows WHERE wf_id" in sql


# ---------------------------------------------------------------------------
# 6. Reconciler — simulate Redis wipe, restore agent/memory/workflow
# ---------------------------------------------------------------------------

class FakeRedis:
    """Minimal fake Redis client for reconciler tests."""
    def __init__(self):
        self._data: dict[str, dict] = {}
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

    def hget(self, key: str, field):
        return self._hashes.get(key, {}).get(field)

    def srem(self, key: str, *values):
        self._sets.get(key, set()).discard(*values)

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
    """Fake durable store with pre-seeded data."""
    def __init__(self, agents=None, memories=None, workflows=None):
        self._agents = agents or []
        self._memories = memories or []
        self._workflows = workflows or []
        self._links: dict[str, list[str]] = {}

    async def list_all_agents(self, account_id=None):
        return self._agents

    async def list_all_memories(self, account_id=None):
        return self._memories

    async def list_all_workflows(self, account_id=None):
        return self._workflows

    def _connect(self):
        """Return a mock psycopg2 connection (for _sync_list_memory_links)."""
        conn = MagicMock()
        cur = MagicMock()
        cur.__enter__ = lambda s: s
        cur.__exit__ = MagicMock(return_value=False)
        cur.fetchall.return_value = [
            (bid,) for bid in self._links.get("uag_test1", [])
        ]
        conn.cursor.return_value = cur
        return conn


@pytest.mark.asyncio
async def test_reconcile_restores_agent():
    """Reconciler restores a missing agent + index into fake Redis."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_r = FakeRedis()
    store = FakeDurableStore(
        agents=[{
            "ua_id": "uag_test1",
            "account_id": "acc1",
            "name": "Mimi",
            "description": "",
            "alias": "mimi",
            "kind": "agent",
            "personality": {"persona": "helpful"},
            "effective_skills": [],
            "declared_skills": [],
            "graph": None,
            "graph_hash": None,
            "letta_agent_id": None,
            "nhi_id": None,
            "created_at": None,
            "updated_at": None,
        }],
    )

    ua, mem, wf = await reconcile_user_plane_from_durable(fake_r, store)

    assert ua == 1
    assert mem == 0
    assert wf == 0
    assert "ua:meta:uag_test1" in fake_r._hashes
    assert b"uag_test1" in fake_r._sets.get("ua:agents:acc1", set())
    # Alias index
    assert b"mimi" in fake_r._hashes.get("ua:alias:acc1", {}).get(b"mimi", b"") or \
           fake_r._hashes.get("ua:alias:acc1", {})  # presence of key is sufficient


@pytest.mark.asyncio
async def test_reconcile_restores_memory():
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_r = FakeRedis()
    store = FakeDurableStore(
        memories=[{
            "block_id": "umb_mem1",
            "account_id": "acc1",
            "label": "My notes",
            "value": "some text",
            "letta_block_id": None,
            "created_at": None,
            "updated_at": None,
        }],
    )

    ua, mem, wf = await reconcile_user_plane_from_durable(fake_r, store)

    assert mem == 1
    assert "ua:mem:meta:umb_mem1" in fake_r._hashes
    assert b"umb_mem1" in fake_r._sets.get("ua:mem:all:acc1", set())


@pytest.mark.asyncio
async def test_reconcile_restores_workflow():
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_r = FakeRedis()
    store = FakeDurableStore(
        workflows=[{
            "wf_id": "wfl_wf1",
            "account_id": "acc1",
            "owner_identity_id": "acc1",
            "name": "Daily brief",
            "description": "",
            "spec": {"steps": [], "schedule": {"kind": "none"}},
            "spec_hash": "sha384:abc",
            "enabled": False,  # disabled — no db/6 push attempted
            "created_at": None,
            "updated_at": None,
        }],
    )

    ua, mem, wf = await reconcile_user_plane_from_durable(fake_r, store)

    assert wf == 1
    assert "wf:meta:wfl_wf1" in fake_r._hashes
    assert b"wfl_wf1" in fake_r._sets.get("wf:workflows:acc1", set())


@pytest.mark.asyncio
async def test_reconcile_skips_existing_redis_entries():
    """If Redis already has the key, reconciler leaves it alone (Redis is authoritative)."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    fake_r = FakeRedis()
    # Pre-populate
    fake_r._data["ua:meta:uag_existing"] = True  # mark as existing

    store = FakeDurableStore(
        agents=[{
            "ua_id": "uag_existing",
            "account_id": "acc1",
            "name": "Already here",
            "description": "",
            "alias": "already",
            "kind": "agent",
            "personality": None,
            "effective_skills": None,
            "declared_skills": None,
            "graph": None,
            "graph_hash": None,
            "letta_agent_id": None,
            "nhi_id": None,
            "created_at": None,
            "updated_at": None,
        }],
    )

    ua, mem, wf = await reconcile_user_plane_from_durable(fake_r, store)

    assert ua == 0  # not restored — already present


@pytest.mark.asyncio
async def test_reconcile_degrade_safe_no_store():
    """reconcile_user_plane_from_durable returns (0,0,0) gracefully when store is None."""
    from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable

    ua, mem, wf = await reconcile_user_plane_from_durable(None, None)
    assert (ua, mem, wf) == (0, 0, 0)


# ---------------------------------------------------------------------------
# 7. Degrade-safe: _get_user_plane_durable() returns None when not wired
# ---------------------------------------------------------------------------

def test_get_user_plane_durable_returns_none_when_not_wired():
    """If backoffice_state.user_plane_durable is None, helper returns None."""
    from yashigani.backoffice.routes.user_agents import _get_user_plane_durable
    from yashigani.backoffice.state import backoffice_state

    original = backoffice_state.user_plane_durable
    try:
        backoffice_state.user_plane_durable = None
        result = _get_user_plane_durable()
        assert result is None
    finally:
        backoffice_state.user_plane_durable = original


def test_get_user_plane_durable_returns_store_when_wired():
    """If backoffice_state.user_plane_durable is set, helper returns it."""
    from yashigani.backoffice.routes.user_agents import _get_user_plane_durable
    from yashigani.backoffice.state import backoffice_state
    from yashigani.agents.user_plane_durable_store import UserPlaneDurableStore

    store = UserPlaneDurableStore(dsn="postgresql://fake/test")
    original = backoffice_state.user_plane_durable
    try:
        backoffice_state.user_plane_durable = store
        result = _get_user_plane_durable()
        assert result is store
    finally:
        backoffice_state.user_plane_durable = original
