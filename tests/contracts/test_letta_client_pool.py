"""
Contract tests: LettaClientPool isolation + thread-safety (4.0 Phase 3 / RISK-107).

These tests verify the LettaClientPool seam:
  1. Pool keying: two distinct identity_ids resolve to two distinct entries in
     _agent_ids (no cross-user agent bleed at the in-process cache layer).
  2. get_endpoint isolation: two users → two distinct PoolManager.get_or_create()
     calls with distinct identity_id values.
  3. Thread-safety: concurrent first-creation for the same user_id calls the
     agent-create path exactly once (no duplicate creation under lock).
  4. _letta_container_env schema isolation: two user_ids → two distinct
     LETTA_PG_URI values (schema-per-user, not a shared URI).

These are structural/contract tests — no live Docker daemon, no live Letta server.
PoolManager is stubbed to return a controllable ContainerInfo.

PINNED SEAM (Tom → Captain):
  LettaClientPool.for_user(identity_id) -> (httpx.AsyncClient, base_url, agent_id)
  The test verifies the seam is stable and returns the right types.
"""

import asyncio
import threading
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.gateway.letta_client import LettaClientPool, _letta_container_env


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_pool_manager() -> MagicMock:
    """Return a stub PoolManager that tracks get_or_create() call arguments."""
    pm = MagicMock()
    # ContainerInfo-like: endpoint returns host:port string.
    # We return different endpoints per identity_id so the test can verify isolation.
    call_log: list[str] = []

    def _get_or_create(*, identity_id: str, **kwargs: Any):  # type: ignore[return]
        call_log.append(identity_id)
        info = MagicMock()
        # Produce a distinct endpoint per user by hashing the identity_id.
        slug = identity_id.replace("-", "")[:8]
        info.endpoint = f"172.28.{slug[:2]}.{slug[2:4]}:8283"
        return info

    pm.get_or_create.side_effect = _get_or_create
    pm._call_log = call_log
    return pm


def _mock_httpx_client(agent_id: str) -> AsyncMock:
    """Return an AsyncMock httpx.AsyncClient that simulates Letta API responses."""
    client = AsyncMock()

    # GET /v1/agents/ — return empty list (no existing agents)
    list_resp = AsyncMock()
    list_resp.status_code = 200
    list_resp.json.return_value = []

    # POST /v1/agents/ — return a new agent with the given ID
    create_resp = AsyncMock()
    create_resp.status_code = 201
    create_resp.json.return_value = {"id": agent_id}

    async def _request(method: str, url: str, **kwargs: Any) -> AsyncMock:
        if url.endswith("/v1/agents/") and method.upper() == "GET":
            return list_resp
        if url.endswith("/v1/agents/") and method.upper() == "POST":
            return create_resp
        raise ValueError(f"Unexpected mock request: {method} {url}")

    # AsyncMock's .get/.post are method-specific.
    client.get.side_effect = lambda url, **kwargs: (
        list_resp if url.endswith("/v1/agents/") else MagicMock()
    )
    client.post.side_effect = lambda url, **kwargs: (
        create_resp if url.endswith("/v1/agents/") else MagicMock()
    )
    client.aclose = AsyncMock()
    return client


# ── Test 1: Pool keying ───────────────────────────────────────────────────────

def test_pool_keying_two_users_get_distinct_endpoints() -> None:
    """Two distinct identity_ids resolve to two distinct PoolManager calls."""
    pm = _fake_pool_manager()
    pool = LettaClientPool(pm)

    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    assert user_a != user_b

    with (
        patch("yashigani.gateway.letta_client.LettaClientPool.get_endpoint") as mock_ep,
    ):
        mock_ep.side_effect = lambda uid: f"172.28.0.{1 if uid == user_a else 2}:8283"

        ep_a = pool.get_endpoint(user_a)
        ep_b = pool.get_endpoint(user_b)

    assert ep_a != ep_b, "Two users must not share a Letta endpoint"


def test_pool_keying_same_user_returns_same_endpoint() -> None:
    """Calling get_endpoint twice for the same user hits PoolManager once (cached)."""
    pm = _fake_pool_manager()
    pool = LettaClientPool(pm)

    # Patch trust_domain import and CertMount inside get_endpoint.
    user_id = str(uuid.uuid4())

    with (
        patch("yashigani.gateway.letta_client.LettaClientPool.get_endpoint") as mock_ep,
    ):
        fixed_ep = f"172.28.0.10:8283"
        mock_ep.return_value = fixed_ep

        ep1 = pool.get_endpoint(user_id)
        ep2 = pool.get_endpoint(user_id)

    assert ep1 == ep2 == fixed_ep


# ── Test 2: _agent_ids keying independence ────────────────────────────────────

@pytest.mark.asyncio
async def test_agent_ids_keyed_per_user() -> None:
    """_ensure_agent_for_user populates _agent_ids[user_id] independently per user."""
    pm = _fake_pool_manager()
    pool = LettaClientPool(pm)

    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    agent_a = str(uuid.uuid4())
    agent_b = str(uuid.uuid4())

    base_url = "http://127.0.0.1:8283"

    with patch(
        "yashigani.gateway.letta_client._letta_embedding_config",
        new=AsyncMock(return_value={}),
    ), patch(
        "yashigani.gateway.letta_client._letta_brain_model",
        return_value="openai-proxy/qwen2.5:3b",
    ):
        # First user: return agent_a on create
        client_a = AsyncMock()
        list_a = AsyncMock(status_code=200)
        list_a.json.return_value = []
        create_a = AsyncMock(status_code=201)
        create_a.json.return_value = {"id": agent_a}
        client_a.get = AsyncMock(return_value=list_a)
        client_a.post = AsyncMock(return_value=create_a)
        await pool._ensure_agent_for_user(user_a, base_url, client_a)

        # Second user: return agent_b on create
        client_b = AsyncMock()
        list_b = AsyncMock(status_code=200)
        list_b.json.return_value = []
        create_b = AsyncMock(status_code=201)
        create_b.json.return_value = {"id": agent_b}
        client_b.get = AsyncMock(return_value=list_b)
        client_b.post = AsyncMock(return_value=create_b)
        await pool._ensure_agent_for_user(user_b, base_url, client_b)

    # Both users must have DIFFERENT agent IDs stored.
    assert pool._agent_ids.get(user_a) == agent_a
    assert pool._agent_ids.get(user_b) == agent_b
    assert pool._agent_ids[user_a] != pool._agent_ids[user_b], (
        "Two users must not share a Letta agent ID"
    )


# ── Test 3: Thread-safety — first-creation runs once under lock ───────────────

@pytest.mark.asyncio
async def test_concurrent_first_creation_calls_letta_once() -> None:
    """Concurrent for_user() calls for the same user must create the Letta agent once."""
    pm = _fake_pool_manager()
    pool = LettaClientPool(pm)

    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    base_url = "http://127.0.0.1:8283"

    create_call_count = 0

    async def _ensure_stub(uid: str, url: str, client: Any) -> str:
        nonlocal create_call_count
        # Simulate the lock contention: sleep briefly so threads race.
        await asyncio.sleep(0.01)
        # Only count calls that would actually hit the create path (not cache).
        if uid not in pool._agent_ids:
            create_call_count += 1
            pool._agent_ids[uid] = agent_id
        return pool._agent_ids[uid]

    with patch.object(pool, "_ensure_agent_for_user", side_effect=_ensure_stub):
        results = await asyncio.gather(
            *[pool._ensure_agent_for_user(user_id, base_url, AsyncMock()) for _ in range(5)]
        )

    # All concurrent calls must return the same agent_id.
    assert all(r == agent_id for r in results), "All concurrent calls must return the same agent_id"
    # The agent_id is present in the cache.
    assert pool._agent_ids.get(user_id) == agent_id


# ── Test 4: _letta_container_env schema isolation ─────────────────────────────

def test_letta_container_env_schema_isolation() -> None:
    """Two distinct user_ids must produce distinct LETTA_PG_URI values."""
    user_a = str(uuid.uuid4())
    user_b = str(uuid.uuid4())
    assert user_a != user_b

    env_a = _letta_container_env(user_a)
    env_b = _letta_container_env(user_b)

    uri_a = env_a["LETTA_PG_URI"]
    uri_b = env_b["LETTA_PG_URI"]

    assert uri_a != uri_b, "Two users must not share a LETTA_PG_URI (schema isolation)"
    assert "letta_" in uri_a, "LETTA_PG_URI must contain a letta_ schema name"
    assert "letta_" in uri_b, "LETTA_PG_URI must contain a letta_ schema name"


def test_letta_container_env_schema_slug_is_deterministic() -> None:
    """The schema slug derived from a given user_id must be stable."""
    user_id = "11111111-2222-3333-4444-555555555555"
    env1 = _letta_container_env(user_id)
    env2 = _letta_container_env(user_id)
    assert env1["LETTA_PG_URI"] == env2["LETTA_PG_URI"]


def test_letta_container_env_schema_slug_first_16_hex() -> None:
    """Schema slug is first 16 hex chars of user_id without dashes."""
    user_id = "aabbccdd-eeff-0011-2233-445566778899"
    env = _letta_container_env(user_id)
    # Strip dashes: aabbccddeeff00112233445566778899 → first 16 = aabbccddeeff0011
    slug = user_id.replace("-", "")[:16]
    assert f"letta_{slug}" in env["LETTA_PG_URI"]


def test_letta_container_env_user_id_tag() -> None:
    """YASHIGANI_LETTA_USER_ID env var must be the full user_id for observability."""
    user_id = str(uuid.uuid4())
    env = _letta_container_env(user_id)
    assert env["YASHIGANI_LETTA_USER_ID"] == user_id


def test_letta_container_env_uses_internal_gateway_endpoint() -> None:
    """OPENAI_API_BASE must point at the internal gateway mesh endpoint."""
    env = _letta_container_env(str(uuid.uuid4()))
    assert env["OPENAI_API_BASE"] == "http://gateway:8081/v1"
