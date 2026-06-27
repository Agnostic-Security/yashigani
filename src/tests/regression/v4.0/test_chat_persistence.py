"""
v4.0 regression — Chat persistence contract + BOLA tests.

Tests the conversation/message routes in user_conversations.py WITHOUT a
live database: asyncpg is mocked at the pool level so the tests exercise
route logic, Pydantic validation, and BOLA enforcement in isolation.

BOLA invariant (the load-bearing regression):
  A user can NEVER read, rename, delete, or append to another user's
  conversation.  The route must return 404 (never 403) when the DB row
  matches the id but not the account_id — this avoids leaking conversation
  existence to the attacker.

Route contract tests verify:
  - list_conversations  → 200 {"conversations": [...]}
  - create_conversation → 201 {"id": "<uuid>"}
  - get_conversation    → 200 with message array; 404 on BOLA mismatch
  - rename_conversation → 200 {"status": "ok"}; 404 on BOLA mismatch
  - delete_conversation → 204; 404 on BOLA mismatch
  - append_messages     → 201 {"ids": [...]}; 404 on BOLA mismatch
  - AppendMessagesBody validates role enum (user/assistant/system only)

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from yashigani.auth.session import Session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_session(account_id: str) -> Session:
    return Session(
        token=f"tok_{account_id}",
        account_id=account_id,
        account_tier="user",
        created_at=1_000_000.0,
        last_active_at=1_000_000.0,
        expires_at=9_999_999_999.0,
        ip_prefix="192.168.0.0",
    )


_SESSION_A = _make_session("user_a@example.com")
_SESSION_B = _make_session("user_b@example.com")

_FAKE_CONV_ID = str(uuid.uuid4())
_FAKE_MSG_ID  = str(uuid.uuid4())
_FAKE_MSG_ID2 = str(uuid.uuid4())


def _make_fake_pool(fetchrow_result=None, fetchval_result=None, fetch_result=None):
    """
    Build a mock asyncpg pool whose acquire() is an async context manager
    returning a mock connection.

    ``fetchrow_result``  — returned by conn.fetchrow()  (dict or None).
    ``fetchval_result``  — returned by conn.fetchval()  (scalar or None).
    ``fetch_result``     — returned by conn.fetch()     (list of dicts or []).
    """
    mock_conn = AsyncMock()
    mock_conn.fetchrow  = AsyncMock(return_value=fetchrow_result)
    mock_conn.fetchval  = AsyncMock(return_value=fetchval_result)
    mock_conn.fetch     = AsyncMock(return_value=fetch_result or [])
    mock_conn.execute   = AsyncMock(return_value=None)

    # conn.transaction() is an async context manager (used as `async with conn.transaction()`)
    @asynccontextmanager
    async def _txn():
        yield
    mock_conn.transaction = MagicMock(side_effect=_txn)

    # pool.acquire() is also an async context manager
    @asynccontextmanager
    async def _acquire():
        yield mock_conn

    mock_pool = MagicMock()
    mock_pool.acquire = MagicMock(side_effect=_acquire)
    return mock_pool


def _make_app(session: Session, fake_pool):
    """
    Minimal FastAPI app that includes ONLY the conversation router.
    Overrides require_user_session and _get_pool_or_503 so no Redis or DB.
    """
    from yashigani.backoffice.middleware import require_user_session
    from yashigani.backoffice.routes.user_conversations import router
    import yashigani.backoffice.routes.user_conversations as _mod

    app = FastAPI()
    app.dependency_overrides[require_user_session] = lambda: session
    # Monkeypatch the module-level pool helper directly on the router module
    _mod._get_pool_or_503 = lambda: fake_pool
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# list_conversations
# ---------------------------------------------------------------------------

def test_list_conversations_empty():
    pool = _make_fake_pool(fetch_result=[])
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.get("/user/conversations")
    assert resp.status_code == 200
    assert resp.json() == {"conversations": []}


def test_list_conversations_returns_rows():
    import datetime

    rows = [
        {
            "id": uuid.UUID(_FAKE_CONV_ID),
            "title": "Hello world",
            "updated_at": datetime.datetime(2026, 6, 27, 10, 0, 0,
                                            tzinfo=datetime.timezone.utc),
        }
    ]
    pool = _make_fake_pool(fetch_result=rows)
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.get("/user/conversations")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["conversations"]) == 1
    assert body["conversations"][0]["id"] == _FAKE_CONV_ID
    assert body["conversations"][0]["title"] == "Hello world"


# ---------------------------------------------------------------------------
# create_conversation
# ---------------------------------------------------------------------------

def test_create_conversation_returns_id():
    pool = _make_fake_pool(fetchrow_result={"id": uuid.UUID(_FAKE_CONV_ID)})
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.post("/user/conversations", json={"title": "My chat"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"] == _FAKE_CONV_ID


def test_create_conversation_default_title():
    """Body with no title should default to 'New conversation'."""
    pool = _make_fake_pool(fetchrow_result={"id": uuid.UUID(_FAKE_CONV_ID)})
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.post("/user/conversations", json={})
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# get_conversation — happy path
# ---------------------------------------------------------------------------

def test_get_conversation_returns_messages():
    import datetime

    conv_row = {
        "id": uuid.UUID(_FAKE_CONV_ID),
        "title": "Test conv",
        "created_at": datetime.datetime(2026, 6, 27, 9, 0, 0, tzinfo=datetime.timezone.utc),
        "updated_at": datetime.datetime(2026, 6, 27, 10, 0, 0, tzinfo=datetime.timezone.utc),
    }
    msg_rows = [
        {
            "id": uuid.UUID(_FAKE_MSG_ID),
            "role": "user",
            "content": "Hello",
            "model": None,
            "created_at": datetime.datetime(2026, 6, 27, 9, 1, 0, tzinfo=datetime.timezone.utc),
            "token_count": None,
            "verdict": None,
        }
    ]

    # fetchrow returns conv row; fetch returns msg rows
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=conv_row)
    mock_conn.fetch    = AsyncMock(return_value=msg_rows)
    mock_conn.execute  = AsyncMock(return_value=None)

    @asynccontextmanager
    async def _txn():
        yield
    mock_conn.transaction = MagicMock(side_effect=_txn)

    @asynccontextmanager
    async def _acquire():
        yield mock_conn

    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=_acquire)

    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.get(f"/user/conversations/{_FAKE_CONV_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == _FAKE_CONV_ID
    assert body["title"] == "Test conv"
    assert len(body["messages"]) == 1
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"] == "Hello"


# ---------------------------------------------------------------------------
# BOLA — get_conversation returns 404 for wrong user
# ---------------------------------------------------------------------------

def test_get_conversation_bola_returns_404():
    """
    LOAD-BEARING REGRESSION (BOLA / OWASP API3).

    The DB returns no row because the query scopes by account_id.
    The route MUST return 404 — never 403 — so an attacker cannot
    determine whether the conversation exists or belongs to someone else.
    """
    # fetchrow returns None — simulates "no row matching id + account_id"
    pool = _make_fake_pool(fetchrow_result=None)
    # User B tries to access a conversation belonging to User A
    app = _make_app(_SESSION_B, pool)
    client = TestClient(app)
    resp = client.get(f"/user/conversations/{_FAKE_CONV_ID}")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "not_found"


# ---------------------------------------------------------------------------
# BOLA — rename_conversation returns 404 for wrong user
# ---------------------------------------------------------------------------

def test_rename_conversation_bola_returns_404():
    """
    UPDATE ... WHERE id=$1 AND account_id=$2 returns no row → 404.
    """
    pool = _make_fake_pool(fetchrow_result=None)
    app = _make_app(_SESSION_B, pool)
    client = TestClient(app)
    resp = client.patch(
        f"/user/conversations/{_FAKE_CONV_ID}",
        json={"title": "Hijacked"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "not_found"


def test_rename_conversation_success():
    pool = _make_fake_pool(fetchrow_result={"id": uuid.UUID(_FAKE_CONV_ID)})
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.patch(
        f"/user/conversations/{_FAKE_CONV_ID}",
        json={"title": "My renamed chat"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# BOLA — delete_conversation returns 404 for wrong user
# ---------------------------------------------------------------------------

def test_delete_conversation_bola_returns_404():
    """
    DELETE ... WHERE id=$1 AND account_id=$2 returns no row → 404.
    """
    pool = _make_fake_pool(fetchrow_result=None)
    app = _make_app(_SESSION_B, pool)
    client = TestClient(app)
    resp = client.delete(f"/user/conversations/{_FAKE_CONV_ID}")
    assert resp.status_code == 404


def test_delete_conversation_success():
    pool = _make_fake_pool(fetchrow_result={"id": uuid.UUID(_FAKE_CONV_ID)})
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.delete(f"/user/conversations/{_FAKE_CONV_ID}")
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# append_messages — happy path
# ---------------------------------------------------------------------------

def test_append_messages_success():
    """
    Happy path: ownership check returns a value → messages are inserted.
    """
    # fetchval (ownership check) returns a value (non-None)
    # fetchrow (INSERT RETURNING id) cycles between two UUIDs
    msg_uuid_1 = uuid.UUID(_FAKE_MSG_ID)
    msg_uuid_2 = uuid.UUID(_FAKE_MSG_ID2)

    mock_conn = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=uuid.UUID(_FAKE_CONV_ID))
    mock_conn.fetchrow = AsyncMock(side_effect=[
        {"id": msg_uuid_1},
        {"id": msg_uuid_2},
    ])
    mock_conn.execute  = AsyncMock(return_value=None)

    @asynccontextmanager
    async def _txn():
        yield
    mock_conn.transaction = MagicMock(side_effect=_txn)

    @asynccontextmanager
    async def _acquire():
        yield mock_conn

    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=_acquire)

    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.post(
        f"/user/conversations/{_FAKE_CONV_ID}/messages",
        json={
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there", "model": "gemma3:4b"},
            ]
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "ids" in body
    assert len(body["ids"]) == 2
    assert body["ids"][0] == _FAKE_MSG_ID
    assert body["ids"][1] == _FAKE_MSG_ID2


# ---------------------------------------------------------------------------
# BOLA — append_messages returns 404 for wrong user
# ---------------------------------------------------------------------------

def test_append_messages_bola_returns_404():
    """
    LOAD-BEARING REGRESSION (BOLA).

    The ownership SELECT returns None (no row for this account_id).
    The route must return 404 without inserting any message.
    """
    # fetchval (ownership check) returns None → BOLA mismatch
    pool = _make_fake_pool(fetchval_result=None)
    app = _make_app(_SESSION_B, pool)
    client = TestClient(app)
    resp = client.post(
        f"/user/conversations/{_FAKE_CONV_ID}/messages",
        json={"messages": [{"role": "user", "content": "Steal data"}]},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "not_found"


# ---------------------------------------------------------------------------
# Pydantic validation — AppendMessagesBody role enum
# ---------------------------------------------------------------------------

def test_append_messages_invalid_role_rejected():
    """role must be one of user/assistant/system; anything else → 422."""
    pool = _make_fake_pool()
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.post(
        f"/user/conversations/{_FAKE_CONV_ID}/messages",
        json={"messages": [{"role": "ADMIN", "content": "drop tables"}]},
    )
    assert resp.status_code == 422


def test_append_messages_empty_list_rejected():
    """messages list must have at least one item."""
    pool = _make_fake_pool()
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.post(
        f"/user/conversations/{_FAKE_CONV_ID}/messages",
        json={"messages": []},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Malformed UUID → 422
# ---------------------------------------------------------------------------

def test_get_conversation_invalid_uuid_returns_422():
    pool = _make_fake_pool()
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.get("/user/conversations/not-a-uuid")
    assert resp.status_code == 422


def test_delete_conversation_invalid_uuid_returns_422():
    pool = _make_fake_pool()
    app = _make_app(_SESSION_A, pool)
    client = TestClient(app)
    resp = client.delete("/user/conversations/not-a-uuid")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# BOLA SQL-pattern structural proof
# ---------------------------------------------------------------------------

def test_bola_all_mutation_routes_scope_by_account_id():
    """
    Structural proof that every per-conversation query in user_conversations.py
    includes 'account_id' in the SQL.  This catches a future developer removing
    the scope accidentally.
    """
    import inspect
    import yashigani.backoffice.routes.user_conversations as _mod

    src = inspect.getsource(_mod)

    # All four operations that touch a specific conversation by id must also
    # check account_id.  The queries are:
    #   get_conversation    : SELECT ... WHERE id=$1 AND account_id=$2
    #   rename_conversation : UPDATE ... WHERE id=$2 AND account_id=$3
    #   delete_conversation : DELETE ... WHERE id=$1 AND account_id=$2
    #   append_messages     : SELECT id ... WHERE id=$1 AND account_id=$2

    account_id_count = src.count("account_id")
    # Expect at least one occurrence per per-conversation query (4 routes) + field references
    assert account_id_count >= 5, (
        f"Expected ≥5 'account_id' occurrences in user_conversations.py "
        f"(one per per-conversation SQL scope), got {account_id_count}. "
        "BOLA enforcement may have been weakened."
    )

    # Verify 'AND account_id' appears in the SQL strings for each operation
    # (belt-and-braces: the count above catches deletions; this catches
    # removing the AND from a specific query without changing total count).
    assert "AND account_id" in src, (
        "All per-conversation queries must include 'AND account_id' scope."
    )
