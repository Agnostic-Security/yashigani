"""
Yashigani Backoffice — 4.0 chat persistence routes.

All endpoints enforce ``require_user_session`` (RISK-100): user-tier session
required; admin sessions are rejected with 403 wrong_plane.

BOLA / OWASP API3:  every query that touches a specific conversation includes
``AND account_id = $N`` scoped to ``session.account_id``.  A mismatch (another
user's conversation or a non-existent id) always returns 404 — never 403 —
so existence of a conversation cannot be inferred.

Routes
------
  GET    /user/conversations                 — list caller's conversations
  POST   /user/conversations                 — create → {id}
  GET    /user/conversations/{id}            — messages for conversation
  PATCH  /user/conversations/{id}            — rename
  DELETE /user/conversations/{id}            — delete (cascades messages)
  POST   /user/conversations/{id}/messages   — persist one or more chat turns

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import UserSession

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_pool_or_503():
    """Return the asyncpg pool or raise HTTP 503 (DB not yet initialised)."""
    try:
        from yashigani.db.postgres import get_pool
        return get_pool()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_unavailable", "message": "Database pool not ready."},
        ) from exc


def _parse_conv_id(raw: str) -> uuid.UUID:
    """Parse a conversation id as UUID; raise HTTP 422 on malformed input."""
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_conversation_id", "message": "Conversation id must be a UUID."},
        ) from exc


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CreateConversationBody(BaseModel):
    title: str = Field(default="New conversation", min_length=1, max_length=255)


class RenameConversationBody(BaseModel):
    title: str = Field(min_length=1, max_length=255)


class MessageIn(BaseModel):
    role: str = Field(pattern=r"^(user|assistant|system)$")
    content: str = Field(default="", max_length=1_000_000)
    model: Optional[str] = Field(default=None, max_length=128)
    token_count: Optional[int] = Field(default=None, ge=0)
    verdict: Optional[dict] = None  # OPA/classifier verdict metadata


class AppendMessagesBody(BaseModel):
    """
    Persist one or more chat messages under a conversation.

    The caller (SPA) typically sends two messages per turn: the user message
    and the assistant response.  Batch semantics (all succeed or none) — the
    route wraps inserts in a single transaction.
    """
    messages: list[MessageIn] = Field(min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/user/conversations")
async def list_conversations(session: UserSession):
    """
    List the calling user's conversations, newest-first.

    Returns: ``{"conversations": [{id, title, updated_at}]}``
    """
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, title, updated_at
                  FROM conversations
                 WHERE account_id = $1
                 ORDER BY updated_at DESC
                """,
                session.account_id,
            )
    except Exception as exc:
        logger.error("list_conversations: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to list conversations."},
        ) from exc

    return {
        "conversations": [
            {
                "id": str(r["id"]),
                "title": r["title"],
                "updated_at": r["updated_at"].isoformat(),
            }
            for r in rows
        ]
    }


@router.post("/user/conversations", status_code=status.HTTP_201_CREATED)
async def create_conversation(body: CreateConversationBody, session: UserSession):
    """
    Create a new conversation for the calling user.

    Returns: ``{"id": "<uuid>"}``
    """
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO conversations (account_id, title)
                    VALUES ($1, $2)
                    RETURNING id
                    """,
                    session.account_id,
                    body.title,
                )
    except Exception as exc:
        logger.error("create_conversation: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to create conversation."},
        ) from exc

    return {"id": str(row["id"])}


@router.get("/user/conversations/{conv_id}")
async def get_conversation(conv_id: str, session: UserSession):
    """
    Fetch a conversation and all its messages.

    BOLA: the query scopes by ``account_id = session.account_id``.
    Returns 404 if the conversation does not exist OR belongs to another user.
    """
    cid = _parse_conv_id(conv_id)
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            conv = await conn.fetchrow(
                """
                SELECT id, title, created_at, updated_at
                  FROM conversations
                 WHERE id = $1 AND account_id = $2
                """,
                cid,
                session.account_id,
            )
            if conv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"error": "not_found"},
                )
            msgs = await conn.fetch(
                """
                SELECT id, role, content, model, created_at, token_count, verdict
                  FROM messages
                 WHERE conversation_id = $1
                 ORDER BY created_at ASC
                """,
                cid,
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_conversation: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to fetch conversation."},
        ) from exc

    return {
        "id": str(conv["id"]),
        "title": conv["title"],
        "created_at": conv["created_at"].isoformat(),
        "updated_at": conv["updated_at"].isoformat(),
        "messages": [
            {
                "id": str(m["id"]),
                "role": m["role"],
                "content": m["content"],
                "model": m["model"],
                "created_at": m["created_at"].isoformat(),
                "token_count": m["token_count"],
                "verdict": m["verdict"],
            }
            for m in msgs
        ],
    }


@router.patch("/user/conversations/{conv_id}")
async def rename_conversation(
    conv_id: str,
    body: RenameConversationBody,
    session: UserSession,
):
    """
    Rename a conversation.

    BOLA: UPDATE scopes by ``account_id = session.account_id``.
    Returns 404 if not found or not owned by the caller.
    """
    cid = _parse_conv_id(conv_id)
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE conversations
                       SET title = $1, updated_at = NOW()
                     WHERE id = $2 AND account_id = $3
                    RETURNING id
                    """,
                    body.title,
                    cid,
                    session.account_id,
                )
    except Exception as exc:
        logger.error("rename_conversation: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to rename conversation."},
        ) from exc

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    return {"status": "ok", "id": str(row["id"]), "title": body.title}


@router.delete("/user/conversations/{conv_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(conv_id: str, session: UserSession):
    """
    Delete a conversation and all its messages (CASCADE).

    BOLA: DELETE scopes by ``account_id = session.account_id``.
    Returns 404 if not found or not owned by the caller.
    """
    cid = _parse_conv_id(conv_id)
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    DELETE FROM conversations
                     WHERE id = $1 AND account_id = $2
                    RETURNING id
                    """,
                    cid,
                    session.account_id,
                )
    except Exception as exc:
        logger.error("delete_conversation: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to delete conversation."},
        ) from exc

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    # 204 No Content — FastAPI returns empty body for status_code=204


@router.post(
    "/user/conversations/{conv_id}/messages",
    status_code=status.HTTP_201_CREATED,
)
async def append_messages(
    conv_id: str,
    body: AppendMessagesBody,
    session: UserSession,
):
    """
    Persist one or more chat messages under a conversation.

    The SPA calls this after each gateway round-trip to record the user
    message and the assistant response.  All messages are inserted in a
    single transaction; the conversation's ``updated_at`` is bumped.

    BOLA: ownership is verified with ``SELECT ... WHERE id=$1 AND account_id=$2``
    before the INSERT, inside the same transaction.  Returns 404 if not owned.

    Returns: ``{"ids": ["<uuid>", ...]}`` — one UUID per inserted message.
    """
    import json as _json

    cid = _parse_conv_id(conv_id)
    pool = _get_pool_or_503()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # BOLA ownership check — must be inside the transaction
                owner = await conn.fetchval(
                    """
                    SELECT id FROM conversations
                     WHERE id = $1 AND account_id = $2
                    """,
                    cid,
                    session.account_id,
                )
                if owner is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={"error": "not_found"},
                    )

                inserted_ids = []
                for msg in body.messages:
                    verdict_json = (
                        _json.dumps(msg.verdict) if msg.verdict is not None else None
                    )
                    row = await conn.fetchrow(
                        """
                        INSERT INTO messages
                            (conversation_id, role, content, model, token_count, verdict)
                        VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                        RETURNING id
                        """,
                        cid,
                        msg.role,
                        msg.content,
                        msg.model,
                        msg.token_count,
                        verdict_json,
                    )
                    inserted_ids.append(str(row["id"]))

                # Bump conversation updated_at
                await conn.execute(
                    "UPDATE conversations SET updated_at = NOW() WHERE id = $1",
                    cid,
                )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("append_messages: DB error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "db_error", "message": "Failed to persist messages."},
        ) from exc

    return {"ids": inserted_ids}
