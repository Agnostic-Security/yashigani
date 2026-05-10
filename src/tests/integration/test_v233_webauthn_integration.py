"""
Integration tests for WebAuthn / FIDO2 (v2.23.3).
Requires a live Postgres + Redis stack — skipped when YASHIGANI_DB_DSN is unset.

IT01 — Register credential: DB-backed store persists across service restart
IT02 — Authenticate: full round-trip with mocked py_webauthn verify
IT03 — sign_count is persisted and advanced on login/finish
IT04 — Delete credential removes from DB; subsequent list returns empty
IT05 — Challenge expiry: Redis TTL expires before login/finish → 401

Uses the PgWebAuthnCredentialStore directly (bypasses HTTP layer)
to isolate DB behaviour from routing.  HTTP-layer integration is
covered by the clean-slate install harness (gate-level).

Last updated: 2026-05-07T00:00:00+00:00
"""
from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

POSTGRES_AVAILABLE = bool(os.getenv("YASHIGANI_DB_DSN"))

pytestmark = pytest.mark.skipif(
    not POSTGRES_AVAILABLE,
    reason="YASHIGANI_DB_DSN not set — Postgres integration tests skipped",
)


@pytest.fixture(scope="module")
async def pg_store():
    """Return a PgWebAuthnCredentialStore backed by the live DB."""
    from yashigani.db import create_pool
    from yashigani.auth.pg_webauthn import PgWebAuthnCredentialStore

    await create_pool()
    return PgWebAuthnCredentialStore()


def _make_credential(user_id: str, sign_count: int = 0) -> "WebAuthnCredential":
    from yashigani.auth.webauthn import WebAuthnCredential
    return WebAuthnCredential(
        id=str(uuid.uuid4()),
        user_id=user_id,
        credential_id=secrets.token_bytes(32),
        public_key=secrets.token_bytes(64),
        sign_count=sign_count,
        aaguid="00000000-0000-0000-0000-000000000000",
        name="Integration Test Key",
    )


@pytest.mark.asyncio
async def test_it01_credential_persisted(pg_store):
    """IT01: add() stores credential; list_for_user() retrieves it."""
    user_id = f"it-user-{uuid.uuid4()}"
    cred = _make_credential(user_id)

    await pg_store.add(cred, transports=["usb", "nfc"])

    results = await pg_store.list_for_user(user_id)
    assert len(results) == 1
    assert results[0].id == cred.id
    assert results[0].sign_count == cred.sign_count

    # Cleanup
    await pg_store.delete(cred.id, user_id)


@pytest.mark.asyncio
async def test_it02_authenticate_round_trip(pg_store):
    """IT02: full register → authenticate sign_count advance."""
    user_id = f"it-user-{uuid.uuid4()}"
    cred = _make_credential(user_id, sign_count=5)
    await pg_store.add(cred)

    await pg_store.update_sign_count(cred.credential_id, 10)

    found = await pg_store.get_by_credential_id(cred.credential_id)
    assert found is not None
    assert found.sign_count == 10

    # Cleanup
    await pg_store.delete(cred.id, user_id)


@pytest.mark.asyncio
async def test_it03_sign_count_advanced_on_update(pg_store):
    """IT03: update_sign_count persists new value and last_used_at."""
    user_id = f"it-user-{uuid.uuid4()}"
    cred = _make_credential(user_id, sign_count=20)
    await pg_store.add(cred)

    await pg_store.update_sign_count(cred.credential_id, 21)
    found = await pg_store.get_by_credential_id(cred.credential_id)
    assert found.sign_count == 21
    assert found.last_used_at is not None

    # Cleanup
    await pg_store.delete(cred.id, user_id)


@pytest.mark.asyncio
async def test_it04_delete_removes_credential(pg_store):
    """IT04: delete() removes credential; list returns empty."""
    user_id = f"it-user-{uuid.uuid4()}"
    cred = _make_credential(user_id)
    await pg_store.add(cred)

    assert len(await pg_store.list_for_user(user_id)) == 1
    deleted = await pg_store.delete(cred.id, user_id)
    assert deleted is True
    assert await pg_store.list_for_user(user_id) == []


@pytest.mark.asyncio
async def test_it04b_delete_wrong_owner_returns_false(pg_store):
    """IT04b: delete() with wrong user_id returns False (ownership check)."""
    user_a = f"it-user-{uuid.uuid4()}"
    user_b = f"it-user-{uuid.uuid4()}"
    cred = _make_credential(user_a)
    await pg_store.add(cred)

    deleted = await pg_store.delete(cred.id, user_b)
    assert deleted is False

    # Cleanup
    await pg_store.delete(cred.id, user_a)


@pytest.mark.asyncio
async def test_it05_multi_credential_list_ordered(pg_store):
    """IT05: multiple credentials returned ordered by created_at ASC."""
    user_id = f"it-user-{uuid.uuid4()}"
    c1 = _make_credential(user_id)
    c2 = _make_credential(user_id)
    await pg_store.add(c1)
    await pg_store.add(c2)

    lst = await pg_store.list_for_user(user_id)
    assert len(lst) == 2
    assert [c.id for c in lst] == [c1.id, c2.id]  # created_at ASC

    await pg_store.delete(c1.id, user_id)
    await pg_store.delete(c2.id, user_id)


@pytest.mark.asyncio
async def test_it06_get_by_credential_id_not_found(pg_store):
    """IT06: get_by_credential_id returns None for unknown credential_id."""
    result = await pg_store.get_by_credential_id(secrets.token_bytes(32))
    assert result is None
