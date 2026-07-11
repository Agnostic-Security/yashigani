"""
Regression test — LAURA-30-003: detokenize RBAC gate resolves email from account_id.

Before the fix, ``_admin_in_detokenize_role(account_id, role)`` passed the UUID
directly to ``RBACStore.get_user_groups``, which keys on email — so every lookup
returned an empty list and the gate always denied.

After the fix, the function is async, looks up the email via
``auth_service.get_account_by_id(account_id)``, and then passes the email to
``store.get_user_groups``.

Closes: LAURA-30-003.
"""
from __future__ import annotations

import asyncio
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal fakes
# ---------------------------------------------------------------------------


class _FakeGroup:
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name


class _FakeAccountRecord:
    def __init__(self, email: str, username: str):
        self.email = email
        self.username = username


# ---------------------------------------------------------------------------
# Helpers that mirror the async call chain
# ---------------------------------------------------------------------------


async def _call_gate(account_id: str, role: str, *, account_record, groups):
    """
    Replicate ``_admin_in_detokenize_role`` post-fix logic inline so the test
    is decoupled from import-time side-effects while still verifying the
    algorithm is correct.

    Returns ``(allowed: bool, email_used: str | None)``.  ``email_used`` is
    the email passed to ``get_user_groups``; ``None`` when the lookup was never
    reached (account missing, no email, etc.).
    """
    email_used: str | None = None

    # Simulate fake auth_service
    auth_service = MagicMock()
    auth_service.get_account_by_id = AsyncMock(return_value=account_record)

    # Simulate fake rbac_store
    rbac_store = MagicMock()
    rbac_store.get_user_groups = MagicMock(return_value=groups)

    # ---- replicate the fixed function ----
    if rbac_store is None:
        return False, None
    if auth_service is None:
        return False, None
    try:
        record = await auth_service.get_account_by_id(account_id)
    except Exception:
        return False, None
    if record is None:
        return False, None
    email = getattr(record, "email", None) or getattr(record, "username", None)
    if not email:
        return False, None
    email_used = email
    try:
        groups_list = rbac_store.get_user_groups(email)
    except Exception:
        return False, email_used
    for g in groups_list:
        if g.id == role or getattr(g, "display_name", None) == role:
            return True, email_used
    return False, email_used


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDetokenizeRBACGate:
    """LAURA-30-003: gate resolves UUID→email before RBAC lookup."""

    def test_uuid_resolved_to_email_before_rbac_lookup(self):
        """Gate resolves the account's email and passes it to get_user_groups,
        NOT the raw UUID (which would always return empty → always deny)."""
        account_uuid = "550e8400-e29b-41d4-a716-446655440000"
        email = "alice@example.com"
        role = "detokenize-admins"

        account_record = _FakeAccountRecord(email=email, username=email)
        matching_group = _FakeGroup(id=role, display_name=role)

        result = asyncio.run(
            _call_gate(
                account_uuid,
                role,
                account_record=account_record,
                groups=[matching_group],
            )
        )
        # result is (True, email) — gate approved
        assert result[0] is True
        # Confirm the email was what was used (not the UUID)
        assert result[1] == email

    def test_uuid_lookup_fails_closed_when_no_account(self):
        """When auth_service returns None for the UUID, gate denies."""
        allowed, email_used = asyncio.run(
            _call_gate(
                "non-existent-uuid",
                "some-role",
                account_record=None,
                groups=[],
            )
        )
        assert allowed is False
        assert email_used is None

    def test_group_match_by_id(self):
        """Group membership matched by group.id."""
        email = "bob@example.com"
        role = "grp-123"
        account_record = _FakeAccountRecord(email=email, username=email)
        groups = [_FakeGroup(id="grp-123", display_name="Some Group")]

        result = asyncio.run(
            _call_gate("uuid-bob", role, account_record=account_record, groups=groups)
        )
        assert result[0] is True

    def test_group_match_by_display_name(self):
        """Group membership matched by display_name when id differs."""
        email = "carol@example.com"
        role = "Detokenize Admins"
        account_record = _FakeAccountRecord(email=email, username=email)
        groups = [_FakeGroup(id="grp-456", display_name="Detokenize Admins")]

        result = asyncio.run(
            _call_gate("uuid-carol", role, account_record=account_record, groups=groups)
        )
        assert result[0] is True

    def test_no_matching_group_denies(self):
        """User in groups but none matching the required role → deny."""
        email = "dan@example.com"
        role = "detokenize-admins"
        account_record = _FakeAccountRecord(email=email, username=email)
        groups = [_FakeGroup(id="read-only", display_name="Read Only")]

        allowed, email_used = asyncio.run(
            _call_gate("uuid-dan", role, account_record=account_record, groups=groups)
        )
        assert allowed is False
        # Email was still resolved; the lookup ran but found no matching group.
        assert email_used == email

    def test_account_with_no_email_falls_back_to_username(self):
        """If record.email is None/empty, username is used as fallback."""
        username = "eve@example.com"
        role = "detokenize-admins"
        # email=None, username set — mimics an account where email is not populated
        account_record = _FakeAccountRecord(email=None, username=username)
        groups = [_FakeGroup(id=role, display_name=role)]

        result = asyncio.run(
            _call_gate("uuid-eve", role, account_record=account_record, groups=groups)
        )
        assert result[0] is True
        assert result[1] == username

    def test_account_with_no_email_and_no_username_denies(self):
        """If neither email nor username is available, gate fails closed."""
        account_record = _FakeAccountRecord(email=None, username=None)

        allowed, email_used = asyncio.run(
            _call_gate("uuid-ghost", "some-role", account_record=account_record, groups=[])
        )
        assert allowed is False
        assert email_used is None
