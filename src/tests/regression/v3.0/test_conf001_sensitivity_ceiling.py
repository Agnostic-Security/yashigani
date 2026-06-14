"""
Regression tests — CONF-001 (AVA-2255-02): sensitivity_ceiling writable via
PUT /admin/users/{username}.

Verifies:
  1. UpdateUserRequest accepts valid sensitivity_ceiling values.
  2. UpdateUserRequest rejects invalid sensitivity_ceiling values (422).
  3. Valid values are normalised to upper-case.
  4. update_user writes sensitivity_ceiling to identity registry when identity exists.
  5. update_user skips gracefully when identity does not exist (no error).
  6. update_user skips gracefully when identity_registry is not wired.
  7. Audit event is emitted on successful sensitivity_ceiling change.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# 1. UpdateUserRequest — valid ceiling values
# ---------------------------------------------------------------------------

def test_update_user_request_valid_ceilings():
    """CONF-001: all four valid ceiling values are accepted."""
    from yashigani.backoffice.routes.users import UpdateUserRequest

    for val in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"):
        req = UpdateUserRequest(sensitivity_ceiling=val)
        assert req.sensitivity_ceiling == val


def test_update_user_request_ceiling_normalised_to_upper():
    """CONF-001: sensitivity_ceiling is normalised to UPPER on parse."""
    from yashigani.backoffice.routes.users import UpdateUserRequest

    for val, expected in [
        ("public", "PUBLIC"),
        ("internal", "INTERNAL"),
        ("Confidential", "CONFIDENTIAL"),
        (" RESTRICTED ", "RESTRICTED"),
    ]:
        req = UpdateUserRequest(sensitivity_ceiling=val)
        assert req.sensitivity_ceiling == expected, (
            f"Expected {expected!r} for input {val!r}, got {req.sensitivity_ceiling!r}"
        )


# ---------------------------------------------------------------------------
# 2. UpdateUserRequest — invalid values rejected with 422
# ---------------------------------------------------------------------------

def test_update_user_request_invalid_ceiling_rejected():
    """CONF-001: invalid sensitivity_ceiling raises ValidationError."""
    from yashigani.backoffice.routes.users import UpdateUserRequest

    for bad in ("TOP_SECRET", "level5", "", "1", "high", "low"):
        with pytest.raises(ValidationError):
            UpdateUserRequest(sensitivity_ceiling=bad)


# ---------------------------------------------------------------------------
# 3. UpdateUserRequest — None is accepted (no change)
# ---------------------------------------------------------------------------

def test_update_user_request_ceiling_none_accepted():
    """CONF-001: sensitivity_ceiling=None leaves field unset (no change)."""
    from yashigani.backoffice.routes.users import UpdateUserRequest

    req = UpdateUserRequest(sensitivity_ceiling=None)
    assert req.sensitivity_ceiling is None


# ---------------------------------------------------------------------------
# 4. update_user writes to identity registry when identity exists
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_user_sensitivity_ceiling_written_to_registry():
    """CONF-001: update_user calls registry.update(sensitivity_ceiling=...) when identity found."""
    import time
    from unittest.mock import AsyncMock, MagicMock

    from yashigani.backoffice.routes import users as users_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()

    # Auth service mock
    mock_auth = MagicMock()
    mock_record = MagicMock()
    mock_record.account_tier = "user"
    mock_record.disabled = False
    mock_record.email = "alice@example.com"
    mock_record.username = "alice"
    mock_auth.get_account = AsyncMock(return_value=mock_record)
    state.auth_service = mock_auth

    # Session store mock
    state.session_store = MagicMock()

    # Audit writer mock
    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    # Identity registry mock — returns an existing identity
    mock_registry = MagicMock()
    mock_registry.get_by_slug.return_value = {
        "identity_id": "id-abc123",
        "sensitivity_ceiling": "PUBLIC",
    }
    mock_registry.update = MagicMock()
    state.identity_registry = mock_registry

    # Patch backoffice_state
    original_state = users_mod.backoffice_state
    users_mod.backoffice_state = state

    try:
        now = time.time()
        from yashigani.auth.session import Session

        session = Session(
            token="t",
            account_id="admin1",
            account_tier="admin",
            created_at=now,
            last_active_at=now,
            expires_at=now + 3600,
            ip_prefix="127.0.0",
            last_totp_verified_at=now,
        )

        from yashigani.backoffice.routes.users import UpdateUserRequest, update_user

        body = UpdateUserRequest(sensitivity_ceiling="CONFIDENTIAL")
        result = await update_user("alice", body, session)
    finally:
        users_mod.backoffice_state = original_state

    # Registry update was called with the correct ceiling
    mock_registry.update.assert_called_once_with("id-abc123", sensitivity_ceiling="CONFIDENTIAL")
    assert "sensitivity_ceiling" in result["changed"]
    # Audit event emitted
    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.setting == "user_sensitivity_ceiling_changed"
    assert evt.previous_value == "PUBLIC"
    assert evt.new_value == "CONFIDENTIAL"


# ---------------------------------------------------------------------------
# 5. update_user — no identity in registry → skip gracefully
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_user_sensitivity_ceiling_no_identity_skips():
    """CONF-001: if HUMAN identity not in registry yet, sensitivity_ceiling skipped (no error)."""
    import time
    from unittest.mock import AsyncMock, MagicMock

    from yashigani.backoffice.routes import users as users_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()

    mock_auth = MagicMock()
    mock_record = MagicMock()
    mock_record.account_tier = "user"
    mock_record.disabled = False
    mock_record.email = "bob@example.com"
    mock_record.username = "bob"
    mock_auth.get_account = AsyncMock(return_value=mock_record)
    state.auth_service = mock_auth
    state.session_store = MagicMock()
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()

    mock_registry = MagicMock()
    mock_registry.get_by_slug.return_value = None  # no identity yet
    mock_registry.update = MagicMock()
    state.identity_registry = mock_registry

    original_state = users_mod.backoffice_state
    users_mod.backoffice_state = state

    try:
        now = time.time()
        from yashigani.auth.session import Session
        from yashigani.backoffice.routes.users import UpdateUserRequest, update_user

        session = Session(
            token="t",
            account_id="admin1",
            account_tier="admin",
            created_at=now,
            last_active_at=now,
            expires_at=now + 3600,
            ip_prefix="127.0.0",
            last_totp_verified_at=now,
        )
        body = UpdateUserRequest(sensitivity_ceiling="RESTRICTED")
        result = await update_user("bob", body, session)
    finally:
        users_mod.backoffice_state = original_state

    # Should succeed, but sensitivity_ceiling NOT in changed (identity absent)
    assert result["status"] == "ok"
    assert "sensitivity_ceiling" not in result["changed"]
    # Registry.update must NOT have been called
    mock_registry.update.assert_not_called()


# ---------------------------------------------------------------------------
# 6. update_user — identity_registry not wired → skip gracefully
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_user_sensitivity_ceiling_no_registry_skips():
    """CONF-001: if identity_registry is None, sensitivity_ceiling skipped (no error)."""
    import time
    from unittest.mock import AsyncMock, MagicMock

    from yashigani.backoffice.routes import users as users_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()

    mock_auth = MagicMock()
    mock_record = MagicMock()
    mock_record.account_tier = "user"
    mock_record.disabled = False
    mock_record.email = "carol@example.com"
    mock_record.username = "carol"
    mock_auth.get_account = AsyncMock(return_value=mock_record)
    state.auth_service = mock_auth
    state.session_store = MagicMock()
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()
    state.identity_registry = None  # not wired

    original_state = users_mod.backoffice_state
    users_mod.backoffice_state = state

    try:
        now = time.time()
        from yashigani.auth.session import Session
        from yashigani.backoffice.routes.users import UpdateUserRequest, update_user

        session = Session(
            token="t",
            account_id="admin1",
            account_tier="admin",
            created_at=now,
            last_active_at=now,
            expires_at=now + 3600,
            ip_prefix="127.0.0",
            last_totp_verified_at=now,
        )
        body = UpdateUserRequest(sensitivity_ceiling="INTERNAL")
        result = await update_user("carol", body, session)
    finally:
        users_mod.backoffice_state = original_state

    assert result["status"] == "ok"
    assert "sensitivity_ceiling" not in result["changed"]


# ---------------------------------------------------------------------------
# 7. No audit event when ceiling unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_user_sensitivity_ceiling_no_audit_if_unchanged():
    """CONF-001: no audit event if ceiling is already at the requested value."""
    import time
    from unittest.mock import AsyncMock, MagicMock

    from yashigani.backoffice.routes import users as users_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()

    mock_auth = MagicMock()
    mock_record = MagicMock()
    mock_record.account_tier = "user"
    mock_record.disabled = False
    mock_record.email = "dave@example.com"
    mock_record.username = "dave"
    mock_auth.get_account = AsyncMock(return_value=mock_record)
    state.auth_service = mock_auth
    state.session_store = MagicMock()

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    mock_registry = MagicMock()
    mock_registry.get_by_slug.return_value = {
        "identity_id": "id-dave",
        "sensitivity_ceiling": "INTERNAL",  # already INTERNAL
    }
    mock_registry.update = MagicMock()
    state.identity_registry = mock_registry

    original_state = users_mod.backoffice_state
    users_mod.backoffice_state = state

    try:
        now = time.time()
        from yashigani.auth.session import Session
        from yashigani.backoffice.routes.users import UpdateUserRequest, update_user

        session = Session(
            token="t",
            account_id="admin1",
            account_tier="admin",
            created_at=now,
            last_active_at=now,
            expires_at=now + 3600,
            ip_prefix="127.0.0",
            last_totp_verified_at=now,
        )
        body = UpdateUserRequest(sensitivity_ceiling="INTERNAL")  # same as current
        result = await update_user("dave", body, session)
    finally:
        users_mod.backoffice_state = original_state

    # No change → not in changed list, no registry update, no audit event
    assert "sensitivity_ceiling" not in result["changed"]
    mock_registry.update.assert_not_called()
    assert audit_events == []
