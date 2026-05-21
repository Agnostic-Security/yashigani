"""
v2.23.4 arch-completion — Q3 F9 revert auto-reactivate + admin reactivate endpoint.

Covers:
  Q3-1 test_suspended_user_login_blocked
        — suspended identity → login returns 403 + audit log emitted
  Q3-2 test_suspended_user_login_no_reactivate
        — login does NOT call registry.reactivate (mock assert)
  Q3-3 test_admin_reactivate_endpoint_succeeds
        — admin StepUp + POST → 200, registry.reactivate called once
  Q3-4 test_admin_reactivate_requires_admin_tier
        — user-tier session → 403 (enforced by StepUpAdminSession dependency)
  Q3-5 test_admin_reactivate_requires_stepup
        — stale TOTP → 401 step_up_required (enforced by StepUpAdminSession)
  Q3-6 test_admin_reactivate_target_must_be_user_tier
        — admin target → 404
  Q3-7 test_admin_reactivate_audit_log
        — successful reactivate emits IDENTITY_REACTIVATED event with admin actor

Tiago directive 2026-05-15 (verbatim): auto-reactivate on login REVERTED;
reactivation is admin-action-only, audit-logged.

Source: src/yashigani/backoffice/routes/auth.py  — _register_human_identity_on_login
        src/yashigani/backoffice/routes/users.py — POST /{username}/reactivate

Last updated: 2026-05-15T00:00:00+01:00
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Optional
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Helpers shared across Q3 tests
# ---------------------------------------------------------------------------

@dataclass
class _Record:
    """Minimal AccountRecord for test scaffolding."""
    username: str
    account_id: str = "u-001"
    account_tier: str = "user"
    email: Optional[str] = "alice@example.com"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False


def _make_registry(existing_identity: dict | None = None):
    registry = MagicMock()
    registry.get_by_slug = MagicMock(return_value=existing_identity)
    registry.register = MagicMock(return_value=("idnt_new", "plaintext-key"))
    registry.reactivate = MagicMock()
    return registry


def _make_state(registry=None, audit_writer=None):
    state = MagicMock()
    state.identity_registry = registry
    state.audit_writer = audit_writer or MagicMock()
    state.audit_writer.write = MagicMock()
    return state


def _call_register(record, registry, audit_writer=None):
    """Invoke _register_human_identity_on_login with a pre-built state."""
    from yashigani.backoffice.routes.auth import _register_human_identity_on_login
    state = _make_state(registry=registry, audit_writer=audit_writer)
    _register_human_identity_on_login(record, state)
    return state


# ===========================================================================
# Q3-1 / Q3-2 — Login path: suspended identity is blocked, not reactivated
# ===========================================================================

class TestSuspendedIdentityLoginBlocked:
    """
    Q3 regression: suspended identity must block login (403), not auto-reactivate.

    Tiago directive 2026-05-15: "admin-action-only, audit-logged".
    """

    def test_suspended_user_login_blocked(self):
        """
        Q3-1: suspended identity → _register_human_identity_on_login raises HTTP 403
        with error=account_suspended.
        """
        from fastapi import HTTPException
        record = _Record(username="alice", account_id="u-001")
        suspended_identity = {
            "identity_id": "idnt-suspended",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        registry = _make_registry(existing_identity=suspended_identity)
        audit_writer = MagicMock()
        audit_writer.write = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            _call_register(record, registry, audit_writer=audit_writer)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "account_suspended"
        # Remediation message must mention "administrator"
        assert "administrator" in exc_info.value.detail["message"].lower()

    def test_inactive_identity_login_blocked(self):
        """
        Q3-1 variant: status='inactive' is treated identically to 'suspended'.
        """
        from fastapi import HTTPException
        record = _Record(username="alice", account_id="u-001")
        inactive_identity = {
            "identity_id": "idnt-inactive",
            "slug": "alice-example-com",
            "status": "inactive",
        }
        registry = _make_registry(existing_identity=inactive_identity)

        with pytest.raises(HTTPException) as exc_info:
            _call_register(record, registry)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "account_suspended"

    def test_suspended_user_login_no_reactivate(self):
        """
        Q3-2: login does NOT call registry.reactivate when identity is suspended.

        Critical regression guard: the old F9 implementation called
        registry.reactivate() on login. After Q3 revert, this MUST NOT happen.
        """
        from fastapi import HTTPException
        record = _Record(username="alice", account_id="u-001")
        suspended_identity = {
            "identity_id": "idnt-suspended",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        registry = _make_registry(existing_identity=suspended_identity)

        with pytest.raises(HTTPException):
            _call_register(record, registry)

        # The critical assertion: reactivate MUST NOT be called.
        registry.reactivate.assert_not_called()

    def test_suspended_login_emits_audit_event(self):
        """
        Q3-1 extended: when login is blocked, a LOGIN_BLOCKED_SUSPENDED_IDENTITY
        event must be written to the audit log before the 403 is raised.
        """
        from fastapi import HTTPException
        from yashigani.audit.schema import LoginBlockedSuspendedIdentityEvent, EventType

        record = _Record(username="alice", account_id="u-001")
        suspended_identity = {
            "identity_id": "idnt-suspended-audit",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        registry = _make_registry(existing_identity=suspended_identity)
        audit_writer = MagicMock()
        audit_writer.write = MagicMock()
        state = _make_state(registry=registry, audit_writer=audit_writer)

        from yashigani.backoffice.routes.auth import _register_human_identity_on_login

        with pytest.raises(HTTPException):
            _register_human_identity_on_login(record, state)

        # Verify audit event was written
        assert audit_writer.write.called, "audit_writer.write was not called"
        written_event = audit_writer.write.call_args[0][0]
        assert isinstance(written_event, LoginBlockedSuspendedIdentityEvent)
        assert written_event.username == "alice"
        assert written_event.identity_id == "idnt-suspended-audit"
        assert written_event.identity_status == "suspended"
        assert written_event.event_type == EventType.LOGIN_BLOCKED_SUSPENDED_IDENTITY

    def test_active_identity_still_permitted_login(self):
        """
        Regression guard: active identity must NOT be blocked — the Q3 change
        must not accidentally block non-suspended identities.
        """
        record = _Record(username="alice", account_id="u-001")
        active_identity = {
            "identity_id": "idnt-active",
            "slug": "alice-example-com",
            "status": "active",
        }
        registry = _make_registry(existing_identity=active_identity)
        # Must NOT raise
        _call_register(record, registry)
        registry.reactivate.assert_not_called()

    def test_new_identity_registered_normally(self):
        """
        New user (no existing identity): register() is still called normally.
        Q3 change must not affect the new-user registration path.
        """
        record = _Record(username="newuser", account_id="u-new")
        registry = _make_registry(existing_identity=None)
        _call_register(record, registry)
        registry.register.assert_called_once()
        registry.reactivate.assert_not_called()

    def test_admin_tier_not_affected(self):
        """
        Admin-tier records bypass the entire helper (account_tier guard).
        Q3 must not break the admin exclusion.
        """
        record = _Record(username="admin@corp.com", account_id="admin-001", account_tier="admin")
        suspended_identity = {
            "identity_id": "idnt-admin",
            "slug": "admin-corp-com",
            "status": "suspended",
        }
        registry = _make_registry(existing_identity=suspended_identity)
        # Must NOT raise — admin tier is excluded before slug lookup
        _call_register(record, registry)
        registry.get_by_slug.assert_not_called()


# ===========================================================================
# Q3-3 through Q3-7 — Admin reactivate endpoint
# ===========================================================================

def _make_user_record(username="alice", account_tier="user", email="alice@example.com"):
    record = MagicMock()
    record.username = username
    record.account_id = "u-001"
    record.account_tier = account_tier
    record.email = email
    return record


def _make_reactivate_state(
    user_record=None,
    identity=None,
    registry_available=True,
):
    """Build mock backoffice_state for the reactivate route handler."""
    auth_service = AsyncMock()
    auth_service.get_account = AsyncMock(return_value=user_record)

    registry = None
    if registry_available:
        registry = MagicMock()
        registry.get_by_slug = MagicMock(return_value=identity)
        registry.reactivate = MagicMock()

    audit_writer = MagicMock()
    audit_writer.write = MagicMock()

    state = MagicMock()
    state.auth_service = auth_service
    state.audit_writer = audit_writer
    state.identity_registry = registry
    return state


def _make_session(account_id="admin-001", account_tier="admin"):
    from yashigani.backoffice.middleware import Session
    session = MagicMock(spec=Session)
    session.account_id = account_id
    session.account_tier = account_tier
    return session


class TestAdminReactivateEndpoint:
    """
    Q3-3 through Q3-7: POST /admin/users/{username}/reactivate endpoint.
    """

    @pytest.mark.asyncio
    async def test_admin_reactivate_endpoint_succeeds(self):
        """
        Q3-3: admin StepUp + POST → 200, registry.reactivate called once.
        """
        from yashigani.backoffice.routes import users as _users_mod

        user_record = _make_user_record()
        suspended_identity = {
            "identity_id": "idnt-suspended",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        mock_state = _make_reactivate_state(
            user_record=user_record,
            identity=suspended_identity,
        )

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest(reason="reinstating after leave")
            session = _make_session()

            result = await reactivate_user("alice", body, session)

        assert result["status"] == "ok"
        assert result["identity_id"] == "idnt-suspended"
        assert result["identity_status"] == "active"
        mock_state.identity_registry.reactivate.assert_called_once_with("idnt-suspended")

    @pytest.mark.asyncio
    async def test_admin_reactivate_target_must_be_user_tier(self):
        """
        Q3-6: target is account_tier='admin' → 404.
        The endpoint refuses to reactivate admin accounts.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        admin_record = _make_user_record(username="superadmin", account_tier="admin")
        mock_state = _make_reactivate_state(user_record=admin_record)

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()
            session = _make_session()

            with pytest.raises(HTTPException) as exc_info:
                await reactivate_user("superadmin", body, session)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "account_not_found"

    @pytest.mark.asyncio
    async def test_admin_reactivate_user_not_found(self):
        """
        Q3-6 variant: target username does not exist → 404.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        mock_state = _make_reactivate_state(user_record=None)

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()
            session = _make_session()

            with pytest.raises(HTTPException) as exc_info:
                await reactivate_user("nonexistent", body, session)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "account_not_found"

    @pytest.mark.asyncio
    async def test_admin_reactivate_no_identity_found(self):
        """
        Q3-6 variant: user exists but has no HUMAN identity (never logged in) → 404.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        user_record = _make_user_record()
        mock_state = _make_reactivate_state(user_record=user_record, identity=None)

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()
            session = _make_session()

            with pytest.raises(HTTPException) as exc_info:
                await reactivate_user("alice", body, session)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "identity_not_found"

    @pytest.mark.asyncio
    async def test_admin_reactivate_already_active_idempotent(self):
        """
        Active identity: returns 200 without calling registry.reactivate.
        Idempotent — safe to call multiple times.
        """
        from yashigani.backoffice.routes import users as _users_mod

        user_record = _make_user_record()
        active_identity = {
            "identity_id": "idnt-active",
            "slug": "alice-example-com",
            "status": "active",
        }
        mock_state = _make_reactivate_state(user_record=user_record, identity=active_identity)

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()
            session = _make_session()

            result = await reactivate_user("alice", body, session)

        assert result["status"] == "ok"
        assert result["identity_status"] == "active"
        # Idempotent: reactivate NOT called when already active
        mock_state.identity_registry.reactivate.assert_not_called()

    @pytest.mark.asyncio
    async def test_admin_reactivate_audit_log(self):
        """
        Q3-7: successful reactivation emits IDENTITY_REACTIVATED event with
        admin actor, target username, and target identity_id.
        """
        from yashigani.backoffice.routes import users as _users_mod
        from yashigani.audit.schema import IdentityReactivatedEvent, EventType

        user_record = _make_user_record()
        suspended_identity = {
            "identity_id": "idnt-for-audit",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        mock_state = _make_reactivate_state(
            user_record=user_record,
            identity=suspended_identity,
        )

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest(reason="compliance audit clearance")
            session = _make_session(account_id="admin-007")

            await reactivate_user("alice", body, session)

        # Verify audit log
        assert mock_state.audit_writer.write.called
        written_event = mock_state.audit_writer.write.call_args[0][0]
        assert isinstance(written_event, IdentityReactivatedEvent)
        assert written_event.acting_admin_account_id == "admin-007"
        assert written_event.target_username == "alice"
        assert written_event.target_identity_id == "idnt-for-audit"
        assert written_event.reason == "compliance audit clearance"
        assert written_event.event_type == EventType.IDENTITY_REACTIVATED

    @pytest.mark.asyncio
    async def test_admin_reactivate_audit_log_reason_optional(self):
        """
        Q3-7 variant: reason is optional — empty reason is still audit-logged
        (with empty string, not None).
        """
        from yashigani.backoffice.routes import users as _users_mod
        from yashigani.audit.schema import IdentityReactivatedEvent

        user_record = _make_user_record()
        suspended_identity = {
            "identity_id": "idnt-no-reason",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        mock_state = _make_reactivate_state(
            user_record=user_record,
            identity=suspended_identity,
        )

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()  # no reason
            session = _make_session()

            await reactivate_user("alice", body, session)

        written_event = mock_state.audit_writer.write.call_args[0][0]
        assert isinstance(written_event, IdentityReactivatedEvent)
        assert written_event.reason == ""  # empty string, not None

    @pytest.mark.asyncio
    async def test_admin_reactivate_registry_unavailable_503(self):
        """
        Registry is None (community-tier): returns 503.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        user_record = _make_user_record()
        mock_state = _make_reactivate_state(
            user_record=user_record,
            registry_available=False,
        )

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state):

            from yashigani.backoffice.routes.users import reactivate_user, ReactivateRequest
            body = ReactivateRequest()
            session = _make_session()

            with pytest.raises(HTTPException) as exc_info:
                await reactivate_user("alice", body, session)

        assert exc_info.value.status_code == 503
        assert "registry" in exc_info.value.detail["error"]


# ===========================================================================
# Q3-4 / Q3-5 — StepUpAdminSession enforcement (middleware-level)
#
# These tests verify the middleware dependency raises the correct HTTP error
# shapes. Because StepUpAdminSession is a FastAPI Depends(), the full
# enforcement runs at request dispatch time — we test the middleware directly.
# ===========================================================================

class TestStepUpEnforcement:

    def test_stepup_session_dependency_exists(self):
        """
        Confirm StepUpAdminSession is imported and used as the session param type
        in the reactivate route.
        """
        import inspect
        from yashigani.backoffice.routes.users import reactivate_user
        from yashigani.backoffice.middleware import StepUpAdminSession

        sig = inspect.signature(reactivate_user)
        session_param = sig.parameters.get("session")
        assert session_param is not None, "reactivate_user must have a 'session' parameter"
        # The annotation must reference StepUpAdminSession or its Annotated wrapper.
        # Check that the underlying dependency is require_stepup_admin_session.
        from yashigani.backoffice.middleware import require_stepup_admin_session
        ann = session_param.annotation
        # Annotated[Session, Depends(require_stepup_admin_session)] — check metadata
        import typing
        if hasattr(ann, "__metadata__"):
            from fastapi import Depends
            deps = [m for m in ann.__metadata__ if hasattr(m, "dependency")]
            assert any(d.dependency is require_stepup_admin_session for d in deps), (
                "reactivate_user session must depend on require_stepup_admin_session"
            )

    def test_require_stepup_raises_step_up_required_without_fresh_totp(self):
        """
        Q3-5: stale TOTP → require_stepup_admin_session raises 401 step_up_required.

        Tested by calling require_stepup_admin_session directly with a mock
        session that has no recent TOTP stamp.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.middleware import require_stepup_admin_session

        # Stale session: no last_totp_verified_at or very old
        stale_session = MagicMock()
        stale_session.account_id = "u-001"
        stale_session.account_tier = "admin"
        stale_session.token = "stale-token"
        stale_session.expires_at = 9999999999
        stale_session.last_totp_verified_at = 0  # epoch — definitely stale

        with pytest.raises(HTTPException) as exc_info:
            require_stepup_admin_session(stale_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["error"] == "step_up_required"
