"""
Unit tests — SoD Admin/User Separation-of-Duties (Iris #96, v2.24.1).

Covers SoD-001..005 enforcement gaps:
  SoD-001: admin creation rejected when user-tier account exists with same username/email
  SoD-002a: user creation rejected when admin account exists with same username/email
  SoD-002b: SCIM provision rejected when admin account exists with same email
  SoD-002c: SSO/OIDC provision rejected when admin account exists with same email
  SoD-003: /auth/verify rejects admin sessions with HTTP 403
  SoD-004: end-to-end exploit chain blocked (SoD-002c + SoD-003 combined)
  SoD-005: cron audit emits IDENTITY_STORE_CONFLICT on collision

NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2
Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch, call
import pytest

from yashigani.audit.schema import (
    AdminCreateRejectedUserExistsEvent,
    AuthVerifyRejectedAdminSessionEvent,
    EventType,
    IdentityStoreConflictEvent,
    ScimProvisionRejectedAdminExistsEvent,
    SsoProvisionRejectedAdminExistsEvent,
    UserCreateRejectedAdminExistsEvent,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_account(username: str, account_tier: str, email: str = "") -> MagicMock:
    acct = MagicMock()
    acct.username = username
    acct.account_tier = account_tier
    acct.email = email or f"{username}@example.com"
    acct.account_id = f"uuid-{username}"
    acct.disabled = False
    acct.force_password_change = False
    acct.force_totp_provision = False
    acct.created_at = 0.0
    return acct


def _make_session(account_id: str, account_tier: str, token: str = "tok-abc") -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    sess.account_tier = account_tier
    sess.token = token
    return sess


# ---------------------------------------------------------------------------
# SoD-001: Admin creation collision checks
# ---------------------------------------------------------------------------

class TestSoD001AdminCreationCollision:
    """Admin creation must reject if user-tier account exists with same identity."""

    @pytest.mark.asyncio
    async def test_create_admin_collision_with_existing_user_raises_409(self):
        """SoD-001: create_admin blocked when user account exists with same username."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import accounts as _accounts_mod

        existing_user = _make_account("alice@example.com", "user")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_user)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.total_admin_count = AsyncMock(return_value=0)
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")

        body = MagicMock()
        body.username = "alice@example.com"

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            # License check must pass
            with patch("yashigani.licensing.enforcer.check_admin_seat_limit"):
                with pytest.raises(HTTPException) as exc_info:
                    await _accounts_mod.create_admin(body, mock_session)

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] in ("username_taken", "admin_user_collision")

    @pytest.mark.asyncio
    async def test_create_admin_no_collision_succeeds(self):
        """SoD-001: create_admin proceeds when no collision exists."""
        from yashigani.backoffice.routes import accounts as _accounts_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        # No existing account with this username
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.total_admin_count = AsyncMock(return_value=1)

        created_admin = _make_account("newadmin@example.com", "admin")
        mock_state.auth_service.create_admin = AsyncMock(return_value=(created_admin, "temp-pw"))
        mock_state.auth_service.set_totp_secret_direct = AsyncMock()
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.username = "newadmin@example.com"

        mock_totp = MagicMock()
        mock_totp.secret_b32 = "JBSWY3DPEHPK3PXP"
        mock_totp.provisioning_uri = "otpauth://totp/..."

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            with patch("yashigani.licensing.enforcer.check_admin_seat_limit"):
                with patch("yashigani.auth.totp.generate_provisioning", return_value=mock_totp):
                    result = await _accounts_mod.create_admin(body, mock_session)

        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_create_admin_collision_emits_audit_event(self):
        """SoD-001: collision emits ADMIN_CREATE_REJECTED_USER_EXISTS audit event."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import accounts as _accounts_mod

        existing_user = _make_account("shared@example.com", "user")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_user)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.total_admin_count = AsyncMock(return_value=1)
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.username = "shared@example.com"

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            with patch("yashigani.licensing.enforcer.check_admin_seat_limit"):
                with pytest.raises(HTTPException):
                    await _accounts_mod.create_admin(body, mock_session)

        # Audit write should have been called (either from username_taken or admin_user_collision path)
        # The 409 username_taken path does NOT emit audit; admin_user_collision DOES.
        # Since existing_user.account_tier == "user", it routes to admin_user_collision.
        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], AdminCreateRejectedUserExistsEvent)]
        assert len(sod_events) == 1


# ---------------------------------------------------------------------------
# SoD-002a: User creation collision checks
# ---------------------------------------------------------------------------

class TestSoD002aUserCreationCollision:
    """User creation must reject if admin account exists with same identity."""

    @pytest.mark.asyncio
    async def test_create_user_collision_with_existing_admin_raises_409(self):
        """SoD-002a: create_user blocked when admin account exists with same email."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        existing_admin = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        # First get_account (username check) returns None, then by email returns admin
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.total_user_count = AsyncMock(return_value=0)
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.email = "admin@example.com"
        body.username = "adminexample"  # derived from email

        with patch.object(_users_mod, "backoffice_state", mock_state):
            with patch("yashigani.licensing.enforcer.check_end_user_limit"):
                with pytest.raises(HTTPException) as exc_info:
                    await _users_mod.create_user(body, mock_session)

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "admin_user_collision"

    @pytest.mark.asyncio
    async def test_create_user_no_collision_succeeds(self):
        """SoD-002a: create_user proceeds when no admin collision exists."""
        from yashigani.backoffice.routes import users as _users_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.total_user_count = AsyncMock(return_value=0)

        created_user = _make_account("newuser", "user", "newuser@example.com")
        mock_state.auth_service.create_user = AsyncMock(return_value=created_user)
        mock_state.auth_service.set_email = AsyncMock()
        mock_state.auth_service.set_totp_secret_direct = AsyncMock()
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.email = "newuser@example.com"
        body.username = "newuserexample"

        mock_totp = MagicMock()
        mock_totp.secret_b32 = "JBSWY3DPEHPK3PXP"
        mock_totp.provisioning_uri = "otpauth://totp/..."

        with patch.object(_users_mod, "backoffice_state", mock_state):
            with patch("yashigani.licensing.enforcer.check_end_user_limit"):
                with patch("yashigani.auth.totp.generate_provisioning", return_value=mock_totp):
                    with patch("yashigani.auth.password.generate_password", return_value="temp-pw-xxxx"):
                        result = await _users_mod.create_user(body, mock_session)

        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_create_user_collision_emits_audit_event(self):
        """SoD-002a: collision emits USER_CREATE_REJECTED_ADMIN_EXISTS audit event."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import users as _users_mod

        existing_admin = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.total_user_count = AsyncMock(return_value=0)
        mock_state.audit_writer = MagicMock()

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.email = "admin@example.com"
        body.username = "adminexample"

        with patch.object(_users_mod, "backoffice_state", mock_state):
            with patch("yashigani.licensing.enforcer.check_end_user_limit"):
                with pytest.raises(HTTPException):
                    await _users_mod.create_user(body, mock_session)

        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], UserCreateRejectedAdminExistsEvent)]
        assert len(sod_events) == 1


# ---------------------------------------------------------------------------
# SoD-002b: SCIM provision collision checks
# ---------------------------------------------------------------------------

class TestSoD002bScimProvisionCollision:
    """SCIM provision must reject if admin account exists with same email."""

    @pytest.mark.asyncio
    async def test_scim_provision_blocked_when_admin_exists(self):
        """SoD-002b: scim_provision_user returns SCIM 409 when admin exists."""
        from yashigani.backoffice.routes import scim as _scim_mod

        existing_admin = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)  # fallback
        mock_state.identity_registry = None
        mock_state.audit_writer = MagicMock()

        mock_store = MagicMock()
        mock_store.get_user_groups = MagicMock(return_value=[])

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.userName = "admin@example.com"

        # Patch require_feature in the scim module's own namespace (it uses 'from ... import')
        with patch.object(_scim_mod, "backoffice_state", mock_state):
            with patch.object(_scim_mod, "_get_store", return_value=mock_store):
                with patch.object(_scim_mod, "require_feature"):
                    result = await _scim_mod.scim_provision_user(body, mock_session)

        assert result.status_code == 409
        import json
        content = json.loads(result.body)
        assert content["scimType"] == "uniqueness"

    @pytest.mark.asyncio
    async def test_scim_provision_no_collision_proceeds(self):
        """SoD-002b: SCIM proceeds when no admin exists with this email."""
        from yashigani.backoffice.routes import scim as _scim_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.audit_writer = MagicMock()

        mock_store = MagicMock()
        mock_store.get_user_groups = MagicMock(return_value=[])

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.userName = "newuser@example.com"

        with patch.object(_scim_mod, "backoffice_state", mock_state):
            with patch.object(_scim_mod, "_get_store", return_value=mock_store):
                with patch.object(_scim_mod, "require_feature"):
                    with patch.object(_scim_mod, "check_end_user_limit"):
                        with patch.object(_scim_mod, "count_canonical_end_users", return_value=0):
                            result = await _scim_mod.scim_provision_user(body, mock_session)

        # Should return a user resource dict, not a JSONResponse error
        assert not hasattr(result, "status_code") or result.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_scim_provision_collision_emits_audit_event(self):
        """SoD-002b: collision emits SCIM_PROVISION_REJECTED_ADMIN_EXISTS audit event."""
        from yashigani.backoffice.routes import scim as _scim_mod

        existing_admin = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.audit_writer = MagicMock()

        mock_store = MagicMock()
        mock_store.get_user_groups = MagicMock(return_value=[])

        mock_session = _make_session("admin-uuid", "admin")
        body = MagicMock()
        body.userName = "admin@example.com"

        with patch.object(_scim_mod, "backoffice_state", mock_state):
            with patch.object(_scim_mod, "_get_store", return_value=mock_store):
                with patch.object(_scim_mod, "require_feature"):
                    await _scim_mod.scim_provision_user(body, mock_session)

        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], ScimProvisionRejectedAdminExistsEvent)]
        assert len(sod_events) == 1


# ---------------------------------------------------------------------------
# SoD-002c + SoD-004: SSO provision collision + SoD-004 exploit chain
# ---------------------------------------------------------------------------

class TestSoD002cSsoProvisionCollision:
    """SSO/OIDC identity creation blocked when admin account exists with same email."""

    @pytest.mark.asyncio
    async def test_check_sod_admin_collision_returns_true_when_admin_exists(self):
        """_check_sod_admin_collision returns True when admin with email exists."""
        from yashigani.backoffice.routes import sso as _sso_mod

        existing_admin = _make_account("admin@example.com", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            result = await _sso_mod._check_sod_admin_collision("admin@example.com")

        assert result is True

    @pytest.mark.asyncio
    async def test_check_sod_admin_collision_returns_false_when_no_admin(self):
        """_check_sod_admin_collision returns False when no admin with email exists."""
        from yashigani.backoffice.routes import sso as _sso_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=None)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            result = await _sso_mod._check_sod_admin_collision("user@example.com")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_sod_admin_collision_false_for_user_tier_account(self):
        """_check_sod_admin_collision returns False when found account is user-tier."""
        from yashigani.backoffice.routes import sso as _sso_mod

        existing_user = _make_account("user@example.com", "user")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_user)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_user)

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            result = await _sso_mod._check_sod_admin_collision("user@example.com")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_sod_admin_collision_fail_open_on_exception(self):
        """_check_sod_admin_collision fails open (returns False) if auth_service errors."""
        from yashigani.backoffice.routes import sso as _sso_mod

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(side_effect=RuntimeError("db down"))
        mock_state.auth_service.get_account_by_email = AsyncMock(side_effect=RuntimeError("db down"))

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            result = await _sso_mod._check_sod_admin_collision("admin@example.com")

        # Fail-open: SoD-005 cron catches residual conflicts
        assert result is False

    def test_sso_provision_rejected_admin_event_fields(self):
        """SsoProvisionRejectedAdminExistsEvent has correct event_type."""
        evt = SsoProvisionRejectedAdminExistsEvent(
            idp_id="test-idp",
            idp_name="Test IdP",
            email_hash="abc123",
            client_ip_prefix="192.168.1.0",
        )
        assert evt.event_type == EventType.SSO_PROVISION_REJECTED_ADMIN_EXISTS
        assert evt.masking_applied is True


# ---------------------------------------------------------------------------
# SoD-003: /auth/verify admin session rejection
# ---------------------------------------------------------------------------

class TestSoD003AuthVerifyAdminSession:
    """verify_session must reject admin sessions with HTTP 403."""

    @pytest.mark.asyncio
    async def test_verify_session_rejects_admin_session_with_403(self):
        """SoD-003: admin session presented to /auth/verify returns HTTP 403."""
        from fastapi import HTTPException, Request
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_session": "tok-abc"}
        mock_request.client = MagicMock()
        mock_request.client.host = "192.168.1.1"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_session(mock_request)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "admin_session_not_allowed_data_plane"

    @pytest.mark.asyncio
    async def test_verify_session_accepts_user_session_with_200(self):
        """SoD-003: user session presented to /auth/verify returns 200 and headers."""
        from fastapi import Request
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-uuid", "user")
        user_record = _make_account("alice", "user", "alice@example.com")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_id = AsyncMock(return_value=user_record)
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_session": "tok-user"}
        mock_request.client = MagicMock()
        mock_request.client.host = "192.168.1.1"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.verify_session(mock_request)

        assert resp.status_code == 200
        assert "X-Forwarded-User" in resp.headers
        assert resp.headers["X-Forwarded-User"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_verify_session_admin_rejection_emits_audit_event(self):
        """SoD-003: admin session rejection emits AUTH_VERIFY_REJECTED_ADMIN_SESSION."""
        from fastapi import HTTPException, Request
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-uuid", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_admin_session": "tok-admin"}
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.1"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException):
                await _auth_mod.verify_session(mock_request)

        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], AuthVerifyRejectedAdminSessionEvent)]
        assert len(sod_events) == 1
        assert sod_events[0][0][0].account_id == "admin-uuid"


# ---------------------------------------------------------------------------
# SoD-004: End-to-end exploit chain blocked
# ---------------------------------------------------------------------------

class TestSoD004ExploitChainBlocked:
    """Combined SoD-002c + SoD-003 blocks the full admin-SSO-to-data-plane chain."""

    @pytest.mark.asyncio
    async def test_admin_sso_identity_creation_blocked_at_layer1(self):
        """SoD-004 layer 1: admin email cannot create HUMAN identity via SSO."""
        from yashigani.backoffice.routes import sso as _sso_mod

        # Admin exists with this email
        existing_admin = _make_account("admin@corp.com", "admin", "admin@corp.com")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            # The SoD check alone (layer 1)
            blocked = await _sso_mod._check_sod_admin_collision("admin@corp.com")

        assert blocked is True

    @pytest.mark.asyncio
    async def test_admin_session_blocked_at_auth_verify_layer2(self):
        """SoD-004 layer 2: even if identity were created, /auth/verify blocks admin session."""
        from fastapi import HTTPException, Request
        from yashigani.backoffice.routes import auth as _auth_mod

        # Admin session (as would exist after a hypothetical admin login)
        admin_session = _make_session("admin-corp-uuid", "admin")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_session": "admin-tok"}
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.2"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_session(mock_request)

        # Layer 2 blocks admin at /auth/verify regardless
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "admin_session_not_allowed_data_plane"


# ---------------------------------------------------------------------------
# SoD-005: Cross-store conflict audit cron
# ---------------------------------------------------------------------------

class TestSoD005ConflictAuditCron:
    """Daily cron detects and reports cross-store admin/user conflicts."""

    @pytest.mark.asyncio
    async def test_conflict_audit_finds_collision(self):
        """SoD-005: cron detects email collision between admin_accounts and identity_registry."""
        from yashigani.backoffice import sod_conflict_audit_task as _cron

        admin_acct = _make_account("admin@corp.com", "admin", "admin@corp.com")

        # Identity registry has a HUMAN entry with the same slug
        from yashigani.backoffice.routes.sso import _email_to_slug
        admin_slug = _email_to_slug("admin@corp.com")
        identity_entry = {
            "identity_id": "id-human-abc",
            "kind": "human",
            "slug": admin_slug,
            "name": "admin@corp.com",
        }

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.list_accounts = AsyncMock(return_value=[admin_acct])
        mock_state.identity_registry = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_cron, "backoffice_state", mock_state):
            with patch.object(_cron, "_list_human_identities", return_value=[identity_entry]):
                count = await _cron.run_sod_conflict_audit()

        assert count >= 1
        # Audit event emitted
        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], IdentityStoreConflictEvent)]
        assert len(sod_events) >= 1

    @pytest.mark.asyncio
    async def test_conflict_audit_no_collision_clean_run(self):
        """SoD-005: cron finds no conflict when stores are clean."""
        from yashigani.backoffice import sod_conflict_audit_task as _cron

        admin_acct = _make_account("admin@corp.com", "admin", "admin@corp.com")
        # Identity has completely different slug
        identity_entry = {
            "identity_id": "id-human-xyz",
            "kind": "human",
            "slug": "completelyunrelated-user",
            "name": "other@user.com",
        }

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.list_accounts = AsyncMock(return_value=[admin_acct])
        mock_state.identity_registry = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_cron, "backoffice_state", mock_state):
            with patch.object(_cron, "_list_human_identities", return_value=[identity_entry]):
                count = await _cron.run_sod_conflict_audit()

        assert count == 0

    @pytest.mark.asyncio
    async def test_conflict_audit_skips_when_auth_service_unavailable(self):
        """SoD-005: cron skips gracefully when auth_service is None."""
        from yashigani.backoffice import sod_conflict_audit_task as _cron

        mock_state = MagicMock()
        mock_state.auth_service = None
        mock_state.identity_registry = MagicMock()
        mock_state.audit_writer = MagicMock()

        with patch.object(_cron, "backoffice_state", mock_state):
            count = await _cron.run_sod_conflict_audit()

        assert count == 0

    @pytest.mark.asyncio
    async def test_conflict_audit_skips_when_registry_unavailable(self):
        """SoD-005: cron skips gracefully when identity_registry is None."""
        from yashigani.backoffice import sod_conflict_audit_task as _cron

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.list_accounts = AsyncMock(return_value=[])
        mock_state.identity_registry = None
        mock_state.audit_writer = MagicMock()

        with patch.object(_cron, "backoffice_state", mock_state):
            count = await _cron.run_sod_conflict_audit()

        assert count == 0

    def test_get_last_run_result_returns_dict(self):
        """SoD-005: get_last_run_result() returns structured result dict."""
        from yashigani.backoffice import sod_conflict_audit_task as _cron

        result = _cron.get_last_run_result()
        assert "conflicts" in result
        assert "conflict_count" in result
        assert "accounts_scanned" in result
        assert "identities_scanned" in result


# ---------------------------------------------------------------------------
# Audit schema event type verification
# ---------------------------------------------------------------------------

class TestSodAuditEventTypes:
    """Verify all SoD audit events have correct event_type values."""

    def test_admin_create_rejected_event_type(self):
        evt = AdminCreateRejectedUserExistsEvent()
        assert evt.event_type == EventType.ADMIN_CREATE_REJECTED_USER_EXISTS
        assert evt.account_tier == "admin"

    def test_user_create_rejected_event_type(self):
        evt = UserCreateRejectedAdminExistsEvent()
        assert evt.event_type == EventType.USER_CREATE_REJECTED_ADMIN_EXISTS
        assert evt.account_tier == "admin"

    def test_scim_provision_rejected_event_type(self):
        evt = ScimProvisionRejectedAdminExistsEvent()
        assert evt.event_type == EventType.SCIM_PROVISION_REJECTED_ADMIN_EXISTS
        assert evt.account_tier == "admin"

    def test_sso_provision_rejected_event_type(self):
        evt = SsoProvisionRejectedAdminExistsEvent()
        assert evt.event_type == EventType.SSO_PROVISION_REJECTED_ADMIN_EXISTS
        assert evt.account_tier == "system"

    def test_auth_verify_rejected_event_type(self):
        evt = AuthVerifyRejectedAdminSessionEvent()
        assert evt.event_type == EventType.AUTH_VERIFY_REJECTED_ADMIN_SESSION
        assert evt.account_tier == "admin"

    def test_identity_store_conflict_event_type(self):
        evt = IdentityStoreConflictEvent()
        assert evt.event_type == EventType.IDENTITY_STORE_CONFLICT
        assert evt.account_tier == "system"

    def test_all_sod_event_types_in_enum(self):
        """All 6 new SoD EventTypes are present in the EventType enum."""
        expected = {
            "ADMIN_CREATE_REJECTED_USER_EXISTS",
            "USER_CREATE_REJECTED_ADMIN_EXISTS",
            "SCIM_PROVISION_REJECTED_ADMIN_EXISTS",
            "SSO_PROVISION_REJECTED_ADMIN_EXISTS",
            "AUTH_VERIFY_REJECTED_ADMIN_SESSION",
            "IDENTITY_STORE_CONFLICT",
        }
        actual = {e.name for e in EventType}
        assert expected.issubset(actual), f"Missing EventTypes: {expected - actual}"
