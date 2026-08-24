"""
Regression tests — FIND-3.1-001 and FIND-3.1-002 (3.1 admin-plane fixes).

FIND-3.1-001 (release-blocker):
    /auth/verify-user denied ALL users 403 owui_access_required after the 3.1 UID
    unification because it compared session email against owui-users group.members,
    but after the migration members contains identity IDs (idnt_xxx), not emails.

    Root cause: auth.py:912  ``if _email not in _members``  — never matched.
    Fix: resolve email → identity_id via identity_registry; compare identity_id against
    members.  Fall back to email comparison only when identity_registry is absent
    (community-tier, pre-3.1 data).

FIND-3.1-002:
    POST /admin/rbac/groups (create), POST /admin/rbac/groups/{id}/members (add-member),
    and DELETE /admin/rbac/groups/{id} (delete) accepted plain admin sessions with no
    step-up TOTP. Higher-sensitivity ops (API-key issuance, policy-write, etc.) already
    enforced step-up. Fix: gate the three mutation endpoints with StepUpAdminSession.

Test matrix:
  F1-001-A  identity_id in members → 200 (was 403 before fix)
  F1-001-B  identity_id NOT in members → 403 owui_access_required
  F1-001-C  community-tier (no identity_registry), email in members → 200 (backward compat)
  F1-001-D  community-tier, email NOT in members → 403
  F1-001-E  identity_registry present but user not yet registered → 403
  F1-001-F  no rbac_store → skip-allow (200) — non-standard deploy guard preserved

  F2-002-A  require_stepup_admin_session: session without step-up → StepUpRequired (401)
  F2-002-B  require_stepup_admin_session: session with fresh step-up → returns session
  F2-002-C  create_group handler uses StepUpAdminSession dependency (signature check)
  F2-002-D  add_member handler uses StepUpAdminSession dependency (signature check)
  F2-002-E  delete_group handler uses StepUpAdminSession dependency (signature check)

Last updated: 2026-07-10T00:00:00+00:00
"""
from __future__ import annotations

import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Helpers — shared
# ---------------------------------------------------------------------------

def _make_session(account_id: str = "user-uuid-abc", account_tier: str = "user",
                  token: str = "tok-test", *, with_stepup: bool = False):
    from yashigani.auth.session import Session
    now = time.time()
    return Session(
        token=token,
        account_id=account_id,
        account_tier=account_tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 14400,
        ip_prefix="127.0.0",
        last_totp_verified_at=now if with_stepup else None,
    )


def _make_user_record(username: str = "ana", email: str = "ana@agnosticsec.com"):
    rec = MagicMock()
    rec.username = username
    rec.email = email
    rec.account_id = f"uuid-{username}"
    rec.account_tier = "user"
    return rec


def _make_rbac_group(display_name: str, members: set):
    """Minimal stub of RBACGroup for membership tests."""
    grp = MagicMock()
    grp.display_name = display_name
    grp.members = members
    return grp


def _make_request(cookies: dict):
    req = MagicMock()
    req.cookies = cookies
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    return req


def _make_identity_registry_stub(email_to_identity_id: dict):
    """
    Faithful stub for IdentityRegistry.get_by_email().
    Maps email → {"identity_id": idnt_xxx} or None.
    """
    class _Stub:
        def get_by_email(self, email: str):
            iid = email_to_identity_id.get(email.strip().lower())
            if iid is None:
                return None
            return {"identity_id": iid, "status": "active"}
    return _Stub()


# ---------------------------------------------------------------------------
# FIND-3.1-001 — /auth/verify-user membership check
# ---------------------------------------------------------------------------

class TestFind31001VerifyUserOwuiMembership:
    """After 3.1 UID unification, verify-user must compare identity_id against
    group members, not email."""

    async def _call_verify_user(self, mock_state, cookies=None):
        from yashigani.backoffice.routes import auth as _auth_mod
        request = _make_request(cookies or {"__Host-yashigani_session": "tok-test"})
        with patch.object(_auth_mod, "backoffice_state", mock_state):
            return await _auth_mod.verify_user_session(request)

    def _build_state(self, session, record, rbac_store=None, identity_registry=None):
        state = MagicMock()
        state.session_store = MagicMock()
        state.session_store.get = MagicMock(return_value=session)
        state.auth_service = AsyncMock()
        state.auth_service.get_account_by_id = AsyncMock(return_value=record)
        state.rbac_store = rbac_store
        state.identity_registry = identity_registry
        return state

    @pytest.mark.asyncio
    async def test_f1_001_a_identity_id_in_members_returns_200(self):
        """F1-001-A: user's identity_id IS in owui-users.members → 200."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("ana", "ana@agnosticsec.com")

        # Members contain identity ID, not email
        owui_group = _make_rbac_group("owui-users", {"idnt_abc123456789"})
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[owui_group])

        registry = _make_identity_registry_stub(
            {"ana@agnosticsec.com": "idnt_abc123456789"}
        )
        state = self._build_state(session, record, rbac_store=rbac,
                                  identity_registry=registry)

        resp = await self._call_verify_user(state)
        assert resp.status_code == 200
        assert resp.headers["X-Forwarded-User"] == "ana@agnosticsec.com"

    @pytest.mark.asyncio
    async def test_f1_001_b_identity_id_not_in_members_returns_403(self):
        """F1-001-B: user's identity_id is NOT in owui-users.members → 403."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("paul", "paul@agnosticsec.com")

        # Membership has some OTHER user's identity_id
        owui_group = _make_rbac_group("owui-users", {"idnt_someoneelse0000"})
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[owui_group])

        registry = _make_identity_registry_stub(
            {"paul@agnosticsec.com": "idnt_paul1234567890"}
        )
        state = self._build_state(session, record, rbac_store=rbac,
                                  identity_registry=registry)

        with pytest.raises(HTTPException) as exc_info:
            await self._call_verify_user(state)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "owui_access_required"

    @pytest.mark.asyncio
    async def test_f1_001_c_community_tier_email_in_members_returns_200(self):
        """F1-001-C: no identity_registry (community), email in members → 200."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("ana", "ana@agnosticsec.com")

        # Community-tier: members still contain emails
        owui_group = _make_rbac_group("owui-users", {"ana@agnosticsec.com"})
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[owui_group])

        # No identity_registry
        state = self._build_state(session, record, rbac_store=rbac,
                                  identity_registry=None)

        resp = await self._call_verify_user(state)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_f1_001_d_community_tier_email_not_in_members_returns_403(self):
        """F1-001-D: community-tier, email NOT in members → 403."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("paul", "paul@agnosticsec.com")

        owui_group = _make_rbac_group("owui-users", {"ana@agnosticsec.com"})
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[owui_group])

        state = self._build_state(session, record, rbac_store=rbac,
                                  identity_registry=None)

        with pytest.raises(HTTPException) as exc_info:
            await self._call_verify_user(state)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "owui_access_required"

    @pytest.mark.asyncio
    async def test_f1_001_e_user_not_in_registry_returns_403(self):
        """F1-001-E: registry present but user has no identity (not yet logged in
        via the user plane) → 403, not a crash."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("ghost", "ghost@example.com")

        owui_group = _make_rbac_group("owui-users", {"idnt_abc123456789"})
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[owui_group])

        # Registry returns None for this email — user not registered
        registry = _make_identity_registry_stub({})
        state = self._build_state(session, record, rbac_store=rbac,
                                  identity_registry=registry)

        with pytest.raises(HTTPException) as exc_info:
            await self._call_verify_user(state)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "owui_access_required"

    @pytest.mark.asyncio
    async def test_f1_001_f_no_rbac_store_skip_allows(self):
        """F1-001-F: rbac_store is None (non-standard deploy) → skip-allow (200)."""
        session = _make_session("user-uuid", "user")
        record = _make_user_record("ana", "ana@agnosticsec.com")

        state = self._build_state(session, record, rbac_store=None,
                                  identity_registry=None)

        resp = await self._call_verify_user(state)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# FIND-3.1-002 — RBAC mutation step-up enforcement
# ---------------------------------------------------------------------------

class TestFind31002RbacMutationStepUp:
    """RBAC create/add-member/delete mutations must require step-up."""

    def test_f2_002_a_no_stepup_raises_step_up_required(self):
        """F2-002-A: require_stepup_admin_session with no step-up → HTTP 401."""
        from yashigani.auth.stepup import StepUpRequired
        from yashigani.backoffice.middleware import require_stepup_admin_session

        session_no_stepup = _make_session("admin-uuid", "admin", with_stepup=False)
        with pytest.raises(StepUpRequired) as exc_info:
            require_stepup_admin_session(session=session_no_stepup)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["error"] == "step_up_required"

    def test_f2_002_b_fresh_stepup_returns_session(self):
        """F2-002-B: require_stepup_admin_session with fresh step-up → returns session."""
        from yashigani.backoffice.middleware import require_stepup_admin_session

        session_with_stepup = _make_session("admin-uuid", "admin", with_stepup=True)
        result = require_stepup_admin_session(session=session_with_stepup)
        assert result is session_with_stepup

    def _get_resolved_hints(self, func):
        """Resolve string annotations (from __future__ import annotations) using
        get_type_hints(). Returns dict of param_name → resolved type."""
        import typing
        import yashigani.backoffice.routes.rbac as _rbac_mod
        # get_type_hints resolves PEP-563 deferred annotations against the
        # function's module globals — needed because rbac.py uses
        # `from __future__ import annotations`.
        try:
            return typing.get_type_hints(func, globalns=vars(_rbac_mod),
                                         include_extras=True)
        except Exception:
            return {}

    def test_f2_002_c_create_group_uses_stepup_dependency(self):
        """F2-002-C: create_group signature requires StepUpAdminSession."""
        from yashigani.backoffice.routes.rbac import create_group
        from yashigani.backoffice.middleware import StepUpAdminSession

        hints = self._get_resolved_hints(create_group)
        assert "session" in hints, "create_group has no session parameter"
        assert hints["session"] == StepUpAdminSession, (
            f"create_group session hint is {hints['session']!r}, "
            f"expected StepUpAdminSession"
        )

    def test_f2_002_d_add_member_uses_stepup_dependency(self):
        """F2-002-D: add_member signature requires StepUpAdminSession."""
        from yashigani.backoffice.routes.rbac import add_member
        from yashigani.backoffice.middleware import StepUpAdminSession

        hints = self._get_resolved_hints(add_member)
        assert "session" in hints, "add_member has no session parameter"
        assert hints["session"] == StepUpAdminSession, (
            f"add_member session hint is {hints['session']!r}, "
            f"expected StepUpAdminSession"
        )

    def test_f2_002_e_delete_group_uses_stepup_dependency(self):
        """F2-002-E: delete_group signature requires StepUpAdminSession."""
        from yashigani.backoffice.routes.rbac import delete_group
        from yashigani.backoffice.middleware import StepUpAdminSession

        hints = self._get_resolved_hints(delete_group)
        assert "session" in hints, "delete_group has no session parameter"
        assert hints["session"] == StepUpAdminSession, (
            f"delete_group session hint is {hints['session']!r}, "
            f"expected StepUpAdminSession"
        )

    def test_f2_002_g_update_group_uses_stepup_dependency(self):
        """F2-002-G: update_group signature requires StepUpAdminSession (a6fd8057)."""
        from yashigani.backoffice.routes.rbac import update_group
        from yashigani.backoffice.middleware import StepUpAdminSession

        hints = self._get_resolved_hints(update_group)
        assert "session" in hints, "update_group has no session parameter"
        assert hints["session"] == StepUpAdminSession, (
            f"update_group session hint is {hints['session']!r}, "
            f"expected StepUpAdminSession"
        )

    def test_f2_002_h_remove_member_uses_stepup_dependency(self):
        """F2-002-H: remove_member signature requires StepUpAdminSession (a6fd8057)."""
        from yashigani.backoffice.routes.rbac import remove_member
        from yashigani.backoffice.middleware import StepUpAdminSession

        hints = self._get_resolved_hints(remove_member)
        assert "session" in hints, "remove_member has no session parameter"
        assert hints["session"] == StepUpAdminSession, (
            f"remove_member session hint is {hints['session']!r}, "
            f"expected StepUpAdminSession"
        )

    def test_f2_002_f_list_groups_still_uses_plain_admin_session(self):
        """F2-002-F: list_groups (read-only) should NOT require step-up."""
        from yashigani.backoffice.routes.rbac import list_groups
        from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession

        hints = self._get_resolved_hints(list_groups)
        assert "session" in hints, "list_groups has no session parameter"
        assert hints["session"] == AdminSession, (
            "list_groups (read-only) should use AdminSession, not StepUpAdminSession"
        )
        assert hints["session"] != StepUpAdminSession
