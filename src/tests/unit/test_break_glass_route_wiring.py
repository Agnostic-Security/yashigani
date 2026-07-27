"""
YSG-RISK-150/132 — break-glass wiring regression tests.

Prior state: BreakGlassManager (auth/break_glass.py) was instantiated at
startup but NO route ever reached activate/approve/revoke/status — the
feature (and its dual-control) was completely unreachable. Additionally,
require_second_approver defaulted to False (insecure — a single admin could
grant themselves immediate ACTIVE emergency access).

Covers:
  - Manager-level: activate() with the new secure default is PENDING, not
    ACTIVE; same-admin self-approve rejected; different-admin approve ->
    ACTIVE + EMERGENCY_UNLOCK_EXECUTED audited (new emission); revoke works;
    status reflects state.
  - Route-level (backoffice/routes/break_glass.py): every route requires
    StepUpAdminSession; /activate always forces require_second_approver=True
    regardless of any client input (the request model does not even expose
    the field); error mapping (400/403/409/503).
"""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import pytest

from yashigani.auth.break_glass import (
    AlreadyActiveError,
    ApprovalExpiredError,
    BreakGlassError,
    BreakGlassManager,
    NotActiveError,
    TTLRangeError,
    activate_break_glass as module_activate_break_glass,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeRedis:
    """In-memory Redis stand-in (set/get/delete/ttl). TTL not time-evolved."""

    def __init__(self):
        self.kv = {}
        self.ttls = {}

    def set(self, k, v, ex=None):
        self.kv[k] = v
        if ex is not None:
            self.ttls[k] = ex

    def get(self, k):
        return self.kv.get(k)

    def delete(self, k):
        self.kv.pop(k, None)
        self.ttls.pop(k, None)

    def ttl(self, k):
        return self.ttls.get(k, -1)


class _CountingAuditWriter:
    """Records every write call without raising."""

    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


def _mgr(audit_writer=None):
    return BreakGlassManager(_FakeRedis(), audit_writer=audit_writer)


# ---------------------------------------------------------------------------
# Secure-default regression (YSG-RISK-150/132)
# ---------------------------------------------------------------------------

class TestSecureDefault:
    def test_manager_default_is_true(self):
        sig = inspect.signature(BreakGlassManager.activate_break_glass)
        assert sig.parameters["require_second_approver"].default is True, (
            "BreakGlassManager.activate_break_glass require_second_approver "
            "must default to True (secure by default) — YSG-RISK-150/132"
        )

    def test_module_wrapper_default_is_true(self):
        sig = inspect.signature(module_activate_break_glass)
        assert sig.parameters["require_second_approver"].default is True

    def test_activate_with_default_args_is_pending_not_active(self):
        """Calling activate_break_glass with ONLY user_id/ttl (relying on the
        default) must land PENDING_APPROVAL, never immediately ACTIVE."""
        m = _mgr()
        state = m.activate_break_glass("admin1", ttl_hours=2)
        assert state["status"] == "PENDING_APPROVAL"
        assert state["active"] is False


# ---------------------------------------------------------------------------
# Manager-level dual-control behaviour
# ---------------------------------------------------------------------------

class TestManagerDualControl:
    def test_same_admin_self_approve_rejected(self):
        m = _mgr()
        m.activate_break_glass("admin1", ttl_hours=4)
        with pytest.raises(BreakGlassError):
            m.approve_break_glass("admin1")
        assert m.get_break_glass_status()["status"] == "PENDING_APPROVAL"

    def test_different_admin_approve_activates(self):
        m = _mgr()
        m.activate_break_glass("admin1", ttl_hours=4)
        state = m.approve_break_glass("admin2")
        assert state["status"] == "ACTIVE"
        assert state["active"] is True
        assert state["approver"] == "admin2"
        assert state["activated_by"] == "admin1"

    def test_approve_without_pending_raises(self):
        m = _mgr()
        with pytest.raises(ApprovalExpiredError):
            m.approve_break_glass("admin2")

    def test_revoke_clears_active(self):
        m = _mgr()
        m.activate_break_glass("admin1", ttl_hours=4)
        m.approve_break_glass("admin2")
        m.revoke_break_glass("admin1")
        status = m.get_break_glass_status()
        assert status["status"] == "INACTIVE"
        assert status["active"] is False

    def test_revoke_without_active_raises(self):
        m = _mgr()
        with pytest.raises(NotActiveError):
            m.revoke_break_glass("admin1")

    def test_status_reflects_pending_then_active_then_inactive(self):
        m = _mgr()
        assert m.get_break_glass_status()["status"] == "INACTIVE"
        m.activate_break_glass("admin1", ttl_hours=1)
        assert m.get_break_glass_status()["status"] == "PENDING_APPROVAL"
        m.approve_break_glass("admin2")
        assert m.get_break_glass_status()["status"] == "ACTIVE"
        m.revoke_break_glass("admin2")
        assert m.get_break_glass_status()["status"] == "INACTIVE"


# ---------------------------------------------------------------------------
# EMERGENCY_UNLOCK_EXECUTED audit emission (new — previously never emitted)
# ---------------------------------------------------------------------------

class TestEmergencyUnlockAudited:
    def test_approve_emits_emergency_unlock_executed(self):
        audit = _CountingAuditWriter()
        m = BreakGlassManager(_FakeRedis(), audit_writer=audit)
        m.activate_break_glass("admin1", ttl_hours=4)
        m.approve_break_glass("admin2")

        from yashigani.audit.schema import EmergencyUnlockExecutedEvent, EventType
        unlock_events = [e for e in audit.events if isinstance(e, EmergencyUnlockExecutedEvent)]
        assert len(unlock_events) == 1, (
            f"Expected exactly 1 EMERGENCY_UNLOCK_EXECUTED event, got {len(unlock_events)}: "
            f"{[type(e).__name__ for e in audit.events]}"
        )
        assert unlock_events[0].event_type == EventType.EMERGENCY_UNLOCK_EXECUTED
        assert unlock_events[0].admin_account == "admin1"
        assert unlock_events[0].severity == "SECURITY_CRITICAL"

    def test_pending_activation_does_not_emit_emergency_unlock(self):
        """A PENDING (not-yet-approved) activation must NOT emit
        EMERGENCY_UNLOCK_EXECUTED — access has not actually been granted yet."""
        audit = _CountingAuditWriter()
        m = BreakGlassManager(_FakeRedis(), audit_writer=audit)
        m.activate_break_glass("admin1", ttl_hours=4)

        from yashigani.audit.schema import EmergencyUnlockExecutedEvent
        unlock_events = [e for e in audit.events if isinstance(e, EmergencyUnlockExecutedEvent)]
        assert unlock_events == []

    def test_single_admin_activation_also_emits_emergency_unlock(self):
        """Defence in depth: even a deliberate require_second_approver=False
        caller (not reachable via the HTTP route) still audits the unlock."""
        audit = _CountingAuditWriter()
        m = BreakGlassManager(_FakeRedis(), audit_writer=audit)
        m.activate_break_glass("admin1", ttl_hours=4, require_second_approver=False)

        from yashigani.audit.schema import EmergencyUnlockExecutedEvent
        unlock_events = [e for e in audit.events if isinstance(e, EmergencyUnlockExecutedEvent)]
        assert len(unlock_events) == 1
        assert unlock_events[0].admin_account == "admin1"

    def test_emit_activated_still_writes_break_glass_activated_event(self):
        """Existing BREAK_GLASS_ACTIVATED emission must be unaffected by the
        new EMERGENCY_UNLOCK_EXECUTED emission added alongside it."""
        audit = _CountingAuditWriter()
        m = BreakGlassManager(_FakeRedis(), audit_writer=audit)
        m.activate_break_glass("admin1", ttl_hours=4)
        m.approve_break_glass("admin2")

        from yashigani.audit.schema import BreakGlassActivatedEvent
        activated_events = [e for e in audit.events if isinstance(e, BreakGlassActivatedEvent)]
        assert len(activated_events) == 1


# ---------------------------------------------------------------------------
# Route-level tests — StepUpAdminSession gating (AST/annotation check)
# ---------------------------------------------------------------------------

class TestRouteStepUpGating:
    """Every break-glass route must require a fresh step-up admin session —
    break-glass is emergency root-equivalent access."""

    def _route_functions(self):
        from yashigani.backoffice.routes import break_glass as mod
        return {
            "activate": mod.break_glass_activate,
            "approve": mod.break_glass_approve,
            "revoke": mod.break_glass_revoke,
            "status": mod.break_glass_status,
        }

    def test_all_routes_require_stepup_session(self):
        import typing
        from yashigani.backoffice.middleware import StepUpAdminSession
        for name, fn in self._route_functions().items():
            sig = inspect.signature(fn)
            assert "session" in sig.parameters, f"{name} route has no session parameter"
            # `from __future__ import annotations` in break_glass.py makes
            # inspect.signature() return the raw string annotation — resolve
            # with get_type_hints() to get the actual Annotated[...] object.
            hints = typing.get_type_hints(fn, include_extras=True)
            annotation = hints["session"]
            assert annotation == StepUpAdminSession, (
                f"{name} route session must be typed StepUpAdminSession, got {annotation!r}"
            )

    def test_activate_request_model_does_not_expose_require_second_approver(self):
        """The request body must NOT let a caller downgrade dual-control —
        require_second_approver is hardcoded True in the route, never read
        from client input."""
        from yashigani.backoffice.routes.break_glass import ActivateBreakGlassRequest
        fields = ActivateBreakGlassRequest.model_fields
        assert "require_second_approver" not in fields


# ---------------------------------------------------------------------------
# Route-level tests — handler behaviour with a mocked manager
# ---------------------------------------------------------------------------

class TestRouteHandlers:
    def _session(self, account_id="admin1"):
        session = MagicMock()
        session.account_id = account_id
        return session

    @pytest.mark.asyncio
    async def test_activate_hardcodes_require_second_approver_true(self):
        from yashigani.backoffice.routes.break_glass import (
            break_glass_activate,
            ActivateBreakGlassRequest,
        )
        mock_mgr = MagicMock()
        mock_mgr.activate_break_glass.return_value = {"status": "PENDING_APPROVAL"}
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            body = ActivateBreakGlassRequest(ttl_hours=2)
            result = await break_glass_activate(body=body, session=session)

        mock_mgr.activate_break_glass.assert_called_once_with(
            user_id="admin1", ttl_hours=2, require_second_approver=True,
        )
        assert result["status"] == "pending_approval"

    @pytest.mark.asyncio
    async def test_approve_passes_session_account_id(self):
        from yashigani.backoffice.routes.break_glass import break_glass_approve
        mock_mgr = MagicMock()
        mock_mgr.approve_break_glass.return_value = {"status": "ACTIVE"}
        session = self._session("admin2")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            result = await break_glass_approve(session=session)

        mock_mgr.approve_break_glass.assert_called_once_with("admin2")
        assert result["status"] == "active"

    @pytest.mark.asyncio
    async def test_approve_self_approval_returns_403(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import break_glass_approve
        mock_mgr = MagicMock()
        mock_mgr.approve_break_glass.side_effect = BreakGlassError(
            "The approver must be different from the initiating admin."
        )
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_approve(session=session)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "self_approval_rejected"

    @pytest.mark.asyncio
    async def test_approve_expired_returns_409(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import break_glass_approve
        mock_mgr = MagicMock()
        mock_mgr.approve_break_glass.side_effect = ApprovalExpiredError("expired")
        session = self._session("admin2")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_approve(session=session)

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "approval_expired"

    @pytest.mark.asyncio
    async def test_activate_ttl_range_error_returns_400(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import (
            break_glass_activate,
            ActivateBreakGlassRequest,
        )
        mock_mgr = MagicMock()
        mock_mgr.activate_break_glass.side_effect = TTLRangeError("bad ttl")
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_activate(body=ActivateBreakGlassRequest(ttl_hours=4), session=session)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error"] == "invalid_ttl"

    @pytest.mark.asyncio
    async def test_activate_already_active_returns_409(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import (
            break_glass_activate,
            ActivateBreakGlassRequest,
        )
        mock_mgr = MagicMock()
        mock_mgr.activate_break_glass.side_effect = AlreadyActiveError("already active")
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_activate(body=ActivateBreakGlassRequest(ttl_hours=4), session=session)

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "already_active"

    @pytest.mark.asyncio
    async def test_revoke_not_active_returns_409(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import break_glass_revoke
        mock_mgr = MagicMock()
        mock_mgr.revoke_break_glass.side_effect = NotActiveError("nothing to revoke")
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_revoke(session=session)

        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "not_active"

    @pytest.mark.asyncio
    async def test_revoke_success(self):
        from yashigani.backoffice.routes.break_glass import break_glass_revoke
        mock_mgr = MagicMock()
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            result = await break_glass_revoke(session=session)

        mock_mgr.revoke_break_glass.assert_called_once_with("admin1")
        assert result["status"] == "revoked"

    @pytest.mark.asyncio
    async def test_status_returns_manager_status(self):
        from yashigani.backoffice.routes.break_glass import break_glass_status
        mock_mgr = MagicMock()
        mock_mgr.get_break_glass_status.return_value = {"status": "INACTIVE", "active": False}
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            result = await break_glass_status(session=session)

        assert result == {"status": "INACTIVE", "active": False}

    @pytest.mark.asyncio
    async def test_manager_unavailable_returns_503(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes.break_glass import break_glass_status
        session = self._session("admin1")

        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = None
            with pytest.raises(HTTPException) as exc_info:
                await break_glass_status(session=session)

        assert exc_info.value.status_code == 503


# ---------------------------------------------------------------------------
# App-mount test — routes actually reachable (regression proof for the
# "orphaned manager" finding: no route previously mounted this router at all)
# ---------------------------------------------------------------------------

class TestRouterMounted:
    def test_router_mounted_in_backoffice_app(self):
        import os
        os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")
        os.environ.setdefault("YASHIGANI_ENV", "dev")
        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        spec = app.openapi()
        break_glass_paths = {p for p in spec["paths"] if "break-glass" in p}
        assert break_glass_paths == {
            "/admin/break-glass/activate",
            "/admin/break-glass/approve",
            "/admin/break-glass/revoke",
            "/admin/break-glass/status",
        }
