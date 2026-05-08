"""
Regression test — v2.23.3 micro-PR 1.

Gap: routes/auth.py logout() invalidated the session but never emitted an
audit event. Every other auth lifecycle outcome (login success, login failure,
totp_provision, stepup, self_reset) was audited; logout was the only gap.

Fix: emit _make_login_event(session.account_id, "logout", None) before
returning, guarded by ``if state.audit_writer is not None``.

Closes: yashigani-retro#95 (OWASP A09 / CMMC AU.L2-3.3.1)

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

_SRC = Path(__file__).parent.parent.parent / "yashigani"
_ROUTES_AUTH = _SRC / "backoffice" / "routes" / "auth.py"


# ---------------------------------------------------------------------------
# AST structural tests — no imports of FastAPI app needed
# ---------------------------------------------------------------------------

class TestLogoutAuditEmitAST:
    """Verify the logout() function contains an audit write call."""

    def _logout_fn(self) -> ast.AsyncFunctionDef:
        tree = ast.parse(_ROUTES_AUTH.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "logout":
                return node
        pytest.fail("logout() async function not found in routes/auth.py")

    def test_logout_function_exists(self):
        fn = self._logout_fn()
        assert fn is not None

    def test_logout_calls_audit_write(self):
        """logout() must call audit_writer.write() with a login event."""
        fn = self._logout_fn()
        fn_src = ast.unparse(fn)
        assert "audit_writer" in fn_src, (
            "logout() has no reference to audit_writer — audit emit not added"
        )
        assert ".write(" in fn_src, (
            "logout() has no .write() call — audit event not emitted"
        )

    def test_logout_calls_make_login_event(self):
        """logout() must construct the audit event via _make_login_event."""
        fn = self._logout_fn()
        fn_src = ast.unparse(fn)
        assert "_make_login_event" in fn_src, (
            "logout() does not call _make_login_event — "
            "must use the same helper as login/stepup"
        )

    def test_logout_passes_logout_outcome(self):
        """_make_login_event must be called with 'logout' as the outcome."""
        fn = self._logout_fn()
        fn_src = ast.unparse(fn)
        assert "'logout'" in fn_src or '"logout"' in fn_src, (
            "logout() audit event does not pass 'logout' as outcome string"
        )

    def test_logout_audit_is_guarded_by_none_check(self):
        """
        The audit write must be guarded: ``if state.audit_writer is not None``.
        This prevents AttributeError when break-glass Redis fails and the state
        object is partially initialised (defensive pattern used in other routes).
        """
        fn = self._logout_fn()
        fn_src = ast.unparse(fn)
        assert "audit_writer is not None" in fn_src, (
            "logout() audit write is not guarded by ``audit_writer is not None`` — "
            "this can cause AttributeError during partial initialisation"
        )

    def test_audit_write_after_invalidate(self):
        """
        The session must be invalidated BEFORE emitting the audit event.
        Ensures the session cannot be replayed in the window between audit
        write and invalidate (defence-in-depth ordering).
        """
        fn = self._logout_fn()
        fn_src = ast.unparse(fn)
        invalidate_pos = fn_src.find("invalidate(")
        audit_pos = fn_src.find("_make_login_event")
        assert invalidate_pos != -1, "store.invalidate() call not found in logout()"
        assert audit_pos != -1, "_make_login_event call not found in logout()"
        assert invalidate_pos < audit_pos, (
            "audit emit must come AFTER session invalidation in logout()"
        )


# ---------------------------------------------------------------------------
# Unit tests — mock backoffice_state to exercise the actual function logic
# ---------------------------------------------------------------------------

class TestLogoutAuditEmitUnit:
    """
    Exercise logout() with a mocked backoffice_state to confirm the audit
    writer receives exactly one write() call with the expected outcome.
    """

    def _make_mock_session(self, account_id="test-account-uuid"):
        session = MagicMock()
        session.token = "test-token-abc"
        session.account_id = account_id
        session.account_tier = "admin"
        return session

    def test_audit_write_called_on_logout(self, monkeypatch):
        """
        Calling logout() must trigger exactly one audit_writer.write() call.
        """
        from yashigani.backoffice.routes.auth import logout

        # Build mocks
        mock_store = MagicMock()
        mock_response = MagicMock()
        mock_audit = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = mock_audit

        # Patch backoffice_state inside the routes.auth module
        import yashigani.backoffice.routes.auth as _auth_mod
        monkeypatch.setattr(_auth_mod, "backoffice_state", mock_state)

        import asyncio
        session = self._make_mock_session("uuid-for-logout-test")

        asyncio.get_event_loop().run_until_complete(
            logout(session=session, response=mock_response, store=mock_store)
        )

        assert mock_audit.write.call_count == 1, (
            f"Expected 1 audit write on logout, got {mock_audit.write.call_count}"
        )

    def test_audit_event_has_logout_outcome(self, monkeypatch):
        """
        The event written to audit_writer must be an AdminLoginEvent with
        outcome='logout' (verified by checking the constructed object's fields).
        """
        from yashigani.backoffice.routes.auth import logout

        written_events = []

        mock_store = MagicMock()
        mock_response = MagicMock()
        mock_audit = MagicMock()
        mock_audit.write.side_effect = written_events.append
        mock_state = MagicMock()
        mock_state.audit_writer = mock_audit

        import yashigani.backoffice.routes.auth as _auth_mod
        monkeypatch.setattr(_auth_mod, "backoffice_state", mock_state)

        import asyncio
        session = self._make_mock_session("uuid-test-outcome")
        asyncio.get_event_loop().run_until_complete(
            logout(session=session, response=mock_response, store=mock_store)
        )

        assert len(written_events) == 1, "Expected exactly one audit event"
        evt = written_events[0]
        # The event is an AdminLoginEvent dataclass/schema object
        assert hasattr(evt, "outcome"), "Audit event lacks 'outcome' attribute"
        assert evt.outcome == "logout", (
            f"Expected outcome='logout', got {evt.outcome!r}"
        )

    def test_audit_write_skipped_when_writer_is_none(self, monkeypatch):
        """
        When state.audit_writer is None (partial init during tests),
        logout() must not raise AttributeError — it silently skips the write.
        """
        from yashigani.backoffice.routes.auth import logout

        mock_store = MagicMock()
        mock_response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = None  # simulate partial init

        import yashigani.backoffice.routes.auth as _auth_mod
        monkeypatch.setattr(_auth_mod, "backoffice_state", mock_state)

        import asyncio
        session = self._make_mock_session("uuid-none-writer")
        # Must not raise
        result = asyncio.get_event_loop().run_until_complete(
            logout(session=session, response=mock_response, store=mock_store)
        )
        assert result == {"status": "ok"}

    def test_session_invalidated_regardless_of_audit_outcome(self, monkeypatch):
        """
        store.invalidate() must be called even if audit_writer raises.
        Session expiry is the primary security control; audit failure is advisory.
        """
        from yashigani.backoffice.routes.auth import logout

        mock_store = MagicMock()
        mock_response = MagicMock()
        mock_audit = MagicMock()
        mock_audit.write.side_effect = RuntimeError("audit bus down")
        mock_state = MagicMock()
        mock_state.audit_writer = mock_audit

        import yashigani.backoffice.routes.auth as _auth_mod
        monkeypatch.setattr(_auth_mod, "backoffice_state", mock_state)

        import asyncio
        session = self._make_mock_session("uuid-audit-fails")
        with pytest.raises(RuntimeError, match="audit bus down"):
            asyncio.get_event_loop().run_until_complete(
                logout(session=session, response=mock_response, store=mock_store)
            )

        # Invalidate was called before the audit write raised
        mock_store.invalidate.assert_called_once_with("test-token-abc")

    def test_logout_returns_status_ok(self, monkeypatch):
        """The existing response shape {status: ok} must be preserved."""
        from yashigani.backoffice.routes.auth import logout

        mock_store = MagicMock()
        mock_response = MagicMock()
        mock_state = MagicMock()
        mock_state.audit_writer = MagicMock()

        import yashigani.backoffice.routes.auth as _auth_mod
        monkeypatch.setattr(_auth_mod, "backoffice_state", mock_state)

        import asyncio
        session = self._make_mock_session("uuid-return-shape")
        result = asyncio.get_event_loop().run_until_complete(
            logout(session=session, response=mock_response, store=mock_store)
        )
        assert result == {"status": "ok"}, f"Unexpected return value: {result!r}"
