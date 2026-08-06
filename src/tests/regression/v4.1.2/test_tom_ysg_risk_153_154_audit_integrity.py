"""
Regression test -- v4.1.2 YSG-RISK-153/154 (LOW): audit integrity.

153 — infrastructure.py's PUT /admin/infrastructure/topology swallowed an
audit-write FAILURE (writer present, .write() itself raised) into a clean
200 with no signal at all that the audit trail was incomplete. Fixed by
surfacing an `audit_recorded: bool` field in the response; the mutation
itself still stands (consistent with the rest of the codebase's fail-soft-
on-transient-write-failure convention).

154 — the audit_writer being COMPLETELY UNSET (a startup-invariant
violation, not a transient hiccup) was, in three sibling call sites
(infrastructure.py, capability_policy.py's _emit_audit helper, rbac.py's
_push helper), an `assert audit_writer is not None` sitting INSIDE the SAME
try/except that also caught transient write failures -- AssertionError IS
an Exception, so the "fail-fast" assert was silently swallowed by its own
surrounding except and the mutation completed with 200 anyway. Fixed:
  - infrastructure.py: explicit check BEFORE the state mutation -> 503.
  - capability_policy.py: explicit check in _emit_audit -> raises 503,
    re-raised past the broad except (not swallowed).
  - rbac.py's _push(): explicitly documented "never raises" (fire-and-forget,
    called AFTER the RBAC mutation already committed) -- cannot adopt the
    same fail-closed-503 unification without breaking that contract. Instead
    the previously-swallowed assert is now a distinctly-logged explicit
    branch so ops/SIEM can tell "writer never wired up" apart from "a write
    attempt failed" -- documented deviation, not an oversight.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


def _make_infra_app():
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.infrastructure import router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router)
    return app


class TestInfrastructureTopologyAuditIntegrity:
    def test_writer_unset_rejects_before_mutating_state(self):
        """YSG-RISK-154: audit_writer=None must fail-closed 503 BEFORE the
        topology state mutation, not silently swallow-then-200."""
        app = _make_infra_app()
        client = TestClient(app)

        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", None):
            resp = client.put(
                "/topology",
                json={"zones": ["a", "b"], "spread_policy": "ScheduleAnyway", "max_skew": 1},
            )
        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "audit_writer_unavailable"

    def test_writer_present_and_healthy_returns_audit_recorded_true(self):
        app = _make_infra_app()
        client = TestClient(app)

        fake_writer = MagicMock()
        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", fake_writer):
            resp = client.put(
                "/topology",
                json={"zones": ["a", "b"], "spread_policy": "ScheduleAnyway", "max_skew": 1},
            )
        assert resp.status_code == 200
        assert resp.json()["audit_recorded"] is True
        fake_writer.write.assert_called_once()

    def test_transient_write_failure_surfaced_not_swallowed(self):
        """YSG-RISK-153: a write EXCEPTION (writer present, .write() raises)
        must surface as audit_recorded=false, not a silent clean 200."""
        app = _make_infra_app()
        client = TestClient(app)

        fake_writer = MagicMock()
        fake_writer.write.side_effect = RuntimeError("db down")
        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", fake_writer):
            resp = client.put(
                "/topology",
                json={"zones": ["a", "b"], "spread_policy": "ScheduleAnyway", "max_skew": 1},
            )
        # The mutation itself still stands (fail-soft on transient write error)...
        assert resp.status_code == 200
        # ...but the response now HONESTLY reports the audit trail is incomplete.
        assert resp.json()["audit_recorded"] is False


class TestCapabilityPolicyEmitAuditFailClosed:
    def test_writer_unset_raises_503_not_swallowed(self):
        from fastapi import HTTPException

        from yashigani.backoffice.routes.capability_policy import _emit_audit

        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", None), \
             pytest.raises(HTTPException) as exc_info:
            _emit_audit("admin1", "org", "default", "updated", ["mcp.tool_call"])
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["error"] == "audit_writer_unavailable"

    def test_writer_present_writes_event(self):
        from yashigani.backoffice.routes.capability_policy import _emit_audit

        fake_writer = MagicMock()
        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", fake_writer):
            _emit_audit("admin1", "org", "default", "updated", ["mcp.tool_call"])
        fake_writer.write.assert_called_once()


class TestRbacPushAuditNeverRaises:
    def test_writer_unset_does_not_raise_and_logs_distinctly(self, caplog):
        from yashigani.backoffice.routes.rbac import _push

        fake_store = MagicMock()
        fake_store.to_opa_document.return_value = {"groups": {}, "user_groups": {}}

        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", None), \
             patch("yashigani.backoffice.state.backoffice_state.opa_url", "https://policy:8181"), \
             patch("yashigani.rbac.opa_push.push_rbac_data", MagicMock()):
            import logging
            caplog.set_level(logging.ERROR)
            # Must not raise — documented fire-and-forget contract.
            _push(fake_store, "admin1")

        assert any(
            "audit_writer is unavailable" in r.message or "RBAC push audit SKIPPED" in r.message
            for r in caplog.records
        )
