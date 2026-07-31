"""
E2 (observability SOP) — authorization-DENY audit coverage for
backoffice/middleware.py::require_admin_session().

ENUMERATION (2026-07-31, Tom): grepped OPA deny sites, RBAC deny sites, and
403 emission points across gateway/ + backoffice/. Findings:

  - gateway/proxy.py's /v1/* deny path (_audit_request -> GatewayRequestEvent)
    is already well-instrumented with SPECIFIC compound deny reasons
    ("body_too_large", "pii_detected", "opa_policy", "document_opa_block",
    "response_injection", ...) — no gap there.
  - gateway/agent_router.py's /agents/* RBAC deny path already writes
    AgentCallDeniedRBACEvent with the OPA-supplied reason
    (_write_denied_rbac_audit) — no gap there.
  - backoffice/routes/auth.py's /auth/verify SoD-003 admin-on-data-plane
    reject already writes AuthVerifyRejectedAdminSessionEvent — no gap.
  - backoffice/middleware.py::require_admin_session() — the SINGLE FastAPI
    dependency EVERY /admin/* route funnels through — had TWO 403 branches
    (admin_password_change_required, insufficient_tier) with ZERO audit
    trail. This is the highest-per-request-volume authorization-DENY gap
    found: every admin request in the system passes through this exact
    function. THIS is the gap this suite closes.
  - Also enumerated (typed audit event classes that exist in
    audit/schema.py with ZERO non-schema call sites — genuinely dead,
    designed but never wired): AgentCallDeniedInspectionEvent,
    NhiInvocationDeniedEvent, McpIdGrantReconciledEvent,
    DynamicCertRevokedEvent. NOT wired in this pass — see final report
    NOT-DONE list; each needs a design decision about which call site
    should emit it (none is a drop-in one-line fix like the
    require_admin_session gap was) and is deferred rather than guessed at.

Fix under test: require_admin_session() now calls
_audit_admin_access_denied_tier_mismatch() (best-effort, audit failure
NEVER blocks the deny) on both 403 branches, emitting
AdminAccessDeniedTierMismatchEvent with the specific reason
("insufficient_tier" | "admin_password_change_required") — never a
generic "forbidden" (V50-011/COV-001 spirit).

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

try:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_SESSION_COOKIE = "__Host-yashigani_admin_session"


def _make_session(account_tier: str, account_id: str = "acct-1"):
    from yashigani.auth.session import Session
    now = time.time()
    return Session(
        token="tok-abc123",
        account_id=account_id,
        account_tier=account_tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="10.0.0.0",
    )


def _make_app(session):
    from yashigani.backoffice.middleware import require_admin_session, get_session_store

    store = MagicMock()
    store.get = MagicMock(return_value=session)

    app = FastAPI()
    app.dependency_overrides[get_session_store] = lambda: store

    @app.get("/admin/probe")
    def probe(session=Depends(require_admin_session)):
        return {"account_id": session.account_id}

    return app, store


class TestAdminAccessDeniedTierMismatchAudited:
    def test_insufficient_tier_writes_audit_event_with_specific_reason(self):
        session = _make_session("user")
        app, _store = _make_app(session)

        from yashigani.backoffice.state import backoffice_state
        mock_audit_writer = MagicMock()
        backoffice_state.audit_writer = mock_audit_writer
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})
        finally:
            backoffice_state.audit_writer = None

        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "insufficient_tier"

        mock_audit_writer.write.assert_called_once()
        written_event = mock_audit_writer.write.call_args[0][0]
        assert written_event.reason == "insufficient_tier"
        assert written_event.session_account_tier == "user"
        assert written_event.account_id == "acct-1"
        assert written_event.path == "/admin/probe"
        assert written_event.method == "GET"

    def test_admin_password_change_required_writes_audit_event_with_specific_reason(self):
        session = _make_session("admin_password_change_required")
        app, _store = _make_app(session)

        from yashigani.backoffice.state import backoffice_state
        mock_audit_writer = MagicMock()
        backoffice_state.audit_writer = mock_audit_writer
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})
        finally:
            backoffice_state.audit_writer = None

        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "admin_password_change_required"

        mock_audit_writer.write.assert_called_once()
        written_event = mock_audit_writer.write.call_args[0][0]
        assert written_event.reason == "admin_password_change_required"
        assert written_event.session_account_tier == "admin_password_change_required"

    def test_valid_admin_session_no_audit_event_written(self):
        """The happy path (real admin, no restriction) must NOT emit a deny
        event — this is a DENY-only audit trail, not a per-request log."""
        session = _make_session("admin")
        app, _store = _make_app(session)

        from yashigani.backoffice.state import backoffice_state
        mock_audit_writer = MagicMock()
        backoffice_state.audit_writer = mock_audit_writer
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})
        finally:
            backoffice_state.audit_writer = None

        assert resp.status_code == 200
        mock_audit_writer.write.assert_not_called()

    def test_401_paths_do_not_emit_this_audit_event(self):
        """Missing/expired session is an AUTHENTICATION failure, not an
        authorization deny — deliberately out of scope for this event
        (already covered by AUTH_LOGIN_ATTEMPT / AUTH_THROTTLE_TRIGGERED
        on the login path)."""
        app, store = _make_app(session=None)
        store.get = MagicMock(return_value=None)

        from yashigani.backoffice.state import backoffice_state
        mock_audit_writer = MagicMock()
        backoffice_state.audit_writer = mock_audit_writer
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})
        finally:
            backoffice_state.audit_writer = None

        assert resp.status_code == 401
        mock_audit_writer.write.assert_not_called()

    def test_audit_writer_failure_never_blocks_the_deny(self):
        """A broken/erroring audit_writer must never prevent the 403 from
        being raised — audit is best-effort forensic trail, not the
        security control itself."""
        session = _make_session("user")
        app, _store = _make_app(session)

        from yashigani.backoffice.state import backoffice_state
        broken_writer = MagicMock()
        broken_writer.write = MagicMock(side_effect=RuntimeError("audit sink down"))
        backoffice_state.audit_writer = broken_writer
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})
        finally:
            backoffice_state.audit_writer = None

        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "insufficient_tier"

    def test_no_audit_writer_configured_still_denies_cleanly(self):
        """backoffice_state.audit_writer is None (feature not wired) — the
        deny must still fire without raising."""
        session = _make_session("user")
        app, _store = _make_app(session)

        from yashigani.backoffice.state import backoffice_state
        backoffice_state.audit_writer = None

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/probe", cookies={_SESSION_COOKIE: "tok-abc123"})

        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "insufficient_tier"
