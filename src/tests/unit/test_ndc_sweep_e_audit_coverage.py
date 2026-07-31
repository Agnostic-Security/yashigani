"""
NDC sweep-E residue (2026-07-31, Tom) — authorization-DENY audit coverage
for the 22-site finding set in
testing_runs/yashigani/ytf/ndc/sweep-e-findings.json.

Each TestXxx class below covers one site from the finding set (bucket "b" —
clear-cut gap, wired with a typed audit event). Bucket "a" sites
(already-audited via an idiom the sweep marker list misses:
verify_mcp_ingress / _verify_mcp_deny, sso_2fa_verify / _write_sso_failure_audit,
_verify_ollama_pin / ModelIntegrityVerifier.verify) are NOT modified — see the
final report for evidence — and are not covered here.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.auth.session import Session


def _session(account_id="acct-1", account_tier="user", **kw) -> Session:
    now = time.time()
    return Session(
        token="tok-abc123",
        account_id=account_id,
        account_tier=account_tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="10.0.0.0",
        **kw,
    )


class _CountingAuditWriter:
    """Records every write call without raising."""

    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


class _BoomAuditWriter:
    """Raises on every write — used to prove audit failure never blocks a deny."""

    def write(self, event):
        raise RuntimeError("audit sink down")


# ---------------------------------------------------------------------------
# 1. auth/spiffe.py::require_spiffe_id() — SpiffeAccessDeniedEvent
# ---------------------------------------------------------------------------

class _FakeHeaders:
    def __init__(self, initial=None):
        self._h = {k.lower(): v for k, v in (initial or {}).items()}

    def get(self, key, default=None):
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(self, headers=None, path_params=None):
        self.headers = _FakeHeaders(headers)
        self.path_params = path_params or {}


class TestSpiffeAccessDenied:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from yashigani.auth.spiffe import _reset_cache_for_tests
        _reset_cache_for_tests()
        yield
        _reset_cache_for_tests()

    @pytest.mark.asyncio
    async def test_no_acl_for_path_audited(self, monkeypatch):
        from yashigani.auth import spiffe as spiffe_mod
        monkeypatch.setattr(spiffe_mod, "_load_acls", lambda: {})
        aw = _CountingAuditWriter()
        mock_bo_state = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bo_state):
            dep = spiffe_mod.require_spiffe_id("/internal/metrics")
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await dep(_FakeRequest({"x-spiffe-id": "spiffe://yashigani.internal/rogue"}))
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].reason == "no_acl_for_path"
        assert aw.events[0].path == "/internal/metrics"

    @pytest.mark.asyncio
    async def test_spiffe_id_not_allowed_audited(self, monkeypatch):
        from yashigani.auth import spiffe as spiffe_mod
        monkeypatch.setattr(
            spiffe_mod, "_load_acls",
            lambda: {"/internal/metrics": frozenset({"spiffe://yashigani.internal/prometheus"})},
        )
        aw = _CountingAuditWriter()
        mock_bo_state = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bo_state):
            dep = spiffe_mod.require_spiffe_id("/internal/metrics")
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await dep(_FakeRequest({"x-spiffe-id": "spiffe://yashigani.internal/rogue"}))
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].reason == "spiffe_id_not_allowed"
        assert aw.events[0].caller_spiffe == "spiffe://yashigani.internal/rogue"

    @pytest.mark.asyncio
    async def test_401_missing_header_not_audited(self, monkeypatch):
        """Authentication failure (missing header) — deliberately NOT audited
        here (no caller identity to attribute the event to)."""
        from yashigani.auth import spiffe as spiffe_mod
        monkeypatch.setattr(
            spiffe_mod, "_load_acls",
            lambda: {"/internal/metrics": frozenset({"spiffe://yashigani.internal/prometheus"})},
        )
        aw = _CountingAuditWriter()
        mock_bo_state = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bo_state):
            dep = spiffe_mod.require_spiffe_id("/internal/metrics")
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await dep(_FakeRequest())
            assert exc.value.status_code == 401
        assert aw.events == []

    @pytest.mark.asyncio
    async def test_no_audit_writer_still_denies(self, monkeypatch):
        from yashigani.auth import spiffe as spiffe_mod
        monkeypatch.setattr(spiffe_mod, "_load_acls", lambda: {})
        mock_bo_state = MagicMock(audit_writer=None)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bo_state):
            dep = spiffe_mod.require_spiffe_id("/internal/metrics")
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await dep(_FakeRequest({"x-spiffe-id": "spiffe://x"}))
            assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# 2. auth/stepup.py::assert_privileged_mutation() — PrivilegedMutationDeniedEvent
# ---------------------------------------------------------------------------

class TestPrivilegedMutationDenied:
    def test_not_operator_denied_audited(self):
        from yashigani.auth.stepup import (
            assert_privileged_mutation, PrivilegedMutationContext,
            NotAuthorisedForPrivilegedMutation,
        )
        session = _session(account_tier="user")
        ctx = PrivilegedMutationContext(reason="mcp.envelope.reapprove", principal="acct-1", target="prov-1")
        aw = _CountingAuditWriter()
        with pytest.raises(NotAuthorisedForPrivilegedMutation):
            assert_privileged_mutation(session, ctx, audit_writer=aw)
        assert len(aw.events) == 1
        assert aw.events[0].reason == "not_operator"
        assert aw.events[0].mutation_reason == "mcp.envelope.reapprove"

    def test_step_up_required_denied_audited(self):
        from yashigani.auth.stepup import (
            assert_privileged_mutation, PrivilegedMutationContext, StepUpRequired,
        )
        session = _session(account_tier="admin")  # no last_totp_verified_at -> stale
        ctx = PrivilegedMutationContext(reason="mcp.envelope.reapprove", principal="acct-1", target="prov-1")
        aw = _CountingAuditWriter()
        with pytest.raises(StepUpRequired):
            assert_privileged_mutation(session, ctx, audit_writer=aw)
        assert len(aw.events) == 1
        assert aw.events[0].reason == "step_up_required"

    def test_audit_writer_failure_never_blocks_deny(self):
        from yashigani.auth.stepup import (
            assert_privileged_mutation, PrivilegedMutationContext,
            NotAuthorisedForPrivilegedMutation,
        )
        session = _session(account_tier="user")
        ctx = PrivilegedMutationContext(reason="x", principal="acct-1", target="t")
        with pytest.raises(NotAuthorisedForPrivilegedMutation):
            assert_privileged_mutation(session, ctx, audit_writer=_BoomAuditWriter())

    def test_no_audit_writer_still_denies(self):
        from yashigani.auth.stepup import (
            assert_privileged_mutation, PrivilegedMutationContext,
            NotAuthorisedForPrivilegedMutation,
        )
        session = _session(account_tier="user")
        ctx = PrivilegedMutationContext(reason="x", principal="acct-1", target="t")
        with pytest.raises(NotAuthorisedForPrivilegedMutation):
            assert_privileged_mutation(session, ctx, audit_writer=None)


# ---------------------------------------------------------------------------
# 3. backoffice/middleware.py — CsrfOriginRejectedEvent + reused
#    AuthVerifyRejectedAdminSessionEvent (require_user_session wrong_plane)
# ---------------------------------------------------------------------------

class _MwFakeRequest:
    def __init__(self, method="POST", origin=None, path="/admin/rbac/groups", cookies=None):
        self.method = method
        self._headers = {}
        if origin is not None:
            self._headers["origin"] = origin
        self.headers = _FakeHeaders(self._headers)
        self.url = MagicMock(path=path)
        self.cookies = cookies or {}
        self.client = MagicMock(host="203.0.113.9")


class TestCsrfOriginRejected:
    def test_cross_site_origin_audited(self, monkeypatch):
        from yashigani.backoffice import middleware as mw
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        aw = _CountingAuditWriter()
        mock_bs = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            from fastapi import HTTPException
            req = _MwFakeRequest(method="POST", origin="https://evil.example")
            with pytest.raises(HTTPException) as exc:
                mw._enforce_csrf_origin(req)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].rejected_origin == "https://evil.example"
        assert aw.events[0].path == "/admin/rbac/groups"

    def test_same_site_origin_not_denied_no_audit(self, monkeypatch):
        from yashigani.backoffice import middleware as mw
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        aw = _CountingAuditWriter()
        mock_bs = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            req = _MwFakeRequest(method="POST", origin="https://yashigani.example.com")
            mw._enforce_csrf_origin(req)  # must not raise
        assert aw.events == []

    def test_audit_writer_failure_never_blocks_deny(self, monkeypatch):
        from yashigani.backoffice import middleware as mw
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        mock_bs = MagicMock(audit_writer=_BoomAuditWriter())
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            from fastapi import HTTPException
            req = _MwFakeRequest(method="POST", origin="https://evil.example")
            with pytest.raises(HTTPException) as exc:
                mw._enforce_csrf_origin(req)
            assert exc.value.status_code == 403


class TestRequireUserSessionWrongPlaneAudited:
    def test_admin_session_on_user_plane_reuses_auth_verify_event(self):
        from yashigani.backoffice import middleware as mw
        aw = _CountingAuditWriter()
        mock_bs = MagicMock(audit_writer=aw)
        store = MagicMock()
        admin_session = _session(account_id="admin-1", account_tier="admin")
        store.get = MagicMock(return_value=admin_session)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            from fastapi import HTTPException
            req = _MwFakeRequest(method="GET", path="/chat", cookies={"__Host-yashigani_session": "tok-abc123"})
            with pytest.raises(HTTPException) as exc:
                mw.require_user_session(req, store=store)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert type(aw.events[0]).__name__ == "AuthVerifyRejectedAdminSessionEvent"
        assert aw.events[0].account_id == "admin-1"


# ---------------------------------------------------------------------------
# 4. backoffice/routes/agent_policies.py::_assert_tenant_scope() —
#    TenantScopeViolationEvent
# ---------------------------------------------------------------------------

class TestTenantScopeViolationAudited:
    def test_wrong_tenant_audited(self, monkeypatch):
        from yashigani.backoffice.routes import agent_policies as ap
        monkeypatch.setenv("YASHIGANI_TENANT_ID", "default")
        aw = _CountingAuditWriter()
        mock_bs = MagicMock(audit_writer=aw)
        session = _session(account_id="admin-1", account_tier="admin")
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                ap._assert_tenant_scope("other-tenant", session)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].path_tenant == "other-tenant"
        assert aw.events[0].configured_tenant == "default"
        assert aw.events[0].account_id == "admin-1"

    def test_matching_tenant_no_audit(self, monkeypatch):
        from yashigani.backoffice.routes import agent_policies as ap
        monkeypatch.setenv("YASHIGANI_TENANT_ID", "default")
        aw = _CountingAuditWriter()
        mock_bs = MagicMock(audit_writer=aw)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            ap._assert_tenant_scope("default", _session())  # must not raise
        assert aw.events == []

    def test_no_session_still_denies(self, monkeypatch):
        from yashigani.backoffice.routes import agent_policies as ap
        monkeypatch.setenv("YASHIGANI_TENANT_ID", "default")
        mock_bs = MagicMock(audit_writer=None)
        with patch("yashigani.backoffice.state.backoffice_state", mock_bs):
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                ap._assert_tenant_scope("other-tenant")  # session omitted (backward compat)


# ---------------------------------------------------------------------------
# 5. backoffice/routes/auth.py::_check_ip_access() — LoginIpAccessDeniedEvent
# ---------------------------------------------------------------------------

class TestLoginIpAccessDenied:
    def test_ip_blocked_audited(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        fake_redis = MagicMock()
        fake_redis.exists = MagicMock(return_value=True)
        with patch.object(auth_routes, "_get_throttle_redis", return_value=fake_redis), \
             patch.object(auth_routes.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                auth_routes._check_ip_access("203.0.113.9")
            assert exc.value.status_code == 403
            assert exc.value.detail["error"] == "ip_blocked"
        assert len(aw.events) == 1
        assert aw.events[0].reason == "ip_blocked"

    def test_ip_not_allowlisted_audited(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        fake_redis = MagicMock()
        fake_redis.exists = MagicMock(return_value=False)
        fake_redis.smembers = MagicMock(return_value={"198.51.100.1"})
        with patch.object(auth_routes, "_get_throttle_redis", return_value=fake_redis), \
             patch.object(auth_routes.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                auth_routes._check_ip_access("203.0.113.9")
            assert exc.value.status_code == 403
            assert exc.value.detail["error"] == "ip_not_allowed"
        assert len(aw.events) == 1
        assert aw.events[0].reason == "ip_not_allowed"

    def test_allowed_ip_no_audit(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        fake_redis = MagicMock()
        fake_redis.exists = MagicMock(return_value=False)
        fake_redis.smembers = MagicMock(return_value=set())
        with patch.object(auth_routes, "_get_throttle_redis", return_value=fake_redis), \
             patch.object(auth_routes.backoffice_state, "audit_writer", aw):
            auth_routes._check_ip_access("203.0.113.9")  # must not raise
        assert aw.events == []


# ---------------------------------------------------------------------------
# 6. backoffice/routes/auth.py::verify_admin_session() — reused
#    AdminAccessDeniedTierMismatchEvent
# ---------------------------------------------------------------------------

class TestVerifyAdminSessionDeniedAudited:
    @pytest.mark.asyncio
    async def test_non_admin_session_audited(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        session = _session(account_id="user-1", account_tier="user")
        store = MagicMock()
        store.get = MagicMock(return_value=session)
        with patch.object(auth_routes, "backoffice_state") as mock_bs:
            mock_bs.audit_writer = aw
            mock_bs.auth_service = MagicMock()
            mock_bs.session_store = store
            req = MagicMock()
            req.cookies = {auth_routes._SESSION_COOKIE: "tok-abc123"}
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await auth_routes.verify_admin_session(req)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert type(aw.events[0]).__name__ == "AdminAccessDeniedTierMismatchEvent"
        assert aw.events[0].reason == "admin_session_required"
        assert aw.events[0].account_id == "user-1"


# ---------------------------------------------------------------------------
# 7. backoffice/routes/auth.py::verify_user_session() —
#    VerifyUserAccessDeniedEvent (+ reused AuthVerifyRejectedAdminSessionEvent)
# ---------------------------------------------------------------------------

class TestVerifyUserSessionDeniedAudited:
    @pytest.mark.asyncio
    async def test_totp_provisioning_incomplete_audited(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        session = _session(account_id="user-1", account_tier="totp_provisioning")
        store = MagicMock()
        store.get = MagicMock(return_value=session)
        with patch.object(auth_routes, "backoffice_state") as mock_bs:
            mock_bs.audit_writer = aw
            mock_bs.auth_service = MagicMock()
            mock_bs.session_store = store
            req = MagicMock()
            req.cookies = {auth_routes._USER_SESSION_COOKIE: "tok-abc123"}
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await auth_routes.verify_user_session(req)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert type(aw.events[0]).__name__ == "VerifyUserAccessDeniedEvent"
        assert aw.events[0].reason == "totp_provisioning_incomplete"

    @pytest.mark.asyncio
    async def test_admin_session_reuses_auth_verify_event(self):
        from yashigani.backoffice.routes import auth as auth_routes
        aw = _CountingAuditWriter()
        session = _session(account_id="admin-1", account_tier="admin")
        store = MagicMock()
        store.get = MagicMock(return_value=session)
        with patch.object(auth_routes, "backoffice_state") as mock_bs:
            mock_bs.audit_writer = aw
            mock_bs.auth_service = MagicMock()
            mock_bs.session_store = store
            req = MagicMock()
            req.cookies = {auth_routes._USER_SESSION_COOKIE: "tok-abc123"}
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await auth_routes.verify_user_session(req)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert type(aw.events[0]).__name__ == "AuthVerifyRejectedAdminSessionEvent"


# ---------------------------------------------------------------------------
# 8. backoffice/routes/break_glass.py::break_glass_approve() —
#    BreakGlassApprovalDeniedEvent
# ---------------------------------------------------------------------------

class TestBreakGlassApprovalDeniedAudited:
    @pytest.mark.asyncio
    async def test_self_approval_rejected_audited(self):
        from yashigani.backoffice.routes.break_glass import break_glass_approve, BreakGlassError
        aw = _CountingAuditWriter()
        mock_mgr = MagicMock()
        mock_mgr.approve_break_glass.side_effect = BreakGlassError("self-approval")
        session = _session(account_id="admin-1", account_tier="admin")
        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            mock_bs.audit_writer = aw
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await break_glass_approve(session=session)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].reason == "self_approval_rejected"
        assert aw.events[0].account_id == "admin-1"

    @pytest.mark.asyncio
    async def test_approval_expired_audited(self):
        from yashigani.backoffice.routes.break_glass import break_glass_approve, ApprovalExpiredError
        aw = _CountingAuditWriter()
        mock_mgr = MagicMock()
        mock_mgr.approve_break_glass.side_effect = ApprovalExpiredError("expired")
        session = _session(account_id="admin-2", account_tier="admin")
        with patch("yashigani.backoffice.routes.break_glass.backoffice_state") as mock_bs:
            mock_bs.break_glass_manager = mock_mgr
            mock_bs.audit_writer = aw
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                await break_glass_approve(session=session)
        assert len(aw.events) == 1
        assert aw.events[0].reason == "approval_expired"


# ---------------------------------------------------------------------------
# 9. backoffice/routes/dp_weaken.py::approve_weaken_request() /
#    10. backoffice/routes/permissions.py::approve_declaration() —
#    shared DistinctApproverViolationEvent
# ---------------------------------------------------------------------------

class TestDistinctApproverViolationAudited:
    def test_dp_weaken_self_approval_denied_audited(self):
        from yashigani.backoffice.routes import dp_weaken
        aw = _CountingAuditWriter()
        with patch.object(dp_weaken.backoffice_state, "audit_writer", aw):
            from yashigani.audit.schema import DistinctApproverViolationEvent
            # Directly exercise the audit call the route makes on self-approval.
            dp_weaken._write_audit(DistinctApproverViolationEvent(
                domain="dp_weaken", account_id="admin-1", request_id="req-123",
            ))
        assert len(aw.events) == 1
        assert aw.events[0].domain == "dp_weaken"
        assert aw.events[0].account_id == "admin-1"

    @pytest.mark.asyncio
    async def test_dp_weaken_route_self_approval_audited_end_to_end(self):
        from yashigani.backoffice.routes import dp_weaken
        aw = _CountingAuditWriter()
        store = MagicMock()
        store.get = MagicMock(return_value={
            "requester_id": "admin-1", "control": "pii_mode", "from_state": "BLOCK", "to_state": "LOG",
        })
        session = _session(account_id="admin-1", account_tier="admin")
        with patch.object(dp_weaken, "_dp_store", return_value=store), \
             patch.object(dp_weaken, "_install_tenant", return_value="default"), \
             patch.object(dp_weaken.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await dp_weaken.approve_weaken_request("req-123", session)
            assert exc.value.status_code == 403
            assert exc.value.detail["error"] == "self_approval_forbidden"
        assert any(type(e).__name__ == "DistinctApproverViolationEvent" for e in aw.events)
        viol = [e for e in aw.events if type(e).__name__ == "DistinctApproverViolationEvent"][0]
        assert viol.domain == "dp_weaken"
        assert viol.request_id == "req-123"

    def test_permissions_self_approval_denied_audited(self):
        from yashigani.backoffice.routes import permissions as perm
        from yashigani.permissions.resolver import ResourceType
        aw = _CountingAuditWriter()
        with patch.object(perm.backoffice_state, "audit_writer", aw):
            perm._audit_declaration_self_approval_denied("admin-1", ResourceType.CLOUD_MODEL, "gpt-4o")
        assert len(aw.events) == 1
        assert aw.events[0].domain == "permission_declaration"
        assert aw.events[0].account_id == "admin-1"
        assert "gpt-4o" in aw.events[0].request_id


# ---------------------------------------------------------------------------
# 11. backoffice/routes/me.py — MeApiKeyAccessDeniedEvent
# ---------------------------------------------------------------------------

class TestMeApiKeyAccessDeniedAudited:
    def test_non_user_tier_audited(self):
        from yashigani.backoffice.routes import me
        aw = _CountingAuditWriter()
        session = _session(account_id="admin-1", account_tier="admin")
        with patch.object(me.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                me._assert_user_tier(session)
            assert exc.value.status_code == 403
        assert len(aw.events) == 1
        assert aw.events[0].reason == "user_tier_required"
        assert aw.events[0].account_id == "admin-1"

    def test_force_password_change_pending_audited(self):
        from yashigani.backoffice.routes import me
        from yashigani.auth.local_auth import AccountRecord
        aw = _CountingAuditWriter()
        record = AccountRecord(
            account_id="user-1", username="u1", password_hash="h", totp_secret="s",
            recovery_codes=None, account_tier="user",
            force_password_change=True, force_totp_provision=False,
        )
        with patch.object(me.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                me._assert_account_ready(record)
        assert len(aw.events) == 1
        assert aw.events[0].reason == "force_password_change_pending"

    def test_account_not_found_audited(self):
        from yashigani.backoffice.routes import me
        aw = _CountingAuditWriter()
        with patch.object(me.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                me._assert_account_ready(None)
        assert len(aw.events) == 1
        assert aw.events[0].reason == "account_not_found"

    def test_user_tier_ok_no_audit(self):
        from yashigani.backoffice.routes import me
        aw = _CountingAuditWriter()
        session = _session(account_id="user-1", account_tier="user")
        with patch.object(me.backoffice_state, "audit_writer", aw):
            me._assert_user_tier(session)  # must not raise
        assert aw.events == []


# ---------------------------------------------------------------------------
# 12. backoffice/routes/user_ui.py::user_chat_proxy() —
#     ChatProxyIdentityDeniedEvent
# ---------------------------------------------------------------------------

class TestChatProxyIdentityDeniedAudited:
    def test_identity_not_found_audited(self):
        from yashigani.backoffice.routes import user_ui
        aw = _CountingAuditWriter()
        with patch.object(user_ui.backoffice_state, "audit_writer", aw):
            user_ui._audit_chat_proxy_identity_denied("user-1")
        assert len(aw.events) == 1
        assert aw.events[0].account_id == "user-1"
        assert aw.events[0].reason == "identity_not_found"

    def test_no_audit_writer_is_noop(self):
        from yashigani.backoffice.routes import user_ui
        with patch.object(user_ui.backoffice_state, "audit_writer", None):
            user_ui._audit_chat_proxy_identity_denied("user-1")  # must not raise


# ---------------------------------------------------------------------------
# 13. gateway/egress_proxy.py::egress_eval() — missing_caller_identity now
#     reuses _emit_deny_audit (OpaDecisionOnMcpEvent)
# ---------------------------------------------------------------------------

class TestEgressEvalMissingIdentityAudited:
    @pytest.mark.asyncio
    async def test_missing_caller_identity_audited(self):
        from yashigani.gateway import egress_proxy as ep
        aw = _CountingAuditWriter()
        ep._state.audit_writer = aw
        try:
            req = MagicMock()
            req.headers = _FakeHeaders({})  # no x-spiffe-id
            resp = await ep.egress_eval(req, "slack", "chat.postMessage")
            assert resp.status_code == 403
        finally:
            ep._state.audit_writer = None
        assert len(aw.events) == 1
        assert aw.events[0].deny_reason == "egress:missing_caller_identity"


# ---------------------------------------------------------------------------
# 14. gateway/openai_router.py::_resolve_yashigani_identity_id_header() —
#     TrustedForwarderIdentityRejectedEvent
# ---------------------------------------------------------------------------

class TestTrustedForwarderIdentityRejectedAudited:
    def test_malformed_identity_id_audited(self):
        from yashigani.gateway import openai_router as oar
        aw = _CountingAuditWriter()
        oar._state.audit_writer = aw
        try:
            from fastapi import HTTPException
            req = MagicMock()
            req.headers = _FakeHeaders({oar._YASHIGANI_IDENTITY_ID_HEADER: "not-idnt-prefixed"})
            with pytest.raises(HTTPException) as exc:
                oar._resolve_yashigani_identity_id_header(req)
            assert exc.value.status_code == 403
        finally:
            oar._state.audit_writer = None
        assert len(aw.events) == 1
        assert aw.events[0].reason == "identity_id_malformed"

    def test_registry_unavailable_audited(self):
        from yashigani.gateway import openai_router as oar
        aw = _CountingAuditWriter()
        oar._state.audit_writer = aw
        prev_registry = oar._state.identity_registry
        oar._state.identity_registry = None
        try:
            from fastapi import HTTPException
            req = MagicMock()
            req.headers = _FakeHeaders({oar._YASHIGANI_IDENTITY_ID_HEADER: "idnt_abc123"})
            with pytest.raises(HTTPException) as exc:
                oar._resolve_yashigani_identity_id_header(req)
            assert exc.value.status_code == 503
        finally:
            oar._state.audit_writer = None
            oar._state.identity_registry = prev_registry
        assert len(aw.events) == 1
        assert aw.events[0].reason == "identity_registry_unavailable"

    def test_absent_header_not_audited(self):
        from yashigani.gateway import openai_router as oar
        aw = _CountingAuditWriter()
        oar._state.audit_writer = aw
        try:
            req = MagicMock()
            req.headers = _FakeHeaders({})
            result = oar._resolve_yashigani_identity_id_header(req)
            assert result is None
        finally:
            oar._state.audit_writer = None
        assert aw.events == []


# ---------------------------------------------------------------------------
# 15. gateway/openai_router.py::_resolve_identity() p1_nhi branch —
#     NhiIdentityResolutionDeniedEvent
# ---------------------------------------------------------------------------

class TestNhiIdentityResolutionDeniedAudited:
    def test_nhi_pending_approval_audited(self):
        from yashigani.gateway import openai_router as oar
        aw = _CountingAuditWriter()
        oar._state.audit_writer = aw
        try:
            with patch.object(oar, "_resolve_caller_role", return_value=("p1_nhi", "nhi-1")), \
                 patch.object(oar, "_resolve_nhi_identity", return_value=None):
                req = MagicMock()
                req.headers = _FakeHeaders({"authorization": "Bearer sometoken"})
                from fastapi import HTTPException
                with pytest.raises(HTTPException) as exc:
                    oar._resolve_identity(req)
                assert exc.value.status_code == 403
                assert exc.value.detail["error"] == "NHI_PENDING_APPROVAL"
        finally:
            oar._state.audit_writer = None
        assert len(aw.events) == 1
        assert aw.events[0].token_identity_id == "nhi-1"
        assert aw.events[0].reason == "nhi_pending_approval"


# ---------------------------------------------------------------------------
# 16. gateway/orchestrator.py::_seed_denied() — OrchestrationSeedDeniedEvent
# ---------------------------------------------------------------------------

class TestOrchestrationSeedDeniedAudited:
    def test_seed_denied_audits_every_call_site(self):
        from yashigani.gateway import orchestrator as orch
        with patch("yashigani.gateway.openai_router._deny_message", return_value="denied"):
            aw = _CountingAuditWriter()
            with patch.object(orch, "_audit") as mock_audit:
                identity = {"identity_id": "idnt_x"}
                resp = orch._seed_denied("req-1", "brain_model_not_allowed", "RESTRICTED", identity)
                assert resp.status_code == 403
                mock_audit.assert_called_once()
                event = mock_audit.call_args[0][0]
                assert type(event).__name__ == "OrchestrationSeedDeniedEvent"
                assert event.reason == "brain_model_not_allowed"
                assert event.identity_id == "idnt_x"
                assert event.request_id == "req-1"
                assert event.sensitivity_level == "RESTRICTED"

    def test_seed_denied_no_identity_still_denies(self):
        from yashigani.gateway import orchestrator as orch
        with patch("yashigani.gateway.openai_router._deny_message", return_value="denied"):
            with patch.object(orch, "_audit") as mock_audit:
                resp = orch._seed_denied("req-2", "seed_pii_blocked", "PUBLIC")
                assert resp.status_code == 403
                mock_audit.assert_called_once()
                event = mock_audit.call_args[0][0]
                assert event.identity_id == "anonymous"
