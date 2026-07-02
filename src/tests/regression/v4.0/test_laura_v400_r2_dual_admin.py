"""
Regression tests — LAURA-V400-R2-001 (dual-admin data-protection maker-checker).

Root cause:
    LAURA-V400-R2-001 (MEDIUM) identified that disabling data-protection controls
    (PII scanning, PII cloud bypass, document enforcement) required only a SINGLE
    admin with step-up TOTP — the same admin who wanted to disable protection
    could do so alone.

Fix (this commit):
    Weakening any of the three data-protection controls now creates a PENDING
    weaken request in DpWeakenPendingStore.  The change is NOT applied until a
    DIFFERENT admin (checker) approves it with step-up TOTP.

    STRENGTHEN direction (tightening) remains single-admin + step-up.

    Fail-closed: if fewer than 2 active admins exist, the weaken request is
    refused with 409.

Test coverage (these tests would fail on the original code):
  1. DpWeakenPendingStore unit — create, get, resolve, count, TTL.
  2. Weaken request REFUSED when <2 active admins.
  3. Maker submits pii_config weaken → 202 pending (not applied).
  4. GET /config still shows enforcing mode after submission.
  5. Maker CANNOT approve own request → 403.
  6. Different checker approves → 200, config now applied.
  7. Status endpoint reflects weakened state after approval.
  8. Re-enable (strengthen) by single admin → 200, applied immediately.
  9. Weaken request rejected → config unchanged.
 10. Non-weaken direction (strengthen) via PUT /admin/pii/config → 200 direct.
 11. pii_cloud_bypass weaken creates pending (not applied).
 12. doc_enforcement weaken creates pending (not applied).
 13. Approve with same-admin as requester → 403.
"""
from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# DpWeakenPendingStore unit tests
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal dict-backed fake Redis for store unit tests.

    Tracks setex/set/delete/get/scan so the store's refresh-from-Redis
    calls see the same data that was written via setex (cross-process
    coherency simulation in a single process)."""

    def __init__(self):
        self._data = {}

    def setex(self, key, ttl, value):
        if isinstance(key, bytes):
            key = key.decode()
        self._data[key] = value

    def set(self, key, value):
        self.setex(key, None, value)

    def get(self, key):
        if isinstance(key, bytes):
            key = key.decode()
        v = self._data.get(key)
        return v.encode() if isinstance(v, str) else v

    def delete(self, key):
        if isinstance(key, bytes):
            key = key.decode()
        self._data.pop(key, None)

    def scan(self, cursor, match="*", count=200):
        import fnmatch
        keys = [k.encode() for k in self._data if fnmatch.fnmatch(k, match.replace("*", "*"))]
        return (0, keys)

    def ping(self):
        return True


class TestDpWeakenPendingStore:
    """Unit tests for the store in isolation (no Redis — FakeRedis)."""

    def _make_store(self):
        from yashigani.protection.weaken_pending_store import DpWeakenPendingStore
        redis_fake = _FakeRedis()
        store = DpWeakenPendingStore(redis_client=redis_fake)
        return store, redis_fake

    def test_create_returns_pending_row(self):
        store, _ = self._make_store()
        row = store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "redact", "enabled_types": []},
            to_state={"mode": "pass", "enabled_types": []},
        )
        assert row["request_id"]
        assert row["requester_id"] == "admin-a"
        assert row["control"] == "pii_config"
        assert row["status"] == "pending"
        assert row["expires_at"] > time.time()

    def test_get_tenant_scoped(self):
        store, _ = self._make_store()
        row = store.create_request(
            tenant_id="tenant-a",
            requester_id="admin-a",
            control="pii_cloud_bypass",
            from_state={"enabled": False},
            to_state={"enabled": True},
        )
        request_id = row["request_id"]

        # Correct tenant: returns row.
        assert store.get(request_id, "tenant-a") is not None
        # Wrong tenant: fail-closed (None).
        assert store.get(request_id, "tenant-b") is None

    def test_list_for_tenant(self):
        store, _ = self._make_store()
        store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "log", "enabled_types": []},
        )
        store.create_request(
            tenant_id="default",
            requester_id="admin-b",
            control="doc_enforcement",
            from_state={"enabled": True},
            to_state={"enabled": False},
        )
        # Other tenant entry should NOT appear.
        store.create_request(
            tenant_id="other-tenant",
            requester_id="admin-c",
            control="pii_cloud_bypass",
            from_state={"enabled": False},
            to_state={"enabled": True},
        )
        rows = store.list_for_tenant("default")
        assert len(rows) == 2
        controls = {r["control"] for r in rows}
        assert controls == {"pii_config", "doc_enforcement"}

    def test_resolve_drops_entry(self):
        store, _ = self._make_store()
        row = store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "pass", "enabled_types": []},
        )
        rid = row["request_id"]
        assert store.get(rid, "default") is not None
        result = store.resolve(rid, "default")
        assert result is True
        assert store.get(rid, "default") is None

    def test_resolve_cross_tenant_is_noop(self):
        store, _ = self._make_store()
        row = store.create_request(
            tenant_id="tenant-a",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "pass", "enabled_types": []},
        )
        rid = row["request_id"]
        # Wrong tenant → no-op.
        assert store.resolve(rid, "tenant-b") is False
        # Entry still exists for correct tenant.
        assert store.get(rid, "tenant-a") is not None

    def test_count_for_tenant(self):
        store, _ = self._make_store()
        assert store.count_for_tenant("default") == 0
        store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "pass", "enabled_types": []},
        )
        assert store.count_for_tenant("default") == 1

    def test_invalid_control_raises(self):
        store, _ = self._make_store()
        with pytest.raises(ValueError, match="control must be one of"):
            store.create_request(
                tenant_id="default",
                requester_id="admin-a",
                control="unknown_control",
                from_state={},
                to_state={},
            )

    def test_idempotent_resubmit_same_requester_same_control(self):
        """Re-submitting the same control from the same requester overwrites."""
        store, _ = self._make_store()
        r1 = store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "pass", "enabled_types": []},
        )
        r2 = store.create_request(
            tenant_id="default",
            requester_id="admin-a",
            control="pii_config",
            from_state={"mode": "block", "enabled_types": []},
            to_state={"mode": "log", "enabled_types": []},  # different desired mode
        )
        # Same request_id (overwrite), different to_state.
        assert r1["request_id"] == r2["request_id"]
        assert r2["to_state"]["mode"] == "log"
        # Still only 1 entry.
        assert store.count_for_tenant("default") == 1


# ---------------------------------------------------------------------------
# Route behaviour tests (mock backoffice_state + store)
# ---------------------------------------------------------------------------

def _make_session(account_id="admin-a", has_stepup=True):
    """Create a minimal session mock."""
    session = MagicMock()
    session.account_id = account_id
    session.account_tier = "admin"
    session.last_totp_verified_at = time.time() if has_stepup else None
    return session


def _make_store():
    """Create a fresh DpWeakenPendingStore backed by FakeRedis."""
    from yashigani.protection.weaken_pending_store import DpWeakenPendingStore
    return DpWeakenPendingStore(redis_client=_FakeRedis())


def _make_auth_service(active_count=2):
    """Create an async mock auth service with the given active admin count."""
    svc = MagicMock()
    svc.active_admin_count = AsyncMock(return_value=active_count)
    return svc


class TestDpWeakenRoutes:
    """Behavioural tests for the dp_weaken route handlers."""

    def setup_method(self):
        """Wire mock state before each test."""
        from yashigani.backoffice.state import backoffice_state
        self._store = _make_store()
        backoffice_state.dp_weaken_store = self._store
        backoffice_state.auth_service = _make_auth_service(active_count=2)
        backoffice_state.audit_writer = None
        # Reset pii_config and cloud_bypass to enforcing defaults.
        backoffice_state.pii_config = {"mode": "redact", "enabled_types": []}
        backoffice_state.pii_cloud_bypass = False
        backoffice_state.document_enforcement_enabled = True

    def teardown_method(self):
        from yashigani.backoffice.state import backoffice_state
        backoffice_state.dp_weaken_store = None
        backoffice_state.auth_service = None

    # --- Fail-closed: <2 admins ---

    @pytest.mark.asyncio
    async def test_submit_refused_when_one_admin(self):
        """Weaken request is refused with 409 when only 1 active admin exists."""
        from yashigani.backoffice.state import backoffice_state
        backoffice_state.auth_service = _make_auth_service(active_count=1)

        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(control="pii_config", to_state={"mode": "pass", "enabled_types": []})
        session = _make_session("admin-a")

        with pytest.raises(HTTPException) as exc_info:
            await submit_weaken_request(body, session)
        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "insufficient_active_admins"

    # --- Maker submits → pending (not applied) ---

    @pytest.mark.asyncio
    async def test_pii_config_weaken_creates_pending(self):
        """PUT /admin/pii/config with pass/log creates a pending request, not applied."""
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(
            control="pii_config",
            to_state={"mode": "pass", "enabled_types": []},
        )
        session = _make_session("admin-a")
        resp = await submit_weaken_request(body, session)

        # Returns pending, not applied.
        assert resp["status"] == "pending"
        assert resp["request_id"]
        assert resp["control"] == "pii_config"

        # Config NOT changed in backoffice_state.
        from yashigani.backoffice.state import backoffice_state
        assert backoffice_state.pii_config["mode"] == "redact"  # unchanged

    @pytest.mark.asyncio
    async def test_pii_cloud_bypass_weaken_creates_pending(self):
        """Enabling cloud bypass creates a pending request, bypass NOT enabled."""
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(
            control="pii_cloud_bypass",
            to_state={"enabled": True},
        )
        session = _make_session("admin-a")
        resp = await submit_weaken_request(body, session)

        assert resp["status"] == "pending"
        assert resp["control"] == "pii_cloud_bypass"
        from yashigani.backoffice.state import backoffice_state
        assert backoffice_state.pii_cloud_bypass is False  # NOT enabled

    @pytest.mark.asyncio
    async def test_doc_enforcement_weaken_creates_pending(self):
        """Disabling doc enforcement creates a pending request, NOT disabled."""
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(
            control="doc_enforcement",
            to_state={"enabled": False},
        )
        session = _make_session("admin-a")
        resp = await submit_weaken_request(body, session)

        assert resp["status"] == "pending"
        assert resp["control"] == "doc_enforcement"
        from yashigani.backoffice.state import backoffice_state
        assert backoffice_state.document_enforcement_enabled is True  # NOT disabled

    # --- Maker CANNOT approve own request ---

    @pytest.mark.asyncio
    async def test_maker_cannot_approve_own_request(self):
        """Admin A cannot approve their own weaken request (403)."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import (
            submit_weaken_request, approve_weaken_request, WeakenRequestBody,
        )

        # Admin A submits.
        body = WeakenRequestBody(
            control="pii_config",
            to_state={"mode": "pass", "enabled_types": []},
        )
        session_a = _make_session("admin-a")
        resp = await submit_weaken_request(body, session_a)
        request_id = resp["request_id"]

        # Admin A tries to approve their own request → 403.
        with pytest.raises(HTTPException) as exc_info:
            await approve_weaken_request(request_id, session_a)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "self_approval_forbidden"

    # --- Different checker approves → applied ---

    @pytest.mark.asyncio
    async def test_checker_approves_applies_change(self):
        """Admin B approves admin A's weaken request → config applied."""
        from yashigani.backoffice.routes.dp_weaken import (
            submit_weaken_request, approve_weaken_request, WeakenRequestBody,
        )

        # Admin A submits.
        body = WeakenRequestBody(
            control="pii_config",
            to_state={"mode": "log", "enabled_types": []},
        )
        session_a = _make_session("admin-a")
        resp = await submit_weaken_request(body, session_a)
        request_id = resp["request_id"]

        # Config still enforcing.
        from yashigani.backoffice.state import backoffice_state
        assert backoffice_state.pii_config["mode"] == "redact"

        # Admin B approves.
        session_b = _make_session("admin-b")
        result = await approve_weaken_request(request_id, session_b)

        assert result["status"] == "approved_and_applied"
        # Config NOW changed.
        assert backoffice_state.pii_config["mode"] == "log"

        # Pending entry consumed.
        assert self._store.count_for_tenant("default") == 0

    # --- Reject keeps config unchanged ---

    @pytest.mark.asyncio
    async def test_reject_keeps_config_unchanged(self):
        """Rejecting a weaken request leaves the config unchanged."""
        from yashigani.backoffice.routes.dp_weaken import (
            submit_weaken_request, reject_weaken_request, WeakenRequestBody,
        )
        from yashigani.backoffice.state import backoffice_state

        body = WeakenRequestBody(
            control="pii_config",
            to_state={"mode": "pass", "enabled_types": []},
        )
        session_a = _make_session("admin-a")
        resp = await submit_weaken_request(body, session_a)
        request_id = resp["request_id"]

        session_b = _make_session("admin-b")
        result = await reject_weaken_request(request_id, session_b)

        assert result["status"] == "rejected"
        # Config unchanged.
        assert backoffice_state.pii_config["mode"] == "redact"
        # Pending entry consumed.
        assert self._store.count_for_tenant("default") == 0

    # --- Non-weakening direction via submit → 422 ---

    @pytest.mark.asyncio
    async def test_strengthen_direction_rejected_by_submit(self):
        """Submitting a strengthen direction is rejected with 422."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        # mode=block is enforcing, not weakening.
        body = WeakenRequestBody(
            control="pii_config",
            to_state={"mode": "block", "enabled_types": []},
        )
        session_a = _make_session("admin-a")
        with pytest.raises(HTTPException) as exc_info:
            await submit_weaken_request(body, session_a)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "not_a_weaken"

    @pytest.mark.asyncio
    async def test_cloud_bypass_disable_is_strengthen(self):
        """Disabling cloud bypass (enabled=False) is rejected as not a weakening."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(
            control="pii_cloud_bypass",
            to_state={"enabled": False},  # disabling = strengthen
        )
        session_a = _make_session("admin-a")
        with pytest.raises(HTTPException) as exc_info:
            await submit_weaken_request(body, session_a)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "not_a_weaken"

    @pytest.mark.asyncio
    async def test_doc_enforcement_enable_is_strengthen(self):
        """Enabling doc enforcement is rejected as not a weakening."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import submit_weaken_request, WeakenRequestBody

        body = WeakenRequestBody(
            control="doc_enforcement",
            to_state={"enabled": True},  # enabling = strengthen
        )
        session_a = _make_session("admin-a")
        with pytest.raises(HTTPException) as exc_info:
            await submit_weaken_request(body, session_a)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "not_a_weaken"

    # --- approve non-existent request → 404 ---

    @pytest.mark.asyncio
    async def test_approve_nonexistent_request_404(self):
        """Approving a nonexistent request returns 404."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import approve_weaken_request

        session_b = _make_session("admin-b")
        with pytest.raises(HTTPException) as exc_info:
            await approve_weaken_request("nonexistent-uuid", session_b)
        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "weaken_request_not_found"

    # --- reject non-existent request → 404 ---

    @pytest.mark.asyncio
    async def test_reject_nonexistent_request_404(self):
        """Rejecting a nonexistent request returns 404."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.dp_weaken import reject_weaken_request

        session_b = _make_session("admin-b")
        with pytest.raises(HTTPException) as exc_info:
            await reject_weaken_request("nonexistent-uuid", session_b)
        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "weaken_request_not_found"


# ---------------------------------------------------------------------------
# PII route intercept tests (unit — PUT /admin/pii/config behaviour)
# ---------------------------------------------------------------------------

class TestPiiRouteWeakenIntercept:
    """Verify that pii.py routes correctly intercept the weaken direction."""

    def setup_method(self):
        from yashigani.backoffice.state import backoffice_state
        self._store = _make_store()
        backoffice_state.dp_weaken_store = self._store
        backoffice_state.auth_service = _make_auth_service(active_count=2)
        backoffice_state.audit_writer = None
        backoffice_state.pii_config = {"mode": "redact", "enabled_types": []}
        backoffice_state.pii_cloud_bypass = False

    def teardown_method(self):
        from yashigani.backoffice.state import backoffice_state
        backoffice_state.dp_weaken_store = None
        backoffice_state.auth_service = None

    @pytest.mark.asyncio
    async def test_pii_config_strengthen_applied_immediately(self):
        """PUT /admin/pii/config with block mode applied immediately (no dual-admin)."""
        from yashigani.backoffice.state import backoffice_state
        from yashigani.backoffice.routes.pii import update_pii_config, PiiConfigRequest

        # Set current to log (weakened).
        backoffice_state.pii_config = {"mode": "log", "enabled_types": []}

        body = PiiConfigRequest(mode="block", enabled_types=[])
        session = _make_session("admin-a")
        resp = await update_pii_config(body, session)

        # Applied immediately.
        assert resp["status"] == "ok"
        assert backoffice_state.pii_config["mode"] == "block"

    @pytest.mark.asyncio
    async def test_pii_config_weaken_intercepted_by_route(self):
        """PUT /admin/pii/config with pass mode is intercepted — returns 202 pending."""
        from yashigani.backoffice.state import backoffice_state
        from yashigani.backoffice.routes.pii import update_pii_config, PiiConfigRequest
        from fastapi.responses import JSONResponse

        body = PiiConfigRequest(mode="pass", enabled_types=[])
        session = _make_session("admin-a")
        resp = await update_pii_config(body, session)

        # Returns JSONResponse with 202.
        assert isinstance(resp, JSONResponse)
        assert resp.status_code == 202
        import json
        data = json.loads(resp.body)
        assert data["status"] == "pending"
        # Config NOT changed.
        assert backoffice_state.pii_config["mode"] == "redact"


# ---------------------------------------------------------------------------
# Audit event schema presence test
# ---------------------------------------------------------------------------

class TestAuditEventSchema:
    """Verify the three new data-protection audit event classes exist."""

    def test_data_protection_weaken_requested_event_exists(self):
        from yashigani.audit.schema import DataProtectionWeakenRequestedEvent, EventType
        evt = DataProtectionWeakenRequestedEvent(
            admin_account="admin-a",
            request_id="req-001",
            control="pii_config",
            from_state={"mode": "redact"},
            to_state={"mode": "pass"},
        )
        assert evt.event_type == EventType.DATA_PROTECTION_WEAKEN_REQUESTED
        assert evt.control == "pii_config"

    def test_data_protection_weaken_approved_event_exists(self):
        from yashigani.audit.schema import DataProtectionWeakenApprovedEvent, EventType
        evt = DataProtectionWeakenApprovedEvent(
            admin_account="admin-b",
            requester_id="admin-a",
            request_id="req-001",
            control="pii_cloud_bypass",
            from_state={"enabled": False},
            to_state={"enabled": True},
        )
        assert evt.event_type == EventType.DATA_PROTECTION_WEAKEN_APPROVED
        assert evt.requester_id == "admin-a"

    def test_data_protection_weaken_rejected_event_exists(self):
        from yashigani.audit.schema import DataProtectionWeakenRejectedEvent, EventType
        evt = DataProtectionWeakenRejectedEvent(
            admin_account="admin-b",
            requester_id="admin-a",
            request_id="req-001",
            control="doc_enforcement",
            from_state={"enabled": True},
            to_state={"enabled": False},
        )
        assert evt.event_type == EventType.DATA_PROTECTION_WEAKEN_REJECTED
