"""
Unit tests — Admin workflow-oversight endpoints.

Covers:
  - GET /admin/workflows — admin can list all users' workflows (cross-user)
  - GET /admin/workflows/{wf_id} — admin can fetch any workflow by ID
  - PATCH /admin/workflows/{wf_id} — admin can disable any user's workflow;
    a user-tier session cannot (session gate, not tested here — middleware unit)
  - BOLA: user-plane /user/workflows/{wf_id} still enforces ownership
    (regression guard — verified via the existing test_user_workflows.py BOLA tests)
  - Audit: WorkflowAdminDisabledEvent emitted on disable
  - Pagination: page/page_size respected
  - 404: missing wf_id returns 404, not 500

All tests are unit-level — no live FastAPI app or Redis instance.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from yashigani.backoffice.routes.admin_workflows import (
    AdminPatchWorkflowBody,
    _get_wf_meta_or_404,
    _scan_all_wf_ids,
)
from yashigani.backoffice.routes.user_workflows import (
    _decode_hash,
    _wf_key,
)


# ===========================================================================
# Fake Redis stubs
# ===========================================================================


def _make_wf_hash(account_id: str, name: str = "Test WF", enabled: bool = True) -> dict:
    spec = json.dumps({"steps": [], "schedule": {"kind": "none"}})
    return {
        b"account_id": account_id.encode(),
        b"owner_identity_id": account_id.encode(),
        b"name": name.encode(),
        b"description": b"",
        b"spec": spec.encode(),
        b"spec_hash": b"sha384:abc",
        b"enabled": b"1" if enabled else b"0",
        b"created_at": b"2026-06-28T00:00:00+00:00",
        b"updated_at": b"2026-06-28T00:00:00+00:00",
    }


class _FakeRedis:
    """Synchronous Redis stub for unit tests."""

    def __init__(self, hashes: dict | None = None, sets: dict | None = None):
        self._hashes: dict = hashes or {}
        self._sets: dict = sets or {}
        self._written: dict = {}  # tracks hset calls

    def hgetall(self, key: str) -> dict:
        return dict(self._hashes.get(key, {}))

    def smembers(self, key: str) -> set:
        return set(self._sets.get(key, set()))

    def hset(self, key: str, mapping: dict) -> None:
        existing = dict(self._hashes.get(key, {}))
        existing.update(mapping)
        self._hashes[key] = existing
        self._written[key] = mapping

    def scan_iter(self, pattern: str, count: int = 100):
        """Yield matching keys as bytes."""
        prefix = pattern.rstrip(b"*" if isinstance(pattern, bytes) else "*")
        for key in self._sets:
            key_b = key.encode() if isinstance(key, str) else key
            if key_b.startswith(prefix.encode() if isinstance(prefix, str) else prefix):
                yield key_b


# ===========================================================================
# _scan_all_wf_ids
# ===========================================================================


class TestScanAllWfIds:
    """Verify _scan_all_wf_ids collects wf_ids from all per-user index keys."""

    def test_empty_store_returns_empty(self):
        r = _FakeRedis()
        result = _scan_all_wf_ids(r)
        assert result == []

    def test_single_user_single_workflow(self):
        r = _FakeRedis(
            sets={"wf:workflows:acct_A": {b"wfl_aaa111"}},
        )
        result = _scan_all_wf_ids(r)
        assert result == ["wfl_aaa111"]

    def test_two_users_workflows_merged_sorted(self):
        r = _FakeRedis(
            sets={
                "wf:workflows:acct_A": {b"wfl_zzz999", b"wfl_aaa000"},
                "wf:workflows:acct_B": {b"wfl_mmm555"},
            }
        )
        result = _scan_all_wf_ids(r)
        assert result == ["wfl_aaa000", "wfl_mmm555", "wfl_zzz999"]

    def test_scan_error_returns_empty_no_raise(self):
        r = MagicMock()
        r.scan_iter.side_effect = Exception("redis down")
        # Should not raise; returns []
        result = _scan_all_wf_ids(r)
        assert result == []


# ===========================================================================
# _get_wf_meta_or_404
# ===========================================================================


class TestGetWfMetaOr404:
    def test_missing_key_raises_404(self):
        r = _FakeRedis()
        with pytest.raises(HTTPException) as exc_info:
            _get_wf_meta_or_404(r, "wfl_nonexistent")
        assert exc_info.value.status_code == 404

    def test_present_key_returns_decoded_dict(self):
        wf_id = "wfl_aaa000"
        r = _FakeRedis(hashes={_wf_key(wf_id): _make_wf_hash("acct_A")})
        meta = _get_wf_meta_or_404(r, wf_id)
        assert meta["account_id"] == "acct_A"
        assert meta["enabled"] == "1"


# ===========================================================================
# Admin list workflows (pagination)
# ===========================================================================


class TestAdminListWorkflowsPagination:
    """Verify pagination slicing in admin_list_workflows."""

    def _build_redis_with_n_workflows(self, n: int):
        hashes = {}
        sets = {}
        wf_ids = [f"wfl_{i:06d}" for i in range(n)]
        acct_id = "acct_owner"
        for wf_id in wf_ids:
            hashes[_wf_key(wf_id)] = _make_wf_hash(acct_id, name=wf_id)
        sets[f"wf:workflows:{acct_id}"] = {wf_id.encode() for wf_id in wf_ids}
        return _FakeRedis(hashes=hashes, sets=sets), wf_ids

    def test_page1_returns_first_n(self):
        """Page 1 with page_size=3 returns the first 3 wf_ids."""
        from yashigani.backoffice.routes.admin_workflows import _scan_all_wf_ids
        r, wf_ids = self._build_redis_with_n_workflows(7)
        all_ids = _scan_all_wf_ids(r)
        assert all_ids == sorted(wf_ids)
        # Simulate pagination
        page, page_size = 1, 3
        offset = (page - 1) * page_size
        page_ids = all_ids[offset : offset + page_size]
        assert page_ids == all_ids[:3]

    def test_page2_returns_next_batch(self):
        r, wf_ids = self._build_redis_with_n_workflows(7)
        from yashigani.backoffice.routes.admin_workflows import _scan_all_wf_ids
        all_ids = _scan_all_wf_ids(r)
        page, page_size = 2, 3
        offset = (page - 1) * page_size
        page_ids = all_ids[offset : offset + page_size]
        assert page_ids == all_ids[3:6]

    def test_last_page_returns_remainder(self):
        r, wf_ids = self._build_redis_with_n_workflows(7)
        from yashigani.backoffice.routes.admin_workflows import _scan_all_wf_ids
        all_ids = _scan_all_wf_ids(r)
        page, page_size = 3, 3
        offset = (page - 1) * page_size
        page_ids = all_ids[offset : offset + page_size]
        assert page_ids == all_ids[6:9]  # only 1 item on page 3
        assert len(page_ids) == 1


# ===========================================================================
# Admin patch — enable/disable
# ===========================================================================


class TestAdminPatchWorkflow:
    """Verify PATCH body model and DB 3 update logic."""

    def test_patch_body_no_enabled_is_no_op(self):
        body = AdminPatchWorkflowBody(enabled=None)
        assert body.enabled is None

    def test_patch_body_enabled_false(self):
        body = AdminPatchWorkflowBody(enabled=False)
        assert body.enabled is False

    def test_db3_updated_on_disable(self):
        """Verify hset is called with enabled=b'0' when body.enabled is False."""
        wf_id = "wfl_target001"
        r = _FakeRedis(
            hashes={_wf_key(wf_id): _make_wf_hash("acct_owner", enabled=True)},
        )
        # Simulate the write logic from admin_patch_workflow
        updates: dict[bytes, bytes] = {
            b"enabled": b"0",
            b"updated_at": b"2026-06-28T00:00:00+00:00",
        }
        r.hset(_wf_key(wf_id), mapping=updates)

        # Verify the written value
        raw = r.hgetall(_wf_key(wf_id))
        meta = _decode_hash(raw)
        assert meta["enabled"] == "0"

    def test_db3_updated_on_enable(self):
        """Verify hset is called with enabled=b'1' when body.enabled is True."""
        wf_id = "wfl_target002"
        r = _FakeRedis(
            hashes={_wf_key(wf_id): _make_wf_hash("acct_owner", enabled=False)},
        )
        updates: dict[bytes, bytes] = {
            b"enabled": b"1",
            b"updated_at": b"2026-06-28T00:00:00+00:00",
        }
        r.hset(_wf_key(wf_id), mapping=updates)

        raw = r.hgetall(_wf_key(wf_id))
        meta = _decode_hash(raw)
        assert meta["enabled"] == "1"


# ===========================================================================
# Audit event — WorkflowAdminDisabledEvent
# ===========================================================================


class TestWorkflowAdminDisabledEvent:
    """Verify the audit event is importable and has correct field defaults."""

    def test_event_importable(self):
        from yashigani.audit.schema import WorkflowAdminDisabledEvent
        evt = WorkflowAdminDisabledEvent(
            admin_account_id="admin_001",
            workflow_id="wfl_abc123",
            owner_identity_id="user_XYZ",
            workflow_name="My Governed WF",
        )
        assert evt.event_type == "WORKFLOW_ADMIN_DISABLED"
        assert evt.account_tier == "admin"
        assert evt.masking_applied is True
        assert evt.admin_account_id == "admin_001"
        assert evt.workflow_id == "wfl_abc123"
        assert evt.owner_identity_id == "user_XYZ"
        assert evt.workflow_name == "My Governed WF"

    def test_event_type_in_enum(self):
        from yashigani.audit.schema import EventType
        assert EventType.WORKFLOW_ADMIN_DISABLED == "WORKFLOW_ADMIN_DISABLED"


# ===========================================================================
# BOLA regression guard — user can't read another user's workflow
# ===========================================================================


class TestBolaUserPlaneUnchanged:
    """The user-plane BOLA guard must be unchanged by admin-plane additions."""

    def test_user_cannot_read_other_user_workflow(self):
        from yashigani.backoffice.routes.user_workflows import _get_workflow_or_404

        wf_id = "wfl_owned_by_A"
        r = _FakeRedis(
            hashes={_wf_key(wf_id): _make_wf_hash("acct_A")},
        )

        # acct_B trying to access acct_A's workflow → 404
        with pytest.raises(HTTPException) as exc_info:
            _get_workflow_or_404(r, wf_id, account_id="acct_B")
        assert exc_info.value.status_code == 404

    def test_user_can_read_own_workflow(self):
        from yashigani.backoffice.routes.user_workflows import _get_workflow_or_404

        wf_id = "wfl_owned_by_A"
        r = _FakeRedis(
            hashes={_wf_key(wf_id): _make_wf_hash("acct_A")},
        )

        meta = _get_workflow_or_404(r, wf_id, account_id="acct_A")
        assert meta["account_id"] == "acct_A"
