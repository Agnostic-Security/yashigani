"""#25 — unit tests for the dual-admin cloud-LLM override manager."""
import json

import pytest

from yashigani.optimization.cloud_override import (
    CloudLlmOverrideManager,
    JustificationRequiredError,
    TTLRangeError,
    ApprovalError,
)


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


def _mgr():
    return CloudLlmOverrideManager(_FakeRedis(), audit_writer=None)


def test_propose_requires_justification():
    m = _mgr()
    with pytest.raises(JustificationRequiredError):
        m.propose("admin1", "openai", "gpt-4o", justification="", ttl_hours=4)
    with pytest.raises(JustificationRequiredError):
        m.propose("admin1", "openai", "gpt-4o", justification="x", ttl_hours=4)  # too short


def test_propose_validates_ttl_and_target():
    m = _mgr()
    with pytest.raises(TTLRangeError):
        m.propose("admin1", "openai", "gpt-4o", justification="TICKET-123", ttl_hours=999)
    with pytest.raises(Exception):
        m.propose("admin1", "", "gpt-4o", justification="TICKET-123", ttl_hours=4)


def test_pending_is_not_active_until_second_admin_approves():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    # PENDING -> not active yet (dual-control)
    assert m.get_active() is None
    assert m.status()["status"] == "PENDING_APPROVAL"


def test_self_approval_rejected():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    with pytest.raises(ApprovalError):
        m.approve("admin1")  # same admin cannot self-approve
    assert m.get_active() is None


def test_dual_admin_approval_activates_with_full_record():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="CEO email 2026-06-07", ttl_hours=6)
    m.approve("admin2")
    active = m.get_active()
    assert active is not None
    assert active["provider"] == "openai" and active["model"] == "gpt-4o"
    assert active["initiated_by"] == "admin1" and active["approver"] == "admin2"
    assert active["justification"] == "CEO email 2026-06-07"


def test_approve_without_pending_fails():
    m = _mgr()
    with pytest.raises(ApprovalError):
        m.approve("admin2")


def test_revoke_clears_active():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    m.approve("admin2")
    assert m.get_active() is not None
    m.revoke("admin1")
    assert m.get_active() is None
    assert m.status()["status"] == "INACTIVE"
