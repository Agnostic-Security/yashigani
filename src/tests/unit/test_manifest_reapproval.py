"""5.0 rug-pull — manifest re-approval gate (register §4 #2)."""
from __future__ import annotations

import json

import pytest

from yashigani.mcp.manifest_reapproval import (
    ManifestReapprovalError,
    ManifestReapprovalGate,
    ManifestStoreUnavailableError,
)


class _FakeRedis:
    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return False
        self.kv[k] = v
        return True

    def delete(self, k):
        self.kv.pop(k, None)


class _BoomRedis:
    def get(self, k):
        raise ConnectionError("down")

    def set(self, *a, **k):
        raise ConnectionError("down")


class _CapAudit:
    def __init__(self, fail=False):
        self.events = []
        self.fail = fail

    def write(self, e):
        if self.fail:
            raise RuntimeError("audit down")
        self.events.append(e)


def _gate(audit=None):
    return ManifestReapprovalGate(_FakeRedis(), audit_writer=audit)


class TestNoteRegistration:
    def test_first_registration_is_tofu_active(self):
        g = _gate()
        r = g.note_registration("agentA", "SHA1", registered_by="alice")
        assert r.status == "first_registration" and r.active is True
        assert g.is_active("agentA", "SHA1") is True

    def test_unchanged_stays_active(self):
        g = _gate()
        g.note_registration("agentA", "SHA1", registered_by="alice")
        r = g.note_registration("agentA", "SHA1", registered_by="alice")
        assert r.status == "unchanged" and r.active is True

    def test_delta_is_pending_and_not_active(self):
        audit = _CapAudit()
        g = ManifestReapprovalGate(_FakeRedis(), audit_writer=audit)
        g.note_registration("agentA", "SHA1", registered_by="alice")
        r = g.note_registration("agentA", "SHA2_EVIL", registered_by="mallory")
        assert r.status == "pending_reapproval" and r.active is False
        # The rug-pulled sha is NOT active; the original still is
        assert g.is_active("agentA", "SHA2_EVIL") is False
        assert g.is_active("agentA", "SHA1") is True
        assert any(e.event_type.value == "MANIFEST_DELTA_PENDING" for e in audit.events)

    def test_store_error_raises(self):
        g = ManifestReapprovalGate(_BoomRedis())
        with pytest.raises(ManifestStoreUnavailableError):
            g.note_registration("agentA", "SHA1", registered_by="alice")


class TestApproval:
    def setup_method(self):
        self.audit = _CapAudit()
        self.g = ManifestReapprovalGate(_FakeRedis(), audit_writer=self.audit)
        self.g.note_registration("agentA", "SHA1", registered_by="alice")
        self.g.note_registration("agentA", "SHA2", registered_by="alice")  # delta pending

    def test_full_approval_activates(self):
        self.g.approve("agentA", approver_id="bob", confirming_sha="SHA2")
        assert self.g.is_active("agentA", "SHA2") is True
        assert self.g.is_active("agentA", "SHA1") is False
        assert any(e.event_type.value == "MANIFEST_DELTA_APPROVED" for e in self.audit.events)

    def test_self_approval_rejected(self):
        with pytest.raises(ManifestReapprovalError, match="DIFFERENT admin"):
            self.g.approve("agentA", approver_id="alice", confirming_sha="SHA2")

    def test_confirming_sha_must_match(self):
        with pytest.raises(ManifestReapprovalError, match="does not match"):
            self.g.approve("agentA", approver_id="bob", confirming_sha="SHA_WRONG")
        assert any(e.event_type.value == "MANIFEST_DELTA_REJECTED" for e in self.audit.events)
        # Still not active
        assert self.g.is_active("agentA", "SHA2") is False

    def test_no_pending_raises(self):
        g = _gate()
        g.note_registration("agentB", "S1", registered_by="alice")
        with pytest.raises(ManifestReapprovalError, match="No pending"):
            g.approve("agentB", approver_id="bob", confirming_sha="S1")

    def test_second_delta_while_pending_is_immutable(self):
        # A second delta must not overwrite the pending record (nx guard)
        self.g.note_registration("agentA", "SHA3_ALSO_EVIL", registered_by="mallory")
        raw = self.g._r.get("yashigani:manifest:pending:agentA")
        rec = json.loads(raw)
        assert rec["new_sha"] == "SHA2"  # original pending unchanged


class TestIsActiveFailClosed:
    def test_store_error_is_not_active(self):
        g = ManifestReapprovalGate(_BoomRedis())
        assert g.is_active("agentA", "anything") is False

    def test_write_ahead_audit_failure_blocks_approval(self):
        g = ManifestReapprovalGate(_FakeRedis(), audit_writer=_CapAudit(fail=True))
        g._r.set("yashigani:manifest:active:agentA", "SHA1")
        # A delta note that must audit-then-store: audit fails → raises, no activation
        with pytest.raises(RuntimeError, match="audit down"):
            g.note_registration("agentA", "SHA2", registered_by="alice")
        # active sha unchanged (never activated the delta)
        assert g.is_active("agentA", "SHA1") is True
