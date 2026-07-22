"""
5.0 A5 — model-integrity pinning + dual-control.

Covers the design's regression attack list: weights/manifest mismatch → block,
fail-closed store, dual-control (B≠A, confirming-digest byte-compare / SOD-1),
immutable pending (second propose rejected), write-ahead audit (SOD-2),
bootstrap TOFU, single-admin deadlock (no fall-open).
"""
from __future__ import annotations

import hashlib
import json

import pytest

from yashigani.inspection.model_integrity import (
    compute_blob_sha256,
    DualControlError,
    ModelIntegrityVerifier,
    ModelPinDualControl,
    ModelPinStore,
    Pin,
    PinStoreUnavailableError,
    VerifyResult,
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

    def scan_iter(self, match):
        prefix = match.rstrip("*")
        return (k for k in list(self.kv) if k.startswith(prefix))


class _BoomRedis:
    def get(self, k):
        raise ConnectionError("redis down")

    def set(self, *a, **k):
        raise ConnectionError("redis down")

    def scan_iter(self, match):
        raise ConnectionError("redis down")


class _CapAudit:
    def __init__(self, fail=False):
        self.events = []
        self.fail = fail

    def write(self, event):
        if self.fail:
            raise RuntimeError("audit sink down")
        self.events.append(event)


def _store():
    return ModelPinStore(_FakeRedis())


# ── blob hash ───────────────────────────────────────────────────────────────

def test_compute_blob_sha256(tmp_path):
    p = tmp_path / "blob"
    p.write_bytes(b"the model weights")
    assert compute_blob_sha256(str(p)) == hashlib.sha256(b"the model weights").hexdigest()


# ── verifier ──────────────────────────────────────────────────────────────

class TestVerifier:
    def setup_method(self):
        self.redis = _FakeRedis()
        self.store = ModelPinStore(self.redis)
        self.audit = _CapAudit()
        self.v = ModelIntegrityVerifier(self.store, audit_writer=self.audit)
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="W_GOOD", manifest_digest="M_GOOD"))

    def test_match_ok(self):
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_GOOD",
                          observed_weights_sha256="W_GOOD")
        assert r.ok and r.reason == "match"
        assert self.audit.events == []

    def test_weights_mismatch_blocks_and_audits(self):
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_GOOD",
                          observed_weights_sha256="W_EVIL")
        assert r.ok is False and r.reason == "weights_mismatch"
        assert len(self.audit.events) == 1

    def test_manifest_mismatch_blocks(self):
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_EVIL")
        assert r.ok is False and r.reason == "manifest_mismatch"

    def test_no_pin_passes(self):
        r = self.v.verify("unpinned:model", observed_manifest_digest="anything")
        assert r.ok is True and r.reason == "no_pin"

    def test_store_unavailable_fails_closed(self):
        v = ModelIntegrityVerifier(ModelPinStore(_BoomRedis()))
        r = v.verify("qwen2.5:3b", observed_manifest_digest="M_GOOD")
        assert r.ok is False and r.reason == "store_unavailable"


# ── dual-control ──────────────────────────────────────────────────────────

class TestDualControl:
    def setup_method(self):
        self.redis = _FakeRedis()
        self.store = ModelPinStore(self.redis)
        self.audit = _CapAudit()
        self.dc = ModelPinDualControl(self.store, self.redis, audit_writer=self.audit)

    def test_bootstrap_writes_pin_and_audits(self):
        self.dc.bootstrap("m", "W1", "M1", actor_id="installer")
        assert self.store.get("m") == Pin("m", "W1", "M1")
        assert any(e.event_type.value == "MODEL_PIN_BOOTSTRAPPED" for e in self.audit.events)

    def test_full_propose_approve_flow(self):
        self.dc.propose("m", "W2", "M2", justification="ticket-42", initiator_id="alice")
        pin = self.dc.approve("m", approver_id="bob",
                              confirming_weights_sha256="W2", confirming_manifest_digest="M2")
        assert pin == Pin("m", "W2", "M2")
        assert self.store.get("m") == Pin("m", "W2", "M2")
        kinds = [e.event_type.value for e in self.audit.events]
        assert "MODEL_PIN_PROPOSED" in kinds and "MODEL_PIN_APPROVED" in kinds

    def test_justification_required(self):
        with pytest.raises(DualControlError):
            self.dc.propose("m", "W2", "M2", justification="", initiator_id="alice")

    def test_self_approval_rejected(self):
        self.dc.propose("m", "W2", "M2", justification="ticket-1", initiator_id="alice")
        with pytest.raises(DualControlError, match="DIFFERENT admin"):
            self.dc.approve("m", approver_id="alice",
                            confirming_weights_sha256="W2", confirming_manifest_digest="M2")

    def test_sod1_confirming_digest_must_match(self):
        # Approver reviewed W2 but the pending record says W2 — supplying W_EVIL
        # (as if a second propose swapped it) must be rejected + audited.
        self.dc.propose("m", "W2", "M2", justification="ticket-1", initiator_id="alice")
        with pytest.raises(DualControlError, match="weights digest"):
            self.dc.approve("m", approver_id="bob",
                            confirming_weights_sha256="W_EVIL", confirming_manifest_digest="M2")
        assert any(e.event_type.value == "MODEL_PIN_REJECTED" for e in self.audit.events)
        # The pin was NOT changed
        assert self.store.get("m") is None

    def test_immutable_pending_second_propose_rejected(self):
        self.dc.propose("m", "W2", "M2", justification="ticket-1", initiator_id="alice")
        with pytest.raises(DualControlError, match="already pending"):
            self.dc.propose("m", "W_EVIL", "M_EVIL", justification="ticket-2", initiator_id="mallory")

    def test_sod2_write_ahead_audit_fails_closed(self):
        # If the audit write fails, the pin mutation must NOT proceed.
        dc = ModelPinDualControl(self.store, self.redis, audit_writer=_CapAudit(fail=True))
        with pytest.raises(RuntimeError, match="audit sink down"):
            dc.bootstrap("m", "W1", "M1", actor_id="installer")
        assert self.store.get("m") is None

    def test_single_admin_deadlocks_no_fall_open(self):
        # Existing pin stays; a single admin cannot both propose and approve.
        self.dc.bootstrap("m", "W1", "M1", actor_id="installer")
        self.dc.propose("m", "W2", "M2", justification="ticket-1", initiator_id="alice")
        with pytest.raises(DualControlError):
            self.dc.approve("m", approver_id="alice",
                            confirming_weights_sha256="W2", confirming_manifest_digest="M2")
        # Old pin is still enforced (never fell open to the proposed value)
        assert self.store.get("m") == Pin("m", "W1", "M1")
