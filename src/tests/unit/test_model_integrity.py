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


class TestVacuousPin:
    """LAURA-V50-004: a pin that compares NOTHING on either axis must never
    report reason="match" — reproduces the live qwen2.5:3b pin state
    (manifest_digest empty, weights anchor unprobeable on this host topology
    ⇒ observed_weights_sha256 always empty) and proves it against the fixed
    verify()."""

    def setup_method(self):
        self.redis = _FakeRedis()
        self.store = ModelPinStore(self.redis)
        self.audit = _CapAudit()
        self.v = ModelIntegrityVerifier(self.store, audit_writer=self.audit)

    def test_all_empty_pin_and_observed_is_never_match_non_strict(self):
        # The live-observed shape: pin has BOTH digests empty (the exact
        # LAURA-V50-004 repro), observed side also empty (weights unprobeable
        # on Mac host-native-ollama; manifest probe hasn't populated either).
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="", manifest_digest=""))
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="",
                          observed_weights_sha256="", strict=False)
        assert r.reason == "pin_unverifiable"
        assert r.reason != "match"
        # Non-strict: does not block (avoids an outage on an unprobeable
        # platform) but is loud — a WARNING + audit event, never silent.
        assert r.ok is True
        assert len(self.audit.events) == 1
        assert self.audit.events[0].event_type.value == "MODEL_PIN_UNVERIFIABLE"
        assert self.audit.events[0].action_taken == "warn"

    def test_pin_with_empty_digest_and_unprobeable_weights_is_never_match(self):
        # Reproduces the EXACT live finding: manifest_digest="" (never set),
        # weights_sha256 populated in the pin but the OBSERVED weights side is
        # always "" on this platform — nothing to compare on either axis.
        self.store.put(Pin(
            model="qwen2.5:3b",
            weights_sha256="a81cf13cef1cfba5fa2e79ea917f9f7e8faab72945bf902e93440be03e775b3e",
            manifest_digest="",
        ))
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="",
                          observed_weights_sha256="", strict=False)
        assert r.reason == "pin_unverifiable"
        assert r.ok is True  # non-strict: warn, don't block

    def test_all_empty_pin_blocks_under_strict(self):
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="", manifest_digest=""))
        r = self.v.verify("qwen2.5:3b", strict=True)
        assert r.reason == "pin_unverifiable"
        assert r.ok is False
        assert self.audit.events[0].action_taken == "block"

    def test_real_manifest_digest_still_matches_when_observed_agrees(self):
        # Regression: a REAL populated pin (the fix's other half — bootstrap
        # now auto-populates manifest_digest) must still report "match" when
        # the observed digest agrees — the vacuous-pin fix must not break the
        # sound path.
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="", manifest_digest="M_REAL"))
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_REAL", strict=True)
        assert r.ok is True and r.reason == "match"
        assert self.audit.events == []

    def test_real_manifest_digest_mismatches_when_observed_differs(self):
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="", manifest_digest="M_REAL"))
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_EVIL", strict=True)
        assert r.ok is False and r.reason == "manifest_mismatch"

    def test_one_axis_comparable_other_empty_is_match_not_vacuous(self):
        # Manifest axis IS comparable (both sides populated and equal); the
        # weights axis simply has nothing to compare. This is a legitimate
        # partial-coverage match, not the vacuous case — must not be flagged
        # pin_unverifiable.
        self.store.put(Pin(model="qwen2.5:3b", weights_sha256="", manifest_digest="M_REAL"))
        r = self.v.verify("qwen2.5:3b", observed_manifest_digest="M_REAL",
                          observed_weights_sha256="", strict=True)
        assert r.ok is True and r.reason == "match"


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

    def test_bootstrap_rejects_all_empty_anchor_no_probe_wired(self):
        # LAURA-V50-004 rec #1: no probe callback wired, admin supplies
        # nothing on either axis → reject, don't let a vacuous pin ship.
        with pytest.raises(DualControlError, match="at least one non-empty anchor"):
            self.dc.bootstrap("m", "", "", actor_id="installer")
        assert self.store.get("m") is None

    def test_bootstrap_autofills_manifest_digest_from_probe(self):
        # LAURA-V50-004 rec #2: admin supplies neither digest, but a live
        # probe callback IS wired and returns a real manifest digest for this
        # model — bootstrap must use it rather than reject or accept empty.
        probed = {"qwen2.5:3b": "sha256:live-observed-digest"}
        dc = ModelPinDualControl(
            self.store, self.redis, audit_writer=self.audit,
            probe_manifest_digest_fn=lambda m: probed.get(m, ""),
        )
        pin = dc.bootstrap("qwen2.5:3b", "", "", actor_id="installer")
        assert pin.manifest_digest == "sha256:live-observed-digest"
        stored = self.store.get("qwen2.5:3b")
        assert stored.manifest_digest == "sha256:live-observed-digest"
        # The stored pin has a non-empty comparable anchor.
        assert stored.weights_sha256 or stored.manifest_digest

    def test_bootstrap_rejects_when_probe_also_returns_empty(self):
        # Probe is wired but has nothing for this model (e.g. not yet served)
        # — must still reject rather than accept a vacuous pin.
        dc = ModelPinDualControl(
            self.store, self.redis, audit_writer=self.audit,
            probe_manifest_digest_fn=lambda m: "",
        )
        with pytest.raises(DualControlError):
            dc.bootstrap("unserved:model", "", "", actor_id="installer")
        assert self.store.get("unserved:model") is None

    def test_bootstrap_probe_failure_does_not_crash_and_still_rejects(self):
        def _boom(model):
            raise ConnectionError("ollama unreachable")
        dc = ModelPinDualControl(
            self.store, self.redis, audit_writer=self.audit,
            probe_manifest_digest_fn=_boom,
        )
        with pytest.raises(DualControlError):
            dc.bootstrap("m", "", "", actor_id="installer")

    def test_bootstrap_explicit_weights_supplied_no_autofill_needed(self):
        # Admin supplies a real weights anchor; the probe callback should not
        # be needed/consulted to satisfy the non-vacuous requirement, but
        # having one wired must not interfere.
        dc = ModelPinDualControl(
            self.store, self.redis, audit_writer=self.audit,
            probe_manifest_digest_fn=lambda m: "should-not-be-used",
        )
        pin = dc.bootstrap("m", "W_REAL", "", actor_id="installer")
        assert pin.weights_sha256 == "W_REAL"
        # manifest_digest was empty and IS autofilled (best-effort always
        # attempted when the field is empty) — both anchors end up real.
        assert pin.manifest_digest == "should-not-be-used"

    def test_propose_autofills_manifest_digest_from_probe(self):
        probed = {"m": "sha256:live-propose-digest"}
        dc = ModelPinDualControl(
            self.store, self.redis, audit_writer=self.audit,
            probe_manifest_digest_fn=lambda mdl: probed.get(mdl, ""),
        )
        pid = dc.propose("m", "", "", justification="ticket-9", initiator_id="alice")
        assert pid
        raw = self.redis.get("yashigani:model:pin:pending:m")
        rec = json.loads(raw)
        assert rec["new_manifest_digest"] == "sha256:live-propose-digest"

    def test_single_admin_deadlocks_no_fall_open(self):
        # Existing pin stays; a single admin cannot both propose and approve.
        self.dc.bootstrap("m", "W1", "M1", actor_id="installer")
        self.dc.propose("m", "W2", "M2", justification="ticket-1", initiator_id="alice")
        with pytest.raises(DualControlError):
            self.dc.approve("m", approver_id="alice",
                            confirming_weights_sha256="W2", confirming_manifest_digest="M2")
        # Old pin is still enforced (never fell open to the proposed value)
        assert self.store.get("m") == Pin("m", "W1", "M1")
