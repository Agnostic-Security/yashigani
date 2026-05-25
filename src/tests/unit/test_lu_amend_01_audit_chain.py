"""
Unit tests for LU-AMEND-01 — tamper-evident audit log hash chain.

Tests cover:
  - Hash primitive consistency with writer.py F-12 scheme
  - Day-anchor computation
  - Canonical JSON (hash excludes prev_hash / prev_event_hash)
  - compute_event_hash determinism
  - compute_hashes_for_event: day transition, first event, subsequent events
  - verify_event: valid and tampered events
  - verify_chain_segment: intact chain, single break, multi-break
  - Merkle root: empty, single event, even/odd counts
  - AuditChainService barrel import from yashigani.audit

Integration tests (requiring Postgres) are skipped and live in
tests/integration/test_lu_amend_01_chain_checkpoint.py (not written here —
those require a live pool and the 0011 migration applied).

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import date, datetime, timezone
from typing import Optional

import pytest

from yashigani.audit.chain import (
    AuditChainService,
    _canonical_json,
    _merkle_root,
    _sha384_hex,
    compute_event_hash,
    compute_prev_hash,
    day_anchor,
)


# ---------------------------------------------------------------------------
# Hash primitives
# ---------------------------------------------------------------------------

class TestHashPrimitives:
    def test_sha384_hex_is_correct_length(self):
        result = _sha384_hex("test")
        assert len(result) == 96  # 384 bits / 4 bits per hex char

    def test_sha384_hex_known_vector(self):
        # SHA-384 of "YYYY-MM-DD" for a known date — stable across runs
        result = _sha384_hex("2026-05-24")
        expected = hashlib.sha384("2026-05-24".encode("utf-8")).hexdigest()
        assert result == expected

    def test_sha384_hex_different_inputs_differ(self):
        assert _sha384_hex("aaa") != _sha384_hex("bbb")


class TestDayAnchor:
    def test_day_anchor_is_sha384_of_date_string(self):
        date_str = "2026-05-24"
        expected = hashlib.sha384(date_str.encode("utf-8")).hexdigest()
        assert day_anchor(date_str) == expected

    def test_day_anchor_changes_by_date(self):
        assert day_anchor("2026-05-24") != day_anchor("2026-05-25")

    def test_day_anchor_length(self):
        assert len(day_anchor("2026-01-01")) == 96


class TestCanonicalJson:
    def test_excludes_prev_hash(self):
        event = {"event_type": "ADMIN_LOGIN", "prev_hash": "abc123", "foo": "bar"}
        canonical = _canonical_json(event)
        data = json.loads(canonical)
        assert "prev_hash" not in data
        assert "event_type" in data

    def test_excludes_prev_event_hash(self):
        event = {"event_type": "ADMIN_LOGIN", "prev_event_hash": "def456", "foo": "bar"}
        canonical = _canonical_json(event)
        data = json.loads(canonical)
        assert "prev_event_hash" not in data

    def test_excludes_both_hash_fields(self):
        event = {
            "event_type": "ADMIN_LOGIN",
            "prev_hash": "abc",
            "prev_event_hash": "def",
            "foo": "bar",
        }
        canonical = _canonical_json(event)
        data = json.loads(canonical)
        assert "prev_hash" not in data
        assert "prev_event_hash" not in data
        assert data["foo"] == "bar"

    def test_sort_keys(self):
        event1 = {"b": 2, "a": 1}
        event2 = {"a": 1, "b": 2}
        assert _canonical_json(event1) == _canonical_json(event2)

    def test_compact_separators(self):
        canonical = _canonical_json({"a": 1})
        assert " " not in canonical


class TestComputeEventHash:
    def test_deterministic_for_same_event(self):
        event = {"event_type": "GATEWAY_REQUEST", "action": "FORWARDED", "ts": "2026-05-24T12:00:00Z"}
        assert compute_event_hash(event) == compute_event_hash(event)

    def test_different_for_different_events(self):
        event1 = {"event_type": "GATEWAY_REQUEST", "action": "FORWARDED"}
        event2 = {"event_type": "GATEWAY_REQUEST", "action": "DENIED"}
        assert compute_event_hash(event1) != compute_event_hash(event2)

    def test_ignores_prev_hash_in_computation(self):
        """event_hash must be the same whether or not prev_hash is set."""
        event = {"event_type": "ADMIN_LOGIN", "outcome": "success"}
        event_with_prev = dict(event)
        event_with_prev["prev_hash"] = "some-previous-hash"
        assert compute_event_hash(event) == compute_event_hash(event_with_prev)

    def test_hash_length(self):
        assert len(compute_event_hash({"x": 1})) == 96


class TestComputePrevHash:
    def test_none_returns_day_anchor(self):
        date_str = "2026-05-24"
        result = compute_prev_hash(None, date_str)
        assert result == day_anchor(date_str)

    def test_preceding_event_returns_hash_of_canonical_json(self):
        preceding = {"event_type": "ADMIN_LOGIN", "outcome": "success"}
        result = compute_prev_hash(preceding, "2026-05-24")
        expected = _sha384_hex(_canonical_json(preceding))
        assert result == expected

    def test_preceding_event_excludes_prev_hash_field(self):
        """The prev_hash field in the preceding event must not affect the result."""
        preceding_no_prev = {"event_type": "ADMIN_LOGIN", "outcome": "success"}
        preceding_with_prev = dict(preceding_no_prev)
        preceding_with_prev["prev_hash"] = "old-chain-link"
        # Both should produce the same prev_hash for the next event
        assert (
            compute_prev_hash(preceding_no_prev, "2026-05-24")
            == compute_prev_hash(preceding_with_prev, "2026-05-24")
        )


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

class TestMerkleRoot:
    def test_empty_list_returns_hash_of_empty_string(self):
        root = _merkle_root([])
        assert root == _sha384_hex("")

    def test_single_element(self):
        h = _sha384_hex("event-1")
        root = _merkle_root([h])
        assert root == h

    def test_two_elements(self):
        h1 = _sha384_hex("event-1")
        h2 = _sha384_hex("event-2")
        root = _merkle_root([h1, h2])
        expected = _sha384_hex(h1 + h2)
        assert root == expected

    def test_three_elements_last_duplicated(self):
        """With 3 leaves, the last is duplicated to make an even count at level 1."""
        h1, h2, h3 = (_sha384_hex(f"event-{i}") for i in range(3))
        root = _merkle_root([h1, h2, h3])
        # Level 1: [hash(h1+h2), hash(h3+h3)] → level 0: hash(those two)
        level1_0 = _sha384_hex(h1 + h2)
        level1_1 = _sha384_hex(h3 + h3)
        expected = _sha384_hex(level1_0 + level1_1)
        assert root == expected

    def test_order_matters(self):
        """Merkle root must change if the order of hashes changes."""
        h1 = _sha384_hex("event-1")
        h2 = _sha384_hex("event-2")
        assert _merkle_root([h1, h2]) != _merkle_root([h2, h1])

    def test_deterministic_for_same_input(self):
        hashes = [_sha384_hex(f"event-{i}") for i in range(10)]
        assert _merkle_root(hashes) == _merkle_root(hashes)

    def test_four_elements(self):
        """Four leaves: exactly two levels, no duplication."""
        hs = [_sha384_hex(f"event-{i}") for i in range(4)]
        root = _merkle_root(hs)
        l1_0 = _sha384_hex(hs[0] + hs[1])
        l1_1 = _sha384_hex(hs[2] + hs[3])
        expected = _sha384_hex(l1_0 + l1_1)
        assert root == expected


# ---------------------------------------------------------------------------
# AuditChainService — compute_hashes_for_event
# ---------------------------------------------------------------------------

class TestAuditChainServiceComputeHashes:
    def test_first_event_prev_hash_is_day_anchor(self):
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "ts": "2026-05-24T00:00:01Z"}
        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        prev, ev_hash = svc.compute_hashes_for_event(event)
        assert prev == day_anchor(today)

    def test_event_hash_matches_compute_event_hash(self):
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "ts": "2026-05-24T00:00:01Z"}
        _, ev_hash = svc.compute_hashes_for_event(event)
        assert ev_hash == compute_event_hash(event)

    def test_second_event_prev_hash_is_first_event_hash(self):
        svc = AuditChainService()
        event1 = {"event_type": "ADMIN_LOGIN", "ts": "2026-05-24T00:00:01Z"}
        event2 = {"event_type": "GATEWAY_REQUEST", "ts": "2026-05-24T00:00:02Z"}

        _, ev1_hash = svc.compute_hashes_for_event(event1)
        prev2, _ = svc.compute_hashes_for_event(event2)

        assert prev2 == ev1_hash

    def test_chain_of_three_events(self):
        svc = AuditChainService()
        events = [
            {"event_type": f"EV_{i}", "seq": i}
            for i in range(3)
        ]
        hashes: list[tuple[str, str]] = []
        for ev in events:
            hashes.append(svc.compute_hashes_for_event(ev))

        # Event 1's prev == event 0's ev_hash
        assert hashes[1][0] == hashes[0][1]
        # Event 2's prev == event 1's ev_hash
        assert hashes[2][0] == hashes[1][1]

    def test_independent_services_same_first_event_same_hash(self):
        """Two independent AuditChainService instances on the same day
        should produce the same prev_hash for their first event (day anchor)."""
        svc1 = AuditChainService()
        svc2 = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "ts": "2026-05-24T00:00:01Z"}
        prev1, _ = svc1.compute_hashes_for_event(event)
        prev2, _ = svc2.compute_hashes_for_event(event)
        assert prev1 == prev2


# ---------------------------------------------------------------------------
# AuditChainService — verify_event
# ---------------------------------------------------------------------------

class TestAuditChainServiceVerifyEvent:
    def test_verify_event_valid(self):
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "outcome": "success", "ts": "2026-05-24T00:00:01Z"}
        _, ev_hash = svc.compute_hashes_for_event(event)
        assert svc.verify_event(event, ev_hash) is True

    def test_verify_event_tampered_field(self):
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "outcome": "success"}
        _, ev_hash = svc.compute_hashes_for_event(event)

        tampered = dict(event)
        tampered["outcome"] = "failure"  # tampered after hashing
        assert svc.verify_event(tampered, ev_hash) is False

    def test_verify_event_with_prev_hash_field_ignored(self):
        """prev_hash in the event dict must not affect verify_event result."""
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN", "outcome": "success"}
        _, ev_hash = svc.compute_hashes_for_event(event)

        event_with_prev = dict(event)
        event_with_prev["prev_hash"] = "some-chain-link"
        # Should still verify correctly — prev_hash is excluded from canonical form
        assert svc.verify_event(event_with_prev, ev_hash) is True

    def test_verify_event_wrong_hash(self):
        svc = AuditChainService()
        event = {"event_type": "ADMIN_LOGIN"}
        assert svc.verify_event(event, "not-the-right-hash") is False


# ---------------------------------------------------------------------------
# AuditChainService — verify_chain_segment
# ---------------------------------------------------------------------------

class TestAuditChainServiceVerifyChainSegment:
    @staticmethod
    def _today() -> str:
        """Return today's UTC date as YYYY-MM-DD — matches compute_hashes_for_event's clock."""
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    def _build_chain(self, n: int) -> tuple[list[dict], str]:
        """Build a valid chain of n events anchored to today's UTC date.

        Returns (events, date_str) so callers can pass the same date_str to
        verify_chain_segment.  Previously the date was hardcoded to a past day
        ("2026-05-24"), but compute_hashes_for_event always anchors to *today*
        internally (it reads the live clock), causing a mismatch once that date
        passed.  Fix: build and verify against today's date.
        """
        date_str = self._today()
        svc = AuditChainService()
        events = []
        for i in range(n):
            ev = {"event_type": f"EV_{i}", "seq": i, "day": date_str}
            prev, ev_hash = svc.compute_hashes_for_event(ev)
            ev["prev_hash"] = prev
            ev["event_hash"] = ev_hash
            events.append(ev)
        return events, date_str

    def test_intact_chain_no_breaks(self):
        events, date_str = self._build_chain(5)
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, date_str)
        assert ok is True
        assert breaks == []

    def test_empty_chain_ok(self):
        date_str = self._today()
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment([], date_str)
        assert ok is True
        assert breaks == []

    def test_single_event_intact(self):
        events, date_str = self._build_chain(1)
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, date_str)
        assert ok is True

    def test_tampered_first_event_prev_hash(self):
        events, date_str = self._build_chain(3)
        # Tamper the first event's prev_hash
        events[0]["prev_hash"] = "wrong-anchor"
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, date_str)
        assert ok is False
        assert 0 in breaks

    def test_tampered_second_event_prev_hash(self):
        events, date_str = self._build_chain(4)
        events[2]["prev_hash"] = "corrupted"
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, date_str)
        assert ok is False
        assert 2 in breaks

    def test_multiple_breaks_detected(self):
        events, date_str = self._build_chain(5)
        events[1]["prev_hash"] = "bad"
        events[3]["prev_hash"] = "also-bad"
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, date_str)
        assert ok is False
        assert 1 in breaks
        assert 3 in breaks


# ---------------------------------------------------------------------------
# Barrel export verification (Verification check 1 + 2)
# ---------------------------------------------------------------------------

class TestBarrelExport:
    def test_audit_chain_service_importable_from_package(self):
        from yashigani.audit import AuditChainService as _S
        assert _S is AuditChainService

    def test_compute_event_hash_importable_from_package(self):
        from yashigani.audit import compute_event_hash as _f
        assert _f is compute_event_hash

    def test_day_anchor_importable_from_package(self):
        from yashigani.audit import day_anchor as _f
        assert _f is day_anchor

    def test_compute_prev_hash_importable_from_package(self):
        from yashigani.audit import compute_prev_hash as _f
        assert _f is compute_prev_hash


# ---------------------------------------------------------------------------
# Hash scheme consistency with writer.py F-12
# ---------------------------------------------------------------------------

class TestConsistencyWithWriterF12:
    """Verify that chain.py hash scheme matches writer.py F-12 exactly.

    The writer.py uses:
      _sha384_hex(_canonical_json(event_dict))  for event hashes
      _day_anchor(today)                         for day anchors

    where _canonical_json excludes 'prev_event_hash' (not 'prev_hash').
    Our chain.py excludes BOTH 'prev_hash' AND 'prev_event_hash' to be
    compatible with both the DB column name (prev_hash) and the writer's
    in-memory field name (prev_event_hash).
    """

    def test_chain_hash_matches_writer_f12_for_event_without_prev_hash(self):
        """When an event has no prev_hash or prev_event_hash, the canonical JSON
        must be identical to what writer.py would produce."""
        event = {"event_type": "ADMIN_LOGIN", "outcome": "success", "ts": "2026"}
        # Simulate writer.py F-12
        d = {k: v for k, v in event.items() if k != "prev_event_hash"}
        writer_canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)
        writer_hash = hashlib.sha384(writer_canonical.encode("utf-8")).hexdigest()
        # Our chain.py
        chain_hash = compute_event_hash(event)
        assert chain_hash == writer_hash

    def test_chain_day_anchor_matches_writer_f12(self):
        """Day anchor in chain.py must be identical to _day_anchor in writer.py."""
        from yashigani.audit.writer import _day_anchor as writer_day_anchor
        for date_str in ("2026-05-24", "2026-01-01", "2025-12-31"):
            assert day_anchor(date_str) == writer_day_anchor(date_str)
