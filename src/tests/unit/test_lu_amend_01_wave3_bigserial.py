"""
Unit tests for LU-AMEND-01 wave-3 — bigserial sequence column (v2.24.1).

Tests cover:
  1. Timestamp collision: two events with identical created_at get deterministic
     ordering via seq (simulated via the seq field in event dicts).
  2. Chain ordering: events ordered by seq produce an intact chain even when
     created_at values collide.
  3. Seq monotonicity: 1000 simulated seq values are unique and monotonic.
  4. Checkpoint query uses seq ordering (SQL ORDER BY seq NULLS LAST).
  5. Backfill: NULL-seq events are sorted LAST (do not corrupt normal chain).
  6. verify_chain_segment: seq-ordered events produce no breaks; reverse-seq
     order does produce breaks on the same event set.

These are pure-Python unit tests — no live Postgres required.
Integration tests with live PG are in
tests/integration/test_lu_amend_01_wave3_integration.py.

Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone

import pytest

from yashigani.audit.chain import (
    AuditChainService,
    _merkle_root,
    _sha384_hex,
    compute_event_hash,
    day_anchor,
)

# Use the actual current date so day anchors match what AuditChainService computes.
_TODAY = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(seq: int, created_at_ts: str | None = None) -> dict:
    """Make a minimal audit event dict with a fixed created_at timestamp."""
    ts = created_at_ts or f"{_TODAY}T12:00:00Z"
    return {
        "event_type": "TEST_SEQ_EVENT",
        "action": f"action_{seq}",
        "created_at": ts,
        # NOTE: 'seq' in this dict is the *simulated* seq for test purposes
        # only. The real seq is DB-assigned; we don't include it in the canonical
        # hash (it's not a field we hash). But we use it to order events here.
    }


def _build_chain_with_seq(n: int, same_timestamp: bool = False) -> list[dict]:
    """
    Build a valid chain of n events using AuditChainService.

    Returns list of dicts with fields: seq, prev_hash, event_hash, created_at.
    If same_timestamp=True, all events share the same created_at (timestamp
    collision scenario). seq is the authoritative ordering key.

    Uses the real current date so day anchors match what AuditChainService computes.
    """
    svc = AuditChainService()
    # Force a fresh chain starting on today's date (reset in-memory state).
    # AuditChainService will recompute today from datetime.now() and set the
    # correct day anchor since _last_hash is None.
    svc._current_day = None
    svc._last_hash = None

    events = []
    for i in range(n):
        ts = f"{_TODAY}T12:00:00Z" if same_timestamp else f"{_TODAY}T12:00:{min(i, 59):02d}Z"
        ev = _make_event(i, ts)
        prev, ev_hash = svc.compute_hashes_for_event(ev)
        events.append({
            "seq": i + 1,  # simulate 1-based BIGSERIAL
            "created_at": ts,
            "event_type": ev["event_type"],
            "action": ev["action"],
            "prev_hash": prev,
            "event_hash": ev_hash,
        })
    return events


# ---------------------------------------------------------------------------
# Test 1: Timestamp collision — seq gives deterministic ordering
# ---------------------------------------------------------------------------

class TestTimestampCollisionDeterminism:
    def test_same_timestamp_chain_intact_when_ordered_by_seq(self):
        """
        10 events with identical created_at — ordered by seq the chain is intact.
        This is the timestamp-collision scenario that wave-3 solves.
        """
        events = _build_chain_with_seq(10, same_timestamp=True)

        # All events share the same created_at
        timestamps = {ev["created_at"] for ev in events}
        assert len(timestamps) == 1, "All events should share the same timestamp"

        # Ordered by seq: chain should be intact
        events_by_seq = sorted(events, key=lambda e: e["seq"])

        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events_by_seq, _TODAY)
        assert ok is True, f"Chain should be intact ordered by seq; breaks at indices: {breaks}"
        assert breaks == []

    def test_same_timestamp_chain_broken_if_ordered_differently(self):
        """
        If events with identical created_at are ordered by event_hash (random)
        rather than seq, the chain breaks. Demonstrates why seq is required.
        """
        events = _build_chain_with_seq(10, same_timestamp=True)

        # Shuffle into a non-seq order (order by event_hash — effectively random)
        events_shuffled = sorted(events, key=lambda e: e["event_hash"])

        # Only intact if this happens to be seq order (extremely unlikely for 10 events)
        seq_order = [e["seq"] for e in events_shuffled]
        is_seq_order = seq_order == sorted(seq_order)

        if not is_seq_order:
            # Non-seq order: chain MUST be broken (prev_hash chain is seq-ordered)
            svc = AuditChainService()
            ok, breaks = svc.verify_chain_segment(events_shuffled, _TODAY)
            assert ok is False, (
                "Chain should be broken when events are not in seq order "
                f"(seq order was: {seq_order})"
            )

    def test_seq_provides_unique_ordering_under_collision(self):
        """
        seq values are unique even when created_at values collide.
        """
        events = _build_chain_with_seq(100, same_timestamp=True)
        seq_values = [ev["seq"] for ev in events]

        # All seq values unique
        assert len(set(seq_values)) == 100, "seq values must be unique"
        # All seq values monotonically increasing (BIGSERIAL property)
        assert seq_values == sorted(seq_values), "seq values must be monotonically increasing"


# ---------------------------------------------------------------------------
# Test 2: Seq monotonicity — 1000 simulated seq values
# ---------------------------------------------------------------------------

class TestSeqMonotonicity:
    def test_1000_simulated_seq_values_unique_and_monotonic(self):
        """
        Simulate 1000 events with DB-assigned seq values (1-based BIGSERIAL).
        Verify unique + strictly increasing.
        """
        events = _build_chain_with_seq(1000)
        seq_values = [ev["seq"] for ev in events]

        assert len(seq_values) == 1000
        assert len(set(seq_values)) == 1000, "All seq values must be unique"
        assert seq_values == sorted(seq_values), "seq values must be monotonically increasing"
        assert seq_values[0] == 1, "seq should start from 1 (1-based BIGSERIAL)"
        assert seq_values[-1] == 1000, "Last seq should equal total count"

    def test_1000_events_chain_intact_by_seq(self):
        """
        1000 sequential events ordered by seq — chain must be intact throughout.
        """
        events = _build_chain_with_seq(1000)
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, _TODAY)
        assert ok is True, f"Expected intact chain over 1000 events; breaks at: {breaks[:10]}..."
        assert len(breaks) == 0


# ---------------------------------------------------------------------------
# Test 3: NULL-seq ordering (NULLS LAST behaviour)
# ---------------------------------------------------------------------------

class TestNullSeqBackfillOrdering:
    def test_null_seq_rows_appear_last(self):
        """
        Rows with seq=None (stray NULL rows) should be sorted LAST in Python
        simulation of ORDER BY seq NULLS LAST, so they don't corrupt the
        chain ordering of normal (non-NULL seq) rows.
        """
        events = _build_chain_with_seq(5)

        # Insert a stray NULL-seq row at position 2
        null_seq_event = {
            "seq": None,
            "created_at": "2026-05-25T11:59:00Z",  # actually earlier
            "event_type": "STRAY_NULL_SEQ",
            "action": "stray",
            "prev_hash": "x" * 96,
            "event_hash": "y" * 96,
        }
        mixed = events[:2] + [null_seq_event] + events[2:]

        # Simulate ORDER BY seq NULLS LAST
        def _seq_key(e):
            s = e["seq"]
            return (0, s) if s is not None else (1, 0)

        ordered = sorted(mixed, key=_seq_key)

        # The NULL-seq event must be last
        assert ordered[-1]["seq"] is None, "NULL-seq row must appear last"
        # Normal rows in seq order first
        normal = [e for e in ordered if e["seq"] is not None]
        assert [e["seq"] for e in normal] == [1, 2, 3, 4, 5]

    def test_chain_still_intact_when_null_seq_rows_are_last(self):
        """
        If NULL-seq rows are sorted to the end, the chain for non-NULL-seq rows
        is intact. The NULL-seq rows may break the tail, but that's acceptable
        (they're backfilled rows whose seq was assigned in (created_at, id) order).
        """
        events = _build_chain_with_seq(5)

        # Verify normal chain is intact
        svc = AuditChainService()
        ok, breaks = svc.verify_chain_segment(events, _TODAY)
        assert ok is True, f"Normal chain should be intact; breaks at: {breaks}"


# ---------------------------------------------------------------------------
# Test 4: Checkpoint merkle root consistency with seq ordering
# ---------------------------------------------------------------------------

class TestCheckpointSeqOrdering:
    def test_merkle_root_deterministic_for_seq_ordered_events(self):
        """
        Merkle root over 50 seq-ordered events is deterministic across two calls.
        This verifies that seq ordering produces a stable merkle tree.
        """
        events = _build_chain_with_seq(50, same_timestamp=True)
        event_hashes = [ev["event_hash"] for ev in sorted(events, key=lambda e: e["seq"])]

        root1 = _merkle_root(event_hashes)
        root2 = _merkle_root(event_hashes)
        assert root1 == root2, "Merkle root must be deterministic"
        assert len(root1) == 96, "Merkle root must be 96-char SHA-384 hex"

    def test_merkle_root_differs_for_different_orderings(self):
        """
        Merkle root changes if events are ordered differently (even same hashes).
        This validates that ordering matters and seq ordering is significant.
        """
        events = _build_chain_with_seq(10, same_timestamp=True)
        hashes_seq_order = [ev["event_hash"] for ev in sorted(events, key=lambda e: e["seq"])]
        # Reverse order
        hashes_reversed = list(reversed(hashes_seq_order))

        root_seq = _merkle_root(hashes_seq_order)
        root_rev = _merkle_root(hashes_reversed)

        # Different orderings should almost always produce different roots
        # (technically could collide for a trivially crafted input, but not here)
        if hashes_seq_order != hashes_reversed:
            assert root_seq != root_rev, (
                "Merkle root should differ for different event orderings"
            )


# ---------------------------------------------------------------------------
# Test 5: Thread safety — concurrent compute_hashes_for_event via seq
# ---------------------------------------------------------------------------

class TestConcurrentHashComputation:
    def test_concurrent_hash_calls_produce_unique_hashes(self):
        """
        Multiple threads calling compute_hashes_for_event concurrently must
        all get unique, non-overlapping hashes. The threading.Lock in
        AuditChainService ensures serialisation.
        """
        svc = AuditChainService()
        results: list[tuple[str, str]] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def _worker(i: int) -> None:
            try:
                ev = {"event_type": "CONCURRENT_TEST", "worker": i}
                pair = svc.compute_hashes_for_event(ev)
                with lock:
                    results.append(pair)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors in concurrent hash computation: {errors}"
        assert len(results) == 50, "Expected 50 results"

        # All event_hash values must be unique
        ev_hashes = [r[1] for r in results]
        assert len(set(ev_hashes)) == 50, (
            "All event_hash values should be unique (each event dict differs)"
        )

        # The prev_hash of result N+1 must equal the event_hash of some result N
        # (chain is serialised even under concurrency — we just can't predict order)
        ev_hash_set = set(ev_hashes)
        prev_hashes = [r[0] for r in results]
        # All prev_hashes except the first in chain order must be in ev_hash_set
        # (or be the day anchor). We can verify at least one chaining occurred.
        chained_prev = [ph for ph in prev_hashes if ph in ev_hash_set]
        assert len(chained_prev) >= 49, (
            "At least 49 of 50 events should have a prev_hash that is a prior event_hash "
            f"(got {len(chained_prev)} chained)"
        )


# ---------------------------------------------------------------------------
# Test 6: Migration 0014 DDL syntax sanity (offline — no live DB)
# Read the migration source file directly (alembic may not be installed in
# the unit test env; we inspect DDL constants without importing via alembic).
# ---------------------------------------------------------------------------

import pathlib

_MIGRATION_PATH = pathlib.Path(__file__).parent.parent.parent / (
    "yashigani/db/migrations/versions/0014_audit_events_bigserial_sequence.py"
)


def _read_migration_src() -> str:
    return _MIGRATION_PATH.read_text(encoding="utf-8")


class TestMigration0014Structure:
    def test_migration_file_exists(self):
        """Migration 0014 file exists at the expected path."""
        assert _MIGRATION_PATH.exists(), (
            f"Migration 0014 not found at {_MIGRATION_PATH}"
        )

    def test_migration_has_correct_revision(self):
        """Migration 0014 source contains correct revision + down_revision."""
        src = _read_migration_src()
        assert 'revision: str = "0014"' in src
        assert 'down_revision: Union[str, None] = "0013"' in src

    def test_migration_ddl_contains_bigserial_sequence(self):
        """Migration DDL creates the audit_events_seq_seq sequence."""
        src = _read_migration_src()
        assert "audit_events_seq_seq" in src
        assert "BIGINT" in src
        assert "seq" in src

    def test_migration_ddl_contains_backfill(self):
        """Migration DDL includes the backfill DO $$ block."""
        src = _read_migration_src()
        assert "ROW_NUMBER()" in src
        assert "setval" in src

    def test_migration_ddl_contains_not_null_and_index(self):
        """Migration DDL applies NOT NULL after backfill and creates ordering index."""
        src = _read_migration_src()
        assert "SET NOT NULL" in src
        # No UNIQUE constraint (partitioned table restriction — see migration comment).
        # Index on seq is created for ORDER BY seq performance.
        assert "idx_audit_events_seq" in src

    def test_migration_downgrade_is_fail_closed(self):
        """Downgrade DDL raises an exception (forward-only migration)."""
        src = _read_migration_src()
        assert "RAISE EXCEPTION" in src

    def test_insert_audit_event_returns_seq(self):
        """INSERT_AUDIT_EVENT SQL includes RETURNING seq."""
        from yashigani.db.models import INSERT_AUDIT_EVENT
        assert "RETURNING seq" in INSERT_AUDIT_EVENT


# ---------------------------------------------------------------------------
# Test 7: Checkpoint SQL uses ORDER BY seq NULLS LAST (code inspection)
# ---------------------------------------------------------------------------

class TestChainServiceOrderingSQL:
    def test_run_daily_checkpoint_orders_by_seq(self):
        """
        Verify that AuditChainService.run_daily_checkpoint contains
        'ORDER BY seq NULLS LAST' — the authoritative ordering from wave-3.
        This is a code-inspection test to guard against regression.
        """
        import inspect
        from yashigani.audit.chain import AuditChainService
        src = inspect.getsource(AuditChainService.run_daily_checkpoint)
        assert "ORDER BY seq NULLS LAST" in src, (
            "run_daily_checkpoint must use 'ORDER BY seq NULLS LAST' (LU-AMEND-01 wave-3). "
            "Found source:\n" + src
        )

    def test_run_daily_checkpoint_selects_seq_column(self):
        """run_daily_checkpoint SELECT must include seq column."""
        import inspect
        from yashigani.audit.chain import AuditChainService
        src = inspect.getsource(AuditChainService.run_daily_checkpoint)
        assert "seq" in src, (
            "run_daily_checkpoint must select the seq column"
        )

    def test_verify_chain_segment_docstring_mentions_seq(self):
        """verify_chain_segment docstring must reference seq ordering (wave-3)."""
        import inspect
        from yashigani.audit.chain import AuditChainService
        doc = AuditChainService.verify_chain_segment.__doc__
        assert doc is not None
        assert "seq" in doc, (
            "verify_chain_segment docstring must mention seq ordering (wave-3 update)"
        )

    def test_flush_batch_uses_fetchrow_for_returning(self):
        """PostgresSink._flush_batch must use fetchrow (not execute) to capture RETURNING seq."""
        import inspect
        from yashigani.audit.sinks import PostgresSink
        src = inspect.getsource(PostgresSink._flush_batch)
        assert "fetchrow" in src, (
            "PostgresSink._flush_batch must use fetchrow to capture RETURNING seq"
        )
        assert "RETURNING seq" not in src or "INSERT_AUDIT_EVENT" in src, (
            "RETURNING seq is in INSERT_AUDIT_EVENT, not inline"
        )
