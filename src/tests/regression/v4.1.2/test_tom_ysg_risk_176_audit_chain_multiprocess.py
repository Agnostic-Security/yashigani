"""
Regression test -- v4.1.2 YSG-RISK-176 (HIGH, witness-integrity):
audit hash-chain interleaving under concurrent multi-process writers.

Root cause (writer.py:231, pre-fix): AuditLogWriter chained each event to
the previous one via a PER-PROCESS in-memory ``_chain_last_hash``. In
production the gateway alone runs TWO concurrent uvicorn processes (mTLS
:8080 + mesh :8081 -- see docker/gateway-start.sh) sharing the SAME
volume-mounted audit.log, each with its OWN AuditLogWriter instance and its
OWN independent chain pointer. Their interleaved appends produced a log
whose chain only validates within one process's own writes -- a live query
under normal concurrent traffic found 4/56 broken links, zero tampering.
This defeats the tamper-evident guarantee: a break caused by ordinary
concurrency is indistinguishable from a break caused by an attacker editing
a row.

Fix: AuditLogWriter now derives prev_event_hash by reading the true last
line physically on disk (whichever process wrote it), under a cross-process
POSIX advisory lock (fcntl.flock on a dedicated sidecar lock file) that
serialises the read-prev -> compute -> append critical section across every
worker process sharing the log file.

This test reproduces the ORIGINAL bug's precondition exactly -- multiple
concurrent OS processes, each with its own AuditLogWriter instance, writing
to the same log path at the same time (multiprocessing.Process, not just
threads, so each worker genuinely gets its own Python process / GIL / heap
-- threads alone would not have reproduced the per-process interleaving
defect) -- and asserts the resulting merged, timestamp-ordered chain has
ZERO breaks. Pre-fix, this test reliably reproduces "N/M broken links, zero
tampering" (the exact class of failure this finding describes); post-fix it
is green.

Dedup: distinct from YSG-RISK-153/154 (audit-write-failure signalling to the
API caller / audit_writer=None fail-closed) -- this finding is about the
CONTENT of the chain under concurrency, not whether a write was attempted.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Standalone re-implementation of the verifier algorithm (mirrors
# scripts/audit_verify.py's verify_chain() exactly -- kept inline so this
# test has no dependency on scripts/ being importable from src/tests).
# ---------------------------------------------------------------------------

def _canonical_json(event_dict: dict) -> str:
    d = {k: v for k, v in event_dict.items() if k != "prev_event_hash"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _sha384_hex(text: str) -> str:
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def _day_anchor(date_str: str) -> str:
    return _sha384_hex(date_str)


def _verify_chain(events: list[dict]) -> list[dict]:
    breaks: list[dict] = []
    last_hash: Optional[str] = None
    current_day: Optional[str] = None

    for idx, event in enumerate(events):
        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)
        event_day = ts.strftime("%Y-%m-%d")

        if current_day != event_day or last_hash is None:
            expected = _day_anchor(event_day)
            current_day = event_day
        else:
            expected = last_hash

        actual = event.get("prev_event_hash", "")
        if actual != expected:
            breaks.append({
                "event_index": idx,
                "event_id": event.get("audit_event_id", "<unknown>"),
                "expected": expected,
                "actual": actual,
            })

        last_hash = _sha384_hex(_canonical_json(event))

    return breaks


# ---------------------------------------------------------------------------
# Multi-process writer worker (module-level -- must be picklable for
# multiprocessing on macOS/spawn as well as fork).
# ---------------------------------------------------------------------------

def _worker_write_events(log_path: str, worker_id: int, n_events: int) -> None:
    """Runs in a SEPARATE OS process. Constructs its OWN AuditLogWriter
    (exactly as gateway/entrypoint.py and gateway/mesh_entrypoint.py each do
    in their own uvicorn process) pointed at the SAME log file, and writes
    n_events events as fast as possible to maximise the chance of
    interleaving with sibling worker processes.
    """
    from yashigani.audit.config import AuditConfig
    from yashigani.audit.schema import GatewayRequestEvent
    from yashigani.audit.scope import MaskingScopeConfig
    from yashigani.audit.writer import AuditLogWriter

    config = AuditConfig(log_path=log_path, max_file_size_mb=1000, retention_days=90)
    writer = AuditLogWriter(config=config, masking_scope=MaskingScopeConfig())
    try:
        for i in range(n_events):
            event = GatewayRequestEvent(
                request_id=f"w{worker_id}-{i}",
                method="GET",
                path="/v1/models",
                action="FORWARDED",
            )
            writer.write(event)
    finally:
        writer.close()


class TestAuditChainMultiProcessConcurrency:
    def test_concurrent_worker_processes_produce_unbroken_chain(self, tmp_path: Path):
        """YSG-RISK-176: N real OS processes writing concurrently to the same
        audit log must produce a chain with ZERO breaks when verified in
        timestamp order (the same algorithm audit_verify.py uses)."""
        log_path = tmp_path / "audit.log"

        n_workers = 6
        n_events_per_worker = 40

        ctx = multiprocessing.get_context("spawn")
        procs = [
            ctx.Process(
                target=_worker_write_events,
                args=(str(log_path), worker_id, n_events_per_worker),
            )
            for worker_id in range(n_workers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=45)
            assert p.exitcode == 0, f"worker process failed: exitcode={p.exitcode}"

        # Collect every event physically written (log + any rotated siblings
        # -- max_file_size_mb=1000 makes rotation extremely unlikely here,
        # but mirror audit_verify.py's file-collection behaviour anyway).
        all_events: list[dict] = []
        for lf in sorted(tmp_path.glob("audit.log*")):
            with lf.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    all_events.append(json.loads(line))

        expected_total = n_workers * n_events_per_worker
        assert len(all_events) == expected_total, (
            f"expected {expected_total} events written across {n_workers} "
            f"concurrent processes, found {len(all_events)} -- a write was "
            f"lost, not just mis-chained."
        )

        # Verify in TIMESTAMP order, exactly as audit_verify.py's CLI does.
        all_events.sort(key=lambda e: e.get("timestamp", ""))
        breaks = _verify_chain(all_events)

        assert breaks == [], (
            f"YSG-RISK-176 regression: {len(breaks)}/{len(all_events)} "
            f"hash-chain links broken under {n_workers}-process concurrent "
            f"writes (should be 0 post-fix). First break: "
            f"{breaks[0] if breaks else None}"
        )

    def test_single_process_multithread_baseline_still_unbroken(self, tmp_path: Path):
        """Sanity baseline: the pre-existing single-process thread-safety
        guarantee (self._lock) must still hold post-fix -- concurrent
        threads within ONE process must also produce zero breaks."""
        import threading

        from yashigani.audit.config import AuditConfig
        from yashigani.audit.schema import GatewayRequestEvent
        from yashigani.audit.scope import MaskingScopeConfig
        from yashigani.audit.writer import AuditLogWriter

        log_path = tmp_path / "audit.log"
        config = AuditConfig(log_path=str(log_path), max_file_size_mb=1000, retention_days=90)
        writer = AuditLogWriter(config=config, masking_scope=MaskingScopeConfig())

        n_threads = 8
        n_events_per_thread = 25

        def _write(tid: int) -> None:
            for i in range(n_events_per_thread):
                writer.write(GatewayRequestEvent(
                    request_id=f"t{tid}-{i}", method="GET", path="/x", action="FORWARDED",
                ))

        threads = [threading.Thread(target=_write, args=(tid,)) for tid in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        writer.close()

        with log_path.open("r", encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]

        assert len(events) == n_threads * n_events_per_thread
        events.sort(key=lambda e: e.get("timestamp", ""))
        breaks = _verify_chain(events)
        assert breaks == [], f"single-process thread-safety regression: {breaks[:3]}"


# ---------------------------------------------------------------------------
# DB-chain (AuditChainService.compute_hashes_for_event_db / PostgresSink)
# concurrency proof.
#
# No live Postgres is available in this sandbox, so this exercises the
# ALGORITHM (advisory-lock-keyed serialisation + seq-ordered "last row"
# lookup) against a minimal fake asyncpg connection that models the two
# Postgres semantics the fix depends on:
#   1. pg_advisory_xact_lock(key) blocks a second acquirer of the SAME key
#      until the holder's transaction ends (commit/rollback) -- modelled
#      with a real asyncio.Lock per key, released when the fake transaction
#      context manager exits.
#   2. A fresh SELECT issued after acquiring the lock sees all rows
#      committed by the previous holder (READ COMMITTED visibility) --
#      modelled by only appending rows to the shared table on "commit".
# This proves the fix's serialisation logic is correct; real Postgres
# lock/visibility semantics are validated live at the Iris integration gate
# per this finding's dispatch brief (168/176 is security-core).
# ---------------------------------------------------------------------------

class _FakeAuditEventsTable:
    """Shared in-memory stand-in for the audit_events table + its BIGSERIAL
    seq column, guarded by per-tenant asyncio.Lock instances that model
    pg_advisory_xact_lock(hashtext(tenant_id))."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self._next_seq = 1
        self._advisory_locks: dict[str, asyncio.Lock] = {}

    def lock_for(self, key: str) -> asyncio.Lock:
        return self._advisory_locks.setdefault(key, asyncio.Lock())

    def last_row_for_tenant(self, tenant_id: str) -> Optional[dict]:
        for row in reversed(self.rows):
            if row["tenant_id"] == tenant_id:
                return row
        return None

    def insert(self, tenant_id: str, event_hash: str, prev_hash: str, created_at) -> int:
        seq = self._next_seq
        self._next_seq += 1
        self.rows.append({
            "seq": seq,
            "tenant_id": tenant_id,
            "event_hash": event_hash,
            "prev_hash": prev_hash,
            "created_at": created_at,
        })
        return seq


class _FakeConn:
    """Minimal asyncpg-connection-shaped fake: only implements what
    AuditChainService.compute_hashes_for_event_db() calls (execute for the
    advisory lock, fetchrow for the seq-ordered last-row lookup)."""

    def __init__(self, table: _FakeAuditEventsTable, tenant_id: str):
        self._table = table
        self._tenant_id = tenant_id
        self._held_lock = None

    async def execute(self, query: str, *args) -> None:
        if "pg_advisory_xact_lock" in query:
            key = args[0]
            lock = self._table.lock_for(key)
            await lock.acquire()
            self._held_lock = lock

    async def fetchrow(self, query: str, *args):
        tenant_id = args[0]
        row = self._table.last_row_for_tenant(tenant_id)
        return row

    def release_xact_locks(self) -> None:
        if self._held_lock is not None and self._held_lock.locked():
            self._held_lock.release()
        self._held_lock = None


class TestAuditChainDbConcurrencyAlgorithm:
    async def test_concurrent_transactions_produce_unbroken_seq_chain(self):
        """N concurrent 'transactions' (asyncio tasks) racing
        compute_hashes_for_event_db() + a simulated INSERT for the SAME
        tenant must still produce a chain with zero breaks, because the
        advisory lock serialises the critical section and the seq-ordered
        SELECT always observes the true last-committed row."""
        import asyncio

        from yashigani.audit.chain import AuditChainService

        table = _FakeAuditEventsTable()
        svc = AuditChainService()
        tenant_id = "11111111-1111-1111-1111-111111111111"

        async def _one_transaction(worker_id: int, i: int) -> None:
            conn = _FakeConn(table, tenant_id)
            event = {"event_type": "GATEWAY_REQUEST", "worker": worker_id, "i": i}
            try:
                prev_hash, event_hash = await svc.compute_hashes_for_event_db(
                    conn, tenant_id, event
                )
                # Simulate the INSERT that PostgresSink._flush_batch issues
                # immediately after, still inside the same transaction/lock.
                table.insert(tenant_id, event_hash, prev_hash, datetime.now(timezone.utc))
            finally:
                conn.release_xact_locks()

        n_workers, n_per_worker = 10, 15
        await asyncio.gather(*[
            _one_transaction(w, i)
            for w in range(n_workers)
            for i in range(n_per_worker)
        ])

        rows = sorted(table.rows, key=lambda r: r["seq"])
        assert len(rows) == n_workers * n_per_worker

        breaks = []
        for idx in range(1, len(rows)):
            expected = rows[idx - 1]["event_hash"]
            actual = rows[idx]["prev_hash"]
            if actual != expected:
                breaks.append(idx)

        assert breaks == [], (
            f"YSG-RISK-176 (DB chain) regression: {len(breaks)}/{len(rows)} "
            f"seq-ordered links broken under {n_workers}-way concurrent "
            f"transactions (should be 0 post-fix)."
        )
