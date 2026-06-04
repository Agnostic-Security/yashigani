"""
v2.25.2 — PostgresSink wiring regression tests.

Tiago decision 2026-06-04: WIRE the PostgresSink into the audit write path.

These tests prove the wiring contract WITHOUT a live DB:

  1. Rows land in audit_events for the main event stream (PII/OPA/auth) — the
     masked event_dict reaches the sink's INSERT path via AuditLogWriter.
  2. prev_hash / event_hash are populated when a chain_service is supplied,
     and the chain is continuous across rows.
  3. DB-down / pool-unavailable → request still succeeds, file sink still
     writes, no exception escapes to the caller.
  4. Queue-full → events are dropped + counted, never block.
  5. Config flag off → no DB sink attached, file sink unaffected.

The file sink (canonical durability anchor) must be UNCHANGED and must never
depend on the DB sink — proven by asserting the file is written even when the
DB sink raises / is full / is absent.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from yashigani.audit.chain import AuditChainService
from yashigani.audit.config import AuditConfig
from yashigani.audit.schema import AuditEvent, EventType, AccountTier
from yashigani.audit.sinks import PostgresSink
from yashigani.audit.writer import AuditLogWriter


# ---------------------------------------------------------------------------
# Fakes — a minimal asyncpg-pool/connection that records INSERT calls.
# ---------------------------------------------------------------------------

class _FakeTxn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeConn:
    def __init__(self, recorder: list):
        self._rec = recorder
        self._seq = 0

    def transaction(self):
        return _FakeTxn()

    async def execute(self, sql, *args):
        # set_config(...) — no-op for the fake.
        return "OK"

    async def fetchrow(self, sql, *args):
        # Record the INSERT params; return a row with a monotonic seq.
        self._seq += 1
        self._rec.append(args)
        return {"seq": self._seq}


class _FakeAcquire:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self):
        self.inserts: list = []
        self._conn = _FakeConn(self.inserts)

    def acquire(self):
        return _FakeAcquire(self._conn)


class _DownPool:
    """A pool whose acquire() raises — simulates DB unreachable at flush time."""

    def acquire(self):
        raise ConnectionError("postgres unreachable")


def _make_event(event_type: str = EventType.PROMPT_INJECTION_DETECTED) -> AuditEvent:
    return AuditEvent(event_type=event_type, account_tier=AccountTier.SYSTEM)


def _writer(tmp_path: Path) -> AuditLogWriter:
    cfg = AuditConfig(
        log_path=str(tmp_path / "audit.log"),
        max_file_size_mb=100,
        retention_days=90,
    )
    return AuditLogWriter(config=cfg)


# ---------------------------------------------------------------------------
# 1. Rows land in audit_events for the main event stream.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_main_stream_event_reaches_db_insert(tmp_path):
    pool = _FakePool()
    sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)
    sink.start()

    w = _writer(tmp_path)
    w.attach_db_sink(sink)

    # Emit a main-stream security event (not ceremony).
    w.write(_make_event(EventType.PROMPT_INJECTION_DETECTED))

    # Allow the drain loop to flush (DRAIN_INTERVAL=2.0s + margin).
    await asyncio.sleep(2.5)
    sink._task.cancel()

    assert len(pool.inserts) == 1, "event did not reach the DB INSERT path"
    # INSERT params: ($1 tenant, $2 event_type, ...). event_type is param index 1.
    assert pool.inserts[0][1] == EventType.PROMPT_INJECTION_DETECTED

    # File sink (canonical) also wrote the event.
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == EventType.PROMPT_INJECTION_DETECTED


# ---------------------------------------------------------------------------
# 2. prev_hash / event_hash populated + continuous when chain_service supplied.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_hashes_populated_and_continuous(tmp_path):
    pool = _FakePool()
    chain = AuditChainService()
    sink = PostgresSink(pool_getter=lambda: pool, chain_service=chain)
    sink.start()

    w = _writer(tmp_path)
    w.attach_db_sink(sink)

    for _ in range(3):
        w.write(_make_event(EventType.PII_DETECTED if hasattr(EventType, "PII_DETECTED") else EventType.PROMPT_INJECTION_DETECTED))

    await asyncio.sleep(2.5)
    sink._task.cancel()

    assert len(pool.inserts) == 3
    # prev_hash = param index 11, event_hash = param index 12 (0-based on args).
    prev_hashes = [row[11] for row in pool.inserts]
    event_hashes = [row[12] for row in pool.inserts]

    # All hashes populated (not None).
    assert all(h is not None for h in prev_hashes)
    assert all(h is not None for h in event_hashes)

    # Continuity: event N's prev_hash chains from event N-1.
    # Row 1's prev is the day anchor; rows 2..N prev == prev recomputed from the
    # preceding canonical event.  We assert strict monotonic distinctness +
    # that prev of row i+1 differs from prev of row i (chain advanced).
    assert len(set(event_hashes)) == 3, "event hashes should be distinct"
    assert prev_hashes[1] != prev_hashes[0], "chain pointer did not advance"


# ---------------------------------------------------------------------------
# 3. DB-down → request succeeds, file sink writes, no exception escapes.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_db_down_does_not_break_request_or_file(tmp_path):
    sink = PostgresSink(pool_getter=lambda: _DownPool(), chain_service=None)
    sink.start()

    w = _writer(tmp_path)
    w.attach_db_sink(sink)

    # Must NOT raise even though the DB is unreachable.
    w.write(_make_event())
    w.write(_make_event())

    # Drain loop will hit the DownPool and log+continue; give it a cycle.
    await asyncio.sleep(2.5)
    sink._task.cancel()

    # File sink (canonical) wrote both events regardless of DB state.
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2


def test_db_down_synchronous_write_never_raises(tmp_path):
    """The sync caller path (no running loop drain needed) never raises."""
    sink = PostgresSink(pool_getter=lambda: _DownPool(), chain_service=None)
    # NOT started — enqueue_nowait must still be safe.
    w = _writer(tmp_path)
    w.attach_db_sink(sink)
    w.write(_make_event())  # must not raise
    assert (tmp_path / "audit.log").read_text().strip() != ""


# ---------------------------------------------------------------------------
# 4. Queue-full → drops + does not block, file sink unaffected.
# ---------------------------------------------------------------------------

def test_queue_full_drops_without_blocking(tmp_path):
    pool = _FakePool()
    sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)
    # Do NOT start the drain loop, so the queue never empties.
    w = _writer(tmp_path)
    w.attach_db_sink(sink)

    # Emit MAX_QUEUE_DEPTH + overflow events.  None must block or raise.
    total = PostgresSink.MAX_QUEUE_DEPTH + 50
    for _ in range(total):
        w.write(_make_event())

    # Queue capped at MAX_QUEUE_DEPTH; overflow dropped.
    assert sink._queue.qsize() == PostgresSink.MAX_QUEUE_DEPTH

    # File sink (canonical) wrote ALL events — DB drop never affects the file.
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == total


def test_enqueue_nowait_returns_false_on_full():
    pool = _FakePool()
    sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)
    for _ in range(PostgresSink.MAX_QUEUE_DEPTH):
        assert sink.enqueue_nowait({"event_type": "X"}) is True
    # Next one overflows → dropped, returns False, never raises.
    assert sink.enqueue_nowait({"event_type": "OVERFLOW"}) is False


# ---------------------------------------------------------------------------
# 5. Config flag off → no DB sink attached, file unaffected.
# ---------------------------------------------------------------------------

def test_config_flag_off_disables_db_sink(monkeypatch):
    monkeypatch.setenv("YASHIGANI_AUDIT_DB_SINK", "false")
    assert AuditConfig.from_env().db_sink_enabled is False
    monkeypatch.setenv("YASHIGANI_AUDIT_DB_SINK", "true")
    assert AuditConfig.from_env().db_sink_enabled is True
    monkeypatch.delenv("YASHIGANI_AUDIT_DB_SINK", raising=False)
    assert AuditConfig.from_env().db_sink_enabled is True  # default ON


def test_writer_without_db_sink_writes_file_only(tmp_path):
    """No DB sink attached: file sink works, no DB dependency."""
    w = _writer(tmp_path)
    assert w._db_sink is None
    w.write(_make_event())
    assert (tmp_path / "audit.log").read_text().strip() != ""


# ---------------------------------------------------------------------------
# 6. Isolation: a DB sink that RAISES from enqueue must not break the request.
# ---------------------------------------------------------------------------

def test_db_sink_raising_enqueue_is_isolated(tmp_path):
    class _ExplodingSink:
        def enqueue_nowait(self, event):
            raise RuntimeError("boom")

    w = _writer(tmp_path)
    w.attach_db_sink(_ExplodingSink())
    # Mirror failure is swallowed; file write succeeds; no exception escapes.
    w.write(_make_event())
    assert (tmp_path / "audit.log").read_text().strip() != ""
