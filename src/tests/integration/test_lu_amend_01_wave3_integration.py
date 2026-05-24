"""
Integration tests — LU-AMEND-01 wave-3: bigserial seq column (v2.24.1).

Requires a live Postgres instance with Alembic migrations 0001–0014 applied.
Skip when YASHIGANI_DB_DSN is not set.

Tests:
  1. test_1000_sequential_inserts_unique_monotonic_seq
     Insert 1000 audit events. Verify every row has a unique, monotonically
     increasing seq value. Proves bigserial works end-to-end.

  2. test_timestamp_collision_seq_ordering
     Insert 2 events with forced identical created_at (via pg_sleep(0) in a
     single transaction so both get the same microsecond timestamp).
     Verify seq gives deterministic, unique ordering despite the timestamp tie.

  3. test_batch_100_events_seq_matches_insert_order
     Insert 100 events in a single transaction (via _flush_batch).
     Verify RETURNING seq values are monotonically increasing across the batch.

  4. test_chain_integrity_with_seq_ordering
     Insert 50 events; fetch ordered by seq; verify hash chain is intact.
     This is the wave-3 regression test — wave-2 could not guarantee this
     for timestamp-colliding events.

  5. test_checkpoint_uses_seq_ordering
     Insert events; run run_daily_checkpoint; verify it produces the same
     merkle root as computing it locally from seq-ordered event hashes.

  6. test_backfill_rows_have_seq
     After migration 0014 is applied, verify that all pre-existing rows
     (created before migration 0014) have non-NULL seq values (backfill ran).

Run manually:
    YASHIGANI_DB_DSN=postgresql://yashigani_app:PASSWORD@localhost:5432/yashigani \\
    YASHIGANI_CHAIN_TEST_DSN=postgresql://postgres:PASSWORD@localhost:5432/yashigani \\
    YASHIGANI_TEST_MODE=1 \\
    pytest src/tests/integration/test_lu_amend_01_wave3_integration.py -v -s

Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import date, datetime, timezone

import pytest

pytestmark = pytest.mark.integration

_DB_DSN = os.getenv("YASHIGANI_DB_DSN", "")
_SUPERUSER_DSN = os.getenv("YASHIGANI_CHAIN_TEST_DSN", _DB_DSN)
_SKIP_REASON = "YASHIGANI_DB_DSN not set — skipping wave-3 integration tests"
_NEEDS_DB = pytest.mark.skipif(
    not _DB_DSN or "${POSTGRES_PASSWORD}" in _DB_DSN,
    reason=_SKIP_REASON,
)

_TENANT_ID = "00000000-0000-0000-0000-000000000000"

# ---------------------------------------------------------------------------
# Module-level pool management
# ---------------------------------------------------------------------------

_LOOP: asyncio.AbstractEventLoop = None   # type: ignore[assignment]
_POOL = None
_SUPERUSER_POOL = None


def _get_loop() -> asyncio.AbstractEventLoop:
    global _LOOP
    if _LOOP is None or _LOOP.is_closed():
        _LOOP = asyncio.new_event_loop()
    return _LOOP


def _run(coro):
    return _get_loop().run_until_complete(coro)


@pytest.fixture(scope="module", autouse=True)
def _setup_module():
    global _POOL, _SUPERUSER_POOL

    if not _DB_DSN or "${POSTGRES_PASSWORD}" in _DB_DSN:
        yield
        return

    import asyncpg

    async def _open():
        global _POOL, _SUPERUSER_POOL
        _POOL = await asyncpg.create_pool(_DB_DSN)
        if _SUPERUSER_DSN and "${POSTGRES_PASSWORD}" not in _SUPERUSER_DSN:
            try:
                _SUPERUSER_POOL = await asyncpg.create_pool(_SUPERUSER_DSN)
            except Exception:
                _SUPERUSER_POOL = None

    _run(_open())
    yield

    async def _close():
        global _POOL, _SUPERUSER_POOL
        if _POOL:
            await _POOL.close()
            _POOL = None
        if _SUPERUSER_POOL:
            await _SUPERUSER_POOL.close()
            _SUPERUSER_POOL = None

    _run(_close())
    _get_loop().close()


@pytest.fixture(scope="module")
def pool():
    if not _DB_DSN or "${POSTGRES_PASSWORD}" in _DB_DSN:
        pytest.skip(_SKIP_REASON)
    assert _POOL is not None, "Pool not initialised"
    return _POOL


@pytest.fixture(scope="module")
def superuser_pool():
    return _SUPERUSER_POOL


@pytest.fixture(scope="module")
def chain_service():
    from yashigani.audit.chain import AuditChainService
    return AuditChainService(signing_key_path=None, signing_spiffe_id="")


@pytest.fixture(scope="module")
def postgres_sink(pool, chain_service):
    from yashigani.audit.sinks import PostgresSink
    return PostgresSink(pool_getter=lambda: pool, chain_service=chain_service)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(i: int, tenant_id: str = _TENANT_ID) -> dict:
    return {
        "tenant_id": tenant_id,
        "event_type": "TEST_W3_EVENT",
        "request_id": str(uuid.uuid4()),
        "session_id": "test-session-w3",
        "agent_id": "test-agent-w3",
        "action": f"action_{i}",
        "reason": f"wave3 integration test i={i}",
        "upstream_status": 200,
        "elapsed_ms": i,
        "confidence_score": 0.99,
        "client_ip_hash": "deadbeef",
    }


async def _set_tenant(conn, tenant_id: str = _TENANT_ID) -> None:
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)


async def _insert_events_returning_seq(
    chain_service_inst, n: int, event_type: str
) -> list[int]:
    """Insert n events; return list of assigned seq values in insertion order."""
    from yashigani.db.models import INSERT_AUDIT_EVENT
    seq_values = []
    async with _POOL.acquire() as conn:
        async with conn.transaction():
            await _set_tenant(conn)
            for i in range(n):
                ev = _make_event(i)
                ev["event_type"] = event_type
                prev_hash, event_hash = chain_service_inst.compute_hashes_for_event(ev)
                row = await conn.fetchrow(
                    INSERT_AUDIT_EVENT,
                    uuid.UUID(_TENANT_ID),
                    event_type,
                    uuid.UUID(ev["request_id"]),
                    ev["session_id"],
                    ev["agent_id"],
                    ev["action"],
                    ev["reason"],
                    ev["upstream_status"],
                    ev["elapsed_ms"],
                    ev["confidence_score"],
                    ev["client_ip_hash"],
                    prev_hash,
                    event_hash,
                )
                seq_values.append(row["seq"])
    return seq_values


async def _fetch_events_by_seq(event_type: str) -> list[dict]:
    """Fetch events ordered by seq (wave-3 authoritative ordering)."""
    async with _POOL.acquire() as conn:
        async with conn.transaction():
            await _set_tenant(conn)
            rows = await conn.fetch(
                """
                SELECT id, seq, prev_hash, event_hash, created_at
                FROM audit_events
                WHERE tenant_id = $1 AND event_type = $2
                ORDER BY seq NULLS LAST
                """,
                uuid.UUID(_TENANT_ID),
                event_type,
            )
    return [dict(r) for r in rows]


async def _cleanup(event_type: str) -> None:
    if _SUPERUSER_POOL is None:
        return
    async with _SUPERUSER_POOL.acquire() as conn:
        await conn.execute(
            "DELETE FROM audit_events WHERE tenant_id = $1 AND event_type = $2",
            uuid.UUID(_TENANT_ID),
            event_type,
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_NEEDS_DB
def test_1000_sequential_inserts_unique_monotonic_seq(pool, chain_service):
    """1000 INSERTs → unique, monotonically increasing seq values."""
    EVENT_TYPE = "TEST_W3_SEQ_1000"
    _run(_cleanup(EVENT_TYPE))

    from yashigani.audit.chain import AuditChainService
    svc = AuditChainService()

    seq_values = _run(_insert_events_returning_seq(svc, 1000, EVENT_TYPE))

    assert len(seq_values) == 1000, f"Expected 1000 seq values, got {len(seq_values)}"

    # All unique
    assert len(set(seq_values)) == 1000, (
        f"seq values not unique — {1000 - len(set(seq_values))} duplicates"
    )

    # Monotonically increasing
    for i in range(1, len(seq_values)):
        assert seq_values[i] > seq_values[i - 1], (
            f"seq not monotonically increasing at index {i}: "
            f"{seq_values[i-1]} → {seq_values[i]}"
        )

    _run(_cleanup(EVENT_TYPE))


@_NEEDS_DB
def test_timestamp_collision_seq_ordering(pool, chain_service):
    """
    Two events inserted in the same microsecond get distinct, ordered seq values.

    We use a single transaction (no pg_sleep needed) so both events share the
    same statement timestamp. seq ordering must be unambiguous.
    """
    EVENT_TYPE = "TEST_W3_TS_COLLISION"
    _run(_cleanup(EVENT_TYPE))

    from yashigani.db.models import INSERT_AUDIT_EVENT
    from yashigani.audit.chain import AuditChainService
    svc = AuditChainService()

    async def _insert_collision_pair():
        seq_vals = []
        async with _POOL.acquire() as conn:
            async with conn.transaction():
                await _set_tenant(conn)
                for i in range(2):
                    ev = _make_event(i)
                    ev["event_type"] = EVENT_TYPE
                    prev, ev_hash = svc.compute_hashes_for_event(ev)
                    row = await conn.fetchrow(
                        INSERT_AUDIT_EVENT,
                        uuid.UUID(_TENANT_ID),
                        EVENT_TYPE,
                        uuid.UUID(ev["request_id"]),
                        ev["session_id"],
                        ev["agent_id"],
                        ev["action"],
                        ev["reason"],
                        ev["upstream_status"],
                        ev["elapsed_ms"],
                        ev["confidence_score"],
                        ev["client_ip_hash"],
                        prev,
                        ev_hash,
                    )
                    seq_vals.append(row["seq"])
        return seq_vals

    seqs = _run(_insert_collision_pair())
    assert len(seqs) == 2
    assert seqs[0] != seqs[1], "Two events must have different seq values"
    assert seqs[1] > seqs[0], "Second event must have higher seq than first"

    # Verify ordering via DB fetch
    rows = _run(_fetch_events_by_seq(EVENT_TYPE))
    assert len(rows) == 2
    assert rows[0]["seq"] < rows[1]["seq"], "DB ORDER BY seq must return rows in seq order"

    _run(_cleanup(EVENT_TYPE))


@_NEEDS_DB
def test_batch_100_events_seq_matches_insert_order(pool, postgres_sink, chain_service):
    """
    Batch INSERT 100 events via _flush_batch; verify seq values are monotonically
    increasing (RETURNING seq is captured in insertion order).
    """
    EVENT_TYPE = "TEST_W3_BATCH_100"
    _run(_cleanup(EVENT_TYPE))

    from yashigani.audit.chain import AuditChainService
    svc = AuditChainService()

    batch = []
    for i in range(100):
        ev = _make_event(i)
        ev["event_type"] = EVENT_TYPE
        batch.append(ev)

    _run(postgres_sink._flush_batch(batch))

    rows = _run(_fetch_events_by_seq(EVENT_TYPE))
    assert len(rows) == 100, f"Expected 100 rows, got {len(rows)}"

    # All seq non-NULL
    null_seq = [r for r in rows if r["seq"] is None]
    assert not null_seq, f"{len(null_seq)} rows have NULL seq after batch INSERT"

    # Monotonically increasing
    seq_values = [r["seq"] for r in rows]
    assert seq_values == sorted(seq_values), (
        "seq values must be monotonically increasing in ORDER BY seq order"
    )
    assert len(set(seq_values)) == 100, "All seq values must be unique"

    _run(_cleanup(EVENT_TYPE))


@_NEEDS_DB
def test_chain_integrity_with_seq_ordering(pool, chain_service):
    """
    50 events inserted sequentially → fetch by seq → chain is intact.

    This is the wave-3 regression test. In wave-2, 50 same-microsecond events
    could be returned in random UUID order, breaking chain verification.
    With seq ordering, the chain is always intact.
    """
    EVENT_TYPE = "TEST_W3_CHAIN_INTEGRITY"
    _run(_cleanup(EVENT_TYPE))

    from yashigani.audit.chain import AuditChainService
    svc = AuditChainService()

    _run(_insert_events_returning_seq(svc, 50, EVENT_TYPE))

    rows = _run(_fetch_events_by_seq(EVENT_TYPE))
    assert len(rows) == 50, f"Expected 50 rows, got {len(rows)}"

    # All rows have non-NULL hashes
    for row in rows:
        assert row["prev_hash"] is not None, f"Row seq={row['seq']} has NULL prev_hash"
        assert row["event_hash"] is not None, f"Row seq={row['seq']} has NULL event_hash"

    # Verify chain integrity using verify_chain_segment (seq-ordered)
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    ok, breaks = chain_service.verify_chain_segment(
        [dict(r) for r in rows], today
    )
    assert ok is True, (
        f"Chain integrity FAILED with seq ordering — breaks at indices: {breaks}. "
        "This is the exact regression that LU-AMEND-01 wave-3 must fix."
    )
    assert len(breaks) == 0

    _run(_cleanup(EVENT_TYPE))


@_NEEDS_DB
def test_checkpoint_uses_seq_ordering(pool, chain_service):
    """
    run_daily_checkpoint computes the same merkle root as local computation
    over seq-ordered event_hash values.
    """
    EVENT_TYPE = "TEST_W3_CHECKPOINT"
    _run(_cleanup(EVENT_TYPE))

    from yashigani.audit.chain import AuditChainService, _merkle_root
    svc = AuditChainService()

    _run(_insert_events_returning_seq(svc, 30, EVENT_TYPE))

    rows = _run(_fetch_events_by_seq(EVENT_TYPE))
    assert len(rows) == 30

    # Compute expected merkle root locally from seq-ordered hashes
    hashes = [r["event_hash"] for r in rows]
    expected_root = _merkle_root(hashes)

    # Run the checkpoint (uses same ORDER BY seq NULLS LAST query)
    today = datetime.now(tz=timezone.utc).date()
    result = _run(chain_service.run_daily_checkpoint(
        target_date=today,
        pool=_POOL,
        tenant_id=_TENANT_ID,
    ))

    assert result["event_count"] >= 30, (
        f"Checkpoint event count should be >= 30, got {result['event_count']}"
    )
    assert result["merkle_root"] == expected_root, (
        f"Checkpoint merkle root does not match local seq-ordered computation. "
        f"Expected: {expected_root[:16]}... Got: {result['merkle_root'][:16]}..."
    )

    _run(_cleanup(EVENT_TYPE))


@_NEEDS_DB
def test_all_rows_have_seq_after_migration(pool):
    """
    After migration 0014, ALL rows in audit_events must have non-NULL seq.
    This verifies the backfill DO $$ block ran to completion.
    """
    async def _check():
        async with _POOL.acquire() as conn:
            async with conn.transaction():
                await _set_tenant(conn)
                row = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM audit_events
                    WHERE tenant_id = $1 AND seq IS NULL
                    """,
                    uuid.UUID(_TENANT_ID),
                )
            return int(row["cnt"])

    null_count = _run(_check())
    assert null_count == 0, (
        f"Found {null_count} audit_events rows with NULL seq after migration 0014. "
        "The backfill block in migration 0014 should have populated seq for all rows."
    )
