"""
Regression test -- v4.1.2 FIND-IRIS-CHECKPOINT-EVENTLOOP (P1, audit
integrity, fixed 2026-08-06).

The daily merkle-root checkpoint job (AuditCheckpointScheduler, APScheduler
BackgroundScheduler, its own worker thread) always failed with an asyncpg
cross-event-loop RuntimeError: `_run_checkpoint_sync()` span up a *brand
new* `asyncio.new_event_loop()` per fire and ran the checkpoint coroutine
there, but the asyncpg pool returned by `pool_getter()` was created on (and
is permanently bound to) the application's own event loop
(backoffice/app.py's async lifespan -> `await create_pool()`). asyncpg
Pool/Connection internals use asyncio.Queue/Future primitives tied to their
creation loop; driving them from any other loop raises a cross-loop
RuntimeError. The per-tenant try/except in `_run_checkpoint_async` caught
and logged this every single time, so `audit_chain_checkpoints` had NEVER
had a row written on this stack -- the signed anchor was silently broken
even though chain-linkage itself (687/687) was fine.

Fix: `start()` captures the application's running event loop (it is called
synchronously from inside the async lifespan, so `asyncio.get_running_loop()`
resolves correctly); `_run_checkpoint_sync()` (which runs in APScheduler's
own worker thread, with no loop of its own) hands the job coroutine to THAT
loop via `asyncio.run_coroutine_threadsafe()` and blocks on the result
instead of building an unrelated loop.

This test reproduces the REAL topology (not a mock of the fix itself):
  - an application event loop running forever in its own thread, like
    uvicorn's;
  - a loop-bound pool stand-in created ON that loop, whose `acquire()`
    raises the same RuntimeError a real asyncpg Pool raises when driven
    from a different loop than the one that created it;
  - the scheduler's job fired from a SEPARATE thread with no loop of its
    own, exactly like APScheduler's BackgroundScheduler worker.

Fails on the pre-fix implementation (new unrelated loop per fire -> the
fake pool's cross-loop guard trips -> job caught+logged as a failure -> no
row ever recorded). Passes on the fix (job runs on the captured app loop ->
pool's own bound loop matches -> checkpoint recorded).
"""
from __future__ import annotations

import asyncio
import threading
from datetime import date
from typing import Any

from yashigani.audit.checkpoint_job import AuditCheckpointScheduler


class _FakeConn:
    async def execute(self, *args: Any, **kwargs: Any) -> str:
        return "INSERT 0 1"


class _FakeAcquireCtx:
    """Mimics asyncpg's PoolAcquireContext cross-loop guard."""

    def __init__(self, pool: "_LoopBoundPool") -> None:
        self._pool = pool

    async def __aenter__(self) -> _FakeConn:
        current = asyncio.get_running_loop()
        if current is not self._pool.bound_loop:
            # This is the exact failure mode asyncpg raises in production
            # when a Pool created on one event loop is driven from another:
            # its internal Queue/Future primitives are bound to the
            # creation loop and refuse to hand out connections cross-loop.
            raise RuntimeError(
                "cross-event-loop pool.acquire(): got Future attached to a "
                "different loop than the one this pool was created on"
            )
        return _FakeConn()

    async def __aexit__(self, *exc: Any) -> None:
        return None


class _LoopBoundPool:
    """Minimal stand-in for an asyncpg Pool: permanently bound to the loop
    that was running when it was constructed -- exactly asyncpg's real
    lifetime contract."""

    def __init__(self) -> None:
        self.bound_loop = asyncio.get_running_loop()

    def acquire(self) -> _FakeAcquireCtx:
        return _FakeAcquireCtx(self)


class _FakeChainService:
    """Stand-in for AuditChainService.run_daily_checkpoint: records a
    'row written' only if it successfully acquired a pool connection."""

    def __init__(self) -> None:
        self.rows_written: list[str] = []

    async def run_daily_checkpoint(
        self, *, target_date: date, pool: _LoopBoundPool, tenant_id: str
    ) -> dict:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_chain_checkpoints (...) VALUES (...)"
            )
        self.rows_written.append(f"{tenant_id}:{target_date.isoformat()}")
        return {
            "date": target_date.isoformat(),
            "event_count": 0,
            "merkle_root": "deadbeef" * 12,
            "chain_break_count": 0,
            "signed": False,
            "checkpoint_id": "fake-checkpoint-id",
            "signing_spiffe_id": "",
        }


async def _make_pool() -> _LoopBoundPool:
    return _LoopBoundPool()


async def _call_start(scheduler: AuditCheckpointScheduler) -> None:
    # start() must be invoked ON the app loop -- mirrors backoffice/app.py
    # calling scheduler.start() synchronously from inside the async
    # lifespan (after `await create_pool()`), so
    # asyncio.get_running_loop() inside start() resolves to the app loop.
    scheduler.start()


def test_checkpoint_job_writes_row_via_app_loop_not_a_fresh_loop() -> None:
    app_loop = asyncio.new_event_loop()
    app_loop_thread = threading.Thread(target=app_loop.run_forever, daemon=True)
    app_loop_thread.start()

    scheduler: AuditCheckpointScheduler | None = None
    try:
        pool = asyncio.run_coroutine_threadsafe(_make_pool(), app_loop).result(
            timeout=5
        )

        chain_service = _FakeChainService()
        scheduler = AuditCheckpointScheduler(
            chain_service=chain_service,
            pool_getter=lambda: pool,
            tenant_ids=["00000000-0000-0000-0000-000000000000"],
        )

        asyncio.run_coroutine_threadsafe(_call_start(scheduler), app_loop).result(
            timeout=5
        )

        # Fire the job from a SEPARATE thread with NO event loop of its
        # own -- exactly how APScheduler's BackgroundScheduler invokes it.
        job_thread = threading.Thread(target=scheduler._run_checkpoint_sync)
        job_thread.start()
        job_thread.join(timeout=15)
        assert not job_thread.is_alive(), (
            "checkpoint job thread did not complete within 15s"
        )

        assert chain_service.rows_written, (
            "AuditCheckpointScheduler job fired from a worker thread with "
            "no event loop of its own must still write a checkpoint row "
            "via the application's event loop "
            "(FIND-IRIS-CHECKPOINT-EVENTLOOP) -- the pre-fix implementation "
            "spun up an unrelated fresh event loop per fire, tripping the "
            "asyncpg cross-loop guard on every call and silently dropping "
            "every checkpoint. chain_service.rows_written="
            f"{chain_service.rows_written!r}"
        )
    finally:
        if scheduler is not None:
            scheduler.stop(wait=False)
        app_loop.call_soon_threadsafe(app_loop.stop)
        app_loop_thread.join(timeout=5)
        app_loop.close()
