"""
Yashigani Audit — Daily merkle-root checkpoint scheduler (LU-AMEND-01 wave 2).

Runs once per day at 00:05 UTC, computes the previous day's merkle root over
all audit_events.event_hash values, signs with the service's internal SPIFFE
identity, and upserts the result into audit_chain_checkpoints.

Uses APScheduler 3.x BackgroundScheduler (already a declared dependency).
The scheduler is managed by the service lifespan; fail-closed per SOP 1:
  - startup failure raises RuntimeError (let the orchestrator surface it)
  - job failure is logged + Prometheus-counted but does NOT stop the scheduler
    (one failed checkpoint is recoverable; a crashed service is not)

FIND-IRIS-CHECKPOINT-EVENTLOOP (v4.1.2 retest, fixed 2026-08-06):
  BackgroundScheduler runs jobs in its own worker thread, which has NO
  asyncio event loop of its own. asyncpg Pool/Connection objects are bound
  for their whole lifetime to the event loop that was running when the pool
  was created (backoffice/app.py's lifespan `await create_pool()`, i.e. the
  application's own uvicorn event loop) -- asyncpg's internal
  queues/futures assert the calling loop matches the creation loop and raise
  a cross-event-loop RuntimeError otherwise. The previous implementation
  span up a *brand-new* `asyncio.new_event_loop()` per job fire and ran the
  checkpoint coroutine there -- always the wrong loop relative to the pool
  -- so every fire failed with that RuntimeError, was caught by the
  per-tenant try/except in `_run_checkpoint_async`, logged, and counted as a
  failure. Net effect: `audit_chain_checkpoints` never received a row on
  this stack. Fix: capture the application's running loop in `start()`
  (called synchronously from within the async lifespan, so
  `asyncio.get_running_loop()` correctly resolves to the uvicorn loop the
  pool lives on) and hand the job coroutine to THAT loop via
  `asyncio.run_coroutine_threadsafe()`, blocking the APScheduler worker
  thread on the result (bounded by `job_timeout_s`) so failures remain
  observable via the exact same logging/Prometheus path as before.

Compliance:
    ASVS V7.3.3   — audit log integrity (tamper-evident)
    NIST AU-9/AU-10 — protection of audit information + non-repudiation
    SOC 2 CC7.2/CC7.3 — monitoring + evaluation of security events

Last updated: 2026-08-06T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Prometheus counter for checkpoint failures (best-effort; not a hard dep).
def _inc_checkpoint_failure() -> None:
    try:
        from yashigani.metrics.registry import audit_chain_breaks_total
        audit_chain_breaks_total.inc()
    except Exception:
        pass


class AuditCheckpointScheduler:
    """
    Wraps APScheduler 3.x BackgroundScheduler to run the daily checkpoint job.

    Usage (in the async service lifespan, AFTER the asyncpg pool is created)::

        async def lifespan(app):
            await create_pool()
            ...
            # MUST be called synchronously from this running event loop --
            # start() captures it via asyncio.get_running_loop() so the
            # scheduler's worker thread can hand its job coroutine back to
            # the same loop the pool lives on (FIND-IRIS-CHECKPOINT-EVENTLOOP).
            scheduler = AuditCheckpointScheduler(
                chain_service=audit_chain_svc,
                pool_getter=lambda: app_state.db_pool,
                tenant_ids=["00000000-0000-0000-0000-000000000000"],
                signing_key_path=Path("/run/secrets/hermes_client.key"),
                signing_spiffe_id="spiffe://yashigani.internal/hermes",
            )
            scheduler.start()
            yield
            scheduler.stop()

    The job runs at 00:05 UTC by default (configurable via hour/minute kwargs)
    and checkpoints *yesterday's* events.  Idempotent: re-running for an
    already-checkpointed date is a no-op (ON CONFLICT DO NOTHING in the
    service -- checkpoints are immutable once written, v2.25.2).
    """

    def __init__(
        self,
        *,
        chain_service,
        pool_getter,
        tenant_ids: Optional[list[str]] = None,
        signing_key_path: Optional[Path] = None,
        signing_spiffe_id: str = "",
        hour: int = 0,
        minute: int = 5,
        job_timeout_s: float = 300.0,
    ) -> None:
        """
        Args:
            chain_service: AuditChainService instance (from audit.chain).
            pool_getter: zero-argument callable returning an asyncpg pool.
            tenant_ids: list of tenant UUID strings to checkpoint each day.
                Defaults to the platform sentinel tenant only.
            signing_key_path: path to the ECDSA leaf key for checkpoint signing.
                If None, checkpoints are written unsigned.
            signing_spiffe_id: SPIFFE URI of the signing identity.
            hour/minute: UTC hour/minute to run the job (default 00:05).
            job_timeout_s: max seconds to wait for one day's checkpoint run
                (across all tenants) when it is handed to the app loop from
                the APScheduler worker thread (FIND-IRIS-CHECKPOINT-EVENTLOOP).
        """
        self._chain_service = chain_service
        self._pool_getter = pool_getter
        self._tenant_ids = tenant_ids or ["00000000-0000-0000-0000-000000000000"]
        self._signing_key_path = signing_key_path
        self._signing_spiffe_id = signing_spiffe_id
        self._hour = hour
        self._minute = minute
        self._job_timeout_s = job_timeout_s
        self._scheduler = None
        # FIND-IRIS-CHECKPOINT-EVENTLOOP: the event loop the asyncpg pool was
        # created on (captured in start()). The APScheduler worker thread has
        # no loop of its own; job coroutines MUST run on this loop, never a
        # freshly-created one, or every asyncpg call raises a cross-loop
        # RuntimeError.
        self._app_loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background scheduler.  Raises RuntimeError on failure (SOP 1).

        MUST be called synchronously from within the application's running
        event loop (e.g. from inside the async lifespan, the same context
        `create_pool()` was awaited in) -- FIND-IRIS-CHECKPOINT-EVENTLOOP.
        `asyncio.get_running_loop()` below resolves to that loop precisely
        because `start()` executes on it; capturing it here is what lets the
        APScheduler worker thread hand its job coroutine back to the correct
        loop later instead of spinning up an unrelated one.
        """
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger
        except ImportError as exc:
            raise RuntimeError(
                "AuditCheckpointScheduler: apscheduler is required but not installed"
            ) from exc

        try:
            self._app_loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            # Fail-closed (SOP 1): a checkpoint scheduler with no known app
            # loop cannot ever run its DB work correctly -- refuse to start
            # rather than silently building a scheduler that will fail every
            # job forever (the exact FIND-IRIS-CHECKPOINT-EVENTLOOP bug).
            raise RuntimeError(
                "AuditCheckpointScheduler.start() must be called from within "
                "the application's running event loop (e.g. the async "
                "lifespan, after create_pool()) so the checkpoint job can "
                "run its asyncpg work on the same loop the pool was created "
                "on."
            ) from exc

        scheduler = BackgroundScheduler(timezone="UTC")
        scheduler.add_job(
            func=self._run_checkpoint_sync,
            trigger=CronTrigger(hour=self._hour, minute=self._minute, timezone="UTC"),
            id="audit_daily_checkpoint",
            name="Audit daily merkle-root checkpoint",
            replace_existing=True,
            misfire_grace_time=600,  # allow up to 10 min late start
        )
        scheduler.start()
        self._scheduler = scheduler
        logger.info(
            "AuditCheckpointScheduler started — daily job at %02d:%02d UTC, "
            "tenants=%d, signed=%s",
            self._hour, self._minute, len(self._tenant_ids),
            bool(self._signing_key_path),
        )

    def stop(self, wait: bool = True) -> None:
        """Stop the background scheduler gracefully."""
        if self._scheduler is not None:
            try:
                self._scheduler.shutdown(wait=wait)
            except Exception as exc:
                logger.warning("AuditCheckpointScheduler shutdown error: %s", exc)
            finally:
                self._scheduler = None
        self._app_loop = None
        logger.info("AuditCheckpointScheduler stopped")

    # ------------------------------------------------------------------
    # Job entrypoints
    # ------------------------------------------------------------------

    def _run_checkpoint_sync(self) -> None:
        """Sync wrapper called by APScheduler BackgroundScheduler.

        FIND-IRIS-CHECKPOINT-EVENTLOOP: this runs in APScheduler's own worker
        thread, which has no event loop of its own. Do NOT spin up a fresh
        `asyncio.new_event_loop()` here -- the asyncpg pool from
        `pool_getter()` is permanently bound to the application's event loop
        (captured in `start()` as `self._app_loop`) and raises a cross-loop
        RuntimeError if driven from any other loop. Instead, hand the job
        coroutine to the app loop via `run_coroutine_threadsafe()` and block
        this worker thread on the result (bounded by `_job_timeout_s`) so a
        stuck checkpoint can't wedge the scheduler thread forever.
        """
        yesterday = (datetime.now(tz=timezone.utc) - timedelta(days=1)).date()
        app_loop = self._app_loop
        if app_loop is None or not app_loop.is_running():
            logger.error(
                "AuditCheckpointScheduler: application event loop unavailable "
                "— skipping checkpoint for %s (was start() called from the "
                "app's running event loop?)",
                yesterday,
            )
            _inc_checkpoint_failure()
            return
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._run_checkpoint_async(yesterday), app_loop
            )
            future.result(timeout=self._job_timeout_s)
        except Exception as exc:
            logger.error("AuditCheckpointScheduler job failed for %s: %s", yesterday, exc)
            _inc_checkpoint_failure()

    async def _run_checkpoint_async(self, target_date: date) -> None:
        """Compute and persist checkpoints for all tenants for target_date."""
        pool = self._pool_getter()
        if pool is None:
            logger.error(
                "AuditCheckpointScheduler: pool not available — skipping checkpoint for %s",
                target_date,
            )
            _inc_checkpoint_failure()
            return

        for tenant_id in self._tenant_ids:
            try:
                result = await self._chain_service.run_daily_checkpoint(
                    target_date=target_date,
                    pool=pool,
                    tenant_id=tenant_id,
                )
                if result["chain_break_count"] > 0:
                    logger.warning(
                        "AuditCheckpointScheduler: %d chain break(s) detected for "
                        "tenant=%s date=%s — investigate audit_events integrity",
                        result["chain_break_count"], tenant_id, target_date,
                    )
                    _inc_checkpoint_failure()
                else:
                    logger.info(
                        "AuditCheckpointScheduler: checkpoint OK — "
                        "tenant=%s date=%s events=%d root=%s... signed=%s",
                        tenant_id, target_date, result["event_count"],
                        result["merkle_root"][:16], result["signed"],
                    )
            except Exception as exc:
                logger.error(
                    "AuditCheckpointScheduler: checkpoint failed for tenant=%s date=%s: %s",
                    tenant_id, target_date, exc,
                )
                _inc_checkpoint_failure()

    # ------------------------------------------------------------------
    # Manual trigger (for ops / testing)
    # ------------------------------------------------------------------

    async def run_now(self, target_date: Optional[date] = None) -> list[dict]:
        """Run the checkpoint job immediately for the given date (default: yesterday).

        Returns a list of result dicts (one per tenant).
        Intended for ops tooling and integration tests.
        """
        if target_date is None:
            target_date = (datetime.now(tz=timezone.utc) - timedelta(days=1)).date()
        pool = self._pool_getter()
        results = []
        for tenant_id in self._tenant_ids:
            result = await self._chain_service.run_daily_checkpoint(
                target_date=target_date,
                pool=pool,
                tenant_id=tenant_id,
            )
            results.append(result)
        return results
