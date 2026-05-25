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

Compliance:
    ASVS V7.3.3   — audit log integrity (tamper-evident)
    NIST AU-9/AU-10 — protection of audit information + non-repudiation
    SOC 2 CC7.2/CC7.3 — monitoring + evaluation of security events

Last updated: 2026-05-24T00:00:00+01:00
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

    Usage (in a service lifespan)::

        scheduler = AuditCheckpointScheduler(
            chain_service=audit_chain_svc,
            pool_getter=lambda: app_state.db_pool,
            tenant_ids=["00000000-0000-0000-0000-000000000000"],
            signing_key_path=Path("/run/secrets/hermes_client.key"),
            signing_spiffe_id="spiffe://yashigani.internal/hermes",
        )
        scheduler.start()
        # ... service runs ...
        scheduler.stop()

    The job runs at 00:05 UTC by default (configurable via hour/minute kwargs)
    and checkpoints *yesterday's* events.  Idempotent: re-running for the same
    date updates the existing row (ON CONFLICT DO UPDATE in the service).
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
        """
        self._chain_service = chain_service
        self._pool_getter = pool_getter
        self._tenant_ids = tenant_ids or ["00000000-0000-0000-0000-000000000000"]
        self._signing_key_path = signing_key_path
        self._signing_spiffe_id = signing_spiffe_id
        self._hour = hour
        self._minute = minute
        self._scheduler = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background scheduler.  Raises RuntimeError on failure (SOP 1)."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger
        except ImportError as exc:
            raise RuntimeError(
                "AuditCheckpointScheduler: apscheduler is required but not installed"
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
        logger.info("AuditCheckpointScheduler stopped")

    # ------------------------------------------------------------------
    # Job entrypoints
    # ------------------------------------------------------------------

    def _run_checkpoint_sync(self) -> None:
        """Sync wrapper called by APScheduler BackgroundScheduler."""
        yesterday = (datetime.now(tz=timezone.utc) - timedelta(days=1)).date()
        # Run in a fresh event loop (BackgroundScheduler thread has no loop)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self._run_checkpoint_async(yesterday))
        except Exception as exc:
            logger.error("AuditCheckpointScheduler job failed for %s: %s", yesterday, exc)
            _inc_checkpoint_failure()
        finally:
            loop.close()

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
