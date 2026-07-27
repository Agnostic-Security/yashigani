"""
Yashigani KSM — Rotation scheduler.
Autonomous cron-based secret rotation with retry and manual trigger support.
"""
from __future__ import annotations

import logging
import secrets
import threading
from collections.abc import Callable
from typing import Any, Optional

from yashigani.kms.base import KSMProvider, ProviderError, RotationError

logger = logging.getLogger(__name__)

_MIN_INTERVAL_HOURS = 1
_RETRY_DELAYS_SECONDS = [300, 300, 300]  # 3 retries × 5 min
_NEW_SECRET_HEX_BYTES = 32  # 64-char hex string


def _import_apscheduler():
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        return BackgroundScheduler, CronTrigger
    except ImportError as exc:
        raise ImportError(
            "apscheduler>=3.10 is required for KSMRotationScheduler. "
            "Install with: pip install 'apscheduler>=3.10'"
        ) from exc


def _validate_cron(expr: str) -> None:
    """Validate cron expression and enforce minimum 1-hour interval."""
    BackgroundScheduler, CronTrigger = _import_apscheduler()
    try:
        trigger = CronTrigger.from_crontab(expr)
    except Exception as exc:
        raise ValueError(f"Invalid cron expression '{expr}': {exc}") from exc

    # Fire twice to check the interval between triggers
    import datetime
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    t1 = trigger.get_next_fire_time(None, now)
    if t1 is None:
        raise ValueError(f"Cron expression '{expr}' never fires")
    t2 = trigger.get_next_fire_time(t1, t1)
    if t2 is not None:
        delta = t2 - t1
        if delta.total_seconds() < _MIN_INTERVAL_HOURS * 3600:
            raise ValueError(
                f"Cron expression '{expr}' fires more frequently than every "
                f"{_MIN_INTERVAL_HOURS} hour(s). Minimum interval enforced."
            )


class KSMRotationScheduler:
    """
    Schedules autonomous secret rotation via APScheduler.

    Usage::

        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="production/db-password",
            cron_expr="0 2 * * *",   # daily at 02:00
            on_event=on_event_handler,
        )
        scheduler.start()
        # ...
        scheduler.stop()

    ``on_event`` is called as ``on_event(name, data)`` where ``name`` is one
    of ``KSM_ROTATION_SUCCESS`` / ``KSM_ROTATION_FAILURE`` /
    ``KSM_ROTATION_CRITICAL`` and ``data`` is a plain dict of event fields.
    Do NOT pass an ``AuditLogWriter.write`` bound method directly here —
    ``write()`` expects a single ``AuditEvent`` instance, not a
    ``(str, dict)`` pair, and will ``AttributeError`` the first time it tries
    to treat the name string as an event object (YSG-RISK-153). Wrap it in an
    adapter that constructs the correct ``KsmRotationEvent`` dataclass first
    — see ``backoffice/entrypoint.py::_make_ksm_rotation_event_handler`` for
    the reference implementation, which also updates the
    ``kms_rotations_total`` counter and ``kms_rotation_last_success_timestamp``
    gauge.
    """

    def __init__(
        self,
        provider: KSMProvider,
        secret_key: str,
        cron_expr: str,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ) -> None:
        _validate_cron(cron_expr)
        self._provider = provider
        self._secret_key = secret_key
        self._cron_expr = cron_expr
        self._on_event = on_event or (lambda name, data: None)
        self._lock = threading.Lock()
        self._scheduler: Optional[Any] = None

    # -- Public API ----------------------------------------------------------

    def start(self) -> None:
        """Start the background cron scheduler."""
        BackgroundScheduler, CronTrigger = _import_apscheduler()
        self._scheduler = BackgroundScheduler()
        trigger = CronTrigger.from_crontab(self._cron_expr)
        self._scheduler.add_job(
            self._rotate_with_retry,
            trigger=trigger,
            id="ksm_rotation",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info("KSM rotation scheduler started (schedule=%s)", self._cron_expr)

    def stop(self) -> None:
        """Cleanly shut down the scheduler."""
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
        logger.info("KSM rotation scheduler stopped")

    def trigger_now(self) -> None:
        """Trigger an immediate out-of-band rotation (manual)."""
        logger.info("Manual KSM rotation triggered for key '%s'", self._secret_key)
        self._rotate(rotation_type="manual")

    def set_schedule(self, cron_expr: str) -> None:
        """Update the cron expression. Validates before accepting."""
        _validate_cron(cron_expr)
        self._cron_expr = cron_expr
        if self._scheduler:
            _, CronTrigger = _import_apscheduler()
            trigger = CronTrigger.from_crontab(cron_expr)
            self._scheduler.reschedule_job("ksm_rotation", trigger=trigger)
        logger.info("KSM rotation schedule updated to '%s'", cron_expr)

    # -- Internal ------------------------------------------------------------

    def _rotate_with_retry(self) -> None:
        """Called by scheduler. Retries up to 3 times before emitting CRITICAL."""
        for attempt, delay in enumerate(_RETRY_DELAYS_SECONDS, start=1):
            try:
                self._rotate(rotation_type="scheduled")
                return
            except (RotationError, ProviderError) as exc:
                logger.warning(
                    "KSM rotation attempt %d/%d failed for '%s': %s",
                    attempt, len(_RETRY_DELAYS_SECONDS), self._secret_key, exc,
                )
                if attempt < len(_RETRY_DELAYS_SECONDS):
                    import time
                    time.sleep(delay)

        logger.error(
            "KSM rotation CRITICAL: all retries exhausted for '%s'",
            self._secret_key,
        )
        self._on_event("KSM_ROTATION_CRITICAL", {
            "secret_key": self._secret_key,
            "provider": self._provider.provider_name,
            "outcome": "critical",
        })

    def _rotate(self, rotation_type: str) -> None:
        """Core rotation procedure — thread-safe via lock."""
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            logger.warning(
                "KSM rotation skipped: rotation already in progress for '%s'",
                self._secret_key,
            )
            return

        try:
            new_value = secrets.token_hex(_NEW_SECRET_HEX_BYTES)
            version = self._provider.rotate_secret(self._secret_key, new_value)

            # Validate the new value is readable
            retrieved = self._provider.get_secret(self._secret_key)
            if retrieved != new_value:
                raise RotationError(
                    "Post-rotation validation failed: retrieved value does not match"
                )

            logger.info(
                "KSM rotation SUCCESS for '%s' (type=%s, version=%s)",
                self._secret_key, rotation_type, version,
            )
            self._on_event("KSM_ROTATION_SUCCESS", {
                "secret_key": self._secret_key,
                "provider": self._provider.provider_name,
                "outcome": "success",
                "rotation_type": rotation_type,
                "new_version": version,
            })
        except Exception:
            self._on_event("KSM_ROTATION_FAILURE", {
                "secret_key": self._secret_key,
                "provider": self._provider.provider_name,
                "outcome": "failure",
                "rotation_type": rotation_type,
            })
            raise
        finally:
            del new_value  # clear from local scope
            self._lock.release()
