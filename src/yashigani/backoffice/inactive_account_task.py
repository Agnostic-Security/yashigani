"""
Yashigani Backoffice — Automated inactive-account disable task.

FedRAMP AC-2(F2) / LU-YSG-002 (v2.23.3).

Runs daily (configurable via YASHIGANI_INACTIVE_DISABLE_INTERVAL_HOURS, default 24).
Disables accounts whose last_login_at is older than YASHIGANI_INACTIVE_DISABLE_DAYS
(default 90).

Safety rail: refuses to disable more than YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT
(default 50) percent of all accounts in a single run. Logs a warning and halts
the run without disabling any accounts if the rail is exceeded.

Exemption list: YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS (comma-separated
account UUIDs) — service accounts that legitimately never log in interactively.

Break-glass accounts are NOT subject to this task. Break-glass access uses a
separate credential mechanism (see auth/break_glass.py) and its admin_accounts
row has account_tier='admin'. If the operator adds a break-glass account ID to
the exempt list, it will not be disabled. Note: break-glass accounts should
always be listed in YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS.

Operator re-enable: to re-enable an automatically-disabled account, use the
backoffice admin API: PATCH /admin/accounts/{username}/enable or the CLI:
  docker exec -it yashigani-backoffice yashigani-admin enable-account <username>
After re-enabling, the account's inactive_disabled_at column is NOT cleared
(preserves the audit trail). last_login_at is reset on next successful login.

Last updated: 2026-05-08T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import logging
import os
from typing import Optional

from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration helpers (read env at call time — not at import time)
# ---------------------------------------------------------------------------

def _threshold_days() -> int:
    raw = os.getenv("YASHIGANI_INACTIVE_DISABLE_DAYS", "90")
    try:
        val = int(raw)
        if val < 1:
            raise ValueError("must be >= 1")
        return val
    except (ValueError, TypeError):
        logger.warning(
            "YASHIGANI_INACTIVE_DISABLE_DAYS invalid (%r); using default 90", raw
        )
        return 90


def _max_percent() -> int:
    raw = os.getenv("YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT", "50")
    try:
        val = int(raw)
        if not 1 <= val <= 100:
            raise ValueError("must be 1–100")
        return val
    except (ValueError, TypeError):
        logger.warning(
            "YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT invalid (%r); using default 50", raw
        )
        return 50


def _exempt_ids() -> frozenset[str]:
    raw = os.getenv("YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS", "")
    ids = {uid.strip() for uid in raw.split(",") if uid.strip()}
    return frozenset(ids)


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

async def run_inactive_account_disable() -> None:
    """
    Identify and disable inactive accounts.

    Safety guarantees:
    - Idempotent: already-disabled accounts are never re-processed.
    - Halt-on-rail: if the candidate set exceeds max_percent of total accounts,
      logs a warning, fires an alert, and exits without any disables.
    - Exempt: accounts in the exempt list are skipped unconditionally.
    - Audit: emits one InactiveAccountDisabledEvent per account disabled.
    """
    from yashigani.audit.schema import InactiveAccountDisabledEvent

    auth_service = backoffice_state.auth_service
    audit_writer = backoffice_state.audit_writer

    if auth_service is None:
        logger.warning(
            "inactive_account_task: auth_service not ready — skipping run"
        )
        return

    threshold_days = _threshold_days()
    max_pct = _max_percent()
    exempt = _exempt_ids()

    logger.info(
        "inactive_account_task: starting run (threshold=%d days, max_pct=%d%%, exempt=%d ids)",
        threshold_days,
        max_pct,
        len(exempt),
    )

    # --- Gather candidates --------------------------------------------------
    try:
        candidates = await auth_service.list_inactive_accounts(
            threshold_days=threshold_days,
            exempt_ids=exempt,
        )
    except Exception as exc:
        logger.exception(
            "inactive_account_task: failed to list inactive accounts: %s", exc
        )
        return

    if not candidates:
        logger.info("inactive_account_task: no inactive accounts found — nothing to do")
        return

    # --- Safety rail --------------------------------------------------------
    try:
        total = await auth_service.total_account_count()
    except Exception as exc:
        logger.exception(
            "inactive_account_task: could not determine total account count — halting run: %s",
            exc,
        )
        return

    if total > 0:
        candidate_pct = (len(candidates) / total) * 100
        if candidate_pct > max_pct:
            logger.warning(
                "inactive_account_task: SAFETY RAIL TRIGGERED — %d candidates (%.1f%%) "
                "exceeds YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT=%d%%. "
                "No accounts disabled. Operator investigation required.",
                len(candidates),
                candidate_pct,
                max_pct,
            )
            _fire_safety_rail_alert(len(candidates), candidate_pct, max_pct, total)
            return

    # --- Disable each candidate + emit audit --------------------------------
    disabled_count = 0
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    for record in candidates:
        try:
            ok = await auth_service.disable_inactive(account_id=record.account_id)
        except Exception as exc:
            logger.exception(
                "inactive_account_task: failed to disable account %s (%s): %s",
                record.username,
                record.account_id,
                exc,
            )
            continue

        if not ok:
            # Already disabled by another path (operator action, race) — skip
            logger.debug(
                "inactive_account_task: account %s already disabled — skipping audit emit",
                record.username,
            )
            continue

        disabled_count += 1

        # Compute days inactive
        if record.last_login_at is not None:
            last_login_dt = datetime.datetime.fromtimestamp(
                record.last_login_at, tz=datetime.timezone.utc
            )
            days_inactive = (now_utc - last_login_dt).days
            last_login_str = last_login_dt.isoformat()
        else:
            days_inactive = 0
            last_login_str = ""

        logger.info(
            "inactive_account_task: disabled account %s (id=%s, days_inactive=%d)",
            record.username,
            record.account_id,
            days_inactive,
        )

        # Emit AU-3.F audit event
        if audit_writer is not None:
            try:
                event = InactiveAccountDisabledEvent(
                    disabled_account_id=record.account_id,
                    disabled_username=record.username,
                    source_ip="system",
                    target_resource=f"admin_accounts/{record.account_id}",
                    outcome="success",
                    days_inactive=days_inactive,
                    threshold_days=threshold_days,
                    last_login_at=last_login_str,
                )
                audit_writer.write(event)
            except Exception as exc:
                logger.exception(
                    "inactive_account_task: audit emit failed for account %s: %s",
                    record.account_id,
                    exc,
                )

    logger.info(
        "inactive_account_task: run complete — %d account(s) disabled out of %d candidates",
        disabled_count,
        len(candidates),
    )


def _fire_safety_rail_alert(
    candidate_count: int,
    candidate_pct: float,
    max_pct: int,
    total: int,
) -> None:
    """
    Fire an alert via the existing alert infrastructure when the safety rail
    is triggered. Non-blocking — errors are logged, not raised.
    """
    try:
        from yashigani.alerts import get_dispatcher
        from yashigani.alerts.base import AlertPayload

        dispatcher = get_dispatcher()
        if not dispatcher.has_sinks:
            return

        import asyncio

        payload = AlertPayload(
            severity="warning",
            title="Yashigani — Inactive Account Disable Safety Rail Triggered",
            body=(
                f"The automated inactive-account disable task found {candidate_count} "
                f"candidate accounts ({candidate_pct:.1f}% of {total} total) which "
                f"exceeds the configured maximum of {max_pct}%. "
                "No accounts were disabled. Operator investigation is required. "
                "To adjust: set YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT or "
                "YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS."
            ),
            event_id=f"inactive-disable-safety-rail-{datetime.date.today().isoformat()}",
            source_component="yashigani.backoffice.inactive_account_task",
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(dispatcher.dispatch(payload))
            else:
                loop.run_until_complete(dispatcher.dispatch(payload))
        except Exception as exc:
            logger.error("inactive_account_task: alert dispatch failed: %s", exc)
    except Exception as exc:
        logger.error("inactive_account_task: could not fire safety-rail alert: %s", exc)
