"""
Yashigani Agent — PSK token auto-rotation (F-09).

Provides:
  rotate_agent_token(agent_id)  — immediate rotation with grace-period revocation.
  AgentTokenRotationScheduler   — optional cron-based scheduled rotation.

Grace period (default 1 hour):
  After a new token is generated and pushed to the KMS, the old token hash
  is stored under a grace key in Redis.  The existing verify_token path
  accepts both old and new tokens during the grace window.  After the window
  expires the old token is silently dropped.

Redis keys (db/3):
  agent:token:{agent_id}           — bcrypt hash of the current token
  agent:token:grace:{agent_id}     — bcrypt hash of the previous token (grace period)
  agent:reg:{agent_id}             — agent registration hash (fields extended below)

Additional fields written to agent:reg:{agent_id}:
  token_last_rotated               — ISO 8601 timestamp of last rotation
  token_rotation_schedule          — cron expression or empty string
"""
from __future__ import annotations

import datetime
import logging
import secrets
import threading
from typing import Any, Optional

import bcrypt

logger = logging.getLogger(__name__)

_BCRYPT_COST = 12
_GRACE_PERIOD_DEFAULT_HOURS = 1
_MIN_INTERVAL_HOURS = 1


# ---------------------------------------------------------------------------
# Core rotation function
# ---------------------------------------------------------------------------

def rotate_agent_token(
    agent_id: str,
    registry,                        # AgentRegistry instance
    kms_provider=None,               # Optional KSMProvider — stores new token value
    audit_writer=None,               # Optional audit writer
    admin_account: str = "__system__",
    grace_period_hours: int = _GRACE_PERIOD_DEFAULT_HOURS,
) -> str:
    """
    Generate a new 256-bit PSK for ``agent_id``, push it to the KMS (if a
    provider is given), and schedule revocation of the old token after the
    grace period.

    Parameters
    ----------
    agent_id:
        Target agent identifier.
    registry:
        An ``AgentRegistry`` instance.  Used to store the new token hash and
        record ``token_last_rotated`` on the registration record.
    kms_provider:
        Optional ``KSMProvider``.  When provided the new plaintext token is
        stored as ``agents/{agent_id}/psk`` (or updated via ``rotate_secret``).
    audit_writer:
        Optional audit writer.  When provided an ``AgentTokenRotatedEvent``
        is emitted.
    admin_account:
        Identity of the actor performing the rotation.  Use ``"__system__"``
        for scheduler-driven rotations.
    grace_period_hours:
        How long (in hours) the previous token hash remains valid.

    Returns
    -------
    str
        The new plaintext PSK token (64-char hex).  The caller must deliver
        this securely to the agent — it is never stored in plaintext again.

    Raises
    ------
    ValueError
        If the agent does not exist.
    """
    if registry.get(agent_id) is None:
        raise ValueError(f"Agent {agent_id!r} not found in registry.")

    # --- 1. Preserve old hash under grace key ---
    r = registry._r
    current_hash_raw = r.get(f"agent:token:{agent_id}")
    if current_hash_raw:
        grace_key = f"agent:token:grace:{agent_id}"
        grace_ttl = int(grace_period_hours * 3600)
        if grace_ttl > 0:
            r.set(grace_key, current_hash_raw, ex=grace_ttl)
        logger.info(
            "token_rotation: old token for %s stored in grace key (TTL=%dh)",
            agent_id, grace_period_hours,
        )

    # --- 2. Generate and store new token ---
    plaintext_token = secrets.token_bytes(32).hex()
    new_hash = bcrypt.hashpw(
        plaintext_token.encode("utf-8"),
        bcrypt.gensalt(rounds=_BCRYPT_COST),
    ).decode("utf-8")

    token_key = f"agent:token:{agent_id}"
    r.set(token_key, new_hash.encode("utf-8"))

    # --- 3. Push to KMS ---
    if kms_provider is not None:
        kms_key = f"agents/{agent_id}/psk"
        try:
            try:
                kms_provider.rotate_secret(kms_key, plaintext_token)
                logger.info(
                    "token_rotation: pushed new token for %s to KMS (%s) via rotate_secret",
                    agent_id, kms_provider.provider_name,
                )
            except Exception:
                kms_provider.set_secret(kms_key, plaintext_token)
                logger.info(
                    "token_rotation: pushed new token for %s to KMS (%s) via set_secret",
                    agent_id, kms_provider.provider_name,
                )
        except Exception as exc:
            logger.error(
                "token_rotation: KMS push failed for %s — %s (rotation still committed to Redis)",
                agent_id, exc,
            )

    # --- 4. Record rotation timestamp on agent registration ---
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    reg_key = f"agent:reg:{agent_id}"
    r.hset(reg_key, b"token_last_rotated", now.isoformat().encode("utf-8"))
    logger.info("token_rotation: %s token rotated by %s", agent_id, admin_account)

    # --- 5. Audit ---
    if audit_writer is not None:
        try:
            from yashigani.audit.schema import AgentTokenRotatedEvent
            audit_writer.write(AgentTokenRotatedEvent(
                agent_id=agent_id,
                admin_account=admin_account,
            ))
        except Exception as exc:
            logger.error(
                "token_rotation: failed to write AgentTokenRotatedEvent for %s — %s",
                agent_id, exc,
            )

    return plaintext_token


# ---------------------------------------------------------------------------
# Grace-period token verification helper
# ---------------------------------------------------------------------------

def verify_token_with_grace(agent_id: str, registry, plaintext_token: str) -> bool:
    """
    Verify ``plaintext_token`` against both the current and grace-period hashes.

    Intended to replace or wrap ``AgentRegistry.verify_token`` during the
    grace window.  Returns True on match, False otherwise.  Fail-closed.
    """
    try:
        r = registry._r
        candidate = plaintext_token.encode("utf-8")

        # Check primary token
        primary_raw = r.get(f"agent:token:{agent_id}")
        if primary_raw:
            primary_hash = primary_raw if isinstance(primary_raw, bytes) else primary_raw.encode("utf-8")
            if bcrypt.checkpw(candidate, primary_hash):
                registry._update_last_seen(agent_id)
                return True

        # Check grace token
        grace_raw = r.get(f"agent:token:grace:{agent_id}")
        if grace_raw:
            grace_hash = grace_raw if isinstance(grace_raw, bytes) else grace_raw.encode("utf-8")
            if bcrypt.checkpw(candidate, grace_hash):
                logger.warning(
                    "verify_token_with_grace: %s authenticated with grace-period token",
                    agent_id,
                )
                registry._update_last_seen(agent_id)
                return True

        return False
    except Exception as exc:
        logger.error("verify_token_with_grace error for %s: %s", agent_id, exc)
        return False


# ---------------------------------------------------------------------------
# Cron-based scheduled rotation
# ---------------------------------------------------------------------------

def _validate_cron(expr: str) -> None:
    """Validate cron expression and enforce minimum 1-hour interval."""
    try:
        from apscheduler.triggers.cron import CronTrigger
    except ImportError as exc:
        raise ImportError(
            "apscheduler>=3.10 is required for scheduled token rotation. "
            "Install with: pip install 'apscheduler>=3.10'"
        ) from exc
    try:
        trigger = CronTrigger.from_crontab(expr)
    except Exception as exc:
        raise ValueError(f"Invalid cron expression {expr!r}: {exc}") from exc
    import datetime as _dt
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    t1 = trigger.get_next_fire_time(None, now)
    if t1 is None:
        raise ValueError(f"Cron expression {expr!r} never fires.")
    t2 = trigger.get_next_fire_time(t1, t1)
    if t2 is not None:
        delta = t2 - t1
        if delta.total_seconds() < _MIN_INTERVAL_HOURS * 3600:
            raise ValueError(
                f"Cron expression {expr!r} fires more frequently than every "
                f"{_MIN_INTERVAL_HOURS} hour(s). Minimum interval enforced."
            )


class AgentTokenRotationScheduler:
    """
    Cron-based PSK token auto-rotation for a single agent.

    Example::

        scheduler = AgentTokenRotationScheduler(
            agent_id="agnt_abc123",
            registry=agent_registry,
            cron_expr="0 3 * * 0",   # weekly Sunday 03:00 UTC
            kms_provider=kms,
            audit_writer=audit,
        )
        scheduler.start()

    The cron expression is also persisted to Redis so the value is visible
    to operators via ``GET agent:reg:{agent_id}`` and the backoffice API.
    """

    def __init__(
        self,
        agent_id: str,
        registry,
        cron_expr: str,
        kms_provider=None,
        audit_writer=None,
        grace_period_hours: int = _GRACE_PERIOD_DEFAULT_HOURS,
    ) -> None:
        _validate_cron(cron_expr)
        self._agent_id = agent_id
        self._registry = registry
        self._cron_expr = cron_expr
        self._kms_provider = kms_provider
        self._audit_writer = audit_writer
        self._grace_period_hours = grace_period_hours
        self._scheduler: Optional[Any] = None
        self._last_token: Optional[str] = None

        # Persist schedule to Redis
        self._write_schedule(cron_expr)

    # -- Public API ----------------------------------------------------------

    def start(self) -> None:
        """Start the background cron scheduler."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger
        except ImportError as exc:
            raise ImportError(
                "apscheduler>=3.10 is required. "
                "Install with: pip install 'apscheduler>=3.10'"
            ) from exc

        self._scheduler = BackgroundScheduler()
        trigger = CronTrigger.from_crontab(self._cron_expr)
        self._scheduler.add_job(
            self._rotate_now,
            trigger=trigger,
            id=f"agent_token_rotation_{self._agent_id}",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(
            "AgentTokenRotationScheduler: started for %s (schedule=%s)",
            self._agent_id, self._cron_expr,
        )

    def stop(self) -> None:
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
        logger.info(
            "AgentTokenRotationScheduler: stopped for %s", self._agent_id
        )

    def trigger_now(self) -> str:
        """
        Trigger an immediate out-of-band rotation.
        Returns the new plaintext token.
        """
        logger.info(
            "AgentTokenRotationScheduler: manual rotation triggered for %s",
            self._agent_id,
        )
        return self._rotate_now()

    def set_schedule(self, cron_expr: str) -> None:
        """Update the cron expression (validates before accepting)."""
        _validate_cron(cron_expr)
        self._cron_expr = cron_expr
        self._write_schedule(cron_expr)
        if self._scheduler:
            try:
                from apscheduler.triggers.cron import CronTrigger
                trigger = CronTrigger.from_crontab(cron_expr)
                self._scheduler.reschedule_job(
                    f"agent_token_rotation_{self._agent_id}",
                    trigger=trigger,
                )
            except Exception as exc:
                logger.error(
                    "AgentTokenRotationScheduler: reschedule failed for %s — %s",
                    self._agent_id, exc,
                )
        logger.info(
            "AgentTokenRotationScheduler: schedule updated to %r for %s",
            cron_expr, self._agent_id,
        )

    # -- Internal ------------------------------------------------------------

    def _rotate_now(self) -> str:
        token = rotate_agent_token(
            agent_id=self._agent_id,
            registry=self._registry,
            kms_provider=self._kms_provider,
            audit_writer=self._audit_writer,
            admin_account="__scheduler__",
            grace_period_hours=self._grace_period_hours,
        )
        self._last_token = token
        return token

    def _write_schedule(self, cron_expr: str) -> None:
        """Persist the rotation schedule to the agent registration hash in Redis."""
        try:
            reg_key = f"agent:reg:{self._agent_id}"
            self._registry._r.hset(
                reg_key,
                b"token_rotation_schedule",
                cron_expr.encode("utf-8"),
            )
        except Exception as exc:
            logger.warning(
                "AgentTokenRotationScheduler: could not persist schedule for %s — %s",
                self._agent_id, exc,
            )
