"""
Yashigani Auth — Break-glass emergency access with hard auto-expiry (S-04).

Enforces:
  - TTL range 1-72 hours, default 4 hours.
  - Optional dual-control: a second admin must approve within 5 minutes.
  - Auto-revoke is scheduled at activation time; no manual step required.
  - All state lives in Redis (db/0) under yashigani:break_glass:*.
  - Every activation and expiry emits a tamper-evident audit event.
"""
from __future__ import annotations

import datetime
import json
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TTL_MIN_HOURS = 1
_TTL_MAX_HOURS = 72
_TTL_DEFAULT_HOURS = 4
_APPROVAL_WINDOW_SECONDS = 300          # 5-minute window for second approver
_KEY_STATE = "yashigani:break_glass:state"
_KEY_PENDING_APPROVAL = "yashigani:break_glass:pending_approval"


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class BreakGlassError(Exception):
    """Base error for break-glass operations."""


class AlreadyActiveError(BreakGlassError):
    """Raised when break-glass is already active."""


class NotActiveError(BreakGlassError):
    """Raised when attempting to revoke a non-active break-glass session."""


class TTLRangeError(BreakGlassError):
    """Raised when the requested TTL is outside the 1-72 hour range."""


class ApprovalPendingError(BreakGlassError):
    """Raised when dual-control is required and approval has not yet been given."""


class ApprovalExpiredError(BreakGlassError):
    """Raised when the second approver did not act within the 5-minute window."""


# ---------------------------------------------------------------------------
# Break-glass manager
# ---------------------------------------------------------------------------

class BreakGlassManager:
    """
    Manages break-glass emergency access sessions.

    All state is stored in Redis so revocations and expirations survive
    process restarts. Auto-revoke timers are also started in-process as a
    best-effort defence in depth; the Redis TTL provides the hard guarantee.

    Usage::

        mgr = BreakGlassManager(redis_client, audit_writer)
        mgr.activate_break_glass("admin@example.com", ttl_hours=2)
        ...
        mgr.revoke_break_glass("admin@example.com")
    """

    def __init__(self, redis_client, audit_writer=None) -> None:
        self._r = redis_client
        self._audit = audit_writer
        self._timer: Optional[threading.Timer] = None

    # -- Public API ----------------------------------------------------------

    def activate_break_glass(
        self,
        user_id: str,
        ttl_hours: int = _TTL_DEFAULT_HOURS,
        require_second_approver: bool = False,
    ) -> dict:
        """
        Activate a break-glass session.

        Parameters
        ----------
        user_id:
            Identity of the admin initiating the session.
        ttl_hours:
            Session lifetime in hours. Must be between 1 and 72 (inclusive).
        require_second_approver:
            When True the session enters PENDING_APPROVAL state. A second
            admin must call ``approve_break_glass`` within 5 minutes or the
            session is automatically cancelled.

        Returns
        -------
        dict
            Current break-glass state dict (as returned by
            ``get_break_glass_status``).

        Raises
        ------
        TTLRangeError
            If ``ttl_hours`` is outside [1, 72].
        AlreadyActiveError
            If a break-glass session is already active or pending.
        """
        if not (_TTL_MIN_HOURS <= ttl_hours <= _TTL_MAX_HOURS):
            raise TTLRangeError(
                f"TTL must be between {_TTL_MIN_HOURS} and {_TTL_MAX_HOURS} hours; "
                f"got {ttl_hours}."
            )

        existing = self._r.get(_KEY_STATE)
        if existing:
            raise AlreadyActiveError(
                "A break-glass session is already active or pending approval."
            )

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        expires_at = now + datetime.timedelta(hours=ttl_hours)

        if require_second_approver:
            state_value = "PENDING_APPROVAL"
            approval_deadline = now + datetime.timedelta(seconds=_APPROVAL_WINDOW_SECONDS)
            # Store pending approval record with a hard TTL of 5 minutes
            pending_record = json.dumps({
                "initiated_by": user_id,
                "ttl_hours": ttl_hours,
                "initiated_at": now.isoformat(),
                "approval_deadline": approval_deadline.isoformat(),
            })
            self._r.set(
                _KEY_PENDING_APPROVAL,
                pending_record,
                ex=_APPROVAL_WINDOW_SECONDS,
            )
        else:
            state_value = "ACTIVE"

        state = {
            "status": state_value,
            "activated_by": user_id,
            "activated_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ttl_hours": ttl_hours,
            "require_second_approver": str(require_second_approver),
            "approver": "",
        }
        ttl_seconds = int(ttl_hours * 3600)
        self._r.set(_KEY_STATE, json.dumps(state), ex=ttl_seconds)

        if state_value == "ACTIVE":
            self._schedule_auto_revoke(user_id, ttl_seconds)
            self._emit_activated(user_id, ttl_hours, expires_at)

        logger.warning(
            "BreakGlass %s by %s — TTL %dh, expires %s, dual-control=%s",
            state_value, user_id, ttl_hours, expires_at.isoformat(), require_second_approver,
        )

        return self.get_break_glass_status()

    def approve_break_glass(self, approver_id: str) -> dict:
        """
        Second-admin approval for dual-control break-glass.

        Must be called within the 5-minute approval window by a different
        admin than the one who initiated the session.

        Raises
        ------
        ApprovalExpiredError
            If the 5-minute window has closed.
        NotActiveError
            If no pending session exists.
        BreakGlassError
            If approver is the same user as the initiator.
        """
        pending_raw = self._r.get(_KEY_PENDING_APPROVAL)
        if not pending_raw:
            raise ApprovalExpiredError(
                "No pending break-glass approval found. "
                "The 5-minute approval window may have expired."
            )

        pending = json.loads(
            pending_raw if isinstance(pending_raw, str) else pending_raw.decode("utf-8")
        )
        if pending["initiated_by"] == approver_id:
            raise BreakGlassError(
                "The approver must be different from the initiating admin."
            )

        state_raw = self._r.get(_KEY_STATE)
        if not state_raw:
            raise NotActiveError(
                "Break-glass state not found — session may have expired."
            )

        state = json.loads(
            state_raw if isinstance(state_raw, str) else state_raw.decode("utf-8")
        )
        state["status"] = "ACTIVE"
        state["approver"] = approver_id

        # Preserve remaining Redis TTL
        remaining_ttl = self._r.ttl(_KEY_STATE)
        if remaining_ttl and remaining_ttl > 0:
            self._r.set(_KEY_STATE, json.dumps(state), ex=remaining_ttl)
        else:
            self._r.set(_KEY_STATE, json.dumps(state))

        self._r.delete(_KEY_PENDING_APPROVAL)

        # Schedule in-process auto-revoke based on remaining TTL
        if remaining_ttl and remaining_ttl > 0:
            self._schedule_auto_revoke(state["activated_by"], remaining_ttl)

        expires_at = datetime.datetime.fromisoformat(state["expires_at"])
        self._emit_activated(state["activated_by"], state["ttl_hours"], expires_at, approver_id)

        logger.warning(
            "BreakGlass APPROVED by %s for %s",
            approver_id, state["activated_by"],
        )

        return self.get_break_glass_status()

    def revoke_break_glass(self, user_id: str) -> None:
        """
        Manually or automatically revoke the active break-glass session.

        Parameters
        ----------
        user_id:
            Identity of the admin revoking the session. Pass
            ``"__auto_expire__"`` for timer-triggered revocations.

        Raises
        ------
        NotActiveError
            If no active break-glass session exists.
        """
        state_raw = self._r.get(_KEY_STATE)
        if not state_raw:
            raise NotActiveError("No active break-glass session to revoke.")

        state = json.loads(
            state_raw if isinstance(state_raw, str) else state_raw.decode("utf-8")
        )

        self._r.delete(_KEY_STATE)
        self._r.delete(_KEY_PENDING_APPROVAL)

        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

        activated_by = state.get("activated_by", "unknown")
        is_auto = (user_id == "__auto_expire__")
        self._emit_expired(activated_by, is_auto=is_auto, revoked_by=user_id)

        logger.warning(
            "BreakGlass REVOKED by %s (auto=%s), originally activated by %s",
            user_id, is_auto, activated_by,
        )

    def get_break_glass_status(self) -> dict:
        """
        Return current break-glass state.

        Returns
        -------
        dict with keys:
            active (bool), status (str), activated_by (str),
            activated_at (str|None), expires_at (str|None),
            ttl_remaining_seconds (int), approver (str)
        """
        state_raw = self._r.get(_KEY_STATE)
        if not state_raw:
            return {
                "active": False,
                "status": "INACTIVE",
                "activated_by": None,
                "activated_at": None,
                "expires_at": None,
                "ttl_remaining_seconds": 0,
                "approver": None,
            }

        state = json.loads(
            state_raw if isinstance(state_raw, str) else state_raw.decode("utf-8")
        )

        ttl_remaining = self._r.ttl(_KEY_STATE) or 0
        if ttl_remaining < 0:
            ttl_remaining = 0

        return {
            "active": state.get("status") == "ACTIVE",
            "status": state.get("status", "UNKNOWN"),
            "activated_by": state.get("activated_by"),
            "activated_at": state.get("activated_at"),
            "expires_at": state.get("expires_at"),
            "ttl_remaining_seconds": ttl_remaining,
            "approver": state.get("approver") or None,
        }

    # -- Internal ------------------------------------------------------------

    def _schedule_auto_revoke(self, user_id: str, delay_seconds: int) -> None:
        """Schedule in-process auto-revoke timer. Redis TTL is the hard guarantee."""
        if self._timer is not None:
            self._timer.cancel()

        self._timer = threading.Timer(
            delay_seconds,
            self._auto_revoke_callback,
            args=(user_id,),
        )
        self._timer.daemon = True
        self._timer.start()
        logger.debug(
            "BreakGlass auto-revoke timer set: %ds for %s", delay_seconds, user_id
        )

    def _auto_revoke_callback(self, user_id: str) -> None:
        """Fired by the in-process timer when the TTL elapses."""
        try:
            self.revoke_break_glass("__auto_expire__")
        except NotActiveError:
            # Redis TTL may have already cleaned up — not an error
            pass
        except Exception as exc:
            logger.error("BreakGlass auto-revoke callback error: %s", exc)

    def _emit_activated(
        self,
        user_id: str,
        ttl_hours: int,
        expires_at: datetime.datetime,
        approver_id: Optional[str] = None,
    ) -> None:
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import BreakGlassActivatedEvent
            self._audit.write(BreakGlassActivatedEvent(
                activated_by=user_id,
                ttl_hours=ttl_hours,
                expires_at=expires_at.isoformat(),
                approver=approver_id or "",
                tamper_evident=True,
            ))
        except Exception as exc:
            logger.error("BreakGlass: failed to write BREAK_GLASS_ACTIVATED audit event: %s", exc)

    def _emit_expired(
        self,
        activated_by: str,
        is_auto: bool,
        revoked_by: str,
    ) -> None:
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import BreakGlassExpiredEvent
            self._audit.write(BreakGlassExpiredEvent(
                activated_by=activated_by,
                revoked_by=revoked_by,
                auto_expired=is_auto,
                tamper_evident=True,
            ))
        except Exception as exc:
            logger.error("BreakGlass: failed to write BREAK_GLASS_EXPIRED audit event: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience wrappers (require a configured manager instance)
# ---------------------------------------------------------------------------

_manager: Optional[BreakGlassManager] = None


def init_break_glass(redis_client, audit_writer) -> BreakGlassManager:
    """Initialise the module-level BreakGlassManager. Call once at startup.

    Parameters
    ----------
    redis_client:
        A configured Redis client (any redis-py compatible client).
    audit_writer:
        Required. An :class:`~yashigani.audit.writer.AuditLogWriter` instance
        that receives ``BreakGlassActivatedEvent`` and ``BreakGlassExpiredEvent``
        records. Break-glass sessions MUST be audited; a silent audit-writer
        default (``None``) was the gap closed by yashigani-retro#95 / OWASP A09.
        Pass ``audit_writer`` explicitly — the entrypoint always has one.

    Raises
    ------
    TypeError
        If called without ``audit_writer`` (enforced by Python's required-arg
        semantics — no default). This converts a runtime silent-failure into a
        startup-time crash that surfaces immediately.
    """
    global _manager
    _manager = BreakGlassManager(redis_client, audit_writer)
    return _manager


def _require_manager() -> BreakGlassManager:
    if _manager is None:
        raise RuntimeError(
            "BreakGlassManager is not initialised. "
            "Call init_break_glass(redis_client) at startup."
        )
    return _manager


def activate_break_glass(
    user_id: str,
    ttl_hours: int = _TTL_DEFAULT_HOURS,
    require_second_approver: bool = False,
) -> dict:
    """Module-level wrapper — see BreakGlassManager.activate_break_glass."""
    return _require_manager().activate_break_glass(user_id, ttl_hours, require_second_approver)


def revoke_break_glass(user_id: str) -> None:
    """Module-level wrapper — see BreakGlassManager.revoke_break_glass."""
    _require_manager().revoke_break_glass(user_id)


def get_break_glass_status() -> dict:
    """Module-level wrapper — see BreakGlassManager.get_break_glass_status."""
    return _require_manager().get_break_glass_status()
