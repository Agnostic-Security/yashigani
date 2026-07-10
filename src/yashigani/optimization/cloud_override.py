"""Cloud-LLM risk-accepted override (#25) — dual-admin, justified, TTL'd break-glass.

A customer with a signed cloud-provider agreement who explicitly accepts the
OptimizationEngine's P1-P9 data-residency/sensitivity risk can have an admin
ALLOW a SPECIFIC cloud LLM to be used despite the engine's local-forcing
(including P1 CONFIDENTIAL/RESTRICTED -> local). This OVERRIDES ONLY the
cloud-vs-local routing for the named LLM — it does NOT touch authentication,
RBAC, or prompt-injection/credential-exfil inspection, which stay fully enforced.

Controls (mirrors auth/break_glass.py, separate Redis namespace):
  - DUAL-ADMIN: a proposer initiates; a DIFFERENT admin must approve within a
    5-minute window. No single-admin path.
  - MANDATORY justification: free text (ticket #, contract #, CEO email, …) is
    required at proposal time and recorded in every audit event.
  - TTL auto-expiry: 1-72h (default 4h); Redis TTL is the hard guarantee.
  - Names the SPECIFIC cloud provider+model the grant permits.
  - Heavy audit on propose / approve / revoke / expire.

State lives in Redis (the gateway engine reads it live to honour the grant).
"""
from __future__ import annotations

import datetime
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_TTL_MIN_HOURS = 1
_TTL_MAX_HOURS = 72
_TTL_DEFAULT_HOURS = 4
_APPROVAL_WINDOW_SECONDS = 300
_KEY_STATE = "yashigani:cloud_override:state"
_KEY_PENDING = "yashigani:cloud_override:pending"


class CloudOverrideError(Exception):
    """Base error for cloud-override operations."""


class JustificationRequiredError(CloudOverrideError):
    """Raised when the mandatory justification is missing/blank."""


class TTLRangeError(CloudOverrideError):
    """Raised when the requested TTL is outside the 1-72 hour range."""


class ApprovalError(CloudOverrideError):
    """Raised on a bad approval (self-approval, expired window, no pending)."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


class CloudLlmOverrideManager:
    """Dual-admin, justified, TTL'd grant permitting a specific cloud LLM."""

    def __init__(self, redis_client, audit_writer=None) -> None:
        self._r = redis_client
        self._audit = audit_writer

    # -- lifecycle ----------------------------------------------------------
    def propose(self, initiator_id: str, provider: str, model: str,
                justification: str, ttl_hours: int = _TTL_DEFAULT_HOURS) -> dict:
        """Admin 1 proposes the override. Always enters PENDING_APPROVAL (dual-control).
        Justification is mandatory. A second, different admin must approve()."""
        just = (justification or "").strip()
        if len(just) < 4:
            raise JustificationRequiredError(
                "A justification is required (ticket #, contract #, CEO email, explicit reason).")
        if not (provider or "").strip() or not (model or "").strip():
            raise CloudOverrideError("provider and model are required.")
        if not (_TTL_MIN_HOURS <= ttl_hours <= _TTL_MAX_HOURS):
            raise TTLRangeError(f"ttl_hours must be {_TTL_MIN_HOURS}-{_TTL_MAX_HOURS}.")

        now = _now()
        expires_at = now + datetime.timedelta(hours=ttl_hours)
        state = {
            "status": "PENDING_APPROVAL",
            "provider": provider.strip(),
            "model": model.strip(),
            "justification": just,
            "initiated_by": initiator_id,
            "initiated_at": now.isoformat(),
            "approver": "",
            "ttl_hours": ttl_hours,
            "expires_at": expires_at.isoformat(),
        }
        # State carries the full TTL; the pending marker expires in 5 min — if the
        # second admin doesn't approve in time, the grant never activates.
        self._r.set(_KEY_STATE, json.dumps(state), ex=ttl_hours * 3600)
        self._r.set(_KEY_PENDING, json.dumps({"initiated_by": initiator_id}),
                    ex=_APPROVAL_WINDOW_SECONDS)
        self._emit("CLOUD_OVERRIDE_PROPOSED", state)
        logger.warning("CLOUD-OVERRIDE proposed by %s for %s/%s (ttl=%dh) — awaiting 2nd admin",
                       initiator_id, provider, model, ttl_hours)
        return state

    def approve(self, approver_id: str) -> dict:
        """Admin 2 approves. Must differ from the initiator and act within 5 min."""
        pending_raw = self._r.get(_KEY_PENDING)
        if not pending_raw:
            raise ApprovalError("No pending cloud-override approval (5-minute window may have expired).")
        pending = json.loads(pending_raw if isinstance(pending_raw, str) else pending_raw.decode())
        if pending["initiated_by"] == approver_id:
            raise ApprovalError("The approver must be a DIFFERENT admin from the initiator.")
        state_raw = self._r.get(_KEY_STATE)
        if not state_raw:
            raise ApprovalError("Cloud-override state not found — it may have expired.")
        state = json.loads(state_raw if isinstance(state_raw, str) else state_raw.decode())
        state["status"] = "ACTIVE"
        state["approver"] = approver_id
        ttl = self._r.ttl(_KEY_STATE)
        if ttl and ttl > 0:
            self._r.set(_KEY_STATE, json.dumps(state), ex=ttl)
        else:
            self._r.set(_KEY_STATE, json.dumps(state))
        self._r.delete(_KEY_PENDING)
        self._emit("CLOUD_OVERRIDE_ACTIVATED", state)
        logger.warning("CLOUD-OVERRIDE ACTIVATED by %s (proposed by %s) for %s/%s",
                       approver_id, state["initiated_by"], state["provider"], state["model"])
        return state

    def revoke(self, user_id: str) -> None:
        state_raw = self._r.get(_KEY_STATE)
        self._r.delete(_KEY_STATE)
        self._r.delete(_KEY_PENDING)
        if state_raw:
            state = json.loads(state_raw if isinstance(state_raw, str) else state_raw.decode())
            state["revoked_by"] = user_id
            self._emit("CLOUD_OVERRIDE_REVOKED", state)
        logger.warning("CLOUD-OVERRIDE revoked by %s", user_id)

    # -- query (gateway reads this live) ------------------------------------
    def get_active(self) -> Optional[dict]:
        """Return the ACTIVE override state (provider/model/justification/…) or None.
        PENDING (un-approved) grants return None — only a dual-approved grant is active."""
        raw = self._r.get(_KEY_STATE)
        if not raw:
            return None
        state = json.loads(raw if isinstance(raw, str) else raw.decode())
        return state if state.get("status") == "ACTIVE" else None

    def status(self) -> dict:
        raw = self._r.get(_KEY_STATE)
        if not raw:
            return {"status": "INACTIVE"}
        return json.loads(raw if isinstance(raw, str) else raw.decode())

    # -- audit --------------------------------------------------------------
    def _emit(self, event_type: str, state: dict) -> None:
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import CloudOverrideEvent
            self._audit.write(CloudOverrideEvent(
                override_event=event_type,
                provider=state.get("provider", ""),
                model=state.get("model", ""),
                justification=state.get("justification", ""),
                initiated_by=state.get("initiated_by", ""),
                approver=state.get("approver", ""),
                expires_at=state.get("expires_at", ""),
            ))
        except Exception:  # pragma: no cover — audit must never break the control
            logger.exception("cloud-override: audit emit failed for %s", event_type)
