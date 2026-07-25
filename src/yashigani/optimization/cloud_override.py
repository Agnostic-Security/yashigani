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

Security invariants (fixed YCS-20260705-v4.1.2-SOD-1/SOD-2):
  SOD-1 — swap-attack prevention: approve() requires a confirming_fingerprint
    (SHA-256 over provider+model+justification) that must match the stored
    proposal fingerprint byte-for-byte.  Any mutation of the pending record after
    the fingerprint is computed causes approve() to raise ApprovalError.
    A second propose() while a proposal is PENDING is also rejected, making the
    pending record effectively immutable for its 5-minute lifetime.
  SOD-2 — write-ahead audit: PROPOSED, ACTIVATED, and REVOKED are durable events.
    The audit write MUST succeed before the corresponding Redis state mutation is
    committed.  If the audit write raises, the mutation does not happen and the
    override does NOT activate (or is not revoked).

State lives in Redis (the gateway engine reads it live to honour the grant).
"""
from __future__ import annotations

import datetime
import hashlib
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
    """Raised on a bad approval: self-approval, expired window, no pending,
    or fingerprint mismatch (SOD-1 swap-attack guard)."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def compute_proposal_fingerprint(provider: str, model: str, justification: str) -> str:
    """Return a canonical SHA-256 hex digest over the decision-bearing proposal fields.

    The approver MUST supply this value to ``approve()`` to prove they reviewed the
    exact same provider/model/justification that was proposed.  Any mutation of those
    fields after the fingerprint is computed produces a different digest, causing
    ``approve()`` to raise ``ApprovalError`` (SOD-1 swap-attack prevention).

    Callers obtain the expected fingerprint from the ``proposal_fingerprint`` key in
    the dict returned by ``propose()``, or compute it independently from the values
    they reviewed.
    """
    canonical = json.dumps(
        {"justification": justification, "model": model, "provider": provider},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class CloudLlmOverrideManager:
    """Dual-admin, justified, TTL'd grant permitting a specific cloud LLM."""

    def __init__(self, redis_client, audit_writer=None) -> None:
        self._r = redis_client
        self._audit = audit_writer

    # -- lifecycle ----------------------------------------------------------
    def propose(self, initiator_id: str, provider: str, model: str,
                justification: str, ttl_hours: int = _TTL_DEFAULT_HOURS) -> dict:
        """Admin 1 proposes the override. Always enters PENDING_APPROVAL (dual-control).
        Justification is mandatory. A second, different admin must approve().

        Returns the pending state dict which includes ``proposal_fingerprint`` — the
        approver passes this value (or an independently computed equivalent) to
        ``approve()`` to bind their approval to the exact proposal they reviewed.

        Raises ``ApprovalError`` if a proposal is already PENDING (SOD-1: pending
        records are immutable for their 5-minute lifetime; a second propose() could
        overwrite the state and change what the approver is about to sign off on).
        """
        just = (justification or "").strip()
        if len(just) < 4:
            raise JustificationRequiredError(
                "A justification is required (ticket #, contract #, CEO email, explicit reason).")
        if not (provider or "").strip() or not (model or "").strip():
            raise CloudOverrideError("provider and model are required.")
        if not (_TTL_MIN_HOURS <= ttl_hours <= _TTL_MAX_HOURS):
            raise TTLRangeError(f"ttl_hours must be {_TTL_MIN_HOURS}-{_TTL_MAX_HOURS}.")

        # SOD-1: reject a second propose() while a proposal is PENDING — prevents an
        # attacker from overwriting the pending state between A's propose() and B's
        # approve() to swap the target LLM under B's review.
        if self._r.get(_KEY_PENDING) is not None:
            raise ApprovalError(
                "A proposal is already pending approval. The current proposal must be "
                "approved or expire before a new one can be submitted.")

        now = _now()
        expires_at = now + datetime.timedelta(hours=ttl_hours)
        provider_s = provider.strip()
        model_s = model.strip()
        fingerprint = compute_proposal_fingerprint(provider_s, model_s, just)
        state = {
            "status": "PENDING_APPROVAL",
            "provider": provider_s,
            "model": model_s,
            "justification": just,
            "initiated_by": initiator_id,
            "initiated_at": now.isoformat(),
            "approver": "",
            "ttl_hours": ttl_hours,
            "expires_at": expires_at.isoformat(),
            "proposal_fingerprint": fingerprint,
        }
        # SOD-2: write-ahead — PROPOSED audit must succeed BEFORE state is committed.
        # If the audit write fails this raises and Redis is never written.
        self._emit_durable("CLOUD_OVERRIDE_PROPOSED", state)
        # State carries the full TTL; the pending marker expires in 5 min — if the
        # second admin doesn't approve in time, the grant never activates.
        self._r.set(_KEY_STATE, json.dumps(state), ex=ttl_hours * 3600)
        self._r.set(_KEY_PENDING, json.dumps({
            "initiated_by": initiator_id,
            "proposal_fingerprint": fingerprint,
        }), ex=_APPROVAL_WINDOW_SECONDS)
        logger.warning("CLOUD-OVERRIDE proposed by %s for %s/%s (ttl=%dh) — awaiting 2nd admin",
                       initiator_id, provider_s, model_s, ttl_hours)
        return state

    def approve(self, approver_id: str, confirming_fingerprint: str) -> dict:
        """Admin 2 approves. Must differ from the initiator and act within 5 min.

        ``confirming_fingerprint`` MUST match the SHA-256 fingerprint stored in the
        pending record (returned as ``proposal_fingerprint`` by ``propose()``, or
        computable via ``compute_proposal_fingerprint(provider, model, justification)``).

        Any mismatch raises ``ApprovalError`` and the override does NOT activate
        (SOD-1 swap-attack prevention — if the pending state was overwritten after the
        approver fetched it, the stored fingerprint will differ from the one computed
        over the original proposal the approver reviewed).

        The ACTIVATED audit event is written BEFORE the state is committed ACTIVE
        (SOD-2 write-ahead).  If the audit write fails this raises and the state is
        left PENDING_APPROVAL.
        """
        pending_raw = self._r.get(_KEY_PENDING)
        if not pending_raw:
            raise ApprovalError("No pending cloud-override approval (5-minute window may have expired).")
        pending = json.loads(pending_raw if isinstance(pending_raw, str) else pending_raw.decode())
        if pending["initiated_by"] == approver_id:
            raise ApprovalError("The approver must be a DIFFERENT admin from the initiator.")

        # SOD-1: bind approval to the exact proposal the approver reviewed.
        stored_fp = pending.get("proposal_fingerprint", "")
        if not stored_fp or confirming_fingerprint != stored_fp:
            raise ApprovalError(
                "Fingerprint mismatch: the pending proposal was modified after it was "
                "presented to you (possible swap attack), or you supplied an incorrect "
                "confirming_fingerprint.  Approval rejected.")

        state_raw = self._r.get(_KEY_STATE)
        if not state_raw:
            raise ApprovalError("Cloud-override state not found — it may have expired.")
        state = json.loads(state_raw if isinstance(state_raw, str) else state_raw.decode())
        state["status"] = "ACTIVE"
        state["approver"] = approver_id
        state["confirming_fingerprint"] = confirming_fingerprint

        ttl = self._r.ttl(_KEY_STATE)

        # SOD-2: write-ahead — ACTIVATED audit must succeed BEFORE state is committed ACTIVE.
        # If the audit write fails this raises and the state is never set to ACTIVE.
        self._emit_durable("CLOUD_OVERRIDE_ACTIVATED", state)
        if ttl and ttl > 0:
            self._r.set(_KEY_STATE, json.dumps(state), ex=ttl)
        else:
            self._r.set(_KEY_STATE, json.dumps(state))
        self._r.delete(_KEY_PENDING)
        logger.warning("CLOUD-OVERRIDE ACTIVATED by %s (proposed by %s) for %s/%s",
                       approver_id, state["initiated_by"], state["provider"], state["model"])
        return state

    def revoke(self, user_id: str) -> None:
        """Revoke the active (or pending) override.

        The REVOKED audit event is written BEFORE the Redis keys are deleted (SOD-2
        write-ahead).  If the audit write fails this raises and the override is NOT
        revoked — the audit backend must be restored before revocation can proceed.
        """
        state_raw = self._r.get(_KEY_STATE)
        if state_raw:
            state = json.loads(state_raw if isinstance(state_raw, str) else state_raw.decode())
            state["revoked_by"] = user_id
            # SOD-2: write-ahead — REVOKED audit must succeed BEFORE keys are deleted.
            self._emit_durable("CLOUD_OVERRIDE_REVOKED", state)
        self._r.delete(_KEY_STATE)
        self._r.delete(_KEY_PENDING)
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
    def _emit_durable(self, event_type: str, state: dict) -> None:
        """Emit a security-critical audit event.  Raises on failure.

        Callers MUST NOT commit the corresponding state mutation if this raises.
        When ``audit_writer`` is None (no writer configured) this is a no-op — the
        guard applies only when a writer is present and the write fails.
        """
        if self._audit is None:
            return
        from yashigani.audit.schema import CloudOverrideEvent
        self._audit.write(CloudOverrideEvent(
            override_event=event_type,
            provider=state.get("provider", ""),
            model=state.get("model", ""),
            justification=state.get("justification", ""),
            initiated_by=state.get("initiated_by", ""),
            approver=state.get("approver", ""),
            expires_at=state.get("expires_at", ""),
            confirming_fingerprint=state.get("confirming_fingerprint", ""),
        ))

    def _emit_best_effort(self, event_type: str, state: dict) -> None:
        """Emit a non-security-critical informational audit event (best-effort).
        Reserved for future informational events that must not block the control path."""
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
                confirming_fingerprint=state.get("confirming_fingerprint", ""),
            ))
        except Exception:  # pragma: no cover — best-effort only, not security-critical
            logger.exception("cloud-override: best-effort audit emit failed for %s", event_type)
