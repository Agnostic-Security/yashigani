"""
Yashigani MCP — manifest rug-pull re-approval gate (5.0).

Register §4 #2: the manifest-registration ledger detects a post-approval
manifest change (SHA-256 delta) but only APPENDS + logs it — detect-and-log,
not detect-and-prevent. A silently-mutated tool manifest ("rug pull") therefore
takes effect the moment it is registered. This gate closes that:

  - note_registration(): on a delta (new sha != the previously-ACTIVE sha), the
    new sha is held PENDING_REAPPROVAL and is NOT active. Audited.
  - approve(): a DIFFERENT admin re-supplies the confirming sha (byte-compared
    against the immutable pending record) to activate it. Audited (write-ahead).
  - is_active(agent_id, sha): the enforcement primitive the invocation path
    calls. First-ever registration is TOFU-active. A delta pending re-approval
    is NOT active → the caller fails closed (blocks the tool call). An error
    reaching the store is also NOT active (fail-closed).

Same corrected dual-control shape as model_integrity.ModelPinDualControl
(immutable pending, confirming-digest byte-compare, write-ahead audit).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_ACTIVE_KEY = "yashigani:manifest:active:"      # agent_id → active sha
_PENDING_KEY = "yashigani:manifest:pending:"    # agent_id → pending record
_PENDING_TTL_SECONDS = 24 * 3600                 # a delta must be reviewed within a day


class ManifestReapprovalError(Exception):
    """Invalid propose/approve (self-approval, digest mismatch, no pending, …)."""


class ManifestStoreUnavailableError(Exception):
    """Store unreachable — is_active() callers MUST fail closed (block)."""


@dataclass
class NoteResult:
    status: str  # "first_registration" | "unchanged" | "pending_reapproval"
    active: bool


class ManifestReapprovalGate:
    def __init__(self, redis_client, audit_writer=None) -> None:
        self._r = redis_client
        self._audit = audit_writer

    # ── registration hook ──────────────────────────────────────────────────
    def note_registration(
        self, agent_id: str, new_sha: str, registered_by: str,
    ) -> NoteResult:
        """Call on every manifest registration. Returns whether the new sha is
        active. First registration (no active sha) is TOFU-active; an unchanged
        sha stays active; a delta is held pending re-approval (NOT active).

        LAURA-V50-005 defense-in-depth: `registered_by` MUST be the same
        canonical, server-verified admin identity namespace `approve()`
        compares `approver_id` against (e.g. the admin's session
        account_id) — never a client-supplied free-text label. If the
        caller passes an empty/non-string identity, fail closed (raise)
        rather than silently record an unnormalizable registrant that
        could later vacuously fail to collide with a real approver_id.
        """
        if not registered_by or not isinstance(registered_by, str):
            raise ManifestReapprovalError(
                "registered_by must be a non-empty, canonical admin identity "
                "string (e.g. the registering admin's session account_id) — "
                "refusing to hold a rug-pull-gated delta with an "
                "unnormalizable registrant identity."
            )
        try:
            active_raw = self._r.get(_ACTIVE_KEY + agent_id)
        except Exception as exc:  # noqa: BLE001
            raise ManifestStoreUnavailableError(str(exc)) from exc
        active_sha = (
            active_raw.decode() if isinstance(active_raw, bytes) else active_raw
        )

        if not active_sha:
            # TOFU: first registration for this agent becomes active immediately.
            self._r.set(_ACTIVE_KEY + agent_id, new_sha)
            return NoteResult(status="first_registration", active=True)

        if new_sha == active_sha:
            return NoteResult(status="unchanged", active=True)

        # Delta — hold pending, do NOT activate. Immutable pending (nx).
        record = {"agent_id": agent_id, "new_sha": new_sha,
                  "old_sha": active_sha, "registered_by": registered_by}
        self._audit_or_raise(
            "MANIFEST_DELTA_PENDING", agent_id, active_sha, new_sha,
            registered_by=registered_by, approver="", action="pending",
        )
        self._r.set(_PENDING_KEY + agent_id, json.dumps(record),
                    ex=_PENDING_TTL_SECONDS, nx=True)
        logger.warning(
            "MANIFEST_DELTA_PENDING agent=%s old=%.12s new=%.12s by=%s — "
            "blocked until re-approved", agent_id, active_sha, new_sha, registered_by)
        return NoteResult(status="pending_reapproval", active=False)

    # ── dual-control approval ───────────────────────────────────────────────
    def approve(self, agent_id: str, approver_id: str, confirming_sha: str) -> str:
        # LAURA-V50-005 defense-in-depth: approver_id must be the same
        # canonical, server-verified identity namespace as registered_by
        # (see note_registration). Fail closed on an unnormalizable
        # approver identity rather than let it vacuously never-match
        # registered_by and sail through the SoD check.
        if not approver_id or not isinstance(approver_id, str):
            raise ManifestReapprovalError(
                "approver_id must be a non-empty, canonical admin identity "
                "string (e.g. the approving admin's session account_id)."
            )
        raw = self._r.get(_PENDING_KEY + agent_id)
        if not raw:
            raise ManifestReapprovalError(
                "No pending manifest re-approval for this agent.")
        rec = json.loads(raw if isinstance(raw, str) else raw.decode())

        if rec["registered_by"] == approver_id:
            raise ManifestReapprovalError(
                "The approver must be a DIFFERENT admin from the registrant.")
        if confirming_sha != rec["new_sha"]:
            self._audit_or_raise(
                "MANIFEST_DELTA_REJECTED", agent_id, rec["old_sha"], confirming_sha,
                registered_by=rec["registered_by"], approver=approver_id, action="rejected",
            )
            raise ManifestReapprovalError(
                "Confirming sha does not match the pending manifest.")

        # Write-ahead durable audit before activating.
        self._audit_or_raise(
            "MANIFEST_DELTA_APPROVED", agent_id, rec["old_sha"], rec["new_sha"],
            registered_by=rec["registered_by"], approver=approver_id, action="approved",
        )
        self._r.set(_ACTIVE_KEY + agent_id, rec["new_sha"])
        self._r.delete(_PENDING_KEY + agent_id)
        logger.warning("MANIFEST_DELTA_APPROVED agent=%s new=%.12s by=%s (registered by %s)",
                       agent_id, rec["new_sha"], approver_id, rec["registered_by"])
        return rec["new_sha"]

    # ── enforcement primitives ──────────────────────────────────────────────
    def is_blocked(self, agent_id: str) -> bool:
        """Invocation-path enforcement: True if this agent has a manifest delta
        PENDING re-approval — its tool surface changed and was not re-approved,
        so calls to it must be blocked until a second admin clears it. A store
        error returns True (fail-closed). No pending delta → False (allow)."""
        try:
            pending = self._r.get(_PENDING_KEY + agent_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("manifest-gate: store unavailable (%s) — fail-closed block", exc)
            return True
        if pending:
            logger.warning(
                "MANIFEST_ACTIVE_BLOCKED agent=%s — invocation blocked (delta pending "
                "re-approval)", agent_id)
            self._audit_or_raise(
                "MANIFEST_ACTIVE_BLOCKED", agent_id, "", "",
                registered_by="", approver="", action="blocked", best_effort=True,
            )
            return True
        return False

    def is_active(self, agent_id: str, sha: str) -> bool:
        """True iff `sha` is the approved-active manifest for the agent. A
        pending-but-unapproved delta, or any store error, returns False so the
        invocation path fails closed."""
        try:
            active_raw = self._r.get(_ACTIVE_KEY + agent_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("manifest-gate: store unavailable (%s) — fail-closed", exc)
            return False
        active_sha = active_raw.decode() if isinstance(active_raw, bytes) else active_raw
        if active_sha and sha == active_sha:
            return True
        logger.warning(
            "MANIFEST_ACTIVE_BLOCKED agent=%s sha=%.12s (active=%.12s) — blocked",
            agent_id, sha or "", (active_sha or "")[:12],
        )
        self._audit_or_raise(
            "MANIFEST_ACTIVE_BLOCKED", agent_id, active_sha or "", sha,
            registered_by="", approver="", action="blocked", best_effort=True,
        )
        return False

    # ── audit ───────────────────────────────────────────────────────────────
    def _audit_or_raise(self, event_type, agent_id, old_sha, new_sha,
                        registered_by, approver, action, best_effort=False) -> None:
        if self._audit is None:
            return
        from yashigani.audit.schema import ManifestReapprovalEvent, EventType
        try:
            self._audit.write(ManifestReapprovalEvent(
                event_type=getattr(EventType, event_type),
                agent_id=agent_id,
                old_manifest_sha256=old_sha, new_manifest_sha256=new_sha,
                registered_by=registered_by, approver=approver, action_taken=action,
            ))
        except Exception:
            if best_effort:
                logger.exception("manifest-gate: best-effort audit emit failed")
                return
            raise  # write-ahead: a state mutation must fail closed on audit failure
