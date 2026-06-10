"""
Yashigani Auth — Step-up authentication (ASVS V6.8.4 / V2.4.x).

Per-route step-up logic: high-value admin endpoints require a fresh
TOTP code submitted within the last N minutes (default 5), independent
of session state and IdP/SSO claims.

Even a fully-authenticated admin must re-prove TOTP at the moment of a
dangerous action.  This is belt-and-braces: IdP compromise or session
hijack cannot bypass the per-action TOTP gate.

Last updated: 2026-04-27T00:00:00+01:00

ASVS references:
  V6.8.4 — Re-authentication before critical operations.
  V2.4.x — Verifier impersonation resistance (step-up is app-layer,
            not solely IdP-derived).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from yashigani.auth.session import Session

_log = logging.getLogger("yashigani.auth.stepup")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: How long (seconds) a step-up TOTP verification remains valid.
#: Configurable via YASHIGANI_STEPUP_TTL_SECONDS. Default: 300 (5 minutes).
STEPUP_TTL_SECONDS: int = int(os.getenv("YASHIGANI_STEPUP_TTL_SECONDS", "300"))


# ---------------------------------------------------------------------------
# Core logic (pure — no FastAPI imports needed here)
# ---------------------------------------------------------------------------

def has_fresh_stepup(session: "Session") -> bool:
    """
    Return True if the session has a recent (<STEPUP_TTL_SECONDS) step-up
    TOTP event.

    Rules:
    - last_totp_verified_at is None (never performed) → False.
    - last_totp_verified_at > now (clock skew / tampered) → False (conservative).
    - Age >= TTL → False (expired).
    - Age < TTL → True.
    """
    if session.last_totp_verified_at is None:
        return False
    age_seconds = time.time() - session.last_totp_verified_at
    if age_seconds < 0:
        # Clock skew or tampered timestamp — reject conservatively.
        return False
    return age_seconds < STEPUP_TTL_SECONDS


class StepUpRequired(HTTPException):
    """
    Raised when a step-up TOTP verification is required before proceeding.
    HTTP 401 with detail.error = "step_up_required" — the JS interceptor
    catches this and shows the TOTP modal before retrying.
    """

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "step_up_required",
                "message": (
                    "This action requires fresh TOTP verification. "
                    "POST a current TOTP code to /auth/stepup and retry."
                ),
                "stepup_endpoint": "/auth/stepup",
                "ttl_seconds": STEPUP_TTL_SECONDS,
            },
        )


def assert_fresh_stepup(session: "Session") -> None:
    """
    Raise StepUpRequired if the session does not have a fresh step-up.
    Call this at the top of any high-value route handler.
    """
    if not has_fresh_stepup(session):
        raise StepUpRequired()


# ---------------------------------------------------------------------------
# Shared privileged-mutation gate (designed ONCE for #3/#4/#5)
#
# Per Iris architecture §5 + Laura §8 (R3-9): tensions #3 (MCP envelope
# re-approval), #4, and #5 ALL need the same step-up.  Build it once as a
# reusable gate, not three bespoke ones.  Su's #4 (MI-4) reuses this.
#
# Contract:
#   1. requires a FRESH step-up (assert_fresh_stepup) — IdP-compromise /
#      session-hijack cannot bypass it.
#   2. requires the OPERATOR identity (admin RBAC tier).
#   3. emits a uniform PRIVILEGED_MUTATION audit event so every privileged
#      action across #3/#4/#5 lands in one tamper-evident audit shape.
#   4. surfaces the I6 decision contract on the deny side (code=STEP_UP_REQUIRED
#      / NOT_AUTHORISED).
#
# The fresh-TOTP requirement is UNCONDITIONAL regardless of whether the
# re-approval action is later rendered as an OPA admin-plane decision or as
# broker-internal-fail-closed (Tiago design-call #1 / GAP-003); the OPA
# rendering is a wrapper that follows that ruling.
# ---------------------------------------------------------------------------


class NotAuthorisedForPrivilegedMutation(HTTPException):
    """
    Raised when the principal lacks the operator (admin) RBAC tier required for
    a privileged mutation.  Distinct from StepUpRequired: a non-admin can never
    satisfy this by re-proving TOTP — they are simply not authorised.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "not_authorised",
                "code": "NOT_AUTHORISED",
                "message": (
                    "This action requires operator (admin) privileges."
                ),
                "reason": reason,
            },
        )


@dataclass
class PrivilegedMutationContext:
    """
    The decision context for a privileged mutation, passed to the gate.

    reason:
        Stable machine reason, e.g. "mcp.envelope.reapprove" (#3).
    principal:
        The operator identity (session.account_id / sub claim).
    target:
        The object being mutated, e.g. the provenance_id (#3).
    justification:
        Optional free-text operator justification (recorded, never trusted).
    before / after:
        Optional state snapshots for the audit event (e.g. the field-level
        diff for an envelope re-approval).
    """
    reason: str
    principal: str
    target: str
    justification: Optional[str] = None
    before: Optional[dict] = None
    after: Optional[dict] = None


#: Admin tier value (matches auth.session.Session.account_tier).
_OPERATOR_TIER = "admin"


def assert_privileged_mutation(
    session: "Session",
    ctx: PrivilegedMutationContext,
    *,
    audit_writer: Any = None,
) -> None:
    """
    The shared privileged-mutation gate.  Call this at the top of any
    privileged-mutation handler (envelope re-approval, #4/#5 surfaces).

    Enforcement order (fail-closed):
      1. operator (admin) RBAC tier — else NotAuthorisedForPrivilegedMutation.
      2. FRESH step-up TOTP — else StepUpRequired.
      3. emit the uniform PRIVILEGED_MUTATION audit event (best-effort; the
         mutation proceeds only AFTER both gates pass).

    Raises StepUpRequired (401) or NotAuthorisedForPrivilegedMutation (403)
    on failure; returns None on success (the caller then performs the mutation).
    """
    # Gate 1 — operator RBAC.  A non-admin is never authorised, full stop.
    if getattr(session, "account_tier", None) != _OPERATOR_TIER:
        _log.warning(
            "privileged_mutation DENIED (not operator): reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )
        raise NotAuthorisedForPrivilegedMutation(ctx.reason)

    # Gate 2 — fresh step-up TOTP (unconditional).
    if not has_fresh_stepup(session):
        _log.info(
            "privileged_mutation STEP-UP REQUIRED: reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )
        raise StepUpRequired()

    # Gate 3 — uniform audit event (both gates passed; mutation is authorised).
    _emit_privileged_mutation_event(ctx, audit_writer)


def _emit_privileged_mutation_event(
    ctx: PrivilegedMutationContext,
    audit_writer: Any,
) -> None:
    """Emit the uniform PRIVILEGED_MUTATION audit event (best-effort)."""
    try:
        from yashigani.audit.schema import PrivilegedMutationEvent
    except Exception as exc:  # noqa: BLE001 — audit import must never block the gate
        _log.error("privileged_mutation: audit schema import failed: %s", exc)
        return

    event = PrivilegedMutationEvent(
        reason=ctx.reason,
        principal=ctx.principal,
        target=ctx.target,
        justification=ctx.justification or "",
        before=ctx.before,
        after=ctx.after,
    )
    if audit_writer is not None:
        try:
            audit_writer.write(event)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "privileged_mutation: audit write failed reason=%s target=%s: %s",
                ctx.reason, ctx.target, exc,
            )
    else:
        _log.warning(
            "privileged_mutation: no audit_writer — PRIVILEGED_MUTATION NOT written "
            "reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )
