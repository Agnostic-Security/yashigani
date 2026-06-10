"""
MCP capability-envelope re-approval — field-level diff + step-up + re-pin.

The operator-facing side of the capability-envelope pin (Iris §5.3 / Laura §3
bypass A).  On a capability-expanding block the backoffice renders a
**field-level diff** for the operator — not a yes/no — and approval is gated
behind the shared ``privileged_mutation`` fresh-TOTP step-up.  Approval mints a
new chained envelope row (``previous_envelope_id``) and un-suspends the tools.

Two diffs are ALWAYS shown (Laura §3 bypass A — incremental re-approvals that
each look like a 1-line delta must not launder cumulative drift):
  * vs the ORIGINAL baseline (cumulative drift since import), AND
  * vs the immediately-prior envelope.
The operator approves the ABSOLUTE new envelope, not a delta.

No silent auto-re-pin on an expansion — only an operator step-up mints a new
envelope.  That is the entire anti-rug-pull property.

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from yashigani.mcp._envelope import DiffFinding, ServerEnvelope, diff_envelope
from yashigani.auth.stepup import (
    PrivilegedMutationContext,
    assert_privileged_mutation,
)

_log = logging.getLogger("yashigani.mcp.envelope.reapproval")


@dataclass
class FieldLevelDiff:
    """
    The operator-facing field-level diff for a re-approval decision.

    ``vs_original`` is the cumulative drift since import (Laura §3 bypass A);
    ``vs_prior`` is the delta vs the immediately-prior approved envelope.  Both
    are always populated so an incremental re-approval cannot hide cumulative
    drift behind a small per-step delta.
    """
    provenance_id: str
    vs_original: list = field(default_factory=list)   # list[DiffFinding]
    vs_prior: list = field(default_factory=list)      # list[DiffFinding]

    def as_dict(self) -> dict:
        def _render(findings: list) -> list:
            return [
                {"dimension": f.dimension, "tool_key": f.tool_key, "detail": f.detail}
                for f in findings
            ]
        return {
            "provenance_id": self.provenance_id,
            "vs_original": _render(self.vs_original),
            "vs_prior": _render(self.vs_prior),
        }


def compute_field_level_diff(
    *,
    provenance_id: str,
    original_baseline: ServerEnvelope,
    prior_envelope: ServerEnvelope,
    candidate: ServerEnvelope,
) -> FieldLevelDiff:
    """
    Compute the operator field-level diff: candidate vs ORIGINAL and vs PRIOR.

    Both diffs use the same deterministic structural diff (the authority).  The
    operator sees the full cumulative drift since import (vs_original) plus the
    immediate delta (vs_prior), and approves the absolute candidate envelope.
    """
    vs_original = diff_envelope(original_baseline, candidate)
    vs_prior = diff_envelope(prior_envelope, candidate)
    return FieldLevelDiff(
        provenance_id=provenance_id,
        vs_original=vs_original.findings,
        vs_prior=vs_prior.findings,
    )


async def reapprove_envelope(
    *,
    session: Any,                       # auth.session.Session
    envelope_service: Any,              # CapabilityEnvelopeService
    candidate: ServerEnvelope,
    server_id: str,
    operator_identity: str,
    topology: str = "ring_fenced",
    sidecar_scan_verdict: Optional[dict] = None,
    audit_writer: Any = None,
) -> int:
    """
    Re-approve a capability-expanding (or blocked) imported-MCP tool surface.

    Enforcement (fail-closed):
      1. The shared ``privileged_mutation`` gate — operator RBAC + FRESH TOTP
         step-up — raises StepUpRequired / NotAuthorisedForPrivilegedMutation
         on failure (the JS interceptor prompts TOTP).  A uniform
         PRIVILEGED_MUTATION audit event is emitted on success.
      2. mint_envelope() INSERTs a NEW chained envelope version (status=active),
         superseding the prior active/blocked row in the same transaction — this
         is what CLEARS a latched block (a reversion never could; only an
         operator step-up mints a new baseline).

    Returns the new envelope row id.

    The before/after snapshots carried into the audit event are the field-level
    diff vs the ORIGINAL baseline (cumulative drift since import) — so the audit
    record is honest about what the operator actually approved.
    """
    # Compute the field-level diff for the audit "before/after" (vs original).
    baseline = await envelope_service.get_baseline_envelope(candidate.provenance_id)
    prior = await envelope_service.get_active_envelope(candidate.provenance_id)
    diff_for_audit: Optional[dict] = None
    if baseline is not None:
        prior_env = prior.envelope if prior is not None else baseline.envelope
        fld = compute_field_level_diff(
            provenance_id=candidate.provenance_id,
            original_baseline=baseline.envelope,
            prior_envelope=prior_env,
            candidate=candidate,
        )
        diff_for_audit = fld.as_dict()

    # Gate 1 — shared privileged-mutation step-up (UNCONDITIONAL fresh TOTP).
    ctx = PrivilegedMutationContext(
        reason="mcp.envelope.reapprove",
        principal=operator_identity,
        target=candidate.provenance_id,
        before=diff_for_audit,
        after={"egress_posture": candidate.egress_posture,
               "tool_count": len(candidate.tools)},
    )
    assert_privileged_mutation(session, ctx, audit_writer=audit_writer)

    # Gate 2 — mint the new chained envelope version (clears any latched block).
    new_id = await envelope_service.mint_envelope(
        candidate,
        server_id=server_id,
        operator_identity=operator_identity,
        topology=topology,
        sidecar_scan_verdict=sidecar_scan_verdict,
    )
    _log.warning(
        "CapabilityEnvelope: RE-APPROVED provenance=%.12s new_id=%d by=%s "
        "(latched block cleared; new baseline-active version minted)",
        candidate.provenance_id, new_id, operator_identity,
    )
    return new_id
