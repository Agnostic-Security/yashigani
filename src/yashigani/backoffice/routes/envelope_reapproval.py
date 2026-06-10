"""
Yashigani Backoffice — Capability-Envelope RE-APPROVAL admin routes (3.0).

The operator-facing admin surface for the imported-MCP capability-envelope pin
(YSG-RISK-060).  Tom built the backend — the durable envelope ledger
(``mcp/envelope_service.py``), the field-level diff + step-up re-approve
(``mcp/envelope_reapproval.py``), and the refresh triage
(``mcp/_envelope_triage.py``).  This route is the THIN API seam the
re-approval SPA consumes; it wires the REAL services (no stub) and surfaces:

  GET    /admin/mcp/envelopes/pending                  — pending re-approval queue
  GET    /admin/mcp/envelopes/pending/{prov}           — field-level diff
                                                          (candidate vs ORIGINAL
                                                          baseline AND vs prior)
  POST   /admin/mcp/envelopes/pending/{prov}/approve   — step-up re-approve →
                                                          re-pin new baseline
  POST   /admin/mcp/envelopes/pending/{prov}/reject    — keep-blocked (step-up)

The candidate (refreshed) surface that triggered a block is held by the
backoffice-owned :class:`EnvelopePendingStore` (Redis db/3), written by the
broker when it latches the block.  The diff is ALWAYS recomputed server-side vs
the ORIGINAL baseline (envelope_version 1) — the anti-rug-pull framing — using
the same deterministic structural diff the broker uses; the store's pre-rendered
findings are advisory only.

Security properties enforced here (the brief's QA mandate on our own build):
  * **RBAC + step-up on approve/reject** — ``reapprove_envelope`` calls the
    shared ``assert_privileged_mutation`` gate (operator tier + FRESH TOTP),
    which raises ``StepUpRequired`` (401, ``error=step_up_required``) so the JS
    interceptor prompts for TOTP, then retries.  A non-admin gets 403; a hijacked
    session without the second factor cannot re-pin or clear a queue entry.
  * **Tenant scoping (BOLA close)** — every read/mutation is scoped to this
    install's tenant; a pending entry from another tenant is invisible and a
    cross-tenant approve/reject fails closed (404).
  * **No secret / no handle in the response** — only the public, typed
    capability dimensions + diff details are returned.  No envelope handle, no
    map material, no salt.
  * **Output escaping is the UI's job** — tool keys, descriptions and diff
    ``detail`` strings derive from an UNTRUSTED upstream MCP (the XSS surface).
    This route returns them as JSON strings (no HTML); the renderer
    (envelope_reapproval.js) escapeHtml()s every field at the DOM sink.

# Last updated: 2026-06-10
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, status

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Tenant / service resolution ────────────────────────────────────────────

def _install_tenant() -> str:
    """Resolve this install's tenant id (mirrors documents._install_tenant).

    Single-tenant installs use the stable default ``"default"``; a multi-tenant
    deployment sets ``YASHIGANI_TENANT_ID`` per install.  Every read + mutation
    here is scoped to this tenant so a pending re-approval (and its candidate)
    never crosses a tenant boundary (BOLA close)."""
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


def _pending_store():
    """Return the wired EnvelopePendingStore or 503 (fail-closed).

    A read/mutation must never appear to succeed against a store that does not
    exist — the operator would see an empty queue and assume nothing is blocked
    when in fact the store is simply down."""
    store = backoffice_state.envelope_pending_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "envelope_pending_store_unavailable",
                "message": "Capability-envelope pending store not initialised (Redis db/3 unavailable).",
            },
        )
    return store


def _envelope_service():
    """Construct a CapabilityEnvelopeService over the live asyncpg pool, or 503.

    The pool is opened in the backoffice lifespan after create_pool(); in
    dev/test without a DB it is absent → 503 (fail-closed) rather than a 500."""
    try:
        from yashigani.db import get_pool
        from yashigani.mcp.envelope_service import CapabilityEnvelopeService
        return CapabilityEnvelopeService(get_pool())
    except Exception as exc:  # noqa: BLE001
        logger.warning("envelope re-approval: service unavailable (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "envelope_service_unavailable",
                "message": "Capability-envelope durable store not initialised (DB pool unavailable).",
            },
        )


# ── Diff rendering ─────────────────────────────────────────────────────────

# The diff dimensions, mapped to a human label + the "what an attacker is
# trying to gain" framing the SPA surfaces.  Severity drives the badge colour.
_DIMENSION_META = {
    "tool_set": {"label": "New tool", "severity": "high"},
    "effect_class": {"label": "Effect class", "severity": "high"},
    "egress": {"label": "Egress posture", "severity": "high"},
    "data_scope": {"label": "Data scope", "severity": "med"},
    "arg_shape": {"label": "Argument schema", "severity": "med"},
    "annotation": {"label": "Model-facing hint", "severity": "med"},
    "output": {"label": "Output shape", "severity": "med"},
    "unknown": {"label": "Unmodelled capability", "severity": "high"},
}


def _render_findings(findings: list) -> list:
    """Render a list[DiffFinding] into JSON-safe rows for the SPA.

    Every string here (tool_key / detail) is attacker-controlled — the route
    passes it through as JSON; the SPA escapeHtml()s it at the DOM sink."""
    out = []
    for f in findings:
        dim = getattr(f, "dimension", "") or ""
        meta = _DIMENSION_META.get(dim, {"label": dim or "change", "severity": "med"})
        out.append({
            "dimension": dim,
            "label": meta["label"],
            "severity": meta["severity"],
            "tool_key": getattr(f, "tool_key", "") or "",
            "detail": getattr(f, "detail", "") or "",
        })
    return out


def _envelope_view(env) -> dict:
    """A compact, JSON-safe view of a ServerEnvelope for the diff panel header.

    Surfaces the typed dimensions only (no secret, no hash material beyond the
    informational surface_set_hash).  Tool keys are untrusted → UI escapes."""
    tools = []
    for tk, t in sorted(env.tools.items()):
        tools.append({
            "tool_key": tk,
            "effect_classes": sorted(e.value for e in t.effect_classes),
            "data_scopes": sorted(t.data_scopes),
            "output_open": bool(t.output_open),
        })
    return {
        "egress_posture": env.egress_posture,
        "tool_count": len(env.tools),
        "tools": tools,
    }


# ── Pending queue ──────────────────────────────────────────────────────────

@router.get("/pending")
async def list_pending(session: AdminSession):
    """List imported MCPs whose tool-surface refresh is BLOCKED + awaiting an
    operator re-approval decision (this tenant only).

    Always 200 (empty queue renders the all-clear state)."""
    store = _pending_store()
    return {"pending": store.list_for_tenant(_install_tenant())}


@router.get("/pending/{provenance_id}")
async def get_pending_diff(provenance_id: str, session: AdminSession):
    """Field-level diff for ONE blocked refresh.

    Returns the candidate diffed vs the ORIGINAL approved baseline (cumulative
    drift since import — the anti-rug-pull framing) AND vs the immediately-prior
    approved envelope.  The diff is recomputed server-side with the authoritative
    deterministic structural diff; the operator approves the ABSOLUTE candidate,
    never a delta.

    404 if the provenance has no pending entry for this tenant (BOLA close)."""
    store = _pending_store()
    tenant = _install_tenant()

    row = store.get(provenance_id, tenant)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "no_pending_reapproval"})

    candidate = store.get_candidate_envelope(provenance_id, tenant)
    if candidate is None:  # pragma: no cover - get() already gated; defensive
        raise HTTPException(status_code=404, detail={"error": "no_pending_reapproval"})

    svc = _envelope_service()
    try:
        baseline = await svc.get_baseline_envelope(provenance_id)
        active = await svc.get_active_envelope(provenance_id)
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="envelope lookup failed")
        raise HTTPException(status_code=503, detail=envelope)

    if baseline is None:
        # No original baseline ⇒ never imported through the ceremony.  The
        # pending entry is stale/orphaned — surface it honestly, do not pretend.
        raise HTTPException(
            status_code=409,
            detail={"error": "no_baseline_envelope",
                    "message": "No original approved baseline for this MCP — cannot diff/re-approve."},
        )

    from yashigani.mcp.envelope_reapproval import compute_field_level_diff

    # vs PRIOR: the active row's typed dimensions == the baseline's until a
    # re-approval mints a new version, so when there is no separate active row we
    # fall back to the baseline (the diff vs prior then equals vs original).
    prior_env = active.envelope if active is not None else baseline.envelope
    fld = compute_field_level_diff(
        provenance_id=provenance_id,
        original_baseline=baseline.envelope,
        prior_envelope=prior_env,
        candidate=candidate,
    )

    return {
        "provenance_id": provenance_id,
        "server_id": row.get("server_id", ""),
        "triage_class": row.get("triage_class", ""),
        "blocked_at": row.get("blocked_at", 0.0),
        # Header views (typed dimensions only — no secrets).
        "original": _envelope_view(baseline.envelope),
        "candidate": _envelope_view(candidate),
        # The two diffs — vs ORIGINAL is the anti-rug-pull anchor.
        "vs_original": _render_findings(fld.vs_original),
        "vs_prior": _render_findings(fld.vs_prior),
        "egress_change": (
            baseline.envelope.egress_posture != candidate.egress_posture
        ),
        "egress_from": baseline.envelope.egress_posture,
        "egress_to": candidate.egress_posture,
    }


# ── Approve (step-up re-approve → re-pin new baseline) ──────────────────────

@router.post("/pending/{provenance_id}/approve")
async def approve_pending(provenance_id: str, session: AdminSession):
    """Re-approve a blocked tool-surface mutation behind the step-up gate.

    Wires the REAL ``reapprove_envelope`` — which calls the shared
    ``assert_privileged_mutation`` gate (operator RBAC + FRESH TOTP).  On a
    session without a fresh step-up it raises ``StepUpRequired`` (401,
    ``error=step_up_required``) so the JS interceptor prompts for TOTP and
    retries.  On success it mints a NEW chained envelope version (re-pins the new
    baseline) and CLEARS the latched block.  The pending entry is then consumed.

    A non-admin session is rejected (403) by the gate before any mutation."""
    store = _pending_store()
    tenant = _install_tenant()

    row = store.get(provenance_id, tenant)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "no_pending_reapproval"})
    candidate = store.get_candidate_envelope(provenance_id, tenant)
    if candidate is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail={"error": "no_pending_reapproval"})

    svc = _envelope_service()
    from yashigani.mcp.envelope_reapproval import reapprove_envelope

    # reapprove_envelope enforces the step-up gate itself (StepUpRequired /
    # NotAuthorisedForPrivilegedMutation propagate as 401/403 to the client) and
    # mints the new baseline.  We do NOT pre-gate with StepUpAdminSession — that
    # would double-enforce and the gate inside reapprove is the audited one.
    try:
        new_id = await reapprove_envelope(
            session=session,
            envelope_service=svc,
            candidate=candidate,
            server_id=row.get("server_id", ""),
            operator_identity=session.account_id,
            topology="ring_fenced",
            audit_writer=backoffice_state.audit_writer,
        )
    except HTTPException:
        # StepUpRequired (401) / NotAuthorised (403) — propagate verbatim so the
        # JS interceptor sees error=step_up_required and prompts for TOTP.
        raise
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="re-approval failed")
        raise HTTPException(status_code=500, detail=envelope)

    # Mutation succeeded + audited — consume the pending entry.
    store.resolve(provenance_id, tenant)
    logger.warning(
        "capability-envelope RE-APPROVED via admin UI: provenance=%.12s new_id=%d by=%s",
        provenance_id, new_id, session.account_id,
    )
    return {
        "status": "ok",
        "provenance_id": provenance_id,
        "new_envelope_id": new_id,
        "message": "Capability envelope re-pinned to the new baseline; block cleared.",
    }


# ── Reject / keep-blocked (step-up) ────────────────────────────────────────

@router.post("/pending/{provenance_id}/reject")
async def reject_pending(provenance_id: str, session: AdminSession):
    """Reject the mutation — keep the MCP blocked.

    Also a privileged decision (a hijacked session must not silently clear the
    operator's re-approval queue), so it is gated by the same
    ``assert_privileged_mutation`` step-up.  On reject the DB block STAYS latched
    (no new baseline is minted — only a step-up re-approval can clear it); the
    pending queue entry is consumed so it no longer nags the operator.  The
    upstream MCP remains hard-gated at the invocation broker (fail-closed)."""
    store = _pending_store()
    tenant = _install_tenant()

    row = store.get(provenance_id, tenant)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "no_pending_reapproval"})

    from yashigani.auth.stepup import (
        PrivilegedMutationContext,
        assert_privileged_mutation,
    )

    ctx = PrivilegedMutationContext(
        reason="mcp.envelope.reject",
        principal=session.account_id,
        target=provenance_id,
        before={"triage_class": row.get("triage_class", "")},
        after={"decision": "keep_blocked"},
    )
    # Raises StepUpRequired (401) / NotAuthorised (403) on failure → JS prompts.
    assert_privileged_mutation(session, ctx, audit_writer=backoffice_state.audit_writer)

    store.resolve(provenance_id, tenant)
    logger.warning(
        "capability-envelope KEEP-BLOCKED via admin UI: provenance=%.12s by=%s "
        "(block remains latched; MCP stays gated)",
        provenance_id, session.account_id,
    )
    return {
        "status": "ok",
        "provenance_id": provenance_id,
        "message": "Mutation rejected — the MCP stays blocked until an explicit re-approval.",
    }
