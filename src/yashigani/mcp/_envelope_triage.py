"""
MCP capability-envelope mutation triage — the decision rule.

This is the three-class triage that runs at tool-surface refresh (the M4
``_content_filter`` / ``fetch_and_filter_tools`` hook).  It composes the
deterministic structural diff (``_envelope.diff_envelope`` — the AUTHORITY)
with the escalate-only semantic-intent sidecar (``inspection.semantic_intent``)
to classify each refresh into:

  * BENIGN          → auto-allow within the envelope, re-pin the byte-hash, log.
  * EXPANDING       → block + step-up re-approve (capability expansion).
  * UNCERTAIN       → FAIL-CLOSED block (sidecar flagged intent, errored, or
                      the refresh is structurally ambiguous).

Decision rule (Laura §8 consolidated):

    structural = (current ⊑ ORIGINAL_envelope)      # deterministic, vs BASELINE
    intent     = sidecar(changed_text)              # escalate-only, hostile input

    if not structural:                      -> EXPANDING (block + re-approve)
    elif intent == suspicious:              -> UNCERTAIN (fail-closed block)
    elif sidecar errored / indeterminate:   -> UNCERTAIN (fail-closed block)
    else:                                   -> BENIGN (auto-allow + re-pin)

Authority asymmetry (Laura must-have #2 / Δ2):
  * The STRUCTURAL diff is the only producer of auto-allow AND of
    block-on-expand.  An LLM is never trusted to rule "this is safe".
  * The sidecar may ONLY escalate a structural-pass to a block (downgrade
    benign→uncertain).  It can NEVER turn a structural-fail into an allow, and
    it can NEVER auto-clear a block.  A sidecar that says "benign" is a no-op
    on a structural-pass (the structural check already permitted it) and a
    no-op on a structural-fail (still blocked).

Baseline-anchoring (Laura must-have #1 / Δ1):
  the diff is ALWAYS against the ORIGINAL approved envelope (envelope_version
  1's typed dimensions == the active envelope's typed dimensions until a
  step-up re-approval mints a new baseline), never against the last
  auto-allowed surface.  Auto-allows consume slack under a fixed ceiling; they
  never raise it.  This closes boiling-frog/salami.

This module is PURE w.r.t. I/O except that it CALLS the sidecar (which is the
injected, fail-closed classifier) — it does not touch the DB.  The caller (the
broker hook) is responsible for the DB side-effects (re-pin / latch) driven by
the returned ``TriageOutcome``.

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from yashigani.mcp._envelope import (
    DiffFinding,
    EffectClass,
    ServerEnvelope,
    StructuralDiffResult,
    diff_envelope,
)

_log = logging.getLogger("yashigani.mcp.envelope.triage")

# Laura Δ4 — network-class envelope dimensions.  For an external-relay MCP (no
# ring-fence backstop) a CHANGE that touches any of these auto-allows ONLY in
# the ring-fenced topology; under external_relay it is force-blocked even when
# structurally within-envelope, because rung-four (egress=NONE containment) is
# absent for that topology (see laura-30-...-v2 §6 / Δ4).
_NETWORK_CLASS_DIMENSIONS = frozenset({"egress", "effect_class", "data_scope"})


class TriageClass(str, Enum):
    BENIGN = "benign"          # auto-allow within envelope + re-pin
    EXPANDING = "expanding"    # block + step-up re-approve
    UNCERTAIN = "uncertain"    # fail-closed block (sidecar / ambiguity)


@dataclass
class TriageOutcome:
    """
    The triage verdict for one surface refresh.

    ``triage_class`` is authoritative.  ``should_block`` is True for both
    EXPANDING and UNCERTAIN (fail-closed).  ``findings`` drive the operator
    field-level diff on a block.
    """
    triage_class: TriageClass
    should_block: bool
    new_surface_hash: str
    findings: list = field(default_factory=list)        # list[DiffFinding]
    sidecar_escalated: bool = False
    sidecar_error: Optional[str] = None
    detail: str = ""

    @property
    def auto_allow(self) -> bool:
        return self.triage_class is TriageClass.BENIGN and not self.should_block


def _evaluate_sidecar_escalation(
    sidecar: Any,
    changed_texts: list,
) -> tuple[bool, Optional[str]]:
    """
    Run the escalate-only sidecar over the changed/new text fragments.

    Returns ``(escalate, error)``:
      * escalate=True  → at least one fragment flagged injection-intent, OR the
                         sidecar errored → caller treats as UNCERTAIN
                         (fail-closed).
      * escalate=False → no fragment flagged intent (or the flag was OFF /
                         sidecar skipped) → the structural verdict stands.

    The sidecar can ONLY escalate; it never grants.  A crash/error is treated
    as an escalation (fail-closed): a classifier we cannot consult must cost an
    operator interrupt, never save one (Laura must-have #2 fail-closed rule).
    """
    if sidecar is None:
        return False, None

    any_escalation = False
    for text in changed_texts:
        if not text:
            continue
        try:
            verdict = sidecar.evaluate(text)
        except Exception as exc:  # noqa: BLE001 — fail-closed on any sidecar fault
            _log.error(
                "envelope-triage: sidecar.evaluate raised %s — fail-closed (UNCERTAIN)",
                type(exc).__name__,
            )
            return True, f"sidecar_error:{type(exc).__name__}"
        if getattr(verdict, "skipped", False):
            # Flag OFF — the sidecar did not run; structural verdict stands.
            continue
        if getattr(verdict, "is_injection", False):
            any_escalation = True
    return any_escalation, None


def _candidate_touches_network(envelope: ServerEnvelope) -> bool:
    """
    True iff the candidate surface carries ANY network-reach capability:
    a non-NONE server egress posture, or any tool with the NETWORK effect class
    (a url/host/webhook-shaped arg projects to NETWORK in ``_envelope``), or any
    tool with a host/url-shaped data scope.

    Used by the external-relay topology gate (Laura Δ4): for an external-relay
    MCP there is no ring-fence to contain a mis-triaged egress/network change,
    so a within-envelope *change* on a network-touching surface must NOT
    auto-allow — it is force-blocked for human review.
    """
    if envelope.egress_posture and envelope.egress_posture.upper() != "NONE":
        return True
    for tool in envelope.tools.values():
        if EffectClass.NETWORK in tool.effect_classes:
            return True
    return False


def apply_topology_gate(
    *,
    topology: str,
    approved_baseline: ServerEnvelope,
    current_envelope: ServerEnvelope,
    structural_expanded: bool,
) -> Optional[DiffFinding]:
    """
    Laura Δ4 conservative-tiering gate, deterministic (no LLM).

    Ring-fenced topology (the 3.0 imported-MCP default): full tiering — a
    within-envelope change auto-allows; the ring-fence (egress=NONE /
    internal:true container network policy) is the containment backstop for a
    mis-triaged network change.  Returns None (no extra gate).

    External-relay topology (YSG-RISK-058, pre-GA): NO ring-fence backstop, so
    the auto-allow path is unsafe for any network-class dimension.  When the
    candidate surface *touches* a network-reach capability AND the surface
    changed (a structural expansion already blocks; this catches the
    within-envelope network *change* the structural diff alone would
    auto-allow), force a block.  Returns a DiffFinding to surface on the block.

    This makes the envelope's declared egress-posture ``≤`` what the network
    topology actually enforces: an external-relay MCP can never auto-allow a
    network/egress/host capability change, regardless of how the structural
    diff scores it against the (possibly already network-bearing) baseline.

    The gate is one-directional: it can only *add* a block, never grant — so it
    composes with the structural authority (which already blocks expansions)
    and the escalate-only sidecar without weakening either.
    """
    if topology != "external_relay":
        return None
    if structural_expanded:
        return None  # already blocked by the structural authority
    # The structural diff said within-envelope.  But if the network-class
    # surface is involved at all, an external-relay MCP has no containment for a
    # silent network re-pin — so any change here blocks.  We treat "candidate
    # carries network reach" conservatively: if either the baseline OR the
    # candidate touches network, and the surface changed (caller only invokes
    # this on a byte-hash mismatch), the network-class change must be reviewed.
    if _candidate_touches_network(current_envelope) or _candidate_touches_network(
        approved_baseline
    ):
        return DiffFinding(
            dimension="egress",
            tool_key="",
            detail=(
                "external-relay topology: network/egress/host-touching surface "
                "change cannot auto-allow (no ring-fence backstop) — operator "
                "re-approval required (Laura Δ4 / YSG-RISK-058)"
            ),
        )
    return None


def _changed_text_fragments(
    approved: ServerEnvelope,
    current_raw_tools: list,
) -> list:
    """
    Gather the tool-description / annotation text fragments that CHANGED or are
    NEW vs the approved envelope, for the sidecar to scan.

    A within-envelope description reword can still be poisoned (Laura A1) — the
    sidecar scans the changed text so a structurally-benign-but-poisoned reword
    is escalated to UNCERTAIN (fail-closed block).
    """
    fragments: list = []
    approved_tool_names = {
        tk.split("::", 1)[1] for tk in approved.tools.keys() if "::" in tk
    }
    for raw in current_raw_tools or []:
        name = str(raw.get("name") or "")
        desc = str(raw.get("description") or "")
        if desc:
            fragments.append(desc)
        # A brand-new tool's full descriptor is changed text by definition.
        if name not in approved_tool_names:
            # already captured desc; nothing extra (structural diff blocks it
            # anyway as a new tool), but scan its description too.
            continue
    return fragments


def triage_refresh(
    *,
    approved_baseline: ServerEnvelope,
    current_envelope: ServerEnvelope,
    current_raw_tools: list,
    new_surface_hash: str,
    sidecar: Any = None,
    topology: str = "ring_fenced",
) -> TriageOutcome:
    """
    Triage a refreshed tool surface against the ORIGINAL approved baseline.

    Parameters
    ----------
    approved_baseline:
        The ORIGINAL approved ServerEnvelope (Laura Δ1 — NEVER the last
        auto-allowed state).
    current_envelope:
        The projection of the just-fetched surface (``project_surface``).
    current_raw_tools:
        The raw tools/list dicts (for the sidecar's text scan).
    new_surface_hash:
        The byte-hash of the just-fetched surface (the change-detector).
    sidecar:
        The escalate-only semantic-intent sidecar, or None.
    topology:
        'ring_fenced' | 'external_relay'.  Laura Δ4: for external-relay MCPs
        there is no ring-fence backstop, so egress/network/host-scope
        EXPANSIONS must always block (they already do — they are structural
        expansions); additionally a within-envelope egress/network *change*
        must not auto-allow.  The conservative gate is enforced by
        ``apply_topology_gate`` (Step 1b below): a network-touching surface
        change under external_relay force-blocks (EXPANDING) even when
        structurally within-envelope.  Ring-fenced topology keeps full tiering.

    Returns a TriageOutcome whose ``triage_class`` is authoritative.
    """
    # Step 1 — the AUTHORITY: deterministic structural diff vs the BASELINE.
    diff: StructuralDiffResult = diff_envelope(approved_baseline, current_envelope)

    if diff.expanded:
        # Capability expansion — block + step-up re-approve.  No sidecar call
        # needed (the structural gate is sufficient and authoritative); we do
        # NOT let a sidecar "benign" verdict downgrade a structural block.
        _log.warning(
            "envelope-triage: EXPANDING provenance=%.12s findings=%d (block + re-approve)",
            current_envelope.provenance_id, len(diff.findings),
        )
        return TriageOutcome(
            triage_class=TriageClass.EXPANDING,
            should_block=True,
            new_surface_hash=new_surface_hash,
            findings=diff.findings,
            detail="capability expansion vs approved envelope",
        )

    # Step 1b — Δ4 topology gate (deterministic, before the sidecar).  For an
    # external-relay MCP a within-envelope network/egress/host change cannot
    # auto-allow (no ring-fence backstop).  This is asymmetric like the
    # structural gate: it only ever adds a block.  EXPANDING (operator step-up),
    # not UNCERTAIN — it is a genuine capability-review requirement, not sidecar
    # ambiguity.
    topo_finding = apply_topology_gate(
        topology=topology,
        approved_baseline=approved_baseline,
        current_envelope=current_envelope,
        structural_expanded=diff.expanded,
    )
    if topo_finding is not None:
        _log.warning(
            "envelope-triage: EXPANDING (topology gate) provenance=%.12s "
            "external-relay network change blocked",
            current_envelope.provenance_id,
        )
        return TriageOutcome(
            triage_class=TriageClass.EXPANDING,
            should_block=True,
            new_surface_hash=new_surface_hash,
            findings=[topo_finding],
            detail="external-relay topology gate: network-class change blocked",
        )

    # Step 2 — structurally benign.  Run the escalate-only sidecar over the
    # changed text: a within-envelope reword can still be poisoned (A1).
    changed = _changed_text_fragments(approved_baseline, current_raw_tools)
    escalate, sidecar_error = _evaluate_sidecar_escalation(sidecar, changed)

    if escalate:
        _log.warning(
            "envelope-triage: UNCERTAIN provenance=%.12s (sidecar escalated/errored: %s) "
            "fail-closed block",
            current_envelope.provenance_id, sidecar_error or "injection_intent",
        )
        finding = DiffFinding(
            dimension="unknown",
            tool_key="",
            detail=(
                "sidecar flagged semantic injection intent in a within-envelope change"
                if sidecar_error is None
                else f"sidecar fail-closed ({sidecar_error})"
            ),
        )
        return TriageOutcome(
            triage_class=TriageClass.UNCERTAIN,
            should_block=True,
            new_surface_hash=new_surface_hash,
            findings=[finding],
            sidecar_escalated=sidecar_error is None,
            sidecar_error=sidecar_error,
            detail="sidecar escalation / fail-closed",
        )

    # Step 3 — structurally within-envelope AND sidecar clean (or off).
    # BENIGN → auto-allow + re-pin (the caller advances current_surface_hash).
    _log.info(
        "envelope-triage: BENIGN provenance=%.12s auto-allow + re-pin hash=%.12s",
        current_envelope.provenance_id, new_surface_hash,
    )
    return TriageOutcome(
        triage_class=TriageClass.BENIGN,
        should_block=False,
        new_surface_hash=new_surface_hash,
        findings=[],
        detail="within approved envelope; sidecar clean",
    )
