"""
Yashigani Document Enforcement — PSEUDONYMIZE mode-B over the gateway PROXY (2.26).

This is the RUNTIME wiring of mode-B (red-team F3 / L-02) into the gateway's
existing request→upstream→response proxy seam (``gateway/proxy.py``).  Mode-B was
already wired at the pipeline API (``DocumentInspectionPipeline.restore_modeb_
response``); this module makes it a real egress feature:

  * OUTBOUND — a document leaving via the proxy is run through the SAME decision
    source the backoffice ``/inspect`` path uses: enumerate (LOG) →
    ``evaluate_document_decision`` (REAL OPA over ``policy/document.rego`` + the
    operator's persisted matrix) → apply the OPA-decided action.  OPA — not a
    hardcoded branch — decides per route / data-class / sensitivity whether the
    document is LOGged (forward unchanged), REDACTed (forward the stripped
    artefact), PSEUDONYMIZEd mode A (forward tokens, user holds the table),
    PSEUDONYMIZEd mode B (forward tokens AND hold a request-scoped
    :class:`ModeBRoundTrip` for the response-leg restore), or BLOCKed (held).
  * INBOUND — for a mode-B egress only, the upstream response is restored through
    the SAME response seam the proxy already runs for response inspection, via
    ``DocumentInspectionPipeline.restore_modeb_response`` + the binder's echo /
    position / namespace-harvest rejections.

Decision source of truth (2.26 gap #2 close): the egress action + mode are no
longer flag-driven (the old "blanket mode-B when the flag is on").  They are
POLICY-driven — the proxy egress reuses ``evaluate_document_decision`` exactly as
the backoffice ``/inspect`` route does, so there is ONE decision source for both
the UI and the proxy.  The egress route is ``egress-mcp-result`` (matched against
each policy's ``route`` in the rego).

Two non-negotiable disciplines this module enforces, because it runs on the HOT
request path AND straddles the cloud-egress security boundary:

  1. **Traffic-safe / fail-closed-but-non-fatal.**  A fault MUST NOT break normal
     traffic.  Every entry point is wrapped so any unexpected error degrades to
     "forward the bytes we already have" — the ORIGINAL request bytes on egress
     (mode-B simply did not engage), or the STILL-TOKENIZED response on ingress
     (never the cleartext, never a crash).  The crown-jewel map is never surfaced
     on any error path.

  2. **Untouched unless opted in AND document-shaped.**  Both the
     document-enforcement flag AND the dedicated mode-B-proxy flag must be on, and
     the request must look like a document egress, before any pipeline work runs.
     A non-document / flag-off call returns immediately with the bytes unchanged.

The round-trip is held REQUEST-SCOPED by the proxy (a local variable passed back
in on the response leg) — never module/global state — so there is no cross-request
namespace bleed and no shared mutable map.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from yashigani.documents.config import (
    is_document_enforcement_enabled,
    is_modeb_proxy_enabled,
)
from yashigani.documents.detection import _MIME_TO_TYPE
from yashigani.documents.opa_decision import evaluate_document_decision
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_LOG,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_ROUTE_LOCAL,
    DocumentInspectionPipeline,
)
from yashigani.documents.pseudonymize import ModeBRoundTrip

logger = logging.getLogger(__name__)

#: The routing decision the proxy egress travels on — matched against each
#: policy's ``route`` in the rego (policy/document.rego ``_route_matches``).  A
#: document leaving the gateway towards an upstream/cloud MCP server is an
#: ``egress-mcp-result`` egress.  This is the SAME route vocabulary the backoffice
#: surfaces and the seeded example policies key on (PII-1/PCI-1 → PSEUDONYMIZE on
#: egress-mcp-result; PII-2/PCI-2 → REDACT on json-attachment).
PROXY_EGRESS_ROUTE = "egress-mcp-result"

#: Content-Type values that mark a request body as a supported document egress.
#: A cheap pre-filter ONLY — the pipeline still sniffs magic bytes and fails
#: closed on a declared/sniffed mismatch (F8).  We never tokenize a body the
#: declared type does not at least claim to be a document.
_DOCUMENT_MIME_PREFIXES: tuple[str, ...] = tuple(sorted(_MIME_TO_TYPE.keys()))


def is_modeb_proxy_active() -> bool:
    """Master gate: BOTH the document-enforcement flag AND the dedicated
    mode-B-proxy flag must be on.  Default OFF — the hot path is untouched."""
    return is_document_enforcement_enabled() and is_modeb_proxy_enabled()


def looks_like_document_egress(content_type: str, body: bytes) -> bool:
    """Cheap pre-filter: does this request body claim to be a supported document?

    Declared-Content-Type-driven only (the pipeline does the authoritative sniff
    + fail-closed mismatch check).  Empty body or a non-document content type →
    False, so normal JSON/MCP traffic is never routed through the pipeline."""
    if not body:
        return False
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return False
    return ct in _MIME_TO_TYPE


@dataclass
class EgressOutcome:
    """Result of the OUTBOUND policy-driven egress decision.

    The OPA-decided ``action`` (LOG/REDACT/PSEUDONYMIZE/BLOCK) drives which of
    these fields are set:

      * ``blocked`` True  — OPA decided BLOCK (or a fail-closed degrade of a real
        document); ``forward_bytes`` is None and the proxy MUST NOT forward.
      * ``transformed`` True with ``forward_bytes`` set — OPA decided a transform
        (REDACT, or PSEUDONYMIZE mode A/B): the proxy forwards ``forward_bytes``
        (the re-rendered/tokenized artefact) instead of the original.  When the
        action is PSEUDONYMIZE **mode B**, ``round_trip`` is also set and
        ``engaged`` is True — the proxy holds it for the response-leg restore.
      * neither set — the egress did not transform the body (OPA decided LOG, or
        this was not a document, or a non-fatal degrade): the proxy forwards the
        ORIGINAL bytes unchanged.  The proxy's existing PII/OPA request-path
        controls still govern those bytes.

    ``action`` carries the OPA disposition for the proxy's audit line so the
    proxy records the SAME action the rego decided (one decision, audited once).

    ``engaged`` stays the mode-B-specific signal (forward tokens AND hold the
    round-trip) so the response-leg restore + the ``X-Yashigani-Document-ModeB``
    header only fire for a genuine mode-B egress, never for LOG/REDACT/mode-A."""

    engaged: bool = False
    blocked: bool = False
    transformed: bool = False
    forward_bytes: Optional[bytes] = None
    round_trip: Optional[ModeBRoundTrip] = None
    block_reason: Optional[str] = None
    action: str = DISPOSITION_LOG
    #: PART 2 (Laura D1) field-role routing: OPA decided ROUTE_LOCAL — the document
    #: carries an OPERATE_ON sensitive field a cloud model would hallucinate over,
    #: so the proxy MUST pin the whole call to the LOCAL model and forward the
    #: ORIGINAL bytes (values stay in-estate, never tokenised to the cloud).  When
    #: True the proxy reroutes to the local model instead of the cloud upstream.
    route_local: bool = False
    #: The operate-on sensitive data classes that forced ROUTE_LOCAL (audit /
    #: layman-alert breadcrumb; class names only, never values).
    operate_on_classes: list[str] = field(default_factory=list)


@dataclass
class IngressOutcome:
    """Result of the INBOUND restore of an untrusted upstream/cloud response.

    ``restored_bytes`` is the bytes the proxy should return downstream.  On a
    clean restore it carries cleartext; on an echo-rejection or a flagged
    (tainted) round-trip it is the STILL-TOKENIZED response (never cleartext that
    failed the binder's checks).  ``tainted`` is True when the round-trip is not
    a clean success (echo or flags) — the proxy surfaces it via a header/alert."""

    restored_bytes: bytes
    restored: bool = False
    echo_rejected: bool = False
    flagged: bool = False
    flags: list[str] = field(default_factory=list)

    @property
    def tainted(self) -> bool:
        return self.echo_rejected or self.flagged


async def egress_decide(
    pipeline: DocumentInspectionPipeline,
    *,
    opa_url: str,
    body: bytes,
    content_type: str,
    request_id: str,
    route: str = PROXY_EGRESS_ROUTE,
    egress_mode: str = "B",
    detokenize_rbac_role: Optional[str] = None,
) -> EgressOutcome:
    """OUTBOUND: ask REAL OPA what to do with a document leaving via the proxy,
    then apply the OPA-decided action.

    This is the policy-driven egress (2.26 gap #2): the action + mode are decided
    by OPA over ``policy/document.rego`` + the operator's persisted matrix — NOT a
    hardcoded "blanket mode-B".  It reuses the EXACT decision source the backoffice
    ``/inspect`` route uses (:func:`evaluate_document_decision`), so there is ONE
    decision source of truth for the UI and the proxy.

    ``egress_mode`` (default ``"B"``) is the pseudonymize mode the proxy egress
    declares to OPA — the egress is the CLOUD round-trip leg, so it is mode B by
    default.  It is what lets the rego drive a mode-B round-trip AND fire the PART 2
    ROUTE_LOCAL field-role escalation (cloud-bound / mode-B PSEUDONYMIZE only).

    Two passes, mirroring ``/inspect``:
      1. enumerate (LOG mode) to build the OPA input WITHOUT applying any
         transform — the action decision is OPA's job;
      2. ``evaluate_document_decision`` over the live matrix (declaring
         ``egress_mode``) → the action + mode;
      3. apply the OPA-decided action via the pipeline.

    Mapping of the OPA action onto the egress:
      * BLOCK         → ``blocked=True`` (the proxy holds the document);
      * LOG           → forward the ORIGINAL bytes unchanged (allow + audit);
      * ROUTE_LOCAL   → forward the ORIGINAL bytes to the LOCAL model
        (``route_local=True``); the values never go cloud-bound (PART 2 / Laura
        D1 field-role routing — an operate-on sensitive field the cloud would
        hallucinate over).  OPA decides; the pipeline ``_route_local`` applies;
      * REDACT        → forward the stripped artefact (``transformed=True``);
      * PSEUDONYMIZE mode A → forward the tokenized artefact, NO round-trip (the
        user holds the correspondence table; the cloud only ever sees tokens);
      * PSEUDONYMIZE mode B → forward the tokenized artefact AND hold the
        round-trip (``engaged=True``) for the response-leg restore.

    Fail-closed-but-non-fatal: an *unexpected* fault (not a disposition) degrades
    to forwarding the ORIGINAL bytes (the egress decision simply did not engage),
    never a crash and never a half-transformed body.  A real BLOCK (OPA deny,
    oversize, mismatch, residual, small-set escalation, OPA-unreachable →
    synthetic BLOCK) is honoured as ``blocked=True`` — the proxy MUST hold the
    document.  That distinction is the whole point of the fail-closed gate."""
    try:
        # --- Pass 1: enumerate (LOG) — build the OPA input, apply no transform.
        enum_result = pipeline.inspect(
            data=body,
            declared_mime=content_type,
            request_id=request_id,
            requested_action=DISPOSITION_LOG,
        )
    except Exception:
        logger.exception(
            "doc egress: enumeration raised — disengaging, forwarding original "
            "(request_id=%s)", request_id,
        )
        return EgressOutcome(engaged=False)

    opa_input = enum_result.opa_input
    if opa_input is None:
        # Enumeration already fail-closed (e.g. extraction incomplete / oversize /
        # mismatch) → HOLD the document.  This is a real document that could not be
        # cleared, never "not a document"; the pipeline's _block carries the reason.
        return EgressOutcome(
            engaged=False, blocked=True, forward_bytes=None,
            block_reason=enum_result.block_reason, action=DISPOSITION_BLOCK,
        )

    # --- Pass 2: ask REAL OPA (the SAME decision source as /inspect). ----------
    # evaluate_document_decision NEVER raises and NEVER fails open: any OPA error /
    # timeout / unreachable → a synthetic fail-closed BLOCK decision.
    # The proxy egress IS the CLOUD round-trip leg, so it declares ``egress_mode``
    # (default "B") to OPA: that is what lets the rego (a) drive a mode-B
    # PSEUDONYMIZE round-trip, and (b) fire the PART 2 ROUTE_LOCAL field-role
    # escalation (which only applies to a cloud-bound / mode-B PSEUDONYMIZE).  A
    # mode-A egress would never see ROUTE_LOCAL because mode A keeps the join under
    # the user's local control (no cloud blob).
    decision = await evaluate_document_decision(
        opa_url,
        opa_input,
        route=route,
        pseudonymize_mode=egress_mode,
    )
    opa_action = decision.get("action", DISPOSITION_BLOCK)
    opa_mode = decision.get("pseudonymize_mode", egress_mode)

    if opa_action == DISPOSITION_BLOCK:
        return EgressOutcome(
            engaged=False, blocked=True, forward_bytes=None,
            block_reason="; ".join(decision.get("deny", []) or ["document_blocked"]),
            action=DISPOSITION_BLOCK,
        )

    if opa_action == DISPOSITION_LOG:
        # Allow + audit — forward the original bytes unchanged (the enum pass
        # already wrote the LOG audit event).  Not a transform, not a round-trip.
        return EgressOutcome(engaged=False, action=DISPOSITION_LOG)

    if opa_action == DISPOSITION_ROUTE_LOCAL:
        # PART 2 (Laura D1): OPA decided the field-role escalation — an OPERATE_ON
        # sensitive field a cloud model would hallucinate over.  We do NOT tokenise
        # to the cloud; we pin the whole call to the LOCAL model and forward the
        # ORIGINAL bytes (values stay in-estate).  Re-run the pipeline with the
        # OPA-decided action so the single source of truth (the pipeline's
        # _route_local) writes the DOCUMENT_ROUTED_LOCAL audit event + computes the
        # operate_on_classes breadcrumb — OPA decides, the pipeline applies.
        try:
            rl = pipeline.inspect(
                data=body,
                declared_mime=content_type,
                request_id=request_id,
                requested_action=DISPOSITION_ROUTE_LOCAL,
            )
        except Exception:
            # An unexpected fault on the route-local apply must not break traffic
            # NOR fail open to the cloud: degrade to BLOCK (hold the document)
            # rather than forward an operate-on sensitive value to the cloud.
            logger.exception(
                "doc egress: ROUTE_LOCAL apply raised — holding the document "
                "(fail-closed, not forwarded to cloud) (request_id=%s)", request_id,
            )
            return EgressOutcome(
                engaged=False, blocked=True, forward_bytes=None,
                block_reason="route_local_apply_failed", action=DISPOSITION_BLOCK,
            )
        if rl.disposition != DISPOSITION_ROUTE_LOCAL or rl.forward_bytes is None:
            # The pipeline did not produce a clean route-local result — fail-closed
            # to BLOCK rather than risk a cloud-bound forward of a sensitive value.
            return EgressOutcome(
                engaged=False, blocked=True, forward_bytes=None,
                block_reason=rl.block_reason or "route_local_not_produced",
                action=DISPOSITION_BLOCK,
            )
        return EgressOutcome(
            engaged=False,
            action=DISPOSITION_ROUTE_LOCAL,
            route_local=True,
            forward_bytes=rl.forward_bytes,
            operate_on_classes=list(rl.operate_on_classes),
        )

    # --- Pass 3: apply the OPA-decided transform (REDACT / PSEUDONYMIZE). ------
    detok = decision.get("detokenize_rbac_role") or detokenize_rbac_role
    try:
        kwargs: dict = {}
        if detok is not None:
            kwargs["detokenize_rbac_role"] = detok
        result = pipeline.inspect(
            data=body,
            declared_mime=content_type,
            request_id=request_id,
            requested_action=opa_action,
            pseudonymize_mode=opa_mode,
            **kwargs,
        )
    except Exception:
        # An *unexpected* transform fault must not break traffic — forward the
        # original.  The pipeline only returns forward_bytes on a clean re-render +
        # no-residual proof, so on exception we have nothing partial to surface.
        logger.exception(
            "doc egress: transform (%s) raised — disengaging, forwarding original "
            "(request_id=%s)", opa_action, request_id,
        )
        return EgressOutcome(engaged=False)

    if result.disposition == DISPOSITION_BLOCK:
        # The transform itself fail-closed (e.g. residual leak, small-set
        # escalation, unsupported re-render) — HOLD the document.
        return EgressOutcome(
            engaged=False, blocked=True, forward_bytes=None,
            block_reason=result.block_reason, action=DISPOSITION_BLOCK,
        )

    if result.forward_bytes is None:
        # No bytes to forward but not a BLOCK — degrade safely to forwarding the
        # original (never ship a None/half body).
        return EgressOutcome(engaged=False, action=result.disposition)

    # PSEUDONYMIZE mode B → forward tokens AND hold the round-trip for the restore.
    if (
        result.disposition == DISPOSITION_PSEUDONYMIZE
        and result.mode_b_roundtrip is not None
    ):
        return EgressOutcome(
            engaged=True,
            transformed=True,
            forward_bytes=result.forward_bytes,
            round_trip=result.mode_b_roundtrip,
            action=DISPOSITION_PSEUDONYMIZE,
        )

    # REDACT or PSEUDONYMIZE mode A → forward the transformed artefact, NO
    # round-trip (the cloud only ever sees the stripped/tokenized bytes; mode A's
    # correspondence table is delivered out-of-band, not restored on the response).
    return EgressOutcome(
        engaged=False,
        transformed=True,
        forward_bytes=result.forward_bytes,
        action=result.disposition,
    )


def ingress_restore(
    pipeline: DocumentInspectionPipeline,
    round_trip: ModeBRoundTrip,
    *,
    response_bytes: bytes,
    request_id: str,
) -> IngressOutcome:
    """INBOUND: restore the untrusted upstream/cloud response through the binder.

    Drives ``DocumentInspectionPipeline.restore_modeb_response`` — which applies
    the verbatim-echo rejection, position binding, and namespace-harvest cap, and
    emits the audit event.  Fail-closed-but-non-fatal: any error (decode, restore)
    degrades to returning the STILL-TOKENIZED response bytes — the proxy forwards
    tokenized data, NEVER cleartext that did not pass the binder, and never
    crashes the response leg.  The crown-jewel map is destroyed in every path."""
    try:
        # The egress frame text was the tokenized output the cloud saw; the
        # response is decoded the same way for restoration.  A non-UTF-8 response
        # is restored on its best-effort decode and re-encoded; we never restore
        # into bytes we could not decode.
        response_text = response_bytes.decode("utf-8", errors="replace")
        restore_result = pipeline.restore_modeb_response(
            request_id=request_id,
            response_text=response_text,
            round_trip=round_trip,
        )
        if restore_result.echo_rejected:
            # Harvest attack rejected — forward the tokenized response unchanged.
            return IngressOutcome(
                restored_bytes=restore_result.restored_text.encode(
                    "utf-8", errors="replace"
                ),
                restored=False,
                echo_rejected=True,
            )
        flagged = not restore_result.restored
        return IngressOutcome(
            restored_bytes=restore_result.restored_text.encode(
                "utf-8", errors="replace"
            ),
            restored=restore_result.restored,
            flagged=flagged,
            flags=list(restore_result.flags),
        )
    except Exception:
        logger.exception(
            "doc-modeB ingress: restore raised — forwarding TOKENIZED response "
            "(no cleartext leaked) (request_id=%s)", request_id,
        )
        return IngressOutcome(restored_bytes=response_bytes, restored=False)
    finally:
        # End-of-request teardown: destroy the replacer map (fail-closed) so the
        # crown jewel never outlives the request, on EVERY path.
        try:
            round_trip.destroy()
        except Exception:
            logger.debug("doc-modeB ingress: round-trip teardown failed", exc_info=True)
