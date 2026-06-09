"""
Yashigani Document Enforcement — PSEUDONYMIZE mode-B over the gateway PROXY (2.26).

This is the RUNTIME wiring of mode-B (red-team F3 / L-02) into the gateway's
existing request→upstream→response proxy seam (``gateway/proxy.py``).  Mode-B was
already wired at the pipeline API (``DocumentInspectionPipeline.restore_modeb_
response``); this module makes it a real egress feature:

  * OUTBOUND — a PSEUDONYMIZE mode-B document leaving via the proxy is tokenized
    by the pipeline (the untrusted upstream/cloud sees only ``[CLASS_N]``
    placeholders) and a request-scoped :class:`ModeBRoundTrip` is held.
  * INBOUND — the upstream response is restored through the SAME response seam the
    proxy already runs for response inspection, via
    ``DocumentInspectionPipeline.restore_modeb_response`` + the binder's echo /
    position / namespace-harvest rejections.

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
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_PSEUDONYMIZE,
    DocumentInspectionPipeline,
)
from yashigani.documents.pseudonymize import ModeBRoundTrip

logger = logging.getLogger(__name__)

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
    """Result of the OUTBOUND mode-B tokenization attempt.

    ``engaged`` is True only when the proxy should send ``forward_bytes`` (the
    tokenized artefact) AND hold ``round_trip`` for the response leg.  When
    ``blocked`` is True the document was held by the pipeline (BLOCK disposition)
    and ``forward_bytes`` is None — the proxy must NOT forward.  When neither is
    set, mode-B did not engage (not a document, not mode-B disposition, or a
    fail-closed degrade) and the proxy forwards the ORIGINAL bytes unchanged."""

    engaged: bool = False
    blocked: bool = False
    forward_bytes: Optional[bytes] = None
    round_trip: Optional[ModeBRoundTrip] = None
    block_reason: Optional[str] = None


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


def egress_tokenize(
    pipeline: DocumentInspectionPipeline,
    *,
    body: bytes,
    content_type: str,
    request_id: str,
    detokenize_rbac_role: Optional[str] = None,
) -> EgressOutcome:
    """OUTBOUND: tokenize a mode-B document for cloud egress, holding the
    round-trip for the response leg.

    Fail-closed-but-non-fatal: any unexpected error returns a non-engaged
    :class:`EgressOutcome` so the proxy forwards the ORIGINAL bytes — mode-B
    simply did not engage.  A real pipeline BLOCK (oversize, mismatch, residual,
    small-set escalation) is honoured as ``blocked=True`` (the proxy must hold the
    document), NOT degraded to a forward — that distinction is the whole point of
    the fail-closed document gate."""
    try:
        if detokenize_rbac_role is not None:
            result = pipeline.inspect(
                data=body,
                declared_mime=content_type,
                request_id=request_id,
                requested_action=DISPOSITION_PSEUDONYMIZE,
                pseudonymize_mode="B",
                detokenize_rbac_role=detokenize_rbac_role,
            )
        else:
            result = pipeline.inspect(
                data=body,
                declared_mime=content_type,
                request_id=request_id,
                requested_action=DISPOSITION_PSEUDONYMIZE,
                pseudonymize_mode="B",
            )
    except Exception:
        # An *unexpected* pipeline fault (not a disposition) must not break
        # traffic — forward the original bytes, mode-B disengaged.  We never leak
        # a half-tokenized body: the pipeline only returns forward_bytes on a
        # clean re-render + no-residual proof, so on exception we have nothing
        # partial to surface.
        logger.exception(
            "doc-modeB egress: pipeline raised — disengaging mode-B, forwarding "
            "original (request_id=%s)", request_id,
        )
        return EgressOutcome(engaged=False)

    if result.disposition == DISPOSITION_BLOCK:
        # The document failed the fail-closed gate — HOLD it (do not forward).
        return EgressOutcome(
            engaged=False, blocked=True, forward_bytes=None,
            block_reason=result.block_reason,
        )

    if (
        result.disposition == DISPOSITION_PSEUDONYMIZE
        and result.mode_b_roundtrip is not None
        and result.forward_bytes is not None
    ):
        return EgressOutcome(
            engaged=True,
            forward_bytes=result.forward_bytes,
            round_trip=result.mode_b_roundtrip,
        )

    # Any other disposition (LOG with no matches, REDACT, mode-A, or a
    # PSEUDONYMIZE that produced no round-trip) is NOT a mode-B egress: do not
    # engage the restore path.  Forward the original bytes unchanged — the proxy's
    # existing request-path inspection (PII/OPA) already governs those.
    return EgressOutcome(engaged=False)


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
