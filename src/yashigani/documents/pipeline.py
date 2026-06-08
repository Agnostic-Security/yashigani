"""
Yashigani Document Enforcement — the document inspection pipeline (front-end
into the EXISTING inspection engines).

Flow (plan §4.2 — reuse, don't duplicate):

    document bytes
       │  size/cap guard + magic-byte sniff (detection.py, fail-closed F8)
       ▼
    [ EXTRACTOR ]  → segments + provenance (extractor.py; fail-closed §6.1)
       │
       ▼
    [ EXISTING PII detector, per-segment ]  → DataMatch[] enumeration (§3.1.1)
       │
       ▼
    [ OPA-ready DocumentDecisionInput ]  (datamatch.py — handed to the policy)
       │
       ▼
    [ ACTION ]  LOG (end-to-end here) / BLOCK (wired) /
                REDACT, PSEUDONYMIZE (stubbed fail-closed → BLOCK)

This module DOES NOT re-implement detection — it calls the existing
``yashigani.pii.PiiDetector`` per segment (plan §3.1.1).  Document-borne
INJECTION is PARKED (rev 7) and is NOT classified here.

Fail-closed (plan §6.1, NON-NEGOTIABLE): ANY extraction error, over-cap,
polyglot, or unavailable-format → ``DISPOSITION_BLOCK`` with a precise reason.
``extraction_complete=False`` likewise forces a fail-closed disposition even
if no matches were found ("matches=[] is trustworthy only when extraction is
complete", F9).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from yashigani.documents.datamatch import (
    DataMatch,
    DocumentDecisionInput,
    location_for,
)
from yashigani.documents.extractor import (
    DocumentExtractionError,
    DocumentTooLargeError,
    ExtractorNotAvailableError,
    ExtractorRegistry,
    UnsupportedFormatError,
)
from yashigani.documents.pseudonymize import (
    DEFAULT_MAP_TTL_S,
    CorrespondenceTable,
    ReplacerMap,
    TokenAssigner,
    build_pseudonymize_plan,
    build_redact_plan,
)
from yashigani.documents.segment import ExtractionResult
from yashigani.pii.detector import PiiDetector, PiiMode

logger = logging.getLogger(__name__)


# Document-level dispositions (mirror the OPA action vocabulary, plan §5.0).
DISPOSITION_LOG = "LOG"
DISPOSITION_REDACT = "REDACT"
DISPOSITION_PSEUDONYMIZE = "PSEUDONYMIZE"
DISPOSITION_BLOCK = "BLOCK"

#: Formats with proven regenerate-from-cleaned-content re-render this version
#: (plan §5.2 / §5.5).  A REDACT/PSEUDONYMIZE decision on any OTHER format fails
#: closed to BLOCK (redaction_supported / pseudonymize_supported = False).
_RENDER_SUPPORTED_FORMATS = frozenset({"txt", "csv", "docx", "xlsx", "pptx", "pdf"})

#: Default RBAC role permitted to de-tokenize / receive the mode-A table (the
#: demo rego default; operator-overridable).  Mirrors the rego ``_detok_role``.
DEFAULT_DETOKENIZE_ROLE = "doc-pseudonymize-reverser"


@dataclass
class DocumentInspectionResult:
    """Outcome of inspecting one document."""

    request_id: str
    disposition: str                       # LOG | REDACT | PSEUDONYMIZE | BLOCK
    extraction_complete: bool
    detected_format: str
    matches: list[DataMatch] = field(default_factory=list)
    # The OPA-ready input the gateway would hand to the policy (plan §4.2).
    opa_input: Optional[dict] = None
    # Precise reason for a BLOCK (audit + layman alert).
    block_reason: Optional[str] = None
    audit_fields: dict = field(default_factory=dict)
    # The bytes to forward.  For LOG this is the original document (allow +
    # audit); for REDACT/PSEUDONYMIZE the freshly re-rendered artefact; None for
    # BLOCK.
    forward_bytes: Optional[bytes] = None
    # --- PSEUDONYMIZE outputs (None for other dispositions) ---------------
    #: The replacer map (crown jewel — F5).  Held request-scoped, encrypted,
    #: TTL'd.  ``handle`` is the unguessable capability; the map itself is never
    #: logged.  Present for both modes; in mode B the gateway drives the round-
    #: trip from it, in mode A it backs the correspondence table.
    replacer_map: Optional["ReplacerMap"] = None
    #: Mode-A artefact: the token->original correspondence table delivered to the
    #: user over the RBAC'd channel (the user's re-identification key, §5.3.1).
    correspondence_table: Optional["CorrespondenceTable"] = None
    #: The PSEUDONYMIZE delivery mode actually applied ("A" | "B").
    pseudonymize_mode: Optional[str] = None


class DocumentInspectionPipeline:
    """Channel-agnostic document front-end into the existing PII enumeration.

    Parameters
    ----------
    registry:
        The :class:`ExtractorRegistry` (caps live here).
    pii_detector:
        The EXISTING PII detector.  Defaults to a LOG-mode detector over all
        types — the document path uses it purely for enumeration (the action
        is decided by disposition, not by the detector's mode).
    on_audit:
        Audit sink ``(event_name, fields) -> None`` — reuses the gateway's
        existing audit callback shape (see InspectionPipeline.on_audit).
    """

    def __init__(
        self,
        registry: Optional[ExtractorRegistry] = None,
        pii_detector: Optional[PiiDetector] = None,
        on_audit: Optional[Callable[[str, dict], None]] = None,
        small_set_threshold: int = 20,
    ) -> None:
        self._registry = registry or ExtractorRegistry()
        # LOG mode: enumerate only; never mutate text in the detector — the
        # document path owns the action decision (LOG/REDACT/PSEUDONYMIZE/BLOCK).
        self._pii = pii_detector or PiiDetector(mode=PiiMode.LOG)
        self._on_audit = on_audit or (lambda name, data: None)
        # F2 small-set re-identification threshold (mirrors the rego default).
        self._small_set_threshold = small_set_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(
        self,
        data: bytes,
        declared_mime: str,
        request_id: str,
        *,
        requested_action: str = DISPOSITION_LOG,
        pseudonymize_mode: str = "A",
        detokenize_rbac_role: str = DEFAULT_DETOKENIZE_ROLE,
        map_ttl_s: int = DEFAULT_MAP_TTL_S,
    ) -> DocumentInspectionResult:
        """Inspect a document end-to-end.

        ``requested_action`` is the action a policy/operator asked for.  All four
        actions are wired: LOG (allow + audit), BLOCK (fail-safe), REDACT
        (irreversible re-render), PSEUDONYMIZE (reversible token re-render).  The
        re-render runs in the SAME jail as extraction (red-team F6) — never in the
        gateway process.

        ``pseudonymize_mode`` selects mode A (deliver the user the correspondence
        table — default) or B (internal vault round-trip; position-binding wired).
        """
        # --- Extract (fail-closed on every error) -------------------------
        try:
            extraction = self._registry.extract(data, declared_mime)
        except DocumentTooLargeError as exc:
            return self._block(request_id, f"document over cap: {exc}", detected="oversize")
        except ExtractorNotAvailableError as exc:
            return self._block(
                request_id, f"format not yet supported (fail-closed): {exc}",
                detected="unavailable_format",
            )
        except UnsupportedFormatError as exc:
            return self._block(
                request_id, f"unsupported/ambiguous format: {exc}",
                detected="unsupported",
            )
        except DocumentExtractionError as exc:
            return self._block(request_id, f"extraction failed: {exc}", detected="error")
        except Exception as exc:  # pragma: no cover - defensive
            # Unexpected extractor failure is STILL fail-closed — we never pass
            # a document we could not fully process (plan §6.1).
            logger.exception("document extraction raised unexpectedly")
            return self._block(request_id, f"unexpected extraction error: {exc!r}", detected="error")

        # --- Enumerate DataMatch[] over EVERY segment (existing PII engine) -
        matches, originals = self._enumerate(extraction)

        fmt = extraction.detected_format
        supported = fmt in _RENDER_SUPPORTED_FORMATS
        decision_input = DocumentDecisionInput(
            format=fmt,
            extraction_complete=extraction.extraction_complete,
            segment_kinds=extraction.segment_kinds,
            matches=matches,
            record_count=self._record_count(extraction),
            redaction_supported=supported,
            pseudonymize_supported=supported,
        )
        opa_input = decision_input.to_opa_input()

        # --- Fail-closed: incomplete extraction never passes (F9/§6.1) -----
        if not extraction.extraction_complete:
            return self._block(
                request_id,
                "extraction incomplete — uninspectable parts present, failing closed",
                detected=extraction.detected_format,
                matches=matches,
                opa_input=opa_input,
            )

        # --- Dispatch the action ------------------------------------------
        action = (requested_action or DISPOSITION_LOG).upper()
        if action == DISPOSITION_LOG:
            return self._log(request_id, data, extraction, matches, opa_input)
        if action == DISPOSITION_BLOCK:
            return self._block(
                request_id, "policy requested BLOCK",
                detected=extraction.detected_format, matches=matches, opa_input=opa_input,
            )
        if action == DISPOSITION_REDACT:
            return self._redact(
                request_id, data, extraction, matches, originals, opa_input,
            )
        if action == DISPOSITION_PSEUDONYMIZE:
            return self._pseudonymize(
                request_id, data, extraction, matches, originals, opa_input,
                mode=pseudonymize_mode,
                detokenize_rbac_role=detokenize_rbac_role,
                map_ttl_s=map_ttl_s,
            )
        # Unknown action → fail-closed.
        return self._block(
            request_id, f"unknown action '{action}' — failing closed",
            detected=extraction.detected_format, matches=matches, opa_input=opa_input,
        )

    # ------------------------------------------------------------------
    # Enumeration (reuse existing PII detector — plan §3.1.1)
    # ------------------------------------------------------------------

    #: PII types that are quasi-identifiers (re-identify in combination — F2).
    #: A QI match left un-tokenized on a small record set escalates (§5.3c).
    _QI_TYPES = frozenset({"DATE_OF_BIRTH", "PHONE", "IP_ADDRESS"})

    def _enumerate(
        self, extraction: ExtractionResult
    ) -> tuple[list[DataMatch], dict[str, str]]:
        """Run the EXISTING PII detector per segment incl. hidden/metadata.

        Returns ``(matches, originals)`` where ``originals`` maps
        ``match.location -> raw matched substring``.  The raw substring is needed
        ONLY to drive the re-render (find-and-transform in the jail) and never
        appears in an audit/log line — the :class:`DataMatch` carries only the
        masked instance (F12).  ``qi`` is set for quasi-identifier classes (F2).
        """
        matches: list[DataMatch] = []
        originals: dict[str, str] = {}
        for seg in extraction.segments:
            result = self._pii.detect(seg.text)
            for f in result.findings:
                loc = location_for(seg, f.start, f.end)
                is_qi = f.pii_type.value in self._QI_TYPES
                matches.append(
                    DataMatch(
                        data_class=f"PII.{f.pii_type.value}",
                        qi=is_qi,
                        instance=f.masked_value,
                        location=loc,
                        char_start=f.start,
                        char_end=f.end,
                    )
                )
                # The raw substring (host-side only) for the re-render transform.
                originals[loc] = seg.text[f.start:f.end]
        return matches, originals

    @staticmethod
    def _record_count(extraction: ExtractionResult) -> int:
        """Population size of the record set (F2 small-set gate).

        For CSV/table content the record count is the number of distinct rows
        seen; for flat text it is 0 (not a record set).  Parsed from segment
        provenance without re-reading the document.
        """
        rows: set[str] = set()
        for seg in extraction.segments:
            # TABLE_CELL provenance is "row=R,col=C"
            if seg.location.startswith("row="):
                rows.add(seg.location.split(",", 1)[0])
        return len(rows)

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _log(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        opa_input: dict,
    ) -> DocumentInspectionResult:
        """LOG: allow the document through, but record EVERY match (with
        provenance) to the audit event (plan §5.0)."""
        audit = {
            "event_type": "DOCUMENT_INSPECTED",
            "request_id": request_id,
            "disposition": DISPOSITION_LOG,
            "detected_format": extraction.detected_format,
            "extraction_complete": extraction.extraction_complete,
            "segment_count": len(extraction.segments),
            "segment_kinds": extraction.segment_kinds,
            "match_count": len(matches),
            # Full per-match record (masked instances only — never raw, F12).
            "matches": [m.as_opa_match() for m in matches],
        }
        self._on_audit("DOCUMENT_INSPECTED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_LOG,
            extraction_complete=extraction.extraction_complete,
            detected_format=extraction.detected_format,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=data,  # LOG forwards the original document unchanged.
        )

    # ------------------------------------------------------------------
    # REDACT / PSEUDONYMIZE — re-render in the jail (F6), assert no-residual.
    # ------------------------------------------------------------------

    def _assert_no_residual(
        self,
        output_segments: list[dict],
        originals: dict[str, str],
        *,
        request_id: str,
        fmt: str,
        opa_input: Optional[dict],
        matches: list[DataMatch],
    ) -> Optional[DocumentInspectionResult]:
        """Re-extract-the-output proof (Laura's gate): assert NO original matched
        value survives anywhere in the re-rendered artefact — body, hidden part,
        or metadata.  Returns a BLOCK result if ANY original leaked, else None.

        This is the no-residual assertion the brief mandates: we scan EVERY
        output segment's text (the worker re-extracted the output incl. metadata)
        for every raw original value.  A single hit fails the whole document
        closed — we never ship an artefact we could not prove clean."""
        output_text = "\n".join(str(s.get("text", "")) for s in output_segments)
        for loc, original in originals.items():
            if original and original in output_text:
                return self._block(
                    request_id,
                    f"re-render residual check FAILED: a matched value survived in "
                    f"the output artefact ({loc}) — refusing to ship, fail-closed",
                    detected=fmt, matches=matches, opa_input=opa_input,
                )
        return None

    def _redact(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        originals: dict[str, str],
        opa_input: dict,
    ) -> DocumentInspectionResult:
        """REDACT: irreversibly destroy every matched span + strip ALL hidden
        parts and metadata, re-render a fresh clean artefact in the jail (F6),
        then PROVE no residual by re-extracting the output."""
        fmt = extraction.detected_format
        if not matches:
            # Nothing to redact → still re-render to strip hidden/metadata? No —
            # a clean doc with no matches passes as LOG (forward original). REDACT
            # with zero matches is a no-op disposition → forward unchanged + audit.
            return self._log(request_id, data, extraction, matches, opa_input)

        plan = build_redact_plan(matches, originals)
        try:
            result = self._registry.render(
                data, fmt, job="redact", plan_b64=plan.to_b64(),
            )
        except Exception as exc:
            return self._block(
                request_id, f"REDACT re-render failed: {exc} — fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        residual = self._assert_no_residual(
            result.output_segments, originals,
            request_id=request_id, fmt=fmt, opa_input=opa_input, matches=matches,
        )
        if residual is not None:
            return residual

        audit = {
            "event_type": "DOCUMENT_REDACTED",
            "request_id": request_id,
            "disposition": DISPOSITION_REDACT,
            "detected_format": fmt,
            "match_count": len(matches),
            "matches": [m.as_opa_match() for m in matches],
            "hidden_and_metadata_stripped": True,
            "no_residual_verified": True,
        }
        self._on_audit("DOCUMENT_REDACTED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_REDACT,
            extraction_complete=extraction.extraction_complete,
            detected_format=fmt,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=result.rendered_bytes,
        )

    def _small_set_escalation(
        self, matches: list[DataMatch], record_count: int, pseudonymized_classes: set,
    ) -> bool:
        """F2 small-set / residual-QI gate: escalate to BLOCK when the record set
        is small AND a quasi-identifier remains un-tokenized (re-identifiable by
        inference even after tokenization)."""
        if record_count <= 0 or record_count > self._small_set_threshold:
            return False
        residual_qi = [
            m for m in matches if m.qi and m.data_class not in pseudonymized_classes
        ]
        return bool(matches) and bool(residual_qi)

    def _pseudonymize(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        originals: dict[str, str],
        opa_input: dict,
        *,
        mode: str,
        detokenize_rbac_role: str,
        map_ttl_s: int,
    ) -> DocumentInspectionResult:
        """PSEUDONYMIZE: replace each matched value with a consistent reversible
        token (all QIs — F2), re-render in the jail (F6), vault the replacer map
        (F5), and emit the mode-A table / wire the mode-B binder.

        Fail-closed: an empty plan, a re-render failure, a residual leak, OR a
        small-set re-identification escalation (F2) → BLOCK."""
        fmt = extraction.detected_format
        if not matches:
            return self._log(request_id, data, extraction, matches, opa_input)

        # F2 small-set gate: all detected matches are pseudonymized here (we
        # tokenize every detected class), so residual-QI is only non-empty if an
        # un-tokenized QI class exists. We tokenize ALL detected classes, so the
        # residual set is the QI matches NOT in the pseudonymized set = empty
        # here; the gate still fires if record_count is tiny AND a QI is present
        # that the policy chose to leave (future per-class policy). We compute
        # the pseudonymized set as every class we are about to tokenize.
        pseudonymized_classes = {m.data_class for m in matches}
        record_count = self._record_count(extraction)
        if self._small_set_escalation(matches, record_count, pseudonymized_classes):
            return self._block(
                request_id,
                "re-identifiable small set with residual quasi-identifiers — "
                "escalated to BLOCK (F2), fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        assigner = TokenAssigner()
        plan = build_pseudonymize_plan(matches, originals, assigner)
        try:
            result = self._registry.render(
                data, fmt, job="pseudonymize", plan_b64=plan.to_b64(),
            )
        except Exception as exc:
            return self._block(
                request_id, f"PSEUDONYMIZE re-render failed: {exc} — fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        # No-residual proof: assert NO original value survives in the output
        # (tokenization that leaks the original is worse than useless, §5.5).
        residual = self._assert_no_residual(
            result.output_segments, originals,
            request_id=request_id, fmt=fmt, opa_input=opa_input, matches=matches,
        )
        if residual is not None:
            return residual

        # Vault the replacer map (F5): unguessable handle, AES-256-GCM, TTL'd.
        # The map is the crown jewel — never logged.
        replacer_map = ReplacerMap.create(
            assigner.reverse_map,
            detokenize_rbac_role=detokenize_rbac_role,
            ttl_s=map_ttl_s,
        )
        table = (
            CorrespondenceTable.from_assigner(
                assigner, detokenize_rbac_role=detokenize_rbac_role
            )
            if mode == "A"
            else None
        )

        audit = {
            "event_type": "DOCUMENT_PSEUDONYMIZED",
            "request_id": request_id,
            "disposition": DISPOSITION_PSEUDONYMIZE,
            "detected_format": fmt,
            "pseudonymize_mode": mode,
            "match_count": len(matches),
            "token_count": assigner.token_count,
            # Masked instances + classes only — NEVER the original or the map (F12).
            "matches": [m.as_opa_match() for m in matches],
            "detokenize_rbac_role": detokenize_rbac_role,
            "replacer_map_ttl_s": replacer_map.ttl_s,
            "no_residual_verified": True,
            # The unguessable handle is a CORRELATION-safe field ONLY if it is
            # never the retrieval capability in a log; we deliberately DO NOT put
            # the handle in the audit event (F5) — it is the capability token.
        }
        self._on_audit("DOCUMENT_PSEUDONYMIZED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_PSEUDONYMIZE,
            extraction_complete=extraction.extraction_complete,
            detected_format=fmt,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=result.rendered_bytes,
            replacer_map=replacer_map,
            correspondence_table=table,
            pseudonymize_mode=mode,
        )

    def _block(
        self,
        request_id: str,
        reason: str,
        *,
        detected: str = "unknown",
        matches: Optional[list[DataMatch]] = None,
        opa_input: Optional[dict] = None,
    ) -> DocumentInspectionResult:
        """BLOCK: stop the document; never forward.  Also the fail-safe
        fallback for every error/over-cap/unavailable path (plan §5.0 / §6.1)."""
        matches = matches or []
        audit = {
            "event_type": "DOCUMENT_BLOCKED",
            "request_id": request_id,
            "disposition": DISPOSITION_BLOCK,
            "detected_format": detected,
            "block_reason": reason,
            "match_count": len(matches),
            "matches": [m.as_opa_match() for m in matches],
        }
        self._on_audit("DOCUMENT_BLOCKED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_BLOCK,
            extraction_complete=False,
            detected_format=detected,
            matches=matches,
            opa_input=opa_input,
            block_reason=reason,
            audit_fields=audit,
            forward_bytes=None,  # BLOCK never forwards.
        )
