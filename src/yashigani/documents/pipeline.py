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
from yashigani.documents.segment import ExtractionResult
from yashigani.pii.detector import PiiDetector, PiiMode

logger = logging.getLogger(__name__)


# Document-level dispositions (mirror the OPA action vocabulary, plan §5.0).
DISPOSITION_LOG = "LOG"
DISPOSITION_REDACT = "REDACT"
DISPOSITION_PSEUDONYMIZE = "PSEUDONYMIZE"
DISPOSITION_BLOCK = "BLOCK"


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
    # audit).  None for BLOCK.  REDACT/PSEUDONYMIZE re-render is a later slice.
    forward_bytes: Optional[bytes] = None


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
    ) -> None:
        self._registry = registry or ExtractorRegistry()
        # LOG mode: enumerate only; never mutate text in the detector — the
        # document path owns the action decision (LOG/REDACT/PSEUDONYMIZE/BLOCK).
        self._pii = pii_detector or PiiDetector(mode=PiiMode.LOG)
        self._on_audit = on_audit or (lambda name, data: None)

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
    ) -> DocumentInspectionResult:
        """Inspect a document end-to-end.

        ``requested_action`` is the action a policy/operator asked for.  This
        slice implements LOG end-to-end and BLOCK; REDACT and PSEUDONYMIZE are
        stubbed to fail-closed (→ BLOCK) until the sandboxed re-render machinery
        lands (next slice).
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
        matches = self._enumerate(extraction)

        decision_input = DocumentDecisionInput(
            format=extraction.detected_format,
            extraction_complete=extraction.extraction_complete,
            segment_kinds=extraction.segment_kinds,
            matches=matches,
            record_count=self._record_count(extraction),
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
        if action in (DISPOSITION_REDACT, DISPOSITION_PSEUDONYMIZE):
            # Stubbed fail-closed (next slice — needs sandboxed re-render, B4).
            # TODO(Tom, next slice): implement REDACT/PSEUDONYMIZE re-render
            #   inside Su's sandbox; until then a policy asking for them on a
            #   format without re-render support fails closed to BLOCK
            #   (redaction_supported / pseudonymize_supported are False here).
            return self._block(
                request_id,
                f"{action} not yet available (re-render machinery pending) — "
                f"failing closed to BLOCK",
                detected=extraction.detected_format, matches=matches, opa_input=opa_input,
            )
        # Unknown action → fail-closed.
        return self._block(
            request_id, f"unknown action '{action}' — failing closed",
            detected=extraction.detected_format, matches=matches, opa_input=opa_input,
        )

    # ------------------------------------------------------------------
    # Enumeration (reuse existing PII detector — plan §3.1.1)
    # ------------------------------------------------------------------

    def _enumerate(self, extraction: ExtractionResult) -> list[DataMatch]:
        """Run the EXISTING PII detector per segment incl. hidden/metadata.

        We call ``PiiDetector.detect`` (read-only scan) on each segment's text
        and wrap each finding as a :class:`DataMatch` with full provenance.
        Raw values never appear — we carry the detector's masked value.
        """
        matches: list[DataMatch] = []
        for seg in extraction.segments:
            result = self._pii.detect(seg.text)
            for f in result.findings:
                matches.append(
                    DataMatch(
                        data_class=f"PII.{f.pii_type.value}",
                        qi=False,  # TODO(Tom, F2): net-new QI tagger (next slice)
                        instance=f.masked_value,
                        location=location_for(seg, f.start, f.end),
                        char_start=f.start,
                        char_end=f.end,
                    )
                )
        return matches

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
