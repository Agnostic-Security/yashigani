"""
Yashigani Document Enforcement — the normalised segment model.

A document is turned into a list of :class:`Segment` by a
:class:`~yashigani.documents.extractor.DocumentExtractor`.  Each segment
carries the extracted text *plus provenance* so a verdict can be applied
precisely and the audit event can record exactly where a match was found.

Design references (Products/Yashigani/opa_document_enforcement_plan_2026-06-07.md):
  - §3.1 the segment model (text + kind + location + confidence + needs_ocr).
  - The hidden-data parts (comments, tracked changes, speaker notes, hidden
    rows/sheets, metadata, headers/footers) are FIRST-CLASS, not an
    afterthought — they are *where* sensitive data hides.  This module
    reserves a ``SegmentKind`` slot for every hidden-part class even though
    the only extractors built in this slice (txt, csv) cannot yet produce
    them; the OOXML/PDF extractors (parked behind Su's sandbox) will.

Scope of THIS slice (foundation): the model itself + the BODY / TABLE_CELL /
METADATA kinds that txt/csv exercise.  The remaining kinds are defined so the
interface is stable for the next slice and downstream consumers (OPA input
``document.segment_kinds``) do not churn.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SegmentKind(str, Enum):
    """Provenance class of an extracted segment.

    Every value here is a slot in the stable extraction contract.  Hidden-part
    kinds (COMMENT, TRACKED_CHANGE, SPEAKER_NOTE, HIDDEN, METADATA,
    HEADER_FOOTER, EMBEDDED_OBJECT, MACRO_SOURCE, ATTACHMENT) are produced by
    extractors not yet built in this slice (they require Su's sandbox); they
    are declared now so the segment model and the OPA ``segment_kinds`` input
    are stable across the build.
    """

    BODY = "BODY"
    TABLE_CELL = "TABLE_CELL"
    COMMENT = "COMMENT"
    TRACKED_CHANGE = "TRACKED_CHANGE"
    SPEAKER_NOTE = "SPEAKER_NOTE"
    HIDDEN = "HIDDEN"
    METADATA = "METADATA"
    HEADER_FOOTER = "HEADER_FOOTER"
    EMBEDDED_OBJECT = "EMBEDDED_OBJECT"
    OCR = "OCR"
    MACRO_SOURCE = "MACRO_SOURCE"
    ATTACHMENT = "ATTACHMENT"


@dataclass(frozen=True)
class Segment:
    """A single normalised unit of extracted document content.

    Parameters
    ----------
    text:
        Extracted text of this segment.
    kind:
        Provenance class (:class:`SegmentKind`).
    location:
        Human/audit-readable provenance, e.g. ``"row=12"``, ``"cell=B12"``,
        ``"sheet=Payroll!B12"``, ``"slide=4/notes"``, ``"page=7"``,
        ``"metadata=author"``.  Never empty — fail-closed callers rely on it
        for the audit event.
    confidence:
        ``1.0`` for native text; ``<1.0`` for OCR-derived text (future).
    needs_ocr:
        ``True`` when this segment references content that could only be fully
        recovered via OCR (parked, §A) — drives ``extraction_complete=false``.
    """

    text: str
    kind: SegmentKind
    location: str
    confidence: float = 1.0
    needs_ocr: bool = False

    def __post_init__(self) -> None:
        if not self.location:
            # Provenance is load-bearing for the audit event; an empty
            # location is a programming error in an extractor, not user input.
            raise ValueError("Segment.location must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Segment.confidence must be in [0.0, 1.0]")


@dataclass
class ExtractionResult:
    """The full output of an extractor for one document.

    ``extraction_complete`` is the load-bearing fail-closed signal (plan §6.1,
    red-team F9/F11): it is ``True`` only when *every* part of the document was
    parsed and classified.  Any skipped/errored/over-cap/uninspectable part
    (e.g. an embedded raster needing OCR) sets it ``False``, and the OPA
    decision point then treats the document as max-sensitivity / fail-closed.

    ``matches=[]`` is trustworthy ONLY when ``extraction_complete`` is ``True``
    AND every segment was classified — see plan §6.1.
    """

    segments: list[Segment]
    extraction_complete: bool
    detected_format: str
    notes: list[str] = field(default_factory=list)

    @property
    def segment_kinds(self) -> list[str]:
        """Distinct segment kinds present — feeds OPA ``document.segment_kinds``."""
        seen: list[str] = []
        for seg in self.segments:
            if seg.kind.value not in seen:
                seen.append(seg.kind.value)
        return seen
