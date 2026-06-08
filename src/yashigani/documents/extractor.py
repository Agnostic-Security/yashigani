"""
Yashigani Document Enforcement — the DocumentExtractor interface + registry.

A :class:`DocumentExtractor` turns ``(bytes, declared_mime)`` into a normalised
:class:`~yashigani.documents.segment.ExtractionResult` (segments + provenance +
``extraction_complete``).  Those segments then fan into the EXISTING inspection
engines (PII detector) via :mod:`yashigani.documents.pipeline` — the extractor
is a *front-end*, not a parallel pipeline (plan §0-pre / §2 / §4.2).

Fail-closed everywhere (plan §6.1, NON-NEGOTIABLE):
  - Over the size cap        → ``DocumentTooLargeError`` → caller BLOCKs.
  - Unrecognised / polyglot  → ``UnsupportedFormatError`` → caller BLOCKs.
  - Untrusted-parser format  → registered-but-unimplemented extractor that
    raises ``ExtractorNotAvailableError`` (docx/xlsx/pptx/pdf wait for Su's
    sandbox — running those parsers in-process is the RCE surface, red-team
    F1/F6).  These are *registered* so the routing is explicit and the
    fail-closed reason is precise, not a silent gap.

THIS slice implements: the interface, the registry, the cap guards, and the
``txt`` + ``csv`` extractors.  Nothing here runs an untrusted parser.
"""
from __future__ import annotations

import abc
import csv
import io
import logging

from yashigani.documents.detection import (
    DetectedType,
    DetectionResult,
    detect_format,
)
from yashigani.documents.segment import (
    ExtractionResult,
    Segment,
    SegmentKind,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Caps (plan §7 — admin-configurable, fail-closed defaults).  These live here
# as conservative module defaults; the feature-flag/config layer (config.py)
# surfaces the operator override.  Over any cap → fail-closed, never truncate.
# ---------------------------------------------------------------------------

#: Hard ceiling on a single document's byte size before extraction is even
#: attempted.  10 MiB is generous for txt/csv and well under any bomb ratio.
DEFAULT_MAX_DOCUMENT_BYTES = 10 * 1024 * 1024

#: Hard ceiling on the number of segments a document may yield.  A CSV with a
#: pathological row/column count is a cheap amplification; cap it.
DEFAULT_MAX_SEGMENTS = 100_000


# ---------------------------------------------------------------------------
# Exceptions — all fail-closed signals the caller maps to a BLOCK disposition.
# ---------------------------------------------------------------------------

class DocumentExtractionError(Exception):
    """Base class for all extraction failures.  Caller MUST fail-closed."""


class DocumentTooLargeError(DocumentExtractionError):
    """Document exceeded a configured cap (size or segment count)."""


class UnsupportedFormatError(DocumentExtractionError):
    """No extractor is registered for the detected type, or the bytes were
    unrecognised / a polyglot rejected by detection (F8)."""


class ExtractorNotAvailableError(DocumentExtractionError):
    """An extractor is *registered* for the format but is intentionally not yet
    available in this build (untrusted-parser format awaiting Su's sandbox).
    Distinct from :class:`UnsupportedFormatError` so the audit reason is precise.
    """


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------

class DocumentExtractor(abc.ABC):
    """Abstract front-end: ``extract(bytes, declared_mime) -> ExtractionResult``.

    Implementations MUST:
      - emit one :class:`Segment` per logical unit with truthful provenance;
      - set ``extraction_complete=False`` if ANY part was skipped/uninspectable
        (plan §6.1 / red-team F9/F11) — partial extraction must never present
        as complete;
      - raise a :class:`DocumentExtractionError` subclass on any failure rather
        than returning a partial-but-"complete" result.
    """

    #: The detected type this extractor handles (set by subclasses).
    handles: DetectedType

    @abc.abstractmethod
    def extract(self, data: bytes, declared_mime: str) -> ExtractionResult:
        """Extract normalised segments from ``data``."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# txt extractor
# ---------------------------------------------------------------------------

class TxtExtractor(DocumentExtractor):
    """Plain-text extractor.

    A txt file has no hidden channel — extraction is provably complete once the
    bytes decode.  We decode with the same defensive posture as the rest of the
    gateway (utf-8 then latin-1 fallback) and emit one BODY segment per line so
    provenance (``line=N``) is precise for the audit event.
    """

    handles = DetectedType.TXT

    def __init__(self, max_segments: int = DEFAULT_MAX_SEGMENTS) -> None:
        self._max_segments = max_segments

    def extract(self, data: bytes, declared_mime: str) -> ExtractionResult:
        text = _decode_text(data)
        lines = text.split("\n")
        if len(lines) > self._max_segments:
            raise DocumentTooLargeError(
                f"txt produced {len(lines)} segments (cap {self._max_segments})"
            )
        segments: list[Segment] = []
        for idx, line in enumerate(lines, start=1):
            # Keep empty lines out of the segment list (no content to classify)
            # but do NOT collapse them silently if they carried zero-width /
            # whitespace-only payloads — strip() only for the emptiness test.
            if line.strip() == "":
                continue
            segments.append(
                Segment(text=line, kind=SegmentKind.BODY, location=f"line={idx}")
            )
        return ExtractionResult(
            segments=segments,
            extraction_complete=True,
            detected_format=DetectedType.TXT.value,
        )


# ---------------------------------------------------------------------------
# csv extractor
# ---------------------------------------------------------------------------

class CsvExtractor(DocumentExtractor):
    """CSV extractor — one segment per *cell* (table-cell-aware, plan §3.2).

    Cell-level segments are the differentiator for spreadsheets/CSV: PII split
    across columns is found per-cell, and provenance is ``row=R,col=C`` so the
    audit event and any future REDACT/PSEUDONYMIZE can target the exact cell.

    A CSV has no hidden channel, so a fully-parsed CSV is ``extraction_complete``.
    A malformed CSV that the stdlib parser cannot read raises a fail-closed
    error rather than returning a partial result.
    """

    handles = DetectedType.CSV

    def __init__(self, max_segments: int = DEFAULT_MAX_SEGMENTS) -> None:
        self._max_segments = max_segments

    def extract(self, data: bytes, declared_mime: str) -> ExtractionResult:
        text = _decode_text(data)
        segments: list[Segment] = []
        try:
            reader = csv.reader(io.StringIO(text))
            for row_idx, row in enumerate(reader, start=1):
                for col_idx, cell in enumerate(row, start=1):
                    if cell.strip() == "":
                        continue
                    segments.append(
                        Segment(
                            text=cell,
                            kind=SegmentKind.TABLE_CELL,
                            location=f"row={row_idx},col={col_idx}",
                        )
                    )
                    if len(segments) > self._max_segments:
                        raise DocumentTooLargeError(
                            f"csv exceeded segment cap {self._max_segments}"
                        )
        except csv.Error as exc:
            # Malformed CSV is uninspectable → fail-closed (plan §6.1).
            raise DocumentExtractionError(f"csv parse failed: {exc}") from exc
        return ExtractionResult(
            segments=segments,
            extraction_complete=True,
            detected_format=DetectedType.CSV.value,
        )


# ---------------------------------------------------------------------------
# Untrusted-parser placeholder — registered, intentionally fail-closed.
# ---------------------------------------------------------------------------

class _UnavailableExtractor(DocumentExtractor):
    """Registered placeholder for a committed format whose parser is NOT yet
    safe to run in-process.

    docx/xlsx/pptx run OOXML/zip+XML parsers and pdf runs a PDF object-graph
    parser — both are untrusted-parser RCE surface (red-team F1/F6) and MUST
    wait for Su's per-job sandbox container.  Registering them here (rather
    than leaving a gap) makes the routing explicit and the BLOCK reason precise.

    TODO(Su): provide the sandboxed extractor container (no-egress, dropped
              caps, seccomp, ro-rootfs, killed-per-job — plan §6 B1).
    TODO(Captain): container isolation parity (Docker/Podman rootful+rootless/
              K8s-Helm) for the sandbox.
    TODO(Tom, next slice): implement OOXMLExtractor + PdfNativeExtractor to run
              INSIDE that sandbox, then replace this placeholder in the registry.
    """

    def __init__(self, handles: DetectedType) -> None:
        self.handles = handles

    def extract(self, data: bytes, declared_mime: str) -> ExtractionResult:
        raise ExtractorNotAvailableError(
            f"format '{self.handles.value}' requires the sandboxed extractor "
            f"(not yet available) — failing closed to BLOCK"
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class ExtractorRegistry:
    """Maps a detected type → its extractor.  Committed formats only (plan §2).

    Unimplemented untrusted-parser formats are registered to a fail-closed
    placeholder so routing is explicit; everything else is an
    :class:`UnsupportedFormatError` (also fail-closed).
    """

    def __init__(
        self,
        max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
        max_segments: int = DEFAULT_MAX_SEGMENTS,
    ) -> None:
        self._max_document_bytes = max_document_bytes
        self._registry: dict[DetectedType, DocumentExtractor] = {
            DetectedType.TXT: TxtExtractor(max_segments=max_segments),
            DetectedType.CSV: CsvExtractor(max_segments=max_segments),
            # Committed formats, registered-but-unimplemented (fail-closed):
            DetectedType.DOCX: _UnavailableExtractor(DetectedType.DOCX),
            DetectedType.XLSX: _UnavailableExtractor(DetectedType.XLSX),
            DetectedType.PPTX: _UnavailableExtractor(DetectedType.PPTX),
            DetectedType.PDF: _UnavailableExtractor(DetectedType.PDF),
        }

    def detect(self, data: bytes, declared_mime: str) -> DetectionResult:
        """Run format detection (cap-guarded)."""
        if len(data) > self._max_document_bytes:
            raise DocumentTooLargeError(
                f"document is {len(data)} bytes (cap {self._max_document_bytes})"
            )
        return detect_format(data, declared_mime)

    def extract(self, data: bytes, declared_mime: str) -> ExtractionResult:
        """Detect, then dispatch to the matching extractor.

        Raises a :class:`DocumentExtractionError` subclass on any failure — the
        caller (pipeline) maps every one of those to a fail-closed BLOCK.
        """
        # Cap-check BEFORE detection so a bomb never fully lands (plan §7).
        detection = self.detect(data, declared_mime)

        if not detection.consistent or detection.detected_type == DetectedType.UNKNOWN:
            raise UnsupportedFormatError(detection.reason)

        extractor = self._registry.get(detection.detected_type)
        if extractor is None:
            raise UnsupportedFormatError(
                f"no extractor registered for '{detection.detected_type.value}'"
            )
        return extractor.extract(data, declared_mime)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_text(data: bytes) -> str:
    """Decode bytes to text defensively: utf-8 then latin-1 fallback.

    latin-1 never raises, so this always returns a str — but it preserves the
    raw code points (incl. any homoglyph/zero-width payload) so downstream
    normalisation (a later-slice concern, red-team F7) still sees them.  We do
    NOT silently drop undecodable bytes.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")
