"""
Yashigani Document Enforcement — channel-agnostic document content front-end.

This package brings document bytes into the SAME inspection + OPA decision point
that typed text / JSON / API streams already pass through (plan §0-pre): a
content-extraction front-end turns document bytes into normalised segments, and
those segments fan into the EXISTING PII enumeration — it is NOT a parallel
pipeline.

Committed formats (plan §2): docx, xlsx, pptx, pdf, csv, txt.
THIS slice (foundation): the extractor interface + format registry + the two
trivial formats (txt, csv) end-to-end, behind a feature flag (default OFF),
wired to the existing PII detector, with the LOG action implemented end-to-end
and BLOCK wired as the fail-safe.  docx/xlsx/pptx/pdf are registered-but-
unimplemented and fail closed to BLOCK (they run untrusted parsers → await
Su's sandbox).

Public surface:
    Segment, SegmentKind, ExtractionResult           — the segment model
    DetectedType, DetectionResult, detect_format     — magic-byte + MIME sniff
    DocumentExtractor, ExtractorRegistry,            — the interface + registry
        TxtExtractor, CsvExtractor
    DocumentExtractionError (+ subclasses)           — fail-closed signals
    DataMatch, DocumentDecisionInput                 — OPA decision input
    DocumentInspectionPipeline,                      — the front-end pipeline
        DocumentInspectionResult, DISPOSITION_*
    DocumentEnforcementConfig,                       — feature flag + caps
        is_document_enforcement_enabled
"""
from yashigani.documents.config import (
    DocumentEnforcementConfig,
    is_document_enforcement_enabled,
)
from yashigani.documents.datamatch import DataMatch, DocumentDecisionInput
from yashigani.documents.detection import (
    DetectedType,
    DetectionResult,
    detect_format,
)
from yashigani.documents.extractor import (
    CsvExtractor,
    DocumentExtractionError,
    DocumentExtractor,
    DocumentTooLargeError,
    ExtractorNotAvailableError,
    ExtractorRegistry,
    TxtExtractor,
    UnsupportedFormatError,
)
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_LOG,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_REDACT,
    DocumentInspectionPipeline,
    DocumentInspectionResult,
)
from yashigani.documents.pseudonymize import (
    CorrespondenceTable,
    PositionBinder,
    ReplacerMap,
    ReplacerMapExpiredError,
    TokenAssigner,
    local_remerge,
)
from yashigani.documents.segment import (
    ExtractionResult,
    Segment,
    SegmentKind,
)
from yashigani.documents.transform import (
    RenderPlan,
    RenderSpan,
    SpanAction,
)

__all__ = [
    # segment model
    "Segment",
    "SegmentKind",
    "ExtractionResult",
    # detection
    "DetectedType",
    "DetectionResult",
    "detect_format",
    # extractor interface + registry + impls
    "DocumentExtractor",
    "ExtractorRegistry",
    "TxtExtractor",
    "CsvExtractor",
    # fail-closed signals
    "DocumentExtractionError",
    "DocumentTooLargeError",
    "UnsupportedFormatError",
    "ExtractorNotAvailableError",
    # OPA decision input
    "DataMatch",
    "DocumentDecisionInput",
    # pipeline
    "DocumentInspectionPipeline",
    "DocumentInspectionResult",
    "DISPOSITION_LOG",
    "DISPOSITION_REDACT",
    "DISPOSITION_PSEUDONYMIZE",
    "DISPOSITION_BLOCK",
    # re-render plan contract (host <-> jail)
    "RenderPlan",
    "RenderSpan",
    "SpanAction",
    # PSEUDONYMIZE engine (host-side; crown-jewel custody)
    "TokenAssigner",
    "ReplacerMap",
    "ReplacerMapExpiredError",
    "CorrespondenceTable",
    "PositionBinder",
    "local_remerge",
    # config / feature flag
    "DocumentEnforcementConfig",
    "is_document_enforcement_enabled",
]
