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
    is_modeb_proxy_enabled,
)
from yashigani.documents.proxy_modeb import (
    PROXY_EGRESS_ROUTE,
    EgressOutcome,
    IngressOutcome,
    egress_decide,
    ingress_restore,
    is_modeb_proxy_active,
    looks_like_document_egress,
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
    DISPOSITION_ROUTE_LOCAL,
    OPERATE_ON_ALLOW_BLOB,
    OPERATE_ON_BLOCK,
    OPERATE_ON_ROUTE_LOCAL,
    DocumentInspectionPipeline,
    DocumentInspectionResult,
    IntegrityVerifyResult,
    ModeBRestoreResult,
)
from yashigani.documents.field_role import (
    FieldRole,
    classify_field_role,
    is_operate_on_sensitive,
)
from yashigani.documents.pseudonymize import (
    CorrespondenceTable,
    EchoEgressError,
    ModeBRoundTrip,
    OpaqueTokenAssigner,
    PositionBinder,
    ReplacerMap,
    ReplacerMapExpiredError,
    ReplacerMapIdentityError,
    TokenAssigner,
    build_modeb_roundtrip,
    is_pseudonymization_token,
    local_remerge,
)
from yashigani.documents.token_scheme import (
    TOKEN_CHARS,
    compute_doc_hash,
    derive_token,
    load_deployment_secret,
    token_matches_doc,
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
from yashigani.documents.qi_context import (
    ContextMatch,
    classify_columns,
    header_driven_matches,
)
from yashigani.documents.policy_store import DocumentPolicyStore
from yashigani.documents.opa_push import push_document_data
from yashigani.documents.opa_decision import evaluate_document_decision

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
    "IntegrityVerifyResult",
    "ModeBRestoreResult",
    "DISPOSITION_LOG",
    "DISPOSITION_REDACT",
    "DISPOSITION_PSEUDONYMIZE",
    "DISPOSITION_BLOCK",
    "DISPOSITION_ROUTE_LOCAL",
    # PART 2 (Laura D1) field-role routing
    "FieldRole",
    "classify_field_role",
    "is_operate_on_sensitive",
    "OPERATE_ON_ROUTE_LOCAL",
    "OPERATE_ON_BLOCK",
    "OPERATE_ON_ALLOW_BLOB",
    # re-render plan contract (host <-> jail)
    "RenderPlan",
    "RenderSpan",
    "SpanAction",
    # PSEUDONYMIZE engine (host-side; crown-jewel custody)
    "TokenAssigner",
    "OpaqueTokenAssigner",
    "is_pseudonymization_token",
    "ReplacerMap",
    "ReplacerMapExpiredError",
    "ReplacerMapIdentityError",
    "CorrespondenceTable",
    "PositionBinder",
    "EchoEgressError",
    "ModeBRoundTrip",
    "build_modeb_roundtrip",
    "local_remerge",
    # opaque, per-file-salted token scheme (DECIDED 2026-06-10)
    "TOKEN_CHARS",
    "compute_doc_hash",
    "derive_token",
    "load_deployment_secret",
    "token_matches_doc",
    # column-semantic identifying-class detection (L-01 / F2 QI breadth)
    "ContextMatch",
    "classify_columns",
    "header_driven_matches",
    # config / feature flag
    "DocumentEnforcementConfig",
    "is_document_enforcement_enabled",
    "is_modeb_proxy_enabled",
    # 2.26 mode-B-via-proxy egress round-trip (gap #1)
    "EgressOutcome",
    "IngressOutcome",
    "egress_decide",
    "PROXY_EGRESS_ROUTE",
    "ingress_restore",
    "is_modeb_proxy_active",
    "looks_like_document_egress",
    # 2.26 productionised policy layer: persistent matrix store + real-OPA path
    "DocumentPolicyStore",
    "push_document_data",
    "evaluate_document_decision",
]
