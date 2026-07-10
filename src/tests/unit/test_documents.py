"""
Tests for the document-enforcement front-end (yashigani.documents).

Covers the foundation slice (2.26 document-OPA):
  - the Segment / ExtractionResult model invariants
  - format detection: magic-bytes + declared-MIME, polyglot/mismatch reject (F8)
  - txt extraction incl. a hidden-data/edge case (zero-width / homoglyph
    survives decoding so the classifier still sees it)
  - csv cell-aware extraction + record_count
  - the byte-size cap guard and segment-count cap guard (fail-closed)
  - the registered-but-unimplemented (untrusted-parser) formats fail closed
  - the feature flag (default OFF) + caps from env
  - the LOG action end-to-end through the pipeline (allow + audit every match)
  - the BLOCK fail-safe + incomplete-extraction fail-closed (F9)
  - REDACT/PSEUDONYMIZE stubbed fail-closed
"""
from __future__ import annotations

import pytest

from yashigani.documents.config import (
    DocumentEnforcementConfig,
    ENV_ENABLED,
    ENV_MAX_BYTES,
    ENV_MAX_SEGMENTS,
    is_document_enforcement_enabled,
)
from yashigani.documents.datamatch import DataMatch, DocumentDecisionInput
from yashigani.documents.detection import (
    DetectedType,
    detect_format,
)
from yashigani.documents.extractor import (
    CsvExtractor,
    DocumentExtractionError,
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
)
from yashigani.documents.segment import (
    ExtractionResult,
    Segment,
    SegmentKind,
)


# ---------------------------------------------------------------------------
# Segment model invariants
# ---------------------------------------------------------------------------

def test_segment_requires_location():
    with pytest.raises(ValueError):
        Segment(text="x", kind=SegmentKind.BODY, location="")


def test_segment_confidence_bounds():
    with pytest.raises(ValueError):
        Segment(text="x", kind=SegmentKind.BODY, location="line=1", confidence=1.5)
    # valid bounds OK
    Segment(text="x", kind=SegmentKind.BODY, location="line=1", confidence=0.0)
    Segment(text="x", kind=SegmentKind.BODY, location="line=1", confidence=1.0)


def test_extraction_result_segment_kinds_distinct_ordered():
    res = ExtractionResult(
        segments=[
            Segment(text="a", kind=SegmentKind.BODY, location="line=1"),
            Segment(text="b", kind=SegmentKind.TABLE_CELL, location="row=1,col=1"),
            Segment(text="c", kind=SegmentKind.BODY, location="line=2"),
        ],
        extraction_complete=True,
        detected_format="txt",
    )
    assert res.segment_kinds == ["BODY", "TABLE_CELL"]


def test_segment_kind_reserves_hidden_part_slots():
    # The hidden-part kinds are first-class slots in the contract even though
    # txt/csv cannot produce them yet (next slice / sandbox).
    for name in (
        "COMMENT", "TRACKED_CHANGE", "SPEAKER_NOTE", "HIDDEN",
        "METADATA", "HEADER_FOOTER", "EMBEDDED_OBJECT", "MACRO_SOURCE",
        "ATTACHMENT", "OCR",
    ):
        assert hasattr(SegmentKind, name)


# ---------------------------------------------------------------------------
# Format detection — magic-bytes vs declared MIME (F2/F8)
# ---------------------------------------------------------------------------

def test_detect_txt_consistent():
    d = detect_format(b"just some plain text\n", "text/plain")
    assert d.detected_type == DetectedType.TXT
    assert d.consistent is True


def test_detect_csv_consistent():
    d = detect_format(b"a,b,c\n1,2,3\n", "text/csv")
    assert d.detected_type == DetectedType.CSV
    assert d.consistent is True


def test_detect_no_declared_mime_accepts_sniff():
    d = detect_format(b"hello world", "")
    assert d.detected_type == DetectedType.TXT
    assert d.consistent is True


def test_detect_polyglot_declared_text_actual_zip_rejected():
    # Declared text/csv but the bytes are an OOXML/zip → fail-closed (F8).
    d = detect_format(b"PK\x03\x04" + b"\x00" * 40, "text/csv")
    assert d.detected_type == DetectedType.UNKNOWN
    assert d.consistent is False
    assert "polyglot" in d.reason or "disagrees" in d.reason


def test_detect_append_aware_zip_eocd_anywhere():
    # "text + appended docx": EOCD signature buried in the stream must still be
    # recognised as a zip/OOXML, not the text path (F8 append-aware sniff).
    payload = b"looks like text at the start " + b"PK\x05\x06" + b"\x00" * 18
    d = detect_format(payload, "")
    # No declared MIME → sniff alone resolves to an OOXML family member.
    assert d.detected_type in (
        DetectedType.DOCX, DetectedType.XLSX, DetectedType.PPTX,
    )


def test_detect_pdf_magic():
    d = detect_format(b"%PDF-1.7\n...", "application/pdf")
    assert d.detected_type == DetectedType.PDF
    assert d.consistent is True


def test_detect_declared_pdf_actual_text_rejected():
    d = detect_format(b"this is plainly text", "application/pdf")
    assert d.detected_type == DetectedType.UNKNOWN
    assert d.consistent is False


def test_detect_binary_unknown_rejected():
    d = detect_format(b"\x00\x01\x02\x03\xff\xfe", "application/octet-stream")
    assert d.detected_type == DetectedType.UNKNOWN
    assert d.consistent is False


# ---------------------------------------------------------------------------
# txt extraction (incl. hidden-data / edge case)
# ---------------------------------------------------------------------------

def test_txt_extracts_per_line_with_provenance():
    ex = TxtExtractor()
    res = ex.extract(b"line one\nline two\n\nline four", "text/plain")
    assert res.extraction_complete is True
    assert [s.location for s in res.segments] == ["line=1", "line=2", "line=4"]
    assert all(s.kind == SegmentKind.BODY for s in res.segments)


def test_txt_hidden_data_zero_width_survives_decoding():
    # Edge case: a zero-width joiner embedded in an email keeps the raw code
    # points intact after decode so a later-slice normaliser (F7) can still see
    # them.  We assert the extractor does NOT silently strip them.
    zwj = "‍"
    raw = f"alice{zwj}@example.com".encode("utf-8")
    res = TxtExtractor().extract(raw, "text/plain")
    assert len(res.segments) == 1
    assert zwj in res.segments[0].text


def test_txt_latin1_fallback_does_not_raise():
    # Non-UTF8 bytes must not crash the extractor (defensive decode).
    res = TxtExtractor().extract(b"caf\xe9 menu", "text/plain")
    assert res.extraction_complete is True
    assert res.segments[0].text.startswith("caf")


# ---------------------------------------------------------------------------
# csv extraction (cell-aware)
# ---------------------------------------------------------------------------

def test_csv_extracts_per_cell_with_provenance():
    ex = CsvExtractor()
    res = ex.extract(b"name,email\nAlice,alice@example.com\n", "text/csv")
    assert res.extraction_complete is True
    locs = [s.location for s in res.segments]
    assert "row=1,col=1" in locs  # header cell "name"
    assert "row=2,col=2" in locs  # alice@example.com cell
    assert all(s.kind == SegmentKind.TABLE_CELL for s in res.segments)


def test_csv_skips_empty_cells():
    res = CsvExtractor().extract(b"a,,c\n", "text/csv")
    # empty middle cell skipped; a and c kept
    texts = [s.text for s in res.segments]
    assert texts == ["a", "c"]


# ---------------------------------------------------------------------------
# Cap guards (fail-closed)
# ---------------------------------------------------------------------------

def test_byte_size_cap_fails_closed():
    reg = ExtractorRegistry(max_document_bytes=16)
    with pytest.raises(DocumentTooLargeError):
        reg.extract(b"x" * 17, "text/plain")


def test_segment_count_cap_fails_closed_txt():
    ex = TxtExtractor(max_segments=3)
    with pytest.raises(DocumentTooLargeError):
        # 5 non-empty lines → more than 3 segments
        ex.extract(b"a\nb\nc\nd\ne\n", "text/plain")


def test_segment_count_cap_fails_closed_csv():
    ex = CsvExtractor(max_segments=2)
    with pytest.raises(DocumentTooLargeError):
        ex.extract(b"1,2,3\n4,5,6\n", "text/csv")


# ---------------------------------------------------------------------------
# Registry: untrusted-parser formats fail closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "magic, mime",
    [
        (b"PK\x03\x04" + b"\x00" * 40, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        (b"%PDF-1.7\n...", "application/pdf"),
    ],
)
def test_untrusted_parser_format_unavailable_when_no_sandbox(magic, mime):
    """When NO sandbox backend is available, an untrusted-parser format fails
    closed with ExtractorNotAvailableError (the precise "sandbox not provisioned"
    reason).  We inject a no-backend runner so this is deterministic regardless
    of whether an extractor image happens to be built on the host — the contract
    is "no isolation → never parse in-process → BLOCK" (Captain's sandbox seam).
    """
    from yashigani.documents.sandbox import (
        SandboxUnavailableError,
        SandboxedExtractorRunner,
    )

    class _NoBackend(SandboxedExtractorRunner):
        def _resolve_backend(self):
            raise SandboxUnavailableError("no backend (test)")

    reg = ExtractorRegistry(sandbox_runner=_NoBackend(backend=None))
    with pytest.raises(ExtractorNotAvailableError):
        reg.extract(magic, mime)


def test_unsupported_format_rejected():
    reg = ExtractorRegistry()
    with pytest.raises(UnsupportedFormatError):
        reg.extract(b"\x00\x01\x02binary", "application/octet-stream")


# ---------------------------------------------------------------------------
# Feature flag (default OFF) + env caps
# ---------------------------------------------------------------------------

def test_feature_flag_default_off(monkeypatch):
    monkeypatch.delenv(ENV_ENABLED, raising=False)
    assert is_document_enforcement_enabled() is False


def test_feature_flag_opt_in(monkeypatch):
    monkeypatch.setenv(ENV_ENABLED, "true")
    assert is_document_enforcement_enabled() is True
    monkeypatch.setenv(ENV_ENABLED, "TRUE")
    assert is_document_enforcement_enabled() is True
    monkeypatch.setenv(ENV_ENABLED, "1")  # only "true" counts → still off
    assert is_document_enforcement_enabled() is False


def test_config_from_env_caps(monkeypatch):
    monkeypatch.setenv(ENV_ENABLED, "true")
    monkeypatch.setenv(ENV_MAX_BYTES, "2048")
    monkeypatch.setenv(ENV_MAX_SEGMENTS, "50")
    cfg = DocumentEnforcementConfig.from_env()
    assert cfg.enabled is True
    assert cfg.max_document_bytes == 2048
    assert cfg.max_segments == 50
    reg = cfg.build_registry()
    with pytest.raises(DocumentTooLargeError):
        reg.extract(b"x" * 4096, "text/plain")


def test_config_malformed_cap_falls_back_to_default(monkeypatch):
    monkeypatch.setenv(ENV_MAX_BYTES, "not-a-number")
    monkeypatch.setenv(ENV_MAX_SEGMENTS, "-5")  # non-positive → default
    cfg = DocumentEnforcementConfig.from_env()
    from yashigani.documents.extractor import (
        DEFAULT_MAX_DOCUMENT_BYTES,
        DEFAULT_MAX_SEGMENTS,
    )
    assert cfg.max_document_bytes == DEFAULT_MAX_DOCUMENT_BYTES
    assert cfg.max_segments == DEFAULT_MAX_SEGMENTS


# ---------------------------------------------------------------------------
# LOG action end-to-end through the pipeline
# ---------------------------------------------------------------------------

def test_log_action_end_to_end_audits_every_match():
    events: list[tuple[str, dict]] = []
    pipe = DocumentInspectionPipeline(on_audit=lambda name, data: events.append((name, data)))

    data = b"name,email,card\nAlice,alice@example.com,4111111111111111\n"
    res = pipe.inspect(data, "text/csv", "req-log-1", requested_action=DISPOSITION_LOG)

    assert res.disposition == DISPOSITION_LOG
    assert res.forward_bytes == data           # LOG forwards original unchanged
    assert res.extraction_complete is True
    # email + valid-Luhn card enumerated
    classes = {m.data_class for m in res.matches}
    assert "PII.EMAIL" in classes
    assert "PII.CREDIT_CARD" in classes
    # audit fired with the full per-match record (masked instances only)
    assert events and events[0][0] == "DOCUMENT_INSPECTED"
    audit = events[0][1]
    assert audit["match_count"] == len(res.matches)
    for m in audit["matches"]:
        assert "****" in m["instance"]  # never raw
    # OPA-ready input is populated
    assert res.opa_input["format"] == "csv"
    assert res.opa_input["extraction_complete"] is True
    # record_count is the DATA-row population (header excluded, L-01/L-06 fix):
    # "name,email,card" header + one "Alice" data row → 1 record.
    assert res.opa_input["record_count"] == 1


def test_log_clean_document_passes_with_no_matches():
    pipe = DocumentInspectionPipeline()
    res = pipe.inspect(b"just some harmless text\nno secrets here", "text/plain", "req-clean")
    assert res.disposition == DISPOSITION_LOG
    assert res.matches == []
    assert res.forward_bytes is not None


def test_datamatch_instance_is_masked_never_raw():
    pipe = DocumentInspectionPipeline()
    res = pipe.inspect(b"email: secret.person@example.com", "text/plain", "req-mask")
    assert res.matches
    for m in res.matches:
        assert "secret.person@example.com" not in m.instance
        assert "****" in m.instance


# ---------------------------------------------------------------------------
# Fail-closed dispositions through the pipeline
# ---------------------------------------------------------------------------

def test_pipeline_blocks_polyglot():
    pipe = DocumentInspectionPipeline()
    res = pipe.inspect(b"PK\x03\x04" + b"\x00" * 40, "text/csv", "req-poly")
    assert res.disposition == DISPOSITION_BLOCK
    assert res.forward_bytes is None
    assert "polyglot" in res.block_reason or "disagrees" in res.block_reason


def test_pipeline_blocks_unavailable_format():
    pipe = DocumentInspectionPipeline()
    res = pipe.inspect(b"%PDF-1.7\n...", "application/pdf", "req-pdf")
    assert res.disposition == DISPOSITION_BLOCK
    assert "sandbox" in res.block_reason or "not yet" in res.block_reason


def test_pipeline_blocks_oversize():
    reg = ExtractorRegistry(max_document_bytes=8)
    pipe = DocumentInspectionPipeline(registry=reg)
    res = pipe.inspect(b"x" * 100, "text/plain", "req-big")
    assert res.disposition == DISPOSITION_BLOCK
    assert "cap" in res.block_reason


def test_pipeline_incomplete_extraction_fails_closed():
    # An extractor that reports incomplete extraction must never pass, even with
    # zero matches (F9: matches=[] is only trustworthy when complete).
    from yashigani.documents.extractor import DocumentExtractor
    from yashigani.documents.detection import DetectedType

    class _IncompleteExtractor(DocumentExtractor):
        handles = DetectedType.TXT

        def extract(self, data, declared_mime):
            return ExtractionResult(
                segments=[Segment(text="clean", kind=SegmentKind.BODY, location="line=1")],
                extraction_complete=False,  # uninspectable part present
                detected_format="txt",
            )

    reg = ExtractorRegistry()
    reg._registry[DetectedType.TXT] = _IncompleteExtractor()
    pipe = DocumentInspectionPipeline(registry=reg)
    res = pipe.inspect(b"clean text", "text/plain", "req-incomplete")
    assert res.disposition == DISPOSITION_BLOCK
    assert "incomplete" in res.block_reason


def test_pipeline_redact_pseudonymize_fail_closed_without_sandbox():
    """REDACT/PSEUDONYMIZE re-render runs ONLY in the jail (red-team F6). With NO
    sandbox backend available the re-render cannot run, so both actions fail
    closed to BLOCK — never an in-process re-render, never a partial allow."""
    from yashigani.documents.sandbox import (
        SandboxedExtractorRunner,
        SandboxUnavailableError,
    )

    class _NoBackend:
        def run_extractor_job(self, *, stdin, timeout_s, **kwargs):
            raise SandboxUnavailableError("no backend in test")

    runner = SandboxedExtractorRunner(backend=_NoBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    pipe = DocumentInspectionPipeline(registry=reg)
    data = b"email,alice@example.com\n"
    for action in (DISPOSITION_REDACT, DISPOSITION_PSEUDONYMIZE):
        res = pipe.inspect(data, "text/csv", "req-stub", requested_action=action)
        assert res.disposition == DISPOSITION_BLOCK
        assert "fail-closed" in (res.block_reason or "")
        assert res.forward_bytes is None


def test_pipeline_unknown_action_fails_closed():
    pipe = DocumentInspectionPipeline()
    res = pipe.inspect(b"hello\n", "text/plain", "req-unknown", requested_action="EXFILTRATE")
    assert res.disposition == DISPOSITION_BLOCK


# ---------------------------------------------------------------------------
# OPA decision input shape
# ---------------------------------------------------------------------------

def test_document_decision_input_opa_shape():
    di = DocumentDecisionInput(
        format="csv",
        extraction_complete=True,
        segment_kinds=["TABLE_CELL"],
        matches=[
            DataMatch(
                data_class="PII.EMAIL",
                qi=False,
                instance="al****om",
                location="TABLE_CELL:row=2,col=2:span=0-17",
                char_start=0,
                char_end=17,
            )
        ],
        record_count=2,
    )
    opa = di.to_opa_input()
    assert opa["format"] == "csv"
    assert opa["matches"][0]["data_class"] == "PII.EMAIL"
    assert opa["matches"][0]["instance"] == "al****om"
    assert opa["max_sensitivity"] == "INTERNAL"
    # incomplete extraction → fail-closed max sensitivity
    di2 = DocumentDecisionInput(
        format="csv", extraction_complete=False, segment_kinds=[],
    )
    assert di2.to_opa_input()["max_sensitivity"] == "RESTRICTED"
