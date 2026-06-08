"""
End-to-end ALL-4-ACTIONS test across the 6 committed formats through the real
DocumentInspectionPipeline (plan §5.0 / §5.2 / §5.5, red-team F4/F5/F6).

After this slice every committed format runs LOG / REDACT / PSEUDONYMIZE / BLOCK
end-to-end.  REDACT/PSEUDONYMIZE re-render runs in the jail (here: the real worker
via the subprocess backend, faithful to the stdin->JSON->exit contract; the LIVE
container proof is scripts/extractor_sandbox_containment.py).

The headline proofs:
  - REDACT: the audit-recorded matched value is GONE from the forwarded artefact
    AND from a re-extract of that artefact (no residual — body/hidden/metadata).
  - PSEUDONYMIZE: the original is GONE, tokens present, the replacer map is held
    (F5 handle present, map NOT in any audit/log field), mode-A table delivered.
  - Strongest-action precedence + small-set escalation (F2) fail-closed to BLOCK.
"""
from __future__ import annotations

import logging
import os
import pathlib

import pytest

pytest.importorskip("openpyxl", reason="xlsx parser")
pytest.importorskip("pypdf", reason="pdf parser")
pytest.importorskip("lxml", reason="hardened XML parser")

from src.tests.unit import _doc_fixtures as fx  # noqa: E402
from src.tests.unit.test_documents_end_to_end_log import (  # noqa: E402
    _WorkerSubprocessBackend,
)
from yashigani.documents.extractor import ExtractorRegistry  # noqa: E402
from yashigani.documents.pipeline import (  # noqa: E402
    DISPOSITION_BLOCK,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_REDACT,
    DocumentInspectionPipeline,
)
from yashigani.documents.sandbox import SandboxedExtractorRunner  # noqa: E402


def _pipeline(audit_sink=None):
    """A pipeline whose registry routes BOTH extraction and re-render through the
    real worker subprocess (the jail's stdin->JSON->exit contract)."""
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    registry = ExtractorRegistry(sandbox_runner=runner)
    return DocumentInspectionPipeline(registry=registry, on_audit=audit_sink)


# Builders that embed a DETECTABLE PII value (so the existing PII detector flags
# it and the pipeline drives a real plan). We use an email (VISIBLE) + an SSN-
# shaped value the detector recognises.
_PII_EMAIL = "alice@example.com"
_PII_SSN = "123-45-6789"


def _txt_doc() -> bytes:
    return f"contact {_PII_EMAIL} ssn {_PII_SSN}\n".encode()


def _csv_doc() -> bytes:
    return f"name,email\nalice,{_PII_EMAIL}\nbob,{_PII_EMAIL}\n".encode()


def _docx_doc() -> bytes:
    return _ooxml_body_docx(f"Email {_PII_EMAIL} here")


def _ooxml_body_docx(body: str) -> bytes:
    import io
    import zipfile
    W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    document = (
        f'<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>'
        f'<w:p><w:r><w:t>{body}</w:t></w:r></w:p>'
        f'</w:body></w:document>'
    )
    parts = {
        "[Content_Types].xml": fx._CONTENT_TYPES,
        "_rels/.rels": fx._RELS,
        "word/document.xml": document.encode(),
        "docProps/core.xml": fx._core_props(),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, p in parts.items():
            zf.writestr(n, p)
    return buf.getvalue()


def _xlsx_doc() -> bytes:
    import io
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = _PII_EMAIL
    ws["A2"] = _PII_EMAIL
    wb.properties.creator = fx.METAVAL
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _pptx_doc() -> bytes:
    import io
    import zipfile
    P = "http://schemas.openxmlformats.org/presentationml/2006/main"
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"
    slide = (
        f'<?xml version="1.0"?><p:sld xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree>'
        f'<p:sp><p:txBody><a:p><a:r><a:t>Contact {_PII_EMAIL}</a:t></a:r></a:p></p:txBody></p:sp>'
        f'</p:spTree></p:cSld></p:sld>'
    )
    parts = {
        "[Content_Types].xml": fx._CONTENT_TYPES,
        "_rels/.rels": fx._RELS,
        "ppt/slides/slide1.xml": slide.encode(),
        "docProps/core.xml": fx._core_props(),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, p in parts.items():
            zf.writestr(n, p)
    return buf.getvalue()


def _pdf_doc() -> bytes:
    return fx._minimal_text_pdf(f"Contact {_PII_EMAIL}", title=fx.METAVAL)


ALL_FORMATS = [
    ("txt", _txt_doc, "text/plain"),
    ("csv", _csv_doc, "text/csv"),
    ("docx", _docx_doc, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("xlsx", _xlsx_doc, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("pptx", _pptx_doc, "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ("pdf", _pdf_doc, "application/pdf"),
]


# ---------------------------------------------------------------------------
# LOG — all six (sanity that the action wiring did not regress LOG).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,builder,mime", ALL_FORMATS)
def test_log_all_six(fmt, builder, mime):
    pipe = _pipeline()
    doc = builder()  # build ONCE (xlsx bytes are non-deterministic across calls)
    r = pipe.inspect(doc, mime, request_id="req-log", requested_action="LOG")
    assert r.disposition == "LOG"
    assert r.forward_bytes == doc  # LOG forwards the SAME original unchanged
    assert any(m.data_class == "PII.EMAIL" for m in r.matches)


# ---------------------------------------------------------------------------
# REDACT — all six: matched value gone from the forwarded artefact (no residual).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,builder,mime", ALL_FORMATS)
def test_redact_all_six_no_residual(fmt, builder, mime):
    pipe = _pipeline()
    r = pipe.inspect(builder(), mime, request_id="req-redact",
                     requested_action="REDACT")
    assert r.disposition == DISPOSITION_REDACT, (fmt, r.block_reason)
    assert r.forward_bytes is not None
    # Re-extract the forwarded artefact independently: NO original PII survives.
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    re_extract = reg.extract(r.forward_bytes, mime)
    text = "\n".join(s.text for s in re_extract.segments)
    assert _PII_EMAIL not in text, f"{fmt}: redacted email survived in artefact"
    assert fx.METAVAL not in text, f"{fmt}: metadata survived REDACT (F4)"
    assert r.audit_fields.get("no_residual_verified") is True
    assert r.audit_fields.get("hidden_and_metadata_stripped") is True


# ---------------------------------------------------------------------------
# PSEUDONYMIZE — all six: original gone, token present, F5 map held, mode-A table.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,builder,mime", ALL_FORMATS)
def test_pseudonymize_all_six(fmt, builder, mime):
    pipe = _pipeline()
    r = pipe.inspect(builder(), mime, request_id="req-pseudo",
                     requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    assert r.disposition == DISPOSITION_PSEUDONYMIZE, (fmt, r.block_reason)
    assert r.forward_bytes is not None

    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    re_extract = reg.extract(r.forward_bytes, mime)
    text = "\n".join(s.text for s in re_extract.segments)
    assert _PII_EMAIL not in text, f"{fmt}: original survived PSEUDONYMIZE (§5.5)"
    assert "[EMAIL_1]" in text, f"{fmt}: token not present in tokenized artefact"

    # F5: the replacer map is held (handle present, encrypted, TTL'd), and the
    # mode-A correspondence table was emitted, recoverable via the map.
    assert r.replacer_map is not None and len(r.replacer_map.handle) >= 40
    assert r.pseudonymize_mode == "A"
    assert r.correspondence_table is not None
    assert "[EMAIL_1]" in r.correspondence_table.rows
    assert r.correspondence_table.rows["[EMAIL_1]"] == _PII_EMAIL


def _docx_custom_meta_only_doc() -> bytes:
    """A docx whose BODY is clean but whose CUSTOM property (docProps/custom.xml)
    carries a DETECTABLE PII email. Proves a metadata-ONLY match drives a verdict
    (concern #2) — it is NOT silently passed because the body is clean."""
    import io
    import zipfile
    W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
    VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
    document = (
        f'<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>'
        f'<w:p><w:r><w:t>nothing sensitive in the body</w:t></w:r></w:p>'
        f'</w:body></w:document>'
    )
    custom = (
        f'<?xml version="1.0"?><Properties xmlns="{CUSTOM}" xmlns:vt="{VT}">'
        f'<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="2" '
        f'name="ClientContact"><vt:lpwstr>{_PII_EMAIL}</vt:lpwstr></property>'
        f'</Properties>'
    )
    parts = {
        "[Content_Types].xml": fx._CONTENT_TYPES,
        "_rels/.rels": fx._RELS,
        "word/document.xml": document.encode(),
        "docProps/custom.xml": custom.encode(),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, p in parts.items():
            zf.writestr(n, p)
    return buf.getvalue()


def test_metadata_only_match_drives_verdict_and_is_stripped():
    """Concern #2/#3: a PII value present ONLY in a custom document property is
    DETECTED (drives matches → a real REDACT verdict) and does NOT survive in the
    re-rendered output — proving metadata-only data is identified, acted on, and
    left no residual."""
    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    pipe = _pipeline()
    doc = _docx_custom_meta_only_doc()
    # The body is clean; the ONLY PII is in the custom property.
    r = pipe.inspect(doc, mime, request_id="req-meta", requested_action="REDACT")
    # A metadata-only match must produce a match (not be silently passed).
    assert any(m.data_class == "PII.EMAIL" for m in r.matches), (
        "metadata-only PII was NOT detected — silent pass (concern #2)"
    )
    assert r.disposition == DISPOSITION_REDACT, r.block_reason
    # And the re-rendered output carries no residual of the metadata value.
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    re_extract = reg.extract(r.forward_bytes, mime)
    text = "\n".join(s.text for s in re_extract.segments)
    assert _PII_EMAIL not in text, "metadata-only PII survived REDACT output"
    assert _PII_EMAIL.encode() not in r.forward_bytes, (
        "metadata-only PII survived in raw REDACT bytes"
    )


def test_csv_pseudonymize_coherent_across_rows():
    """Same value in two rows → same token in both (coherence, §5.3a)."""
    pipe = _pipeline()
    r = pipe.inspect(_csv_doc(), "text/csv", request_id="req",
                     requested_action="PSEUDONYMIZE")
    assert r.disposition == DISPOSITION_PSEUDONYMIZE
    text = r.forward_bytes.decode()
    assert _PII_EMAIL not in text
    assert text.count("[EMAIL_1]") == 2  # both rows collapsed to one token


# ---------------------------------------------------------------------------
# F5 — the replacer map NEVER appears in any audit/log field (crown jewel).
# ---------------------------------------------------------------------------

def test_replacer_map_and_original_never_in_audit_or_logs(caplog):
    events: list[tuple[str, dict]] = []
    pipe = _pipeline(audit_sink=lambda name, data: events.append((name, data)))
    with caplog.at_level(logging.DEBUG):
        r = pipe.inspect(_txt_doc(), "text/plain", request_id="req-secret",
                         requested_action="PSEUDONYMIZE", pseudonymize_mode="A")
    assert r.disposition == DISPOSITION_PSEUDONYMIZE
    # The audit event must NOT carry the original value, the map, or the handle.
    import json
    audit_blob = json.dumps([d for _, d in events], default=str)
    assert _PII_EMAIL not in audit_blob, "original PII leaked into audit (F12)"
    assert r.replacer_map.handle not in audit_blob, "map handle leaked into audit (F5)"
    # Logs likewise must not carry the original or the handle.
    log_blob = caplog.text
    assert _PII_EMAIL not in log_blob
    assert r.replacer_map.handle not in log_blob


# ---------------------------------------------------------------------------
# F2 — small-set residual-QI escalation → BLOCK.
# ---------------------------------------------------------------------------

def test_small_set_residual_qi_escalates_to_block():
    # A 2-row CSV with an email (tokenized) + a phone (QI) left un-tokenized.
    # Construct a pipeline whose PII detector tokenizes EMAIL only, leaving the
    # phone QI residual on a tiny record set → F2 escalation to BLOCK.
    from yashigani.pii.detector import PiiDetector, PiiMode, PiiType
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    # Detector that flags BOTH email and phone; phone is a QI (_QI_TYPES).
    det = PiiDetector(mode=PiiMode.LOG,
                      enabled_types={PiiType.EMAIL, PiiType.PHONE})
    pipe = DocumentInspectionPipeline(registry=reg, pii_detector=det,
                                      small_set_threshold=20)
    # Monkey-patch: pseudonymize EMAIL only so PHONE is a residual QI.
    orig = pipe._pseudonymize

    csv = (f"email,phone\n"
           f"{_PII_EMAIL},+14155550100\n"
           f"bob@example.com,+14155550101\n").encode()
    # The default _pseudonymize tokenizes ALL detected classes, so to exercise
    # the gate we restrict the pseudonymized set via a thin subclass override.
    import yashigani.documents.pipeline as P

    def _restricted(self, request_id, data, extraction, matches, originals,
                    opa_input, *, mode, detokenize_rbac_role, map_ttl_s):
        pseudonymized = {"PII.EMAIL"}  # policy chose to tokenize EMAIL only
        rc = self._record_count(extraction)
        if self._small_set_escalation(matches, rc, pseudonymized):
            return self._block(request_id, "F2 small-set escalation",
                               detected=extraction.detected_format,
                               matches=matches, opa_input=opa_input)
        return orig(request_id, data, extraction, matches, originals, opa_input,
                    mode=mode, detokenize_rbac_role=detokenize_rbac_role,
                    map_ttl_s=map_ttl_s)

    pipe._pseudonymize = _restricted.__get__(pipe, P.DocumentInspectionPipeline)
    r = pipe.inspect(csv, "text/csv", request_id="req-f2",
                     requested_action="PSEUDONYMIZE")
    assert r.disposition == DISPOSITION_BLOCK
    assert "small-set" in (r.block_reason or "")
