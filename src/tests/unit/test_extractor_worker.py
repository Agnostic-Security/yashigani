"""
Unit tests for the in-sandbox extractor worker (docker/extractor/worker.py) —
Tom's docx/xlsx/pptx/pdf parser slice (plan §6 B1 + §3.1).

These prove the PARSER LOGIC in-process (the LIVE jail proof is the separate
``scripts/extractor_sandbox_containment.py`` run under Docker + Podman). Per
format we assert:
  - VISIBLE body text surfaces;
  - the HIDDEN-data part surfaces with the right SegmentKind + provenance — the
    differentiator (a hidden-cell/comment/note/tracked-change hit is LABELLED);
  - document METADATA surfaces;
  - a MALFORMED/truncated doc fails closed (ok=False), never crashes ambiguously;
  - an ENCRYPTED/password-protected doc fails closed (never cracked);
  - the emitted segment ``kind`` strings are all valid ``SegmentKind`` values
    (the host-side SandboxedExtractor maps them back to the enum — an unknown
    kind there is a fail-closed ValueError, so this locks the contract).

The worker lives at a non-importable path (it is baked into the extractor image,
not the yashigani package), so we load it by file path via importlib.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

from yashigani.documents.segment import SegmentKind

# Parser libs live in the EXTRACTOR IMAGE, not the gateway/test env. If a given
# lib is absent on the host, skip that format's tests here (the containerised
# harness still exercises it) rather than failing — these are logic tests.
openpyxl = pytest.importorskip("openpyxl", reason="xlsx parser (extractor image)")
pypdf = pytest.importorskip("pypdf", reason="pdf parser (extractor image)")
pytest.importorskip("lxml", reason="hardened XML parser")

from src.tests.unit import _doc_fixtures as fx  # noqa: E402


# ---------------------------------------------------------------------------
# Load the worker module by file path (it is not on the package path).
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_WORKER_PATH = _REPO_ROOT / "docker" / "extractor" / "worker.py"


def _worker_env() -> dict:
    """In the real image the worker imports yashigani.documents.bomb_guard from
    /app (baked). Here we point PYTHONPATH at src/ so the same import resolves
    when we invoke the worker as a standalone subprocess (the stdin→stdout→exit
    contract test)."""
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")
    return env


def _load_worker():
    spec = importlib.util.spec_from_file_location("ysg_extractor_worker", _WORKER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


worker = _load_worker()


def _extract(fmt: str, data: bytes) -> tuple[bool, dict]:
    """Drive the worker's _run_extract path the way the contract does; return
    (ok, result_or_contained). A _Contained → ok=False with reason."""
    try:
        result = worker._run_extract(fmt, data)
        return True, result
    except worker._Contained as exc:
        return False, {"reason": str(exc)}


def _texts(result: dict) -> str:
    return "\n".join(s["text"] for s in result["segments"])


def _kinds(result: dict) -> set[str]:
    return {s["kind"] for s in result["segments"]}


def _assert_kinds_valid(result: dict) -> None:
    for s in result["segments"]:
        # Must round-trip through the host enum or the host fail-closes.
        SegmentKind(s["kind"])
        assert s["location"], "every segment needs non-empty provenance"


# ---------------------------------------------------------------------------
# docx
# ---------------------------------------------------------------------------

def test_docx_visible_and_hidden_and_metadata():
    ok, res = _extract("docx", fx.make_docx(with_hidden=True))
    assert ok
    body = _texts(res)
    assert fx.VISIBLE in body            # visible body
    assert fx.HIDDENVAL in body          # comment + tracked-change deletion
    assert fx.METAVAL in body            # core metadata creator
    assert fx.CUSTOMVAL in body          # CUSTOM property (docProps/custom.xml)
    kinds = _kinds(res)
    assert "BODY" in kinds
    assert "COMMENT" in kinds            # hidden part LABELLED
    assert "TRACKED_CHANGE" in kinds     # hidden part LABELLED
    assert "METADATA" in kinds
    _assert_kinds_valid(res)
    assert res["extraction_complete"] is True


def test_docx_visible_only_has_no_hidden_kinds():
    ok, res = _extract("docx", fx.make_docx(with_hidden=False))
    assert ok
    assert fx.VISIBLE in _texts(res)
    assert "COMMENT" not in _kinds(res)
    assert "TRACKED_CHANGE" not in _kinds(res)


def test_docx_malformed_fails_closed():
    ok, res = _extract("docx", fx.truncate(fx.make_docx()))
    assert ok is False
    assert "fail-closed" in res["reason"] or "not a valid" in res["reason"] \
        or "malformed" in res["reason"] or "zip" in res["reason"]


def test_docx_encrypted_ole_fails_closed():
    ok, res = _extract("docx", fx.ole_encrypted_stub())
    assert ok is False
    assert "encrypted" in res["reason"]


# ---------------------------------------------------------------------------
# xlsx
# ---------------------------------------------------------------------------

def test_xlsx_visible_hidden_sheet_column_formula_metadata():
    ok, res = _extract("xlsx", fx.make_xlsx(with_hidden=True))
    assert ok
    body = _texts(res)
    assert fx.VISIBLE in body                         # visible cell
    assert fx.HIDDENVAL in body                        # hidden column value
    assert fx.HIDDENVAL + "-sheet" in body             # hidden SHEET value
    assert "formula-" in body                          # FORMULA TEXT surfaced
    assert "SecretRange" in body                       # defined name
    assert fx.METAVAL in body                          # workbook creator
    assert fx.CUSTOMVAL in body                         # CUSTOM workbook property
    kinds = _kinds(res)
    assert "TABLE_CELL" in kinds
    assert "HIDDEN" in kinds                            # hidden cells LABELLED
    assert "METADATA" in kinds
    # Provenance labels the hiding mechanism.
    locs = " ".join(s["location"] for s in res["segments"])
    assert "sheet-hidden" in locs or "col-hidden" in locs
    _assert_kinds_valid(res)
    assert res["extraction_complete"] is True


def test_xlsx_malformed_fails_closed():
    ok, res = _extract("xlsx", fx.truncate(fx.make_xlsx()))
    assert ok is False
    # Either the bomb guard rejects the truncated zip, or openpyxl does — both
    # are clean containment (never a crash, never a partial-complete claim).
    assert "fail-closed" in res["reason"] or "not a valid zip" in res["reason"]


def test_xlsx_encrypted_ole_fails_closed():
    ok, res = _extract("xlsx", fx.ole_encrypted_stub())
    assert ok is False
    assert "encrypted" in res["reason"]


# ---------------------------------------------------------------------------
# pptx
# ---------------------------------------------------------------------------

def test_pptx_visible_speaker_notes_metadata():
    ok, res = _extract("pptx", fx.make_pptx(with_hidden=True))
    assert ok
    body = _texts(res)
    assert fx.VISIBLE in body                  # visible slide
    assert fx.HIDDENVAL in body                # SPEAKER NOTE
    assert fx.METAVAL in body                  # metadata
    assert fx.CUSTOMVAL in body                # CUSTOM property (docProps/custom.xml)
    kinds = _kinds(res)
    assert "BODY" in kinds
    assert "SPEAKER_NOTE" in kinds             # hidden part LABELLED
    assert "METADATA" in kinds
    _assert_kinds_valid(res)
    assert res["extraction_complete"] is True


def test_pptx_visible_only_no_notes():
    ok, res = _extract("pptx", fx.make_pptx(with_hidden=False))
    assert ok
    assert fx.VISIBLE in _texts(res)
    assert "SPEAKER_NOTE" not in _kinds(res)


def test_pptx_malformed_fails_closed():
    ok, res = _extract("pptx", fx.truncate(fx.make_pptx()))
    assert ok is False


def test_pptx_encrypted_ole_fails_closed():
    ok, res = _extract("pptx", fx.ole_encrypted_stub())
    assert ok is False
    assert "encrypted" in res["reason"]


# ---------------------------------------------------------------------------
# pdf
# ---------------------------------------------------------------------------

def test_pdf_native_text_and_metadata():
    ok, res = _extract("pdf", fx.make_pdf_text())
    assert ok
    body = _texts(res)
    assert fx.VISIBLE in body
    assert fx.HIDDENVAL in body            # same text layer
    assert fx.METAVAL in body              # DocInfo title
    kinds = _kinds(res)
    assert "BODY" in kinds
    assert "METADATA" in kinds
    _assert_kinds_valid(res)
    assert res["extraction_complete"] is True


def test_pdf_image_only_emits_needs_ocr_and_incomplete():
    ok, res = _extract("pdf", fx.make_pdf_image_only())
    assert ok
    # No native text → a needs-OCR segment + extraction NOT complete (BLOCK).
    assert res["extraction_complete"] is False
    assert any(s["needs_ocr"] for s in res["segments"])
    assert "OCR" in _kinds(res)
    _assert_kinds_valid(res)


def test_pdf_encrypted_fails_closed():
    ok, res = _extract("pdf", fx.make_pdf_encrypted())
    assert ok is False
    assert "encrypted" in res["reason"]


def test_pdf_malformed_fails_closed():
    ok, res = _extract("pdf", b"%PDF-1.4\nnot really a pdf at all")
    # Either a clean contain (ok=False) or an empty/incomplete extraction —
    # never a crash and never a complete-with-no-text claim.
    if ok:
        assert res["extraction_complete"] is False
    else:
        assert "fail-closed" in res["reason"]


# ---------------------------------------------------------------------------
# contract-level: unsupported format + segment cap + JSON shape
# ---------------------------------------------------------------------------

def test_unsupported_format_contained():
    ok, res = _extract("rtf", b"{\\rtf1}")
    assert ok is False
    assert "unsupported" in res["reason"]


def test_worker_emits_single_json_object_on_stdin_contract():
    """End-to-end through main(): stdin bytes → ONE JSON object on stdout,
    exit 0. Exercised as a subprocess so the actual stdin/stdout/exit contract
    (the seam sandbox.py depends on) is what we assert."""
    proc = subprocess.run(
        [sys.executable, str(_WORKER_PATH),
         "--job", "extract", "--format", "docx", "--declared-mime", "x"],
        input=fx.make_docx(with_hidden=True),
        capture_output=True,
        timeout=30,
        env=_worker_env(),
    )
    assert proc.returncode == 0
    obj = json.loads(proc.stdout.decode())          # exactly one JSON object
    assert obj["ok"] is True
    assert obj["detected_format"] == "docx"
    assert any(fx.HIDDENVAL in s["text"] for s in obj["segments"])


def test_worker_subprocess_encrypted_pdf_contained_exit_zero():
    proc = subprocess.run(
        [sys.executable, str(_WORKER_PATH),
         "--job", "extract", "--format", "pdf", "--declared-mime", "application/pdf"],
        input=fx.make_pdf_encrypted(),
        capture_output=True,
        timeout=30,
        env=_worker_env(),
    )
    # Contained cleanly: exit 0, ok=False with the encrypted reason.
    assert proc.returncode == 0
    obj = json.loads(proc.stdout.decode())
    assert obj["ok"] is False
    assert "encrypted" in obj["reason"]


def test_worker_subprocess_redact_job_contained():
    """The re-render jobs are the NEXT slice — they must contain cleanly now."""
    proc = subprocess.run(
        [sys.executable, str(_WORKER_PATH),
         "--job", "redact", "--format", "docx", "--declared-mime", "x"],
        input=fx.make_docx(),
        capture_output=True,
        timeout=30,
        env=_worker_env(),
    )
    assert proc.returncode == 0
    obj = json.loads(proc.stdout.decode())
    assert obj["ok"] is False
    assert "re-render" in obj["reason"] or "not yet implemented" in obj["reason"]
