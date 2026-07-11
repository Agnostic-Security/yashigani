"""
End-to-end LOG-path test for ALL SIX committed formats (txt, csv, docx, xlsx,
pptx, pdf) through the real DocumentInspectionPipeline (plan §2 / §4.2 / §5).

This is the wire-through proof named in the slice brief: after the parser slice,
every committed format extracts → the EXISTING classifier/PII pipeline → a LOG
disposition end-to-end, with BLOCK as the fail-safe (incomplete extraction,
encrypted, malformed all → BLOCK).

The untrusted-parser formats (docx/xlsx/pptx/pdf) run their REAL worker code via
a fake backend that shells out to ``docker/extractor/worker.py`` exactly as the
sandbox does (stdin bytes → one JSON object on stdout → exit code). That keeps
the test daemon-free for CI while still exercising the true parser bodies and the
true stdin→JSON→exit contract the sandbox depends on. The LIVE jail proof (real
container, both runtimes) is ``scripts/extractor_sandbox_containment.py`` +
``test_extractor_worker.py``'s subprocess cases.

txt/csv take the in-process trivial extractors (no sandbox) — they are already
wired; this test confirms all six land on LOG together.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

pytest.importorskip("openpyxl", reason="xlsx parser")
pytest.importorskip("pypdf", reason="pdf parser")
pytest.importorskip("lxml", reason="hardened XML parser")

from src.tests.unit import _doc_fixtures as fx  # noqa: E402
from yashigani.documents.extractor import ExtractorRegistry  # noqa: E402
from yashigani.documents.pipeline import (  # noqa: E402
    DISPOSITION_BLOCK,
    DISPOSITION_LOG,
    DocumentInspectionPipeline,
)
from yashigani.documents.sandbox import SandboxedExtractorRunner  # noqa: E402

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_WORKER_PATH = _REPO_ROOT / "docker" / "extractor" / "worker.py"


class _WorkerSubprocessBackend:
    """A ContainerBackend stand-in that runs the REAL worker as a subprocess via
    the exact stdin→stdout→exit contract the hardened container uses. Faithful to
    the parser code; just without the container isolation (proven separately)."""

    def run_extractor_job(self, *, stdin, timeout_s, command, **kwargs):
        # command is the worker argv (--job/--format/--declared-mime).
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT / "src")
        proc = subprocess.run(
            ["python3", str(_WORKER_PATH), *command],
            input=stdin, capture_output=True, timeout=timeout_s, env=env,
        )
        return (proc.stdout, proc.returncode, False)


def _pipeline() -> DocumentInspectionPipeline:
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    return DocumentInspectionPipeline(registry=ExtractorRegistry(sandbox_runner=runner))


_DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"


@pytest.mark.parametrize(
    "fmt,data,mime",
    [
        ("txt", b"alice@example.com is here\n", "text/plain"),
        ("csv", b"name,email\nalice,alice@example.com\n", "text/csv"),
        ("docx", fx.make_docx(with_hidden=True), _DOCX_MIME),
        ("xlsx", fx.make_xlsx(with_hidden=True), _XLSX_MIME),
        ("pptx", fx.make_pptx(with_hidden=True), _PPTX_MIME),
        ("pdf", fx.make_pdf_text(), "application/pdf"),
    ],
)
def test_all_six_formats_reach_log_end_to_end(fmt, data, mime):
    result = _pipeline().inspect(data, mime, request_id=f"req-{fmt}",
                                 requested_action=DISPOSITION_LOG)
    assert result.disposition == DISPOSITION_LOG, (
        f"{fmt} did not LOG: {result.block_reason}"
    )
    assert result.extraction_complete is True
    # LOG forwards the original bytes (allow + audit).
    assert result.forward_bytes == data


def test_encrypted_pdf_fails_closed_to_block():
    result = _pipeline().inspect(
        fx.make_pdf_encrypted(), "application/pdf", request_id="req-enc")
    assert result.disposition == DISPOSITION_BLOCK
    assert "encrypted" in (result.block_reason or "") or "extraction failed" in (result.block_reason or "")


def test_image_only_pdf_incomplete_fails_closed_to_block():
    result = _pipeline().inspect(
        fx.make_pdf_image_only(), "application/pdf", request_id="req-img")
    assert result.disposition == DISPOSITION_BLOCK
    assert "incomplete" in (result.block_reason or "")


def test_malformed_docx_fails_closed_to_block():
    result = _pipeline().inspect(
        fx.truncate(fx.make_docx()), _DOCX_MIME, request_id="req-mal")
    assert result.disposition == DISPOSITION_BLOCK
