"""
Regression test -- v4.1.2 YSG-RISK-145 (MED): CSV/formula injection (CWE-1236)
in the detokenize export writer -- 3rd unescaped call site, recurrence of
YSG-RISK-010.

Root cause:
  - documents/pseudonymize.py :: DetokenizeMappingFile.to_csv() (the
    token,original correspondence table the pipeline hands back to the doc
    owner) wrote every row via csv.writer(...).writerow([tok, val]) with NO
    escaping at all. `val` (the "original", de-tokenized) content comes
    straight from the source document, which is attacker-influenced -- a
    cell such as `=cmd|'/c calc'!A1` would execute as a formula when the
    exported CSV is opened in Excel/LibreOffice/Google Sheets.
  - docker/extractor/worker.py :: _render_text_like()'s csv branch (a 5th,
    previously-unnoticed site found by sweeping for OTHER csv.writer call
    sites per this finding's instruction) re-emits every cell from the
    SOURCE document verbatim except cells that were explicitly redacted --
    a non-redacted cell carrying an untouched formula-trigger payload
    survives into the "cleaned" re-rendered file.

Fix: both sites now escape every cell via escape_csv_cell() (audit/export.py)
-- pseudonymize.py imports the canonical function directly; worker.py (a
dependency-free sandboxed jail script, see its module docstring) duplicates
the same leading-whitespace-safe logic locally as _escape_csv_cell().

Payloads per the brief: "=", "\\r=", "\\n=", "\\t=", " =".
"""
from __future__ import annotations

import csv
import importlib.util
import io
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]

_PAYLOADS = ["=cmd|'/c calc'!A1", "\r=1+1", "\n=1+1", "\t=1+1", " =1+1"]


def _read_csv_rows(csv_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(csv_text)))


class TestPseudonymizeToCsv:
    """documents/pseudonymize.py :: CorrespondenceTable.to_csv()"""

    @pytest.mark.parametrize("payload", _PAYLOADS)
    def test_formula_payload_in_original_value_is_escaped(self, payload):
        from yashigani.documents.pseudonymize import CorrespondenceTable

        rows = {"TOK_1": payload}
        mapping = CorrespondenceTable(
            rows=rows,
            detokenize_rbac_role="user",
            doc_hash="deadbeef",
            owner_identity="alice",
            tenant="default",
            created_at=0.0,
            ttl_s=3600,
        )
        csv_text = mapping.to_csv()
        parsed = _read_csv_rows(csv_text.split("\n", 1)[1] if csv_text.startswith("#") else csv_text)
        # find the data row (skip header)
        data_rows = [r for r in parsed if r and r[0] == "TOK_1"]
        assert data_rows, f"row not found in output: {csv_text!r}"
        original_cell = data_rows[0][1]
        stripped = original_cell.lstrip()
        assert not stripped.startswith(("=", "+", "-", "@")), (
            f"formula trigger not neutralised: {original_cell!r}"
        )
        # The escape must be a single-quote prefix (Excel-safe neutralisation),
        # never silent deletion of the payload content.
        assert original_cell.lstrip("'").strip() != "" or payload.strip() == ""

    def test_doc_hash_header_preserved(self):
        from yashigani.documents.pseudonymize import CorrespondenceTable

        mapping = CorrespondenceTable(
            rows={"TOK_1": "safe value"},
            detokenize_rbac_role="user",
            doc_hash="deadbeef",
            owner_identity="alice",
            tenant="default",
            created_at=0.0,
            ttl_s=3600,
        )
        csv_text = mapping.to_csv()
        assert csv_text.startswith("# doc_hash=deadbeef\n")


class TestExtractorWorkerCsvRerender:
    """docker/extractor/worker.py :: _render_text_like() csv branch (5th site,
    found while sweeping for other CSV writer call sites per this finding)."""

    @staticmethod
    def _load_worker():
        worker_path = _REPO_ROOT / "docker" / "extractor" / "worker.py"
        spec = importlib.util.spec_from_file_location("ysg_worker_csv_injection", worker_path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @pytest.mark.parametrize("payload", _PAYLOADS)
    def test_escape_csv_cell_neutralises_formula_triggers(self, payload):
        worker = self._load_worker()
        escaped = worker._escape_csv_cell(payload)
        stripped = escaped.lstrip()
        assert not stripped.startswith(("=", "+", "-", "@"))

    def test_non_redacted_cell_with_formula_payload_is_escaped_on_rerender(self):
        worker = self._load_worker()
        csv_in = "name,note\nAlice,safe\nBob,=cmd|'/c calc'!A1\n"
        plan = {"spans": [], "strip_hidden_and_metadata": True}
        out = worker._render_text_like(csv_in.encode("utf-8"), plan, "csv")
        out_text = out.decode("utf-8")
        rows = _read_csv_rows(out_text)
        bob_row = [r for r in rows if r and r[0] == "Bob"]
        assert bob_row, f"row missing from rerender: {out_text!r}"
        assert not bob_row[0][1].lstrip().startswith(("=", "+", "-", "@")), (
            f"formula payload survived re-render unescaped: {bob_row[0][1]!r}"
        )

    def test_safe_cell_content_unchanged_by_escaping(self):
        worker = self._load_worker()
        assert worker._escape_csv_cell("Alice") == "Alice"
        assert worker._escape_csv_cell("normal note") == "normal note"
