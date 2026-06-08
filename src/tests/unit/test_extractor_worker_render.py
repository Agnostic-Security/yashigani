"""
In-jail re-render tests for the extractor worker (docker/extractor/worker.py) —
Tom's REDACT / PSEUDONYMIZE slice (plan §5.1 / §5.3 / §5.5, red-team F4/F6).

Per format (docx/xlsx/pptx/pdf/txt/csv) we prove, IN-PROCESS (the LIVE jail proof
is the containerised harness), the regenerate-from-cleaned-content contract:

  - REDACT destroys the matched span in the rebuilt artefact (no residual);
  - PSEUDONYMIZE substitutes a consistent token (no original residual);
  - the NO-RESIDUAL proof is the re-extract-the-OUTPUT assertion (Laura's gate):
    we re-extract the worker's OWN output and assert NO original value survives in
    ANY part — body, hidden part, OR metadata;
  - hidden parts + metadata are stripped wholesale (the F4 residual vectors:
    core/app metadata, comments, tracked changes, speaker notes, hidden cells,
    defined names, cached formula values, DocInfo/XMP);
  - a malformed/encrypted doc fails closed (never re-rendered).

The worker is loaded by file path (it is baked into the image, not the package).
"""
from __future__ import annotations

import base64
import importlib.util
import pathlib

import pytest

openpyxl = pytest.importorskip("openpyxl", reason="xlsx parser (extractor image)")
pypdf = pytest.importorskip("pypdf", reason="pdf parser (extractor image)")
pytest.importorskip("lxml", reason="hardened XML parser")

from src.tests.unit import _doc_fixtures as fx  # noqa: E402

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_WORKER_PATH = _REPO_ROOT / "docker" / "extractor" / "worker.py"


def _load_worker():
    spec = importlib.util.spec_from_file_location("ysg_extractor_worker_render", _WORKER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


worker = _load_worker()


# ---------------------------------------------------------------------------
# Helpers — build a plan from the worker's OWN extraction (the real flow shape).
# ---------------------------------------------------------------------------

def _plan_targeting(fmt: str, data: bytes, values: list[str], action: str,
                    *, token_prefix: str = "TOK") -> dict:
    """Extract the doc, then build a plan that transforms every occurrence of
    each value in ``values`` wherever it was found."""
    res = worker._run_extract(fmt, data)
    spans = []
    counter = 0
    seen = {}
    for s in res["segments"]:
        for val in values:
            if val and val in s["text"]:
                if val not in seen:
                    counter += 1
                    seen[val] = f"[{token_prefix}_{counter}]"
                span = {
                    "segment_location": s["location"],
                    "original": val,
                    "action": action,
                }
                if action == "PSEUDONYMIZE":
                    span["token"] = seen[val]
                spans.append(span)
    return {"spans": spans, "strip_hidden_and_metadata": True}


def _render(fmt: str, data: bytes, job: str, plan: dict) -> tuple[bytes, dict]:
    out = worker._run_render(job, fmt, data, plan)
    rendered = base64.b64decode(out["rendered_b64"])
    return rendered, out


def _output_text(out: dict) -> str:
    return "\n".join(str(s.get("text", "")) for s in out["output_segments"])


def _reextract_text(fmt: str, rendered: bytes) -> str:
    """Re-extract the rendered artefact INDEPENDENTLY (a second pass) so the
    no-residual proof does not trust the worker's own output_segments."""
    if fmt in ("txt", "csv"):
        return rendered.decode("utf-8", "replace")
    res = worker._run_extract(fmt, rendered)
    return "\n".join(s["text"] for s in res["segments"])


# ---------------------------------------------------------------------------
# Per-format REDACT — no residual anywhere (body, hidden, metadata).
# ---------------------------------------------------------------------------

OOXML_PDF = [
    ("docx", fx.make_docx),
    ("xlsx", fx.make_xlsx),
    ("pptx", fx.make_pptx),
    ("pdf", fx.make_pdf_text),
]


# OOXML fixtures carry a custom-property metadata leak (docProps/custom.xml);
# pdf has no custom-property analogue, so CUSTOMVAL is OOXML-only.
_HAS_CUSTOM_META = {"docx", "xlsx", "pptx"}


@pytest.mark.parametrize("fmt,builder", OOXML_PDF)
def test_redact_destroys_secret_and_strips_metadata(fmt, builder):
    data = builder()
    targets = [fx.HIDDENVAL, fx.VISIBLE, fx.METAVAL]
    plan = _plan_targeting(fmt, data, targets, "REDACT")
    rendered, out = _render(fmt, data, "redact", plan)

    # Re-extract the OUTPUT (worker's own + an independent pass): NO original
    # value of any kind survives — not the secret, not the CORE metadata leaker,
    # not the CUSTOM-property metadata leaker (docProps/custom.xml).
    for text in (_output_text(out), _reextract_text(fmt, rendered)):
        assert fx.HIDDENVAL not in text, f"{fmt}: secret survived REDACT"
        assert fx.METAVAL not in text, f"{fmt}: core metadata survived REDACT (F4)"
        assert fx.VISIBLE not in text, f"{fmt}: redacted visible value survived"
        if fmt in _HAS_CUSTOM_META:
            assert fx.CUSTOMVAL not in text, (
                f"{fmt}: CUSTOM-property metadata survived REDACT (F4 — custom.xml)"
            )
    # Belt + suspenders: the raw output bytes carry no custom-prop value either.
    if fmt in _HAS_CUSTOM_META:
        assert fx.CUSTOMVAL.encode() not in rendered, (
            f"{fmt}: CUSTOM-property value survived in raw REDACT bytes"
        )


@pytest.mark.parametrize("fmt,builder", OOXML_PDF)
def test_pseudonymize_tokenizes_without_original_residual(fmt, builder):
    data = builder()
    # Tokenize EVERY detected value (the real pipeline tokenizes all matches).
    # For pdf both values live in the one native text layer (no hidden part), so
    # both must be tokenized; for ooxml the secret lives in a hidden part that is
    # stripped wholesale — either way NO original may survive.
    plan = _plan_targeting(fmt, data, [fx.VISIBLE, fx.HIDDENVAL], "PSEUDONYMIZE",
                           token_prefix="PERSON")
    rendered, out = _render(fmt, data, "pseudonymize", plan)

    for text in (_output_text(out), _reextract_text(fmt, rendered)):
        assert fx.VISIBLE not in text, f"{fmt}: original survived PSEUDONYMIZE (§5.5)"
        assert fx.HIDDENVAL not in text, f"{fmt}: secret survived PSEUDONYMIZE"
        assert fx.METAVAL not in text, f"{fmt}: core metadata survived PSEUDONYMIZE (F4)"
        if fmt in _HAS_CUSTOM_META:
            assert fx.CUSTOMVAL not in text, (
                f"{fmt}: CUSTOM-property metadata survived PSEUDONYMIZE (F4 — custom.xml)"
            )
    # Belt + suspenders: a PSEUDONYMIZED artefact is worthless if metadata still
    # carries the original — assert the raw output bytes carry no custom-prop value.
    if fmt in _HAS_CUSTOM_META:
        assert fx.CUSTOMVAL.encode() not in rendered, (
            f"{fmt}: CUSTOM-property value survived in raw PSEUDONYMIZE bytes"
        )
    # At least the visible value's token landed in the output body.
    assert "[PERSON_1]" in _output_text(out), f"{fmt}: token not in output body"


@pytest.mark.parametrize("fmt,builder", [
    ("docx", fx.make_docx), ("xlsx", fx.make_xlsx), ("pptx", fx.make_pptx),
])
def test_custom_property_metadata_is_detected(fmt, builder):
    """Metadata-only detection (concern #2/#3): a sensitive value sitting ONLY in
    a CUSTOM document property (docProps/custom.xml) MUST surface as a segment so
    it drives a verdict — it must NOT be silently passed because the body is clean.
    """
    data = builder()
    res = worker._run_extract(fmt, data)
    blob = "\n".join(s["text"] for s in res["segments"])
    assert fx.CUSTOMVAL in blob, (
        f"{fmt}: CUSTOM-property value NOT surfaced — metadata-only leak undetected"
    )
    # It is surfaced AS metadata (right provenance class), not mislabelled body.
    hits = [s for s in res["segments"] if fx.CUSTOMVAL in s["text"]]
    assert all(s["kind"] == "METADATA" for s in hits), (
        f"{fmt}: custom-property hit not labelled METADATA: {[s['kind'] for s in hits]}"
    )


@pytest.mark.parametrize("fmt,builder,action,job", [
    ("docx", fx.make_docx, "REDACT", "redact"),
    ("docx", fx.make_docx, "PSEUDONYMIZE", "pseudonymize"),
    ("xlsx", fx.make_xlsx, "REDACT", "redact"),
    ("xlsx", fx.make_xlsx, "PSEUDONYMIZE", "pseudonymize"),
    ("pptx", fx.make_pptx, "REDACT", "redact"),
    ("pptx", fx.make_pptx, "PSEUDONYMIZE", "pseudonymize"),
])
def test_custom_property_metadata_does_not_survive_render(fmt, builder, action, job):
    """A value matched ONLY in a custom property must NOT survive in the rendered
    output of EITHER action — for PSEUDONYMIZE it is either tokenized OR (as here,
    since render rebuilds a minimal package) stripped; for REDACT it is destroyed.
    NEVER ship output whose metadata still contains the original matched value."""
    data = builder()
    plan = _plan_targeting(fmt, data, [fx.CUSTOMVAL], action, token_prefix="CUSTOM")
    # The custom value IS detected, so the plan targets it.
    assert plan["spans"], f"{fmt}: custom-property value was not in the extract plan"
    rendered, out = _render(fmt, data, job, plan)
    for text in (_output_text(out), _reextract_text(fmt, rendered)):
        assert fx.CUSTOMVAL not in text, (
            f"{fmt}/{action}: custom-property value survived in re-extracted output"
        )
    assert fx.CUSTOMVAL.encode() not in rendered, (
        f"{fmt}/{action}: custom-property value survived in raw rendered bytes"
    )


# ---------------------------------------------------------------------------
# txt / csv — provably clean (no hidden channel, §5.1).
# ---------------------------------------------------------------------------

def test_txt_redact_and_pseudonymize():
    body = f"name: {fx.VISIBLE}\nssn: {fx.HIDDENVAL}\n"
    data = body.encode()
    # REDACT both
    plan = {
        "spans": [
            {"segment_location": "line=1", "original": fx.VISIBLE, "action": "REDACT"},
            {"segment_location": "line=2", "original": fx.HIDDENVAL, "action": "REDACT"},
        ],
        "strip_hidden_and_metadata": True,
    }
    rendered, out = _render("txt", data, "redact", plan)
    text = rendered.decode()
    assert fx.VISIBLE not in text and fx.HIDDENVAL not in text
    # PSEUDONYMIZE
    plan2 = {
        "spans": [
            {"segment_location": "line=1", "original": fx.VISIBLE,
             "action": "PSEUDONYMIZE", "token": "[PERSON_1]"},
        ],
        "strip_hidden_and_metadata": True,
    }
    rendered2, _ = _render("txt", data, "pseudonymize", plan2)
    t2 = rendered2.decode()
    assert "[PERSON_1]" in t2 and fx.VISIBLE not in t2


def test_csv_redact_cell_consistent():
    body = f"alice,{fx.VISIBLE}\nbob,{fx.VISIBLE}\n"  # same value twice
    data = body.encode()
    res = worker._run_extract  # csv extracts host-side; build plan by hand
    plan = {
        "spans": [
            {"segment_location": "row=1,col=2", "original": fx.VISIBLE,
             "action": "PSEUDONYMIZE", "token": "[EMAIL_1]"},
            {"segment_location": "row=2,col=2", "original": fx.VISIBLE,
             "action": "PSEUDONYMIZE", "token": "[EMAIL_1]"},
        ],
        "strip_hidden_and_metadata": True,
    }
    rendered, _ = _render("csv", data, "pseudonymize", plan)
    text = rendered.decode()
    assert fx.VISIBLE not in text
    # Same source value → same token in both rows (coherence).
    assert text.count("[EMAIL_1]") == 2


# ---------------------------------------------------------------------------
# Fail-closed: encrypted / malformed / missing-plan never re-renders.
# ---------------------------------------------------------------------------

def test_render_encrypted_pdf_fails_closed():
    data = fx.make_pdf_encrypted()
    with pytest.raises(worker._Contained):
        worker._run_render("redact", "pdf", data, {"spans": []})


def test_render_encrypted_ooxml_fails_closed():
    data = fx.ole_encrypted_stub()
    with pytest.raises(worker._Contained):
        worker._run_render("redact", "docx", data, {"spans": []})


def test_render_malformed_docx_fails_closed():
    data = fx.truncate(fx.make_docx(), keep=0.3)
    with pytest.raises(worker._Contained):
        worker._run_render("redact", "docx", data, {"spans": []})


def test_render_missing_plan_fails_closed():
    with pytest.raises(worker._Contained):
        worker._decode_plan("")


def test_render_pseudonymize_span_missing_token_fails_closed():
    plan = {"spans": [{"segment_location": "line=1", "original": "x",
                       "action": "PSEUDONYMIZE"}]}
    with pytest.raises(worker._Contained):
        worker._run_render("pseudonymize", "txt", b"x\n", plan)
