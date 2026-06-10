"""
No-residual proof tests (red-team L-03).

L-03 (PROVEN mechanism): the no-residual proof used a raw byte-exact substring
scan, so the re-render + re-extract round-trip's normalisation (PDF
newline-collapse / 90-char wrap, homoglyph / Unicode normal form) produced FALSE
NEGATIVES — the proof passed while a value survived in the output in a
recoverable, human-readable form.

These tests prove the hardened proof now catches:
  - a value that survives in PDF-WRAPPED form (newline-collapse / wrap-boundary);
  - a value that survives in a HOMOGLYPH / Unicode-normalised form;
both via (1) normalised-substring scan of known originals AND (2) a detector
re-pass over the OUTPUT segments.
"""
from __future__ import annotations

from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DocumentInspectionPipeline,
)
from yashigani.documents.datamatch import DataMatch
from yashigani.documents.residual_proof import (
    normalise_for_residual,
    residual_substring_hit,
)


# ---------------------------------------------------------------------------
# normalise_for_residual — folds the round-trip artefacts.
# ---------------------------------------------------------------------------

def test_normalise_collapses_newline_and_wrap():
    # PDF writer collapses \n to space + wraps; both fold to the same canonical.
    assert normalise_for_residual("John\nSmith") == normalise_for_residual("John Smith")
    assert normalise_for_residual("John   Smith\r\n") == "john smith"


def test_normalise_folds_homoglyphs():
    # Cyrillic Ѕ (U+0405) for Latin S, Cyrillic а/о/е for Latin look-alikes.
    assert normalise_for_residual("Ѕmith") == normalise_for_residual("Smith")
    assert normalise_for_residual("Аlіcе") == normalise_for_residual("Alice")


def test_normalise_strips_zero_width():
    # Zero-width space fragmentation must not hide a value.
    assert normalise_for_residual("Sm​ith") == normalise_for_residual("Smith")


def test_residual_substring_hit_wrapped():
    # A wrapped/newline-collapsed survivor IS detected by the normalised scan.
    output = "Onboarding for John\n  Smith completed."
    assert residual_substring_hit(output, "John Smith") is True


def test_residual_substring_hit_homoglyph():
    output = "Contact Ѕmith for details."   # Cyrillic Ѕ
    assert residual_substring_hit(output, "Smith") is True


def test_residual_substring_hit_blank_original_never_hits():
    assert residual_substring_hit("anything", "") is False


# ---------------------------------------------------------------------------
# _assert_no_residual — the proof catches reformatted survivors (the L-03 fix).
# ---------------------------------------------------------------------------

def _pipe() -> DocumentInspectionPipeline:
    # No sandbox needed — we call _assert_no_residual directly with synthetic
    # output segments (the worker's re-extract of the re-rendered artefact).
    return DocumentInspectionPipeline()


def _match(loc: str, cls: str = "PII.EMAIL") -> DataMatch:
    return DataMatch(data_class=cls, qi=False, instance="ma****ed",
                     location=loc, char_start=0, char_end=5)


def test_assert_no_residual_catches_pdf_wrapped_survivor():
    """A name that survives the round-trip ONLY because the PDF writer wrapped it
    across a newline — the old byte-exact scan MISSED this (false-negative); the
    normalised scan now BLOCKS."""
    pipe = _pipe()
    originals = {"BODY:page=1:span=0-10": "Jonathan Smith"}
    matches = [_match("BODY:page=1:span=0-10", "PII.PERSON")]
    # Worker re-extract: the value survived but the writer re-flowed it.
    output_segments = [{"text": "Jonathan\nSmith is the data subject.",
                        "kind": "BODY", "location": "page=1"}]
    result = pipe._assert_no_residual(
        output_segments, originals,
        request_id="r1", fmt="pdf", opa_input=None, matches=matches,
    )
    assert result is not None
    assert result.disposition == DISPOSITION_BLOCK
    assert "residual" in (result.block_reason or "").lower()


def test_assert_no_residual_catches_homoglyph_survivor():
    """A value re-emitted with a Cyrillic homoglyph survives a byte scan but is
    caught by the normalised scan."""
    pipe = _pipe()
    originals = {"BODY:page=1:span=0-5": "Smithson"}
    matches = [_match("BODY:page=1:span=0-5", "PII.PERSON")]
    output_segments = [{"text": "Contact Ѕmithson today.",  # Cyrillic Ѕ
                        "kind": "BODY", "location": "page=1"}]
    result = pipe._assert_no_residual(
        output_segments, originals,
        request_id="r2", fmt="pdf", opa_input=None, matches=matches,
    )
    assert result is not None
    assert result.disposition == DISPOSITION_BLOCK


def test_assert_no_residual_detector_repass_catches_surviving_email():
    """Detector re-pass: even with NO known-original match (e.g. the original
    map drifted), a value the detector still recognises as the acted-on class,
    surviving in the output, is caught."""
    pipe = _pipe()
    # originals deliberately does NOT contain the surviving value — only the
    # detector re-pass can catch it.
    originals: dict[str, str] = {}
    matches = [_match("BODY:page=1:span=0-5", "PII.EMAIL")]
    output_segments = [{"text": "reach me at leaked@corp.example anytime",
                        "kind": "BODY", "location": "page=1"}]
    result = pipe._assert_no_residual(
        output_segments, originals,
        request_id="r3", fmt="pdf", opa_input=None, matches=matches,
    )
    assert result is not None
    assert result.disposition == DISPOSITION_BLOCK
    assert "re-detected" in (result.block_reason or "").lower()


def test_assert_no_residual_clean_output_passes():
    """A genuinely clean re-render (value gone, no detectable class) passes."""
    pipe = _pipe()
    originals = {"BODY:page=1:span=0-10": "Jonathan Smith"}
    matches = [_match("BODY:page=1:span=0-10", "PII.PERSON")]
    output_segments = [{"text": "[PERSON_1] is the data subject.",
                        "kind": "BODY", "location": "page=1"}]
    result = pipe._assert_no_residual(
        output_segments, originals,
        request_id="r4", fmt="pdf", opa_input=None, matches=matches,
    )
    assert result is None  # nothing survived → proof passes
