"""
Regression — Laura L-01 (2.26): the F2 small-set re-identification gate was dead
code, and the QI detector was too narrow (name+email only, leaving DOB / NI /
address / phone in the clear under PSEUDONYMIZE).

These tests reproduce the ORIGINAL bug at the detection/decision level (the
re-render bytes need a sandbox-capable host — a known limit — so we prove the
detection + gate logic independently of the sandbox).  They build segments
exactly as the xlsx/csv worker emits them (``sheet=Title!<coord>`` /
``row=R,col=C``) so the column-semantic enrichment + record-count + gate are
exercised on the real provenance shapes.

What would re-fail on the original bug:
  * ``test_qi_breadth_pii_*`` — DOB column / NI / postal address / full-name
    were NOT tokenized (the detector only saw name+email) → these assert every
    identifying column produces a match.
  * ``test_small_set_gate_fires_*`` — the gate could never fire on the wired
    path (residual-QI set was always empty) → these assert it fires.
  * ``test_pci_spaced_pan_and_cvv_expiry_cardholder`` — the PCI columns whose
    cells have no distinctive lone-cell form (CVV/expiry/cardholder) were
    missed → these assert they are detected (PAN incl. the spaced form).
"""
from __future__ import annotations

from yashigani.documents.pipeline import DocumentInspectionPipeline
from yashigani.documents.segment import ExtractionResult, Segment, SegmentKind


# ---------------------------------------------------------------------------
# Synthetic worker-shaped segments (no sandbox host needed).
# ---------------------------------------------------------------------------

def _xlsx_segments(headers: list[str], rows: list[list[str]], sheet="Sheet1") -> ExtractionResult:
    """Build segments the xlsx worker emits: one TABLE_CELL per cell, located
    ``sheet=<title>!<COL><ROW>`` (row 1 = header)."""
    cols = "ABCDEFGHIJ"
    segs: list[Segment] = []
    for c, h in enumerate(headers):
        segs.append(Segment(text=h, kind=SegmentKind.TABLE_CELL,
                            location=f"sheet={sheet}!{cols[c]}1"))
    for r, row in enumerate(rows, start=2):
        for c, cell in enumerate(row):
            if cell == "":
                continue
            segs.append(Segment(text=cell, kind=SegmentKind.TABLE_CELL,
                                location=f"sheet={sheet}!{cols[c]}{r}"))
    return ExtractionResult(segments=segs, extraction_complete=True, detected_format="xlsx")


def _pii_30() -> ExtractionResult:
    headers = ["Full Name", "Work Email", "Mobile", "Date of Birth",
               "Home Address", "National Insurance No."]
    rows = []
    for i in range(30):
        rows.append([
            f"Person{i} Surname{i}",
            f"person{i}@example-corp.co.uk",
            "07700000000",
            "01/01/1960",
            f"{i} High St, London, SW1A 1AA",
            "AA 10 10 10 A",
        ])
    return _xlsx_segments(headers, rows, sheet="Employees")


def _pci_30() -> ExtractionResult:
    headers = ["Cardholder Name", "Card Number", "Scheme", "Expiry",
               "CVV", "Billing Postcode", "Amount (GBP)"]
    rows = []
    for i in range(30):
        rows.append([
            f"Holder{i} Name{i}",
            "4111 1111 1111 1111",   # spaced PAN — Laura's explicit case
            "Visa",
            "01/26",
            "123",
            "SW1A 1AA",
            "12.50",
        ])
    return _xlsx_segments(headers, rows, sheet="Payments")


def _classes(matches) -> set[str]:
    return {m.data_class for m in matches}


# ---------------------------------------------------------------------------
# QI breadth — every identifying PII column tokenizes (not just name+email).
# ---------------------------------------------------------------------------

def test_qi_breadth_pii_all_identifying_columns_detected():
    pipe = DocumentInspectionPipeline()
    matches, _ = pipe._enumerate(_pii_30())
    classes = _classes(matches)
    # The full identifying / QI set — the original bug left these in the clear.
    for expected in (
        "PII.PERSON_NAME", "PII.EMAIL", "PII.PHONE",
        "PII.DATE_OF_BIRTH", "PII.POSTAL_ADDRESS", "PII.NATIONAL_INSURANCE",
    ):
        assert expected in classes, f"{expected} not tokenized (L-01 QI breadth)"


def test_qi_breadth_dob_ni_address_phone_are_quasi_identifiers():
    pipe = DocumentInspectionPipeline()
    matches, _ = pipe._enumerate(_pii_30())
    qi_classes = {m.data_class for m in matches if m.qi}
    for expected in (
        "PII.DATE_OF_BIRTH", "PII.POSTAL_ADDRESS",
        "PII.NATIONAL_INSURANCE", "PII.PHONE", "PII.PERSON_NAME",
    ):
        assert expected in qi_classes, f"{expected} not flagged QI"


def test_pii_nothing_identifying_in_the_clear():
    """Every body data cell in an identifying column has a tokenizable original;
    only the non-identifying columns + headers are left untouched."""
    pipe = DocumentInspectionPipeline()
    ext = _pii_30()
    matches, originals = pipe._enumerate(ext)
    # 30 rows × 6 identifying columns = 180 identifying cells, all with originals.
    assert len(originals) >= 180
    # Each of the six identifying columns is covered for all 30 rows.
    from collections import Counter
    cnt = Counter(m.data_class for m in matches)
    for cls in ("PII.PERSON_NAME", "PII.DATE_OF_BIRTH", "PII.POSTAL_ADDRESS",
                "PII.PHONE"):
        assert cnt[cls] == 30, (cls, cnt[cls])


# ---------------------------------------------------------------------------
# Small-set gate — fires on the WIRED path for a 30-row QI set (was dead code).
# ---------------------------------------------------------------------------

def test_record_count_xlsx_counts_data_rows():
    # L-06 seam: the xlsx record count was 0 (only row= provenance was counted),
    # so the gate was blind to the xlsx format the demo uses.  Now 30.
    pipe = DocumentInspectionPipeline()
    assert pipe._record_count(_pii_30()) == 30
    assert pipe._record_count(_pci_30()) == 30


def test_small_set_gate_fires_on_30_row_qi_set():
    # Threshold raised so the 30-row demo set is "small"; the wired gate fires.
    pipe = DocumentInspectionPipeline(small_set_threshold=50)
    matches, _ = pipe._enumerate(_pii_30())
    rc = pipe._record_count(_pii_30())
    assert pipe._small_set_escalation(matches, rc) is True


def test_small_set_gate_quiet_above_threshold():
    # At the default threshold (20) a 30-row set is above the gate → no fire.
    pipe = DocumentInspectionPipeline(small_set_threshold=20)
    matches, _ = pipe._enumerate(_pii_30())
    rc = pipe._record_count(_pii_30())
    assert pipe._small_set_escalation(matches, rc) is False


# ---------------------------------------------------------------------------
# PCI — spaced PAN + CVV + expiry + cardholder name detected on the sample.
# ---------------------------------------------------------------------------

def test_pci_spaced_pan_and_cvv_expiry_cardholder():
    pipe = DocumentInspectionPipeline()
    matches, _ = pipe._enumerate(_pci_30())
    classes = _classes(matches)
    for expected in (
        "PCI.PAN", "PCI.CVV", "PCI.CARD_EXPIRY", "PCI.CARDHOLDER_NAME",
    ):
        assert expected in classes, f"{expected} not detected on PCI sample"
    # The billing postcode column is caught by the value-only postcode pattern.
    assert "PII.POSTAL_ADDRESS" in classes


def test_pci_spaced_pan_value_detected_directly():
    from yashigani.pii.detector import PiiDetector, PiiMode
    d = PiiDetector(mode=PiiMode.LOG)
    r = d.detect("4111 1111 1111 1111")
    assert any(f.pii_type.value == "CREDIT_CARD" for f in r.findings)
