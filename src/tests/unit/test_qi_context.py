"""
Unit tests for the column-semantic identifying-class detector
(``yashigani.documents.qi_context``) — the L-01 / red-team F2 breadth that flags
identifying columns whose cell values have no distinctive lone-cell form
(DOB column, CVV, expiry, cardholder/full-name).
"""
from __future__ import annotations

from yashigani.documents.qi_context import (
    classify_columns,
    header_driven_matches,
)
from yashigani.documents.segment import Segment, SegmentKind


def _xlsx(headers, rows, sheet="S"):
    cols = "ABCDEFGH"
    segs = []
    for c, h in enumerate(headers):
        segs.append(Segment(text=h, kind=SegmentKind.TABLE_CELL,
                            location=f"sheet={sheet}!{cols[c]}1"))
    for r, row in enumerate(rows, start=2):
        for c, cell in enumerate(row):
            segs.append(Segment(text=cell, kind=SegmentKind.TABLE_CELL,
                                location=f"sheet={sheet}!{cols[c]}{r}"))
    return segs


def test_classify_columns_pii_headers():
    segs = _xlsx(["Full Name", "Date of Birth", "Home Address",
                  "National Insurance No."],
                 [["Olivia Bennett", "01/01/1960", "1 High St, SW1A 1AA",
                   "AA 10 10 10 A"]])
    cls = {k: v.data_class for k, v in classify_columns(segs).items()}
    assert cls[("S", "A")] == "PII.PERSON_NAME"
    assert cls[("S", "B")] == "PII.DATE_OF_BIRTH"
    assert cls[("S", "C")] == "PII.POSTAL_ADDRESS"
    assert cls[("S", "D")] == "PII.NATIONAL_INSURANCE"


def test_classify_columns_pci_cardholder_wins_over_name():
    segs = _xlsx(["Cardholder Name", "CVV", "Expiry", "Card Number"],
                 [["Ethan Khan", "100", "01/26", "4111 1111 1111 1111"]])
    cls = {k: v.data_class for k, v in classify_columns(segs).items()}
    # "Cardholder Name" must map to PCI.CARDHOLDER_NAME, not the generic name QI.
    assert cls[("S", "A")] == "PCI.CARDHOLDER_NAME"
    assert cls[("S", "B")] == "PCI.CVV"
    assert cls[("S", "C")] == "PCI.CARD_EXPIRY"
    assert cls[("S", "D")] == "PCI.PAN"


def test_header_driven_matches_tag_data_cells_only():
    segs = _xlsx(["Date of Birth"], [["01/01/1960"], ["02/02/1961"]])
    ms = header_driven_matches(segs)
    assert len(ms) == 2
    assert all(m.data_class == "PII.DATE_OF_BIRTH" and m.qi for m in ms)
    # The header cell itself is never tagged.
    assert all("!A1" not in m.segment.location for m in ms)


def test_value_plausibility_guards_stray_cell():
    # A CVV column with a non-numeric stray cell: only the numeric cell tags.
    segs = _xlsx(["CVV"], [["100"], ["n/a"]])
    ms = header_driven_matches(segs)
    tagged = {m.segment.text for m in ms}
    assert "100" in tagged
    assert "n/a" not in tagged


def test_no_headers_no_matches():
    segs = _xlsx(["Scheme", "Amount"], [["Visa", "12.50"]])
    assert header_driven_matches(segs) == []
