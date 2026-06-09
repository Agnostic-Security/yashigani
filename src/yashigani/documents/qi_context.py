"""
Yashigani Document Enforcement — column-semantic identifying-class detection
(L-01 / red-team F2 breadth).

The per-value regex detector (``yashigani.pii``) catches values whose FORM is
distinctive on a lone cell: email, phone, PAN, IBAN, NHS/NI numbers, postcodes.
But three identifying classes in Tiago's canonical spreadsheet have NO
distinctive lone-cell form and are missed by a value-only scan:

  * a **date-of-birth column** whose cells are bare dates (``01/01/1960``) — a
    bare date is ambiguous without context (could be a report date);
  * a **CVV column** whose cells are bare 3–4 digit numbers (``100``) —
    indistinguishable from any small integer on its own;
  * a **cardholder-name / full-name column** whose cells are person names
    (``Olivia Bennett``) — a person name has no regex form at all.

A spreadsheet/CSV gives us the missing context for free: the **header row**.
This module classifies a column by its header text (``Date of Birth``,
``CVV``, ``Cardholder Name`` …) and tags every data cell in that column with
the right identifying class.  This is exactly the "column-semantic QI detector
beyond the three PII types" Laura's L-01 fix called for — and it carries the
``qi`` flag so the small-set re-identification gate sees the full QI set.

The classification is header-driven (deterministic, low false-positive) and the
value is still required to look plausible for the class (a non-empty cell for a
name; a date-shaped or digit-shaped cell for DOB/CVV) so a stray non-conforming
cell is not mis-tagged.  Class strings mirror the ``PII.<TYPE>`` /
``PCI.<TYPE>`` namespace the OPA matrix reasons over.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from yashigani.documents.pseudonymize import is_pseudonymization_token
from yashigani.documents.segment import Segment, SegmentKind


# ---------------------------------------------------------------------------
# Column-header → identifying class mapping.
# ---------------------------------------------------------------------------
# Each entry: (compiled header matcher, data_class, is_qi).  Header text is
# matched case-insensitively against the cell that heads the column.  The class
# uses the namespaced form the policy matrix matches on (PII.* / PCI.*).

@dataclass(frozen=True)
class _ColumnClass:
    matcher: re.Pattern[str]
    data_class: str
    qi: bool


_COLUMN_CLASSES: list[_ColumnClass] = [
    # --- PCI cardholder name FIRST so it wins over the generic name matcher ---
    _ColumnClass(
        re.compile(r"\b(?:cardholder\s*name|card\s*holder|name\s+on\s+card)\b", re.I),
        "PCI.CARDHOLDER_NAME", False,
    ),
    # --- PII / quasi-identifiers (re-identify a small set in combination) ----
    _ColumnClass(
        re.compile(r"\b(?:d\.?o\.?b\.?|date\s+of\s+birth|birth\s*date|born)\b", re.I),
        "PII.DATE_OF_BIRTH", True,
    ),
    _ColumnClass(
        re.compile(r"\b(?:full\s*name|first\s*name|last\s*name|surname|forename|"
                   r"employee\s*name|customer\s*name|person|name)\b", re.I),
        "PII.PERSON_NAME", True,
    ),
    _ColumnClass(
        re.compile(r"\b(?:home\s*address|postal\s*address|billing\s*address|address)\b", re.I),
        "PII.POSTAL_ADDRESS", True,
    ),
    _ColumnClass(
        re.compile(r"\b(?:national\s*insurance|nino|ni\s*(?:no|number)|"
                   r"social\s*security|ssn)\b", re.I),
        "PII.NATIONAL_INSURANCE", True,
    ),
    _ColumnClass(
        re.compile(r"\b(?:salary|remuneration|annual\s*pay|gross\s*pay|compensation)\b", re.I),
        "PII.SALARY", True,
    ),
    _ColumnClass(
        re.compile(r"\b(?:job\s*title|title|role|position|grade)\b", re.I),
        "PII.JOB_TITLE", True,
    ),
    # --- PCI (cardholder data) ----------------------------------------------
    _ColumnClass(
        re.compile(r"\b(?:cvv|cvc|cvv2|cvc2|security\s*code|card\s*verification)\b", re.I),
        "PCI.CVV", False,
    ),
    _ColumnClass(
        re.compile(r"\b(?:expiry|expiration|exp\.?\s*date|valid\s*thru|valid\s*until)\b", re.I),
        "PCI.CARD_EXPIRY", False,
    ),
    _ColumnClass(
        re.compile(r"\b(?:card\s*number|card\s*no|pan|primary\s*account\s*number)\b", re.I),
        "PCI.PAN", False,
    ),
]


# ---------------------------------------------------------------------------
# Value plausibility guards — a header-classified cell must still LOOK like the
# class before we tag it, so a non-conforming stray cell is not mis-tagged.
# ---------------------------------------------------------------------------

_DATE_SHAPED = re.compile(
    r"^\s*\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}\s*$"  # 01/01/1960, 1960-01-01
    r"|^\s*\d{1,2}\s+[A-Za-z]{3,9}\s+\d{2,4}\s*$"  # 1 January 1960
    r"|^\s*[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{2,4}\s*$",  # January 1, 1960
)
_CVV_SHAPED = re.compile(r"^\s*\d{3,4}\s*$")
_EXPIRY_SHAPED = re.compile(
    r"^\s*\d{1,2}\s*[/\-]\s*\d{2,4}\s*$"            # 01/26, 01/2026
    r"|^\s*\d{4}\s*[/\-]\s*\d{1,2}\s*$",            # 2026/01
)
# A person/cardholder name: at least one letter, no @ (not an email), short-ish.
_NAME_SHAPED = re.compile(r"^[^@\d]*[A-Za-z][^@]*$")


def _value_plausible(data_class: str, value: str) -> bool:
    """Whether ``value`` plausibly belongs to ``data_class`` (guard against
    mis-tagging a stray non-conforming cell under a classified header)."""
    v = value.strip()
    if not v:
        return False
    # Never re-classify one of OUR OWN emitted pseudonymization tokens
    # (``[PERSON_NAME_1]``, ``[DOB_2]`` …).  When the residual re-detect
    # re-classifies the TOKENIZED output, a name-shaped token under a still-present
    # ``name`` header would otherwise be re-flagged as a surviving PERSON_NAME and
    # BLOCK a clean artefact (csv name-column false positive).  A real input cell
    # literally equal to ``[PERSON_NAME_1]`` is not a plausible class value either.
    if is_pseudonymization_token(v):
        return False
    if data_class == "PII.DATE_OF_BIRTH":
        return bool(_DATE_SHAPED.match(v))
    if data_class == "PCI.CVV":
        return bool(_CVV_SHAPED.match(v))
    if data_class == "PCI.CARD_EXPIRY":
        return bool(_EXPIRY_SHAPED.match(v))
    if data_class in ("PII.PERSON_NAME", "PCI.CARDHOLDER_NAME"):
        # A name: contains letters, isn't an email, and is short (a few words).
        return bool(_NAME_SHAPED.match(v)) and len(v) <= 80 and len(v.split()) <= 6
    # Address / salary / title / PAN: any non-empty cell under the header.
    return True


# ---------------------------------------------------------------------------
# Column key recovery from a segment's provenance location.
# ---------------------------------------------------------------------------

_XLSX_CELL = re.compile(r"sheet=(?P<sheet>[^!]+)!(?P<col>[A-Z]+)(?P<row>\d+)")
_CSV_CELL = re.compile(r"row=(?P<row>\d+),col=(?P<col>\d+)")


def _column_key(location: str) -> tuple[str, str, int] | None:
    """Return ``(sheet, column, row)`` for a table cell, else None.

    ``sheet`` is the worksheet name (or ``""`` for CSV), ``column`` is the
    column key within that sheet, ``row`` is the 1-based row number.  Both the
    xlsx worker provenance (``sheet=Title!B2``) and the CSV provenance
    (``row=2,col=2``) are understood.
    """
    m = _XLSX_CELL.search(location)
    if m:
        return (m.group("sheet"), m.group("col"), int(m.group("row")))
    m = _CSV_CELL.search(location)
    if m:
        return ("", m.group("col"), int(m.group("row")))
    return None


# ---------------------------------------------------------------------------
# Public: enrich a list of segments with header-driven identifying matches.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContextMatch:
    """A header-driven identifying-class hit on a data cell (the QI breadth the
    value-only detector cannot see)."""

    segment: Segment
    data_class: str
    qi: bool
    char_start: int
    char_end: int


def classify_columns(segments: list[Segment]) -> dict[tuple[str, str], _ColumnClass]:
    """Map ``(sheet, column) -> _ColumnClass`` from the header row.

    The header is the FIRST row that has cells per sheet (row index 1 in both
    provenance schemes).  Only header cells whose text matches a known column
    class contribute; everything else is left for the value-only detector.
    """
    # Find the minimum row per (sheet) so we treat the true first row as header
    # even if row numbering does not start at 1 in some provenance.
    min_row: dict[str, int] = {}
    for seg in segments:
        key = _column_key(seg.location)
        if key is None:
            continue
        sheet, _col, row = key
        if sheet not in min_row or row < min_row[sheet]:
            min_row[sheet] = row

    classes: dict[tuple[str, str], _ColumnClass] = {}
    for seg in segments:
        key = _column_key(seg.location)
        if key is None:
            continue
        sheet, col, row = key
        if row != min_row.get(sheet):
            continue  # not a header cell
        header = seg.text
        for cc in _COLUMN_CLASSES:
            if cc.matcher.search(header):
                classes[(sheet, col)] = cc
                break
    return classes


def header_driven_matches(segments: list[Segment]) -> list[ContextMatch]:
    """Produce header-driven identifying matches over the DATA cells.

    For every table cell whose column was classified by its header AND whose
    value is plausible for that class, emit a :class:`ContextMatch` spanning the
    whole cell.  Header cells themselves and the value-only detector's domain
    (email/phone/PAN/postcode/NI — caught directly) are left untouched; the
    caller de-duplicates against the value-only matches by location/class.
    """
    classes = classify_columns(segments)
    if not classes:
        return []

    min_row: dict[str, int] = {}
    for seg in segments:
        key = _column_key(seg.location)
        if key is None:
            continue
        sheet, _col, row = key
        if sheet not in min_row or row < min_row[sheet]:
            min_row[sheet] = row

    out: list[ContextMatch] = []
    for seg in segments:
        # Only TABLE_CELL / HIDDEN cell content carries column semantics.
        if seg.kind not in (SegmentKind.TABLE_CELL, SegmentKind.HIDDEN):
            continue
        key = _column_key(seg.location)
        if key is None:
            continue
        sheet, col, row = key
        if row == min_row.get(sheet):
            continue  # header cell, not a value
        cc = classes.get((sheet, col))
        if cc is None:
            continue
        if not _value_plausible(cc.data_class, seg.text):
            continue
        out.append(
            ContextMatch(
                segment=seg,
                data_class=cc.data_class,
                qi=cc.qi,
                char_start=0,
                char_end=len(seg.text),
            )
        )
    return out
