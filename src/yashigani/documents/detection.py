"""
Yashigani Document Enforcement — format detection (magic-bytes + declared MIME).

Threat model (red-team review 2026-06-08, F2 polyglot / F8 content-type confusion):
  - NEVER trust the declared MIME / extension alone.  An attacker can declare
    ``text/csv`` over a zip bomb, or hide an OOXML payload under a ``text/plain``
    header (zip central directory lives at the *end* of the file).
  - The sniff is **append-aware** for the zip/OOXML family: scan for a zip
    End-Of-Central-Directory ("PK\\x05\\x06") signature anywhere, not just the
    offset-0 local-file-header magic, so "text + appended docx" routes to the
    extractor, not the text path.
  - When the declared MIME and the sniffed type **disagree**, the request is
    **rejected fail-closed** (BLOCK).  Extension/declared-content-type never
    win the tie-break.

THIS slice implements the *detection-and-reject* path end-to-end for the two
trivial formats (txt, csv) and recognises — but does NOT parse — the
untrusted-parser families (OOXML-zip, pdf).  Those families resolve to a
registered-but-unimplemented extractor that fail-closes to BLOCK (they need
Su's sandbox; see ``extractor.py``).

Per the plan §2 the committed format set is: docx, xlsx, pptx, pdf, csv, txt.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DetectedType(str, Enum):
    """Canonical detected document type."""

    TXT = "txt"
    CSV = "csv"
    DOCX = "docx"
    XLSX = "xlsx"
    PPTX = "pptx"
    PDF = "pdf"
    # Sentinel: the byte stream did not match any committed format, or the
    # declared MIME and sniffed bytes were inconsistent → fail-closed BLOCK.
    UNKNOWN = "unknown"


# Declared-MIME → expected DetectedType.  Used only to CHECK the sniff, never
# to override it (F8 — declared content-type must not win).
_MIME_TO_TYPE: dict[str, DetectedType] = {
    "text/plain": DetectedType.TXT,
    "text/csv": DetectedType.CSV,
    "application/csv": DetectedType.CSV,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": DetectedType.DOCX,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": DetectedType.XLSX,
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": DetectedType.PPTX,
    "application/pdf": DetectedType.PDF,
}

# Families that share magic bytes and can only be distinguished by inspecting
# the zip's internal part names (OOXML).  In THIS slice we do not crack the zip
# (that runs an untrusted parser → needs the sandbox); we resolve the whole
# OOXML family to a single sniff and let the registry fail it closed.
_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_ZIP_EOCD = b"PK\x05\x06"  # End-Of-Central-Directory — append-aware sniff (F8)
_PDF_MAGIC = b"%PDF-"


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of sniffing a byte stream against its declared MIME."""

    detected_type: DetectedType
    declared_mime: str
    # True when declared MIME and sniffed bytes are consistent (or no MIME
    # declared and the sniff is unambiguous).  False → fail-closed BLOCK (F8).
    consistent: bool
    reason: str


def _looks_like_zip(data: bytes) -> bool:
    """Append-aware zip detection (F8).

    True if the stream starts with a zip local-file header OR carries an
    End-Of-Central-Directory signature anywhere (handles "text + appended
    docx" and zip-with-prefix polyglots).
    """
    if data.startswith(_ZIP_LOCAL_HEADER):
        return True
    # EOCD is near the end of a zip; scan the whole buffer (already capped by
    # the caller's size guard before this is reached).
    return _ZIP_EOCD in data


def _looks_like_pdf(data: bytes) -> bool:
    # PDF magic may be preceded by up to a few junk bytes per spec; check the
    # head window rather than only offset 0.
    return _PDF_MAGIC in data[:1024]


def _looks_textual(data: bytes) -> bool:
    """Heuristic: the stream decodes as UTF-8/Latin-1 text with no NUL bytes
    and no binary container magic.  Deliberately conservative — anything that
    smells like a container is NOT textual.
    """
    if not data:
        return True  # empty stream is trivially text (and will produce no matches)
    if b"\x00" in data:
        return False
    if _looks_like_zip(data) or _looks_like_pdf(data):
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        # Latin-1 always decodes; accept as text only if it is mostly
        # printable to avoid classifying arbitrary binary as "text".
        printable = sum(
            1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
        )
        return printable / len(data) >= 0.95


def _sniff(data: bytes, declared_type: DetectedType | None) -> DetectedType:
    """Sniff the byte stream.  Container magic wins over a textual fallback.

    For the textual case we cannot tell txt from csv by bytes alone, so we use
    the declared type as a *hint within the textual family only* (both are
    handled by trivial extractors, so this is not a trust-elevation).
    """
    if _looks_like_zip(data):
        # OOXML family — we cannot crack the zip in this slice (no sandbox), so
        # we cannot distinguish docx/xlsx/pptx.  Resolve to the declared OOXML
        # type if one was given (so the registry can fail the right format
        # closed); otherwise DOCX as a representative OOXML member.  Either way
        # the registry routes the whole family to fail-closed BLOCK.
        if declared_type in (DetectedType.DOCX, DetectedType.XLSX, DetectedType.PPTX):
            return declared_type
        return DetectedType.DOCX
    if _looks_like_pdf(data):
        return DetectedType.PDF
    if _looks_textual(data):
        # Textual family: trust the declared hint between txt/csv only.
        if declared_type in (DetectedType.TXT, DetectedType.CSV):
            return declared_type
        return DetectedType.TXT
    return DetectedType.UNKNOWN


def detect_format(data: bytes, declared_mime: str) -> DetectionResult:
    """Detect the document type from magic bytes, cross-checked against the
    declared MIME.  Mismatch → ``consistent=False`` (fail-closed BLOCK, F8).

    Parameters
    ----------
    data:
        The raw document bytes (already size-capped by the caller).
    declared_mime:
        The Content-Type / declared MIME accompanying the bytes.  May be empty.
    """
    declared = declared_mime.split(";")[0].strip().lower() if declared_mime else ""
    declared_type = _MIME_TO_TYPE.get(declared)

    sniffed = _sniff(data, declared_type)

    if sniffed == DetectedType.UNKNOWN:
        return DetectionResult(
            detected_type=DetectedType.UNKNOWN,
            declared_mime=declared,
            consistent=False,
            reason="unrecognised or binary content — no committed format matched",
        )

    # No declared MIME, or an unrecognised one: accept the sniff on its own.
    if declared_type is None:
        return DetectionResult(
            detected_type=sniffed,
            declared_mime=declared,
            consistent=True,
            reason=(
                "no declared MIME — accepted sniffed type"
                if not declared
                else f"unrecognised declared MIME '{declared}' — accepted sniffed type"
            ),
        )

    # Declared MIME present: it MUST agree with the sniff.
    # Within the textual family (txt<->csv) the sniff already deferred to the
    # declared hint, so they will match.  A cross-family disagreement
    # (declared text, sniffed zip/pdf — or vice versa) is a polyglot/confusion
    # attempt → fail-closed.
    if declared_type == sniffed:
        return DetectionResult(
            detected_type=sniffed,
            declared_mime=declared,
            consistent=True,
            reason="declared MIME matches sniffed type",
        )

    return DetectionResult(
        detected_type=DetectedType.UNKNOWN,
        declared_mime=declared,
        consistent=False,
        reason=(
            f"declared MIME '{declared}' (=> {declared_type.value}) disagrees with "
            f"sniffed type '{sniffed.value}' — possible polyglot/content-type "
            f"confusion, rejecting fail-closed (F8)"
        ),
    )
