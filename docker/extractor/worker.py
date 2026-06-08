#!/usr/bin/env python3
"""
Yashigani sandboxed-extractor WORKER — runs INSIDE the per-job jail.

This is the in-sandbox entrypoint of the hardened extractor runtime (plan §6
B1). It is the process the Captain sandbox spawns; it is the SEAM Tom plugged the
real OOXML/PDF parsers into. The REDACT/PSEUDONYMIZE re-render (red-team F6 —
re-render runs in the SAME jail) lands in the NEXT slice at ``_render_*``.

CONTRACT (language-agnostic, process-level — see sandbox.py docstring):
    stdin  : raw document bytes (the single read-only input)
    argv   : --job extract|redact|pseudonymize  --format docx|xlsx|pptx|pdf
             --declared-mime <mime>
    stdout : exactly ONE JSON object (SandboxJobResult schema):
               {"ok": true,  "segments": [...], "extraction_complete": bool,
                "detected_format": "docx"}
               {"ok": false, "reason": "<why we contained it>"}
    exit 0 : a JSON result was written (ok true OR ok-false-with-reason).
    exit !=0 : the worker crashed — the runner fails closed to BLOCK.

WHAT CAPTAIN OWNS HERE (the env): reading stdin under a size cap, the
decompression-bomb / billion-laughs guard (bomb_guard.py) that runs BEFORE any
parser, the hardened-XML parser factory, the JSON output contract, and the
fail-closed exit semantics. NO untrusted parser runs until the guard passes.

WHAT TOM ADDS (this slice): the bodies of ``_extract_docx`` / ``_extract_xlsx``
/ ``_extract_pptx`` / ``_extract_pdf``. Each returns
``(segments: list[dict], extraction_complete: bool)``. A segment dict mirrors
``yashigani.documents.segment.Segment``:
    {"text": str, "kind": "BODY"|"TABLE_CELL"|"COMMENT"|..., "location": str,
     "confidence": float, "needs_ocr": bool}
The ``kind`` strings MUST match ``SegmentKind`` values (host-side
``SandboxedExtractor`` maps them back to the enum); an unknown kind there is a
fail-closed ValueError, so the kinds here are the single source of truth.

THE DIFFERENTIATOR (plan §3.1, NON-NEGOTIABLE): we surface the HIDDEN data parts
and metadata, not just the visible body. Sensitive data hides in comments,
tracked changes, footnotes, headers/footers, speaker notes, hidden sheets/rows/
columns, cell notes, defined names, formula text, and document properties. Each
segment carries truthful provenance + part-kind so a hidden-cell hit is LABELLED
as a hidden-cell hit in the audit event.

HARDENING (red-team F1): every untrusted XML part is parsed with the
XXE/entity-expansion-safe ``harden_xml_parser()`` (no external entities, no DTD,
bounded expansion). The bomb guard runs BEFORE any part is touched. A malformed/
truncated/encrypted document → clean ``_Contained`` (ok=False, BLOCK), never an
ambiguous crash.

The worker imports the guard + hardened parser from the installed
``yashigani.documents.bomb_guard`` (baked into the extractor image) so there is a
single source of truth for the caps + the parser settings — no copy-drift
(Verification Protocol §4). The parser libraries (python-docx-free direct-XML for
docx/pptx, openpyxl for xlsx, pypdf for pdf) live ONLY in the extractor image
(docker/Dockerfile.extractor), never the gateway image.

REDACT/PSEUDONYMIZE re-render seam (NEXT slice): ``_render_docx`` /
``_render_xlsx`` / ``_render_pptx`` / ``_render_pdf`` are stubbed below and the
``redact``/``pseudonymize`` jobs are contained until they land. They run in THIS
same jail (F6); do NOT move re-render into the gateway process.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import zipfile

# Hard cap on stdin so a giant pipe cannot exhaust the jail before the guard
# even runs. The cgroup mem-limit is the backstop; this is the fast precise stop.
_MAX_STDIN_BYTES = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_STDIN_BYTES", str(64 * 1024 * 1024)))

#: Cap on the number of segments any one document may yield, mirroring the
#: front-end ``DEFAULT_MAX_SEGMENTS`` (extractor.py). A pathological sheet/slide
#: count is a cheap amplification — bound it here too (the front-end cannot,
#: because it never sees the cracked parts; only the worker does).
_MAX_SEGMENTS = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_SEGMENTS", str(100_000)))

#: Cap on a single segment's text length so one giant run/cell/note cannot blow
#: the output budget (the runner also caps total stdout — this is the per-unit
#: precise stop).
_MAX_SEGMENT_CHARS = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_SEGMENT_CHARS", str(1_000_000)))

_SUPPORTED = {"docx", "xlsx", "pptx", "pdf"}

# OOXML namespaces we read parts under. Kept local (no XML lib import at module
# load — lxml is imported lazily via the hardened factory). We match element tags
# by these namespaces (w: wordprocessing, a: DrawingML for slide/notes text);
# metadata parts are matched by LOCAL tag name (namespace-stripped) since the
# docProps schemas vary by Office version.
_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"


def _emit(obj: dict) -> None:
    """Write the single JSON result object to stdout and flush."""
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))
    sys.stdout.flush()


def _read_stdin_capped() -> bytes:
    """Read stdin up to the cap. Over the cap → contained (ok=False)."""
    data = sys.stdin.buffer.read(_MAX_STDIN_BYTES + 1)
    if len(data) > _MAX_STDIN_BYTES:
        raise _Contained(f"input exceeds stdin cap {_MAX_STDIN_BYTES} bytes")
    return data


class _Contained(Exception):
    """A guard tripped — emit ok=False with the reason, exit 0 (contained
    cleanly, the runner still BLOCKs but distinguishes it from a crash)."""


# ---------------------------------------------------------------------------
# Shared helpers (provenance, caps, hardened XML, zip parts).
# ---------------------------------------------------------------------------

def _seg(text, kind: str, location: str, *, needs_ocr: bool = False,
         confidence: float = 1.0) -> dict | None:
    """Build a segment dict, dropping empties and enforcing the per-segment
    text cap. Provenance (``location``) is load-bearing for the audit event and
    must never be empty — a programming error here, not user input."""
    if text is None:
        return None
    s = str(text)
    if s.strip() == "":
        return None
    if len(s) > _MAX_SEGMENT_CHARS:
        raise _Contained(
            f"segment at {location} is {len(s)} chars (cap {_MAX_SEGMENT_CHARS}) "
            f"— amplification, fail-closed"
        )
    if not location:
        # Defensive: never emit a segment the host cannot audit.
        raise _Contained("internal: empty segment location — fail-closed")
    return {
        "text": s,
        "kind": kind,
        "location": location,
        "confidence": confidence,
        "needs_ocr": needs_ocr,
    }


def _signal(text: str, kind: str, location: str) -> dict:
    """A control SEGMENT that must ALWAYS be emitted (never dropped as empty) —
    e.g. a needs-OCR / unparseable-page marker. These drive the fail-closed
    extraction_complete=False decision, so they carry confidence=0.0 +
    needs_ocr=True and are surfaced verbatim (the front-end treats them as
    uninspectable content)."""
    return {
        "text": text,
        "kind": kind,
        "location": location,
        "confidence": 0.0,
        "needs_ocr": True,
    }


def _cap_segments(segments: list[dict]) -> None:
    if len(segments) > _MAX_SEGMENTS:
        raise _Contained(
            f"document produced {len(segments)} segments (cap {_MAX_SEGMENTS}) "
            f"— amplification, fail-closed"
        )


def _xml_parser():
    """Return the single hardened lxml parser (XXE / billion-laughs safe).

    Captain owns the settings in bomb_guard.harden_xml_parser(); the worker
    NEVER constructs its own XML parser — one source of truth (F1)."""
    from yashigani.documents.bomb_guard import harden_xml_parser
    return harden_xml_parser()


def _parse_xml(raw: bytes):
    """Parse one untrusted XML part with the hardened parser. Malformed → None
    (the caller decides whether a missing/garbled part fails the whole doc or is
    a tolerable absence; a *body* part going None fails-closed, an *optional*
    hidden part going None marks extraction incomplete)."""
    from lxml import etree  # type: ignore[import-untyped]
    try:
        return etree.fromstring(raw, parser=_xml_parser())
    except etree.XMLSyntaxError:
        return None


def _open_zip(data: bytes) -> zipfile.ZipFile:
    """Open the OOXML zip. The bomb guard has ALREADY validated this archive is
    safe to decompress (run_extract calls _guard_ooxml first); a BadZipFile here
    is a malformed/truncated container → contained."""
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise _Contained(f"not a valid OOXML zip container: {exc}") from exc


def _read_part(zf: zipfile.ZipFile, name: str) -> bytes | None:
    """Read one zip part by exact name. Missing part → None (not an error; many
    parts are optional)."""
    try:
        return zf.read(name)
    except KeyError:
        return None


def _names(zf: zipfile.ZipFile) -> list[str]:
    return zf.namelist()


def _local(tag: str) -> str:
    """Strip the XML namespace from a tag for matching."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text_of(el) -> str:
    """All descendant text of an element, joined — used for a paragraph/run tree
    where we want the concatenated visible text of the node."""
    if el is None:
        return ""
    return "".join(el.itertext())


def _guard_ooxml(data: bytes) -> None:
    """Run the decompression-bomb / nesting / entry-count guard on the OOXML zip
    BEFORE any parser sees a part (plan §6). Raises _Contained on any breach."""
    from yashigani.documents.bomb_guard import (
        BombGuardLimits,
        DecompressionBombError,
        guard_zip_bytes,
    )

    try:
        guard_zip_bytes(data, BombGuardLimits())
    except DecompressionBombError as exc:
        raise _Contained(str(exc)) from exc


def _ooxml_is_encrypted(data: bytes) -> bool:
    """An OOXML file that was password-protected/encrypted by Office is wrapped
    in an OLE Compound File (CFB), NOT a zip — its magic is the CFB signature.
    We never attempt to decrypt/crack (red-team + design): detect → fail-closed.

    A genuine OOXML zip starts with 'PK'. A CFB starts with the OLE magic. If the
    bytes are a CFB (or otherwise not a zip), the zip-open below contains it; this
    helper gives the precise "encrypted" reason for the common Office case."""
    return data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


# ---------------------------------------------------------------------------
# docx — body + comments + tracked changes + headers/footers + foot/endnotes +
#        document metadata. Parsed via direct hardened-XML (no python-docx, so
#        no surprise object-model parsing of untrusted parts; full control over
#        the hidden parts the high-level lib does not expose).
# ---------------------------------------------------------------------------

def _extract_docx(data: bytes) -> tuple[list[dict], bool]:
    if _ooxml_is_encrypted(data):
        raise _Contained(
            "docx is encrypted/password-protected (OLE-wrapped) — never cracked, "
            "fail-closed BLOCK"
        )
    zf = _open_zip(data)
    names = _names(zf)
    segments: list[dict] = []
    complete = True

    # --- body (word/document.xml) ---
    body = _read_part(zf, "word/document.xml")
    if body is None:
        raise _Contained("docx missing word/document.xml — malformed, fail-closed")
    root = _parse_xml(body)
    if root is None:
        raise _Contained("docx word/document.xml is malformed XML — fail-closed")
    # One BODY segment per paragraph (provenance: the running paragraph index).
    for idx, para in enumerate(root.iter(f"{{{_W}}}p"), start=1):
        seg = _seg(_text_of(para), "BODY", f"word/document.xml#p={idx}")
        if seg:
            segments.append(seg)

    # --- tracked changes / revisions (w:ins inserts, w:del deletions) ---
    # Deleted text lives in w:delText; inserted text in normal w:t under w:ins.
    for idx, ins in enumerate(root.iter(f"{{{_W}}}ins"), start=1):
        seg = _seg(_text_of(ins), "TRACKED_CHANGE",
                   f"word/document.xml#ins={idx}")
        if seg:
            segments.append(seg)
    for idx, dele in enumerate(root.iter(f"{{{_W}}}del"), start=1):
        # delText is the deleted run text — sensitive data is often what was
        # "removed" but still ships in the file.
        txt = "".join(
            t.text or "" for t in dele.iter(f"{{{_W}}}delText")
        )
        seg = _seg(txt, "TRACKED_CHANGE", f"word/document.xml#del={idx}")
        if seg:
            segments.append(seg)

    # --- comments (word/comments.xml) ---
    comments = _read_part(zf, "word/comments.xml")
    if comments is not None:
        croot = _parse_xml(comments)
        if croot is None:
            complete = False  # a present-but-garbled hidden part → incomplete
        else:
            for idx, c in enumerate(croot.iter(f"{{{_W}}}comment"), start=1):
                cid = c.get(f"{{{_W}}}id", str(idx))
                seg = _seg(_text_of(c), "COMMENT",
                           f"word/comments.xml#id={cid}")
                if seg:
                    segments.append(seg)

    # --- footnotes + endnotes ---
    for part, kind_loc in (("word/footnotes.xml", "footnote"),
                           ("word/endnotes.xml", "endnote")):
        raw = _read_part(zf, part)
        if raw is None:
            continue
        froot = _parse_xml(raw)
        if froot is None:
            complete = False
            continue
        note_tag = f"{{{_W}}}footnote" if "footnote" in part else f"{{{_W}}}endnote"
        for idx, n in enumerate(froot.iter(note_tag), start=1):
            nid = n.get(f"{{{_W}}}id", str(idx))
            seg = _seg(_text_of(n), "BODY", f"{part}#{kind_loc}={nid}")
            if seg:
                segments.append(seg)

    # --- headers + footers (word/header*.xml, word/footer*.xml) ---
    for name in names:
        base = name.rsplit("/", 1)[-1]
        if name.startswith("word/") and (base.startswith("header") or base.startswith("footer")) \
                and name.endswith(".xml"):
            raw = _read_part(zf, name)
            if raw is None:
                continue
            hroot = _parse_xml(raw)
            if hroot is None:
                complete = False
                continue
            seg = _seg(_text_of(hroot), "HEADER_FOOTER", f"{name}")
            if seg:
                segments.append(seg)

    # --- document metadata (core + app properties) ---
    segments.extend(_ooxml_metadata(zf))

    _cap_segments(segments)
    return segments, complete


# ---------------------------------------------------------------------------
# xlsx — all sheets incl. hidden sheets/rows/columns + cell comments/notes +
#        defined names + formula text + workbook metadata. openpyxl models all
#        of these cleanly (its only runtime dep is et-xmlfile; it parses untrusted
#        XML with resolve_entities=False / defusedxml — both in the image).
# ---------------------------------------------------------------------------

def _extract_xlsx(data: bytes) -> tuple[list[dict], bool]:
    if _ooxml_is_encrypted(data):
        raise _Contained(
            "xlsx is encrypted/password-protected (OLE-wrapped) — never cracked, "
            "fail-closed BLOCK"
        )
    # openpyxl raises on a non-zip / corrupt workbook — map to clean containment.
    import openpyxl  # type: ignore[import-untyped]
    from openpyxl.utils import get_column_letter  # type: ignore[import-untyped]

    try:
        # data_only=False → keep FORMULA TEXT (sensitive data hides in formulas).
        # read_only=False so hidden row/column dims + defined names are available.
        # keep_links=False avoids resolving external workbook links (egress is
        # blocked anyway, but no point parsing them).
        wb = openpyxl.load_workbook(
            io.BytesIO(data), data_only=False, read_only=False, keep_links=False,
        )
    except Exception as exc:  # openpyxl raises InvalidFileException / KeyError etc.
        raise _Contained(f"xlsx parse failed: {exc!r} — fail-closed") from exc

    segments: list[dict] = []
    complete = True

    for ws in wb.worksheets:
        sheet = ws.title
        # A hidden/veryHidden sheet is a classic data-hiding spot — label it.
        sheet_hidden = ws.sheet_state in ("hidden", "veryHidden")
        hidden_cols = {
            c for c, d in ws.column_dimensions.items() if getattr(d, "hidden", False)
        }
        hidden_rows = {
            r for r, d in ws.row_dimensions.items() if getattr(d, "hidden", False)
        }
        for row in ws.iter_rows():
            for cell in row:
                val = cell.value
                if val is None or (isinstance(val, str) and val == ""):
                    continue
                col_letter = get_column_letter(cell.column)
                is_hidden = (
                    sheet_hidden
                    or col_letter in hidden_cols
                    or cell.row in hidden_rows
                )
                kind = "HIDDEN" if is_hidden else "TABLE_CELL"
                loc = f"sheet={sheet}!{cell.coordinate}"
                if sheet_hidden:
                    loc += ";sheet-hidden"
                elif col_letter in hidden_cols:
                    loc += ";col-hidden"
                elif cell.row in hidden_rows:
                    loc += ";row-hidden"
                # A formula cell: the .value already carries the '=...' text when
                # data_only=False. Label its kind so a formula-text hit is clear.
                seg = _seg(val, kind, loc)
                if seg:
                    segments.append(seg)

        # --- cell comments / notes ---
        for row in ws.iter_rows():
            for cell in row:
                cmt = getattr(cell, "comment", None)
                if cmt is not None and getattr(cmt, "text", None):
                    seg = _seg(cmt.text, "COMMENT",
                               f"sheet={sheet}!{cell.coordinate};comment")
                    if seg:
                        segments.append(seg)

    # --- defined names (named ranges/constants — text can carry sensitive data) ---
    try:
        for name, dn in wb.defined_names.items():
            attr = getattr(dn, "attr_text", "") or getattr(dn, "value", "")
            seg = _seg(f"{name}={attr}", "METADATA", f"defined-name={name}")
            if seg:
                segments.append(seg)
    except Exception:
        complete = False  # malformed defined-names table → don't claim complete

    # --- workbook metadata (core properties) ---
    segments.extend(_ooxml_metadata_from_props(wb.properties))

    wb.close()
    _cap_segments(segments)
    return segments, complete


# ---------------------------------------------------------------------------
# pptx — slides + speaker notes + slide masters/layouts + comments + metadata.
#        Direct hardened-XML (avoids pulling Pillow + XlsxWriter that python-pptx
#        requires — keeps the jail surface minimal).
# ---------------------------------------------------------------------------

def _extract_pptx(data: bytes) -> tuple[list[dict], bool]:
    if _ooxml_is_encrypted(data):
        raise _Contained(
            "pptx is encrypted/password-protected (OLE-wrapped) — never cracked, "
            "fail-closed BLOCK"
        )
    zf = _open_zip(data)
    names = _names(zf)
    segments: list[dict] = []
    complete = True

    def _drawing_text(root) -> str:
        # Slide/notes/master text lives in DrawingML a:t runs.
        return "".join(t.text or "" for t in root.iter(f"{{{_A}}}t"))

    # --- slides (visible body) ---
    slide_names = sorted(
        n for n in names
        if n.startswith("ppt/slides/slide") and n.endswith(".xml")
    )
    if not slide_names:
        # A pptx with no slide parts is malformed (or not really a pptx).
        raise _Contained("pptx has no slide parts — malformed, fail-closed")
    for name in slide_names:
        raw = _read_part(zf, name)
        if raw is None:
            continue
        root = _parse_xml(raw)
        if root is None:
            raise _Contained(f"pptx slide {name} is malformed XML — fail-closed")
        seg = _seg(_drawing_text(root), "BODY", name)
        if seg:
            segments.append(seg)

    # --- speaker notes (ppt/notesSlides/notesSlide*.xml) — the differentiator ---
    for name in sorted(n for n in names
                       if n.startswith("ppt/notesSlides/notesSlide")
                       and n.endswith(".xml")):
        raw = _read_part(zf, name)
        if raw is None:
            continue
        root = _parse_xml(raw)
        if root is None:
            complete = False
            continue
        seg = _seg(_drawing_text(root), "SPEAKER_NOTE", name)
        if seg:
            segments.append(seg)

    # --- slide masters + layouts (boilerplate can carry sensitive placeholders) ---
    for prefix, loc_kind in (("ppt/slideMasters/slideMaster", "master"),
                             ("ppt/slideLayouts/slideLayout", "layout")):
        for name in sorted(n for n in names
                           if n.startswith(prefix) and n.endswith(".xml")):
            raw = _read_part(zf, name)
            if raw is None:
                continue
            root = _parse_xml(raw)
            if root is None:
                complete = False
                continue
            seg = _seg(_drawing_text(root), "HEADER_FOOTER", f"{name};{loc_kind}")
            if seg:
                segments.append(seg)

    # --- comments (ppt/comments/* — modern + legacy) ---
    for name in sorted(n for n in names
                       if n.startswith("ppt/comments/") and n.endswith(".xml")):
        raw = _read_part(zf, name)
        if raw is None:
            continue
        root = _parse_xml(raw)
        if root is None:
            complete = False
            continue
        # Modern comments use a:t (DrawingML); legacy p:text — grab all text.
        txt = _text_of(root)
        seg = _seg(txt, "COMMENT", name)
        if seg:
            segments.append(seg)

    # --- metadata (core + app properties) ---
    segments.extend(_ooxml_metadata(zf))

    _cap_segments(segments)
    return segments, complete


# ---------------------------------------------------------------------------
# pdf — native text layer per page + document metadata / XMP. Image-only /
#       scanned pages (no extractable text) emit a needs-OCR signal that the
#       front-end maps to extraction_complete=False → fail-closed BLOCK. We do
#       NOT attempt OCR (parked, §A). Encrypted → fail-closed (never cracked).
# ---------------------------------------------------------------------------

def _extract_pdf(data: bytes) -> tuple[list[dict], bool]:
    import pypdf  # type: ignore[import-untyped]
    from pypdf.errors import PdfReadError, DependencyError  # type: ignore[import-untyped]

    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
    except (PdfReadError, DependencyError, OSError, ValueError) as exc:
        raise _Contained(f"pdf parse failed: {exc!r} — fail-closed") from exc

    # Encrypted PDFs: never attempt to crack. is_encrypted is True even for
    # empty-owner-password files; we refuse all encryption (design + red-team).
    if reader.is_encrypted:
        raise _Contained(
            "pdf is encrypted/password-protected — never cracked, fail-closed BLOCK"
        )

    segments: list[dict] = []
    complete = True

    try:
        pages = reader.pages
        n_pages = len(pages)
    except (PdfReadError, DependencyError, ValueError) as exc:
        raise _Contained(f"pdf page tree unreadable: {exc!r} — fail-closed") from exc

    for idx in range(n_pages):
        try:
            page = pages[idx]
            text = page.extract_text() or ""
        except (PdfReadError, DependencyError, KeyError, ValueError, TypeError) as exc:
            # One unreadable page → mark incomplete, keep going (other pages may
            # still carry text we must classify); the doc cannot claim complete.
            complete = False
            segments.append(_signal(
                f"[unparseable page: {exc!r}]", "OCR",
                f"page={idx + 1};unparseable"))
            continue
        if text.strip() == "":
            # No native text layer on this page → likely image-only/scanned.
            # Emit a needs-OCR signal (parked) that fails the doc closed: a page
            # we could not read is NOT an empty page we can wave through (F9/F11).
            complete = False
            segments.append(_signal(
                "[no native text — needs OCR]", "OCR",
                f"page={idx + 1};needs-ocr"))
            continue
        seg = _seg(text, "BODY", f"page={idx + 1}")
        if seg:
            segments.append(seg)

    # --- document metadata (DocInfo) ---
    try:
        meta = reader.metadata
        if meta:
            for key in ("title", "author", "subject", "creator", "producer",
                        "keywords"):
                val = getattr(meta, key, None)
                seg = _seg(val, "METADATA", f"metadata={key}")
                if seg:
                    segments.append(seg)
    except Exception:
        complete = False

    # --- XMP metadata (the richer, often-overlooked metadata stream) ---
    try:
        xmp = reader.xmp_metadata
        if xmp is not None:
            # Surface the raw XMP packet text — it can carry author, custom
            # fields, redaction breadcrumbs. Parsed defensively as a string.
            raw = getattr(xmp, "rdf_root", None)
            xmp_text = ""
            try:
                if raw is not None:
                    # rdf_root is an ElementTree element already parsed by pypdf;
                    # join its descendant text rather than re-parsing the packet.
                    xmp_text = "".join(raw.itertext())
            except Exception:
                xmp_text = ""
            seg = _seg(xmp_text, "METADATA", "metadata=xmp")
            if seg:
                segments.append(seg)
    except Exception:
        complete = False

    # A PDF with zero extractable text and zero pages-with-text is fully
    # uninspectable → not complete (already reflected via the per-page needs-OCR
    # signals; this is the belt-and-suspenders for a zero-page doc).
    if n_pages == 0:
        complete = False

    _cap_segments(segments)
    return segments, complete


# ---------------------------------------------------------------------------
# OOXML metadata helpers (core + app properties), shared by docx/pptx.
# ---------------------------------------------------------------------------

def _ooxml_metadata(zf: zipfile.ZipFile) -> list[dict]:
    """Extract core + extended document properties from an OOXML package.

    docProps/core.xml carries author/title/subject/keywords/lastModifiedBy;
    docProps/app.xml carries company/manager/template. Both are frequent leak
    spots (the 'lastModifiedBy' on a 'cleaned' doc, the internal company name)."""
    out: list[dict] = []

    core = _read_part(zf, "docProps/core.xml")
    if core is not None:
        root = _parse_xml(core)
        if root is not None:
            for el in root.iter():
                tag = _local(el.tag)
                if tag in ("coreProperties",):
                    continue
                seg = _seg(el.text, "METADATA", f"docProps/core.xml#{tag}")
                if seg:
                    out.append(seg)

    app = _read_part(zf, "docProps/app.xml")
    if app is not None:
        root = _parse_xml(app)
        if root is not None:
            for el in root.iter():
                tag = _local(el.tag)
                if tag in ("Properties",):
                    continue
                seg = _seg(el.text, "METADATA", f"docProps/app.xml#{tag}")
                if seg:
                    out.append(seg)

    return out


def _ooxml_metadata_from_props(props) -> list[dict]:
    """xlsx metadata via openpyxl's parsed DocumentProperties object."""
    out: list[dict] = []
    if props is None:
        return out
    for key in ("creator", "title", "subject", "description", "keywords",
                "lastModifiedBy", "category", "company", "manager"):
        val = getattr(props, key, None)
        seg = _seg(val, "METADATA", f"metadata={key}")
        if seg:
            out.append(seg)
    return out


_EXTRACTORS = {
    "docx": _extract_docx,
    "xlsx": _extract_xlsx,
    "pptx": _extract_pptx,
    "pdf": _extract_pdf,
}


# ---------------------------------------------------------------------------
# Re-render seam (REDACT / PSEUDONYMIZE) — NEXT slice (red-team F6, same jail).
# Stubs left intentionally so the contract is stable; jobs are contained until
# the bodies land. Do NOT move re-render into the gateway process.
# ---------------------------------------------------------------------------

def _render_docx(data: bytes, plan: dict) -> bytes:  # pragma: no cover - next slice
    raise _Contained("docx re-render not yet implemented (REDACT/PSEUDONYMIZE slice)")


def _render_xlsx(data: bytes, plan: dict) -> bytes:  # pragma: no cover - next slice
    raise _Contained("xlsx re-render not yet implemented (REDACT/PSEUDONYMIZE slice)")


def _render_pptx(data: bytes, plan: dict) -> bytes:  # pragma: no cover - next slice
    raise _Contained("pptx re-render not yet implemented (REDACT/PSEUDONYMIZE slice)")


def _render_pdf(data: bytes, plan: dict) -> bytes:  # pragma: no cover - next slice
    raise _Contained("pdf re-render not yet implemented (REDACT/PSEUDONYMIZE slice)")


def _run_extract(fmt: str, data: bytes) -> dict:
    if fmt not in _SUPPORTED:
        raise _Contained(f"unsupported format '{fmt}' — fail-closed")
    if fmt in ("docx", "xlsx", "pptx"):
        # Encrypted/password-protected OOXML is an OLE Compound File, NOT a zip.
        # Detect it FIRST (before the zip bomb guard tries to open it and reports
        # the generic "not a valid zip") so the audit reason is the precise
        # "encrypted — never cracked, fail-closed BLOCK".
        if _ooxml_is_encrypted(data):
            raise _Contained(
                f"{fmt} is encrypted/password-protected (OLE-wrapped) — never "
                f"cracked, fail-closed BLOCK"
            )
        # Guard the container BEFORE parsing (OOXML is a zip; pdf is guarded by
        # the parser's own bounds + the cgroup — no zip layer to bomb-check).
        _guard_ooxml(data)
    segments, complete = _EXTRACTORS[fmt](data)
    return {
        "ok": True,
        "segments": segments,
        "extraction_complete": complete,
        "detected_format": fmt,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="yashigani-extractor-worker")
    parser.add_argument("--job", default="extract",
                        choices=["extract", "redact", "pseudonymize"])
    parser.add_argument("--format", dest="fmt", required=True)
    parser.add_argument("--declared-mime", dest="declared_mime", default="")
    args = parser.parse_args(argv)

    try:
        data = _read_stdin_capped()
        if args.job == "extract":
            result = _run_extract(args.fmt, data)
        else:
            # Re-render (REDACT/PSEUDONYMIZE) runs in THIS same jail (F6) — the
            # _render_* bodies land next slice. Until then: contained.
            raise _Contained(
                f"re-render job '{args.job}' not yet implemented (next slice)"
            )
        _emit(result)
        return 0
    except _Contained as exc:
        # Clean containment: a guard/limit caught it. ok=False, exit 0 — the
        # runner BLOCKs but records this as "contained", not "worker crashed".
        _emit({"ok": False, "reason": str(exc)})
        return 0
    except Exception as exc:  # pragma: no cover - any unexpected parser death
        # A parser crash. Write nothing parseable as a result; exit non-zero so
        # the runner fails closed to BLOCK (do NOT emit ok=true on a crash).
        sys.stderr.write(f"worker crashed: {exc!r}\n")
        return 70  # EX_SOFTWARE


if __name__ == "__main__":
    sys.exit(main())
