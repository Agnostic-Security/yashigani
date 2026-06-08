#!/usr/bin/env python3
"""
Yashigani sandboxed-extractor WORKER — runs INSIDE the per-job jail.

This is the in-sandbox entrypoint of the hardened extractor runtime (plan §6
B1). It is the process the Captain sandbox spawns; it is the SEAM Tom plugs the
real OOXML/PDF parsers and the REDACT/PSEUDONYMIZE re-render into (red-team F6 —
re-render runs in the SAME jail).

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

WHAT TOM ADDS (next slice): the bodies of ``_extract_docx`` / ``_extract_xlsx``
/ ``_extract_pptx`` / ``_extract_pdf`` and the ``_render_*`` re-render functions.
Each returns segments (extraction) or new bytes (re-render). Tom does NOT touch
the guard, the contract, or the container hardening.

The worker imports the guard from the installed ``yashigani.documents.bomb_guard``
(baked into the extractor image) so there is a single source of truth for the
caps — no copy-drift (Verification Protocol §4).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Hard cap on stdin so a giant pipe cannot exhaust the jail before the guard
# even runs. The cgroup mem-limit is the backstop; this is the fast precise stop.
_MAX_STDIN_BYTES = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_STDIN_BYTES", str(64 * 1024 * 1024)))

_SUPPORTED = {"docx", "xlsx", "pptx", "pdf"}


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


# ---------------------------------------------------------------------------
# Parser dispatch — THE SEAM FOR TOM.
# Each returns (segments: list[dict], extraction_complete: bool).
# A segment dict mirrors yashigani.documents.segment.Segment:
#   {"text": str, "kind": "BODY"|"TABLE_CELL"|"COMMENT"|..., "location": str,
#    "confidence": float, "needs_ocr": bool}
# Until Tom implements them, every committed untrusted-parser format is
# NOT-IMPLEMENTED → contained (ok=False) so the pipeline stays fail-closed.
# ---------------------------------------------------------------------------

def _extract_docx(data: bytes) -> tuple[list[dict], bool]:
    raise _Contained("docx extractor not yet implemented (Tom, next slice)")


def _extract_xlsx(data: bytes) -> tuple[list[dict], bool]:
    raise _Contained("xlsx extractor not yet implemented (Tom, next slice)")


def _extract_pptx(data: bytes) -> tuple[list[dict], bool]:
    raise _Contained("pptx extractor not yet implemented (Tom, next slice)")


def _extract_pdf(data: bytes) -> tuple[list[dict], bool]:
    raise _Contained("pdf extractor not yet implemented (Tom, next slice)")


_EXTRACTORS = {
    "docx": _extract_docx,
    "xlsx": _extract_xlsx,
    "pptx": _extract_pptx,
    "pdf": _extract_pdf,
}


def _run_extract(fmt: str, data: bytes) -> dict:
    if fmt not in _SUPPORTED:
        raise _Contained(f"unsupported format '{fmt}' — fail-closed")
    # Guard the container BEFORE parsing (OOXML is a zip; pdf is guarded by the
    # parser's own bounds + the cgroup — no zip layer to bomb-check).
    if fmt in ("docx", "xlsx", "pptx"):
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
            # Re-render (REDACT/PSEUDONYMIZE) runs in THIS same jail (F6) — Tom
            # adds the _render_* bodies next slice. Until then: contained.
            raise _Contained(
                f"re-render job '{args.job}' not yet implemented (Tom, next slice)"
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
