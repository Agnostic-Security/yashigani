"""
Yashigani Document Enforcement — decompression-bomb / zip-bomb / billion-laughs
guards (plan §6: "Zip / decompression bombs", "Deeply-nested OOXML /
billion-laughs", "Recursive containers").

These guards run **inside the sandbox** (the worker imports them) AND are unit-
testable in-process here, so a malicious document is *killed by the guard* before
it can OOM even the throwaway jail.  Belt-and-suspenders: the container cgroup
memory/pids caps (Captain's sandbox, sandbox.py) are the hard backstop; these
guards make the failure precise + fast and keep a bomb from spending the whole
job budget on decompression.

Fail-closed (plan §6.1, NON-NEGOTIABLE): any cap breach raises
:class:`DecompressionBombError` — the worker maps that to a non-zero exit and the
runner maps a non-zero exit to a BLOCK disposition.  We NEVER return a partial
decompression.

Caps (admin-overridable via the sandbox env, conservative defaults):
  - max **total decompressed** bytes across all entries
  - max **single-entry** decompressed bytes
  - max **compression ratio** (decompressed / compressed) — the zip-bomb signal
  - max **entry count** in an archive
  - max **nesting depth** (zip-in-zip / doc-in-doc)

This module is pure-Python and dependency-free so it can run in the most minimal
sandbox image (no parser libs needed to enforce the guard).
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass


class DecompressionBombError(Exception):
    """A document tripped a decompression / nesting / entry-count cap.

    Fail-closed: the caller (worker → runner → pipeline) maps this to BLOCK.
    The message names the specific cap so the audit reason is precise.
    """


@dataclass(frozen=True)
class BombGuardLimits:
    """Decompression-bomb guard caps (plan §6).

    Defaults are conservative for the committed OOXML formats: a real 50-page
    docx decompresses to a few MiB across tens of parts at a ratio well under
    100:1.  A zip bomb is ratio 1000:1+ or fans out to thousands of entries.
    """

    #: Hard ceiling on the SUM of decompressed bytes across every entry.
    max_total_decompressed_bytes: int = 200 * 1024 * 1024  # 200 MiB
    #: Hard ceiling on any SINGLE entry's decompressed size.
    max_entry_decompressed_bytes: int = 100 * 1024 * 1024  # 100 MiB
    #: Max decompressed/compressed ratio before we call it a bomb.  OOXML parts
    #: rarely exceed ~50:1; 1000:1 is unambiguously hostile.
    max_compression_ratio: float = 200.0
    #: Max number of entries (members) in one archive.
    max_entry_count: int = 4096
    #: Max nesting depth for recursive containers (doc-embeds-doc / zip-in-zip).
    #: Plan §6 example: 2.  Over depth → don't recurse, flag + fail-closed.
    max_nesting_depth: int = 2
    #: Chunk size for streamed decompression accounting.
    chunk_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_total_decompressed_bytes",
            "max_entry_decompressed_bytes",
            "max_entry_count",
            "chunk_bytes",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_compression_ratio <= 1.0:
            raise ValueError("max_compression_ratio must be > 1.0")
        if self.max_nesting_depth < 0:
            raise ValueError("max_nesting_depth must be >= 0")


def guard_zip_bytes(
    data: bytes,
    limits: BombGuardLimits | None = None,
    *,
    _depth: int = 0,
) -> int:
    """Stream-and-count a zip archive, aborting fail-closed on any cap breach.

    This enforces the §6 controls *before* a parser library ever sees a fully
    decompressed part:
      - entry-count cap (checked against the central directory, cheaply)
      - per-entry + total decompressed-size caps (streamed, never buffer-all)
      - compression-ratio cap (per entry — the canonical zip-bomb signal)
      - nesting-depth cap (recurse into entries that are themselves zips)

    Returns the total decompressed byte count when the archive is within every
    cap.  Raises :class:`DecompressionBombError` otherwise.

    NOTE: this validates the archive is *safe to decompress*; it does not parse
    OOXML semantics — that is the (separate, sandboxed) parser's job.  Running
    this guard first means the parser only ever sees a bounded amount of data.
    """
    limits = limits or BombGuardLimits()

    if _depth > limits.max_nesting_depth:
        raise DecompressionBombError(
            f"nesting depth {_depth} exceeds cap {limits.max_nesting_depth} "
            f"(recursive container / zip-in-zip) — fail-closed"
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        # Not a valid zip at this layer — that's the detection/parser's problem,
        # not a bomb.  Re-raise as a generic error so the caller fails closed.
        raise DecompressionBombError(f"not a valid zip container: {exc}") from exc

    infos = zf.infolist()
    if len(infos) > limits.max_entry_count:
        raise DecompressionBombError(
            f"archive has {len(infos)} entries (cap {limits.max_entry_count}) "
            f"— entry-count bomb, fail-closed"
        )

    total_decompressed = 0
    for info in infos:
        # Reject the classic "lie in the header" by streaming the actual bytes
        # rather than trusting info.file_size.  Cap the per-entry stream as we go.
        entry_decompressed = _stream_count_entry(zf, info, limits)
        total_decompressed += entry_decompressed
        if total_decompressed > limits.max_total_decompressed_bytes:
            raise DecompressionBombError(
                f"total decompressed {total_decompressed} bytes exceeds cap "
                f"{limits.max_total_decompressed_bytes} — fail-closed"
            )

        compressed = info.compress_size or 1
        ratio = entry_decompressed / compressed
        if ratio > limits.max_compression_ratio:
            raise DecompressionBombError(
                f"entry '{info.filename}' ratio {ratio:.1f}:1 exceeds cap "
                f"{limits.max_compression_ratio:.0f}:1 — zip bomb, fail-closed"
            )

        # Recurse into nested zips (zip-in-zip / doc-embeds-doc) within the
        # depth budget.  We only recurse on entries that *look like* a zip to
        # avoid reading every part twice.
        if entry_decompressed >= 4 and _entry_is_zip(zf, info):
            nested = zf.read(info)
            guard_zip_bytes(nested, limits, _depth=_depth + 1)

    return total_decompressed


def _stream_count_entry(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: BombGuardLimits,
) -> int:
    """Decompress one entry in chunks, counting bytes, aborting over the
    per-entry cap.  Never buffers the whole entry — a 100 GiB entry is detected
    after the first ``max_entry_decompressed_bytes`` are seen, not after it is
    fully materialised."""
    count = 0
    with zf.open(info, "r") as fh:
        while True:
            chunk = fh.read(limits.chunk_bytes)
            if not chunk:
                break
            count += len(chunk)
            if count > limits.max_entry_decompressed_bytes:
                raise DecompressionBombError(
                    f"entry '{info.filename}' decompressed past per-entry cap "
                    f"{limits.max_entry_decompressed_bytes} bytes — fail-closed"
                )
    return count


def _entry_is_zip(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    """Cheap peek: does this entry start with a zip local-file header?"""
    try:
        with zf.open(info, "r") as fh:
            head = fh.read(4)
        return head == b"PK\x03\x04"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hardened XML parser factory (plan §6: billion-laughs / XXE).
# ---------------------------------------------------------------------------

def harden_xml_parser():
    """Return an ``lxml`` parser configured to defeat XXE + entity-expansion
    (billion-laughs) on untrusted XML (plan §6 rows 2-3 / ASVS V14 / OWASP A05).

    Settings:
      - ``resolve_entities=False`` — no entity expansion (billion-laughs).
      - ``no_network=True``        — no network fetch of DTD/entities.
      - ``load_dtd=False`` + ``dtd_validation=False`` — no DTD loading at all.
      - ``huge_tree=False``        — keep libxml2's hard expansion limits on.

    Importing lxml is deferred so this module stays dependency-free for the
    bomb-guard-only path (the worker imports lxml only when it must parse XML).
    Raises ImportError if lxml is unavailable — the caller fails closed.
    """
    from lxml import etree  # type: ignore[import-untyped]

    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
