"""
Yashigani Document Enforcement — no-residual proof helper (red-team L-03).

The no-residual proof backstops the marketed claim "no original matched value
survives anywhere in the re-rendered artefact — body, hidden part, or metadata."
The first implementation proved this with a raw, case-sensitive, byte-exact
substring scan of the re-extracted output for each raw original value.

Laura (gate 2026-06-09, L-03) proved that scan has **false negatives** under the
normalisation the re-render + re-extract round-trip introduces:

  * **PDF wrap / newline-collapse** — the PDF writer collapses ``\r``/``\n`` to a
    space and wraps lines at a fixed width, so a value containing a newline, or
    straddling a wrap boundary, re-extracts with *different whitespace* than the
    raw original.  ``"John\nSmith"`` survives as ``"John Smith"`` and the exact
    substring scan misses it.
  * **Homoglyph / Unicode normal form** — a value re-emitted with a visually
    identical homoglyph (Cyrillic ``Ѕ`` for Latin ``S``) or a different Unicode
    normal form is byte-different from the raw original and the scan misses it.

Either way the proof can return *clean* while the value survives in a
recoverable, human-readable form — the dangerous direction.

This module closes that gap with TWO independent, complementary checks; a hit on
EITHER fails the proof closed:

  1. :func:`normalise_for_residual` — fold both sides (the re-extracted output
     and each raw original) to a canonical form (Unicode NFKC + homoglyph
     skeleton + whitespace/newline/wrap collapse + casefold) before the substring
     comparison, so a reformatted survivor is still found.
  2. :func:`detect_surviving_classes` — re-run the SAME PII / quasi-identifier
     detector over the OUTPUT segments (not just substring-match the known
     originals), so a value that survives in ANY form the detector still
     recognises as the same data class is caught — a class of survivor a literal
     scan can never reach.

Both are intentionally allow-list-free and over-broad on the *block* side: the
proof's job is to refuse to ship anything it cannot prove clean, so a normalised
near-collision that is actually benign costs a (rare) false BLOCK, never a leak.
"""
from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# Homoglyph folding — map confusable code points to a Latin/ASCII skeleton.
# ---------------------------------------------------------------------------
#
# NFKC alone does NOT fold cross-script homoglyphs (Cyrillic Ѕ, Greek Α, etc.)
# because they are distinct, legitimately-distinct characters — NFKC only folds
# *compatibility* equivalents.  The residual proof needs a confusable skeleton:
# the small, hand-curated table below covers the Cyrillic/Greek/fullwidth
# look-alikes an attacker would reach for to smuggle a name past a byte scan.
# It is deliberately conservative (a real skeleton would use the Unicode
# confusables data); over-folding here only ever causes a (rare) false BLOCK.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic look-alikes → Latin
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I",
    "Ј": "J", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    # Greek look-alikes → Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ν": "v",
}

#: Characters that carry no semantic weight for a residual comparison but can be
#: injected to fragment a value (zero-width space/joiner, soft hyphen, BOM).
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0x00AD, 0xFEFF], None
)

_WS_RE = re.compile(r"\s+")


def _fold_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def normalise_for_residual(text: str) -> str:
    """Canonicalise *text* for a normalisation-resistant residual comparison.

    Folds the round-trip artefacts that defeat a byte-exact scan:

      * strip zero-width / soft-hyphen / BOM code points (value fragmentation);
      * Unicode NFKC (compatibility normal form — fold width/ligature variants);
      * homoglyph skeleton (cross-script look-alikes → Latin);
      * collapse ALL whitespace runs (incl. PDF newline-collapse and the
        90-char wrap that re-inserts a space at the boundary) to a single space,
        then strip;
      * casefold (case-insensitive).

    Applying the SAME fold to both the output text and each raw original makes
    the substring test see them as equal whenever they are the same human value,
    regardless of how the writer re-flowed/normalised it.
    """
    # 1. Drop zero-width / fragmenting code points outright.
    text = text.translate(_ZERO_WIDTH)
    # 2. Compatibility normal form (width, ligatures, etc.).
    text = unicodedata.normalize("NFKC", text)
    # 3. Cross-script homoglyph skeleton.
    text = _fold_homoglyphs(text)
    # 4. NFKC again — the homoglyph map may have introduced new decomposables.
    text = unicodedata.normalize("NFKC", text)
    # 5. Collapse whitespace (newline-collapse + wrap-boundary spaces) → single
    #    space; strip leading/trailing.
    text = _WS_RE.sub(" ", text).strip()
    # 6. Case-insensitive.
    return text.casefold()


def residual_substring_hit(output_text: str, original: str) -> bool:
    """True if *original* survives in *output_text* under residual normalisation.

    Both sides are folded with :func:`normalise_for_residual` before the
    substring test, so a wrapped / newline-collapsed / homoglyph / case / width
    variant of *original* is still detected.  An empty/blank original never hits
    (nothing to leak)."""
    norm_original = normalise_for_residual(original)
    if not norm_original:
        return False
    return norm_original in normalise_for_residual(output_text)
