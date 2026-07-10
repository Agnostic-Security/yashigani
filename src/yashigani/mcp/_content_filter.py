"""
MCP Broker — v1 prompt-injection content filter (M4).

Implements the Phase-2 M4 SHIP-BLOCKER finding:

  When the broker fetches a tool catalogue (tools/list) or a prompt
  (prompts/get), each tool description / prompt text is run through this
  filter BEFORE it can reach the downstream agent.

Filter pipeline (per description/prompt text):
  1. NFKC-normalise the input (collapses ligatures, fullwidth chars used to
     evade byte-level pattern matching).
  2. Strip Unicode category Cf (format) characters — zero-width chars, bidi
     overrides, soft-hyphens, etc. — that survive NFKC yet break \b anchors.
     Defeats ZWSP/ZWJ/ZWNJ/RLM/RLO insertion attacks (LAURA-V250-M4-001).
  3. Homoglyph-normalise: map common Cyrillic/Greek look-alikes for the
     targeted keywords to their ASCII equivalents so "SYSTеM" (Cyrillic е)
     and similar substitutions are caught.
  4. Leet-digit normalise (detection variant only): map unambiguous digit
     substitutions (0→o, 1→i, 3→e, 4→a, 5→s, 7→t) so "syst3m"→"system"
     and "ov3rride"→"override" are caught.  Applied ONLY to the internal
     detection text — the clean safe_text returned to the caller is
     unaffected (FIX-M4-003 / LAURA-V250-M4-003).
  5. 2048-char hard cap — reject anything over the cap (large blobs have no
     legitimate place in a tool description).
  6. Control-char scan — reject any text containing ASCII control characters
     outside the normal printable/whitespace range (0x00-0x1F except 0x09/
     0x0A/0x0D, and 0x7F).  These are not valid prose.
  7. Pattern scan — case-insensitive search for prompt-injection markers.
     Applied to BOTH the Cf-stripped+homoglyph+leet-normalised text AND a
     "separator-collapsed" variant (spaces/hyphens/underscores between
     individual letters stripped) to catch S-Y-S-T-E-M / o_v_e_r_r_i_d_e.
     On match: the text is REJECTED (FilterResult.rejected=True) and a
     sanitised replacement is substituted ("") before being offered to the
     caller.  The caller decides whether to drop the tool/prompt entirely
     or pass the replacement.

Per-tenant catalogue isolation:
  ToolCatalogueStore holds catalogues keyed by (tenant_id, server_id).
  Catalogues are NEVER shared across tenants.

Audit:
  Callers MUST emit McpToolDescriptionFetchedEvent after every fetch; see
  broker.py fetch_and_filter_tools() / fetch_and_filter_prompt() for
  integration.

TODO [M4-v2]: replace heuristic pattern set with an LLM-classifier sidecar
              (off-by-default, operator-opt-in, rate-limited).  The v1
              heuristic approach is conservative by design — it rejects
              injections that match common patterns and caps description size;
              it does NOT catch all semantic injection variants.
              FIND-3.0-LLM-B64: a bounded base64 decode pre-pass (step 7c)
              is now wired into filter_description so naively-encoded payloads
              are caught by the same heuristic patterns.  Deeper semantic
              coverage (multi-encoding chains, hex, rot13, URL-encode) remains
              in scope for the LLM-classifier sidecar (v2 / YSG-RISK-057).

v2.25.0 / P1 Phase-2 / M4 / YSG-RISK-054 (tool-description audit) /
  LAURA-MCP-005 (injection vector in tool descriptions) /
  FIX-M4-001 (LAURA-V250-M4-001 Cf-strip + homoglyph + separator-collapse) /
  FIX-M4-002 (LAURA-V250-M4-002 you-are false-positive narrowing) /
  FIX-M4-003 (LAURA-V250-M4-003 leet-digit bypass — 0→o 1→i 3→e 4→a 5→s 7→t).
"""
from __future__ import annotations

import base64
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

_MAX_DESCRIPTION_CHARS: int = 2048
_REPLACEMENT_TEXT: str = ""   # substituted for a rejected description

# ---------------------------------------------------------------------------
# FIX-M4-001: Unicode format-character stripping (LAURA-V250-M4-001)
#
# Unicode category "Cf" (Format) characters survive NFKC normalisation and
# interrupt Python's \b word-boundary matching.  Zero-width spaces, joiners,
# bidi overrides, and soft-hyphens are all Cf category.  An attacker inserts
# them between keyword letters (e.g. "SY​STEM") to defeat pattern checks.
#
# Strategy: strip every character whose Unicode category starts with "Cf"
# AFTER NFKC normalisation.  This is more future-proof than an enumerated
# list — any new format character added to Unicode is automatically stripped.
# ---------------------------------------------------------------------------

def _strip_cf_chars(text: str) -> str:
    """Remove all Unicode category Cf (format) characters from *text*."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


# ---------------------------------------------------------------------------
# FIX-M4-001: Homoglyph normalisation table
#
# Map common Cyrillic and Greek look-alikes for the targeted injection keywords
# to their ASCII equivalents.  This covers the most common substitutions used
# in adversarial prompts; it is not a complete homoglyph database.
#
# Keywords targeted: SYSTEM, OVERRIDE, JAILBREAK, ignore, act as, DAN.
# Characters covered: Cyrillic а/е/о/с/р/і, Greek ο/ι.
# ---------------------------------------------------------------------------

_HOMOGLYPH_TABLE: dict[int, int] = {
    ord("а"): ord("a"),   # Cyrillic а → Latin a
    ord("е"): ord("e"),   # Cyrillic е → Latin e
    ord("о"): ord("o"),   # Cyrillic о → Latin o
    ord("с"): ord("c"),   # Cyrillic с → Latin c
    ord("р"): ord("p"),   # Cyrillic р → Latin p
    ord("і"): ord("i"),   # Cyrillic і → Latin i
    ord("ο"): ord("o"),   # Greek ο → Latin o
    ord("ι"): ord("i"),   # Greek ι → Latin i
    ord("Α"): ord("A"),   # Greek capital Alpha → A
    ord("Ε"): ord("E"),   # Greek capital Epsilon → E
    ord("Ο"): ord("O"),   # Greek capital Omicron → O
    ord("І"): ord("I"),   # Cyrillic capital І → I
}


def _homoglyph_normalise(text: str) -> str:
    """Map common Cyrillic/Greek homoglyphs to their ASCII equivalents."""
    return text.translate(_HOMOGLYPH_TABLE)


# ---------------------------------------------------------------------------
# FIX-M4-003: Leet-digit normalisation (LAURA-V250-M4-003)
#
# Digit substitutions are a common bypass technique: "syst3m" → "system",
# "ov3rride" → "override".  This normalisation is applied ONLY to the
# internal detection text — the caller's safe_text is the NFKC-normalised
# original and is NOT de-leeted.
#
# Conservative map — only unambiguous substitutions whose character is
# exclusively used as a letter stand-in in adversarial prompts:
#   3 → e   (the only digit used this way in the target keywords)
#   0 → o   (used in "0verride", "pr0mpt")
#   1 → i   (used in "1gnore", "1nstruction")
#   4 → a   (used in "4ct as", "j4ilbreak")
#   5 → s   (used in "5ystem")
#   7 → t   (used in "sys7em", "instruc7ion")
#
# Ambiguous digits (2, 6, 8, 9) are intentionally excluded — they do not
# appear unambiguously in the target keyword set and would risk false
# positives on numeric descriptions (e.g. "HTTP/2", "retry 6 times").
#
# False-positive guard: the de-leeted form is only dangerous if it matches
# a keyword.  Purely numeric strings such as "retry up to 5 times" de-leet
# to "retry up to s times" — "s" alone never matches a \b-anchored keyword.
# ---------------------------------------------------------------------------

_LEET_TABLE: dict[int, int] = {
    ord("0"): ord("o"),
    ord("1"): ord("i"),
    ord("3"): ord("e"),
    ord("4"): ord("a"),
    ord("5"): ord("s"),
    ord("7"): ord("t"),
}


def _leet_normalise(text: str) -> str:
    """
    Replace unambiguous leet digit substitutions with their ASCII letter
    equivalents for keyword-detection purposes.

    IMPORTANT: Only call this on the internal detection variant — NEVER on
    the text that is returned to the caller (safe_text must be unmodified).
    """
    return text.translate(_LEET_TABLE)


# ---------------------------------------------------------------------------
# FIX-M4-001: Separator-collapse for keyword evasion via interspersed chars
#
# Attackers insert single spaces, hyphens, or underscores between every letter
# of a keyword to break word-boundary matching:
#   S-Y-S-T-E-M   o_v_e_r_r_i_d_e   i g n o r e
#
# Strategy: build a "collapsed" variant by removing single-char separators
# (space, hyphen, underscore, period, slash) when they appear between two
# single non-separator characters.  This variant is checked IN ADDITION TO
# (not instead of) the normal text — so legitimate hyphenated compound words
# in clean descriptions are never at risk.
#
# The regex matches a run of the pattern: LETTER sep LETTER sep LETTER ...
# and collapses the separators out.
# ---------------------------------------------------------------------------

# Matches a sequence of: single-char word-char, optional repeated (sep + single-word-char)
# e.g. "S-Y-S-T-E-M", "o_v_e_r_r_i_d_e", "i g n o r e"
_SEP_SPLIT_PATTERN = re.compile(
    r"(?<!\w)(\w(?:[\s\-_.\/]\w)+)(?!\w)"
)


def _collapse_separators(text: str) -> str:
    """
    Remove separators between individually-spaced letters.

    "S-Y-S-T-E-M" → "SYSTEM"; "o_v_e_r_r_i_d_e" → "override"
    Only affects runs where EVERY token is a single character separated by
    a single separator character — standard words are not collapsed.
    """
    def _collapse_match(m: re.Match) -> str:
        # Strip all whitespace/hyphens/underscores/dots/slashes from the match
        return re.sub(r"[\s\-_.\/]", "", m.group(0))

    return _SEP_SPLIT_PATTERN.sub(_collapse_match, text)


# ---------------------------------------------------------------------------
# FIND-3.0-LLM-B64 — bounded base64 decode pre-pass
#
# Robustness improvement: a base64-encoded injection payload is invisible to
# the raw-text heuristic scan.  A single decode step exposes the plaintext
# so the existing injection patterns catch it.
#
# Design constraints (pragmatic, NOT full semantic coverage — that lives in
# the LLM-sidecar v2 path per YSG-RISK-057):
#  • Decode depth = 1.  We do NOT recurse (no "base64 of base64 of base64…").
#    An attacker can still nest, but each additional layer costs them
#    significantly and the sidecar handles deeper obfuscation.
#  • Size cap: decode only when the blob is ≤ _B64_MAX_BYTES after decoding.
#    Prevents DoS via a huge base64 blob that would be decoded and re-scanned.
#  • Require the decoded bytes to be valid UTF-8 with a plausible ratio of
#    printable characters — this cuts out binary/compressed blobs that are
#    noise, not injection attempts.
#  • Malformed base64 → silently skip (never crash the filter path).
#  • The pre-pass runs AFTER the main scan (step 7) — only if the raw text
#    passed clean.  This keeps the hot path fast (the common case is clean).
#
# This is a LOW/robustness addition. It does not replace the sidecar.
# ---------------------------------------------------------------------------

# Minimum blob length that might be a meaningful base64 payload.
# Short base64 (<= 20 chars) is common in tool IDs and is not worth decoding.
_B64_MIN_ENCODED_CHARS: int = 20
# Maximum decoded byte length we will accept and re-scan.
_B64_MAX_BYTES: int = 512
# Minimum fraction of printable ASCII in the decoded text to treat it as text.
_B64_MIN_PRINTABLE_RATIO: float = 0.80

# Matches a contiguous base64 blob: standard or URL-safe alphabet + optional
# padding.  At least _B64_MIN_ENCODED_CHARS characters long.
_B64_BLOB_RE = re.compile(
    r"(?:[A-Za-z0-9+/\-_]{" + str(_B64_MIN_ENCODED_CHARS) + r",}={0,2})"
)


def _try_decode_b64_blob(blob: str) -> str | None:
    """
    Attempt to base64-decode *blob* (standard or URL-safe).

    Returns the decoded UTF-8 string if the result is plausible text (mostly
    printable ASCII, within size bounds), otherwise returns None.

    Never raises — malformed input silently returns None.
    """
    try:
        # Accept both standard and URL-safe alphabets; add padding if missing.
        b = blob.replace("-", "+").replace("_", "/")
        # Pad to a multiple of 4
        padding = (4 - len(b) % 4) % 4
        decoded_bytes = base64.b64decode(b + "=" * padding)
    except Exception:
        return None

    if len(decoded_bytes) > _B64_MAX_BYTES:
        return None

    try:
        decoded_str = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    # Require a minimum ratio of printable characters.
    if not decoded_str:
        return None
    printable = sum(1 for c in decoded_str if c.isprintable() or c in "\t\n\r")
    if printable / len(decoded_str) < _B64_MIN_PRINTABLE_RATIO:
        return None

    return decoded_str


# ---------------------------------------------------------------------------
# Pattern set — v1 heuristic
#
# Design notes:
#   • Applied AFTER NFKC normalisation, Cf-stripping, and homoglyph mapping.
#   • Also applied to separator-collapsed variant (FIX-M4-001).
#   • Case-insensitive (re.IGNORECASE).
#   • \b word-boundary anchors avoid false-positives on mid-word occurrences
#     (e.g. "systematic" must not match "system").
#   • The OR list is ordered longest-first where alternatives overlap so that
#     the more-specific variant is tried first; no correctness dependency.
#   • FIX-M4-002 (LAURA-V250-M4-002): the broad \byou\s+are\s+\S+ pattern is
#     replaced with injection-SPECIFIC role phrases so legitimate tool
#     descriptions containing "you are given..." / "you are able to..." pass
#     cleanly.
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    # Direct override instructions
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier|the\s+above)\b",
    r"\bforget\b.{0,30}?\b(?:instructions?|context|rules?|guidelines?)\b",
    # Role/identity injection — FIX-M4-002: precise role phrases only, not
    # the broad "you are <anything>" that fires on legitimate descriptions.
    r"\byou\s+are\s+now\b",              # "you are now [role]" — injection signal
    r"\bact\s+as\s+(?:an?\s+)?\S+",
    r"\bpretend\s+to\s+be\b",
    r"\bpretend\s+you\s+are\b",
    r"\bbehave\s+as\s+(?:an?\s+)?\S+",
    r"\brole[\s-]?play\b",
    r"\bignore[s]?\s+(?:your\s+)?instructions?\b",
    r"\bignore[s]?\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:safety\s+)?(?:rules?|guidelines?|constraints?|restrictions?)\b",
    r"\bDAN\b",                          # "DAN mode" / "act as DAN" / standalone "DAN"
    r"\bjailbreak\b",
    # System/context manipulation markers
    r"\bSYSTEM\b",
    r"\b(?:NEW\s+)?SYSTEM\s+PROMPT\b",
    r"\bSYSTEM_PROMPT\b",
    r"\bINSTRUCTION[S]?\b",
    r"\bOVERRIDE\b",
    # Prompt-structure injection (attempts to inject fake turn boundaries)
    r"\bassistant\s*:",
    r"\buser\s*:",
    r"\bhuman\s*:",
    r"<\s*/?(?:system|assistant|user|human|im_start|im_end)\s*>",
    r"\[INST\]",
    r"\[/INST\]",
    # Confidentiality / leak instructions
    r"\breveal\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context|secrets?)\b",
    r"\brepeat\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bprint\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bshow\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bexfiltrat",
    # Separator / injection attempt signals
    r"---\s*SYSTEM\s*---",
    r"###\s*(?:SYSTEM|INSTRUCTION)",
    r"<\?xml",
    r"<\!DOCTYPE",
]

_COMPILED_PATTERN = re.compile(
    "|".join(f"(?:{p})" for p in _INJECTION_PATTERNS),
    re.IGNORECASE | re.DOTALL,
)

# Control characters outside normal whitespace (tab=0x09, LF=0x0A, CR=0x0D)
_CONTROL_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)


# ---------------------------------------------------------------------------
# FilterResult
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """
    Result of filtering a single tool description or prompt text.

    Attributes
    ----------
    original_length:
        Character length of the input BEFORE NFKC normalisation.
    normalised_length:
        Character length AFTER NFKC normalisation.
    rejected:
        True when the filter rejected the text (pattern match, over-cap,
        or control-char hit).  The caller should use ``safe_text`` instead.
    reject_reason:
        Human-readable rejection reason; empty string when not rejected.
    safe_text:
        The text to use downstream.  When not rejected, this is the
        NFKC-normalised input (identical semantics, normalised encoding).
        When rejected, this is ``_REPLACEMENT_TEXT`` ("").
    matched_pattern:
        The first pattern that matched (for audit logging only).
        Never sent to the downstream agent.
    """

    original_length: int
    normalised_length: int
    rejected: bool
    reject_reason: str
    safe_text: str
    matched_pattern: Optional[str] = None
    # v2.26 / YSG-RISK-057 — populated only when the semantic-intent sidecar
    # ran and contributed to the verdict.  None when the sidecar was OFF or not
    # supplied (v1 heuristic-only behaviour is byte-identical to before).
    semantic_intent_score: Optional[float] = None
    semantic_intent_view: Optional[str] = None
    # MASKED encoded token (pii.decode._mask_token: first4…last4 + length) of the
    # decoded view that drove the verdict — audit-safe, never raw content.
    semantic_intent_segment: Optional[str] = None


def filter_description(text: str) -> FilterResult:
    """
    Run the M4 content filter on a single tool description or prompt text.

    Returns a FilterResult.  The caller is responsible for emitting the
    audit event (McpToolDescriptionFetchedEvent) — see broker.py.

    Thread-safe (stateless function; uses pre-compiled regex).

    Pipeline:
      1. NFKC normalise.
      2. Strip Unicode Cf (format) chars — defeats ZWSP/ZWJ/bidi bypass.
      3. Homoglyph-normalise (Cyrillic/Greek → ASCII for targeted keywords).
      4. Leet-digit normalise (detection variant only — safe_text unaffected).
      5. 2048-char cap (applied after normalisation).
      6. Control-char scan.
      7. Pattern scan on detection text AND on separator-collapsed variant.
      7c. FIND-3.0-LLM-B64 — bounded base64 decode pre-pass: extract
          plausible base64 blobs from the clean text, decode each once (no
          recursion), and run the injection patterns over the decoded text.
          Malformed blobs are silently skipped.  Depth-1 only; deeper
          obfuscation chains remain in scope for the LLM-sidecar (v2 /
          YSG-RISK-057).
    """
    original_length = len(text)

    # Step 1: NFKC normalise
    normalised = unicodedata.normalize("NFKC", text)

    # Step 2: strip Unicode Cf format characters (FIX-M4-001)
    # This defeats ZWSP/ZWJ/ZWNJ/RLM/RLO insertions that survive NFKC and
    # break \b anchors in the pattern scanner.
    prepared = _strip_cf_chars(normalised)

    # Step 3: homoglyph normalise (FIX-M4-001)
    # Maps Cyrillic/Greek look-alikes to ASCII for the targeted keywords.
    prepared = _homoglyph_normalise(prepared)

    normalised_length = len(prepared)

    # Step 4: leet-digit normalise — detection variant only (FIX-M4-003)
    # "syst3m" → "system", "ov3rride" → "override" for keyword matching.
    # 'detection' is the text used for all pattern scans; 'prepared' (without
    # de-leet) is kept intact so safe_text is never digit-mangled.
    detection = _leet_normalise(prepared)

    # Step 5: 2048-char cap (applied AFTER normalisation + Cf-strip)
    if normalised_length > _MAX_DESCRIPTION_CHARS:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason=f"over_char_cap:{normalised_length}>{_MAX_DESCRIPTION_CHARS}",
            safe_text=_REPLACEMENT_TEXT,
        )

    # Step 6: control-char scan (on prepared — control chars unchanged by de-leet)
    ctrl_match = _CONTROL_CHAR_PATTERN.search(prepared)
    if ctrl_match:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason=f"control_char:0x{ord(ctrl_match.group()):02X}",
            safe_text=_REPLACEMENT_TEXT,
        )

    # Step 7a: injection pattern scan on detection text (FIX-M4-001 + FIX-M4-003)
    # 'detection' = prepared + leet-normalised; catches homoglyphs, Cf-splits,
    # AND leet digit substitutions (syst3m → system, ov3rride → override).
    pattern_match = _COMPILED_PATTERN.search(detection)
    if pattern_match:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason="injection_pattern",
            safe_text=_REPLACEMENT_TEXT,
            matched_pattern=pattern_match.group()[:64],  # truncated for audit only
        )

    # Step 7b: injection pattern scan on separator-collapsed variant (FIX-M4-001)
    # Apply separator-collapse to the detection text (already leet-normalised)
    # so "s-y-s-t-3-m" → collapse → "syst3m" → already de-leeted → "system".
    collapsed = _collapse_separators(detection)
    if collapsed != detection:
        collapsed_match = _COMPILED_PATTERN.search(collapsed)
        if collapsed_match:
            return FilterResult(
                original_length=original_length,
                normalised_length=normalised_length,
                rejected=True,
                reject_reason="injection_pattern:separator_split",
                safe_text=_REPLACEMENT_TEXT,
                matched_pattern=collapsed_match.group()[:64],
            )

    # Step 7c: FIND-3.0-LLM-B64 — bounded base64 decode pre-pass.
    # Only runs when the raw heuristic (steps 7a+7b) passed clean.  Extracts
    # plausible base64 blobs, decodes each once (depth-1, bounded size), and
    # re-runs the injection patterns over the decoded text.  Fail-safe: any
    # exception or malformed blob is silently skipped (never crashes the
    # filter path).  This is a LOW/robustness addition — deeper obfuscation
    # (multi-layer, hex, rot13, URL-encode) remains in scope for the
    # LLM-sidecar v2 path (YSG-RISK-057).
    #
    # IMPORTANT: scan 'prepared' (pre-leet), NOT 'detection' (post-leet).
    # Leet normalisation corrupts base64 characters (e.g. '3' → 'e' inside
    # a b64 blob), making the blob undecodeable.  'prepared' has had only
    # Cf-strip and homoglyph normalisation applied — those do not affect the
    # base64 alphabet.
    for blob_match in _B64_BLOB_RE.finditer(prepared):
        decoded_str = _try_decode_b64_blob(blob_match.group())
        if decoded_str is None:
            continue
        # Apply the full normalisation pipeline to the decoded view so
        # homoglyphs/leet/Cf-chars INSIDE the encoded payload are also caught.
        decoded_det = _leet_normalise(_homoglyph_normalise(
            _strip_cf_chars(unicodedata.normalize("NFKC", decoded_str))
        ))
        b64_match = _COMPILED_PATTERN.search(decoded_det)
        if b64_match:
            return FilterResult(
                original_length=original_length,
                normalised_length=normalised_length,
                rejected=True,
                reject_reason="injection_pattern:b64_decoded",
                safe_text=_REPLACEMENT_TEXT,
                matched_pattern=b64_match.group()[:64],
            )

    # Clean — pass through the NFKC-normalised (but NOT Cf-stripped or
    # homoglyph-normalised) text so the downstream agent receives the
    # original semantics.  The Cf-stripped/normalised form is an internal
    # analysis artefact only.
    return FilterResult(
        original_length=original_length,
        normalised_length=normalised_length,
        rejected=False,
        reject_reason="",
        safe_text=normalised,
    )


# ---------------------------------------------------------------------------
# v2.26 / YSG-RISK-057 — content-filter v2: heuristic + semantic-intent sidecar
#
# Defence-in-depth composition.  The v1 heuristic (filter_description) is the
# fast, always-on stage.  filter_description_v2 runs it first, and ONLY if the
# heuristic passed AND a sidecar is supplied AND the feature flag is ON, it asks
# the semantic-intent sidecar for a second, encoding-aware opinion (the sidecar
# decodes base64/hex/url/rot13 before classifying — the YSG-RISK-057 residual).
#
# The sidecar can only ESCALATE (clean -> rejected), never downgrade a heuristic
# rejection.  When the sidecar is OFF / not supplied, behaviour is byte-identical
# to filter_description (the v1 path is untouched).
# ---------------------------------------------------------------------------


def filter_description_v2(
    text: str,
    sidecar=None,  # Optional[SemanticIntentSidecar]
) -> FilterResult:
    """
    Content-filter v2: v1 heuristic + optional semantic-intent sidecar.

    Stage 1 (always): the v1 heuristic ``filter_description``.  If it rejects,
    return immediately — no need to spend a GPU inference on already-blocked
    content.

    Stage 2 (flag-gated, defence-in-depth): if a ``sidecar`` is supplied and the
    feature flag is ON, evaluate the ORIGINAL text for semantic injection intent
    across decoded views.  An injection verdict ESCALATES a clean heuristic
    result to rejected (reject_reason="semantic_intent").  Fail-closed semantics
    live in the sidecar; here we simply honour ``verdict.is_injection``.

    The sidecar is hostile-input-aware (it quotes content as a literal) and
    fail-closed; see ``inspection.semantic_intent``.
    """
    base = filter_description(text)

    # Heuristic already rejected, or no sidecar wired — return v1 result as-is.
    if base.rejected or sidecar is None:
        return base

    try:
        verdict = sidecar.evaluate(text)
    except Exception as exc:  # sidecar must not break the filter path
        # A crashing sidecar (not just an unreachable backend — the sidecar
        # already fail-closes that internally) is a code fault.  Be honest in
        # the audit trail but do not weaken the heuristic verdict that passed.
        import logging
        logging.getLogger(__name__).error(
            "filter_description_v2: sidecar.evaluate raised %s — heuristic verdict stands",
            type(exc).__name__,
        )
        return base

    if verdict.skipped:
        # Flag OFF — v1 behaviour.
        return base

    # Masked encoded token of the view that drove the verdict (audit-safe).
    # ViewVerdict.segment is already masked by pii.decode._mask_token.
    flagged_segment = ""
    for vv in verdict.view_verdicts:
        if vv.view_name == verdict.flagged_view:
            flagged_segment = vv.segment or ""
            break

    # Annotate for audit regardless of disposition.
    base.semantic_intent_score = verdict.score
    base.semantic_intent_view = verdict.flagged_view
    base.semantic_intent_segment = flagged_segment

    if verdict.is_injection:
        return FilterResult(
            original_length=base.original_length,
            normalised_length=base.normalised_length,
            rejected=True,
            reject_reason="semantic_intent",
            safe_text=_REPLACEMENT_TEXT,
            matched_pattern=f"semantic_intent:{verdict.flagged_view}",
            semantic_intent_score=verdict.score,
            semantic_intent_view=verdict.flagged_view,
            semantic_intent_segment=flagged_segment,
        )
    return base


# ---------------------------------------------------------------------------
# Tool catalogue entry + per-tenant store
# ---------------------------------------------------------------------------


@dataclass
class ToolDescriptor:
    """
    A single tool entry from a tools/list response, after filtering.

    ``safe_description`` is the value that MUST be sent downstream.
    ``filter_result`` is retained for audit emission only — never forward it.
    """

    tool_name: str
    safe_description: str
    filter_result: FilterResult


@dataclass
class PromptDescriptor:
    """
    A single prompt entry from a prompts/get response, after filtering.
    """

    prompt_name: str
    safe_content: str
    filter_result: FilterResult


@dataclass
class TenantCatalogue:
    """
    Filtered tool + prompt catalogue for one (tenant_id, server_id) pair.

    Per-tenant isolation: never shared across tenant_ids.
    """

    tenant_id: str
    server_id: str
    tools: list[ToolDescriptor] = field(default_factory=list)
    prompts: list[PromptDescriptor] = field(default_factory=list)
    # 3.0 / YSG-RISK-060 — byte-surface-hash of the raw surface this catalogue
    # was built from (the capability-envelope change-detector).  Populated by
    # build_catalogue; "" when not computed.  Used by the invocation gate to
    # detect a surface that mutated between fetch and call.
    surface_set_hash: str = ""

    # Aggregate stats for audit emission
    @property
    def tool_count(self) -> int:
        return len(self.tools)

    @property
    def filtered_tool_count(self) -> int:
        """Tools whose description was NFKC-normalised (may or may not have been rejected)."""
        return sum(
            1 for t in self.tools
            if t.filter_result.normalised_length != t.filter_result.original_length
        )

    @property
    def rejected_tool_count(self) -> int:
        return sum(1 for t in self.tools if t.filter_result.rejected)

    @property
    def prompt_count(self) -> int:
        return len(self.prompts)

    @property
    def rejected_prompt_count(self) -> int:
        return sum(1 for p in self.prompts if p.filter_result.rejected)


class ToolCatalogueStore:
    """
    Per-tenant in-memory catalogue store.

    Keyed by (tenant_id, server_id).  Never shares entries across tenant_ids.

    Thread-safety: a single threading.Lock guards all mutations.  In
    production, callers update the catalogue on every tools/list fetch and
    read on every mcp.tools.call — reads and writes are fast (in-memory dict).

    Production note: in a multi-worker deployment, this in-memory store is
    per-process.  Each worker maintains its own independent catalogue.  This
    is acceptable for v1 — catalogue staleness across workers is bounded by
    the refresh interval and does not create a cross-tenant leak because keys
    include tenant_id.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, str], TenantCatalogue] = {}

    def store(self, catalogue: TenantCatalogue) -> None:
        """Replace the catalogue for (tenant_id, server_id)."""
        key = (catalogue.tenant_id, catalogue.server_id)
        with self._lock:
            self._store[key] = catalogue

    def get(self, tenant_id: str, server_id: str) -> Optional[TenantCatalogue]:
        """Retrieve the catalogue for (tenant_id, server_id), or None."""
        key = (tenant_id, server_id)
        with self._lock:
            return self._store.get(key)

    def evict(self, tenant_id: str, server_id: str) -> None:
        """Remove the catalogue for (tenant_id, server_id) if present."""
        key = (tenant_id, server_id)
        with self._lock:
            self._store.pop(key, None)

    def evict_tenant(self, tenant_id: str) -> int:
        """Remove all catalogues for a tenant; returns count removed."""
        with self._lock:
            to_remove = [k for k in self._store if k[0] == tenant_id]
            for k in to_remove:
                del self._store[k]
        return len(to_remove)

    def size(self) -> int:
        with self._lock:
            return len(self._store)


def build_catalogue(
    tenant_id: str,
    server_id: str,
    raw_tools: list[dict],
    raw_prompts: Optional[list[dict]] = None,
    sidecar=None,  # Optional[SemanticIntentSidecar]
) -> TenantCatalogue:
    """
    Build a TenantCatalogue from raw tools/list and optional prompts/list
    responses by running each description through the content filter.

    Filtering uses ``filter_description_v2`` so that — when a ``sidecar`` is
    supplied AND the YSG-RISK-057 feature flag is ON — each clean-heuristic
    description gets a second, encoding-aware look (decode-before-classify).
    When ``sidecar`` is None or the flag is OFF, behaviour is byte-identical to
    the v1 ``filter_description`` path.

    Parameters
    ----------
    tenant_id:
        Tenant the catalogue belongs to.
    server_id:
        Upstream MCP server identifier.
    raw_tools:
        List of tool dicts from the tools/list response.  Each dict is
        expected to have at least ``name`` (str) and ``description`` (str).
        Missing keys are tolerated — treated as empty string.
    raw_prompts:
        List of prompt dicts from prompts/list or prompts/get.  Expected
        keys: ``name`` (str) and ``description``/``content`` (str).
    sidecar:
        Optional semantic-intent sidecar (content-filter v2).  Escalate-only,
        flag-gated, fail-closed — see ``filter_description_v2``.
    """
    tools: list[ToolDescriptor] = []
    for raw in raw_tools:
        name = str(raw.get("name") or "")
        desc = str(raw.get("description") or "")
        result = filter_description_v2(desc, sidecar=sidecar)
        tools.append(ToolDescriptor(
            tool_name=name,
            safe_description=result.safe_text,
            filter_result=result,
        ))

    prompts: list[PromptDescriptor] = []
    for raw in (raw_prompts or []):
        name = str(raw.get("name") or "")
        # MCP prompts/get response uses "content" or "description"
        content = str(raw.get("content") or raw.get("description") or "")
        result = filter_description_v2(content, sidecar=sidecar)
        prompts.append(PromptDescriptor(
            prompt_name=name,
            safe_content=result.safe_text,
            filter_result=result,
        ))

    # 3.0 / YSG-RISK-060 — compute the byte-surface-hash change-detector over
    # the raw surface (lazy import to avoid a cycle at module load).
    try:
        from yashigani.mcp._envelope import surface_set_hash as _ssh
        _hash = _ssh(raw_tools, raw_prompts)
    except Exception:  # pragma: no cover — never let hashing break the filter
        _hash = ""

    return TenantCatalogue(
        tenant_id=tenant_id,
        server_id=server_id,
        tools=tools,
        prompts=prompts,
        surface_set_hash=_hash,
    )
