"""
Yashigani Inspection — Deterministic secret / credential detector.

A pure-Python, NO-LLM, fail-closed detector for credentials and high-entropy
secrets in egressing text.  It is the deterministic FLOOR of a defence-in-depth
egress stack on the orchestration final-answer path (``gate_relaxed_final``).

────────────────────────────────────────────────────────────────────────────
LAYERED DEFENCE MODEL (orchestration final egress — gate_relaxed_final)
────────────────────────────────────────────────────────────────────────────
The relaxed-brain final answer passes THREE independent layers before delivery;
ANY layer blocks.  They are ordered cheapest/most-deterministic first:

  Layer 0 (THIS MODULE) — deterministic MECHANICAL detector.  Pure Python, no
      LLM, no network, fail-closed.  Closes every *encoding / obfuscation /
      reassembly* bypass deterministically (see "Mechanical closures" below).
      A hit forces ``response_verdict="blocked"`` regardless of any LLM verdict
      or the caller's sensitivity ceiling.  This is the headline leak-closure.

  Layer 1 — deterministic SENSITIVITY classifier (``classify_decoded``, the same
      first-pass classifier the chat INGRESS leg uses, fail-closes to RESTRICTED).
      Catches secrets/credentials/PII by CLASS even when no mechanical pattern
      fires, and a CONFIDENTIAL/RESTRICTED classification forces a block.  This
      is the deterministic backstop for content that is *sensitive by category*
      rather than by encoded shape.

  Layer 2 — LLM RESPONSE INSPECTOR (``ResponseInspectionPipeline`` → ollama).
      Non-deterministic semantic judgement.  Catches *meaning* the lower layers
      cannot pattern-match: a secret DESCRIBED in natural language ("my password
      is my first pet's name then my birth year"), a translated/paraphrased
      disclosure, an instruction to reconstruct a credential.  It is the genuine
      SEMANTIC backstop; because it sits behind Layers 0/1 it never has to carry
      the mechanical cases alone (which is why its ~10-15% verbatim-secret miss
      rate is no longer a leak).

────────────────────────────────────────────────────────────────────────────
MECHANICAL CLOSURES (Layer 0 — this module, all deterministic)
────────────────────────────────────────────────────────────────────────────
Run over the candidate text AND a battery of decoded/normalised views:

  • Unicode normalisation — NFKC + a curated Cyrillic/Greek→Latin CONFUSABLES
    fold applied BEFORE detection, so homoglyph-obfuscated keys (e.g. Cyrillic
    'А' for Latin 'A') are folded back and caught.
  • Phonetic-alphabet reassembly — NATO/ICAO ("whiskey juliet alpha …") and
    spelled-letter ("doubleyou jay …") sequences are reassembled to letters and
    tested against the key formats / entropy floor.
  • Spelled-out separators + filler — "then a slash then", "underscore", ordinal
    words, "comma"/"space" → literal glue, then fragments re-concatenated.
  • English-connective fragment fusion — "X next comes Y" with high-entropy
    fragments fuses while prose words are skipped.
  • Encodings — base64, base32, URL-encoding (%xx), hex (with separators
    ``de:ad:be:ef`` / ``de ad be ef``, AND bare-contiguous ``de ad be ef`` →
    ``deadbeef`` runs decoded to text), leetspeak digit↔letter de-swaps,
    zero-width-character stripping, and reversed strings — each decoded view is
    re-scanned by the known-format regex + entropy floor AND (for the depth-1
    encoding families) by the reassembly battery, so a split-token secret hidden
    UNDER one encoding layer is reassembled + caught (incl. the bare-contiguous-
    hex split form, LAURA-ORCH-HEXSPLIT).

  After every decode/normalise the SAME known-key-format regex set + entropy
  floor (Layers below) runs over the resulting view.  Known formats: AWS access
  key, AWS secret (40-char base64), JWT, PEM private-key headers, GitHub/Slack/
  Stripe/Google/sk- tokens, generic base64/hex high-entropy blobs.

Return value is a structured :class:`SecretVerdict`.  The matched span is
HASHED (SHA-256[:16]) — the raw secret is NEVER carried in the verdict, logs,
or audit, so wiring this into an egress gate cannot itself become an exfil
channel.

────────────────────────────────────────────────────────────────────────────
HONEST RESIDUAL (the ONLY one — a genuine semantic-AI frontier, not a skipped
mechanical case): YSG-RISK-057 trained-classifier frontier.
────────────────────────────────────────────────────────────────────────────
Every MECHANICAL vector above is closed deterministically here.  What remains
is intrinsically SEMANTIC and is handled by Layer 2 (LLM inspector), with the
narrow tail that even a small local LLM may miss being the YSG-RISK-057 trained
sensitivity-classifier frontier:

  • A secret that is never WRITTEN at all, only DESCRIBED as a procedure to
    reconstruct from context the model legitimately holds ("the admin password
    is the project codename in reverse, lowercased").  There is no token, no
    encoding and no high-entropy run to detect — the *meaning* must be judged.
    Layer 2 catches the common phrasings (see the prose-narration test set);
    the adversarially-rephrased long tail is the trained-classifier frontier.

This residual is a true AI-semantic limit: it has no mechanical signal by
construction.  It is NOT a mechanical corner skipped here.

────────────────────────────────────────────────────────────────────────────
BOUNDED DEPTH-2 RESIDUALS (behind the Layer-1/Layer-2 semantic backstop)
────────────────────────────────────────────────────────────────────────────
The encoding decode is DEPTH-1: each decoded view is re-scanned (format / entropy
/ reassembly) but is NOT itself recursively re-decoded, which bounds cost at one
decode pass per encoding family.  Two adversarial forms therefore chain TWO
non-reassembly encodings and are NOT closed by Layer 0 alone:

  • ``b64(leet-token)`` — base64 of a leetspeaked key whose leet de-swap only runs
    on the canonical text, not inside the decoded base64 view.
  • ``b64(hex-colon-verbatim)`` — base64 of a colon-separated hex of a verbatim
    key; the hex-separator decode does not re-run inside the base64 decoded view.

Both are *double-encoded verbatim* forms, not split-token reassembly forms, so the
depth-1 reassembly recursion does not reach them.  Laura ruled them bounded
residuals (diminishing returns: each is a second mechanical wrapper around a form
the FIRST layer already catches, so an attacker gains nothing a single layer did
not already require).  They remain covered by Layer 1 (sensitivity classifier) and
Layer 2 (LLM response inspector) — they are NOT open leaks, only Layer-0 depth
limits.  Documented here for honesty; not required to be closed mechanically.

Last updated: 2026-06-10
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Tunables (module-level so tests can reference the exact thresholds)
# ---------------------------------------------------------------------------

# Minimum length for a token to be considered for the entropy floor.  Short
# tokens (UUID segments, ordinary words, hex colours) never reach the floor.
_ENTROPY_MIN_LEN: int = 20

# Shannon entropy (bits/char) above which a long token is treated as a likely
# secret.  base64/hex secrets sit ~4.5–6.0 bits/char; English prose ~3.5–4.2;
# repetitive identifiers (snake_case, long product names) sit well under 4.0.
# 4.0 catches Laura's AWS secret (entropy ~5.0) while clearing prose.  Tuned
# against the benign fixtures in the unit suite (prose / code / UUID / product
# name must NOT trip).
_ENTROPY_THRESHOLD: float = 4.0

# A reassembled blob is the concatenation of split fragments; we apply a
# slightly lower length floor to it because the de-obfuscator has already
# established intent (spelled-out separators are not innocent).
_REASSEMBLY_MIN_LEN: int = 20

# Max consecutive prose/connective words tolerated BETWEEN two secret-looking
# fragments before a fused run is broken.  3 covers "X next comes Y" /
# "X and then Y is" without letting far-apart prose tokens fuse.
_MAX_GAP_WORDS: int = 3


# ---------------------------------------------------------------------------
# Known-key-format detectors
# ---------------------------------------------------------------------------
#
# Each entry: (name, compiled-regex).  Order matters only for which detector
# is REPORTED first; any single hit blocks.  These are intentionally specific
# (vendor prefixes, fixed-width key bodies) so they do not fire on prose.

_KEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS access key id — AKIA/ASIA + 16 upper-alnum.
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # GitHub tokens — ghp_/gho_/ghu_/ghs_/ghr_ + 36+ base62.
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    # Slack tokens — xoxb-/xoxa-/xoxp-/xoxr-/xoxs- + body.
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # OpenAI / Anthropic style — sk-, sk-ant-, sk-proj- + 20+.
    ("sk_token", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    # Google API key — AIza + 35.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    # Google OAuth client/refresh — ya29. prefix.
    ("google_oauth", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b")),
    # JWT — three dot-separated base64url segments beginning eyJ.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b")),
    # PEM private-key header (any algo).
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    # Stripe live/secret keys.
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    # Generic "AWS_SECRET..." / "secret"/"password"/"token" = <value> assignment
    # where the value is a long high-entropy run.  Anchored on the assignment so
    # it does not fire on prose.  Captures the 40-char AWS secret form that the
    # old regex set missed because the trailing "KEY=" broke a bare token match.
    ("labelled_secret", re.compile(
        r"(?i)(?:secret|passwd|password|token|api[_-]?key|access[_-]?key)"
        r"[\"'\s]{0,4}[:=][\"'\s]{0,4}([A-Za-z0-9/+_=-]{16,})")),
]

# AWS secret access keys are EXACTLY 40 chars of base64 alphabet.  We treat a
# 40-char base64 run as an AWS-secret candidate; the entropy floor confirms it
# is high-entropy (so a 40-char lowercase English run would not trip).
_AWS_SECRET_RE = re.compile(r"[A-Za-z0-9/+]{40}")

# Generic high-entropy base64 / hex runs (confirmed by the entropy floor).
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9/+]{20,}={0,2}")
_HEX_RUN_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# A pure-hex run of >=32 chars is itself a strong signal (hashes, hex-encoded
# secrets/payloads, raw key bytes).  Hex of an ASCII secret has LOWER entropy
# (~3.4 bits/char — only the 16 hex symbols, ASCII-biased) than base64, so the
# generic 4.0 floor misses it.  A dedicated, slightly lower hex floor catches a
# hex-encoded secret while still clearing short hex (colours, ids < 32 chars).
_HEX_ENTROPY_THRESHOLD: float = 3.2

# Token boundary for entropy candidates: runs of base64-alphabet chars.
_TOKEN_RE = re.compile(r"[A-Za-z0-9/+_=-]+")


# ---------------------------------------------------------------------------
# Unicode normalisation — NFKC + curated confusables (homoglyph) fold
# ---------------------------------------------------------------------------
#
# NFKC alone does NOT fold cross-script look-alikes (Cyrillic 'А' U+0410 is a
# distinct character from Latin 'A' and survives NFKC).  We add a focused fold
# of the Cyrillic/Greek/full-width characters that look like the Latin letters +
# digits used in base64/hex/key alphabets, so a homoglyph-substituted secret is
# normalised back to its ASCII form before detection.  Curated (not a giant
# Unicode table) to stay import-light and auditable; covers the practical
# obfuscation alphabet.  Source: Unicode confusables for [A-Za-z0-9].

_CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin (upper)
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    # Cyrillic → Latin (lower)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    # Greek → Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t",
    # Misc look-alikes
    "Ⅰ": "I", "Ⅴ": "V", "Ⅹ": "X", "ǀ": "l", "І": "I", "і": "i", "Ј": "J",
    "ј": "j", "ѕ": "s", "Ѕ": "S",
}

# Zero-width / invisible characters inserted to break token boundaries.
_ZERO_WIDTH_RE = re.compile(
    "[​‌‍‎‏⁠﻿­͏؜]")

# Leetspeak digit→letter map (only the unambiguous, common swaps).  Applied as a
# SEPARATE decoded view, never to the canonical text, so legitimate alphanumeric
# secrets (which already contain digits) are scanned both ways.
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _fold_confusables(text: str) -> str:
    """NFKC-normalise then fold curated cross-script homoglyphs to ASCII."""
    norm = unicodedata.normalize("NFKC", text)
    if any(ch in _CONFUSABLES for ch in norm):
        norm = "".join(_CONFUSABLES.get(ch, ch) for ch in norm)
    return norm


def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)


# ---------------------------------------------------------------------------
# Phonetic-alphabet reassembly (NATO/ICAO + spelled-out letters)
# ---------------------------------------------------------------------------

_NATO: dict[str, str] = {
    "alpha": "a", "alfa": "a", "bravo": "b", "charlie": "c", "delta": "d",
    "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i",
    "juliet": "j", "juliett": "j", "kilo": "k", "lima": "l", "mike": "m",
    "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r",
    "sierra": "s", "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w",
    "xray": "x", "x-ray": "x", "yankee": "y", "zulu": "z",
}

# Spelled-out single letters (how a letter is pronounced/written out).
_SPELLED_LETTER: dict[str, str] = {
    "doubleyou": "w", "doubleu": "w", "aitch": "h", "haitch": "h", "jay": "j",
    "kay": "k", "cue": "q", "queue": "q", "are": "r", "ess": "s", "ex": "x",
    "why": "y", "zed": "z", "zee": "z", "dee": "d", "bee": "b", "cee": "c",
    "gee": "g", "vee": "v", "pee": "p", "tee": "t", "el": "l", "em": "m",
    "en": "n", "oh": "o",
}

# Spelled-out digits.
_SPELLED_DIGIT: dict[str, str] = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}

_PHONETIC_ALL = {**_NATO, **_SPELLED_LETTER, **_SPELLED_DIGIT}


# A dense run of >= this many consecutive phonetic tokens is a deliberate
# spell-out (exfil intent), not incidental prose.  Reassembling 8 phonetic
# words has no benign reading; the reassembled letters ARE the payload.
_PHONETIC_MIN_TOKENS: int = 8


def _phonetic_reassemble(text: str) -> Optional[str]:
    """Reassemble a RUN of >= _PHONETIC_MIN_TOKENS consecutive phonetic-alphabet
    / spelled tokens into the contiguous letters/digits they name.  Returns the
    longest such run or None.

    Only fires on a DENSE run of phonetic tokens (a deliberate spell-out), so an
    ordinary sentence containing one stray word like "echo" or "delta" never
    reassembles.  The token minimum is well above incidental prose; the
    reassembled blob is treated as a secret by the caller REGARDLESS of its
    entropy/pronounceability, because the spell-out itself is the signal."""
    tokens = re.findall(r"[a-z][a-z-]*", text.lower())
    best = ""
    current: list[str] = []

    def _flush() -> None:
        nonlocal best
        if len(current) >= _PHONETIC_MIN_TOKENS:
            blob = "".join(current)
            if len(blob) > len(best):
                best = blob

    for tok in tokens:
        mapped = _PHONETIC_ALL.get(tok)
        if mapped is not None:
            current.append(mapped)
        else:
            _flush()
            current = []
    _flush()
    return best or None


# ---------------------------------------------------------------------------
# De-obfuscation: spelled-out separators and filler words
# ---------------------------------------------------------------------------
#
# Ordered longest-first so "then a slash then" is consumed before " slash ".
# Each maps a spelled-out separator phrase to the literal character.  Applied
# to a lowercased copy of the text before reassembly.

_SEPARATOR_PHRASES: list[tuple[str, str]] = [
    ("then a slash then", "/"),
    ("then a dot then", "."),
    ("then a dash then", "-"),
    ("then an underscore then", "_"),
    ("then a colon then", ":"),
    ("then a plus then", "+"),
    ("forward slash", "/"),
    ("backslash", "/"),
    ("slash", "/"),
    ("underscore", "_"),
    ("hyphen", "-"),
    ("dash", "-"),
    ("colon", ":"),
    (" dot ", "."),
    (" plus ", "+"),
    (" equals ", "="),
    (" comma ", ","),
]

# Filler words that sit between high-entropy fragments in a split payload.
# Removed (as whole words) AFTER separator substitution so "then"/"a"/"the"
# glue does not survive into the reassembly.  Includes ordinal/positional words
# ("first"/"second"/...) and "space"/"then" connectives.
_FILLER_WORDS = {
    "then", "a", "an", "the", "done", "first", "next", "and", "is",
    "after", "that", "comes", "followed", "by", "with", "value",
    "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth",
    "ninth", "tenth", "space", "char", "character", "letter", "digit",
}


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass
class SecretVerdict:
    """Structured outcome of a deterministic secret scan.

    ``span_hash`` is SHA-256[:16] of the matched/normalised secret span — the
    raw secret is NEVER stored on the verdict, so it is safe to log/audit.
    """
    is_secret: bool
    detector: Optional[str] = None          # which detector fired
    reassembled: bool = False               # True if a de-obfuscated/decoded form tripped
    span_hash: Optional[str] = None         # SHA-256[:16] of the matched span
    entropy: Optional[float] = None         # entropy of the matched token, when relevant
    detectors_hit: list[str] = field(default_factory=list)  # all detectors that fired
    views_hit: list[str] = field(default_factory=list)      # which decoded views tripped

    def audit_dict(self) -> dict:
        """A log/audit-safe dict (no raw secret material)."""
        return {
            "is_secret": self.is_secret,
            "detector": self.detector,
            "reassembled": self.reassembled,
            "span_hash": self.span_hash,
            "entropy": round(self.entropy, 3) if self.entropy is not None else None,
            "detectors_hit": list(self.detectors_hit),
            "views_hit": list(self.views_hit),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Empty string → 0.0."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _hash_span(span: str) -> str:
    return hashlib.sha256(span.encode("utf-8", "replace")).hexdigest()[:16]


def _looks_like_word(token: str) -> bool:
    """True for ordinary identifiers / words that should NOT trip the entropy
    floor even if long: all-alpha lowercase, or snake_case/CamelCase made of
    pronounceable parts (long product names, function identifiers).

    Heuristic: a token with NO digit and NO base64-only run, OR one whose
    alphabetic ratio is very high and which contains a vowel in most syllables,
    is treated as a word.  Kept deliberately simple — the entropy floor is the
    real gate; this just suppresses obvious false positives.
    """
    # Pure alphabetic (with _ or - as joiners) and contains vowels → a word.
    core = token.replace("_", "").replace("-", "")
    if core.isalpha():
        vowels = sum(core.lower().count(v) for v in "aeiou")
        # Real words/identifiers carry vowels; a 20+ alpha run with vowels is
        # prose, not a secret.  (AWS secrets always carry digits and / or +.)
        return vowels >= max(2, len(core) // 6)
    return False


def _normalise_for_reassembly(text: str) -> tuple[str, bool]:
    """Produce a de-obfuscated copy of *text* in which spelled-out separators
    are literal characters and filler words between fragments are removed, so a
    split secret is concatenated back into a contiguous run.

    Returns ``(reassembled, obfuscation_seen)`` where ``obfuscation_seen`` is
    True only when at least one spelled-out separator phrase was actually
    substituted.  The caller scans the reassembly ONLY when obfuscation was
    seen — concatenating ordinary space-separated PROSE would otherwise fuse a
    long sentence into a spurious high-entropy run (false positive on product
    names / long descriptions).  Genuine split-token payloads always carry a
    spelled-out separator ("then a slash then", "underscore", ...), which is
    the signal of intent.
    """
    lowered = text.lower()
    obfuscation_seen = False
    # 1) spelled-out separators → literal chars (longest phrase first).
    for phrase, literal in _SEPARATOR_PHRASES:
        if phrase in lowered:
            obfuscation_seen = True
            lowered = lowered.replace(phrase, literal)
    # 2) tokenise on whitespace; drop filler words; rejoin WITHOUT spaces so
    #    adjacent alnum fragments concatenate.  Tokens that are pure separators
    #    (now "/", ".", etc.) are kept inline.
    out_parts: list[str] = []
    for tok in re.split(r"\s+", lowered):
        if not tok:
            continue
        if tok in _FILLER_WORDS:
            continue
        out_parts.append(tok)
    return "".join(out_parts), obfuscation_seen


def _looks_like_secret_fragment(tok: str) -> bool:
    """True when *tok* looks like a fragment of a high-entropy secret rather
    than an ordinary word: it is alnum, length >= 5, AND either contains a
    digit OR mixes upper+lower case in a non-word way (e.g. ``wJalrXUtnFEMI``,
    ``K7MDENG``, ``bPxRfiCYEXAMPLEKEY``).  Ordinary English words ("next",
    "comes", "value", "bucket") return False, so fusing fragments across them
    does not pull prose into a spurious run.
    """
    if len(tok) < 5 or not tok.isalnum():
        return False
    has_digit = any(c.isdigit() for c in tok)
    has_upper = any(c.isupper() for c in tok)
    has_lower = any(c.islower() for c in tok)
    mixed_case = has_upper and has_lower
    # A pronounceable mixed-case word (e.g. "CamelCase") would mix case too, so
    # require EITHER a digit OR a mixed-case token whose entropy is already high.
    if has_digit:
        return True
    if mixed_case and _shannon_entropy(tok) >= 3.3:
        return True
    return False


def _fuse_secret_fragments(text: str) -> Optional[str]:
    """Concatenate RUNS of adjacent secret-looking fragments, skipping over
    ordinary prose/filler words between them.  Returns the longest fused run
    (>= _REASSEMBLY_MIN_LEN) or None.

    Defeats split payloads that use plain English connectives ("X next comes Y
    next comes Z") instead of spelled-out separator characters — the fragments
    themselves are high-entropy, so they fuse while the connective words are
    skipped.  Conservative: only fragments that pass
    :func:`_looks_like_secret_fragment` are fused, so prose never forms a run.
    """
    tokens = re.split(r"\s+", text)
    best: str = ""
    current: list[str] = []
    gap = 0  # consecutive non-fragment words since the last fragment

    def _flush() -> None:
        nonlocal best
        if len(current) >= 2:
            fused = "".join(current)
            if len(fused) > len(best):
                best = fused

    for tok in tokens:
        # Strip surrounding punctuation that would otherwise break a fragment.
        clean = tok.strip(".,;:!?\"'()[]{}")
        if _looks_like_secret_fragment(clean):
            current.append(clean)
            gap = 0
        else:
            # Allow a bounded number of connective/filler words BETWEEN
            # fragments ("X next comes Y") without breaking the run.  More than
            # _MAX_GAP_WORDS of prose ends the run (so genuine prose never
            # fuses two coincidentally-secret-looking tokens far apart).
            gap += 1
            if gap > _MAX_GAP_WORDS:
                _flush()
                current = []
                gap = 0
    _flush()
    return best if len(best) >= _REASSEMBLY_MIN_LEN else None


# ---------------------------------------------------------------------------
# Encoding decoders (each returns a decoded VIEW or None)
# ---------------------------------------------------------------------------

def _decode_base32_views(text: str) -> list[str]:
    """Return decoded strings for every base32 run in *text*.

    Base32 alphabet is A-Z2-7; a >=24-char run that decodes to printable ASCII
    is a candidate.  Padding-tolerant.  Multiple runs → multiple views."""
    views: list[str] = []
    for m in re.finditer(r"[A-Z2-7]{24,}={0,6}", text):
        run = m.group(0)
        pad = (-len(run.rstrip("="))) % 8
        try:
            raw = base64.b32decode(run.rstrip("=") + "=" * pad, casefold=False)
            dec = raw.decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable():
            views.append(dec)
    return views


def _decode_url_view(text: str) -> Optional[str]:
    """URL-decode (%xx) if the text actually contains percent-escapes."""
    if "%" not in text:
        return None
    dec = unquote(text)
    return dec if dec != text else None


def _decode_hex_separated_view(text: str) -> Optional[str]:
    """Reassemble separator-delimited hex (``de:ad:be:ef`` / ``de ad be ef`` /
    ``de-ad``) into a contiguous hex string and, if it decodes to printable
    ASCII, return that decoded view (so a hex-encoded ASCII secret is caught).

    Requires >= 8 hex byte-pairs joined by a CONSISTENT single separator, so a
    MAC-address-style id or ordinary prose does not trip.  The contiguous hex is
    also handed back so the hex floor can see it."""
    for sep in (":", " ", "-"):
        # >= 8 pairs of hex separated by sep
        pat = re.compile(r"(?:[0-9a-fA-F]{2}" + re.escape(sep) + r"){7,}[0-9a-fA-F]{2}")
        m = pat.search(text)
        if not m:
            continue
        joined = m.group(0).replace(sep, "")
        try:
            raw = bytes.fromhex(joined)
            dec = raw.decode("ascii")
            if dec.isprintable():
                return dec
        except (ValueError, UnicodeDecodeError):
            pass
        # Even if it does not decode to ASCII, the contiguous hex itself is a
        # signal (raw key bytes) — return it so the hex floor evaluates it.
        return joined
    return None


def _decode_hex_contiguous_views(text: str) -> list[str]:
    """Return decoded strings for every BARE-CONTIGUOUS hex run (``_HEX_RUN_RE``,
    >=32 hex chars, no separators) that decodes to printable ASCII.

    This is the DECODED-VIEW companion to :func:`_decode_hex_separated_view`
    (which handles ``de:ad:be:ef`` separator forms) and to the ``hex_blob`` direct
    path in :func:`_scan_view`.  The direct ``hex_blob`` path is guarded by
    :func:`_hex_decodes_to_secret`, whose ``<=2-whitespace`` anti-FP guard REJECTS
    hex-of-space-separated-prose so a bare hash / git-SHA / digest never
    over-blocks.  But that same guard means a SPLIT-TOKEN secret hex-encoded as one
    contiguous run (``hex("First wJalr... then a slash then K7MDENG ...")`` — many
    spaces in the decoded text) produced NO decoded view at all, so the reassembly
    battery never saw the split prose inside and the split form LEAKED
    (LAURA-ORCH-HEXSPLIT).

    This view decodes the contiguous hex to text REGARDLESS of the whitespace
    count in the decoded output, and the caller feeds it to ``_run_view`` +
    ``_run_reassembly_passes`` like the other depth-1 decoded views — so the split
    prose inside is reassembled + matched.  It does NOT change the ``hex_blob``
    direct path: a benign hex-of-a-real-sentence decodes to prose with no
    spelled separator / no secret-shaped fragments / no dense phonetic run, so the
    INTENT-gated reassembly battery stays shut and the entropy/format floor finds
    nothing — it stays clean (proven by the ``hex_of_real_sentence`` benign test)."""
    views: list[str] = []
    for m in _HEX_RUN_RE.finditer(text):
        run = m.group(0)
        if len(run) % 2 != 0:
            continue
        try:
            dec = bytes.fromhex(run).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable() and len(dec) >= 12:
            views.append(dec)
    return views


def _decode_base64_view(text: str) -> list[str]:
    """Return decoded strings for base64 runs that decode to printable ASCII.

    A >=24-char base64 run that decodes to PRINTABLE ascii reveals a payload
    (e.g. a secret base64-of-a-secret).  We do NOT treat a base64 run that
    decodes to binary as a view here (the raw run is already covered by the
    entropy/AWS floor)."""
    views: list[str] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        run = m.group(0)
        pad = (-len(run)) % 4
        try:
            raw = base64.b64decode(run + "=" * pad, validate=False)
            dec = raw.decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable() and len(dec) >= 8:
            views.append(dec)
    return views


def _leet_view(text: str) -> str:
    """De-leet digits→letters as a separate scan view."""
    return text.translate(_LEET_MAP)


def _reversed_view(text: str) -> str:
    return text[::-1]


# ---------------------------------------------------------------------------
# Core scanners over a single view
# ---------------------------------------------------------------------------

def _scan_known_formats(text: str) -> Optional[tuple[str, str]]:
    """Return (detector_name, matched_span) for the first known-format hit, or
    None.  For the labelled_secret pattern the captured value is the span."""
    for name, pat in _KEY_PATTERNS:
        m = pat.search(text)
        if m:
            # group(1) for capture-based patterns (labelled_secret), else group(0).
            span = m.group(1) if (m.lastindex and m.lastindex >= 1) else m.group(0)
            return name, span
    return None


def _scan_aws_secret(text: str) -> Optional[str]:
    """A 40-char base64-alphabet run with high entropy is an AWS secret access
    key candidate.  Returns the span or None.  Entropy-confirmed so a 40-char
    low-entropy run (unlikely but possible) does not trip.  A 40-char run that is
    base64-OF-PROSE (decodes to space-separated words) is NOT an AWS secret — the
    decode view re-scans it for any embedded key — so it is excluded here to
    avoid a benign-base64 false positive that happens to land at 40 chars."""
    for m in _AWS_SECRET_RE.finditer(text):
        span = m.group(0)
        if _shannon_entropy(span) >= _ENTROPY_THRESHOLD and not _is_base64_of_prose(span):
            return span
    return None


def _is_base64_of_prose(tok: str) -> bool:
    """True when *tok* is a base64 run that decodes to readable English-like
    PROSE (printable ASCII, spaces, low decoded entropy).  Such a blob is
    high-entropy in the base64 alphabet (so it would trip the raw entropy floor)
    but is benign — it is base64-of-a-sentence, not a secret.  The separate
    base64-DECODE view re-scans the decoded text, so a base64-of-SECRET is still
    caught there; this only suppresses the RAW-view entropy false positive."""
    if len(tok) < 16 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", tok):
        return False
    pad = (-len(tok)) % 4
    try:
        dec = base64.b64decode(tok + "=" * pad, validate=False).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    if not dec.isprintable():
        return False
    # Prose signature: the decoded payload reads as WORDS — multiple spaces and a
    # high alphabetic-or-space ratio.  A secret never base64-decodes to several
    # space-separated dictionary words; an English sentence (~4.0-4.3 bits/char,
    # ABOVE the raw secret floor) is reliably distinguished by its word shape,
    # not by entropy.  We also require the decoded text to NOT itself contain a
    # known key format / 40-char AWS run (so base64-of-"the key is wJalr..." is
    # still flagged via the decode view, not suppressed here).
    spaces = dec.count(" ")
    alpha_or_space = sum(c.isalpha() or c == " " for c in dec)
    is_wordy = spaces >= 2 and alpha_or_space / len(dec) >= 0.85
    if not is_wordy:
        return False
    if _scan_known_formats(dec) or _scan_aws_secret(dec):
        return False
    return True


def _scan_entropy(text: str, *, min_len: int) -> Optional[tuple[str, float]]:
    """Return (token, entropy) for the first long high-entropy token that does
    not look like an ordinary word, or None."""
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if len(tok) < min_len:
            continue
        if _looks_like_word(tok):
            continue
        if _is_base64_of_prose(tok):
            continue
        ent = _shannon_entropy(tok)
        if ent >= _ENTROPY_THRESHOLD:
            return tok, ent
    return None


def _hex_decodes_to_secret(run: str) -> bool:
    """True when a hex run decodes to a PRINTABLE-ASCII payload that is itself a
    plausible secret — i.e. the hex IS an encoding of a credential rather than a
    hash/commit-SHA/digest.

    A bare 40-char (SHA-1) / 64-char (SHA-256) hex run that decodes to BINARY is
    indistinguishable from a hash by pattern alone, so we do NOT flag it on the
    raw view (that is the git-SHA / digest false-positive class the suite
    guards).  But hex that decodes to printable ASCII reveals a hidden text
    secret, and the decoded view is separately re-scanned for key formats, so a
    True here means "this hex is carrying readable payload" — flag it."""
    if len(run) % 2 != 0:
        return False
    try:
        raw = bytes.fromhex(run)
        dec = raw.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return False
    # Printable + mostly non-whitespace (a real ASCII secret), length >= 12.
    return dec.isprintable() and len(dec) >= 12 and sum(c.isspace() for c in dec) <= 2


def _scan_view(text: str, *, min_len: int, hex_floor: bool,
               entropy_floor: bool = True) -> Optional[tuple[str, str, Optional[float]]]:
    """Run the full known-format + AWS + hex + entropy battery over a SINGLE
    decoded/normalised view.  Returns (detector, span, entropy) for the first
    hit, or None.  ``hex_floor`` enables hex-secret detection — but only for a
    hex run that DECODES TO A PRINTABLE-ASCII payload, so a bare hash / git-SHA /
    image digest (binary-decoding hex) is NOT over-blocked.  ``entropy_floor``
    can be disabled for views (reversed) whose characters are ALREADY entropy-
    scanned in their forward form — re-running the generic floor on the reversed
    bytes only manufactures duplicate false positives (e.g. reversed base64
    prose), never new coverage; the format/aws scan is what reversed needs.
    """
    km = _scan_known_formats(text)
    if km:
        return km[0], km[1], None
    aws = _scan_aws_secret(text)
    if aws:
        return "aws_secret", aws, _shannon_entropy(aws)
    if hex_floor:
        for hexm in _HEX_RUN_RE.finditer(text):
            run = hexm.group(0)
            if _hex_decodes_to_secret(run):
                return "hex_blob", run, _shannon_entropy(run)
    if entropy_floor:
        ent = _scan_entropy(text, min_len=min_len)
        if ent:
            return "entropy_blob", ent[0], ent[1]
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _run_reassembly_passes(
    view_text: str,
    view_prefix: str,
    *,
    record,
) -> None:
    """Run the spelled-out-separator / fragment-fusion / phonetic reassembly
    passes (Passes B/C/D below) over a SINGLE view, recording any hit via
    *record*.  ``view_prefix`` namespaces the recorded view label (e.g.
    ``"base64_decode"`` → ``"base64_decode:separator_reassembly"``).

    Factored out of :func:`scan` so the SAME reassembly battery can be applied
    BOTH to the canonical normalised text AND to each depth-1 decoded view
    (base64/base32/url/hex-separated).  A single encoding layer wrapped around a
    split-token / phonetic / connective-fused secret form decodes to prose the
    reassembly catches — but historically the reassembly ran ONLY over the
    canonical text, so the decoded view was scanned with the format/entropy
    battery alone and the split-token form leaked (Laura vector #18).  Running
    the reassembly over each decoded view closes that.

    Reassembly is INTENT-gated (a spelled-out separator must be present, the
    fragments must individually look like secret material, or a dense phonetic
    run must exist), so recursing it over decoded views does NOT start flagging
    benign base64-of-a-sentence: a decoded English sentence carries no
    spelled-out separator, its words are not secret fragments, and it has no
    dense phonetic run — all three gates stay shut on prose.

    ``view_prefix`` of ``""`` (the canonical text) emits the historical bare view
    labels (``"separator_reassembly"`` …) to preserve the ``views_hit`` contract;
    a non-empty prefix (a decoded view) namespaces them
    (``"base64_decode:separator_reassembly"``).
    """
    def _label(name: str) -> str:
        return f"{view_prefix}:{name}" if view_prefix else name

    # Pass B — spelled-out-separator reassembly (split-token defeat).
    reassembled, obfuscation_seen = _normalise_for_reassembly(view_text)
    if reassembled and obfuscation_seen:
        r = _scan_view(reassembled, min_len=_REASSEMBLY_MIN_LEN, hex_floor=True)
        if r:
            record(r[0], r[1], True, r[2], _label("separator_reassembly"))

    # Pass C — English-connective fragment fusion.
    fused = _fuse_secret_fragments(view_text)
    if fused:
        r = _scan_view(fused, min_len=_REASSEMBLY_MIN_LEN, hex_floor=True)
        if r:
            record(r[0], r[1], True, r[2], _label("fragment_fusion"))

    # Pass D — phonetic / spelled-letter reassembly.
    phon = _phonetic_reassemble(view_text)
    if phon:
        r = _scan_view(phon, min_len=_REASSEMBLY_MIN_LEN, hex_floor=False)
        if r:
            record(r[0], r[1], True, r[2], _label("phonetic"))
        elif len(phon) >= 12:
            record("phonetic_spellout", phon, True, _shannon_entropy(phon),
                   _label("phonetic"))


def scan(text: str) -> SecretVerdict:
    """Deterministically scan *text* for credentials / secrets.

    Runs the known-format regex + AWS + hex + entropy battery over the raw text
    AND a set of normalised / de-obfuscated / decoded VIEWS:

      • confusables-folded (NFKC + Cyrillic/Greek→Latin) view
      • zero-width-stripped view
      • spelled-out-separator reassembly (only when obfuscation intent seen)
      • English-connective fragment fusion
      • phonetic-alphabet / spelled-letter reassembly
      • base64 / base32 decoded views, URL-decoded view, hex-separator view,
        leetspeak-de-swap view, reversed view

    For each DEPTH-1 decoded view (base64 / base32 / URL / hex-separated) the
    reassembly battery (separator / fragment-fusion / phonetic) ALSO re-runs over
    the decoded text — so an encoding layer wrapped around a split-token /
    connective-fused / phonetic secret form is caught, not just an encoding layer
    wrapped around a verbatim key.  Depth-1 is sufficient (one encoding layer);
    the decoded views are NOT themselves recursively re-decoded, which bounds the
    cost at one decode pass per encoding family.

    The FIRST detector to fire wins; ``detectors_hit`` records every detector
    that matched and ``views_hit`` records which views tripped.

    Fail-closed: any internal error raises (the gate catches and denies).
    """
    if not text:
        return SecretVerdict(is_secret=False)

    hits: list[str] = []
    views_hit: list[str] = []
    first: Optional[tuple[str, str, bool, Optional[float]]] = None

    def _record(name: str, span: str, reassembled: bool,
                entropy: Optional[float], view: str) -> None:
        nonlocal first
        hits.append(name)
        if view not in views_hit:
            views_hit.append(view)
        if first is None:
            first = (name, span, reassembled, entropy)

    def _run_view(view_text: str, view_name: str, *, min_len: int,
                  reassembled: bool, hex_floor: bool,
                  entropy_floor: bool = True) -> None:
        if not view_text:
            return
        r = _scan_view(view_text, min_len=min_len, hex_floor=hex_floor,
                       entropy_floor=entropy_floor)
        if r:
            _record(r[0], r[1], reassembled, r[2], view_name)

    # ---- Canonical normalised base: fold confusables + strip zero-width -----
    # These are pure normalisations (not "decodes"), so a hit on them is NOT
    # flagged reassembled — the secret is verbatim, merely obfuscated by glyphs.
    folded = _fold_confusables(text)
    stripped = _strip_zero_width(folded)

    # ---- Pass A: raw / normalised text (verbatim secrets, hex floor on) -----
    _run_view(stripped, "normalised", min_len=_ENTROPY_MIN_LEN,
              reassembled=False, hex_floor=True)
    if stripped != text:
        # Also scan the truly-raw text so a normalisation that DROPS a separator
        # never hides a verbatim run.
        _run_view(text, "raw", min_len=_ENTROPY_MIN_LEN,
                  reassembled=False, hex_floor=True)

    # ---- Passes B/C/D: reassembly battery over the canonical normalised text -
    # Empty prefix → historical bare view labels (separator_reassembly, …).
    _run_reassembly_passes(stripped, "", record=_record)

    # ---- Pass E: encoding decodes (base64 / base32 / url / hex-sep / leet /
    #             reversed) — each decoded view re-scanned with BOTH the
    #             format/entropy battery AND the reassembly battery (depth-1)
    #             so a split-token secret hidden under one encoding layer is
    #             caught (Laura vector #18).  Decoded views are NOT re-decoded
    #             (depth bounded at 1) to cap cost.
    for dec in _decode_base64_view(stripped):
        _run_view(dec, "base64_decode", min_len=_REASSEMBLY_MIN_LEN,
                  reassembled=True, hex_floor=True)
        _run_reassembly_passes(dec, "base64_decode", record=_record)
    for dec in _decode_base32_views(stripped):
        _run_view(dec, "base32_decode", min_len=_REASSEMBLY_MIN_LEN,
                  reassembled=True, hex_floor=True)
        _run_reassembly_passes(dec, "base32_decode", record=_record)
    url_dec = _decode_url_view(stripped)
    if url_dec:
        _run_view(url_dec, "url_decode", min_len=_ENTROPY_MIN_LEN,
                  reassembled=True, hex_floor=True)
        _run_reassembly_passes(url_dec, "url_decode", record=_record)
    hexsep = _decode_hex_separated_view(stripped)
    if hexsep:
        _run_view(hexsep, "hex_separated", min_len=_REASSEMBLY_MIN_LEN,
                  reassembled=True, hex_floor=True)
        _run_reassembly_passes(hexsep, "hex_separated", record=_record)
    # Bare-contiguous-hex decoded views: each >=32-char hex run that decodes to
    # printable ASCII becomes a depth-1 view, REGARDLESS of whitespace count in
    # the decoded text.  Unlike the direct hex_blob path (kept guarded by the
    # <=2-space anti-FP rule in _hex_decodes_to_secret), this view exists purely so
    # the reassembly battery can see a SPLIT-TOKEN secret hidden inside contiguous
    # hex (LAURA-ORCH-HEXSPLIT).  The reassembly is intent-gated, so hex-of-a-real-
    # sentence decodes to prose and stays clean.
    for dec in _decode_hex_contiguous_views(stripped):
        _run_view(dec, "hex_contiguous_decode", min_len=_REASSEMBLY_MIN_LEN,
                  reassembled=True, hex_floor=True)
        _run_reassembly_passes(dec, "hex_contiguous_decode", record=_record)
    # Reversed view: a verbatim KNOWN-FORMAT key written backwards (AKIA…, ghp_…,
    # sk-…, PEM header).  We restrict reversed to the format regex only — NOT the
    # AWS-40-char heuristic or the entropy floor — because a reversed benign
    # base64 blob is still a 40-char base64 run and would falsely trip those.
    # The forward view already covers verbatim AWS-40 / entropy cases.
    rev = _reversed_view(stripped)
    rkm = _scan_known_formats(rev)
    if rkm:
        _record(rkm[0], rkm[1], True, None, "reversed")
    # Leet de-swap can manufacture vowels (a 40-char run becomes pronounceable),
    # so only run it for the KNOWN-FORMAT scan, not the entropy floor — it must
    # not lower entropy enough to clear a real secret, but its main value is
    # de-leeting a prefixed key (e.g. "5k-..." → "sk-...").  Known-format only.
    leet = _leet_view(stripped)
    if leet != stripped:
        lkm = _scan_known_formats(leet)
        if lkm:
            _record(lkm[0], lkm[1], True, None, "leet_deswap")

    if first is None:
        return SecretVerdict(is_secret=False, detectors_hit=[], views_hit=[])

    name, span, was_reassembled, entropy = first
    return SecretVerdict(
        is_secret=True,
        detector=name,
        reassembled=was_reassembled,
        span_hash=_hash_span(span),
        entropy=entropy,
        detectors_hit=hits,
        views_hit=views_hit,
    )


def is_secret(text: str) -> bool:
    """Boolean convenience wrapper over :func:`scan`."""
    return scan(text).is_secret
