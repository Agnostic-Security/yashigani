"""
Yashigani — decode-before-classify normalisation (F-RT1).

Red-team finding F-RT1 (Medium, verified 2026-05-30):
    The PII/sensitivity classifier matched literal patterns on RAW prompt
    text only.  An attacker who base64-encoded a payload — e.g.
    base64("SSN 123-45-6789") — produced NO PII_DETECTED event and the
    request was delivered (200 OK).  The bypass was *invisible* in every
    audit sink because no event was emitted at all.  The decode stage below
    normalises plausibly-encoded segments back to plaintext BEFORE the
    PII detector and the sensitivity classifier run, so a hit in ANY view
    triggers detection — and a suspicious-but-undecodable / high-entropy
    blob still produces an audit signal (the silent-pass is the worst part
    of F-RT1).

Relationship to YSG-RISK-057 (v2.26):
    YSG-RISK-057 is the *tool-description* encoded-injection residual on the
    MCP path (mcp/_content_filter.py explicitly defers base64/hex to the
    v2.26 LLM-classifier sidecar).  THIS module is the INFERENCE-path PII
    sibling — same encoded-bypass *class*, different surface (chat prompt
    text vs tool descriptions).  They are NOT the same fix and must not be
    conflated: this one ships in 2.25.2 (fix-in-branch); the sidecar is v2.26.

Design principles:
  - stdlib only (base64, binascii, codecs, urllib, re, math).
  - Defensive: NEVER raises on non-decodable input; returns what it can.
  - Bounded (anti-DoS):
        * MAX_INPUT_CHARS — input above the cap is not decoded (only the raw
          view is classified; oversize-blob is flagged separately).
        * MAX_DECODE_PASSES — caps nested-decoding depth (e.g. double-base64).
        * MAX_SEGMENTS — caps how many candidate segments we attempt.
        * MAX_VIEW_CHARS — each decoded view is truncated to this length.
  - Plausibility-gated: a codec is only ATTEMPTED when a segment plausibly
    looks like that encoding, so we don't waste work / emit noise on prose.
  - Audit-honest: returns suspicious_blob / high_entropy flags so the caller
    can emit an audit event even when a blob cannot be decoded to plaintext.

Codecs covered (minimum per F-RT1 scope):
    base64 (standard + urlsafe), hex, URL percent-encoding, ROT13.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Bounds — anti-DoS. Tuned conservatively; a legitimate chat prompt is well
# under these, while a nested/huge payload is bounded to a fixed work budget.
# ---------------------------------------------------------------------------
MAX_INPUT_CHARS: int = 100_000      # above this, do not attempt decoding
MAX_DECODE_PASSES: int = 2          # nested-decode depth cap (e.g. base64(base64(x)))
MAX_SEGMENTS: int = 64              # max candidate segments attempted per pass
MAX_VIEW_CHARS: int = 20_000        # truncate each decoded view to this length

# A blob is "suspicious" (worth an audit signal even if undecodable) when it is
# a long, contiguous, high-entropy token that looks encoded but did not yield
# printable plaintext.
_SUSPICIOUS_MIN_LEN: int = 24
_HIGH_ENTROPY_BITS: float = 4.0     # Shannon bits/char threshold over the token

# Candidate-token extraction: contiguous runs of chars that appear in the
# encodings we handle (base64/urlsafe-b64 alphabet, hex, percent-encoding).
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-%]{16,}")

# Tighter shape checks per codec (plausibility gates).
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")
_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass
class DecodedView:
    """A single normalised view of (a segment of) the input."""
    view_name: str          # "raw" | "base64" | "base64url" | "hex" | "url" | "rot13"
    text: str               # decoded plaintext (possibly truncated to MAX_VIEW_CHARS)
    segment: str            # masked original encoded token this view came from
    depth: int = 1          # decode pass depth (1 = single decode of raw input)


@dataclass
class DecodeResult:
    """
    Outcome of decode_views().

    views:
        Always includes a "raw" view (the original text; Unicode normalisation
        is the classifiers' concern, not this stage's).  Additional views are
        decoded segments worth classifying.
    suspicious_blob:
        True when at least one long, contiguous, encoded-looking token did NOT
        decode to printable plaintext (or decoded to non-text bytes).  The
        caller MUST emit an audit event in this case even if no PII matched —
        this is the F-RT1 silent-pass guard.
    high_entropy:
        True when a suspicious blob also had Shannon entropy above the
        high-entropy threshold (looks like ciphertext / packed data).
    flagged_tokens:
        Masked, truncated representations of the suspicious tokens (audit-safe;
        never the full token).
    oversize:
        True when the input exceeded MAX_INPUT_CHARS and decoding was skipped.
    """
    views: list[DecodedView]
    suspicious_blob: bool = False
    high_entropy: bool = False
    flagged_tokens: list[str] = field(default_factory=list)
    oversize: bool = False


# ---------------------------------------------------------------------------
# Entropy + safety helpers
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


def _is_mostly_printable(s: str) -> bool:
    """True when the decoded string is predominantly printable text.

    A successful decode of an encoded *payload* should yield human-readable
    text; binary noise (the usual result of decoding random prose as base64)
    is rejected so we don't classify garbage or flood views.
    """
    if not s:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\n\r\t")
    return (printable / len(s)) >= 0.90


def _mask_token(token: str) -> str:
    """Audit-safe representation of a flagged token: first4…last4 + length."""
    t = token.strip()
    if len(t) <= 10:
        return f"****(len={len(t)})"
    return f"{t[:4]}...{t[-4:]}(len={len(t)})"


# ---------------------------------------------------------------------------
# Per-codec attempts. Each returns decoded text or None (never raises).
# ---------------------------------------------------------------------------

def _try_base64(segment: str, urlsafe: bool) -> str | None:
    seg = segment.strip()
    shape = _B64URL_RE if urlsafe else _B64_RE
    if not shape.match(seg):
        return None
    # base64 length must be a multiple of 4 (with padding); pad defensively.
    pad = (-len(seg)) % 4
    candidate = seg + ("=" * pad)
    try:
        raw = (
            base64.urlsafe_b64decode(candidate)
            if urlsafe
            else base64.b64decode(candidate, validate=True)
        )
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _is_mostly_printable(text) else None


def _try_hex(segment: str) -> str | None:
    seg = segment.strip()
    if not _HEX_RE.match(seg):
        return None
    try:
        raw = bytes.fromhex(seg)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _is_mostly_printable(text) else None


def _try_url(text: str) -> str | None:
    """Whole-text URL percent-decode. Only meaningful if percent-escapes present."""
    if not _PERCENT_RE.search(text):
        return None
    try:
        decoded = unquote(text, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if decoded == text:
        return None
    return decoded if _is_mostly_printable(decoded) else None


def _try_rot13(text: str) -> str | None:
    """Whole-text ROT13. Cheap and always reversible; only useful on prose."""
    decoded = codecs.decode(text, "rot_13")
    if decoded == text:
        return None
    return decoded if _is_mostly_printable(decoded) else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decode_views(text: str) -> DecodeResult:
    """
    Produce normalised views of *text* for the PII / sensitivity classifiers.

    Always returns a "raw" view first.  Then, bounded by the module limits,
    extracts plausibly-encoded segments and decodes them (base64 std + urlsafe,
    hex), plus whole-text URL-decode and ROT13 transforms, recursing up to
    MAX_DECODE_PASSES for nested encodings.

    Never raises.  On oversize input, only the raw view is returned and
    ``oversize`` is set (so the caller can still audit a too-large payload).
    """
    raw_view = DecodedView(view_name="raw", text=text, segment="", depth=0)
    result = DecodeResult(views=[raw_view])

    if not text:
        return result

    if len(text) > MAX_INPUT_CHARS:
        result.oversize = True
        result.suspicious_blob = True
        result.flagged_tokens.append(f"oversize(len={len(text)})")
        return result

    seen_texts: set[str] = {text}

    # Whole-text transforms (URL-decode, ROT13) — cheap, applied to the raw text.
    _whole_text_codecs: tuple[tuple[str, Callable[[str], str | None]], ...] = (
        ("url", _try_url),
        ("rot13", _try_rot13),
    )
    for name, fn in _whole_text_codecs:
        decoded = fn(text)
        if decoded and decoded not in seen_texts:
            seen_texts.add(decoded)
            result.views.append(
                DecodedView(
                    view_name=name,
                    text=decoded[:MAX_VIEW_CHARS],
                    segment="",
                    depth=1,
                )
            )

    # Segment-based transforms (base64 / hex) with bounded nested-decode.
    frontier: list[tuple[str, int]] = [(text, 0)]  # (text-to-scan, current depth)
    passes = 0
    while frontier and passes < MAX_DECODE_PASSES:
        passes += 1
        next_frontier: list[tuple[str, int]] = []
        for scan_text, depth in frontier:
            tokens = _TOKEN_RE.findall(scan_text)[:MAX_SEGMENTS]
            for token in tokens:
                if len(token) < 16:
                    continue
                decoded_any = False
                _segment_codecs: tuple[tuple[str, Callable[[str], str | None]], ...] = (
                    ("base64", lambda s: _try_base64(s, urlsafe=False)),
                    ("base64url", lambda s: _try_base64(s, urlsafe=True)),
                    ("hex", _try_hex),
                )
                for name, fn in _segment_codecs:
                    decoded = fn(token)
                    if decoded and decoded not in seen_texts:
                        seen_texts.add(decoded)
                        decoded_any = True
                        result.views.append(
                            DecodedView(
                                view_name=name,
                                text=decoded[:MAX_VIEW_CHARS],
                                segment=_mask_token(token),
                                depth=depth + 1,
                            )
                        )
                        # Feed the decoded text back for a further pass (nested).
                        next_frontier.append((decoded, depth + 1))
                        break  # one successful codec per token is enough

                # F-RT1 silent-pass guard: a long, encoded-looking, high-entropy
                # token that did NOT decode to plaintext is still suspicious.
                if not decoded_any and len(token) >= _SUSPICIOUS_MIN_LEN:
                    looks_encoded = bool(
                        _B64_RE.match(token)
                        or _B64URL_RE.match(token)
                        or _HEX_RE.match(token)
                    )
                    if looks_encoded:
                        ent = _shannon_entropy(token)
                        if ent >= _HIGH_ENTROPY_BITS:
                            result.suspicious_blob = True
                            result.high_entropy = True
                            masked = _mask_token(token)
                            if masked not in result.flagged_tokens:
                                result.flagged_tokens.append(masked)
        frontier = next_frontier

    return result
