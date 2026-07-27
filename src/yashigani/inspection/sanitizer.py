"""
Yashigani Inspection — Query sanitizer.
Strips detected injection payload spans from a query and reconstructs
a clean version for forwarding downstream.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_MIN_CLEAN_TOKENS = 3


@dataclass
class SanitizationResult:
    success: bool
    clean_query: Optional[str]      # None if discard required
    tokens_remaining: int
    spans_removed: int


def sanitize(
    raw_query: str,
    payload_spans: list[dict],      # [{"start": int, "end": int}]
    min_clean_tokens: int = _MIN_CLEAN_TOKENS,
    require_spans: bool = False,
) -> SanitizationResult:
    """
    Remove detected injection spans from raw_query and reconstruct a
    clean query string.

    Algorithm:
    1. Validate and merge overlapping spans.
    2. Remove spans from raw_query (descending order to preserve offsets).
    3. Collapse whitespace.
    4. Token count check — if < min_clean_tokens, return discard sentinel.

    require_spans: when True, an empty `payload_spans` list is treated as a
    FAILURE, not a no-op success. This is the fail-closed guard for callers
    on a confirmed-positive verdict (e.g. CREDENTIAL_EXFIL at/above threshold):
    a positive detection with no spans to excise means the caller has no way
    to prove the payload was actually redacted, so returning the query
    "unchanged and successful" would silently forward the exfil content
    while claiming it was sanitized (YSG-RISK-149). Callers that never carry
    a positive-verdict-with-empty-spans case (or that intentionally treat
    empty spans as "nothing to remove") should leave this False.

    Returns SanitizationResult. Never raises; on any error returns discard.
    """
    if not payload_spans:
        if require_spans:
            logger.warning(
                "sanitize() called with require_spans=True and no payload_spans — "
                "cannot prove redaction on a positive verdict; failing closed"
            )
            return SanitizationResult(
                success=False,
                clean_query=None,
                tokens_remaining=0,
                spans_removed=0,
            )
        return SanitizationResult(
            success=True,
            clean_query=raw_query,
            tokens_remaining=len(raw_query.split()),
            spans_removed=0,
        )

    try:
        spans = _validate_spans(payload_spans, len(raw_query))
        merged = _merge_spans(spans)
        clean = _excise_spans(raw_query, merged)
        clean = _normalize_whitespace(clean)
        tokens = clean.split()

        if len(tokens) < min_clean_tokens:
            logger.debug(
                "Sanitization produced %d tokens (min=%d) — discarding",
                len(tokens), min_clean_tokens,
            )
            return SanitizationResult(
                success=False,
                clean_query=None,
                tokens_remaining=len(tokens),
                spans_removed=len(merged),
            )

        return SanitizationResult(
            success=True,
            clean_query=clean,
            tokens_remaining=len(tokens),
            spans_removed=len(merged),
        )

    except Exception as exc:
        logger.warning("Sanitization error — discarding query: %s", exc)
        return SanitizationResult(
            success=False,
            clean_query=None,
            tokens_remaining=0,
            spans_removed=0,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_spans(spans: list[dict], text_len: int) -> list[tuple[int, int]]:
    """Validate span format and bounds. Returns list of (start, end) tuples."""
    result = []
    for s in spans:
        start = int(s["start"])
        end = int(s["end"])
        if start < 0 or end > text_len or start >= end:
            raise ValueError(f"Invalid span ({start}, {end}) for text length {text_len}")
        result.append((start, end))
    return result


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping or adjacent spans."""
    if not spans:
        return []
    sorted_spans = sorted(spans, key=lambda s: s[0])
    merged = [sorted_spans[0]]
    for start, end in sorted_spans[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _excise_spans(text: str, merged_spans: list[tuple[int, int]]) -> str:
    """Remove spans from text in descending order to preserve offsets."""
    result = text
    for start, end in sorted(merged_spans, reverse=True):
        result = result[:start] + result[end:]
    return result


def _normalize_whitespace(text: str) -> str:
    import re
    return re.sub(r'\s+', ' ', text).strip()
