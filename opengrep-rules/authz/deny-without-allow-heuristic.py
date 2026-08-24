"""
opengrep test fixture for deny-without-allow-heuristic.

Run via: opengrep test opengrep-rules/authz/

Path filters (paths.include in the sibling rule file) are NOT applied in
test mode -- this file validates pattern correctness only.
"""
import re

DENY_PATTERNS = {"admin", "root", "system"}
ALLOWED_MODELS = {"claude-sonnet-4-6", "qwen2.5:3b"}


def is_model_denied_subtractive_only(model: str) -> bool:
    """Positive: subtractive canonicalization feeds a denylist-only check,
    no allowlist/positive-match check anywhere in the function body. This
    is the exact LAURA-412-001 shape (openai:gpt-4o. / :: / :// bypassed a
    single-form normalizer)."""
    # ruleid: deny-without-allow-heuristic
    norm = model.replace("://", ":").replace("::", ":")
    norm = norm.strip(" .:;,/").lower()
    if norm in DENY_PATTERNS:
        return True
    return False


def gate_reject_on_denylist(raw_value: str) -> bool:
    """Positive: re.sub canonicalization feeding a reject/gate decision with
    no allowlist check in scope."""
    # ruleid: deny-without-allow-heuristic
    cleaned = re.sub(r"[\s\-_.\/]", "", raw_value)
    if cleaned.lower() in DENY_PATTERNS:
        return True
    return False


def is_model_denied_with_allowlist(model: str) -> bool:
    """Negative: same subtractive canonicalization, but the function ALSO
    contains a positive allowlist check -- the intended safe pattern
    (LAURA-412-001's fix: canonicalize once, then check the allowlist)."""
    # ok: deny-without-allow-heuristic
    norm = model.replace("://", ":").replace("::", ":")
    norm = norm.strip(" .:;,/").lower()
    if norm in ALLOWED_MODELS:
        return False
    return True


def collapse_separators_for_injection_scan(text: str) -> str:
    """Negative: this is the _content_filter.py pattern -- subtractive
    canonicalization used to WIDEN detection recall before a pattern scan,
    not to gate a deny decision by itself in this function. No deny/block/
    reject/gate keyword in the function name, so the rule's name filter
    should not even consider this function a candidate."""
    def _collapse(m: re.Match) -> str:
        # ok: deny-without-allow-heuristic
        return re.sub(r"[\s\-_.\/]", "", m.group(0))
    return re.sub(r"(?<!\w)(\w(?:[\s\-_.\/]\w)+)(?!\w)", _collapse, text)
