"""Egress payload scoping for the DLP inspector — YSG-RISK-200.

Lives in its own module (not `gateway/egress_proxy.py`) so it can be imported
by tests without pulling in the gateway package, which requires a live
`YASHIGANI_INTERNAL_BEARER` at import time. Tom flagged the previous
exec-a-slice-of-the-source test loader as fragile in the 2026-08-07 pre-push
review; it then broke on the very next edit, which made the point.
"""
from __future__ import annotations

import json as _json

# Bodies larger than this are not envelope-parsed; they are scanned whole.
_MAX_ENVELOPE_PARSE_BYTES = 256 * 1024

_OPENAI_TOP_STRUCTURAL = frozenset({"id", "object", "created", "model", "system_fingerprint"})
_OPENAI_CHOICE_STRUCTURAL = frozenset({"index", "finish_reason", "logprobs"})
_OPENAI_MESSAGE_STRUCTURAL = frozenset({"role"})


def _inspectable_payload(body_text: str, prefix: str = "") -> str:
    """Return the inspectable text for an outbound body.

    YSG-RISK-200: the egress inspector scanned the whole transport envelope, so
    the random ``chatcmpl-<hex>`` correlation id tripped ``entropy_blob`` on
    10-80% of responses (by id length) and denied the agent's own LLM call.

    SCOPE (Tom, pre-push review 2026-08-07 — this is the fix to the first fix):
    the first version excluded a set of key NAMES at ANY depth, for EVERY egress
    prefix. That was a genuine new DLP bypass: a secret nested under one of those
    names in a Slack/Telegram-bound body skipped the scanner entirely. Proven:
    ``{"metadata": {"id": "AKIA..."}}`` scanned is_secret=True on the raw body and
    False through the helper.

    Now: stripping applies ONLY to the ``llm`` prefix (the agent's own internal
    self-call, the only class with the id false-positive) AND only at the exact
    POSITIONS the OpenAI envelope defines — top level, ``choices[*]``,
    ``choices[*].message`` role, and numeric ``usage``. A key called ``id``
    anywhere else is inspected like any other content. Every other prefix
    (slack, slack-hooks, telegram, and any future external destination) is
    scanned verbatim, exactly as before this change.

    Fail-closed everywhere: unknown prefix, unparseable body, unexpected shape,
    or nothing extracted -> return the full body.
    """
    if prefix != "llm" or not body_text:
        return body_text
    # Size guard (Tom, pre-push review): this runs on EVERY egress request and
    # ~78KB agent system prompts have been seen in the wild. Past the cap, skip
    # the parse and scan the body verbatim — strictly the safer direction.
    if len(body_text) > _MAX_ENVELOPE_PARSE_BYTES:
        return body_text
    try:
        doc = _json.loads(body_text)
    except Exception:
        return body_text
    if not isinstance(doc, dict):
        return body_text
    # Only a recognisable OpenAI-shaped envelope qualifies.
    if "choices" not in doc or not isinstance(doc.get("choices"), list):
        return body_text

    parts: list[str] = []

    def _emit(value: object) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _emit(v)
        elif isinstance(value, list):
            for v in value:
                _emit(v)

    for k, v in doc.items():
        if k in _OPENAI_TOP_STRUCTURAL:
            continue
        if k == "usage":
            continue  # numeric counters only
        if k == "choices":
            for choice in v:
                if not isinstance(choice, dict):
                    _emit(choice)
                    continue
                for ck, cv in choice.items():
                    if ck in _OPENAI_CHOICE_STRUCTURAL:
                        continue
                    if ck in ("message", "delta") and isinstance(cv, dict):
                        for mk, mv in cv.items():
                            if mk in _OPENAI_MESSAGE_STRUCTURAL:
                                continue
                            _emit(mv)
                    else:
                        _emit(cv)
            continue
        _emit(v)

    if not parts:
        return body_text
    return "\n".join(parts)


