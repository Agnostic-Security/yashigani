"""
Yashigani Inspection — security-event content capture (5.0).

Requirement (Tiago): anything Yashigani blocks, scrubs, or judges malicious /
bypass-seeking MUST land in the audit log — and the log must be able to carry
the analysed CONTENT (the actual injection payload) for forensics and demos,
attributed to the identity/MCP-server that sent it.

This reconciles that with the long-standing privacy invariant (audit stores a
content HASH, never raw content — ASVS V7):

  - The content HASH is ALWAYS recorded (attribution + non-repudiation).
  - The matched deterministic PATTERN is ALWAYS recorded when the mechanical
    filter fired (which rule caught it — not sensitive, and shows the block was
    mechanical, not an exploitable LLM call).
  - The raw CONTENT is captured ONLY in forensic mode
    (YASHIGANI_SECURITY_FORENSIC_CAPTURE=true), bounded to a max length. Default
    OFF, so production keeps the hash-only invariant; a demo/forensic stack
    turns it on to show the payload.
"""
from __future__ import annotations

import hashlib
import os

_MAX_FORENSIC_CHARS = 4096


def forensic_capture_enabled() -> bool:
    return os.getenv("YASHIGANI_SECURITY_FORENSIC_CAPTURE", "false").strip().lower() in (
        "true", "1", "yes", "on",
    )


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def capture_content(text: str) -> str:
    """Return the analysed content for audit when forensic mode is on (bounded),
    else empty string. Credentials/secrets are MASKED before capture so forensic
    mode records the ATTACK STRUCTURE without writing raw secrets to the audit
    store (defence for the case where an operator enables it with real traffic).
    Never raises."""
    if not text or not forensic_capture_enabled():
        return ""
    masked = _mask_secrets(text)
    if len(masked) > _MAX_FORENSIC_CHARS:
        return masked[:_MAX_FORENSIC_CHARS] + f"…[+{len(masked) - _MAX_FORENSIC_CHARS} chars]"
    return masked


def _mask_secrets(text: str) -> str:
    """Mask credential-shaped substrings before forensic capture. Best-effort:
    if the masker is unavailable, fall back to the raw text (forensic mode is an
    explicit operator opt-in)."""
    try:
        from yashigani.audit.masking import CredentialMasker
        return CredentialMasker().mask_string(text)
    except Exception:
        return text
