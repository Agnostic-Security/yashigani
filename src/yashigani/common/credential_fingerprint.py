"""
Yashigani — credential-logging standard (Tiago directive 2026-07-26).

A credential must NEVER appear in plaintext in any log or audit record. A
bare class-only marker (``[REDACTED:api_key]``) is not enough either: it
destroys correlatability — an operator investigating an incident cannot tell
whether two masked events involved the SAME credential or two different
ones. The fix is a deterministic, non-reversible fingerprint:

    "cred:" + sha256(value.encode("utf-8")).hexdigest()[-12:]

Properties:
  - Deterministic: the same secret always produces the same fingerprint, so
    operators can correlate events (e.g. "this leaked key was used in 4
    other blocked requests") without ever seeing the plaintext.
  - Non-reversible: SHA-256 preimage resistance; 12 hex chars (48 bits) of
    a 256-bit digest is not a full hash disclosure, but is not intended as
    a security boundary either — the input space of real credentials is
    large enough that this is not brute-forceable back to the secret from
    the fingerprint alone in any practical sense relevant to audit logs.
  - Never the plaintext: the fingerprint fully replaces the credential
    value wherever it is emitted.

This is the ONE canonical format token for credential fingerprints across
the codebase (masking pipeline, forensic capture, application logging).
Do not invent a second format.
"""
from __future__ import annotations

import hashlib

_FINGERPRINT_PREFIX = "cred:"
_FINGERPRINT_TAIL_CHARS = 12


def credential_fingerprint(value: str) -> str:
    """Return a deterministic, non-reversible fingerprint for a credential
    value, safe to place in logs/audit records in place of the plaintext.

    Format: ``"cred:" + sha256(value).hexdigest()[-12:]``

    Args:
        value: the raw credential value (password, API key, bearer token,
            JWT, etc.). Never returned or logged by this function.

    Returns:
        A ``cred:<12 hex chars>`` string. Same input -> same output,
        always (deterministic), and the original value cannot be
        recovered from it (non-reversible).
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{_FINGERPRINT_PREFIX}{digest[-_FINGERPRINT_TAIL_CHARS:]}"
