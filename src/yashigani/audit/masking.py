"""
Yashigani Audit — Credential masking pipeline.
Applied to all content before it reaches any model or log sink.
"""
from __future__ import annotations

import copy
import dataclasses
import re
from typing import Any

from yashigani.audit.schema import AuditEvent

# ---------------------------------------------------------------------------
# Immutable floor — these event types are ALWAYS masked regardless of config
# ---------------------------------------------------------------------------

IMMUTABLE_FLOOR_EVENTS: frozenset[str] = frozenset({
    "CREDENTIAL_LEAK_DETECTED",
    "PROMPT_INJECTION_CREDENTIAL_EXFIL",
    "TOTP_RESET_CONSOLE",
    "EMERGENCY_UNLOCK_EXECUTED",
    "RECOVERY_CODE_USED",
    "KSM_ROTATION_SUCCESS",
    "KSM_ROTATION_FAILURE",
    "KSM_ROTATION_CRITICAL",
    "MASKING_CONFIG_CHANGED",
    "USER_FULL_RESET",
    "FULL_RESET_TOTP_FAILURE",
})

# ---------------------------------------------------------------------------
# Audit-integrity events — NEVER masked (complement of IMMUTABLE_FLOOR)
#
# These event types carry cryptographic audit anchors (SHA-256 / SHA-384
# hashes) that MUST be plaintext for auditors to cross-reference change
# tickets against the Merkle chain. Masking them would undermine the
# CM-3 / CC8.1 detective control.
#
# v2.25.0 / Lu-Gap-06 / G2.
# ---------------------------------------------------------------------------

AUDIT_INTEGRITY_EVENTS: frozenset[str] = frozenset({
    "MANIFEST_ONBOARD",   # manifest_sha256 must be readable by auditors
    "MANIFEST_OFFBOARD",  # audit trail completeness (no secret fields)
})

# ---------------------------------------------------------------------------
# Structured fields — NEVER value-masked, regardless of event type
#
# LAURA-V50-003(b): the generic 32-64 char hex pattern below exists to catch
# unlabelled secrets, but a SHA-256 hexdigest IS a 32-64 char hex string by
# definition — so the pattern was matching the schema's own integrity/
# attribution fields (content_hash, response_content_hash, manifest_digest,
# weights_sha256, etc.) and rewriting them to the literal string
# "[REDACTED:api_key]" on every masked event, destroying the
# non-repudiation guarantee those fields exist to provide.
#
# LAURA-V50-006: the same collision hits any OTHER hex-shaped structured
# identifier that isn't a hash/digest — e.g. candidate_id
# (uuid.uuid4().hex, 32 lowercase hex chars). The V50-003(b) fix was a
# field-*name* denylist scoped to hash/digest suffixes only, so it did not
# cover this case; extending it one field at a time ("also exempt
# candidate_id") is whack-a-mole — the schema has ~150 more `_id` fields
# following the same naming convention (request_id, session_id, agent_id,
# tenant_id, rule_id, workflow_id, key_id, spiffe_id, ...), all of which are
# server-generated/server-verified correlation identifiers, never free-form
# text a caller could paste a credential into.
#
# Fix, generalized by NAMING CONVENTION rather than by field list: any field
# whose name ends in a structured-identifier or hash/digest suffix is,
# by construction across this schema, a correlation identifier or a
# computed integrity anchor — never a place a credential could be pasted —
# so it is exempt from value-masking. Free-form/captured-payload fields
# (analyzed_content, justification, ack_text_shown, error, previous_value/
# new_value, etc.) do NOT end in these suffixes and remain fully masked, so
# LAURA-V50-003(a)'s plain-password-in-content coverage is unchanged.
# ---------------------------------------------------------------------------

_HASH_FIELD_SUFFIXES: tuple[str, ...] = (
    "_hash",
    "_hash_tail",   # e.g. old_hash_tail / new_hash_tail (Argon2id hash tail)
    "_digest",
    "_sha256",
    "_sha384",
    "_sha512",
)

# LAURA-V50-006: structured correlation-identifier suffix. Every identifier
# field in schema.py follows this naming convention (agent_id, session_id,
# candidate_id, tenant_id, rule_id, spiffe_id, key_id, ...) — server-
# generated or server-verified IDs, never free-form content.
_STRUCTURAL_ID_SUFFIXES: tuple[str, ...] = (
    "_id",
)

_NEVER_MASKED_FIELD_SUFFIXES: tuple[str, ...] = (
    _HASH_FIELD_SUFFIXES + _STRUCTURAL_ID_SUFFIXES
)


def _is_hash_field(field_name: str) -> bool:
    """True if `field_name` holds a hash/digest value that must never be masked.

    Kept name for backward compatibility (LAURA-V50-003(b) call sites/tests
    reference `_is_hash_field`); it now also covers LAURA-V50-006's
    structured-identifier generalization via `_is_never_masked_field`.
    """
    return field_name.endswith(_HASH_FIELD_SUFFIXES)


def _is_never_masked_field(field_name: str) -> bool:
    """True if `field_name` holds a hash/digest OR a structured correlation
    identifier — either way, a value that must never be handed to
    mask_string() (LAURA-V50-003(b) + LAURA-V50-006)."""
    return field_name.endswith(_NEVER_MASKED_FIELD_SUFFIXES)


# ---------------------------------------------------------------------------
# Regex patterns — compiled once at module import
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # JWT  (three base64url segments)
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
     "[REDACTED:jwt]"),
    # Bearer token in header/string
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),
     "[REDACTED:bearer]"),
    # LAURA-V50-003(a): labelled plain-password disclosure — "password is X",
    # "password: X", "pwd=X". Plain passwords don't match any vendor-format
    # pattern below (not hex, no known key prefix), so they previously leaked
    # in cleartext into forensically-captured audit content. Keeps the label
    # (attack structure) but drops the value.
    (re.compile(r'(?i)\b(password|passwd|pwd)\b\s*(?:is\s+|[:=]\s*)[\'"]?[^\s\'",;]+'),
     r'\1: [REDACTED:password]'),
    # OpenAI / Anthropic / generic sk- keys
    (re.compile(r'sk-[A-Za-z0-9]{20,}'),
     "[REDACTED:api_key]"),
    # GitHub personal access token
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),
     "[REDACTED:api_key]"),
    # GitLab PAT
    (re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
     "[REDACTED:api_key]"),
    # AWS access key ID
    (re.compile(r'AKIA[0-9A-Z]{16}'),
     "[REDACTED:api_key]"),
    # 32–64 char hex strings (generic secret)
    (re.compile(r'\b[0-9a-fA-F]{32,64}\b'),
     "[REDACTED:api_key]"),
    # PEM private key header
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----'),
     "[REDACTED:private_key]"),
    # Basic auth header
    (re.compile(r'Basic\s+[A-Za-z0-9+/=]{8,}', re.IGNORECASE),
     "[REDACTED:basic_auth]"),
]


class CredentialMasker:
    """
    Applies all credential-detection patterns to strings and dicts.
    Thread-safe (stateless after init — compiled patterns are read-only).
    """

    def mask_string(self, text: str) -> str:
        """Apply all patterns sequentially. Return masked string."""
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def mask_dict(self, data: dict) -> dict:
        """Recursively mask all string values in a dict (deep copy)."""
        result: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, str):
                result[k] = self.mask_string(v)
            elif isinstance(v, dict):
                result[k] = self.mask_dict(v)
            elif isinstance(v, list):
                result[k] = self._mask_list(v)
            else:
                result[k] = v
        return result

    def mask_event(self, event: AuditEvent) -> AuditEvent:
        """
        Return a shallow-copied event with all string fields masked.
        Non-string fields are left unchanged.
        Hash/digest fields (content_hash, response_content_hash,
        manifest_digest, weights_sha256, etc.) and structured correlation-
        identifier fields (candidate_id, session_id, agent_id, tenant_id,
        etc. — see _is_never_masked_field) are NEVER masked: they carry a
        computed integrity value or a server-verified identifier, not
        free-form content, and the generic hex-secret pattern would
        otherwise rewrite any hex-shaped one to a static placeholder
        (LAURA-V50-003(b), LAURA-V50-006).
        raw_query_logged is always forced to False.
        """
        cloned = copy.copy(event)
        for f in dataclasses.fields(cloned):
            if _is_never_masked_field(f.name):
                continue
            val = getattr(cloned, f.name)
            if isinstance(val, str):
                setattr(cloned, f.name, self.mask_string(val))
        # Invariant: raw query is never logged
        if hasattr(cloned, "raw_query_logged"):
            object.__setattr__(cloned, "raw_query_logged", False)
        return cloned

    def is_floor_event(self, event: AuditEvent) -> bool:
        return event.event_type in IMMUTABLE_FLOOR_EVENTS

    # -- Internal ------------------------------------------------------------

    def _mask_list(self, lst: list) -> list:
        result: list = []
        for item in lst:
            if isinstance(item, str):
                result.append(self.mask_string(item))
            elif isinstance(item, dict):
                result.append(self.mask_dict(item))
            else:
                result.append(item)
        return result
