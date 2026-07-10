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
# Regex patterns — compiled once at module import
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # JWT  (three base64url segments)
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
     "[REDACTED:jwt]"),
    # Bearer token in header/string
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),
     "[REDACTED:bearer]"),
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
        raw_query_logged is always forced to False.
        """
        cloned = copy.copy(event)
        for f in dataclasses.fields(cloned):
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
