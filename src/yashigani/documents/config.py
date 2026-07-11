"""
Yashigani Document Enforcement — feature flag + caps configuration.

The whole document-enforcement front-end ships DARK: default OFF.  When the
flag is off, ``is_document_enforcement_enabled()`` returns False and the
gateway never invokes the document pipeline — nothing changes for any existing
flow (plan: "ships dark and touches nothing when disabled").

Flag (env, default OFF):
    YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED   "true" | "false"  (default "false")

Caps (env, fail-closed defaults — plan §7):
    YASHIGANI_DOCUMENT_MAX_BYTES             int   (default 10 MiB)
    YASHIGANI_DOCUMENT_MAX_SEGMENTS          int   (default 100000)

This mirrors the existing env-flag convention in the codebase
(YASHIGANI_STREAMING_ENABLED, YASHIGANI_HIBP_CHECK_ENABLED).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from yashigani.documents.extractor import (
    DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_SEGMENTS,
    ExtractorRegistry,
)

ENV_ENABLED = "YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED"
ENV_MAX_BYTES = "YASHIGANI_DOCUMENT_MAX_BYTES"
ENV_MAX_SEGMENTS = "YASHIGANI_DOCUMENT_MAX_SEGMENTS"

#: Mode-B-via-proxy egress round-trip (2.26 gap #1).  When ON, a PSEUDONYMIZE
#: mode-B document leaving via the gateway proxy is tokenized OUTBOUND and the
#: untrusted upstream/cloud response is restored INBOUND through the proxy's
#: existing response-inspection seam.  Default OFF (dark) — the hot request path
#: is completely untouched for non-document / flag-off traffic.  This is a
#: STRICTER gate than the general document-enforcement flag: even with document
#: enforcement enabled, mode-B-via-proxy stays off unless explicitly opted in.
ENV_MODEB_PROXY = "YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED"


def is_document_enforcement_enabled() -> bool:
    """True only when the operator explicitly opts in.  Default OFF (dark)."""
    return os.environ.get(ENV_ENABLED, "false").strip().lower() == "true"


def is_modeb_proxy_enabled() -> bool:
    """True only when the operator explicitly opts into mode-B-via-proxy egress.

    Default OFF (dark).  Independent of :func:`is_document_enforcement_enabled`
    so the cloud-egress round-trip is a deliberate, separately-gated opt-in: a
    fault on this hot path must never be reachable unless the operator turned it
    on.  Both gates must be satisfied for the proxy to drive the round-trip."""
    return os.environ.get(ENV_MODEB_PROXY, "false").strip().lower() == "true"


def _int_env(name: str, default: int) -> int:
    """Read a positive-int env var; fall back to the fail-closed default on any
    malformed value (never raise at import-time, never accept <= 0)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class DocumentEnforcementConfig:
    """Resolved configuration for the document front-end."""

    enabled: bool
    max_document_bytes: int
    max_segments: int

    @classmethod
    def from_env(cls) -> "DocumentEnforcementConfig":
        return cls(
            enabled=is_document_enforcement_enabled(),
            max_document_bytes=_int_env(ENV_MAX_BYTES, DEFAULT_MAX_DOCUMENT_BYTES),
            max_segments=_int_env(ENV_MAX_SEGMENTS, DEFAULT_MAX_SEGMENTS),
        )

    def build_registry(self) -> ExtractorRegistry:
        """Construct an :class:`ExtractorRegistry` honouring these caps."""
        return ExtractorRegistry(
            max_document_bytes=self.max_document_bytes,
            max_segments=self.max_segments,
        )
