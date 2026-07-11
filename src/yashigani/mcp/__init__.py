"""
Yashigani MCP Broker — P1 W3 Phase 2b-ii + Phase-2 hardening

Ring-fences MCP traffic with:
  - Gateway-signed ES384 identity JWT (Nico NICO-004 spec)
  - Channel-derived posture (YSG-RISK-055 — NEVER from request body)
  - OPA enforcement on every MCP call (fail-closed, 500ms timeout)
  - Merkle-chained audit emission on every decision (AU-2/12/CC7.1)

Transports:
  - stdio (Shape A/C local process — gateway spawns subprocess)
  - Streamable HTTP (Shape B MCP-client + Shape C MCP-server-over-HTTP)

Phase-2 hardening (implemented):
  [M4] Tool-description / prompts.get prompt-injection content filter
       (_content_filter.py — filter_description, build_catalogue,
       ToolCatalogueStore, TenantCatalogue).
  [P8] Upstream MCP-server cert/SPIFFE pinning enforcement
       (_upstream_pin.py — UpstreamPinConfig, verify_upstream_pin,
       require_pin_mode_for_servers, PinMode).
  [P1-pool] Per-tenant provider-key cache + per-tenant connection pools
       (_pool.py — TenantPoolManager).

v2.25.0 / P1 W3 Phase 2b-ii + Phase-2 /
  YSG-RISK-054 (audit) + YSG-RISK-055 (posture) +
  YSG-RISK-056 (upstream pin) + YSG-RISK-057 (cross-tenant isolation).
"""
from __future__ import annotations

from yashigani.mcp._types import (
    BrokerDecision,
    EgressDecision,
    McpCallContext,
    McpPosture,
    McpTransportKind,
    PostureBinding,
    OpaDecision,
)
from yashigani.mcp.broker import McpBroker, McpBrokerConfig
from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier
from yashigani.mcp._nonce import NonceStore, InMemoryNonceStore
from yashigani.mcp._posture import derive_posture_from_channel
from yashigani.mcp._opa import (
    query_mcp_decision,
    query_mcp_response_decision,
    OpaDecisionResult,
    OpaResponseDecisionResult,
)

# Phase-2 hardening exports
from yashigani.mcp._content_filter import (
    FilterResult,
    ToolCatalogueStore,
    TenantCatalogue,
    ToolDescriptor,
    PromptDescriptor,
    build_catalogue,
    filter_description,
)
from yashigani.mcp._upstream_pin import (
    PinMode,
    UpstreamPinConfig,
    PinVerificationResult,
    PinManifestValidationError,
    verify_upstream_pin,
    require_pin_mode_for_servers,
    CERT_PIN_MISMATCH_LABEL,
)
# 3.0 / YSG-RISK-058 — external-upstream revocation-watch
from yashigani.mcp._upstream_revocation import (
    RevocationConfig,
    RevocationResult,
    RevocationStatus,
    check_revocation,
    REVOKED_LABEL,
    REVOCATION_STALE_LABEL,
    REVOCATION_NO_CHANNEL_LABEL,
    REVOCATION_PIN_EXPIRED_LABEL,
)
from yashigani.mcp._pool import TenantPoolManager

# 3.0 / YSG-RISK-060 — capability-envelope tool-surface pin
from yashigani.mcp._envelope import (
    EffectClass,
    ArgShape,
    ToolEnvelope,
    ServerEnvelope,
    StructuralDiffResult,
    DiffFinding,
    compute_provenance_id,
    namespaced_tool_key,
    surface_set_hash,
    project_tool,
    project_surface,
    combine_effect_classes,
    diff_envelope,
)
from yashigani.mcp._envelope_triage import (
    TriageClass,
    TriageOutcome,
    triage_refresh,
)
from yashigani.mcp.envelope_service import (
    CapabilityEnvelopeService,
    EnvelopeRecord,
    serialise_envelope,
    deserialise_envelope,
    STATUS_ACTIVE,
    STATUS_BLOCKED,
    STATUS_SUPERSEDED,
    TOPOLOGY_RING_FENCED,
    TOPOLOGY_EXTERNAL_RELAY,
)
from yashigani.mcp.envelope_reapproval import (
    FieldLevelDiff,
    compute_field_level_diff,
    reapprove_envelope,
)

__all__ = [
    # Core
    "McpBroker",
    "McpBrokerConfig",
    "BrokerDecision",
    "EgressDecision",
    "McpCallContext",
    "McpPosture",
    "McpTransportKind",
    "PostureBinding",
    "OpaDecision",
    "McpJwtIssuer",
    "McpJwtVerifier",
    "NonceStore",
    "InMemoryNonceStore",
    "derive_posture_from_channel",
    "query_mcp_decision",
    "query_mcp_response_decision",
    "OpaDecisionResult",
    "OpaResponseDecisionResult",
    # Phase-2: M4 content filter
    "FilterResult",
    "ToolCatalogueStore",
    "TenantCatalogue",
    "ToolDescriptor",
    "PromptDescriptor",
    "build_catalogue",
    "filter_description",
    # Phase-2: P8 upstream pinning
    "PinMode",
    "UpstreamPinConfig",
    "PinVerificationResult",
    "PinManifestValidationError",
    "verify_upstream_pin",
    "require_pin_mode_for_servers",
    "CERT_PIN_MISMATCH_LABEL",
    # 3.0: external-upstream revocation-watch (YSG-RISK-058)
    "RevocationConfig",
    "RevocationResult",
    "RevocationStatus",
    "check_revocation",
    "REVOKED_LABEL",
    "REVOCATION_STALE_LABEL",
    "REVOCATION_NO_CHANNEL_LABEL",
    "REVOCATION_PIN_EXPIRED_LABEL",
    # Phase-2: P1-pool
    "TenantPoolManager",
    # 3.0: capability-envelope tool-surface pin (YSG-RISK-060)
    "EffectClass",
    "ArgShape",
    "ToolEnvelope",
    "ServerEnvelope",
    "StructuralDiffResult",
    "DiffFinding",
    "compute_provenance_id",
    "namespaced_tool_key",
    "surface_set_hash",
    "project_tool",
    "project_surface",
    "combine_effect_classes",
    "diff_envelope",
    "TriageClass",
    "TriageOutcome",
    "triage_refresh",
    "CapabilityEnvelopeService",
    "EnvelopeRecord",
    "serialise_envelope",
    "deserialise_envelope",
    "STATUS_ACTIVE",
    "STATUS_BLOCKED",
    "STATUS_SUPERSEDED",
    "TOPOLOGY_RING_FENCED",
    "TOPOLOGY_EXTERNAL_RELAY",
    "FieldLevelDiff",
    "compute_field_level_diff",
    "reapprove_envelope",
]
