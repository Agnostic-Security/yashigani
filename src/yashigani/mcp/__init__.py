"""
Yashigani MCP Broker — P1 W3 Phase 2b-ii

Ring-fences MCP traffic with:
  - Gateway-signed ES384 identity JWT (Nico NICO-004 spec)
  - Channel-derived posture (YSG-RISK-055 — NEVER from request body)
  - OPA enforcement on every MCP call (fail-closed, 500ms timeout)
  - Merkle-chained audit emission on every decision (AU-2/12/CC7.1)

Transports:
  - stdio (Shape A/C local process — gateway spawns subprocess)
  - Streamable HTTP (Shape B MCP-client + Shape C MCP-server-over-HTTP)

Deferred to broker phase-2 (scope guard):
  - TODO[M4]: MCP tool-description / prompts.get prompt-injection content filter
  - TODO[P8]: Upstream MCP-server cert/SPIFFE pinning enforcement
  - TODO[P1-pool]: Per-tenant provider-key cache + per-tenant connection pools

v2.25.0 / P1 W3 Phase 2b-ii / YSG-RISK-054 (audit emission) + YSG-RISK-055 (posture).
"""
from __future__ import annotations

from yashigani.mcp._types import (
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
from yashigani.mcp._opa import query_mcp_decision, OpaDecisionResult

__all__ = [
    "McpBroker",
    "McpBrokerConfig",
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
    "OpaDecisionResult",
]
