"""
MCP Broker — core type definitions.

v2.25.0 / P1 W3 Phase 2b-ii
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class McpPosture(str, Enum):
    """
    MCP posture levels — MUST be derived from the physical channel.

    mcp-a: local stdio (OS pipe / Unix socket peer-cred / localhost-only bind)
    mcp-b: network Streamable-HTTP (single hop, TLS-terminated at gateway)
    mcp-c: chained relay (upstream JWT with verified SPIFFE chain present)

    BINDING REQUIREMENT (YSG-RISK-055 / LAURA-MCP-003):
      - mcp-a is assignable ONLY when the physical transport is a local OS pipe.
      - Any network-arriving request receives mcp-b or mcp-c regardless of what
        the caller asserts in the request body.
      - This invariant is enforced in _posture.py::derive_posture_from_channel().
        The OPA policy's mcp-a allowlist-exemption depends on this.
    """

    MCP_A = "mcp-a"
    MCP_B = "mcp-b"
    MCP_C = "mcp-c"


class McpTransportKind(str, Enum):
    """Physical transport type — drives posture derivation."""

    LOCAL_STDIO = "local-stdio"              # OS pipe fd pair (Shape A)
    NETWORK_STREAMABLE_HTTP = "network-streamable-http"  # TCP/TLS (Shape B)
    CHAINED_RELAY = "chained-relay"          # Upstream JWT present (Shape C)


@dataclass
class PostureBinding:
    """
    Evidence of how posture was derived — carried in JWT claim posture_binding.

    Not evaluated by OPA but required for audit trail.
    Per Nico spec §4 posture_binding object.
    """

    derived_from: str  # "physical_channel" | "tls_channel" | "spiffe_cert"
    channel_type: str  # McpTransportKind value

    def to_dict(self) -> dict:
        return {"derived_from": self.derived_from, "channel_type": self.channel_type}

    @classmethod
    def for_posture(cls, posture: McpPosture) -> "PostureBinding":
        mapping = {
            McpPosture.MCP_A: cls(
                derived_from="physical_channel",
                channel_type=McpTransportKind.LOCAL_STDIO.value,
            ),
            McpPosture.MCP_B: cls(
                derived_from="tls_channel",
                channel_type=McpTransportKind.NETWORK_STREAMABLE_HTTP.value,
            ),
            McpPosture.MCP_C: cls(
                derived_from="spiffe_cert",
                channel_type=McpTransportKind.CHAINED_RELAY.value,
            ),
        }
        return mapping[posture]


@dataclass
class McpCallContext:
    """
    Per-call context assembled by the broker before JWT issuance and OPA query.

    Populated by the transport layer from physical channel observation.
    The OPA input document is constructed from this context.
    """

    # Identity
    tenant_id: str
    agent_name: str
    user_id: str                       # opaque internal user_id (not PII)

    # Posture — MUST be derived from physical channel, NEVER from request body
    posture: McpPosture
    posture_binding: PostureBinding

    # MCP call subject — exactly one of tool / prompt / resource
    action: str                        # e.g. "mcp.tools.call"
    tool_name: Optional[str] = None
    tool_args_redacted: Optional[dict] = None
    prompt_name: Optional[str] = None
    resource_uri: Optional[str] = None

    # Multi-hop chain (mcp-c only) — list of SPIFFE URI strings
    upstream_chain: list[str] = field(default_factory=list)

    # Upstream JWT (mcp-c only) — raw JWT string from the relay caller
    upstream_jwt: Optional[str] = None

    # Correlation IDs
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Transport metadata (for OPA input enrichment)
    server_id: str = ""     # upstream MCP server identifier

    # FIX-C (Iris FIND-001): sensitivity labels for resource and prompt calls.
    # OPA policy (mcp.rego:380-391) escalates audit_capture for CONFIDENTIAL/RESTRICTED
    # access but the escalation was structurally unreachable because McpCallContext had
    # no sensitivity fields.  Populate from MCP protocol metadata (wire what's available;
    # default None).  Values: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | None
    resource_sensitivity: Optional[str] = None
    prompt_sensitivity: Optional[str] = None


@dataclass
class OpaDecision:
    """
    Decision returned from OPA mcp_decision compound document.

    Maps /v1/data/yashigani/mcp/mcp_decision response shape.
    """

    allow: bool
    deny_reason: str         # "ok" when allowed; label when denied
    redact_args: set[str]    # set of arg key names to redact
    audit_capture: bool      # escalate to full audit record when True
    rate_limit_key: Optional[str]
    elapsed_ms: Optional[int] = None


@dataclass
class BrokerDecision:
    """
    Final broker decision after OPA + JWT issuance.
    Emitted as audit events (MCP_CALL + OPA_DECISION_ON_MCP).
    """

    call_id: str
    allow: bool
    deny_reason: str
    opa_decision: OpaDecision
    issued_jwt: Optional[str] = None    # gateway-signed JWT (when allowed)
    chain_depth: int = 0
    elapsed_ms: Optional[int] = None
    error: Optional[str] = None         # internal error string (never client-visible)
