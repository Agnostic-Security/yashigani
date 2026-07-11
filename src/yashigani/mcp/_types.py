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

    # G-ORCH-OPA-1 — egress: caller's declared sensitivity ceiling.
    # Set from the caller's identity/session before calling enforce_result().
    # Defaults to None; OPA's mcp_response_decision fails-closed when absent
    # (undefined _ceiling_rank → deny).  Transport layers MUST populate this
    # from the authenticated caller identity before the egress check.
    caller_sensitivity_ceiling: Optional[str] = None

    # 3.1 Phase 1 — calling agent's identity for MCP authorization decisions.
    # Populated by the transport layer; flows into the OPA input so policies
    # can make caller-aware decisions (e.g. per-caller rate limits, allow-lists).
    # Values:
    #   - agent_id string: from AgentAuthMiddleware (request.state.agent_id)
    #     for authenticated agent-originated MCP calls.
    #   - "gateway:orchestrator": reserved service identity for the gateway's
    #     own orchestrator when it issues MCP calls via the gateway-mediated
    #     self-call path (detected via X-Yashigani-Orchestration-Depth header).
    #   - None (default): caller not identified / unauthenticated path.
    # Phase 1 is ADDITIVE — unbound policies are no-ops on this field.
    caller_agent_id: Optional[str] = None

    # 3.1 Phase 3 — per-caller tool allowlist.
    # Populated by the MCP router runtime from the identity registry (field
    # IdentityRecord.allowed_tools for the caller identified by caller_agent_id).
    # Enforcement in McpBroker.enforce():
    #   - None / empty list → no per-caller tool restriction (all tools allowed
    #     for this caller, subject to OPA and other gates).
    #   - Non-empty list → only tools in the list are permitted for this caller;
    #     any other tool_name results in deny_reason="tool_not_permitted".
    # "gateway:orchestrator" is exempt from this check (unrestricted access to
    # all tools on any registered MCP server).
    caller_allowed_tools: Optional[list[str]] = None

    # 3.1 Phase 4 (group/user narrowing) — caller's group membership for the
    # connection allow-list check in _check_connection_permit.
    # Populated by mcp_router_runtime from the identity registry when the
    # caller's identity is resolved via get_by_slug(user_id).
    # Empty list → org-only check (same as current behaviour when identity absent).
    caller_group_ids: list[str] = field(default_factory=list)

    # 3.1 Phase 4 (group/user narrowing) — caller's email (human principals only).
    # PRESENTATION FIELD ONLY — never passed as the authz key to the resolver.
    # The authz key for the "user" principal tier is ctx.user_id (the identity_id
    # idnt_{12hex} from the identity registry, set by mcp_router_runtime after 3.1
    # UID unification — NOT a slug and NOT PII).
    # Populated when the caller kind is "human"/"user" AND an X-OpenWebUI-User-Email
    # header is present.  Serves as the "is this a human?" discriminator in
    # _check_connection_permit.  None for agents, orchestrator, unauthenticated, and
    # any path where the identity registry is absent or the kind is not "human"/"user".
    caller_user_email: Optional[str] = None


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


@dataclass
class EgressDecision:
    """
    G-ORCH-OPA-1 — MCP egress decision after OPA mcp_response_decision check.

    Returned by McpBroker.enforce_result().  When allow=False the transport
    layer MUST NOT return the tool result to the caller — the result is
    withheld and the deny shape (deny_reason, code, user_message) is returned
    as the error body to the calling agent.

    Fields mirror OpaResponseDecisionResult so callers need only inspect this
    dataclass; they do not need to import from _opa directly.
    """

    allow: bool
    deny_reason: str    # "ok" when allowed; label when denied
    policy_id: str      # "mcp.response_decision" (stable self-describing ID)
    code: str           # MCP_RESULT_OK | MCP_RESULT_* (machine-readable)
    user_message: str   # layman explanation (safe to surface to calling agent)
    elapsed_ms: int
    error: Optional[str] = None   # internal OPA error string (never client-visible)
