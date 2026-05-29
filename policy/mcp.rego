# Yashigani MCP OPA Policy — P1 W3 Phase 2b-i
#
# Enforces access control for MCP-posture requests proxied through the gateway.
# Covers Shape A (stdio local), Shape B (Streamable-HTTP remote), Shape C
# (multi-hop chained) as defined in the Yashigani manifest schema §3.2.
#
# P-findings implemented:
#   P3  (HIGH)  — MCP input schema + policy (this file)
#   P9  (MEDIUM) — MCP-B per-tool authz enforced at gateway inbound
#
# Input schema: policy/mcp-input.schema.json
# Query path:   /v1/data/yashigani/mcp/mcp_decision
#               /v1/data/yashigani/mcp/allow
#
# Multi-hop identity chain (MCP-C / Lu-Gap-02):
#   Consumed here; populated by the MCP identity JWT in a later chunk (P2/N3).
#   The policy is ready for the JWT landing — test with synthetic input now.
#
# Fail-closed: default allow := false.  Any missing / malformed input → deny.
# Operator overrides: push a data bundle to data.yashigani.mcp.policy.*

package yashigani.mcp

import rego.v1

# ---------------------------------------------------------------------------
# Constants / tunables (operator-overridable via data bundle)
# ---------------------------------------------------------------------------

# Maximum allowed identity-chain depth for MCP-C multi-hop calls.
# Default: 3 (origin + 1 relay + gateway).  Operators may increase this via:
#   data.yashigani.mcp.policy.chain_max_depth = <n>
mcp_chain_max_depth := d if {
    d := data.yashigani.mcp.policy.chain_max_depth
} else := 3

# ---------------------------------------------------------------------------
# Default: deny everything.  Every allow path must be explicit.
# ASVS V4.1.3 — access control must default-deny.
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# _spiffe_present — true when a non-empty SPIFFE URI is present in input
_spiffe_present if {
    input.identity.spiffe != ""
}

# _posture_valid — sanity-check the posture string (not in canonical set → deny)
_posture_valid if {
    input.posture in {"mcp-a", "mcp-b", "mcp-c"}
}

# _exactly_one_subject — exactly one of tool / prompt / resource is present.
# Fail-closed: if none are present, the request is incomplete (deny).
# Enforces the oneOf exclusivity from mcp-input.schema.json.
_tool_present     if { input.tool.name != "" }
_prompt_present   if { input.prompt.name != "" }
_resource_present if { input.resource.uri != "" }

_exactly_one_subject if {
    _tool_present
    not _prompt_present
    not _resource_present
}

_exactly_one_subject if {
    _prompt_present
    not _tool_present
    not _resource_present
}

_exactly_one_subject if {
    _resource_present
    not _tool_present
    not _prompt_present
}

# ---------------------------------------------------------------------------
# Identity chain depth guard — MCP-C multi-hop (Lu-Gap-02)
#
# When input.identity.chain is present (non-null, non-empty array), the chain
# depth must not exceed mcp_chain_max_depth.  A chain with depth > max is
# indicative of a routing loop, a confused-deputy attack, or an injection
# attempt — deny and force audit capture.
#
# When input.identity.chain is absent (mcp-a / mcp-b), the guard is skipped.
# ---------------------------------------------------------------------------

_chain_depth := count(input.identity.chain) if {
    input.identity.chain
    count(input.identity.chain) > 0
} else := 0

_chain_depth_ok if {
    _chain_depth <= mcp_chain_max_depth
}

# ---------------------------------------------------------------------------
# Core allow rules — posture-aware
# ---------------------------------------------------------------------------

# MCP-A (local stdio, Shape A):
#   - SPIFFE required
#   - Chain absent or depth ≤ max
#   - Valid posture
#   - Exactly one subject (tool OR prompt OR resource)
#   - Action must be a recognised MCP action prefix
allow if {
    input.posture == "mcp-a"
    _posture_valid
    _spiffe_present
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
}

# MCP-B (remote Streamable-HTTP, Shape B):
#   Same as MCP-A plus per-tool authz gate (_tool_authz_ok).
#   For non-tool actions, the authz check is a no-op (passes through).
allow if {
    input.posture == "mcp-b"
    _posture_valid
    _spiffe_present
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_authz_ok
}

# MCP-C (multi-hop chained, Shape C):
#   Chain MUST be present and non-empty (chain is the core assertion of MCP-C).
#   Chain depth must be within limit.
allow if {
    input.posture == "mcp-c"
    _posture_valid
    _spiffe_present
    # MCP-C requires an explicit chain
    _chain_depth > 0
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_authz_ok
}

# ---------------------------------------------------------------------------
# P9 — MCP-B per-tool authz (exposed tool allowlist)
#
# When data.yashigani.mcp.exposed_tools is populated (operator data bundle),
# it acts as the canonical allowlist of tool names exposed at the gateway
# inbound.  Any tool call for a name NOT in the allowlist → deny.
#
# When the allowlist is absent or empty (default install), the gate is open —
# all tool names are permitted. This preserves backward-compat for installs
# that have not configured a tool allowlist.
#
# Operators populate data.yashigani.mcp.exposed_tools as a set of strings:
#   PUT /v1/data/yashigani/mcp/exposed_tools ["web_search", "code_exec", ...]
# ---------------------------------------------------------------------------

_tool_authz_ok if {
    # No tool subject on this request — authz gate is not applicable
    not _tool_present
}

# Resolve the exposed_tools allowlist — default to empty set when absent in data bundle.
# This makes the gate open (backward-compat) when operators have not loaded a bundle.
_exposed_tools := data.yashigani.mcp.exposed_tools if {
    data.yashigani.mcp.exposed_tools
} else := set()

_tool_authz_ok if {
    # Tool present: allowlist absent or empty → open gate (backward-compat)
    _tool_present
    count(_exposed_tools) == 0
}

_tool_authz_ok if {
    # Tool present: allowlist populated → tool name must be in it
    _tool_present
    count(_exposed_tools) > 0
    input.tool.name in _exposed_tools
}

# ---------------------------------------------------------------------------
# Action recognition
# ---------------------------------------------------------------------------

_recognised_actions := {
    "mcp.tools.call",
    "mcp.tools.list",
    "mcp.prompts.list",
    "mcp.prompts.get",
    "mcp.resources.list",
    "mcp.resources.read",
    "mcp.resources.subscribe",
    "mcp.ping",
    "mcp.initialize",
    "mcp.sampling.createMessage",
}

_action_recognised if {
    input.action in _recognised_actions
}

# ---------------------------------------------------------------------------
# Deny reasons — used by the gateway for audit events and error bodies.
# Only one should fire per request (first matching wins in priority order).
# ---------------------------------------------------------------------------

deny_reason := "ok" if { allow }

deny_reason := "missing_spiffe_identity" if {
    not allow
    not _spiffe_present
}

deny_reason := "invalid_posture" if {
    not allow
    _spiffe_present
    not _posture_valid
}

deny_reason := "chain_depth_exceeded" if {
    not allow
    _spiffe_present
    _posture_valid
    not _chain_depth_ok
}

deny_reason := "multiple_subjects_in_request" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    not _exactly_one_subject
    # At least two of the three subjects are simultaneously present
    _subject_count >= 2
}

deny_reason := "missing_subject" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    not _exactly_one_subject
    _subject_count == 0
}

deny_reason := "unrecognised_action" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    not _action_recognised
}

deny_reason := "tool_not_in_exposed_allowlist" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_present
    count(_exposed_tools) > 0
    not input.tool.name in _exposed_tools
}

deny_reason := "mcp_c_requires_chain" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    input.posture == "mcp-c"
    _chain_depth == 0
}

# Count how many subjects are present (used by deny_reason selectors above)
_tool_count := 1 if { _tool_present } else := 0
_prompt_count := 1 if { _prompt_present } else := 0
_resource_count := 1 if { _resource_present } else := 0

_subject_count := _tool_count + _prompt_count + _resource_count

# ---------------------------------------------------------------------------
# redact_args — list of tool argument keys to redact before logging
#
# When a tool call is in scope, any argument key whose name contains a
# secret-like pattern is added to the redact list.  The gateway uses this
# list to replace values with "<REDACTED>" before writing audit records.
#
# This covers common patterns (api_key, token, secret, password, credential).
# The source-of-truth redaction of the actual bytes must happen in the gateway
# CHS (Credential Hiding Service) before populating args_redacted in the input.
# This list is a secondary policy-layer assertion for audit enforcement.
# ---------------------------------------------------------------------------

_secret_key_patterns := {
    "api_key", "apikey", "token", "secret", "password", "passwd", "credential",
    "credentials", "private_key", "private_token", "auth", "authorization",
    "bearer", "key", "access_key", "secret_key",
}

redact_args := ra if {
    allow
    _tool_present
    input.tool.args_redacted
    ra := {k |
        k := object.keys(input.tool.args_redacted)[_]
        lower(k) in _secret_key_patterns
    }
} else := set()

# ---------------------------------------------------------------------------
# audit_capture — true when gateway must write a full audit record
#
# Always capture on:
#   - Any deny
#   - CONFIDENTIAL / RESTRICTED resource/prompt access
#   - Any chain-depth > 1 (multi-hop)
#   - Any tool call with non-empty redact_args
# ---------------------------------------------------------------------------

default audit_capture := false

audit_capture if { not allow }

audit_capture if {
    allow
    _resource_present
    input.resource.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
}

audit_capture if {
    allow
    _prompt_present
    input.prompt.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
}

audit_capture if {
    allow
    _chain_depth > 1
}

audit_capture if {
    allow
    _tool_present
    count(redact_args) > 0
}

# ---------------------------------------------------------------------------
# rate_limit_key — bucket key for the gateway rate limiter
#
# Non-null when the gateway should apply a per-caller rate limit for this action.
# Format: "<spiffe_hash>/<action>[/<tool_name>]"
#
# The SPIFFE URI is hashed (sha256 hex) to keep the key short and avoid
# leaking identity topology into the rate-limit store.
# ---------------------------------------------------------------------------

rate_limit_key := k if {
    allow
    _tool_present
    k := sprintf("%s/%s/%s", [
        _spiffe_hash,
        input.action,
        input.tool.name,
    ])
}

rate_limit_key := k if {
    allow
    not _tool_present
    k := sprintf("%s/%s", [
        _spiffe_hash,
        input.action,
    ])
}

default rate_limit_key := null

_spiffe_hash := h if {
    h := crypto.sha256(input.identity.spiffe)
} else := "anonymous"

# ---------------------------------------------------------------------------
# mcp_decision — compound decision document
#
# The gateway queries /v1/data/yashigani/mcp/mcp_decision.
# Shape matches mcp-input.schema.json §definitions.mcp_decision.
# ---------------------------------------------------------------------------

mcp_decision := {
    "allow": allow,
    "deny_reason": deny_reason_value,
    "redact_args": ra,
    "audit_capture": audit_capture,
    "rate_limit_key": rate_limit_key,
}

# Use a safe getter to avoid undefined when allow is true (deny_reason is undefined)
deny_reason_value := deny_reason if { not allow }
deny_reason_value := "ok" if { allow }

ra := redact_args
