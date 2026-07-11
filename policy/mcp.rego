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
# Pinned to 9 as a policy CONSTANT — intentionally NOT operator-overridable at runtime.
# YSG-RISK-056 (CWE-15): the previous `data.yashigani.mcp.policy.chain_max_depth` override was
# writable at runtime via the OPA REST data API, letting any policy-write cert holder raise the
# limit and defeat the chain-depth guard. 9 covers complex multi-agent + MCP workflows; each hop
# is independently JWT/SPIFFE-authenticated, so depth is a sanity backstop, not the authN control.
# Changing it requires a reviewed policy edit + redeploy.
# TODO (Yashigani backlog): move this to a governed, audited admin-UI setting instead of a
# hardcoded constant; consider a no-repeat/cycle check so loop defense is identity-based, not depth.
mcp_chain_max_depth := 9

# ---------------------------------------------------------------------------
# Default: deny everything.  Every allow path must be explicit.
# ASVS V4.1.3 — access control must default-deny.
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# _spiffe_present — true when a non-empty SPIFFE URI string is present in input.
# FIX LAURA-MCP-004 (Info): non-string spiffe guard.
# Without is_string, a truthy non-string value (integer 1, boolean true,
# non-empty object) satisfies != "" and passes the SPIFFE check, allowing a
# request with a forged/non-string SPIFFE to reach the allow path.
_spiffe_present if {
    is_string(input.identity.spiffe)
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
#
# FIX LAURA-MCP-001 / LU-MCP-01 (HIGH): malformed-chain depth bypass.
# _chain_depth is ONLY computed from an array whose every element is a string.
# An object, array-of-objects, or array-of-ints yields 0 (fail-closed).
# Previously: count(obj) counted object keys, allowing a 1-key object to pass
# a depth ≤ 3 check and reach the mcp-c ALLOW path without a real chain.
# ---------------------------------------------------------------------------

_chain_depth := count(input.identity.chain) if {
    is_array(input.identity.chain)
    every e in input.identity.chain { is_string(e) }
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
#
# NOTE (LAURA-MCP-003 / FIX-5): MCP-A intentionally skips _tool_authz_ok.
# This is safe ONLY under the following BINDING TRANSPORT REQUIREMENTS.
# The transport/JWT chunk invoking this policy path MUST guarantee:
#
#   1. `posture` MUST be derived from the physical channel (OS pipe FD,
#      Unix-socket peer-cred, localhost-only bind) — NEVER from
#      `input.posture` in the request body. A network-arriving request with
#      a body that asserts posture=="mcp-a" MUST be rejected or reassigned
#      to mcp-b/mcp-c at the transport layer BEFORE this policy runs.
#
#   2. If the transport cannot positively guarantee that the request
#      originates from a local-only channel, mcp-a MUST NOT be assigned
#      and the request MUST be evaluated under mcp-b or mcp-c (which
#      enforce _tool_authz_ok).
#
#   3. This is not currently exploitable because no MCP handler invoking
#      this policy exists yet. This comment is an advance binding requirement
#      for the transport chunk authors. See: LAURA-MCP-003 tracked gate.
#      Maxine is registering this as a transport-chunk gate for P2/N-next.
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

# FIX LAURA-MCP-002 / LU-MCP-02 (MED): secret-redaction gaps.
# Added exact-match entries: aws_secret_access_key, aws_session_token,
# client_secret, refresh_token, session_token, pat, x-api-key.
# Exact-match is intentional — do NOT switch to substring matching, which
# would over-redact innocent keys like sort_key and cache_key.
# Nested-key redaction (e.g. config.api_key inside an object value) is the
# gateway CHS's (Credential Hiding Service) responsibility, not policy.
_secret_key_patterns := {
    "api_key", "apikey", "token", "secret", "password", "passwd", "credential",
    "credentials", "private_key", "private_token", "auth", "authorization",
    "bearer", "key", "access_key", "secret_key",
    "aws_secret_access_key", "aws_session_token", "client_secret",
    "refresh_token", "session_token", "pat", "x-api-key",
}

# FIX LAURA-MCP-004 (Info): non-object args_redacted guard.
# If args_redacted is not an object (e.g. an array or boolean), is_object fails
# and redact_args falls through to the else := set() — audit still emits an
# empty redact list rather than crashing or silently suppressing audit.
redact_args := ra if {
    allow
    _tool_present
    is_object(input.tool.args_redacted)
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
    # FIX-004: surface caller in the OPA decision output for audit visibility.
    #
    # input.caller.agent_id is the POLICY-AUTHOR EXTENSION POINT for per-agent
    # enforcement in custom policies.  Example: "deny if input.caller.agent_id
    # not in allowed_callers[input.tool.name]" to restrict which agents may call
    # which tools.
    #
    # NOTE: substantive per-agent enforcement is ALREADY done by the permission
    # model in the broker BEFORE this OPA query fires:
    #   • broker._check_connection_permit  — MCP_SERVER org-level allow-list
    #   • broker._check_tool_permit        — per-caller allowed_tools
    # This default policy does NOT re-implement those checks here (they are not
    # OPA-visible by design — see admin-plane-not-OPA-gated memory entry).
    # The caller field is surfaced for AUDIT RECORD COMPLETENESS so the OPA
    # decision log carries the caller identity alongside the tool decision.
    "caller": _mcp_caller_info,
}

# Safe caller extraction — guard against missing/non-string input.caller.agent_id.
_mcp_caller_info := {"agent_id": input.caller.agent_id} if {
    is_string(input.caller.agent_id)
} else := {"agent_id": ""}

# Use a safe getter to avoid undefined when allow is true (deny_reason is undefined)
deny_reason_value := deny_reason if { not allow }
deny_reason_value := "ok" if { allow }

ra := redact_args

# ---------------------------------------------------------------------------
# G-ORCH-OPA-1 — MCP egress decision: mcp_response_decision
#
# Evaluated AFTER the upstream tool result is obtained (by the broker's
# enforce_result() method), AFTER the content-filter + inspection step.
# Closes the gap documented in the orchestration buildsheet as G-ORCH-OPA-1:
# previously there was content-filter + inspection on the result, but NO OPA
# DECISION evaluating the result against the caller's sensitivity ceiling.
#
# Mirrors agent_response_decision (policy/agents.rego) for the MCP surface.
# The v1_routing.rego response_decision (gateway LLM egress) is the third
# sibling that follows the same shape.
#
# Input schema (caller + result):
#   input.caller.spiffe                 SPIFFE URI of the calling entity
#   input.caller.sensitivity_ceiling    caller's clearance level (string or int)
#   input.caller.groups                 list of RBAC group IDs (informational)
#   input.result.sensitivity            sensitivity label of the tool result
#   input.result.pii_detected           bool — PII found in the result body
#   input.tool.name                     (optional) tool that produced the result
#   input.agent.name                    (optional) agent being called
#
# Query path: /v1/data/yashigani/mcp/mcp_response_decision
#
# Fail-closed: default allow := false.  Any missing / malformed input → deny.
# Self-describing: carries policy_id + code + user_message (I6 / user-alert contract).
# ---------------------------------------------------------------------------

# Sensitivity rank helper (duplicated from agents.rego — packages are scoped).
# Maps content/ceiling level to an integer rank for comparison.
# Unknown string → rank 5 (above RESTRICTED — fail-closed for content operand).
_result_sensitivity_rank(level) := level if {
    is_number(level)
    level >= 1
}
_result_sensitivity_rank(level) := 0 if level == "PUBLIC"
_result_sensitivity_rank(level) := 1 if level == "INTERNAL"
_result_sensitivity_rank(level) := 2 if level == "CONFIDENTIAL"
_result_sensitivity_rank(level) := 3 if level == "RESTRICTED"
_result_sensitivity_rank(level) := 5 if {
    not is_number(level)
    not level in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
}

# _result_ceiling_rank — rank for the CEILING operand.
# Unknown ceiling string → UNDEFINED → rule does not fire → fail-closed deny.
# This is intentionally asymmetric with _result_sensitivity_rank:
# an unknown CONTENT label is most-sensitive (rank 5 = deny all);
# an unknown CEILING label is undefined (deny rather than treating as highest
# clearance — that would be permissive on a garbage input).
_result_ceiling_rank(level) := level if {
    is_number(level)
    level >= 1
}
_result_ceiling_rank(level) := 0 if level == "PUBLIC"
_result_ceiling_rank(level) := 1 if level == "INTERNAL"
_result_ceiling_rank(level) := 2 if level == "CONFIDENTIAL"
_result_ceiling_rank(level) := 3 if level == "RESTRICTED"

# Fail-closed default.
default mcp_response_allowed := false

mcp_response_allowed if {
    # Caller SPIFFE must be a non-empty string.
    is_string(input.caller.spiffe)
    input.caller.spiffe != ""

    # Caller ceiling must be a recognised level (unknown → _ceiling_rank undefined → deny).
    result_rank := _result_sensitivity_rank(input.result.sensitivity)
    ceiling_rank := _result_ceiling_rank(input.caller.sensitivity_ceiling)
    result_rank <= ceiling_rank

    # No PII gate trigger.
    not input.result.pii_detected == true
}

# Deny reasons — exactly one fires per deny case.
#
# Priority order (high → low):
#   1. missing_caller_identity (identity check first)
#   2. invalid_or_missing_caller_ceiling (ceiling must be parseable)
#   3. result_sensitivity_exceeds_caller_ceiling (ceiling breach, with or without PII)
#   4. pii_detected_in_result (PII only when ceiling is satisfied)
#
# Ceiling takes priority over PII: when result exceeds ceiling AND PII is present,
# the auditor sees the sensitivity-governance reason (ceiling) — that is the
# primary data-governance signal.  PII only fires when the result is within the
# ceiling (the caller has clearance but PII blocks delivery).
_mcp_response_deny_reason := "ok" if { mcp_response_allowed }

_mcp_response_deny_reason := "result_sensitivity_exceeds_caller_ceiling" if {
    not mcp_response_allowed
    is_string(input.caller.spiffe)
    input.caller.spiffe != ""
    # _ceiling_rank MUST be defined (meaning the ceiling string is valid).
    _result_ceiling_rank(input.caller.sensitivity_ceiling)
    result_rank := _result_sensitivity_rank(input.result.sensitivity)
    ceiling_rank := _result_ceiling_rank(input.caller.sensitivity_ceiling)
    # Ceiling breach: report regardless of whether PII is also present.
    result_rank > ceiling_rank
}

_mcp_response_deny_reason := "pii_detected_in_result" if {
    not mcp_response_allowed
    input.result.pii_detected == true
    is_string(input.caller.spiffe)
    input.caller.spiffe != ""
    # Only fire when ceiling is valid AND result is within ceiling.
    # If ceiling is also exceeded, the ceiling rule above takes priority.
    _result_ceiling_rank(input.caller.sensitivity_ceiling)
    result_rank := _result_sensitivity_rank(input.result.sensitivity)
    ceiling_rank := _result_ceiling_rank(input.caller.sensitivity_ceiling)
    result_rank <= ceiling_rank
}

_mcp_response_deny_reason := "invalid_or_missing_caller_ceiling" if {
    not mcp_response_allowed
    is_string(input.caller.spiffe)
    input.caller.spiffe != ""
    # _ceiling_rank is UNDEFINED for the provided ceiling — that is why we denied.
    # This rule fires regardless of PII status; an unrecognised ceiling is
    # structurally prior to all content-level checks.
    not _result_ceiling_rank(input.caller.sensitivity_ceiling)
}

_mcp_response_deny_reason := "missing_caller_identity" if {
    not mcp_response_allowed
    not is_string(input.caller.spiffe)
}

_mcp_response_deny_reason := "missing_caller_identity" if {
    not mcp_response_allowed
    is_string(input.caller.spiffe)
    input.caller.spiffe == ""
}

# Self-describing user messages (I6 / unified user-alert contract).
_mcp_response_user_message := msg if {
    mcp_response_allowed
    msg := "Tool result approved for delivery."
}

_mcp_response_user_message := msg if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "result_sensitivity_exceeds_caller_ceiling"
    msg := "The tool result contains information above your authorisation level and cannot be returned to you."
}

_mcp_response_user_message := msg if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "pii_detected_in_result"
    msg := "The tool result was blocked because personal information (PII) was detected in the response."
}

_mcp_response_user_message := msg if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "invalid_or_missing_caller_ceiling"
    msg := "The tool result could not be returned because your authorisation level is not recognised."
}

_mcp_response_user_message := msg if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "missing_caller_identity"
    msg := "The tool result was blocked because the caller identity could not be verified."
}

# Default user message (catches any deny reason not covered above).
default _mcp_response_user_message := "The tool result was blocked by the security policy."

_mcp_response_code := "MCP_RESULT_OK" if { mcp_response_allowed }
_mcp_response_code := "MCP_RESULT_SENSITIVITY_EXCEEDED" if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "result_sensitivity_exceeds_caller_ceiling"
}
_mcp_response_code := "MCP_RESULT_PII_BLOCKED" if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "pii_detected_in_result"
}
_mcp_response_code := "MCP_RESULT_CEILING_INVALID" if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "invalid_or_missing_caller_ceiling"
}
_mcp_response_code := "MCP_RESULT_IDENTITY_MISSING" if {
    not mcp_response_allowed
    _mcp_response_deny_reason == "missing_caller_identity"
}
default _mcp_response_code := "MCP_RESULT_DENIED"

# mcp_response_decision — compound egress decision document.
# Query path: /v1/data/yashigani/mcp/mcp_response_decision
mcp_response_decision := {
    "allow":        mcp_response_allowed,
    "deny_reason":  _mcp_response_deny_reason,
    "policy_id":    "mcp.response_decision",
    "code":         _mcp_response_code,
    "user_message": _mcp_response_user_message,
}

# ---------------------------------------------------------------------------
# 3.0 / YSG-RISK-060 — capability-envelope decision contract (self-describing)
#
# The capability-envelope INVOCATION HARD GATE and the refresh-time triage are
# enforced in the broker (deterministic structural diff is the authority — an
# LLM is never trusted to grant; see _envelope.py / _envelope_triage.py).  OPA
# does NOT re-derive the structural diff (that authority is code, by design).
#
# What lives here is the SELF-DESCRIBING DECISION CONTRACT (I6 / the unified
# user-alert envelope, 2026-06-06): stable policy_id + layman user_message +
# code keyed by the broker's envelope deny_reason, so the gateway can render a
# consistent layman explanation at the enforcement point WITHOUT a lookup
# table.  The broker passes its deny_reason; this maps it to the contract.
#
# Whether the re-approval ADMIN action is rendered as a real OPA admin-plane
# decision or as broker-internal-fail-closed + AdminSession+StepUp is contingent
# on Tiago design-call #1 (GAP-003/004 admin-plane OPA).  The fresh-TOTP step-up
# is UNCONDITIONAL either way (auth.stepup.assert_privileged_mutation).
# ---------------------------------------------------------------------------

# Stable policy identifier for the capability-envelope enforcement point.
capability_envelope_policy_id := "mcp.capability_envelope"

# capability_envelope_contract(reason) -> {policy_id, code, user_message}
# `reason` is the broker's envelope deny_reason (e.g.
# "capability_envelope_not_active", "capability_envelope_tool_not_approved",
# "capability_envelope_surface_stale", "refresh_expanding", "refresh_uncertain").
capability_envelope_contract(reason) := out if {
    out := {
        "policy_id": capability_envelope_policy_id,
        "code": "TOOL_SURFACE_REAPPROVAL_REQUIRED",
        "user_message": _capability_envelope_user_message(reason),
    }
}

_capability_envelope_user_message(reason) := msg if {
    reason == "capability_envelope_not_active"
    msg := "This imported tool has not been approved (or its approval was suspended pending review), so it cannot be used until an operator re-approves it."
}

_capability_envelope_user_message(reason) := msg if {
    reason == "capability_envelope_tool_not_approved"
    msg := "The tool you tried to use is not part of the approved capability set for this imported service, so it was blocked."
}

_capability_envelope_user_message(reason) := msg if {
    reason == "capability_envelope_surface_stale"
    msg := "This imported tool changed since it was last approved. It is blocked until an operator reviews the change."
}

_capability_envelope_user_message(reason) := msg if {
    startswith(reason, "refresh_")
    msg := "An imported tool tried to expand what it can do beyond what was approved, so it was blocked. An operator must review and re-approve the change before this tool can be used again."
}

# Fallback for any unmapped envelope reason — fail-closed wording (closed-world).
_capability_envelope_user_message(reason) := msg if {
    not _known_envelope_reason(reason)
    msg := "This imported tool was blocked by the capability-envelope control and requires operator review."
}

_known_envelope_reason(reason) if {
    reason in {
        "capability_envelope_not_active",
        "capability_envelope_tool_not_approved",
        "capability_envelope_surface_stale",
    }
}

_known_envelope_reason(reason) if { startswith(reason, "refresh_") }

# ---------------------------------------------------------------------------
# P3 — Filesystem MCP server tool gating (Laura threat model §5)
#
# These rules enforce the filesystem-specific OPA constraints for the
# @modelcontextprotocol/server-filesystem bundle.  They are checked by the
# gateway broker AFTER the global allow path when input.agent.name == "filesystem"
# (or any agent whose name matches a manifest with category=mcp_server).
#
# The global mcp.rego allow path (above) handles posture/SPIFFE/chain checks.
# These rules add the agent-specific per-tool authz layer (P9).
#
# References:
#   LAURA-FS-TM-001  path traversal (§2.2.1)
#   LAURA-FS-TM-003  ReDoS via search_files (§2.3)
#   LAURA-FS-TM-005  list_allowed_directories info-disclosure (§2.2.5)
# ---------------------------------------------------------------------------

# Filesystem read-only tool set (permitted by default)
_fs_readonly_tools := {
    "read_file",
    "read_multiple_files",
    "list_directory",
    "directory_tree",
    "get_file_info",
    "search_files",
}

# Filesystem write/mutating tool set (denied by default; allowed when write_posture=readwrite)
_fs_write_tools := {
    "write_file",
    "edit_file",
    "create_directory",
    "move_file",
}

# ---------------------------------------------------------------------------
# Path argument safety (LAURA-FS-TM-001 §5.1)
#
# Belt-and-suspenders against path traversal. Primary control is the
# named-volume mount boundary (the container has no /etc, no host paths).
# OPA adds a policy-layer pre-call assertion.
#
# FIX-P3-001 (broker-layer normalisation): The broker _normalize_tool_args()
# function iteratively percent-decodes + NFKC-normalises all path-bearing args
# BEFORE building the OPA input document.  A path that reaches OPA as
# "..%2fetc%2fshadow" is therefore decoded to "../etc/shadow" before the
# literal "../" check fires here — closing the encoded-traversal bypass.
#
# This OPA rule is the belt-and-suspenders layer; broker normalisation is the
# primary decode layer.  Both are required (defence-in-depth).
#
# Rules:
#   - args.path must not contain "../"
#   - args.path must not start with "/" (absolute paths rejected;
#     the server's --allowed-dir is the root, not the container's root)
#   - args.path must not contain residual encoded dots/slashes (%2e, %2f)
#     after the broker normalization layer.  A path that still contains these
#     patterns post-decode is anomalous and likely adversarial.
#   - When no path arg is present (e.g. list_directory of root), pass.
#
# FIX-P3-002: singular args.path check only. args.paths array check is in
# _fs_paths_array_safe below.
# ---------------------------------------------------------------------------

_fs_path_arg_safe(args) if {
    is_string(args.path)
    not contains(args.path, "../")
    not startswith(args.path, "/")
    # Belt-and-suspenders: reject residual percent-encoded dots/slashes that
    # survived broker normalisation.  Lower-case comparison is sufficient
    # because unquote() produces lower-case hex and NFKC does not introduce
    # upper-case percent sequences.
    not contains(lower(args.path), "%2e")
    not contains(lower(args.path), "%2f")
}

_fs_path_arg_safe(args) if {
    not args.path
}

# ---------------------------------------------------------------------------
# FIX-P3-002 — paths-array safety (read_multiple_files)
#
# read_multiple_files uses args.paths (an array).  _fs_path_arg_safe only
# checks args.path (singular).  An array traversal bypassed the old check.
#
# _fs_paths_array_safe(args) is satisfied when:
#   - args.paths is absent (tool uses singular args.path), OR
#   - args.paths is present, is an array, and EVERY element passes the
#     same checks as _fs_path_arg_safe (no "../", no leading "/",
#     no residual %2e/%2f after normalisation).
#
# Also covers move_file's args.source and args.destination path args.
# ---------------------------------------------------------------------------

# Paths array absent (single-path tools) — safe
_fs_paths_array_safe(args) if {
    not args.paths
}

# Paths array present — every element must be safe
_fs_paths_array_safe(args) if {
    is_array(args.paths)
    every p in args.paths {
        is_string(p)
        not contains(p, "../")
        not startswith(p, "/")
        not contains(lower(p), "%2e")
        not contains(lower(p), "%2f")
    }
}

# FIX-P3-002 (move_file): validate args.source and args.destination separately.
# move_file is in _fs_write_tools so it is already denied in readonly posture.
# This helper guards the readwrite path.
_fs_move_args_safe(args) if {
    # source must not traverse
    is_string(args.source)
    not contains(args.source, "../")
    not startswith(args.source, "/")
    not contains(lower(args.source), "%2e")
    not contains(lower(args.source), "%2f")
    # destination must not traverse
    is_string(args.destination)
    not contains(args.destination, "../")
    not startswith(args.destination, "/")
    not contains(lower(args.destination), "%2e")
    not contains(lower(args.destination), "%2f")
}

_fs_move_args_safe(args) if {
    not args.source
    not args.destination
}

# ---------------------------------------------------------------------------
# directory_tree depth cap (LAURA-FS-TM-003 §5.2)
#
# Prevents recursive directory traversal DoS.
# maxDepth must be <= 5 or absent (broker enforces cap when absent).
# ---------------------------------------------------------------------------

_fs_directory_tree_safe(args) if {
    not args.maxDepth
}

_fs_directory_tree_safe(args) if {
    to_number(args.maxDepth) <= 5
}

# ---------------------------------------------------------------------------
# search_files pattern length cap (LAURA-FS-TM-003 §5.3 — ReDoS)
#
# The glob package has had historical ReDoS vulnerabilities.
# Cap pattern length at 256 characters.
# ---------------------------------------------------------------------------

_fs_search_files_safe(args) if {
    is_string(args.pattern)
    count(args.pattern) <= 256
}

_fs_search_files_safe(args) if {
    not args.pattern
}

# ---------------------------------------------------------------------------
# filesystem_tool_allowed — the compound filesystem tool decision
#
# Called from the gateway broker's per-agent authz layer.
# Returns true when the tool call is permitted for the filesystem bundle.
# Fail-closed: default := false means any unmatched combination is denied.
# ---------------------------------------------------------------------------

default filesystem_tool_allowed := false

# Read-only tools (singular args.path): PERMIT with path validation.
# Excludes read_multiple_files (uses args.paths array — separate rule below).
# Excludes directory_tree (depth cap) and search_files (pattern cap).
# Excludes list_allowed_directories (always denied — info-disclosure).
filesystem_tool_allowed if {
    input.tool.name in _fs_readonly_tools
    not input.tool.name == "list_allowed_directories"
    not input.tool.name == "directory_tree"
    not input.tool.name == "search_files"
    not input.tool.name == "read_multiple_files"
    _fs_path_arg_safe(input.tool.args)
}

# FIX-P3-002: read_multiple_files — validate every path in the array.
filesystem_tool_allowed if {
    input.tool.name == "read_multiple_files"
    _fs_paths_array_safe(input.tool.args)
}

# directory_tree: depth cap + path validation
filesystem_tool_allowed if {
    input.tool.name == "directory_tree"
    _fs_path_arg_safe(input.tool.args)
    _fs_directory_tree_safe(input.tool.args)
}

# search_files: path + pattern-length cap
filesystem_tool_allowed if {
    input.tool.name == "search_files"
    _fs_path_arg_safe(input.tool.args)
    _fs_search_files_safe(input.tool.args)
}

# Write tools: PERMIT only when write_posture=readwrite in data bundle.
# Operator sets: PUT /v1/data/yashigani/mcp/filesystem_write_posture "readwrite"
# FIX-P3-002: move_file uses source/destination args — validated separately.
_fs_write_posture := p if {
    p := data.yashigani.mcp.filesystem_write_posture
} else := "readonly"

filesystem_tool_allowed if {
    input.tool.name in _fs_write_tools
    not input.tool.name == "move_file"
    _fs_write_posture == "readwrite"
    _fs_path_arg_safe(input.tool.args)
}

# FIX-P3-002: move_file uses source + destination, not args.path.
filesystem_tool_allowed if {
    input.tool.name == "move_file"
    _fs_write_posture == "readwrite"
    _fs_move_args_safe(input.tool.args)
}

# list_allowed_directories: ALWAYS denied (info-disclosure — Laura §2.2.5)
# No allow rule matches for this tool; default := false catches it.

# ---------------------------------------------------------------------------
# filesystem_deny_reason — reason string for denied filesystem tool calls
# ---------------------------------------------------------------------------

filesystem_deny_reason := "fs_path_traversal_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    contains(input.tool.args.path, "../")
}

filesystem_deny_reason := "fs_path_traversal_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    startswith(input.tool.args.path, "/")
}

# FIX-P3-001 belt-and-suspenders: residual encoded traversal after normalisation
filesystem_deny_reason := "fs_path_traversal_encoded_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    contains(lower(input.tool.args.path), "%2e")
}

filesystem_deny_reason := "fs_path_traversal_encoded_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    contains(lower(input.tool.args.path), "%2f")
}

# FIX-P3-002: traversal in paths array (read_multiple_files)
filesystem_deny_reason := "fs_paths_array_traversal_attempt" if {
    not filesystem_tool_allowed
    input.tool.name == "read_multiple_files"
    is_array(input.tool.args.paths)
    some p in input.tool.args.paths
    is_string(p)
    contains(p, "../")
}

filesystem_deny_reason := "fs_paths_array_traversal_attempt" if {
    not filesystem_tool_allowed
    input.tool.name == "read_multiple_files"
    is_array(input.tool.args.paths)
    some p in input.tool.args.paths
    is_string(p)
    startswith(p, "/")
}

filesystem_deny_reason := "fs_directory_tree_depth_exceeded" if {
    not filesystem_tool_allowed
    input.tool.name == "directory_tree"
    is_number(to_number(input.tool.args.maxDepth))
    to_number(input.tool.args.maxDepth) > 5
}

filesystem_deny_reason := "fs_search_pattern_too_long" if {
    not filesystem_tool_allowed
    input.tool.name == "search_files"
    is_string(input.tool.args.pattern)
    count(input.tool.args.pattern) > 256
}

filesystem_deny_reason := "fs_tool_denied_readonly_posture" if {
    not filesystem_tool_allowed
    input.tool.name in _fs_write_tools
    _fs_write_posture == "readonly"
}

filesystem_deny_reason := "fs_list_allowed_directories_denied" if {
    not filesystem_tool_allowed
    input.tool.name == "list_allowed_directories"
}

default filesystem_deny_reason := "fs_tool_not_permitted"

# ===========================================================================
# §P3-GIT — git MCP-server per-tool authorisation (GIT-TM-001..004)
#
# Called from the gateway broker's second OPA gate after a global
# mcp_decision allow.  Fail-closed: default := false.
#
# Tool sets:
#   _git_read_tools  — 7 read-only tools (always permitted)
#   _git_write_tools — 5 mutating tools (only when write_posture=readwrite)
#
# Helpers:
#   _git_repo_path_safe(args)  — GIT-TM-001 belt-and-suspenders path guard
#   _git_timestamp_safe(ts)    — GIT-TM-004 git_log option injection guard
# ===========================================================================

# Read-only tools (Laura §5 — default posture)
_git_read_tools := {
    "git_status",
    "git_diff_unstaged",
    "git_diff_staged",
    "git_diff",
    "git_log",
    "git_show",
    "git_init",
}

# Mutating tools — denied by default; permitted only with write_posture=readwrite
_git_write_tools := {
    "git_add",
    "git_commit",
    "git_reset",
    "git_checkout",
    "git_create_branch",
}

# ---------------------------------------------------------------------------
# _git_repo_path_safe — GIT-TM-001 belt-and-suspenders path guard
#
# The upstream server enforces --repository /workspace when the arg is
# present.  OPA enforces the path boundary as a second layer:
#   - Must start with /workspace
#   - Must not contain ../ (traversal)
#   - Must not contain %2e (percent-encoded dot — decoded upstream by broker)
#   - Must not contain %2f (percent-encoded slash)
# When args.repo_path is absent (upstream uses the configured default),
# OPA passes — the subprocess --repository /workspace is the binding
# constraint (GIT-TM-001).
# ---------------------------------------------------------------------------

_git_repo_path_safe(args) if {
    not args.repo_path
}

_git_repo_path_safe(args) if {
    is_string(args.repo_path)
    startswith(args.repo_path, "/workspace")
    not contains(args.repo_path, "../")
    not contains(lower(args.repo_path), "%2e")
    not contains(lower(args.repo_path), "%2f")
}

# ---------------------------------------------------------------------------
# _git_timestamp_safe — GIT-TM-004 git_log option injection guard
#
# git_log passes start_timestamp / end_timestamp directly to repo.git.log()
# as argv elements via ['--since', ts, '--until', ts].  A value beginning
# with '--' injects a git top-level option (e.g. --exec-path).
# Reject: anything starting with '-', and percent-encoded equivalents.
# Allow: null/absent, ISO 8601 dates, git relative date strings.
# Allowlist pattern: [A-Za-z0-9 .:+\-/]+ (no leading dashes, no control chars)
# ---------------------------------------------------------------------------

_git_timestamp_safe(ts) if {
    ts == null
}

_git_timestamp_safe(ts) if {
    not ts
}

_git_timestamp_safe(ts) if {
    is_string(ts)
    not startswith(ts, "-")
    not contains(lower(ts), "%2d")
    regex.match(`^[A-Za-z0-9 .:+\-/]+$`, ts)
}

# ---------------------------------------------------------------------------
# git_tool_allowed — compound git tool decision
#
# Fail-closed: default := false catches any unmatched combination.
# ---------------------------------------------------------------------------

default git_tool_allowed := false

# Read tools: PERMIT with repo_path validation.
git_tool_allowed if {
    input.tool.name in _git_read_tools
    not input.tool.name == "git_log"
    _git_repo_path_safe(input.tool.args)
}

# git_log: additionally validate timestamp args (GIT-TM-004)
# BUG-7-FIX (Ava 2026-05-30): use object.get() to default absent timestamp fields
# to null before passing to _git_timestamp_safe.  In OPA, accessing an absent
# key via input.tool.args.start_timestamp yields `undefined`, and passing
# undefined to a function that only handles null/string caused the entire rule
# body to be undefined → git_tool_allowed=false even for valid calls without
# timestamps.  Fix: object.get(args, key, null) guarantees the argument is
# either a string or null — both handled by _git_timestamp_safe.
git_tool_allowed if {
    input.tool.name == "git_log"
    _git_repo_path_safe(input.tool.args)
    _git_timestamp_safe(object.get(input.tool.args, "start_timestamp", null))
    _git_timestamp_safe(object.get(input.tool.args, "end_timestamp", null))
}

# Write tools: PERMIT only when write_posture=readwrite.
# Operator sets via data bundle: PUT /v1/data/yashigani/mcp/git_write_posture "readwrite"
_git_write_posture := p if {
    p := data.yashigani.mcp.git_write_posture
} else := "readonly"

git_tool_allowed if {
    input.tool.name in _git_write_tools
    _git_write_posture == "readwrite"
    _git_repo_path_safe(input.tool.args)
}

# ---------------------------------------------------------------------------
# git_deny_reason — reason string for denied git tool calls
# ---------------------------------------------------------------------------

git_deny_reason := "git_repo_path_traversal_attempt" if {
    not git_tool_allowed
    is_string(input.tool.args.repo_path)
    contains(input.tool.args.repo_path, "../")
}

git_deny_reason := "git_repo_path_outside_workspace" if {
    not git_tool_allowed
    is_string(input.tool.args.repo_path)
    not startswith(input.tool.args.repo_path, "/workspace")
}

git_deny_reason := "git_timestamp_option_injection" if {
    not git_tool_allowed
    input.tool.name == "git_log"
    is_string(input.tool.args.start_timestamp)
    startswith(input.tool.args.start_timestamp, "-")
}

git_deny_reason := "git_timestamp_option_injection" if {
    not git_tool_allowed
    input.tool.name == "git_log"
    is_string(input.tool.args.end_timestamp)
    startswith(input.tool.args.end_timestamp, "-")
}

git_deny_reason := "git_tool_denied_readonly_posture" if {
    not git_tool_allowed
    input.tool.name in _git_write_tools
    _git_write_posture == "readonly"
}

default git_deny_reason := "git_tool_not_permitted"
