package yashigani

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# sensitivity_rank — shared helper (duplicated from v1_routing.rego because
# OPA policy packages are scoped; no cross-package function calls without data).
#
# GAP-1 catch-all (defence-in-depth, fail-closed):
# Any sensitivity string not in the canonical set is assigned rank 4 —
# above RESTRICTED.  An unrecognised label silently blocks delivery to ALL
# callers whose ceiling is below a hypothetical rank-4 level (i.e., everyone).
# ASVS V4.1.3: access control must default-deny on input validation failure.
# ---------------------------------------------------------------------------
sensitivity_rank(level) := 0 if level == "PUBLIC"
sensitivity_rank(level) := 1 if level == "INTERNAL"
sensitivity_rank(level) := 2 if level == "CONFIDENTIAL"
sensitivity_rank(level) := 3 if level == "RESTRICTED"
sensitivity_rank(level) := 4 if {
    not level in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
}

# ---------------------------------------------------------------------------
# agent_call_allowed — true when a calling agent is permitted to reach
# the target agent's path.
#
# Input fields (set by the gateway for /agents/* requests):
#   input.principal.type                  "agent"
#   input.principal.agent_id              calling agent's ID
#   input.principal.groups                list of RBAC group IDs the caller belongs to
#   input.target_agent.agent_id           target agent ID
#   input.target_agent.allowed_caller_groups  groups allowed to call this agent
#   input.target_agent.allowed_paths      path prefixes or exact paths the agent accepts
#   input.request.remainder_path          path after /agents/{target_agent_id}
# ---------------------------------------------------------------------------

agent_call_allowed if {
    input.principal.type == "agent"
    input.principal.agent_id != ""

    # Caller must be in at least one of the target's allowed_caller_groups
    group := input.principal.groups[_]
    group in input.target_agent.allowed_caller_groups

    # The remainder path must match at least one allowed path pattern
    _path_allowed(input.request.remainder_path, input.target_agent.allowed_paths)
}

# Path matching helper — exact or prefix
_path_allowed(path, allowed_paths) if {
    p := allowed_paths[_]
    _agent_path_matches(p, path)
}

_agent_path_matches(pattern, path) if { pattern == "**" }
_agent_path_matches(pattern, path) if { pattern == path }
_agent_path_matches(pattern, path) if {
    endswith(pattern, "/**")
    prefix := trim_suffix(pattern, "/**")
    startswith(path, concat("", [prefix, "/"]))
}
_agent_path_matches(pattern, path) if {
    not endswith(pattern, "/**")
    not contains(pattern, "*")
    startswith(path, concat("", [pattern, "/"]))
}

# ---------------------------------------------------------------------------
# agent_call_deny_reason — human-readable explanation used in audit events
# ---------------------------------------------------------------------------

agent_call_deny_reason := "caller_group_not_in_allowed_caller_groups" if {
    input.principal.type == "agent"
    not _caller_group_allowed
}

agent_call_deny_reason := "path_not_in_allowed_paths" if {
    input.principal.type == "agent"
    _caller_group_allowed
    not _path_allowed(input.request.remainder_path, input.target_agent.allowed_paths)
}

agent_call_deny_reason := "target_agent_not_in_data" if {
    input.principal.type == "agent"
    not input.target_agent.agent_id
}

_caller_group_allowed if {
    group := input.principal.groups[_]
    group in input.target_agent.allowed_caller_groups
}

# ---------------------------------------------------------------------------
# agent_response_allowed — v2.24.1 GAP-3 / SEC-5
#
# Response-leg OPA check for agent-to-agent calls (/agents/* path).
# Symmetric to the /v1/* response_allowed rule in v1_routing.rego.
# Closes the asymmetry identified in Iris SEC-5 (Ava GAP-3): /v1/* had a
# response-OPA-check; /agents/* did not.
#
# Input fields (set by the gateway AFTER receiving the upstream response):
#   input.caller.agent_id           calling agent's ID
#   input.caller.groups             list of RBAC group IDs the caller belongs to
#   input.caller.sensitivity_ceiling  caller's data clearance ceiling (PUBLIC…RESTRICTED)
#   input.target_agent.agent_id     target agent ID
#   input.response_sensitivity      sensitivity label of the response content
#   input.response_pii_detected     boolean — PII found in response body
#
# Evaluated at: /v1/data/yashigani/agent_response_decision
#
# Default: DENY (fail-closed). The caller must prove every condition.
# ---------------------------------------------------------------------------

default agent_response_allowed := false

agent_response_allowed if {
    # Both parties must be identified
    input.caller.agent_id != ""
    input.target_agent.agent_id != ""

    # Caller's clearance ceiling must accommodate response sensitivity
    response_rank := sensitivity_rank(input.response_sensitivity)
    ceiling_rank := sensitivity_rank(input.caller.sensitivity_ceiling)
    response_rank <= ceiling_rank

    # No PII gate trigger
    not input.response_pii_detected == true
}

# Compound decision object — mirrors v1_routing.rego response_decision shape
agent_response_decision := {
    "allow": agent_response_allowed,
    "reason": agent_response_deny_reason,
}

# deny reason helpers — only one should fire at a time
agent_response_deny_reason := "ok" if { agent_response_allowed }

agent_response_deny_reason := "response_sensitivity_exceeds_caller_ceiling" if {
    not agent_response_allowed
    input.caller.agent_id != ""
    input.target_agent.agent_id != ""
    response_rank := sensitivity_rank(input.response_sensitivity)
    ceiling_rank := sensitivity_rank(input.caller.sensitivity_ceiling)
    response_rank > ceiling_rank
}

agent_response_deny_reason := "pii_detected_in_response" if {
    not agent_response_allowed
    input.response_pii_detected == true
    # Only assign this reason when it is not also a ceiling violation
    response_rank := sensitivity_rank(input.response_sensitivity)
    ceiling_rank := sensitivity_rank(input.caller.sensitivity_ceiling)
    response_rank <= ceiling_rank
}

agent_response_deny_reason := "missing_agent_identity" if {
    not agent_response_allowed
    not input.caller.agent_id != ""
}

agent_response_deny_reason := "missing_agent_identity" if {
    not agent_response_allowed
    not input.target_agent.agent_id != ""
}
