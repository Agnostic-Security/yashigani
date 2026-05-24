# Yashigani v1.0 — OPA Routing Safety Net
#
# Second-pass validation of Optimization Engine routing decisions.
# Defence-in-depth: even if the OE has a bug, OPA catches policy violations.
#
# Input schema:
#   input.identity          — identity record (kind, groups, allowed_models, sensitivity_ceiling)
#   input.routing_decision  — OE decision (provider, model, route, sensitivity, rule)
#   input.request           — request metadata (path, method)

package yashigani.v1

import rego.v1

# ── Identity authorisation ────────────────────────────────────────────────

# Allow /v1/* requests from authenticated identities
default allow_v1 := false

allow_v1 if {
    input.identity.status == "active"
}

# ── Model access control ─────────────────────────────────────────────────

# Identity can use the selected model
default model_allowed := true

model_allowed if {
    count(input.identity.allowed_models) == 0  # No restriction = all models allowed
}

model_allowed if {
    input.routing_decision.model in input.identity.allowed_models
}

model_allowed if {
    "*" in input.identity.allowed_models
}

# ── Routing safety net ────────────────────────────────────────────────────

# CRITICAL: CONFIDENTIAL/RESTRICTED data must NEVER route to cloud
# unless the provider is in the trusted_cloud_providers list
default routing_safe := true

routing_safe := false if {
    input.routing_decision.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
    input.routing_decision.route == "cloud"
    not trusted_cloud_provider
}

trusted_cloud_provider if {
    input.routing_decision.provider in input.trusted_cloud_providers
}

# Identity cannot receive data above their sensitivity ceiling
default sensitivity_allowed := true

sensitivity_allowed := false if {
    sensitivity_rank(input.routing_decision.sensitivity) > sensitivity_rank(input.identity.sensitivity_ceiling)
}

sensitivity_rank(level) := 0 if level == "PUBLIC"
sensitivity_rank(level) := 1 if level == "INTERNAL"
sensitivity_rank(level) := 2 if level == "CONFIDENTIAL"
sensitivity_rank(level) := 3 if level == "RESTRICTED"

# GAP-1 catch-all (defence-in-depth, fail-closed):
# Any sensitivity string not in the canonical set is assigned rank 4 — above RESTRICTED.
# This means an unrecognised label (classifier bug, future label, empty string, injection)
# will never silently allow delivery; it will be blocked for every identity whose ceiling
# is below a hypothetical rank-4 level, i.e., all identities. Without this rule,
# `sensitivity_rank("UNKNOWN")` is undefined, the comparison is undefined, and
# `response_allowed` defaults to true — a silent allow. Rank 4 closes that gap.
# ASVS V4.1.3: access control must default-deny on input validation failure.
# Ava GAP-1 finding: ava-v241-opa-response-ceiling-verification.md, EDGE-1.
sensitivity_rank(level) := 4 if {
    not level in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
}

# ── Response-path enforcement ─────────────────────────────────────────────
#
# Evaluates whether a response can be delivered to the caller.
# Input schema (response path):
#   input.identity              — caller's identity record
#   input.response_sensitivity  — detected sensitivity of the response content
#   input.response_verdict      — inspection verdict (clean/suspicious/blocked)
#   input.pii_detected          — boolean, PII found in response

default response_allowed := true

# Block response if its sensitivity exceeds the caller's ceiling
response_allowed := false if {
    sensitivity_rank(input.response_sensitivity) > sensitivity_rank(input.identity.sensitivity_ceiling)
}

# Block response if inspection verdict is BLOCKED and identity is not admin
response_allowed := false if {
    input.response_verdict == "blocked"
    input.identity.kind != "admin"
}

response_decision := {
    "allow": response_allowed,
    "reason": response_reason,
}

response_reason := "ok" if response_allowed

response_reason := "response_sensitivity_exceeds_ceiling" if {
    not response_allowed
    sensitivity_rank(input.response_sensitivity) > sensitivity_rank(input.identity.sensitivity_ceiling)
}

response_reason := "response_blocked_by_inspection" if {
    not response_allowed
    input.response_verdict == "blocked"
}

# ── Combined decision ─────────────────────────────────────────────────────

decision := {
    "allow": allow_v1,
    "model_allowed": model_allowed,
    "routing_safe": routing_safe,
    "sensitivity_allowed": sensitivity_allowed,
    "reason": reason,
}

reason := "ok" if {
    allow_v1
    model_allowed
    routing_safe
    sensitivity_allowed
}

reason := "identity_not_active" if not allow_v1

reason := "model_not_allowed" if {
    allow_v1
    not model_allowed
}

reason := "routing_unsafe_sensitive_to_cloud" if {
    allow_v1
    model_allowed
    not routing_safe
}

reason := "sensitivity_ceiling_exceeded" if {
    allow_v1
    model_allowed
    routing_safe
    not sensitivity_allowed
}
