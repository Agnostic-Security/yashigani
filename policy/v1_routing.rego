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
#   input.prompt_sensitivity    — sensitivity of the REQUEST (prompt), from request-leg scan
#   input.response_sensitivity  — sensitivity of the RESPONSE CONTENT (from ResponseInspectionPipeline)
#                                  When pipeline is off, gateway sets this equal to prompt_sensitivity
#                                  (backward-compatible: old callers that only send response_sensitivity
#                                  still work because the MAX rule reads only response_sensitivity).
#   input.response_verdict      — inspection verdict (clean/suspicious/blocked)
#   input.pii_detected          — boolean, PII found in response
#
# v2.24.1 — GAP-3 / SEC-5:
#   The ceiling check evaluates MAX(prompt_sensitivity, response_sensitivity).
#   This means a CONFIDENTIAL response to a PUBLIC prompt is blocked for a
#   INTERNAL-ceiling identity — the most restrictive signal wins.
#   Backward compat: if prompt_sensitivity is absent (old callers), the rule
#   falls back to response_sensitivity-only (pre-v2.24.1 behaviour).

# effective_sensitivity — the stricter of prompt and response sensitivity ranks.
# When prompt_sensitivity is absent (old caller), effective = response_sensitivity.
# When response_sensitivity is absent, effective = prompt_sensitivity.
# GAP-1 catch-all: unknown strings map to rank 4 (above RESTRICTED) via the
# sensitivity_rank helper.
_effective_sensitivity_rank := r if {
    ps := sensitivity_rank(input.prompt_sensitivity)
    rs := sensitivity_rank(input.response_sensitivity)
    r := max([ps, rs])
}

_effective_sensitivity_rank := r if {
    not input.prompt_sensitivity
    r := sensitivity_rank(input.response_sensitivity)
}

_effective_sensitivity_rank := r if {
    not input.response_sensitivity
    r := sensitivity_rank(input.prompt_sensitivity)
}

default response_allowed := true

# Block response if effective sensitivity exceeds the caller's ceiling
response_allowed := false if {
    _effective_sensitivity_rank > sensitivity_rank(input.identity.sensitivity_ceiling)
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
    _effective_sensitivity_rank > sensitivity_rank(input.identity.sensitivity_ceiling)
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

# ── GET /v1/models — principal-aware model listing (GAP-001) ──────────────
#
# Controls whether a caller may enumerate the model list and what subset
# they receive.  Human principals with non-anonymous identity get the full
# list.  Service-account principals (internal_bearer, SPIFFE workloads) see
# only models they are authorised to call — the full topology must not be
# enumerable by compromised internal-mesh containers.
#
# Input schema:
#   input.identity.status         — active | suspended | anonymous
#   input.identity.kind           — human | service | admin | unknown
#   input.identity.sensitivity_ceiling — PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
#
# Decision document:
#   models_list_allowed           — bool: may the caller see any model list at all?
#   models_list_filter            — "full" | "restricted" | "denied"
#
# Operator override: push a data bundle with
#   data.yashigani.v1.models_list_policy.service_account_filter = "full"
# to grant service accounts the full list (opt-in, explicit, auditable).

default models_list_allowed := false

# Human principals with an active identity always get a model listing.
models_list_allowed if {
    input.identity.status == "active"
    input.identity.kind in {"human", "admin"}
}

# Service-account principals get RESTRICTED listing by default.
# Operator can grant full listing via data bundle override (see above).
models_list_allowed if {
    input.identity.status == "active"
    input.identity.kind in {"service", "unknown"}
}

# Filter level:
#   human / admin → full list
#   service / unknown → restricted (their allowed_models only, or all if allowed_models is empty and operator grants)
#   denied → should not reach this branch (models_list_allowed = false guards above)
default models_list_filter := "denied"

models_list_filter := "full" if {
    models_list_allowed
    input.identity.kind in {"human", "admin"}
}

models_list_filter := "restricted" if {
    models_list_allowed
    input.identity.kind in {"service", "unknown"}
    not _service_full_override
}

models_list_filter := "full" if {
    models_list_allowed
    input.identity.kind in {"service", "unknown"}
    _service_full_override
}

# Operator override gate — requires explicit data bundle entry.
_service_full_override if {
    data.yashigani.v1.models_list_policy.service_account_filter == "full"
}

models_list_decision := {
    "allow": models_list_allowed,
    "filter": models_list_filter,
    "reason": _models_list_reason,
}

_models_list_reason := "ok" if models_list_allowed
_models_list_reason := "identity_not_active_or_anonymous" if not models_list_allowed

# ── Catch-all proxy response-leg OPA (GAP-002) ───────────────────────────
#
# Evaluates whether the caller may receive the upstream MCP response.
# Mirrors the /v1/* response_decision shape.
#
# Input schema:
#   input.principal.status              — active | suspended | anonymous
#   input.principal.kind                — human | service | admin | unknown
#   input.principal.sensitivity_ceiling — PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
#   input.response_sensitivity          — PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
#   input.response_pii_detected         — boolean
#   input.request_path                  — the MCP tool path that was proxied
#
# When response_sensitivity is absent (pipeline off), the check runs with
# PUBLIC sensitivity — conservative but not blocking (pipeline-off default).
# Operators who enable the pipeline get full sensitivity enforcement.
#
# Fail-closed: unknown sensitivity strings map to rank 4 via sensitivity_rank.

default proxy_response_allowed := true

proxy_response_allowed := false if {
    _proxy_effective_sensitivity_rank > sensitivity_rank(input.principal.sensitivity_ceiling)
}

proxy_response_allowed := false if {
    input.response_pii_detected == true
    input.principal.kind != "admin"
    input.principal.kind != "human"
}

_proxy_effective_sensitivity_rank := r if {
    r := sensitivity_rank(input.response_sensitivity)
}

_proxy_effective_sensitivity_rank := 0 if {
    not input.response_sensitivity
}

default proxy_response_reason := "ok"

proxy_response_reason := "ok" if proxy_response_allowed

proxy_response_reason := "response_sensitivity_exceeds_ceiling" if {
    not proxy_response_allowed
    _proxy_effective_sensitivity_rank > sensitivity_rank(input.principal.sensitivity_ceiling)
}

proxy_response_reason := "response_pii_blocked_for_service_account" if {
    not proxy_response_allowed
    input.response_pii_detected == true
    input.principal.kind != "admin"
    input.principal.kind != "human"
}

proxy_response_decision := {
    "allow": proxy_response_allowed,
    "reason": proxy_response_reason,
}
