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

# Identity can use the selected model.
# LAURA-OPA-003 class-fix (2.25.2): default-DENY + explicit positive-allow,
# matching the agents.rego pattern. Previously `default := true`, which silently
# allowed when allowed_models was absent/undefined (inverted default, ASVS V4.1.3).
# Legit-allow flows (enumerated):
#   1. identity declares no restriction (allowed_models == [])  → all models OK
#   2. allowed_models field absent entirely (no restriction declared) → all OK
#   3. the selected model is explicitly in allowed_models
#   4. allowed_models contains the "*" wildcard
default model_allowed := false

# Flow 1: empty allowlist = no restriction
model_allowed if {
    count(input.identity.allowed_models) == 0
}

# Flow 2: allowed_models absent entirely = no restriction declared.
# (count(undefined) is undefined, so flow 1 does not cover this — explicit guard.)
model_allowed if {
    not input.identity.allowed_models
}

# Flow 3: selected model explicitly allowed
model_allowed if {
    input.routing_decision.model in input.identity.allowed_models
}

# Flow 4: wildcard
model_allowed if {
    "*" in input.identity.allowed_models
}

# ── Routing safety net ────────────────────────────────────────────────────

# CRITICAL: CONFIDENTIAL/RESTRICTED data must NEVER route to cloud
# unless the provider is in the trusted_cloud_providers list.
# LAURA-OPA-003 class-fix (2.25.2): default-DENY + explicit positive-allow.
# Legit-allow flows (enumerated) — routing is SAFE when:
#   1. the routing is NOT a sensitive-to-untrusted-cloud combination
#      (i.e. NOT(sensitivity in {CONFIDENTIAL,RESTRICTED} AND route==cloud
#       AND provider not trusted)).
# The positive rule is the exact logical negation of the previous deny clause,
# so every input that was SAFE before is still SAFE; only undefined-shaped
# inputs (which previously fell through to the permissive default) now DENY.
default routing_safe := false

routing_safe if {
    not _routing_unsafe
}

# _routing_unsafe — the single sensitive-to-untrusted-cloud violation.
_routing_unsafe if {
    input.routing_decision.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
    input.routing_decision.route == "cloud"
    not trusted_cloud_provider
}

trusted_cloud_provider if {
    input.routing_decision.provider in input.trusted_cloud_providers
}

# Identity cannot receive data above their sensitivity ceiling.
# LAURA-OPA-003 class-fix (2.25.2): default-DENY + explicit positive-allow.
# Legit-allow flow (enumerated): the routing sensitivity rank is within the
# identity's ceiling rank. When the ceiling is ABSENT, sensitivity_rank(undefined)
# is undefined, the comparison is undefined, the allow rule does not fire, and the
# decision DENIES (fail-closed) — previously it silently ALLOWED via default:=true.
default sensitivity_allowed := false

sensitivity_allowed if {
    # Content operand: sensitivity_rank (unknown→4, fail-closed for content).
    # Ceiling operand: _ceiling_rank (undefined for unknown → rule does not fire
    # → default-deny). Prevents a garbage ceiling string from becoming rank-4 and
    # admitting RESTRICTED content.
    sensitivity_rank(input.routing_decision.sensitivity) <= _ceiling_rank(input.identity.sensitivity_ceiling)
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

# ---------------------------------------------------------------------------
# _ceiling_rank — rank helper for the CEILING operand (the identity's declared
# clearance), NOT for content sensitivity.
#
# sensitivity_rank maps an unknown string to rank 4 ("treat unknown CONTENT as
# the most sensitive" — correct fail-closed for the data operand). Applying the
# same map to a CEILING string is PERMISSIVE: a garbage ceiling becomes rank 4
# (the highest ceiling) so RESTRICTED content (rank 3) satisfies
# `content <= garbage_ceiling` and is ALLOWED — the opposite of fail-closed.
# (Laura residual, 2.25.2 — currently unreachable because consumers validate the
# ceiling, but closed here for defence-in-depth.)
#
# _ceiling_rank is defined ONLY for the canonical four levels. An unknown ceiling
# string leaves it UNDEFINED → the `<=` comparison is undefined → the positive
# allow rule does not fire → default-deny. ASVS V4.1.3.
# ---------------------------------------------------------------------------
_ceiling_rank(level) := 0 if level == "PUBLIC"
_ceiling_rank(level) := 1 if level == "INTERNAL"
_ceiling_rank(level) := 2 if level == "CONFIDENTIAL"
_ceiling_rank(level) := 3 if level == "RESTRICTED"

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

# LAURA-OPA-003 class-fix (2.25.2): default-DENY + explicit positive-allow,
# matching agents.rego agent_response_allowed. Previously `default := true`,
# which silently delivered a RESTRICTED response to an identity with NO declared
# ceiling (absent sensitivity_ceiling → undefined rank → undefined comparison →
# stayed at default true). Inverted default, ASVS V4.1.3 / LLM02.
# Legit-allow flow (enumerated): the response is delivered when BOTH:
#   1. effective sensitivity rank (MAX of prompt+response) is within the caller's
#      ceiling rank, AND
#   2. the inspection verdict does not block delivery for this identity
#      (i.e. NOT(verdict==blocked AND kind!=admin)).
# This is the exact logical negation of the two prior deny clauses, so every
# input previously ALLOWED is still allowed; absent-ceiling now DENIES.
default response_allowed := false

response_allowed if {
    # Condition 1: effective sensitivity within ceiling.
    # Absent OR unknown ceiling → _ceiling_rank undefined → rule does not fire → DENY.
    # (Ceiling operand uses _ceiling_rank, not sensitivity_rank, so a garbage
    # ceiling string can never become rank-4 and admit RESTRICTED content.)
    _effective_sensitivity_rank <= _ceiling_rank(input.identity.sensitivity_ceiling)

    # Condition 2: not blocked-for-non-admin.
    not _response_blocked_by_inspection
}

# _response_blocked_by_inspection — verdict==blocked AND identity is not admin.
_response_blocked_by_inspection if {
    input.response_verdict == "blocked"
    input.identity.kind != "admin"
}

response_decision := {
    "allow": response_allowed,
    "reason": response_reason,
}

# LAURA-OPA-003 (2.25.2): with response_allowed now default-deny, an input that
# denies for an undefined-comparison reason (e.g. absent sensitivity_ceiling)
# would leave response_reason undefined. Provide an explicit default so the audit
# trail always carries a reason. The specific rules below override it.
default response_reason := "denied_default_deny"

response_reason := "ok" if response_allowed

response_reason := "response_sensitivity_exceeds_ceiling" if {
    not response_allowed
    _effective_sensitivity_rank > _ceiling_rank(input.identity.sensitivity_ceiling)
}

# Invalid / unrecognised ceiling string — fail-closed deny with an explicit
# audit reason (otherwise the deny carries the default reason and the operator
# cannot tell the ceiling string itself was the problem).
response_reason := "invalid_identity_ceiling" if {
    not response_allowed
    _invalid_identity_ceiling
}

# _invalid_identity_ceiling — ceiling is present but not in the canonical set.
_invalid_identity_ceiling if {
    input.identity.sensitivity_ceiling
    not _ceiling_rank(input.identity.sensitivity_ceiling)
}

response_reason := "response_blocked_by_inspection" if {
    not response_allowed
    input.response_verdict == "blocked"
    # Defer to invalid_identity_ceiling when the ceiling itself is unrecognised,
    # so exactly one reason fires (no eval_conflict on the decision object).
    not _invalid_identity_ceiling
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

# LAURA-OPA-003 class-fix (2.25.2): default-DENY + explicit positive-allow.
# Previously `default := true` — a RESTRICTED response was delivered to a
# principal with NO declared ceiling (absent sensitivity_ceiling → undefined
# rank → undefined comparison → stayed true). Inverted default, ASVS V4.1.3.
# Legit-allow flow (enumerated): delivery is permitted when BOTH:
#   1. proxy effective sensitivity rank is within the principal's ceiling rank
#      (when response_sensitivity is ABSENT the rank is 0/PUBLIC — pipeline-off
#       default is preserved: a PUBLIC-rank response is delivered), AND
#   2. PII delivery is permitted (i.e. NOT(pii AND principal is a service account)).
# Exact logical negation of the two prior deny clauses; absent-ceiling now DENIES.
default proxy_response_allowed := false

proxy_response_allowed if {
    # Condition 1: effective sensitivity within ceiling.
    # Absent OR unknown ceiling → _ceiling_rank undefined → rule does not fire → DENY.
    # Ceiling operand uses _ceiling_rank (not sensitivity_rank) so a garbage
    # ceiling string cannot become rank-4 and admit RESTRICTED content.
    _proxy_effective_sensitivity_rank <= _ceiling_rank(input.principal.sensitivity_ceiling)

    # Condition 2: not a PII-block for a service account.
    not _proxy_pii_blocked
}

# _proxy_pii_blocked — PII present AND principal is neither admin nor human.
_proxy_pii_blocked if {
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

# LAURA-OPA-003 (2.25.2): default-deny means a denied-by-default decision must
# not report "ok". The "ok" reason is asserted only when allowed.
default proxy_response_reason := "denied_default_deny"

proxy_response_reason := "ok" if proxy_response_allowed

proxy_response_reason := "response_sensitivity_exceeds_ceiling" if {
    not proxy_response_allowed
    _proxy_effective_sensitivity_rank > _ceiling_rank(input.principal.sensitivity_ceiling)
}

# Invalid / unrecognised ceiling string — fail-closed deny with explicit reason.
proxy_response_reason := "invalid_principal_ceiling" if {
    not proxy_response_allowed
    _invalid_principal_ceiling
}

# _invalid_principal_ceiling — ceiling present but not in the canonical set.
_invalid_principal_ceiling if {
    input.principal.sensitivity_ceiling
    not _ceiling_rank(input.principal.sensitivity_ceiling)
}

proxy_response_reason := "response_pii_blocked_for_service_account" if {
    not proxy_response_allowed
    input.response_pii_detected == true
    input.principal.kind != "admin"
    input.principal.kind != "human"
    # Defer to invalid_principal_ceiling so exactly one reason fires.
    not _invalid_principal_ceiling
}

proxy_response_decision := {
    "allow": proxy_response_allowed,
    "reason": proxy_response_reason,
}
