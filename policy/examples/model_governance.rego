# EXAMPLE / ILLUSTRATIVE — Model governance for an AI gateway.
# Cross-vertical (ISO 42001, NIST AI RMF, SOC 2 CC). Generic starter: restrict which models a
# principal may use, cap the data sensitivity a model may receive, and enforce a per-tier cost cap.
#
# Decision document:  data.clients.model.decision = {allow, deny}
#
# === CUSTOMIZE ===
#   input.identity.allowed_models[]   models this principal may use ([] = all, "*" = all)
#   input.identity.tier               billing/risk tier key
#   input.routing_decision.model      selected model
#   input.routing_decision.sensitivity  sensitivity of the data being sent
#   input.request.estimated_cost_usd  estimated request cost
#   data.clients.model.model_max_sensitivity[model] = "PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED"
#   data.clients.model.max_cost_by_tier[tier]       = number (USD)
package clients.model

import rego.v1

_sens := {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}

# Fail-closed ranking: unknown label ranks above the top.
rank(l) := _sens[l]

rank(l) := 99 if not l in object.keys(_sens)

_allowed_models := {m | some m in input.identity.allowed_models}

default _model_permitted := false

_model_permitted if count(_allowed_models) == 0 # no restriction configured

_model_permitted if "*" in _allowed_models

_model_permitted if input.routing_decision.model in _allowed_models

# Principal may only use models on their allow-list.
deny contains "model_not_in_allowlist" if not _model_permitted

# A model must not receive data above its certified sensitivity.
deny contains "model_sensitivity_exceeded" if {
	some max_label in [data.clients.model.model_max_sensitivity[input.routing_decision.model]]
	rank(input.routing_decision.sensitivity) > rank(max_label)
}

default _over_budget := false

_over_budget if input.request.estimated_cost_usd > data.clients.model.max_cost_by_tier[input.identity.tier]

# Per-tier cost guardrail.
deny contains "request_over_cost_budget" if _over_budget

default allow := false

allow if count(deny) == 0

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.model.model-governance"
user_message := "Blocked by model-governance policy: the requested model isn't permitted for your role/sensitivity, or it exceeds the cost budget."
code := 403
decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}
