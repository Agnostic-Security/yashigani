# Behavioural tests for examples/model_governance.rego (G2 closure — see
# gdpr_test.rego header for rationale).
#
# Run with: opa test policy/
package clients.model_test

import rego.v1

_max_sensitivity := {"gpt-4o": "CONFIDENTIAL", "qwen2.5:3b": "RESTRICTED"}

_max_cost_by_tier := {"free": 0.01, "pro": 5.00}

_base_input := {
	"identity": {"allowed_models": [], "tier": "pro"},
	"routing_decision": {"model": "qwen2.5:3b", "sensitivity": "INTERNAL"},
	"request": {"estimated_cost_usd": 0.10},
}

test_allow_when_no_allowlist_configured if {
	data.clients.model.decision.allow
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as _base_input
}

test_deny_model_not_in_allowlist if {
	i := object.union(_base_input, {"identity": {"allowed_models": ["gpt-4o"], "tier": "pro"}})
	"model_not_in_allowlist" in data.clients.model.decision.deny
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as i
}

test_allow_model_in_allowlist if {
	i := object.union(_base_input, {"identity": {"allowed_models": ["qwen2.5:3b"], "tier": "pro"}})
	not "model_not_in_allowlist" in data.clients.model.decision.deny
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as i
}

test_allow_wildcard_allowlist if {
	i := object.union(_base_input, {"identity": {"allowed_models": ["*"], "tier": "pro"}})
	not "model_not_in_allowlist" in data.clients.model.decision.deny
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as i
}

test_deny_model_sensitivity_exceeded if {
	i := object.union(_base_input, {"routing_decision": {"model": "gpt-4o", "sensitivity": "RESTRICTED"}})
	"model_sensitivity_exceeded" in data.clients.model.decision.deny
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as i
}

test_deny_request_over_cost_budget if {
	i := object.union(_base_input, {"identity": {"allowed_models": [], "tier": "free"}, "request": {"estimated_cost_usd": 1.00}})
	"request_over_cost_budget" in data.clients.model.decision.deny
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as i
}

test_decision_contract_shape if {
	d := data.clients.model.decision
		with data.clients.model.model_max_sensitivity as _max_sensitivity
		with data.clients.model.max_cost_by_tier as _max_cost_by_tier
		with input as _base_input
	d.policy_id == "clients.model.model-governance"
	d.code == 403
}
