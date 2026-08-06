# Behavioural tests for examples/data_residency.rego (G2 closure — see
# gdpr_test.rego header for rationale).
#
# Run with: opa test policy/
package clients.residency_test

import rego.v1

_allowed_providers := {"eu": ["ollama-eu", "azure-eu-west"], "us": ["ollama-local", "aws-us"]}

test_allow_local_route_no_region_check if {
	data.clients.residency.decision.allow with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "eu"},
			"routing_decision": {"route": "local", "provider": "ollama-eu"},
		}
}

test_deny_data_region_missing_key_absent if {
	"data_region_missing" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

# YSG-RISK-151 (fixed): previously `deny contains "data_region_missing" if
# not input.data.region` only caught an ABSENT region key — `not X` in Rego
# is true only when X is undefined, not when X is a defined-but-falsy value.
# An empty string ("") is a DEFINED value, so a caller serialising "no
# region set" as `"region": ""` silently bypassed the guard (for a "local"
# route, which has no other region check, this meant a fully-unlabelled
# request was allowed). Fixed via _region_blank (missing OR blank/whitespace
# after trim_space). These tests now assert the closed behaviour.
test_deny_data_region_missing_empty_string if {
	"data_region_missing" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": ""},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_data_region_missing_whitespace_only if {
	"data_region_missing" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "   "},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_data_region_missing_empty_string_blocks_overall_allow if {
	d := data.clients.residency.decision with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": ""},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
	d.allow == false
}

test_deny_cross_region_egress if {
	"cross_region_egress" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "eu"},
			"routing_decision": {"route": "cloud", "provider": "openai-us"},
		}
}

test_allow_cross_region_egress_to_permitted_provider if {
	not "cross_region_egress" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "eu"},
			"routing_decision": {"route": "cloud", "provider": "azure-eu-west"},
		}
}

test_obligation_log_data_location_on_cloud_egress if {
	d := data.clients.residency.decision with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "eu"},
			"routing_decision": {"route": "cloud", "provider": "azure-eu-west"},
		}
	"log_data_location" in d.obligations
}

test_decision_contract_shape if {
	d := data.clients.residency.decision with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": "eu"},
			"routing_decision": {"route": "local", "provider": "ollama-eu"},
		}
	d.policy_id == "clients.residency.data-residency"
	d.code == 451
}
