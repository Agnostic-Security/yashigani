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

# KNOWN GAP (found while writing this test, flagged for Lu — NOT silently
# fixed here): the rule is `deny contains "data_region_missing" if not
# input.data.region`. In Rego, `not X` is true only when X is UNDEFINED, not
# when X is a defined-but-falsy value — an empty string ("") is a DEFINED
# value, so `not input.data.region` does NOT fire when region is present but
# empty, only when the `region` key is entirely ABSENT from the input
# object. The doc comment's "Fail-closed: an unlabelled region cannot be
# placed safely" claim only holds for the omitted-key shape; an upstream
# caller that serialises "no region set" as `"region": ""` (at least as
# likely in practice as omitting the key) silently bypasses this guard. This
# test PINS the current (arguably buggy) behaviour so a future accidental
# "fix" doesn't slip through unnoticed either way — it does not endorse it.
test_KNOWN_GAP_empty_string_region_not_caught if {
	not "data_region_missing" in data.clients.residency.decision.deny with data.clients.residency.allowed_providers as _allowed_providers
		with input as {
			"data": {"region": ""},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
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
