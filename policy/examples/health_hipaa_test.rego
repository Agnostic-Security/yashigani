# Behavioural tests for examples/health_hipaa.rego (G2 closure — see gdpr_test.rego
# header for the full option-(a)-vs-(b) rationale: examples/ stays live-loaded
# because policies.py's template-duplicate feature reads it from live OPA).
#
# Run with: opa test policy/
package clients.hipaa_test

import rego.v1

_baa_providers := ["azure-baa", "aws-baa"]

_base_input := {
	"phi_present": false,
	"response_phi_detected": false,
	"request": {"purpose": "treatment", "break_glass": false},
	"identity": {"role": "clinician"},
	"deidentified": false,
	"routing_decision": {"route": "local", "provider": "ollama-local"},
}

test_allow_when_no_phi if {
	data.clients.hipaa.decision.allow with data.clients.hipaa.baa_providers as _baa_providers
		with input as _base_input
}

test_deny_phi_purpose_not_minimum_necessary if {
	i := object.union(_base_input, {"phi_present": true, "request": {"purpose": "research", "break_glass": false}})
	"phi_purpose_not_minimum_necessary" in data.clients.hipaa.decision.deny with data.clients.hipaa.baa_providers as _baa_providers
		with input as i
}

test_deny_phi_to_provider_without_baa if {
	i := object.union(_base_input, {
		"phi_present": true,
		"routing_decision": {"route": "cloud", "provider": "openai"},
	})
	"phi_to_provider_without_baa" in data.clients.hipaa.decision.deny with data.clients.hipaa.baa_providers as _baa_providers
		with input as i
}

test_allow_phi_to_baa_provider if {
	i := object.union(_base_input, {
		"phi_present": true,
		"routing_decision": {"route": "cloud", "provider": "azure-baa"},
		"deidentified": true,
	})
	not "phi_to_provider_without_baa" in data.clients.hipaa.decision.deny with data.clients.hipaa.baa_providers as _baa_providers
		with input as i
}

test_deny_phi_response_to_nonclinical_role if {
	i := object.union(_base_input, {"response_phi_detected": true, "identity": {"role": "sales"}})
	"phi_response_to_nonclinical_role" in data.clients.hipaa.decision.deny with data.clients.hipaa.baa_providers as _baa_providers
		with input as i
}

test_break_glass_allows_despite_deny if {
	i := object.union(_base_input, {
		"phi_present": true,
		"request": {"purpose": "research", "break_glass": true},
	})
	d := data.clients.hipaa.decision with data.clients.hipaa.baa_providers as _baa_providers
		with input as i
	d.allow
	count(d.deny) > 0
	"break_glass_review" in d.obligations
}

test_decision_contract_shape if {
	d := data.clients.hipaa.decision with data.clients.hipaa.baa_providers as _baa_providers
		with input as _base_input
	d.policy_id == "clients.hipaa.hipaa"
	d.code == 403
}
