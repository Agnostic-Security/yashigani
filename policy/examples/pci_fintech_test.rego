# Behavioural tests for examples/pci_fintech.rego (G2 closure — see gdpr_test.rego
# header for rationale).
#
# Run with: opa test policy/
package clients.pci_test

import rego.v1

_compliant_providers := ["cde-provider-1"]

_base_input := {
	"data_tags": [],
	"routing_decision": {"route": "local", "provider": "ollama-local"},
	"response_pan_detected": false,
	"response_pan_masked": false,
}

test_allow_when_no_sensitive_tags if {
	data.clients.pci.decision.allow with data.clients.pci.compliant_providers as _compliant_providers
		with input as _base_input
}

test_deny_sensitive_authentication_data if {
	i := object.union(_base_input, {"data_tags": ["CVV"]})
	"sensitive_authentication_data_present" in data.clients.pci.decision.deny with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
}

test_deny_chd_egress_to_noncompliant_provider if {
	i := object.union(_base_input, {
		"data_tags": ["PAN"],
		"routing_decision": {"route": "cloud", "provider": "openai"},
	})
	"chd_egress_to_noncompliant_provider" in data.clients.pci.decision.deny with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
}

test_allow_chd_egress_to_compliant_provider if {
	i := object.union(_base_input, {
		"data_tags": ["PAN"],
		"routing_decision": {"route": "cloud", "provider": "cde-provider-1"},
	})
	not "chd_egress_to_noncompliant_provider" in data.clients.pci.decision.deny with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
}

test_deny_unmasked_pan_in_response if {
	i := object.union(_base_input, {"response_pan_detected": true, "response_pan_masked": false})
	"unmasked_pan_in_response" in data.clients.pci.decision.deny with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
}

test_allow_masked_pan_in_response if {
	i := object.union(_base_input, {"response_pan_detected": true, "response_pan_masked": true})
	not "unmasked_pan_in_response" in data.clients.pci.decision.deny with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
}

test_decision_contract_shape if {
	d := data.clients.pci.decision with data.clients.pci.compliant_providers as _compliant_providers
		with input as _base_input
	d.policy_id == "clients.pci.pci-dss"
	d.code == 403
}

# --- Additive against-spec coverage (Lu conf/v412-opa-templates) -------------
# Req 10 / redact obligations had no assertion in 2d582105's G2 tests.

# Req 10 — any CHD access carries the audit obligation (even when allowed).
test_obligation_audit_chd_access if {
	i := object.union(_base_input, {"data_tags": ["PAN"]})
	d := data.clients.pci.decision with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
	"audit_chd_access" in d.obligations
}

# Req 3.4.1 — an unmasked PAN in the response raises the redact obligation.
test_obligation_redact_pan if {
	i := object.union(_base_input, {"response_pan_detected": true, "response_pan_masked": false})
	d := data.clients.pci.decision with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
	"redact_pan" in d.obligations
	not d.allow # unmasked PAN also denies
}

# Negative: a masked PAN raises no redact obligation.
test_no_redact_obligation_when_masked if {
	i := object.union(_base_input, {"response_pan_detected": true, "response_pan_masked": true})
	d := data.clients.pci.decision with data.clients.pci.compliant_providers as _compliant_providers
		with input as i
	not "redact_pan" in d.obligations
}
