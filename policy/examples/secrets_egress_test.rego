# Behavioural tests for examples/secrets_egress.rego (G2 closure — see
# gdpr_test.rego header for rationale). This template references no operator
# data.* config (the secret_tags allowlist is package-internal), so no
# `with data.clients.secrets...` override is needed.
#
# Run with: opa test policy/
package clients.secrets_test

import rego.v1

test_allow_when_no_secret_tags if {
	data.clients.secrets.decision.allow with input as {
		"data_tags": [],
		"routing_decision": {"route": "local"},
	}
}

test_deny_secret_material_local_route if {
	"secret_material_in_payload" in data.clients.secrets.decision.deny with input as {
		"data_tags": ["API_KEY"],
		"routing_decision": {"route": "local"},
	}
}

test_deny_secret_material_cloud_route if {
	"secret_material_in_payload" in data.clients.secrets.decision.deny with input as {
		"data_tags": ["AWS_SECRET_KEY"],
		"routing_decision": {"route": "cloud"},
	}
}

test_obligations_on_secret_egress_to_cloud if {
	d := data.clients.secrets.decision with input as {
		"data_tags": ["JWT"],
		"routing_decision": {"route": "cloud"},
	}
	"redact_secret" in d.obligations
	"rotate_exposed_secret" in d.obligations
}

test_no_rotate_obligation_when_local_only if {
	d := data.clients.secrets.decision with input as {
		"data_tags": ["JWT"],
		"routing_decision": {"route": "local"},
	}
	"redact_secret" in d.obligations
	not "rotate_exposed_secret" in d.obligations
}

test_decision_contract_shape if {
	d := data.clients.secrets.decision with input as {
		"data_tags": [],
		"routing_decision": {"route": "local"},
	}
	d.policy_id == "clients.secrets.secret-egress"
	d.code == 403
}
