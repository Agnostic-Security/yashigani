# Behavioural tests for examples/eu_ai_act.rego (G2 closure — see gdpr_test.rego
# header for rationale). This template references no operator data.* config
# (input-only decision), so no `with data.clients.aiact...` override is needed.
#
# Run with: opa test policy/
package clients.aiact_test

import rego.v1

test_deny_prohibited_ai_practice if {
	"prohibited_ai_practice" in data.clients.aiact.decision.deny with input as {
		"ai_use": {"risk_class": "unacceptable", "human_oversight": false, "transparency_notice": false},
	}
}

test_deny_high_risk_without_human_oversight if {
	"high_risk_without_human_oversight" in data.clients.aiact.decision.deny with input as {
		"ai_use": {"risk_class": "high", "human_oversight": false, "transparency_notice": true},
	}
}

test_allow_high_risk_with_oversight_and_notice if {
	data.clients.aiact.decision.allow with input as {
		"ai_use": {"risk_class": "high", "human_oversight": true, "transparency_notice": true},
	}
}

test_deny_missing_transparency_notice if {
	"missing_transparency_notice" in data.clients.aiact.decision.deny with input as {
		"ai_use": {"risk_class": "limited", "human_oversight": true, "transparency_notice": false},
	}
}

test_deny_ai_risk_class_missing if {
	"ai_risk_class_missing" in data.clients.aiact.decision.deny with input as {
		"ai_use": {"risk_class": "", "human_oversight": false, "transparency_notice": false},
	}
}

test_allow_minimal_risk if {
	data.clients.aiact.decision.allow with input as {
		"ai_use": {"risk_class": "minimal", "human_oversight": false, "transparency_notice": false},
	}
}

test_decision_contract_shape if {
	d := data.clients.aiact.decision with input as {
		"ai_use": {"risk_class": "minimal", "human_oversight": false, "transparency_notice": false},
	}
	d.policy_id == "clients.aiact.eu-ai-act"
	d.code == 403
}
