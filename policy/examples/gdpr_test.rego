# Behavioural tests for examples/gdpr.rego (G2, Lu audit YCS-20260723-v4.1.2-CONFORMANCE).
#
# G2 closure decision: OPTION (a) — add behavioural tests, KEEP the template
# live-loaded in OPA. Option (b) (move to a non-mounted docs/ path) was
# considered and REJECTED: policies.py's `duplicate_template` (R8,
# POST /admin/policies/templates/duplicate) fetches the template's raw Rego
# via a LIVE `GET {opa_url}/v1/policies/examples/<id>` call — moving examples/
# out of the OPA-mounted `policy/` dir would 404 every "Save-As" template
# duplication in the admin UI, breaking a load-bearing product feature.
# Testing in place is the correct fix; see report for the full rationale.
#
# Run with: opa test policy/
package clients.gdpr_test

import rego.v1

_eu_providers := ["ollama-eu", "azure-eu-west"]

test_allow_when_no_personal_data if {
	data.clients.gdpr.decision.allow with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": false,
			"special_category": false,
			"request": {"lawful_basis": "", "purpose": "", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": [], "subject_id": "", "pii_categories": [], "purpose_max_categories": 0},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_no_lawful_basis if {
	"no_lawful_basis" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_purpose_incompatible if {
	"purpose_incompatible" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "marketing", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_international_transfer_without_safeguard if {
	"international_transfer_without_safeguard" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "cloud", "provider": "openai"},
		}
}

test_allow_international_transfer_with_safeguard if {
	not "international_transfer_without_safeguard" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "scc",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "cloud", "provider": "openai"},
		}
}

test_deny_special_category_without_condition if {
	"special_category_without_condition" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": true,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_deny_subject_restricted if {
	"subject_processing_restricted" in data.clients.gdpr.decision.deny with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "sub-blocked", "pii_categories": [], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
}

test_decision_contract_shape if {
	d := data.clients.gdpr.decision with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": false,
			"special_category": false,
			"request": {"lawful_basis": "", "purpose": "", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": [], "subject_id": "", "pii_categories": [], "purpose_max_categories": 0},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
	d.policy_id == "clients.gdpr.gdpr"
	d.code == 403
}

# --- Additive against-spec coverage (Lu conf/v412-opa-templates) -------------
# The two documented Art 30 / Art 5(1)(c) obligations had no assertion in
# 2d582105's G2 tests.

# Art 30 — processing personal data carries a record-of-processing obligation.
test_obligation_record_processing_activity if {
	d := data.clients.gdpr.decision with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": ["name"], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
	"record_processing_activity" in d.obligations
}

# Art 5(1)(c) — more PII categories present than the purpose needs => minimisation review.
test_obligation_review_data_minimisation if {
	d := data.clients.gdpr.decision with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": ["name", "email", "phone"], "purpose_max_categories": 1},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
	"review_data_minimisation" in d.obligations
}

# Negative: within-budget category count does NOT raise the minimisation obligation.
test_no_minimisation_obligation_within_budget if {
	d := data.clients.gdpr.decision with data.clients.gdpr.eu_region_providers as _eu_providers
		with data.clients.gdpr.restricted_subjects as ["sub-blocked"]
		with input as {
			"personal_data_present": true,
			"special_category": false,
			"request": {"lawful_basis": "consent", "purpose": "support", "art9_condition": ""},
			"transfer_safeguard": "",
			"data": {"permitted_purposes": ["support"], "subject_id": "", "pii_categories": ["name"], "purpose_max_categories": 5},
			"routing_decision": {"route": "local", "provider": "ollama-local"},
		}
	not "review_data_minimisation" in d.obligations
}
