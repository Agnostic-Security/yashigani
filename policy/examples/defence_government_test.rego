# Behavioural tests for examples/defence_government.rego (G2 closure — see
# gdpr_test.rego header for rationale). This template references no operator
# data.* config (the classification rank table is package-internal), so no
# `with data.clients.gov...` override is needed.
#
# Run with: opa test policy/
package clients.gov_test

import rego.v1

_base_input := {
	"identity": {"clearance": "SECRET", "caveats": [], "compartments": []},
	"data": {"classification": "OFFICIAL", "caveats": [], "compartment": ""},
	"routing_decision": {"route": "local"},
}

test_allow_clearance_dominates_classification if {
	data.clients.gov.decision.allow with input as _base_input
}

test_deny_classification_label_missing_key_absent if {
	# NOTE: built as a full literal (not object.union) — object.union performs
	# a RECURSIVE/deep merge of nested objects (verified empirically), so
	# unioning a "data" object that omits "classification" onto _base_input
	# would NOT actually remove the key — it would keep _base_input's
	# "classification": "OFFICIAL" from the base object.
	i := {
		"identity": {"clearance": "SECRET", "caveats": [], "compartments": []},
		"data": {"caveats": [], "compartment": ""},
		"routing_decision": {"route": "local"},
	}
	"classification_label_missing" in data.clients.gov.decision.deny with input as i
}

# KNOWN GAP (found while writing this test — same root cause as
# data_residency_test.rego's test_KNOWN_GAP_empty_string_region_not_caught,
# flagged for Lu, NOT silently fixed here): `not input.data.classification`
# only fires when the `classification` key is entirely ABSENT — a defined
# empty string ("") does not trigger this deny. This test pins the current
# behaviour rather than asserting the doc comment's stated (but not fully
# implemented) fail-closed intent.
test_KNOWN_GAP_empty_string_classification_not_caught_by_missing_check if {
	i := object.union(_base_input, {"data": {"classification": "", "caveats": [], "compartment": ""}})
	not "classification_label_missing" in data.clients.gov.decision.deny with input as i
}

test_deny_clearance_below_classification if {
	i := object.union(_base_input, {"identity": {"clearance": "OFFICIAL", "caveats": [], "compartments": []}})
	i2 := object.union(i, {"data": {"classification": "TOP SECRET", "caveats": [], "compartment": ""}})
	"clearance_below_classification" in data.clients.gov.decision.deny with input as i2
}

test_deny_classified_data_to_cloud if {
	i := object.union(_base_input, {
		"data": {"classification": "SECRET", "caveats": [], "compartment": ""},
		"routing_decision": {"route": "cloud"},
	})
	"classified_data_to_cloud" in data.clients.gov.decision.deny with input as i
}

test_deny_caveat_not_satisfied if {
	i := object.union(_base_input, {"data": {"classification": "OFFICIAL", "caveats": ["UK_EYES_ONLY"], "compartment": ""}})
	deny := data.clients.gov.decision.deny with input as i
	some d in deny
	startswith(d, "caveat_not_satisfied:")
}

test_deny_compartment_not_authorised if {
	i := object.union(_base_input, {"data": {"classification": "OFFICIAL", "caveats": [], "compartment": "SPECIAL"}})
	"compartment_not_authorised" in data.clients.gov.decision.deny with input as i
}

test_unknown_classification_fails_closed if {
	i := object.union(_base_input, {"data": {"classification": "NOVEL_LABEL", "caveats": [], "compartment": ""}})
	"clearance_below_classification" in data.clients.gov.decision.deny with input as i
}

test_decision_contract_shape if {
	d := data.clients.gov.decision with input as _base_input
	d.policy_id == "clients.gov.classification-control"
	d.code == 403
}
