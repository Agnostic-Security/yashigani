# Yashigani — document.rego property tests (2.26).
# Run with: opa test policy/
#
# Coverage:
#   1. LOG       — clean pass-through (extraction complete, no matches)
#   2. LOG       — PII match policed to LOG (internal passthrough)
#   3. PSEUDONYMIZE — PII match policed to PSEUDONYMIZE on a supported format
#   4. REDACT    — PII match policed to REDACT on a supported format
#   5. BLOCK     — PCI match policed to BLOCK (fail-closed cardholder data)
#   6. PRECEDENCE — BLOCK > REDACT > PSEUDONYMIZE > LOG when multiple policies apply
#   7. FAIL-CLOSED — extraction_complete == false ⇒ BLOCK regardless of matches
#   8. FAIL-CLOSED — matched class with NO policy ⇒ BLOCK (no clearance)
#   9. FAIL-CLOSED — PSEUDONYMIZE on an unsupported format ⇒ BLOCK
#  10. F2 — small-set residual-QI re-identification escalation ⇒ BLOCK
#  11. per_match_actions populated for PSEUDONYMIZE; empty otherwise
#  12. self-describing contract (policy_id + code + user_message) present
#  13. namespace-prefix class match (policy "PII" matches "PII.EMAIL")

package yashigani.document_test

import rego.v1

import data.yashigani.document

# --- Reusable data fixtures (the operator's policy matrix) --------------------

_policies_log_pii := [{
	"data_class": "PII",
	"format": "any",
	"route": "any",
	"action": "LOG",
	"pseudonymize_mode": "A",
	"small_set_escalation": false,
}]

_policies_pseudo_pii := [{
	"data_class": "PII",
	"format": "any",
	"route": "any",
	"action": "PSEUDONYMIZE",
	"pseudonymize_mode": "A",
	"small_set_escalation": true,
}]

_policies_redact_pii := [{
	"data_class": "PII",
	"format": "any",
	"route": "any",
	"action": "REDACT",
	"pseudonymize_mode": "A",
	"small_set_escalation": false,
}]

_policies_block_pci := [{
	"data_class": "PCI",
	"format": "any",
	"route": "any",
	"action": "BLOCK",
	"pseudonymize_mode": "A",
	"small_set_escalation": true,
}]

# All four actions configured for PII at once (precedence test).
_policies_all_pii := [
	{"data_class": "PII", "format": "any", "route": "any", "action": "LOG", "pseudonymize_mode": "A", "small_set_escalation": false},
	{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false},
	{"data_class": "PII", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "A", "small_set_escalation": false},
	{"data_class": "PII", "format": "any", "route": "any", "action": "BLOCK", "pseudonymize_mode": "A", "small_set_escalation": false},
]

_match_email := {"data_class": "PII.EMAIL", "qi": false, "instance": "j***@e.com", "location": "BODY:p1:span=0-9"}

_match_dob_qi := {"data_class": "PII.DATE_OF_BIRTH", "qi": true, "instance": "1*/*/19**", "location": "BODY:p1:span=10-20"}

_match_card := {"data_class": "PCI.CARD", "qi": false, "instance": "****-1234", "location": "BODY:p1:span=0-9"}

_doc(matches, complete, supported) := {
	"format": "xlsx",
	"extraction_complete": complete,
	"segment_kinds": ["BODY"],
	"matches": matches,
	"record_count": 100,
	"reid_handle": "cap-xyz",
	"pseudonymize_supported": supported,
	"redaction_supported": supported,
}

# ---------------------------------------------------------------------------
# 1. LOG — clean pass-through
# ---------------------------------------------------------------------------
test_log_clean_passthrough if {
	document.action == "LOG" with input as {"document": _doc([], true, true)}
		with data.yashigani.document.policies as _policies_log_pii
}

# ---------------------------------------------------------------------------
# 2. LOG — PII policed to LOG
# ---------------------------------------------------------------------------
test_log_pii_policed if {
	document.action == "LOG" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_log_pii
}

# ---------------------------------------------------------------------------
# 3. PSEUDONYMIZE on supported format
# ---------------------------------------------------------------------------
test_pseudonymize_supported if {
	document.action == "PSEUDONYMIZE" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_pseudo_pii
}

# ---------------------------------------------------------------------------
# 4. REDACT on supported format
# ---------------------------------------------------------------------------
test_redact_supported if {
	document.action == "REDACT" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_redact_pii
}

# ---------------------------------------------------------------------------
# 5. BLOCK — PCI policed to BLOCK
# ---------------------------------------------------------------------------
test_block_pci if {
	document.action == "BLOCK" with input as {"document": _doc([_match_card], true, true)}
		with data.yashigani.document.policies as _policies_block_pci
}

# ---------------------------------------------------------------------------
# 6. PRECEDENCE — BLOCK wins when all four actions apply
# ---------------------------------------------------------------------------
test_precedence_block_wins if {
	document.action == "BLOCK" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_all_pii
}

# PRECEDENCE — REDACT wins over PSEUDONYMIZE and LOG.
test_precedence_redact_over_pseudo if {
	policies := [
		{"data_class": "PII", "format": "any", "route": "any", "action": "LOG", "pseudonymize_mode": "A", "small_set_escalation": false},
		{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false},
		{"data_class": "PII", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "A", "small_set_escalation": false},
	]
	document.action == "REDACT" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# PRECEDENCE — PSEUDONYMIZE wins over LOG.
test_precedence_pseudo_over_log if {
	policies := [
		{"data_class": "PII", "format": "any", "route": "any", "action": "LOG", "pseudonymize_mode": "A", "small_set_escalation": false},
		{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false},
	]
	document.action == "PSEUDONYMIZE" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# ---------------------------------------------------------------------------
# 7. FAIL-CLOSED — incomplete extraction ⇒ BLOCK
# ---------------------------------------------------------------------------
test_fail_closed_incomplete_extraction if {
	document.action == "BLOCK" with input as {"document": _doc([], false, true)}
		with data.yashigani.document.policies as _policies_log_pii
}

# ---------------------------------------------------------------------------
# 8. FAIL-CLOSED — matched class with no applicable policy ⇒ BLOCK
# ---------------------------------------------------------------------------
test_fail_closed_unpoliced_class if {
	# PCI match but only a PII policy is configured → no clearance → BLOCK.
	document.action == "BLOCK" with input as {"document": _doc([_match_card], true, true)}
		with data.yashigani.document.policies as _policies_log_pii
}

# ---------------------------------------------------------------------------
# 9. FAIL-CLOSED — PSEUDONYMIZE on unsupported format ⇒ BLOCK
# ---------------------------------------------------------------------------
test_fail_closed_unsupported_format if {
	document.action == "BLOCK" with input as {"document": _doc([_match_email], true, false)}
		with data.yashigani.document.policies as _policies_pseudo_pii
}

# ---------------------------------------------------------------------------
# 10. F2 — small-set residual-QI escalation ⇒ BLOCK
# ---------------------------------------------------------------------------
test_f2_small_set_escalation if {
	doc := {
		"format": "xlsx",
		"extraction_complete": true,
		"segment_kinds": ["BODY"],
		"matches": [_match_dob_qi],
		"record_count": 5, # ≤ default threshold 20
		"reid_handle": "cap-xyz",
		"pseudonymize_supported": true,
		"redaction_supported": true,
	}
	document.action == "BLOCK" with input as {"document": doc}
		with data.yashigani.document.policies as _policies_pseudo_pii
}

# F2 — same small set but escalation disabled in the policy ⇒ PSEUDONYMIZE (no block).
test_f2_no_escalation_when_disabled if {
	doc := {
		"format": "xlsx",
		"extraction_complete": true,
		"segment_kinds": ["BODY"],
		"matches": [_match_dob_qi],
		"record_count": 5,
		"reid_handle": "cap-xyz",
		"pseudonymize_supported": true,
		"redaction_supported": true,
	}
	policies := [{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "PSEUDONYMIZE" with input as {"document": doc}
		with data.yashigani.document.policies as policies
}

# ---------------------------------------------------------------------------
# 11. per_match_actions populated for PSEUDONYMIZE; empty for LOG
# ---------------------------------------------------------------------------
test_per_match_actions_populated if {
	pma := document.per_match_actions with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_pseudo_pii
	count(pma) == 1
	pma[0].token == "pii_email_1"
}

test_per_match_actions_empty_for_log if {
	pma := document.per_match_actions with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_log_pii
	count(pma) == 0
}

# ---------------------------------------------------------------------------
# 12. self-describing contract present
# ---------------------------------------------------------------------------
test_decision_contract_present if {
	d := document.decision with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_pseudo_pii
	d.policy_id == "DOC-ENFORCE-001"
	d.code == "DOCUMENT_PII_PSEUDONYMIZED"
	d.user_message != ""
	d.action == "PSEUDONYMIZE"
	d.detokenize_rbac_role == "doc-pseudonymize-reverser"
	d.replacer_map_ttl == 300
	d.replacer_map_handle == "cap-xyz"
}

# config override flows through.
test_config_override if {
	d := document.decision with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as _policies_pseudo_pii
		with data.yashigani.document.config as {"detokenize_role": "custom-reverser", "map_ttl_seconds": 60, "small_set_threshold": 5}
	d.detokenize_rbac_role == "custom-reverser"
	d.replacer_map_ttl == 60
}

# ---------------------------------------------------------------------------
# 13. namespace-prefix class match — policy "PII" matches match "PII.EMAIL"
# ---------------------------------------------------------------------------
test_namespace_prefix_class_match if {
	# An exact-class policy must also work.
	policies := [{"data_class": "PII.EMAIL", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "REDACT" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# ---------------------------------------------------------------------------
# 14. The four example policies drive the right action on representative matches.
#     (PII-1 PSEUDONYMIZE, PII-2 REDACT, PCI-1 PSEUDONYMIZE, PCI-2 REDACT.)
# ---------------------------------------------------------------------------

_match_pci_pan := {"data_class": "PCI.PAN", "qi": false, "instance": "41****11", "location": "TABLE_CELL:sheet=S!B2:span=0-19"}

_match_ni_qi := {"data_class": "PII.NATIONAL_INSURANCE", "qi": true, "instance": "AA****0A", "location": "TABLE_CELL:sheet=S!F2:span=0-13"}

# PII-1 — PII detected → PSEUDONYMIZE (mode A).
test_example_pii_1_pseudonymize if {
	policies := [{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "PSEUDONYMIZE" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# PII-2 — PII detected → REDACT.
test_example_pii_2_redact if {
	policies := [{"data_class": "PII", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "REDACT" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# PCI-1 — PCI cardholder data (PAN) detected → PSEUDONYMIZE.
test_example_pci_1_pseudonymize if {
	policies := [{"data_class": "PCI", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "PSEUDONYMIZE" with input as {"document": _doc([_match_pci_pan], true, true)}
		with data.yashigani.document.policies as policies
}

# PCI-2 — PCI cardholder data (PAN) detected → REDACT.
test_example_pci_2_redact if {
	policies := [{"data_class": "PCI", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "A", "small_set_escalation": false}]
	document.action == "REDACT" with input as {"document": _doc([_match_pci_pan], true, true)}
		with data.yashigani.document.policies as policies
}

# ---------------------------------------------------------------------------
# 15. L-01 — broadened QI (NATIONAL_INSURANCE) escalates a small PSEUDONYMIZE set.
#     A small set carrying a National-Insurance quasi-identifier escalates to
#     BLOCK under PII-1 (PSEUDONYMIZE + small_set_escalation) — the gate the
#     pipeline now fires on the wired path is mirrored in the rego.
# ---------------------------------------------------------------------------
test_example_pii_1_small_set_ni_escalates if {
	doc := {
		"format": "xlsx",
		"extraction_complete": true,
		"segment_kinds": ["TABLE_CELL"],
		"matches": [_match_email, _match_ni_qi],
		"record_count": 30, # ≤ threshold (raised below)
		"reid_handle": "cap-xyz",
		"pseudonymize_supported": true,
		"redaction_supported": true,
	}
	policies := [{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "A", "small_set_escalation": true}]
	document.action == "BLOCK" with input as {"document": doc}
		with data.yashigani.document.policies as policies
		with data.yashigani.document.config as {"small_set_threshold": 50}
}

# format/route scoping — a policy scoped to a different format does NOT apply,
# leaving the match unpoliced ⇒ BLOCK.
test_format_scoping_unmatched_blocks if {
	policies := [{"data_class": "PII", "format": "pdf", "route": "any", "action": "LOG", "pseudonymize_mode": "A", "small_set_escalation": false}]
	# document is xlsx, policy is pdf → no applicable policy → unpoliced → BLOCK.
	document.action == "BLOCK" with input as {"document": _doc([_match_email], true, true)}
		with data.yashigani.document.policies as policies
}

# default-deny when NO policies and NO matches but extraction incomplete.
test_default_block_no_input if {
	document.action == "BLOCK" with input as {}
}

# ---------------------------------------------------------------------------
# 16. PART 2 (Laura D1) field-role routing — ROUTE_LOCAL.
#     An OPERATE_ON sensitive field (e.g. SALARY/AMOUNT/IBAN/DOB) on a CLOUD-bound
#     (mode-B) PSEUDONYMIZE escalates the disposition to ROUTE_LOCAL: the whole
#     document is routed to the LOCAL model rather than blobbing a value the cloud
#     would hallucinate over.  Precedence: BLOCK > REDACT > ROUTE_LOCAL >
#     PSEUDONYMIZE > LOG.
# ---------------------------------------------------------------------------

# An OPERATE_ON sensitive match (currency amount the cloud would sum/compute on).
_match_amount_operate := {
	"data_class": "PII.AMOUNT",
	"qi": false,
	"instance": "£**,***",
	"location": "TABLE_CELL:sheet=S!C2:span=0-7",
	"field_role": "OPERATE_ON",
}

# An OPERATE_ON sensitive IBAN (checksum-validated by the model).
_match_iban_operate := {
	"data_class": "PII.IBAN",
	"qi": false,
	"instance": "GB**...**",
	"location": "TABLE_CELL:sheet=S!D2:span=0-21",
	"field_role": "OPERATE_ON",
}

# A REFERENCE_ONLY match (email — safe to opaque-tokenise; no ROUTE_LOCAL).
_match_email_reference := {
	"data_class": "PII.EMAIL",
	"qi": false,
	"instance": "j***@e.com",
	"location": "BODY:p1:span=0-9",
	"field_role": "REFERENCE_ONLY",
}

# A pseudonymize policy on the cloud egress route (the matrix asks PSEUDONYMIZE).
_policies_pseudo_pii_b := [{
	"data_class": "PII",
	"format": "any",
	"route": "any",
	"action": "PSEUDONYMIZE",
	"pseudonymize_mode": "B",
	"small_set_escalation": false,
}]

# 16a — OPERATE_ON sensitive + cloud (mode B) + PSEUDONYMIZE ⇒ ROUTE_LOCAL.
test_route_local_operate_on_sensitive_cloud if {
	document.action == "ROUTE_LOCAL" with input as {
		"document": _doc([_match_amount_operate], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16b — REFERENCE_ONLY field on the same cloud PSEUDONYMIZE ⇒ normal PSEUDONYMIZE.
test_route_local_reference_only_stays_pseudonymize if {
	document.action == "PSEUDONYMIZE" with input as {
		"document": _doc([_match_email_reference], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16c — OPERATE_ON sensitive but MODE A (table stays under the user's local
# control, not cloud-bound) ⇒ normal PSEUDONYMIZE (the seam fires on mode B only).
test_route_local_mode_a_stays_pseudonymize if {
	document.action == "PSEUDONYMIZE" with input as {
		"document": _doc([_match_amount_operate], true, true),
		"request": {"pseudonymize_mode": "A"},
	}
		with data.yashigani.document.policies as [{
			"data_class": "PII", "format": "any", "route": "any",
			"action": "PSEUDONYMIZE", "pseudonymize_mode": "A",
			"small_set_escalation": false,
		}]
}

# 16d — precedence: REDACT configured beats ROUTE_LOCAL (the operate-on field is
# permanently removed, so there is nothing for the cloud to hallucinate over).
test_route_local_redact_wins if {
	policies := [
		{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "B", "small_set_escalation": false},
		{"data_class": "PII", "format": "any", "route": "any", "action": "REDACT", "pseudonymize_mode": "B", "small_set_escalation": false},
	]
	document.action == "REDACT" with input as {
		"document": _doc([_match_amount_operate], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as policies
}

# 16e — precedence: BLOCK configured beats ROUTE_LOCAL (a hold still wins).
test_route_local_block_wins if {
	policies := [
		{"data_class": "PII", "format": "any", "route": "any", "action": "PSEUDONYMIZE", "pseudonymize_mode": "B", "small_set_escalation": false},
		{"data_class": "PII", "format": "any", "route": "any", "action": "BLOCK", "pseudonymize_mode": "B", "small_set_escalation": false},
	]
	document.action == "BLOCK" with input as {
		"document": _doc([_match_amount_operate], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as policies
}

# 16f — precedence: ROUTE_LOCAL beats a plain (non-escalated) PSEUDONYMIZE when
# both an operate-on sensitive AND a reference-only field are present on mode B.
test_route_local_beats_pseudonymize_mixed if {
	document.action == "ROUTE_LOCAL" with input as {
		"document": _doc([_match_email_reference, _match_iban_operate], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16g — ROUTE_LOCAL fires even on an UNSUPPORTED re-render format (it forwards the
# ORIGINAL bytes to the local model — no re-render needed), rather than BLOCKing.
test_route_local_unsupported_format_still_routes if {
	document.action == "ROUTE_LOCAL" with input as {
		"document": _doc([_match_amount_operate], true, false),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16h — unknown OPERATE_ON class is fail-safe SENSITIVE ⇒ ROUTE_LOCAL (mirrors the
# Python is_operate_on_sensitive fail-safe: unknown operate-on class is sensitive).
test_route_local_unknown_operate_on_is_sensitive if {
	unknown := {
		"data_class": "PII.MYSTERY_VALUE",
		"qi": false,
		"instance": "***",
		"location": "BODY:p1:span=0-3",
		"field_role": "OPERATE_ON",
	}
	document.action == "ROUTE_LOCAL" with input as {
		"document": _doc([unknown], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16i — known OPERATE_ON but NON-sensitive class (PHONE/DATE) does NOT route local;
# it stays a normal PSEUDONYMIZE (mirrors _operate_on_nonsensitive_classes).
test_route_local_nonsensitive_operate_on_stays_pseudonymize if {
	phone := {
		"data_class": "PII.PHONE",
		"qi": false,
		"instance": "+44******",
		"location": "BODY:p1:span=0-9",
		"field_role": "OPERATE_ON",
	}
	document.action == "PSEUDONYMIZE" with input as {
		"document": _doc([phone], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
}

# 16j — self-describing contract on a ROUTE_LOCAL decision: code, user_message,
# allow, obligation, operate_on_classes breadcrumb all present + correct.
test_route_local_decision_contract if {
	d := document.decision with input as {
		"document": _doc([_match_amount_operate, _match_iban_operate], true, true),
		"request": {"pseudonymize_mode": "B"},
	}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
	d.action == "ROUTE_LOCAL"
	d.code == "DOCUMENT_ROUTED_LOCAL"
	d.allow == true
	d.user_message != ""
	d.policy_id == "DOC-ENFORCE-001"
	d.operate_on_classes == {"PII.AMOUNT", "PII.IBAN"}
	"route_document_to_local_model" in d.obligations
	"audit_document_decision" in d.obligations
}

# 16k — a LOG/PSEUDONYMIZE decision carries an EMPTY operate_on_classes set (the
# breadcrumb is ROUTE_LOCAL-only).
test_operate_on_classes_empty_off_route_local if {
	d := document.decision with input as {"document": _doc([_match_email_reference], true, true)}
		with data.yashigani.document.policies as _policies_pseudo_pii_b
	count(d.operate_on_classes) == 0
}
