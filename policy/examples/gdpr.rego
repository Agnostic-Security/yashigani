# EXAMPLE / ILLUSTRATIVE — GDPR processing control for an AI gateway.
# (EU 2016/679: Art 5 purpose limitation/minimisation, Art 6 lawful basis, Art 9 special
# category, Art 18/21 restriction/objection, Art 30 records, Art 44-49 transfers / Schrems II.)
# Generic starter — adapt purposes, regions and safeguards, then have the client's DPO review it.
#
# Decision document:  data.clients.gdpr.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   input.personal_data_present        bool — content contains personal data
#   input.special_category             bool — Art 9 data (health, biometric, race, ...)
#   input.request.lawful_basis         Art 6 basis claimed for this processing
#   input.request.purpose              processing purpose for this request
#   input.request.art9_condition       Art 9(2) condition (when special_category)
#   input.transfer_safeguard           "adequacy_decision" | "scc" | "bcr" | ""
#   input.data.permitted_purposes[]    purposes the data was collected for
#   input.data.subject_id              data-subject identifier
#   input.data.pii_categories[] / .purpose_max_categories  for minimisation hint
#   input.routing_decision.route/.provider
#   data.clients.gdpr.eu_region_providers[]    providers hosting in-region
#   data.clients.gdpr.restricted_subjects[]    subjects who exercised Art 18/21 rights
package clients.gdpr

import rego.v1

_eu := {p | some p in data.clients.gdpr.eu_region_providers}
_restricted := {s | some s in data.clients.gdpr.restricted_subjects}
_valid_basis := {"consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"}
_art9 := {"explicit_consent", "health_care", "public_health", "substantial_public_interest", "employment_social_security"}
_safeguards := {"adequacy_decision", "scc", "bcr"}

personal if input.personal_data_present == true

special if input.special_category == true

_to_cloud if input.routing_decision.route == "cloud"

default _basis_valid := false

_basis_valid if input.request.lawful_basis in _valid_basis

default _purpose_permitted := false

_purpose_permitted if input.request.purpose in {p | some p in input.data.permitted_purposes}

default _provider_in_eu := false

_provider_in_eu if input.routing_decision.provider in _eu

default _has_safeguard := false

_has_safeguard if input.transfer_safeguard in _safeguards

default _art9_ok := false

_art9_ok if input.request.art9_condition in _art9

_subject_restricted if input.data.subject_id in _restricted

# Art 6 — a valid lawful basis is required to process personal data.
deny contains "no_lawful_basis" if {
	personal
	not _basis_valid
}

# Art 5(1)(b) — purpose limitation: the request purpose must be one the data was collected for.
deny contains "purpose_incompatible" if {
	personal
	not _purpose_permitted
}

# Art 44-49 / Schrems II — personal data must stay in-region unless a transfer safeguard exists.
deny contains "international_transfer_without_safeguard" if {
	personal
	_to_cloud
	not _provider_in_eu
	not _has_safeguard
}

# Art 9 — special-category data needs an explicit Art 9(2) condition.
deny contains "special_category_without_condition" if {
	special
	not _art9_ok
}

# Art 18 / 21 — a subject who has restricted or objected must not be processed.
deny contains "subject_processing_restricted" if _subject_restricted

default allow := false

allow if count(deny) == 0

# Art 30 — maintain a record of processing activities.
obligations contains "record_processing_activity" if personal

# Art 5(1)(c) — data-minimisation hint: more PII categories present than the purpose needs.
obligations contains "review_data_minimisation" if {
	personal
	count({c | some c in input.data.pii_categories}) > input.data.purpose_max_categories
}

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.gdpr.gdpr"
user_message := "Blocked under GDPR policy: no lawful basis, an incompatible purpose, an international transfer without safeguards, special-category data, or an active processing restriction."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
