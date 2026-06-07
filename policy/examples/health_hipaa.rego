# EXAMPLE / ILLUSTRATIVE — PHI safeguards for an AI gateway.
# Health context (HIPAA Security Rule 45 CFR 164.308/312/502/514). Generic starter —
# adapt roles, purposes and the BAA provider list, then have the client's privacy
# officer / counsel review it.
#
# Decision document:  data.clients.hipaa.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   input.phi_present                 bool — prompt/request carries PHI
#   input.response_phi_detected       bool — PHI found in the response body
#   input.request.purpose             "treatment" | "payment" | "operations" | ...
#   input.request.break_glass         bool — emergency clinical override
#   input.identity.role               "clinician" | "care_team" | "admin" | ...
#   input.deidentified                bool — 164.514 Safe-Harbor / expert-determination applied
#   input.routing_decision.route      "local" | "cloud"
#   input.routing_decision.provider   provider id
#   data.clients.hipaa.baa_providers[]  vendors with a signed Business Associate Agreement
package clients.hipaa

import rego.v1

_baa := {p | some p in data.clients.hipaa.baa_providers}
_tpo := {"treatment", "payment", "operations"}
_clinical_roles := {"clinician", "care_team", "admin"}

phi if input.phi_present == true

_to_cloud if input.routing_decision.route == "cloud"

default _purpose_tpo := false

_purpose_tpo if input.request.purpose in _tpo

default _provider_has_baa := false

_provider_has_baa if input.routing_decision.provider in _baa

default _deidentified := false

_deidentified if input.deidentified == true

default _role_clinical := false

_role_clinical if input.identity.role in _clinical_roles

default _break_glass := false

_break_glass if input.request.break_glass == true

# 164.502(b) Minimum necessary — PHI use must be for a permitted TPO purpose.
deny contains "phi_purpose_not_minimum_necessary" if {
	phi
	not _purpose_tpo
}

# 164.308(b)/314 — PHI may only reach a cloud model whose vendor has a BAA.
deny contains "phi_to_provider_without_baa" if {
	phi
	_to_cloud
	not _provider_has_baa
}

# 164.514 — PHI sent to the cloud must be de-identified unless it is direct treatment.
deny contains "phi_not_deidentified_for_cloud" if {
	phi
	_to_cloud
	input.request.purpose != "treatment"
	not _deidentified
}

# Response leg — PHI must not be returned to a non-clinical role.
deny contains "phi_response_to_nonclinical_role" if {
	input.response_phi_detected == true
	not _role_clinical
}

default allow := false

allow if count(deny) == 0

# Break-glass — emergency access is permitted but forces post-hoc review + notification.
allow if _break_glass

obligations contains "break_glass_review" if _break_glass

# 164.312(b) — audit controls: log all PHI access.
obligations contains "audit_phi_access" if phi

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.hipaa.hipaa"
user_message := "Blocked under HIPAA policy: PHI handling failed the minimum-necessary, BAA, de-identification, or clinical-role requirements."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
