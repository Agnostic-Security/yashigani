# EXAMPLE / ILLUSTRATIVE — Classification & clearance control for an AI gateway.
# Defence / government context (UK Govt Security Classifications; maps to NIST 800-53
# AC-3/AC-4/AC-16, UK MoD Secure by Design). Generic starter — adapt labels, caveats
# and ranks to the client's national scheme, then have their accreditor review it.
#
# Decision document:  data.clients.gov.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   _rank                                  classification scheme + numeric order
#   input.identity.clearance               subject clearance label
#   input.identity.caveats[]               handling caveats the subject holds (e.g. "UK_EYES_ONLY")
#   input.identity.compartments[]          need-to-know compartments the subject is read into
#   input.data.classification              data classification label
#   input.data.caveats[] / .compartment    data handling caveats / compartment
#   input.routing_decision.route           "local" | "cloud"
package clients.gov

import rego.v1

# Classification scheme (illustrative). Higher = more sensitive.
_rank := {"OFFICIAL": 0, "OFFICIAL-SENSITIVE": 1, "SECRET": 2, "TOP SECRET": 3}

# Fail-closed ranking: an unknown DATA label ranks above the top (deny to everyone);
# an unknown CLEARANCE ranks below the bottom (grants nothing).
classification_rank(l) := _rank[l]
classification_rank(l) := 99 if not l in object.keys(_rank)

clearance_rank(l) := _rank[l]
clearance_rank(l) := -1 if not l in object.keys(_rank)

_id_caveats := {c | some c in input.identity.caveats}
_id_compartments := {g | some g in input.identity.compartments}

# Fail-closed presence check — recommended pattern: a missing label is a violation,
# not a silent allow. (The other example policies omit this for brevity; add it.)
deny contains "classification_label_missing" if not input.data.classification

# AC-3 "no read up" — clearance must dominate the data classification.
deny contains "clearance_below_classification" if {
	clearance_rank(input.identity.clearance) < classification_rank(input.data.classification)
}

# AC-4 / sovereignty — SECRET and above must never leave for a commercial cloud model.
deny contains "classified_data_to_cloud" if {
	classification_rank(input.data.classification) >= _rank["SECRET"]
	input.routing_decision.route == "cloud"
}

# AC-16 — every data caveat must be satisfied by a caveat the subject holds.
deny contains sprintf("caveat_not_satisfied:%s", [c]) if {
	some c in input.data.caveats
	not c in _id_caveats
}

# Need-to-know compartment.
deny contains "compartment_not_authorised" if {
	input.data.compartment != ""
	not input.data.compartment in _id_compartments
}

default allow := false

allow if count(deny) == 0

# Two-person integrity for the most sensitive export; audit from OFFICIAL-SENSITIVE up.
obligations contains "two_person_integrity" if {
	classification_rank(input.data.classification) >= _rank["TOP SECRET"]
}

obligations contains "audit_classified_access" if {
	classification_rank(input.data.classification) >= _rank["OFFICIAL-SENSITIVE"]
}

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.gov.classification-control"
user_message := "Blocked by classification policy: the data classification, your clearance, required caveats, or compartment authorisation were not satisfied."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
