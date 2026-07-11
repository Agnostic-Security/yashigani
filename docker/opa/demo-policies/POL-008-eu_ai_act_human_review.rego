package clients.eu_ai_act_human_review
import rego.v1

# Policy: EU AI Act Human-in-the-Loop
# policy_id: POL-008
# user_message: High-risk AI decisions require human review before enactment (EU AI Act Art.14).

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_high_risk_purposes := {"policy_promotion", "governance_change", "access_grant", "identity_change"}

deny contains "POL-008:human_review_required" if {
    input.request.purpose in _high_risk_purposes
    not input.request.human_approved == true
}

obligations contains "require_human_approval" if {
    input.request.purpose in _high_risk_purposes
}

obligations contains "audit_high_risk_decision" if {
    input.request.purpose in _high_risk_purposes
}
