package clients.pii_redaction_policy
import rego.v1

# Policy: PII Redaction Enforcement
# policy_id: POL-004
# user_message: Personally Identifiable Information must be redacted before transmission to AI models.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-004:pii_transmission_blocked" if {
    input.data_tags[_] == "pii"
    not "pii_redacted" in input.obligations
    not "compliance-team" in input.identity.groups
}

obligations contains "redact_pii" if {
    input.data_tags[_] == "pii"
}
