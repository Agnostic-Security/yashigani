package clients.compliance_audit_log
import rego.v1

# Policy: Compliance Audit Logging
# policy_id: POL-003
# user_message: All compliance-team actions are subject to mandatory audit logging.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# Compliance team has broad access but all actions must be audited
obligations contains "mandatory_audit_log" if {
    "compliance-team" in input.identity.groups
}

deny contains "POL-003:compliance_pii_redact_required" if {
    "compliance-team" in input.identity.groups
    input.data_tags[_] == "pii"
    not "audit_log" in input.obligations
}
