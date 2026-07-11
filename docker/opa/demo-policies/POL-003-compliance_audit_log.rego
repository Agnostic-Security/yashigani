package clients.compliance_audit_log
import rego.v1

# Policy: Compliance Audit Logging
# policy_id: POL-003
# user_message: All compliance-team actions are subject to mandatory audit logging.
# LAURA-31DR-001 fix: use object.get(input, "obligations", set()) instead of bare
# input.obligations so the Rego check is never undefined when the field is absent.
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check compliance-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "compliance-team" via RBAC.
_compliance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "compliance-team"
}

# Compliance team has broad access but all actions must be audited
obligations contains "mandatory_audit_log" if {
    _compliance_team_member
}

deny contains "POL-003:compliance_pii_redact_required" if {
    _compliance_team_member
    input.data_tags[_] == "pii"
    not "audit_log" in object.get(input, "obligations", set())
}
