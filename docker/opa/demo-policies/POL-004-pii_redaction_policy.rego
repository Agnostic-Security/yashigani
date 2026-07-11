package clients.pii_redaction_policy
import rego.v1

# Policy: PII Transmission Block
# policy_id: POL-004
# user_message: Content containing PII is blocked. Remove the personal information and try again.
# LAURA-31DR-001 fix: use object.get(input, "obligations", set()) instead of bare
# input.obligations.  In Rego v1, "pii_redacted" in undefined evaluates to
# undefined → not undefined → rule body undefined → deny never fires → silent
# allow-bypass.  object.get defaults to set() when the key is absent, so the
# check evaluates deterministically (false → deny fires as designed).
#
# LAURA-31DR-003 fix: input.identity.groups is never populated for human users
# (identity registry groups field is not synced from RBAC).  Use
# data.yashigani.rbac to check group membership instead.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "compliance-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_compliance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "compliance-team"
}

deny contains "POL-004:pii_transmission_blocked" if {
    input.data_tags[_] == "pii"
    not "pii_redacted" in object.get(input, "obligations", set())
    not _compliance_team_member
}

obligations contains "redact_pii" if {
    input.data_tags[_] == "pii"
}
