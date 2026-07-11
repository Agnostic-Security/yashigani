package clients.data_access_control
import rego.v1

# Policy: Data Access Control
# policy_id: POL-001
# user_message: Access to sensitive data requires membership in data-team.
# Applies to: data-team users accessing /v1/** routes
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check data-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "data-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_data_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "data-team"
}

deny contains "POL-001:data_access_denied" if {
    not _data_team_member
    startswith(input.path, "/v1/data")
}

obligations contains "audit_data_access" if {
    startswith(input.path, "/v1/data")
}
