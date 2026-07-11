package clients.finance_read_only
import rego.v1

# Policy: Finance Read-Only Enforcement
# policy_id: POL-002
# user_message: Finance team users may only read (GET) financial endpoints.
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check finance-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "finance-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_finance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "finance-team"
}

deny contains "POL-002:write_forbidden_finance" if {
    _finance_team_member
    input.method != "GET"
    startswith(input.path, "/v1/finance")
}

obligations contains "audit_finance_access" if {
    _finance_team_member
}
