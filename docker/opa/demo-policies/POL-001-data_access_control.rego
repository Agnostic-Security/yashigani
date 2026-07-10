package clients.data_access_control
import rego.v1

# Policy: Data Access Control
# policy_id: POL-001
# user_message: Access to sensitive data requires membership in data-team.
# Applies to: data-team users accessing /v1/** routes

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-001:data_access_denied" if {
    not "data-team" in input.identity.groups
    startswith(input.path, "/v1/data")
}

obligations contains "audit_data_access" if {
    startswith(input.path, "/v1/data")
}
