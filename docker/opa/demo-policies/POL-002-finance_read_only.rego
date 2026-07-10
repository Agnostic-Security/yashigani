package clients.finance_read_only
import rego.v1

# Policy: Finance Read-Only Enforcement
# policy_id: POL-002
# user_message: Finance team users may only read (GET) financial endpoints.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-002:write_forbidden_finance" if {
    "finance-team" in input.identity.groups
    input.method != "GET"
    startswith(input.path, "/v1/finance")
}

obligations contains "audit_finance_access" if {
    "finance-team" in input.identity.groups
}
