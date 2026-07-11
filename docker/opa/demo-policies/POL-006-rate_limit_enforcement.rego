package clients.rate_limit_enforcement
import rego.v1

# Policy: Rate Limit Enforcement
# policy_id: POL-006
# user_message: Excessive API usage is blocked to prevent resource exhaustion.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-006:rate_limit_exceeded" if {
    input.identity.request_count > 1000
    input.identity.window_seconds <= 60
}

obligations contains "track_usage" if {
    input.identity.role != ""
}
