package clients.agent_tool_restriction
import rego.v1

# Policy: Agent Tool Restriction
# policy_id: POL-007
# user_message: Destructive tools (delete, purge, drop) are blocked for AI agents by default.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_destructive_tools := {"email.delete", "email.trash", "db.drop", "file.purge", "db.truncate"}

deny contains "POL-007:destructive_tool_blocked" if {
    input.identity.agent != ""
    input.tool in _destructive_tools
}

obligations contains "audit_tool_call" if {
    input.identity.agent != ""
    input.tool != ""
}
