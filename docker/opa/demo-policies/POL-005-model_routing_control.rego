package clients.model_routing_control
import rego.v1

# Policy: Model Routing Control
# policy_id: POL-005
# user_message: Only approved AI models may be used for sensitive data processing.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_approved_models := {"gemma3:4b", "phi4-mini", "llama3.1:8b", "qwen2.5:3b"}

deny contains "POL-005:unapproved_model" if {
    model := input.routing_decision.model
    not model in _approved_models
    input.data_tags[_] == "sensitive"
}

obligations contains "log_model_selection" if {
    input.routing_decision.model != ""
}
