# EXAMPLE / ILLUSTRATIVE — Secret / credential egress prevention for an AI gateway.
# Cross-vertical (PCI Req 6/8, ISO 27001 A.8, SOC 2 CC6, NIST 800-53 SC-28). Generic starter:
# stop API keys, tokens and connection strings being sent to a model or returned.
#
# Decision document:  data.clients.secrets.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   input.data_tags[]                 detector labels on prompt/response content
#   input.routing_decision.route      "local" | "cloud"
package clients.secrets

import rego.v1

secret_tags := {
	"API_KEY", "PRIVATE_KEY", "PASSWORD", "AWS_SECRET_KEY", "GCP_SA_KEY",
	"JWT", "BEARER_TOKEN", "SSH_KEY", "DB_CONNECTION_STRING", "OAUTH_TOKEN",
}

_tags := {t | some t in input.data_tags}

_has_secret if {
	some t in secret_tags
	t in _tags
}

_to_cloud if input.routing_decision.route == "cloud"

# Secret material must never be forwarded to a model (local or cloud).
deny contains "secret_material_in_payload" if _has_secret

default allow := false

allow if count(deny) == 0

obligations contains "redact_secret" if _has_secret

# If it already egressed to a third party, the secret must be treated as compromised.
obligations contains "rotate_exposed_secret" if {
	_has_secret
	_to_cloud
}

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.secrets.secret-egress"
user_message := "Blocked: this request contained secret material (keys, tokens, or credentials) that must not leave the environment."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
