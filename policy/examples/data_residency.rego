# EXAMPLE / ILLUSTRATIVE — Data residency / sovereignty for an AI gateway.
# Cross-vertical (GDPR Ch.V, UK DPA, sectoral sovereignty, FedRAMP boundary). Generic starter.
#
# Decision document:  data.clients.residency.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   input.data.region                 region the data must stay in, e.g. "eu","uk","us"
#   input.routing_decision.route      "local" | "cloud"
#   input.routing_decision.provider   provider id
#   data.clients.residency.allowed_providers[region] = ["provider", ...]
package clients.residency

import rego.v1

# Providers permitted to host data for the request's region.
_allowed_for_region := {p | some p in data.clients.residency.allowed_providers[input.data.region]}

_to_cloud if input.routing_decision.route == "cloud"

default _provider_ok := false

_provider_ok if input.routing_decision.provider in _allowed_for_region

# Fail-closed: an unlabelled region cannot be placed safely.
deny contains "data_region_missing" if not input.data.region

# Cloud egress must use a provider approved for the data's region.
deny contains "cross_region_egress" if {
	_to_cloud
	input.data.region
	not _provider_ok
}

default allow := false

allow if count(deny) == 0

obligations contains "log_data_location" if _to_cloud

# Yashigani decision contract — user-facing alert fields:
#   policy_id    ID of the OPA (stable, unique)
#   user_message message to the end user (human or non-human agent)
#   code         HTTP status to return (any standard 1xx–5xx, RFC 9110)
policy_id := "clients.residency.data-residency"
user_message := "Blocked: this request would move data outside its permitted region. Data-residency policy requires the data to stay in-region."
code := 451  # Unavailable For Legal Reasons
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
