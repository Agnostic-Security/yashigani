# EXAMPLE / ILLUSTRATIVE — PCI DSS v4.0.1 cardholder-data control for an AI gateway.
#
# Demonstrates how Yashigani-style OPA can keep cardholder data out of LLM/agent
# traffic. NOT a turnkey control — tune tags, providers and obligations to the
# client's CDE and have their QSA review it.
#
# Decision document:  data.clients.pci.decision = {allow, deny, obligations}
#
# Inputs (gateway-supplied; the inspection pipeline tags prompt/response content):
#   input.data_tags[]                 content labels, e.g. "PAN","CHD","CVV"
#   input.routing_decision.route      "local" | "cloud"
#   input.routing_decision.provider   provider id
#   input.response_pan_detected       bool — PAN found in the response body
#   input.response_pan_masked         bool — PAN was masked (first6/last4)
#
# Operator data bundle:
#   data.clients.pci.compliant_providers[]  providers inside the client CDE / AOC
#
# NOTE on the helper pattern: negated optional fields use `_pred if ...; default _pred := false`.
# Writing `not input.foo in set` directly FAILS OPEN when input.foo is absent
# (in OPA, `not <undefined>` is not true). The default makes absent ⇒ deny (fail-closed).
package clients.pci

import rego.v1

# Sensitive Authentication Data — must never be stored or forwarded (Req 3.3.1).
sad_tags := {"SAD", "CVV", "CVV2", "TRACK_DATA", "PIN", "PIN_BLOCK"}

# Cardholder Data.
chd_tags := {"PAN", "CHD", "CARDHOLDER_NAME", "EXPIRY"}

_tags := {t | some t in input.data_tags}
_compliant := {p | some p in data.clients.pci.compliant_providers}

_has_sad if {
	some t in sad_tags
	t in _tags
}

_has_chd if {
	some t in chd_tags
	t in _tags
}

_to_cloud if input.routing_decision.route == "cloud"

default _provider_compliant := false

_provider_compliant if input.routing_decision.provider in _compliant

default _pan_masked := false

_pan_masked if input.response_pan_masked == true

# Req 3.3.1 — SAD is categorically blocked, regardless of route or role.
deny contains "sensitive_authentication_data_present" if _has_sad

# Req 3 & 4 — CHD must not egress to a provider outside the CDE / AOC.
deny contains "chd_egress_to_noncompliant_provider" if {
	_has_chd
	_to_cloud
	not _provider_compliant
}

# Req 3.4.1 — PAN must be masked (max first 6 / last 4) when returned.
deny contains "unmasked_pan_in_response" if {
	input.response_pan_detected == true
	not _pan_masked
}

default allow := false

allow if count(deny) == 0

# Req 10 — every access to CHD is logged, allowed or not.
obligations contains "audit_chd_access" if _has_chd

# The gateway must redact before delivery when PAN is unmasked.
obligations contains "redact_pan" if {
	input.response_pan_detected == true
	not _pan_masked
}

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.pci.pci-dss"
user_message := "Blocked by PCI-DSS policy: sensitive authentication data, egress to a non-compliant provider, or an unmasked card number (PAN) was detected."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
