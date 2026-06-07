# Tests for the #16 client-policy aggregator (package client_enforce).
package client_enforce

import rego.v1

# Reusable mock client policies (data.clients[name].decision).
_clients := {
	"deny_secrets": {"decision": {"allow": false, "deny": {"secrets_egress"}, "obligations": set()}},
	"deny_region": {"decision": {"allow": false, "deny": {"region_blocked"}, "obligations": set()}},
	"allow_audit": {"decision": {"allow": true, "deny": set(), "obligations": {"audit_high_value"}}},
	"allow_redact": {"decision": {"allow": true, "deny": set(), "obligations": {"redact_pii"}}},
}

_scope := {"_scope": {"kind": "agent", "id": "openclaw"}, "_direction": "ingress"}

# 1. No binding for this scope+direction -> no-op allow (passes through to core gates).
test_no_binding_is_noop_allow if {
	a := aggregate with input as _scope
		with data.client_bindings as {}
		with data.clients as _clients
	a.allow == true
	count(a.deny) == 0
	count(a.evaluated) == 0
}

# 2. A single bound denying policy propagates its deny code and flips allow false.
test_single_deny_propagates if {
	a := aggregate with input as _scope
		with data.client_bindings as {"agent:openclaw": {"ingress": ["deny_secrets"]}}
		with data.clients as _clients
	a.allow == false
	"secrets_egress" in a.deny
	"deny_secrets" in a.evaluated
}

# 3. Multiple bound denying policies -> union of all deny codes.
test_multi_policy_deny_union if {
	a := aggregate with input as _scope
		with data.client_bindings as {"agent:openclaw": {"ingress": ["deny_secrets", "deny_region"]}}
		with data.clients as _clients
	a.allow == false
	"secrets_egress" in a.deny
	"region_blocked" in a.deny
	count(a.deny) == 2
}

# 4. Dangling binding (policy missing from data.clients) -> fail-closed synthetic deny.
test_dangling_binding_fail_closed if {
	a := aggregate with input as _scope
		with data.client_bindings as {"agent:openclaw": {"ingress": ["ghost_policy"]}}
		with data.clients as _clients
	a.allow == false
	"bound_policy_missing:ghost_policy" in a.deny
}

# 5. Wildcard (kind:*) and specific (kind:id) bindings both apply (union).
test_wildcard_and_specific_union if {
	a := aggregate with input as _scope
		with data.client_bindings as {
			"agent:*": {"ingress": ["allow_audit"]},
			"agent:openclaw": {"ingress": ["deny_secrets"]},
		}
		with data.clients as _clients
	a.allow == false # the specific deny wins
	"secrets_egress" in a.deny
	"allow_audit" in a.evaluated
	"deny_secrets" in a.evaluated
}

# 6. All bound policies allow -> allow true, obligations unioned.
test_obligations_union_on_allow if {
	a := aggregate with input as _scope
		with data.client_bindings as {"agent:openclaw": {"ingress": ["allow_audit", "allow_redact"]}}
		with data.clients as _clients
	a.allow == true
	count(a.deny) == 0
	"audit_high_value" in a.obligations
	"redact_pii" in a.obligations
}

# 7. Direction isolation: an egress binding does NOT apply to an ingress request.
test_direction_isolation if {
	a := aggregate with input as _scope
		with data.client_bindings as {"agent:openclaw": {"egress": ["deny_secrets"]}}
		with data.clients as _clients
	a.allow == true # nothing bound to ingress
	count(a.evaluated) == 0
}

# 8. Scope-kind isolation: a binding for a different kind does NOT apply.
test_scope_kind_isolation if {
	a := aggregate with input as _scope
		with data.client_bindings as {"human:openclaw": {"ingress": ["deny_secrets"]}}
		with data.clients as _clients
	a.allow == true
	count(a.evaluated) == 0
}
