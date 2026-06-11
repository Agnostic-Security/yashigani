# clients_aggregate.rego — OPA Phase 2 (#16) client-policy aggregator.
#
# The gateway evaluates the core yashigani.* / yashigani.v1.* gates first; this
# package is queried STRICTLY AFTER them and can only ADD denials, never remove
# one (defence-in-depth, fail-closed). It fans out — in a single OPA round-trip
# per direction — over every client policy BOUND to the caller's scope+direction
# and unions their denials + obligations.
#
# Data contract (pushed by the backoffice under the SEPARATE /v1/data/client_bindings
# namespace so push_rbac_data's PUT /v1/data/yashigani cannot clobber it):
#   data.client_bindings[scope_key][direction] = ["policyA", "policyB", ...]
#   scope_key = "<kind>:<id>" (specific subject) OR "<kind>:*" (all of that kind)
# Gateway supplies input._scope.{kind,id} and input._direction (ingress|egress).
# Each bound policy is data.clients[name].decision = {allow, deny:set, obligations:set}.
package client_enforce

import rego.v1

# Fail-closed default: if this rule is undefined (module missing / bad input) the
# gateway treats a non-dict result as deny (see _client_enforce.py).
default aggregate := {
	"allow": false,
	"deny": {"client_enforce_undefined"},
	"obligations": set(),
	"evaluated": set(),
}

# The two scope keys that apply to this caller: the specific subject and the
# kind-wildcard. Both are unioned so a "agent:*" rule and an "agent:openclaw"
# rule both bind.
_scope_keys := {
	sprintf("%s:%s", [input._scope.kind, input._scope.id]),
	sprintf("%s:*", [input._scope.kind]),
}

# Policy names bound to this scope+direction (union of specific + wildcard keys).
_bound_names := {name |
	some sk in _scope_keys
	some name in data.client_bindings[sk][input._direction]
}

# Deny codes: union over every bound policy that denies.
deny contains code if {
	some name in _bound_names
	data.clients[name].decision.allow == false
	some code in data.clients[name].decision.deny
}

# Dangling binding -> fail-closed synthetic deny (the policy was deleted from OPA
# but a binding still references it). Without this, a missing policy would be a
# silent no-op (allow).
deny contains sprintf("bound_policy_missing:%s", [name]) if {
	some name in _bound_names
	not data.clients[name].decision
}

# Obligations: union over every bound policy (audit_* / redact_* directives the
# gateway applies on allow).
obligations contains o if {
	some name in _bound_names
	some o in data.clients[name].decision.obligations
}

# When there ARE bindings: allow iff nothing denied. When there are NO bindings
# for this scope+direction: deny is empty -> allow:true, evaluated:{} -> a clean
# no-op so unbound subjects pass through to the existing core gates unchanged.
aggregate := {
	"allow": count(deny) == 0,
	"deny": deny,
	"obligations": obligations,
	"evaluated": _bound_names,
}
