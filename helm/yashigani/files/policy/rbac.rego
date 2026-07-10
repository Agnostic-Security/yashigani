# Yashigani RBAC — OPA enforcement module.
#
# Deny-by-default: if data.yashigani.rbac is empty or the user has no
# groups, allow_rbac evaluates to false.
#
# data.yashigani.rbac is populated by rbac/opa_push.py after every mutation
# via a PUT to /v1/data/yashigani/rbac.
#
# Input fields consumed:
#   input.session.email    — user email resolved from the gateway session
#   input.request.method   — HTTP method
#   input.request.path     — request path

package yashigani

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ---------------------------------------------------------------------------
# allow_rbac — true if the user is in a group that permits the request
# ---------------------------------------------------------------------------

allow_rbac if {
    # Require RBAC data to be present and non-empty
    count(data.yashigani.rbac.groups) > 0

    email := input.session.email
    email != ""

    # Walk user → group → pattern
    group_id := data.yashigani.rbac.user_groups[email][_]
    group    := data.yashigani.rbac.groups[group_id]
    pattern  := group.allowed_resources[_]

    _method_matches(pattern.method, input.request.method)
    _path_matches(pattern.path_glob, input.request.path)
}

# ---------------------------------------------------------------------------
# Method helper — "*" matches anything; otherwise exact match
# ---------------------------------------------------------------------------

_method_matches(pattern, method) if { pattern == "*" }
_method_matches(pattern, method) if { pattern == method }

# ---------------------------------------------------------------------------
# Path helper — mirrors store.py _path_matches exactly
#
#   "**"           — any path
#   "/prefix/**"   — /prefix/ and anything underneath
#   exact string   — only that path
# ---------------------------------------------------------------------------

_path_matches(glob, path) if { glob == "**" }
_path_matches(glob, path) if { glob == path }
_path_matches(glob, path) if {
    endswith(glob, "/**")
    prefix := trim_suffix(glob, "/**")
    startswith(path, concat("", [prefix, "/"]))
}

# #4 — self-describing denial for the RBAC gate (same package `yashigani`,
# contributes to the shared `denials` set consumed by the gateway deny response).
denials contains {
    "policy_id": "yashigani.rbac.group-permission",
    "rule": "RBAC group permission",
    "user_message": "Blocked by access policy: your group is not permitted to use this resource.",
    "code": 403,
    "action": "DENIED",
} if { deny_rbac }
