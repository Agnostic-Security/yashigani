# LAURA-OPA deny-override class-fix (2.25.2) — top-level allow regression tests
#
# These tests prove the deny-overrides restructure in yashigani.rego: a positive
# `allow if {...}` and a deny condition can NEVER co-fire. Previously the policy
# used `allow := false if {deny_rbac}` / `allow := false if {deny_agent_call}`,
# which produced TWO complete-rule outputs (true + false) → eval_conflict_error
# (OPA 500 → opaque fail-closed deny). The fix folds every deny into a single
# `_denied` set negated inside the one allow rule, so `allow` is a single,
# clean-valued decision.
#
# `opa test` itself FAILS a test that triggers an eval_conflict during evaluation,
# so each of these tests passing IS the proof that no conflict arises.
#
# Run with: opa test policy/
package yashigani_test

import future.keywords.if

# ── RBAC deny-override: clean single-valued false, no eval_conflict ──────────
#
# RBAC data that loads the gate (non-empty groups) but does NOT permit the caller
# is inlined per test via `with data as {...}` (a package-level helper rule used in
# a `with data as` clause trips OPA's recursion analysis).

# Laura repro #1: a session that passes session/method/path checks but is NOT
# RBAC-permitted. Pre-fix: allow=true (general rule) co-fired allow:=false
# (deny_rbac) → eval_conflict. Post-fix: clean false.
test_rbac_not_permitted_clean_deny_no_conflict if {
    not data.yashigani.allow with data.yashigani.rbac as {"groups": {"admins": ["u9"]}, "users": {}} with input as {
        "session_id": "sh",
        "agent_id": "agentX",
        "method": "GET",
        "path": "/v1/chat",
        "session": {"email": "nope@x"},
    }
}

# Decision preserved: when RBAC permits the caller, allow stays true (no regression).
# allow_rbac (rbac.rego) matches input.session.email → user_groups → group
# allowed_resources (method + path_glob); reads input.request.{method,path}.
test_rbac_permitted_still_allows if {
    data.yashigani.allow with data.yashigani.rbac as {
        "groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "**"}]}},
        "user_groups": {"nope@x": ["eng"]},
    } with input as {
        "session_id": "sh",
        "agent_id": "agentX",
        "method": "GET",
        "path": "/v1/chat",
        "session": {"email": "nope@x"},
        "request": {"method": "GET", "path": "/v1/chat"},
    }
}

# RBAC absent/empty → gate open (backwards-compat preserved).
test_rbac_absent_allows if {
    data.yashigani.allow with input as {
        "session_id": "sh",
        "agent_id": "agentX",
        "method": "GET",
        "path": "/v1/chat",
    }
}

# ── Agent deny-override: clean single-valued false, no eval_conflict ─────────

# An agent principal whose agent_call is NOT allowed. Pre-fix: if any positive
# allow had fired it would have co-fired allow:=false(deny_agent_call). Post-fix:
# clean false, deterministically, with no eval_conflict.
test_agent_call_not_allowed_clean_deny_no_conflict if {
    not data.yashigani.allow with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["nope"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["yes"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
        "session_id": "sh",
        "method": "GET",
        "path": "/mcp/x",
    }
}

# Decision preserved: a legit agent call still allows (no regression).
# RBAC absent → gate open; agent_call_allowed true → allow true.
test_agent_call_allowed_still_allows if {
    data.yashigani.allow with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["analytics"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["analytics"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
        "session_id": "sh",
        "method": "GET",
        "path": "/mcp/x",
    }
}

# RBAC deny still wins even for an otherwise-legit agent call (deny-overrides):
# the agent positive rule includes `not _denied`, so a loaded-but-unpermitting
# RBAC dataset denies the agent too — single-valued false, no conflict.
test_agent_call_denied_by_rbac_no_conflict if {
    not data.yashigani.allow with data.yashigani.rbac as {"groups": {"admins": ["u9"]}, "users": {}} with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["analytics"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["analytics"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
        "session_id": "sh",
        "method": "GET",
        "path": "/mcp/x",
    }
}

# ── Human MCP session deny-override ─────────────────────────────────────────

# Human MCP session denied by RBAC: pre-fix the human-MCP allow(true) co-fired
# allow:=false(deny_rbac). Post-fix: clean false.
test_human_mcp_denied_by_rbac_no_conflict if {
    not data.yashigani.allow with data.yashigani.rbac as {"groups": {"admins": ["u9"]}, "users": {}} with input as {
        "session_id": "cookiehash",
        "method": "GET",
        "path": "/mcp/filesystem-mcp",
    }
}

# Human MCP session allowed when RBAC permits (no regression).
test_human_mcp_allowed_when_rbac_permits if {
    data.yashigani.allow with data.yashigani.rbac as {
        "groups": {"users": {"allowed_resources": [{"method": "*", "path_glob": "**"}]}},
        "user_groups": {"u@x": ["users"]},
    } with input as {
        "session_id": "cookiehash",
        "method": "GET",
        "path": "/mcp/filesystem-mcp",
        "session": {"email": "u@x"},
        "request": {"method": "GET", "path": "/mcp/filesystem-mcp"},
    }
}

# ── LAURA-30-006: JWKS endpoint allows anonymous GET ─────────────────────
#
# The public JWKS path must be reachable with no session, no agent_id, no
# RBAC context — external MCP validators need to fetch the gateway public key.

# Unauthenticated GET → allowed (no session, no agent_id).
test_jwks_endpoint_allows_anonymous_get if {
    data.yashigani.allow with input as {
        "method": "GET",
        "path": "/.well-known/yashigani-mcp-jwks.json",
        "session_id": "",
        "agent_id": "",
    }
}

# Unauthenticated GET → also allowed when session is "anonymous".
test_jwks_endpoint_allows_anonymous_session if {
    data.yashigani.allow with input as {
        "method": "GET",
        "path": "/.well-known/yashigani-mcp-jwks.json",
        "session_id": "anonymous",
        "agent_id": "unknown",
    }
}

# POST to the JWKS path is NOT allowed anonymously (must fail default-deny).
test_jwks_endpoint_rejects_anonymous_post if {
    not data.yashigani.allow with input as {
        "method": "POST",
        "path": "/.well-known/yashigani-mcp-jwks.json",
        "session_id": "",
        "agent_id": "",
    }
}

# RBAC gate must NOT widen the JWKS allow: when RBAC is loaded but the
# anonymous caller is not in any group, the JWKS allow still fires because
# deny_rbac only applies inside allow rules that carry `not _denied`.
# The JWKS allow rule does NOT carry `not _denied` — intentional: public key
# material is not gated by session policy.
test_jwks_endpoint_allowed_even_with_rbac_loaded if {
    data.yashigani.allow with data.yashigani.rbac as {
        "groups": {"admins": ["u9"]},
        "users": {},
    } with input as {
        "method": "GET",
        "path": "/.well-known/yashigani-mcp-jwks.json",
        "session_id": "",
        "agent_id": "",
    }
}

# Non-JWKS /.well-known/* paths remain gated (no widening).
test_well_known_internal_still_blocked if {
    not data.yashigani.allow with input as {
        "method": "GET",
        "path": "/.well-known/internal/something",
        "session_id": "",
        "agent_id": "",
    }
}
