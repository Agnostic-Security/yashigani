# UA-07 — OPA agent_call_allowed property tests
#
# Tests the agent_call_allowed rule and agent_call_deny_reason rule in agents.rego.
# Run with: opa test policy/
#
# Coverage:
#   1. Caller in allowed_caller_groups + path in allowed_paths → ALLOW
#   2. Caller NOT in allowed_caller_groups → DENY (caller_group_not_in_allowed_caller_groups)
#   3. Caller in group, path not allowed → DENY (path_not_in_allowed_paths)
#   4. Target agent_id missing/empty → DENY (target_agent_not_in_data)
#   5. Path matching: exact, **, prefix/** patterns, plain-prefix
#   6. Edge cases: empty groups, empty allowed_paths, principal.type != "agent"
#
package yashigani_test

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# 1. ALLOW — caller in allowed_caller_groups + path in allowed_paths
# ---------------------------------------------------------------------------

test_allow_caller_in_group_path_exact if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_allow_caller_with_multiple_groups_one_matches if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["group-a", "analytics-agents", "group-c"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_allow_path_wildcard_star_star if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["all-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["all-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/anything/at/all"},
    }
}

test_allow_path_prefix_slash_star_star if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["writers"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["writers"],
            "allowed_paths": ["/v1/memory/**"],
        },
        "request": {"remainder_path": "/v1/memory/write"},
    }
}

test_allow_path_plain_prefix if {
    # Pattern without * — startswith(path, pattern + "/")
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["readers"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["readers"],
            "allowed_paths": ["/v1/query"],
        },
        "request": {"remainder_path": "/v1/query/results"},
    }
}

test_allow_multiple_paths_second_matches if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["ops"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["ops"],
            "allowed_paths": ["/v1/admin", "/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# ---------------------------------------------------------------------------
# 2. DENY — caller NOT in allowed_caller_groups
# ---------------------------------------------------------------------------

test_deny_caller_group_not_in_allowed if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["unrelated-group"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_deny_reason_caller_group_not_in_allowed if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["unrelated-group"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    r == "caller_group_not_in_allowed_caller_groups"
}

# ---------------------------------------------------------------------------
# 3. DENY — caller in group, path not in allowed_paths
# ---------------------------------------------------------------------------

test_deny_path_not_in_allowed if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/admin"},
    }
}

test_deny_reason_path_not_in_allowed if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/admin"},
    }
    r == "path_not_in_allowed_paths"
}

# ---------------------------------------------------------------------------
# 4. target_agent_id missing or empty — deny_reason fires; allow state documented
#
# POLICY GAP FINDING (UA-07-GAP-001):
# agent_call_allowed does NOT check input.target_agent.agent_id. If allowed_caller_groups
# and allowed_paths are populated but agent_id is absent/empty, agent_call_allowed still
# evaluates to true. Only agent_call_deny_reason="target_agent_not_in_data" surfaces this
# condition. The gateway MUST check deny_reason as the authoritative gate — relying solely
# on agent_call_allowed is insufficient when target_agent data is incomplete.
# Routing: file against Tom (gateway/agent_auth.py decision logic) per §3.4 rule scope.
# ---------------------------------------------------------------------------

# 4a. agent_id absent: deny_reason fires (gateway should reject on deny_reason)
test_deny_reason_target_agent_not_in_data_when_id_missing if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    r == "target_agent_not_in_data"
}

# 4b. agent_id empty string: deny_reason does NOT fire target_agent_not_in_data
# POLICY GAP FINDING (UA-07-GAP-002):
# Rego treats "" (empty string) as truthy — `not input.target_agent.agent_id`
# is FALSE when agent_id == "". The target_agent_not_in_data deny_reason therefore
# does NOT fire for agent_id: "". If caller is in group and paths allow, no deny_reason
# fires at all — call is silently allowed with an empty-string target. Gateway must
# validate target_agent.agent_id is a non-empty string before calling OPA.
# Routing: file against Tom (gateway/agent_auth.py) — pre-OPA input validation.
test_deny_reason_target_agent_empty_string_no_deny_reason_fires if {
    not data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# 4c. agent_id absent with no matching group — UA-07-GAP-003 RESOLVED (2.25.2).
# Previously: target_agent_not_in_data AND caller_group_not_in_allowed_caller_groups
# both fired → agent_call_deny_reason eval_conflict_error (OPA 500). The class-fix
# folds target_agent_not_in_data behind `_caller_group_allowed` (precedence 4), so
# caller-not-authorised (precedence 1) now wins cleanly. The deny_reason MUST now
# evaluate to a single value with NO eval_conflict.
test_deny_reason_conflict_resolved_when_target_id_absent_and_group_mismatch if {
    # Decision unchanged: still denied.
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["unrelated-group"],
        },
        "target_agent": {
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    # Reason is now single-valued (no eval_conflict) and deterministic:
    # caller authorisation (precedence 1) wins over target-data (precedence 4).
    data.yashigani.agent_call_deny_reason == "caller_group_not_in_allowed_caller_groups" with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["unrelated-group"],
        },
        "target_agent": {
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# ---------------------------------------------------------------------------
# 5. Path matching — detailed coverage of _agent_path_matches
# ---------------------------------------------------------------------------

# 5a. "**" matches any path including root
test_path_star_star_matches_root if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/"},
    }
}

test_path_star_star_matches_deep_path if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/a/b/c/d"},
    }
}

# 5b. Exact match
test_path_exact_match if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/health"],
        },
        "request": {"remainder_path": "/v1/health"},
    }
}

test_path_exact_no_match_different_path if {
    # pattern "/v1/healthz" (z suffix) against path "/v1/health" — no match
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/healthz"],
        },
        "request": {"remainder_path": "/v1/health"},
    }
}

# 5c. Prefix-/** pattern
test_path_prefix_slash_star_star_matches_direct_child if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/agents/**"],
        },
        "request": {"remainder_path": "/v1/agents/123"},
    }
}

test_path_prefix_slash_star_star_matches_nested_child if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/agents/**"],
        },
        "request": {"remainder_path": "/v1/agents/123/memory/read"},
    }
}

test_path_prefix_slash_star_star_no_match_on_exact_prefix if {
    # "/v1/agents/**" should NOT match "/v1/agents" itself (no trailing slash)
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/agents/**"],
        },
        "request": {"remainder_path": "/v1/agents"},
    }
}

test_path_prefix_slash_star_star_no_match_on_sibling if {
    # "/v1/agents/**" should NOT match "/v1/agentsx" (sibling, not a child)
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/agents/**"],
        },
        "request": {"remainder_path": "/v1/agentsx"},
    }
}

# 5d. Plain prefix (no * in pattern, startswith path + "/")
test_path_plain_prefix_matches_child if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run/batch"},
    }
}

test_path_plain_prefix_no_match_sibling if {
    # "/v1/run" should NOT match "/v1/runner" (sibling, not a child)
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a", "groups": ["g"]},
        "target_agent": {
            "agent_id": "b",
            "allowed_caller_groups": ["g"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/runner"},
    }
}

# ---------------------------------------------------------------------------
# 6. Edge cases
# ---------------------------------------------------------------------------

# 6a. Principal type is NOT "agent" — rule must not fire; no deny_reason either
test_edge_principal_type_not_agent_no_allow if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "user",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_edge_principal_type_not_agent_no_deny_reason if {
    not data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "user",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# 6b. Empty groups list — caller can never be in allowed_caller_groups
test_edge_empty_caller_groups_no_allow if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": [],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_edge_empty_caller_groups_deny_reason if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": [],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    r == "caller_group_not_in_allowed_caller_groups"
}

# 6c. Empty allowed_paths on target — caller in group but no path can match
test_edge_empty_allowed_paths_no_allow if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": [],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

test_edge_empty_allowed_paths_deny_reason if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": [],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    r == "path_not_in_allowed_paths"
}

# 6d. Principal agent_id empty — agent_call_allowed requires agent_id != ""
test_edge_empty_caller_agent_id_no_allow if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "",
            "groups": ["analytics-agents"],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# 6e. Both caller groups and paths are empty — deny reason is caller_group
test_edge_both_empty_deny_reason_is_caller_group if {
    r := data.yashigani.agent_call_deny_reason with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": [],
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": [],
            "allowed_paths": [],
        },
        "request": {"remainder_path": "/v1/run"},
    }
    r == "caller_group_not_in_allowed_caller_groups"
}

# ---------------------------------------------------------------------------
# 7. GAP-1 closure — sensitivity_rank catch-all (v1_routing.rego)
#
# Ava GAP-1 finding (ava-v241-opa-response-ceiling-verification.md EDGE-1):
# Unknown sensitivity strings previously produced undefined rank, causing
# response_allowed to default true (silent allow). The catch-all assigns
# rank 4 (above RESTRICTED) to any unrecognised string, ensuring fail-closed
# behaviour per ASVS V4.1.3.
#
# Tests exercise:
#   7a. sensitivity_rank("FOO_BAR") == 4
#   7b. response_decision denies delivery of "FOO_BAR"-sensitivity to an
#       INTERNAL-ceiling identity (rank 4 > rank 1 → block)
#   7c. response_decision denies delivery of "FOO_BAR"-sensitivity even to a
#       RESTRICTED-ceiling identity (rank 4 > rank 3 → block)
#   7d. Empty string is also caught by the catch-all (rank 4 → block)
# ---------------------------------------------------------------------------

# 7a. Unknown sensitivity string gets rank 5
# R14/R15 (v2.25.5): GAP-1 catch-all updated from rank 4 → rank 5 so numeric
# level 4 (RESTRICTED) is a valid content rank without collision with the
# unknown-string sentinel. Unknown strings still fail-closed (rank 5 > all ceilings).
test_sensitivity_rank_unknown_string_is_4 if {
    data.yashigani.v1.sensitivity_rank("FOO_BAR") == 5
}

# 7b. Unknown sensitivity → DENY for INTERNAL-ceiling identity
test_response_decision_unknown_sensitivity_denies_internal_ceiling if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {
            "status": "active",
            "kind": "agent",
            "sensitivity_ceiling": "INTERNAL",
        },
        "response_sensitivity": "FOO_BAR",
        "response_verdict": "clean",
        "pii_detected": false,
    }
    d.allow == false
    d.reason == "response_sensitivity_exceeds_ceiling"
}

# 7c. Unknown sensitivity → DENY even for RESTRICTED-ceiling identity
#     (rank 4 > rank 3 — no identity has an unbounded ceiling)
test_response_decision_unknown_sensitivity_denies_restricted_ceiling if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {
            "status": "active",
            "kind": "agent",
            "sensitivity_ceiling": "RESTRICTED",
        },
        "response_sensitivity": "FOO_BAR",
        "response_verdict": "clean",
        "pii_detected": false,
    }
    d.allow == false
    d.reason == "response_sensitivity_exceeds_ceiling"
}

# 7d. Empty string sensitivity → also caught (rank 4 → block)
test_response_decision_empty_sensitivity_denies_internal_ceiling if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {
            "status": "active",
            "kind": "agent",
            "sensitivity_ceiling": "INTERNAL",
        },
        "response_sensitivity": "",
        "response_verdict": "clean",
        "pii_detected": false,
    }
    d.allow == false
    d.reason == "response_sensitivity_exceeds_ceiling"
}

# ---------------------------------------------------------------------------
# LAURA-OPA-001 (2.25.2) — path-traversal confused-deputy regression tests
#
# An agent scoped to "/do/**" must NOT reach "/admin" via "/do/../admin".
# httpx collapses dot-segments on the wire; the OPA gate previously matched the
# un-collapsed path with literal startswith. The _agent_path_safe guard now
# rejects any traversal sequence (raw or percent-encoded).
# PoC: testing_runs/yashigani/opa-bypass-audit-20260604/inputs/proof_004_agent_path_traversal.json
# ---------------------------------------------------------------------------

test_deny_path_traversal_dotdot_to_admin if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/../admin"},
    }
}

test_deny_reason_path_traversal if {
    data.yashigani.agent_call_deny_reason == "path_traversal_attempt" with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/../admin"},
    }
}

test_deny_path_traversal_encoded_dots if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/%2e%2e/admin"},
    }
}

test_deny_path_traversal_encoded_slash if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do%2f..%2fadmin"},
    }
}

test_deny_path_traversal_double_encoded if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/%252e%252e/admin"},
    }
}

test_deny_path_traversal_backslash if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/..\\admin"},
    }
}

# Legit traffic that LOOKS dotty but is not traversal must still ALLOW.
test_allow_legit_path_under_prefix_unchanged if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/run"},
    }
}

test_allow_filename_with_embedded_dots if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g1"]},
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": ["g1"],
            "allowed_paths": ["/do/**"],
        },
        "request": {"remainder_path": "/do/report..final.pdf"},
    }
}

# ===========================================================================
# 8. LAURA-OPA-005 closure — top-level `allow` eval_conflict on agent + MCP path
#
# Before fix: an agent principal hitting /mcp/* with a valid session fired BOTH
# the human-MCP-session `allow if {...}` (true) AND `allow := false if
# {deny_agent_call}` (false) → two complete-rule outputs → OPA eval_conflict_error
# (HTTP 500 → opaque fail-closed deny). After fix the human-MCP rule is gated to
# non-agent principals and a positive `allow if {agent_call_allowed}` lifts legit
# agent calls, so the path evaluates cleanly for every combination.
#
# 8a. legit agent + /mcp/* (group allowed) → allow == true, no conflict
# 8b. illegit agent + /mcp/* (group not allowed) → allow == false, no conflict
# 8c. human MCP session (no principal) → allow == true (unchanged)
# 8d. agent + /mcp/* with empty allowed_caller_groups (Laura's exact repro) → false
# ===========================================================================

# 8a. Legit agent reaching /mcp/* ALLOWs cleanly (no eval_conflict).
test_opa005_legit_agent_mcp_allows if {
    data.yashigani.allow with input as {
        "session_id": "s1",
        "method": "POST",
        "path": "/mcp/filesystem-mcp",
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g-yes"]},
        "target_agent": {
            "agent_id": "a1",
            "allowed_caller_groups": ["g-yes"],
            "allowed_paths": ["/mcp/**"],
        },
        "request": {"remainder_path": "/mcp/filesystem-mcp"},
    }
}

# 8b. Illegit agent (group not in allowed_caller_groups) → DENY, no conflict.
test_opa005_illegit_agent_mcp_denies if {
    not data.yashigani.allow with input as {
        "session_id": "s1",
        "method": "POST",
        "path": "/mcp/filesystem-mcp",
        "principal": {"type": "agent", "agent_id": "a1", "groups": ["g-nope"]},
        "target_agent": {
            "agent_id": "a1",
            "allowed_caller_groups": ["g-yes"],
            "allowed_paths": ["/mcp/**"],
        },
        "request": {"remainder_path": "/mcp/filesystem-mcp"},
    }
}

# 8c. Human MCP session (no principal object) still ALLOWs — the non-agent guard
# must not break the human path.
test_opa005_human_mcp_session_allows if {
    data.yashigani.allow with input as {
        "session_id": "s1",
        "method": "POST",
        "path": "/mcp/filesystem-mcp",
    }
}

# 8d. Laura's exact eval_conflict repro (agent, empty allowed_caller_groups) →
# clean DENY (was eval_conflict_error before fix).
test_opa005_laura_repro_denies_cleanly if {
    not data.yashigani.allow with input as {
        "principal": {"type": "agent", "agent_id": "a1"},
        "session_id": "s",
        "method": "GET",
        "path": "/mcp/x",
        "target_agent": {
            "agent_id": "a2",
            "allowed_caller_groups": [],
            "allowed_paths": ["**"],
        },
        "request": {"remainder_path": "/y"},
    }
}

# ===========================================================================
# 9. sensitivity_rank catch-all hardening — UNKNOWN CEILING string fails closed
#
# Laura residual (2.25.2): sensitivity_rank maps an unknown CEILING string to
# rank 4 (the highest), making a garbage ceiling the MOST permissive — so
# RESTRICTED content (rank 3) <= garbage-ceiling (rank 4) would ALLOW. The
# ceiling operand now uses _ceiling_rank, which is UNDEFINED for non-canonical
# strings → comparison undefined → positive allow does not fire → default-deny.
#
# 9a. agents: garbage ceiling + RESTRICTED response → agent_response_allowed false
# 9b. agents: garbage ceiling deny reason is invalid_caller_ceiling
# 9c. valid ceiling still allows (regression)
# ===========================================================================

# 9a. Unknown ceiling string + RESTRICTED → DENY (was ALLOW via permissive rank-4).
test_unknown_ceiling_restricted_denies_agents if {
    not data.yashigani.agent_response_allowed with input as {
        "caller": {"agent_id": "a1", "sensitivity_ceiling": "GARBAGE_CEILING"},
        "target_agent": {"agent_id": "a2"},
        "response_sensitivity": "RESTRICTED",
        "response_pii_detected": false,
    }
}

# 9b. Deny carries an explicit invalid_caller_ceiling reason (audit clarity).
test_unknown_ceiling_reason_is_invalid_agents if {
    d := data.yashigani.agent_response_decision with input as {
        "caller": {"agent_id": "a1", "sensitivity_ceiling": "GARBAGE_CEILING"},
        "target_agent": {"agent_id": "a2"},
        "response_sensitivity": "RESTRICTED",
        "response_pii_detected": false,
    }
    d.reason == "invalid_caller_ceiling"
}

# 9c. Regression: a VALID ceiling still allows within-clearance content.
test_valid_ceiling_still_allows_agents if {
    data.yashigani.agent_response_allowed with input as {
        "caller": {"agent_id": "a1", "sensitivity_ceiling": "CONFIDENTIAL"},
        "target_agent": {"agent_id": "a2"},
        "response_sensitivity": "INTERNAL",
        "response_pii_detected": false,
    }
}

# 9d. Empty-string ceiling is also caught (rank undefined → DENY).
test_empty_ceiling_denies_agents if {
    not data.yashigani.agent_response_allowed with input as {
        "caller": {"agent_id": "a1", "sensitivity_ceiling": ""},
        "target_agent": {"agent_id": "a2"},
        "response_sensitivity": "PUBLIC",
        "response_pii_detected": false,
    }
}

# ---------------------------------------------------------------------------
# 10. #47 / G-NEW-5 / R3 — verified signed-principal contract.
#
# The orchestration principal is verified at the GATEWAY (ES384 signature +
# SPIFFE binding + jti replay dedup) BEFORE OPA is queried — a forged or
# replayed principal never reaches OPA (the gateway returns 403 fail-closed,
# proven by test_g_new_5_agent_principal_signing.py).  These tests assert the
# rego CONTRACT: it adjudicates on input.principal (now the VERIFIED principal
# id) and the carried `verified` provenance fact is non-load-bearing (it does
# not, on its own, change the allow/deny — authority is group + path).
# ---------------------------------------------------------------------------

# 10a. A relay hop: verified principal feeds OPA as a verified fact → ALLOW by
# group + path exactly as before (the verified id is just the principal).
test_verified_relay_principal_allows if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-orig",
            "groups": ["analytics-agents"],
            "verified": true,
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# 10b. First hop: the gateway is the asserting authority and mints the signed
# claim on forward, so a verified=false principal still adjudicates normally by
# group + path (the gateway has already authenticated the immediate caller).
test_first_hop_unverified_principal_still_adjudicates if {
    data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-alpha",
            "groups": ["analytics-agents"],
            "verified": false,
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}

# 10c. The verified principal is still bound by group: a verified principal NOT
# in the allowed caller groups is DENIED (verification ≠ authorisation).
test_verified_principal_wrong_group_denied if {
    not data.yashigani.agent_call_allowed with input as {
        "principal": {
            "type": "agent",
            "agent_id": "agent-orig",
            "groups": ["other-agents"],
            "verified": true,
        },
        "target_agent": {
            "agent_id": "agent-beta",
            "allowed_caller_groups": ["analytics-agents"],
            "allowed_paths": ["/v1/run"],
        },
        "request": {"remainder_path": "/v1/run"},
    }
}
