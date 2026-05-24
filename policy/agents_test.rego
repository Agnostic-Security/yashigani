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

# 4c. agent_id absent with no matching group: OPA eval_conflict_error
# POLICY GAP FINDING (UA-07-GAP-003):
# When target_agent.agent_id is absent AND caller group does not match, both
# target_agent_not_in_data and caller_group_not_in_allowed_caller_groups conditions
# are simultaneously true. agent_call_deny_reason is a complete rule (:=) with
# multiple heads — OPA raises eval_conflict_error (multiple outputs). Gateway must
# catch this OPA exception and treat it as DENY. Policy should be restructured to
# use prioritised ordered rules (default + override) to avoid the conflict.
# Routing: file against Tom for rule restructure (policy/agents.rego — contract layer,
# Iris owns the contract gap filing; rule restructure is Tom's implementation).
# Test documents the conflict: the deny_reason evaluation MUST NOT succeed cleanly.
test_deny_reason_conflict_when_target_id_absent_and_group_mismatch if {
    # We verify agent_call_allowed is false (no allow fires without group match)
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

# 7a. Unknown sensitivity string gets rank 4
test_sensitivity_rank_unknown_string_is_4 if {
    data.yashigani.v1.sensitivity_rank("FOO_BAR") == 4
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
