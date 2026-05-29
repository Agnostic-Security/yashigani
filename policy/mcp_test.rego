# Yashigani MCP OPA Policy Tests — P1 W3 Phase 2b-i
#
# Tests the mcp.rego policy package.
# Run with: opa test policy/
#
# Coverage sections:
#   1. Basic allow paths — MCP-A, MCP-B, MCP-C
#   2. Fail-closed defaults — missing SPIFFE, invalid posture, bad action
#   3. Subject exclusivity (oneOf) — multiple subjects deny, no subject deny
#   4. Chain-depth guard — MCP-C length enforcement + operator override
#   5. P9 per-tool authz — exposed_tools allowlist present and absent
#   6. Deny reasons — one fires per scenario
#   7. redact_args — secret-key patterns in tool args
#   8. audit_capture — trigger conditions
#   9. rate_limit_key — format and null cases
#  10. mcp_decision compound document shape
#
package yashigani_mcp_test

import rego.v1

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_base_input := {
    "posture": "mcp-a",
    "action": "mcp.tools.call",
    "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
    "tool": {"name": "web_search", "args_redacted": {}},
}

_mcp_a_tool_input := {
    "posture": "mcp-a",
    "action": "mcp.tools.call",
    "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
    "tool": {"name": "web_search", "args_redacted": {}},
}

_mcp_b_tool_input := {
    "posture": "mcp-b",
    "action": "mcp.tools.call",
    "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
    "tool": {"name": "web_search", "args_redacted": {}},
}

_mcp_c_input_ok := {
    "posture": "mcp-c",
    "action": "mcp.tools.call",
    "identity": {
        "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
        "chain": [
            "spiffe://cluster.local/ns/default/sa/origin",
            "spiffe://cluster.local/ns/default/sa/relay",
        ],
    },
    "tool": {"name": "web_search", "args_redacted": {}},
}

# ---------------------------------------------------------------------------
# 1. Basic allow paths
# ---------------------------------------------------------------------------

test_allow_mcp_a_tool_call if {
    data.yashigani.mcp.allow with input as _mcp_a_tool_input
}

test_allow_mcp_a_prompt_list if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.prompts.list",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "prompt": {"name": "summarize"},
    }
}

test_allow_mcp_a_resource_read if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.resources.read",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "resource": {"uri": "file:///data/report.md"},
    }
}

test_allow_mcp_b_tool_call if {
    data.yashigani.mcp.allow with input as _mcp_b_tool_input
}

test_allow_mcp_c_with_valid_chain if {
    data.yashigani.mcp.allow with input as _mcp_c_input_ok
}

test_allow_mcp_a_ping if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.ping",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "ping", "args_redacted": {}},
    }
}

test_allow_mcp_a_initialize if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.initialize",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "init", "args_redacted": {}},
    }
}

test_allow_mcp_b_sampling if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-b",
        "action": "mcp.sampling.createMessage",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
        "tool": {"name": "sample", "args_redacted": {}},
    }
}

# ---------------------------------------------------------------------------
# 2. Fail-closed defaults — missing SPIFFE, invalid posture, bad action
# ---------------------------------------------------------------------------

test_deny_missing_spiffe if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_reason_missing_spiffe if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d == "missing_spiffe_identity"
}

test_deny_identity_missing_entirely if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_invalid_posture if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-z",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_reason_invalid_posture if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-z",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d == "invalid_posture"
}

test_deny_unrecognised_action if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.unknown.action",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_reason_unrecognised_action if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-a",
        "action": "mcp.unknown.action",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d == "unrecognised_action"
}

test_deny_empty_action if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# ---------------------------------------------------------------------------
# 3. Subject exclusivity (oneOf)
# ---------------------------------------------------------------------------

test_deny_multiple_subjects_tool_and_prompt if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
        "prompt": {"name": "summarize"},
    }
}

test_deny_reason_multiple_subjects if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
        "prompt": {"name": "summarize"},
    }
    d == "multiple_subjects_in_request"
}

test_deny_multiple_subjects_tool_and_resource if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
        "resource": {"uri": "file:///data"},
    }
}

test_deny_multiple_subjects_all_three if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {}},
        "prompt": {"name": "summarize"},
        "resource": {"uri": "file:///data"},
    }
}

test_deny_no_subject if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
    }
}

test_deny_reason_missing_subject if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
    }
    d == "missing_subject"
}

# ---------------------------------------------------------------------------
# 4. Chain-depth guard — MCP-C length enforcement + operator override
# ---------------------------------------------------------------------------

test_deny_chain_depth_exceeded_default_max if {
    # 4 entries > default max of 3
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
            "chain": [
                "spiffe://cluster.local/ns/default/sa/hop1",
                "spiffe://cluster.local/ns/default/sa/hop2",
                "spiffe://cluster.local/ns/default/sa/hop3",
                "spiffe://cluster.local/ns/default/sa/hop4",
            ],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_reason_chain_depth_exceeded if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
            "chain": [
                "spiffe://cluster.local/ns/default/sa/hop1",
                "spiffe://cluster.local/ns/default/sa/hop2",
                "spiffe://cluster.local/ns/default/sa/hop3",
                "spiffe://cluster.local/ns/default/sa/hop4",
            ],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d == "chain_depth_exceeded"
}

test_allow_chain_depth_at_max if {
    # Exactly 3 entries == default max: should allow
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
            "chain": [
                "spiffe://cluster.local/ns/default/sa/hop1",
                "spiffe://cluster.local/ns/default/sa/hop2",
                "spiffe://cluster.local/ns/default/sa/hop3",
            ],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_allow_chain_depth_2_within_default_max if {
    data.yashigani.mcp.allow with input as _mcp_c_input_ok
}

test_allow_chain_depth_exceeds_default_with_operator_override if {
    # Operator data bundle overrides chain_max_depth to 5
    # 4 entries <= 5: should allow
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
            "chain": [
                "spiffe://cluster.local/ns/default/sa/hop1",
                "spiffe://cluster.local/ns/default/sa/hop2",
                "spiffe://cluster.local/ns/default/sa/hop3",
                "spiffe://cluster.local/ns/default/sa/hop4",
            ],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    } with data.yashigani.mcp.policy.chain_max_depth as 5
}

test_deny_mcp_c_no_chain if {
    # MCP-C posture but no chain provided → deny mcp_c_requires_chain
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/relay"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_deny_reason_mcp_c_requires_chain if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/relay"},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d == "mcp_c_requires_chain"
}

test_deny_mcp_c_empty_chain if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/relay", "chain": []},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# MCP-A with chain present: chain is extra data — chain_depth_ok passes (depth=0 when absent)
# When chain IS provided on mcp-a it's ignored for the depth check (depth is count of chain array)
# but the allow path for mcp-a doesn't check chain presence — it only checks depth_ok.
# A short chain present on mcp-a should still allow.
test_allow_mcp_a_with_extra_chain_short if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/test",
            "chain": ["spiffe://cluster.local/ns/default/sa/test"],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# ---------------------------------------------------------------------------
# 5. P9 per-tool authz — exposed_tools allowlist
# ---------------------------------------------------------------------------

# 5a. No allowlist data loaded → gate open (backward-compat), any tool allowed
test_p9_allow_any_tool_when_allowlist_absent if {
    data.yashigani.mcp.allow with input as _mcp_b_tool_input
}

# 5b. Empty allowlist → gate open
test_p9_allow_any_tool_when_allowlist_empty if {
    data.yashigani.mcp.allow with input as _mcp_b_tool_input
        with data.yashigani.mcp.exposed_tools as set()
}

# 5c. Tool in allowlist → allow
test_p9_allow_tool_in_allowlist if {
    data.yashigani.mcp.allow with input as _mcp_b_tool_input
        with data.yashigani.mcp.exposed_tools as {"web_search", "code_review"}
}

# 5d. Tool NOT in allowlist → deny
test_p9_deny_tool_not_in_allowlist if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-b",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    } with data.yashigani.mcp.exposed_tools as {"web_search", "code_review"}
}

# 5e. Deny reason for tool not in allowlist
test_p9_deny_reason_tool_not_in_allowlist if {
    d := data.yashigani.mcp.deny_reason with input as {
        "posture": "mcp-b",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    } with data.yashigani.mcp.exposed_tools as {"web_search", "code_review"}
    d == "tool_not_in_exposed_allowlist"
}

# 5f. MCP-A is NOT subject to tool allowlist (allowlist only enforced on mcp-b and mcp-c)
# Per brief: "MCP-B per-tool authz … enforced at gateway inbound for exposed tools"
# Policy implementation: mcp-a allow path does NOT call _tool_authz_ok, so allowlist ignored.
test_p9_mcp_a_not_gated_by_allowlist if {
    data.yashigani.mcp.allow with input as _mcp_a_tool_input
        with data.yashigani.mcp.exposed_tools as {"other_tool"}
}

# 5g. Tool allowlist applied on mcp-c too
test_p9_deny_tool_not_in_allowlist_mcp_c if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/relay",
            "chain": ["spiffe://cluster.local/ns/default/sa/origin", "spiffe://cluster.local/ns/default/sa/relay"],
        },
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    } with data.yashigani.mcp.exposed_tools as {"web_search"}
}

# 5h. Non-tool actions (prompts/resources) are not gated by the tool allowlist
test_p9_prompt_action_not_blocked_by_tool_allowlist if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-b",
        "action": "mcp.prompts.list",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/langflow"},
        "prompt": {"name": "summarize"},
    } with data.yashigani.mcp.exposed_tools as {"web_search"}
}

# ---------------------------------------------------------------------------
# 6. Deny reasons — spot checks for each reason string
# ---------------------------------------------------------------------------

test_deny_reason_is_ok_on_allow if {
    d := data.yashigani.mcp.deny_reason with input as _mcp_a_tool_input
    d == "ok"
}

# (See sections 2–5 for all other deny_reason tests)

# ---------------------------------------------------------------------------
# 7. redact_args — secret-key pattern detection
# ---------------------------------------------------------------------------

test_redact_args_empty_when_no_secrets if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"query": "hello world", "limit": 10}},
    }
    count(r) == 0
}

test_redact_args_api_key_detected if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"query": "test", "api_key": "<REDACTED>"}},
    }
    "api_key" in r
}

test_redact_args_token_detected if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"query": "test", "token": "<REDACTED>"}},
    }
    "token" in r
}

test_redact_args_password_detected if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"query": "test", "password": "<REDACTED>"}},
    }
    "password" in r
}

test_redact_args_multiple_secrets_detected if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"query": "test", "api_key": "<REDACTED>", "token": "<REDACTED>", "limit": 5}},
    }
    "api_key" in r
    "token" in r
    not "query" in r
    not "limit" in r
}

test_redact_args_empty_on_deny if {
    # redact_args returns empty when allow is false
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {"api_key": "<REDACTED>"}},
    }
    count(r) == 0
}

test_redact_args_empty_for_non_tool_subject if {
    # No tool: redact_args is empty set
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.prompts.list",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "prompt": {"name": "summarize"},
    }
    count(r) == 0
}

# ---------------------------------------------------------------------------
# 8. audit_capture
# ---------------------------------------------------------------------------

test_audit_capture_false_on_clean_allow if {
    data.yashigani.mcp.audit_capture == false with input as _mcp_a_tool_input
}

test_audit_capture_true_on_deny if {
    data.yashigani.mcp.audit_capture == true with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_audit_capture_true_for_confidential_resource if {
    data.yashigani.mcp.audit_capture == true with input as {
        "posture": "mcp-a",
        "action": "mcp.resources.read",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "resource": {"uri": "file:///data/secret.doc", "sensitivity": "CONFIDENTIAL"},
    }
}

test_audit_capture_true_for_restricted_resource if {
    data.yashigani.mcp.audit_capture == true with input as {
        "posture": "mcp-a",
        "action": "mcp.resources.read",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "resource": {"uri": "file:///data/top_secret.doc", "sensitivity": "RESTRICTED"},
    }
}

test_audit_capture_false_for_public_resource if {
    data.yashigani.mcp.audit_capture == false with input as {
        "posture": "mcp-a",
        "action": "mcp.resources.read",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "resource": {"uri": "file:///data/readme.md", "sensitivity": "PUBLIC"},
    }
}

test_audit_capture_true_for_multihop_chain if {
    data.yashigani.mcp.audit_capture == true with input as _mcp_c_input_ok
}

test_audit_capture_true_for_redactable_args if {
    data.yashigani.mcp.audit_capture == true with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "web_search", "args_redacted": {"api_key": "<REDACTED>"}},
    }
}

test_audit_capture_true_for_confidential_prompt if {
    data.yashigani.mcp.audit_capture == true with input as {
        "posture": "mcp-a",
        "action": "mcp.prompts.list",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "prompt": {"name": "classified_summary", "sensitivity": "CONFIDENTIAL"},
    }
}

# ---------------------------------------------------------------------------
# 9. rate_limit_key
# ---------------------------------------------------------------------------

test_rate_limit_key_includes_tool_name if {
    k := data.yashigani.mcp.rate_limit_key with input as _mcp_a_tool_input
    contains(k, "mcp.tools.call")
    contains(k, "web_search")
}

test_rate_limit_key_null_on_deny if {
    k := data.yashigani.mcp.rate_limit_key with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    k == null
}

test_rate_limit_key_excludes_tool_name_for_prompt if {
    k := data.yashigani.mcp.rate_limit_key with input as {
        "posture": "mcp-a",
        "action": "mcp.prompts.list",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "prompt": {"name": "summarize"},
    }
    contains(k, "mcp.prompts.list")
    not contains(k, "web_search")
}

# ---------------------------------------------------------------------------
# 10. mcp_decision compound document shape
# ---------------------------------------------------------------------------

test_decision_allow_has_correct_shape if {
    d := data.yashigani.mcp.mcp_decision with input as _mcp_a_tool_input
    d.allow == true
    d.deny_reason == "ok"
    d.audit_capture == false
    d.rate_limit_key != null
    is_set(d.redact_args)
}

test_decision_deny_has_correct_shape if {
    d := data.yashigani.mcp.mcp_decision with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": ""},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d.allow == false
    d.deny_reason != ""
    d.deny_reason != "ok"
    d.audit_capture == true
    d.rate_limit_key == null
    is_set(d.redact_args)
    count(d.redact_args) == 0
}

test_decision_redact_args_is_set_in_compound_doc if {
    d := data.yashigani.mcp.mcp_decision with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "api_caller", "args_redacted": {"endpoint": "https://example.com", "api_key": "<REDACTED>"}},
    }
    d.allow == true
    d.audit_capture == true
    "api_key" in d.redact_args
}
