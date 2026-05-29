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

# ---------------------------------------------------------------------------
# 11. Security regression tests — Laura PoC probes + gate fixes
#     Reference: LAURA-MCP-001..004, LU-MCP-01..02, FINDING-MCP-001
# ---------------------------------------------------------------------------

# --- FIX-1: LAURA-MCP-001 / LU-MCP-01 — malformed-chain depth bypass ---

# probe1a: chain is an object (1 key) — count(object) == 1 but NOT an array of strings
# Previously allowed mcp-c by counting object keys. Must deny.
test_fix1_probe1a_object_chain_denies_mcp_c if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/attacker",
            "chain": {"x": "y"},
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

test_fix1_probe1a_object_chain_chain_depth_is_zero if {
    # When chain is an object, _chain_depth must resolve to 0 (fail-closed)
    d := data.yashigani.mcp.mcp_decision with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/attacker",
            "chain": {"x": "y"},
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
    d.allow == false
    # depth=0 → mcp_c_requires_chain
    d.deny_reason == "mcp_c_requires_chain"
}

# probe1c: chain is an array of objects — each element is NOT a string
# Previously counted 2 elements and allowed. Must deny.
test_fix1_probe1c_array_of_objects_chain_denies_mcp_c if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/attacker",
            "chain": [{"spiffe": "spiffe://a"}, {"spiffe": "spiffe://b"}],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# probe1d: chain is an array of integers — not strings
# Previously counted 3 elements (≤ default max 3) and allowed. Must deny.
test_fix1_probe1d_array_of_ints_chain_denies_mcp_c if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-c",
        "action": "mcp.tools.call",
        "identity": {
            "spiffe": "spiffe://cluster.local/ns/default/sa/attacker",
            "chain": [1, 2, 3],
        },
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# Positive: valid array of SPIFFE strings at depth 2 still allows on mcp-c
test_fix1_valid_string_array_chain_allows_mcp_c if {
    data.yashigani.mcp.allow with input as {
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
}

# --- FIX-2: LAURA-MCP-002 / LU-MCP-02 — secret-redaction gaps ---

# probe2: pat key must now appear in redact_args
test_fix2_pat_key_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "s3_upload", "args_redacted": {"pat": "<REDACTED>", "query": "safe"}},
    }
    "pat" in r
    not "query" in r
}

test_fix2_aws_secret_access_key_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "aws_tool", "args_redacted": {"aws_secret_access_key": "<REDACTED>", "bucket": "my-bucket"}},
    }
    "aws_secret_access_key" in r
    not "bucket" in r
}

test_fix2_aws_session_token_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "aws_tool", "args_redacted": {"aws_session_token": "<REDACTED>", "region": "us-east-1"}},
    }
    "aws_session_token" in r
    not "region" in r
}

test_fix2_client_secret_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "oauth_tool", "args_redacted": {"client_secret": "<REDACTED>", "client_id": "abc"}},
    }
    "client_secret" in r
    not "client_id" in r
}

test_fix2_refresh_token_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "oauth_tool", "args_redacted": {"refresh_token": "<REDACTED>", "grant_type": "refresh_token"}},
    }
    "refresh_token" in r
    # grant_type is not a secret key
    not "grant_type" in r
}

test_fix2_session_token_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "session_tool", "args_redacted": {"session_token": "<REDACTED>", "user_id": "123"}},
    }
    "session_token" in r
    not "user_id" in r
}

test_fix2_x_api_key_is_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "http_tool", "args_redacted": {"x-api-key": "<REDACTED>", "url": "https://api.example.com"}},
    }
    "x-api-key" in r
    not "url" in r
}

# probe2j: sort_key and cache_key must NOT be redacted (exact-match, not substring)
test_fix2_sort_key_and_cache_key_not_redacted if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "db_tool", "args_redacted": {"sort_key": "id", "cache_key": "user:123", "query": "safe"}},
    }
    not "sort_key" in r
    not "cache_key" in r
    not "query" in r
}

# probe2n: mix — sort_key and cache_key NOT redacted; key IS redacted
test_fix2_mixed_probe2n_key_redacted_sort_cache_not if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "tool", "args_redacted": {"sort_key": "id", "monkey": "value", "key": "<REDACTED>", "cache_key": "user:123"}},
    }
    "key" in r
    not "sort_key" in r
    not "cache_key" in r
    not "monkey" in r
}

# --- FIX-4: LAURA-MCP-004 — non-string spiffe type bypass ---

# probe5b: spiffe=1 (integer) — must deny (is_string fails)
test_fix4_non_string_spiffe_integer_denies if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": 1},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# probe5c: spiffe=true (boolean) — must deny
test_fix4_non_string_spiffe_boolean_denies if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": true},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# probe5d: spiffe={"uri":"spiffe://evil"} (object) — must deny
test_fix4_non_string_spiffe_object_denies if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": {"uri": "spiffe://evil"}},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# probe5h: spiffe={} (empty object) — must deny
test_fix4_non_string_spiffe_empty_object_denies if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": {}},
        "tool": {"name": "web_search", "args_redacted": {}},
    }
}

# --- FIX-4: LAURA-MCP-004 — non-object args_redacted guard ---

# probe3e: args_redacted is an array — must not crash; audit still fires correctly
test_fix4_non_object_args_redacted_array_no_crash if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "tool", "args_redacted": ["api_key", "secret"]},
    }
    # Falls through to else := set() — returns empty set without crashing
    count(r) == 0
}

# probe3f: args_redacted is a boolean — must not crash
test_fix4_non_object_args_redacted_bool_no_crash if {
    r := data.yashigani.mcp.redact_args with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/test"},
        "tool": {"name": "tool", "args_redacted": true},
    }
    count(r) == 0
}

# --- FIX-5: LAURA-MCP-003 — mcp-a allowlist bypass (SKIPPED, doc-only) ---
# This test is intentionally SKIPPED. It documents the transport requirement
# that the mcp-a allow path MUST be restricted to locally-verified channels
# by the transport/JWT chunk. The policy intentionally skips _tool_authz_ok
# for mcp-a (same-trust-boundary design). This is NOT a policy bug — it is a
# binding constraint on the transport layer that must be enforced before this
# policy is invoked. See LAURA-MCP-003 tracked gate (Maxine/transport chunk).

# SKIPPED: test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only
# This test cannot be expressed as a pure policy assertion because the
# invariant ("posture=mcp-a requests can only arrive on a local channel")
# is a TRANSPORT-LAYER property, not an OPA-input property. A network
# attacker who can forge input.posture="mcp-a" bypasses _tool_authz_ok.
# The transport layer must prevent that from happening.
# Tracked: LAURA-MCP-003. Transport chunk gate owned by Maxine (P2/N-next).

# Sanity check: mcp-a with dangerous_exec and a populated exposed_tools
# allowlist DOES allow (intentional — mcp-a bypasses tool authz).
# This is correct behaviour given the transport trust requirement above.
test_fix5_mcp_a_bypasses_tool_allowlist_by_design if {
    data.yashigani.mcp.allow with input as {
        "posture": "mcp-a",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/attacker"},
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    } with data.yashigani.mcp.exposed_tools as {"web_search", "code_review"}
}

# Contrast: mcp-b with the same tool NOT in allowlist → deny (tool authz enforced)
test_fix5_mcp_b_enforces_tool_allowlist if {
    not data.yashigani.mcp.allow with input as {
        "posture": "mcp-b",
        "action": "mcp.tools.call",
        "identity": {"spiffe": "spiffe://cluster.local/ns/default/sa/attacker"},
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    } with data.yashigani.mcp.exposed_tools as {"web_search", "code_review"}
}
