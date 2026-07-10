# LAURA-OPA-003 (2.25.2) — v1_routing default-deny regression tests
#
# All five v1_routing access-control rules were `default := true` (inverted
# default). When sensitivity_ceiling was ABSENT the rank comparison was
# undefined and the rule stayed at its permissive default, delivering a
# RESTRICTED response to an identity with no declared ceiling.
# Class-fix: default-DENY + explicit positive-allow (matches agents.rego).
#
# Each bypass input now DENIES; each legit flow still ALLOWS.
# PoC: testing_runs/yashigani/opa-bypass-audit-20260604/inputs/proof_002_v1_response_failopen.json
#
# Run with: opa test policy/

package yashigani_v1_test

import future.keywords.if

# ── response_allowed ──────────────────────────────────────────────────────

# PoC OPA-003: active identity, NO ceiling, RESTRICTED response → must DENY
test_response_deny_absent_ceiling_restricted if {
    not data.yashigani.v1.response_allowed with input as {
        "identity": {"status": "active"},
        "response_sensitivity": "RESTRICTED",
    }
}

test_response_allow_within_ceiling if {
    data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "INTERNAL", "kind": "human"},
        "response_sensitivity": "PUBLIC",
        "response_verdict": "clean",
    }
}

test_response_allow_equal_ceiling if {
    data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "RESTRICTED", "kind": "human"},
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "clean",
    }
}

test_response_deny_exceeds_ceiling if {
    not data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "INTERNAL", "kind": "human"},
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "clean",
    }
}

test_response_deny_blocked_for_non_admin if {
    not data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "RESTRICTED", "kind": "human"},
        "response_sensitivity": "PUBLIC",
        "response_verdict": "blocked",
    }
}

test_response_allow_blocked_for_admin if {
    data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "RESTRICTED", "kind": "admin"},
        "response_sensitivity": "PUBLIC",
        "response_verdict": "blocked",
    }
}

test_response_uses_max_of_prompt_and_response if {
    # prompt CONFIDENTIAL, response PUBLIC, ceiling INTERNAL → effective=CONFIDENTIAL>INTERNAL → DENY
    not data.yashigani.v1.response_allowed with input as {
        "identity": {"sensitivity_ceiling": "INTERNAL", "kind": "human"},
        "prompt_sensitivity": "CONFIDENTIAL",
        "response_sensitivity": "PUBLIC",
        "response_verdict": "clean",
    }
}

# ── proxy_response_allowed ────────────────────────────────────────────────

test_proxy_deny_absent_ceiling_restricted if {
    not data.yashigani.v1.proxy_response_allowed with input as {
        "response_sensitivity": "RESTRICTED",
    }
}

test_proxy_allow_pipeline_off_no_sensitivity if {
    # response_sensitivity absent → rank 0 (PUBLIC) → within RESTRICTED ceiling
    data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"sensitivity_ceiling": "RESTRICTED", "kind": "human"},
    }
}

test_proxy_allow_public_within_ceiling if {
    data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"sensitivity_ceiling": "RESTRICTED", "kind": "service"},
        "response_sensitivity": "PUBLIC",
    }
}

test_proxy_deny_pii_for_service if {
    not data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"sensitivity_ceiling": "RESTRICTED", "kind": "service"},
        "response_sensitivity": "PUBLIC",
        "response_pii_detected": true,
    }
}

test_proxy_allow_pii_for_human if {
    data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"sensitivity_ceiling": "RESTRICTED", "kind": "human"},
        "response_sensitivity": "PUBLIC",
        "response_pii_detected": true,
    }
}

# ── models_list_decision (GAP-001) ────────────────────────────────────────
# Rego-level parity for the /v1/models OPA rule. The Python handler
# (_opa_models_check + list_models) is covered by
# test_v241_gap001_models_opa.py; these assert the policy contract directly.

# Under-privileged identity: anonymous / non-active → DENY (filter=denied).
# This is the GAP-001 exploit class — an authenticated-but-not-active or
# anonymous caller (e.g. compromised internal-mesh container presenting a
# stale token) must NOT enumerate the topology.
test_models_deny_anonymous if {
    d := data.yashigani.v1.models_list_decision with input as {
        "identity": {"status": "anonymous", "kind": "unknown"},
    }
    d.allow == false
    d.filter == "denied"
    d.reason == "identity_not_active_or_anonymous"
}

test_models_deny_inactive if {
    not data.yashigani.v1.models_list_allowed with input as {
        "identity": {"status": "suspended", "kind": "human"},
    }
}

# Human / admin principal → full topology listing.
test_models_human_full if {
    d := data.yashigani.v1.models_list_decision with input as {
        "identity": {"status": "active", "kind": "human"},
    }
    d.allow == true
    d.filter == "full"
    d.reason == "ok"
}

test_models_admin_full if {
    data.yashigani.v1.models_list_filter == "full" with input as {
        "identity": {"status": "active", "kind": "admin"},
    }
}

# Service account → RESTRICTED by default (agent/service-identity topology
# withheld). This is the conservative default that prevents a compromised
# internal-bearer from mapping the full agent topology.
test_models_service_restricted_default if {
    d := data.yashigani.v1.models_list_decision with input as {
        "identity": {"status": "active", "kind": "service"},
    }
    d.allow == true
    d.filter == "restricted"
}

test_models_unknown_kind_restricted_default if {
    data.yashigani.v1.models_list_filter == "restricted" with input as {
        "identity": {"status": "active", "kind": "unknown"},
    }
}

# Operator opt-in: data bundle grants service accounts the full list.
test_models_service_full_with_operator_override if {
    data.yashigani.v1.models_list_filter == "full" with input as {
        "identity": {"status": "active", "kind": "service"},
    }
    with data.yashigani.v1.models_list_policy.service_account_filter as "full"
}

# ── sensitivity_allowed ───────────────────────────────────────────────────

test_sensitivity_deny_absent_ceiling if {
    not data.yashigani.v1.sensitivity_allowed with input as {
        "routing_decision": {"sensitivity": "RESTRICTED"},
    }
}

test_sensitivity_allow_within_ceiling if {
    data.yashigani.v1.sensitivity_allowed with input as {
        "identity": {"sensitivity_ceiling": "RESTRICTED"},
        "routing_decision": {"sensitivity": "CONFIDENTIAL"},
    }
}

test_sensitivity_deny_exceeds_ceiling if {
    not data.yashigani.v1.sensitivity_allowed with input as {
        "identity": {"sensitivity_ceiling": "INTERNAL"},
        "routing_decision": {"sensitivity": "RESTRICTED"},
    }
}

# ── model_allowed ─────────────────────────────────────────────────────────

test_model_allow_empty_allowlist if {
    data.yashigani.v1.model_allowed with input as {
        "identity": {"allowed_models": []},
        "routing_decision": {"model": "gpt-4"},
    }
}

test_model_allow_absent_field if {
    data.yashigani.v1.model_allowed with input as {
        "identity": {},
        "routing_decision": {"model": "gpt-4"},
    }
}

test_model_allow_in_list if {
    data.yashigani.v1.model_allowed with input as {
        "identity": {"allowed_models": ["gpt-4"]},
        "routing_decision": {"model": "gpt-4"},
    }
}

test_model_allow_wildcard if {
    data.yashigani.v1.model_allowed with input as {
        "identity": {"allowed_models": ["*"]},
        "routing_decision": {"model": "anything"},
    }
}

test_model_deny_not_in_list if {
    not data.yashigani.v1.model_allowed with input as {
        "identity": {"allowed_models": ["gpt-4"]},
        "routing_decision": {"model": "claude-3"},
    }
}

# ── routing_safe ──────────────────────────────────────────────────────────

test_routing_safe_local_sensitive if {
    data.yashigani.v1.routing_safe with input as {
        "routing_decision": {"sensitivity": "RESTRICTED", "route": "local"},
    }
}

test_routing_safe_public_cloud if {
    data.yashigani.v1.routing_safe with input as {
        "routing_decision": {"sensitivity": "PUBLIC", "route": "cloud", "provider": "openai"},
    }
}

test_routing_unsafe_sensitive_untrusted_cloud if {
    not data.yashigani.v1.routing_safe with input as {
        "routing_decision": {"sensitivity": "RESTRICTED", "route": "cloud", "provider": "openai"},
        "trusted_cloud_providers": [],
    }
}

test_routing_safe_sensitive_trusted_cloud if {
    data.yashigani.v1.routing_safe with input as {
        "routing_decision": {"sensitivity": "RESTRICTED", "route": "cloud", "provider": "azure"},
        "trusted_cloud_providers": ["azure"],
    }
}

# ===========================================================================
# sensitivity_rank catch-all hardening — UNKNOWN CEILING string fails closed
# (v1 response leg + catch-all proxy response leg)
#
# Laura residual (2.25.2): the CEILING operand used sensitivity_rank, which maps
# an unknown string to rank 4 (the highest ceiling) → permissive. It now uses
# _ceiling_rank, undefined for non-canonical strings → DENY (default-deny).
# ===========================================================================

# v1 response: garbage ceiling + RESTRICTED content → DENY.
test_unknown_ceiling_restricted_denies_v1 if {
    not data.yashigani.v1.response_allowed with input as {
        "identity": {"kind": "human", "sensitivity_ceiling": "GARBAGE"},
        "prompt_sensitivity": "PUBLIC",
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "clean",
    }
}

# v1 response: deny reason is invalid_identity_ceiling.
test_unknown_ceiling_reason_is_invalid_v1 if {
    data.yashigani.v1.response_reason == "invalid_identity_ceiling" with input as {
        "identity": {"kind": "human", "sensitivity_ceiling": "GARBAGE"},
        "prompt_sensitivity": "PUBLIC",
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "clean",
    }
}

# v1 response: invalid ceiling + blocked verdict → single reason (no eval_conflict
# on the decision object), invalid_identity_ceiling takes precedence.
test_unknown_ceiling_blocked_verdict_single_reason_v1 if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {"kind": "human", "sensitivity_ceiling": "GARBAGE"},
        "prompt_sensitivity": "PUBLIC",
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "blocked",
    }
    d.reason == "invalid_identity_ceiling"
    d.allow == false
}

# v1 request leg sensitivity_allowed: garbage ceiling → DENY.
test_unknown_ceiling_request_leg_denies_v1 if {
    not data.yashigani.v1.sensitivity_allowed with input as {
        "routing_decision": {"sensitivity": "RESTRICTED"},
        "identity": {"sensitivity_ceiling": "GARBAGE"},
    }
}

# proxy response: garbage ceiling + RESTRICTED → DENY.
test_unknown_ceiling_restricted_denies_proxy if {
    not data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"kind": "human", "sensitivity_ceiling": "GARBAGE"},
        "response_sensitivity": "RESTRICTED",
        "response_pii_detected": false,
    }
}

# proxy response: invalid ceiling + PII + service account → single reason
# (invalid_principal_ceiling), no eval_conflict on the decision object.
test_unknown_ceiling_pii_single_reason_proxy if {
    d := data.yashigani.v1.proxy_response_decision with input as {
        "principal": {"kind": "service", "sensitivity_ceiling": "GARBAGE"},
        "response_sensitivity": "RESTRICTED",
        "response_pii_detected": true,
    }
    d.reason == "invalid_principal_ceiling"
    d.allow == false
}

# Regression: VALID ceiling still allows within-clearance content (v1 + proxy).
test_valid_ceiling_still_allows_v1 if {
    data.yashigani.v1.response_allowed with input as {
        "identity": {"kind": "human", "sensitivity_ceiling": "INTERNAL"},
        "prompt_sensitivity": "PUBLIC",
        "response_sensitivity": "PUBLIC",
        "response_verdict": "clean",
    }
}

test_valid_ceiling_still_allows_proxy if {
    data.yashigani.v1.proxy_response_allowed with input as {
        "principal": {"kind": "human", "sensitivity_ceiling": "CONFIDENTIAL"},
        "response_sensitivity": "INTERNAL",
        "response_pii_detected": false,
    }
}

# ── DENY-OVERRIDES single-reason regression (2.25.2, LAURA-OPA close-out) ────
#
# The previously-conflicting case is a VALID ceiling that is EXCEEDED while ANOTHER
# deny condition (inspection-blocked / PII) ALSO holds. Pre-fix the two deny
# reason branches co-fired → response_decision / proxy_response_decision OBJECT
# eval_conflict (OPA 500 → lost audit reason). The fixed precedence makes the
# reason single-valued. `opa test` fails on any eval_conflict during evaluation,
# so these tests passing IS the no-conflict proof.

# Laura repro #2 (exact): RESTRICTED response, PUBLIC ceiling (valid, exceeded),
# verdict=blocked. response_sensitivity_exceeds_ceiling (prec 2) wins over
# response_blocked_by_inspection (prec 3). allow stays false (unchanged).
test_laura_repro2_valid_ceiling_exceeded_and_blocked_single_reason_v1 if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {"status": "active", "kind": "human", "sensitivity_ceiling": "PUBLIC"},
        "response_sensitivity": "RESTRICTED",
        "response_verdict": "blocked",
    }
    d.allow == false
    d.reason == "response_sensitivity_exceeds_ceiling"
}

# Within-ceiling but blocked verdict → only blocked_by_inspection fires (prec 3).
test_within_ceiling_blocked_verdict_single_reason_v1 if {
    d := data.yashigani.v1.response_decision with input as {
        "identity": {"status": "active", "kind": "human", "sensitivity_ceiling": "RESTRICTED"},
        "response_sensitivity": "PUBLIC",
        "response_verdict": "blocked",
    }
    d.allow == false
    d.reason == "response_blocked_by_inspection"
}

# proxy: valid ceiling EXCEEDED + PII + service account → exceeds_ceiling (prec 2)
# wins over response_pii_blocked_for_service_account (prec 3). Single reason.
test_valid_ceiling_exceeded_and_pii_single_reason_proxy if {
    d := data.yashigani.v1.proxy_response_decision with input as {
        "principal": {"kind": "service", "sensitivity_ceiling": "PUBLIC"},
        "response_sensitivity": "RESTRICTED",
        "response_pii_detected": true,
    }
    d.allow == false
    d.reason == "response_sensitivity_exceeds_ceiling"
}

# proxy: within ceiling + PII + service account → only PII reason fires (prec 3).
test_within_ceiling_pii_single_reason_proxy if {
    d := data.yashigani.v1.proxy_response_decision with input as {
        "principal": {"kind": "service", "sensitivity_ceiling": "RESTRICTED"},
        "response_sensitivity": "PUBLIC",
        "response_pii_detected": true,
    }
    d.allow == false
    d.reason == "response_pii_blocked_for_service_account"
}
