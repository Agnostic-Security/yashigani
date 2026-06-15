# Tests for system.authz (LAURA-30-001 L2 authorisation policy).
#
# Run: opa test policy/system/
#
# Coverage:
#   1. backoffice SPIFFE URI: write allowed (PUT /v1/policies/*)
#   2. backoffice SPIFFE URI: write allowed (PUT /v1/data/yashigani)
#   3. backoffice CN form: write allowed (PUT /v1/policies/*)
#   4. backoffice: read allowed (GET /v1/policies)
#   5. backoffice: sandbox PUT + DELETE (OPA-assistant sanity check path)
#   6. gateway SPIFFE URI: eval allowed (POST /v1/data/yashigani)
#   7. gateway CN form: eval allowed (POST /v1/data/yashigani)
#   8. gateway: eval allowed (POST /v1/data/client_enforce/aggregate)
#   9. gateway: DENIED — write attempt (PUT /v1/data/yashigani) → DENY
#  10. gateway: DENIED — policy write (PUT /v1/policies/x) → DENY
#  11. no-identity (unauthenticated): /health → ALLOW (K8s kubelet probe)
#  12. no-identity: /v1/policies → DENY (mgmt API, no cert)
#  13. agent identity: eval attempt (POST /v1/data/yashigani) → DENY
#  14. agent identity: policy write (PUT /v1/policies/agent_policy) → DENY
#  15. MCP sidecar identity: eval attempt → DENY
#  16. backoffice: delete policy (DELETE /v1/policies/clients/x) → ALLOW
#  17. backoffice: PATCH data (PATCH /v1/data/yashigani) → ALLOW
#  18. gateway: GET policy → DENY (gateway only POSTs eval)
#  19. backoffice: POST eval (dry-run/simulate via POST /v1/data/<path>) → ALLOW
#  20. unrecognised identity string (rogue service): any method → DENY

package system.authz_test

import future.keywords.if

# ── Helpers ───────────────────────────────────────────────────────────────────

_backoffice_spiffe := "spiffe://yashigani.internal/backoffice"
_backoffice_cn     := "backoffice"
# OPA 1.x TLS auth: RFC 2253 Subject DN (verified live on OPA 1.16.1, 2026-06-15).
# OPA with --authentication=tls sets input.identity to the client cert Subject DN
# in RFC 2253 format, NOT the URI SAN. The install.sh-generated certs have
# Subject: O=Agnostic Security, CN=<service> → RFC 2253: "CN=<service>,O=Agnostic Security".
_backoffice_dn     := "CN=backoffice,O=Agnostic Security"
_gateway_spiffe    := "spiffe://yashigani.internal/gateway"
_gateway_cn        := "gateway"
_gateway_dn        := "CN=gateway,O=Agnostic Security"
_agent_id          := "spiffe://yashigani.internal/langflow"
_mcp_id            := "spiffe://yashigani.internal/openclaw"
_rogue_id          := "spiffe://evil.example.com/attacker"

# ── 1. backoffice SPIFFE: PUT /v1/policies/* ────────────────────────────────
test_backoffice_spiffe_put_policy_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "PUT",
        "path": ["v1", "policies", "clients", "my_policy"],
    }
}

# ── 2. backoffice SPIFFE: PUT /v1/data/yashigani ────────────────────────────
test_backoffice_spiffe_put_data_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "PUT",
        "path": ["v1", "data", "yashigani"],
    }
}

# ── 3. backoffice CN form: PUT /v1/policies/* ───────────────────────────────
test_backoffice_cn_put_policy_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_cn,
        "method": "PUT",
        "path": ["v1", "policies", "rbac"],
    }
}

# ── 4. backoffice: GET /v1/policies ─────────────────────────────────────────
test_backoffice_get_policies_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "GET",
        "path": ["v1", "policies"],
    }
}

# ── 5. backoffice: sandbox PUT + DELETE (OPA-assistant sanity path) ──────────
test_backoffice_sandbox_put_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "PUT",
        "path": ["v1", "policies", "clients", "_sanity_mycheck"],
    }
}

test_backoffice_sandbox_delete_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "DELETE",
        "path": ["v1", "policies", "clients", "_sanity_mycheck"],
    }
}

# ── 6. gateway SPIFFE: POST /v1/data/yashigani/* ────────────────────────────
test_gateway_spiffe_post_eval_allowed if {
    data.system.authz.allow with input as {
        "identity": _gateway_spiffe,
        "method": "POST",
        "path": ["v1", "data", "yashigani", "allow"],
    }
}

# ── 7. gateway CN form: POST /v1/data/yashigani ─────────────────────────────
test_gateway_cn_post_eval_allowed if {
    data.system.authz.allow with input as {
        "identity": _gateway_cn,
        "method": "POST",
        "path": ["v1", "data", "yashigani"],
    }
}

# ── 8. gateway: POST /v1/data/client_enforce/aggregate ──────────────────────
test_gateway_post_client_enforce_allowed if {
    data.system.authz.allow with input as {
        "identity": _gateway_spiffe,
        "method": "POST",
        "path": ["v1", "data", "client_enforce", "aggregate"],
    }
}

# ── 9. gateway: PUT /v1/data/yashigani → DENY ───────────────────────────────
test_gateway_put_data_denied if {
    not data.system.authz.allow with input as {
        "identity": _gateway_spiffe,
        "method": "PUT",
        "path": ["v1", "data", "yashigani"],
    }
}

# ── 10. gateway: PUT /v1/policies → DENY ─────────────────────────────────────
test_gateway_put_policy_denied if {
    not data.system.authz.allow with input as {
        "identity": _gateway_spiffe,
        "method": "PUT",
        "path": ["v1", "policies", "evil"],
    }
}

# ── 11. no-identity: /health → ALLOW (K8s probe) ────────────────────────────
test_health_unauthenticated_allowed if {
    data.system.authz.allow with input as {
        "identity": "",
        "method": "GET",
        "path": ["health"],
    }
}

# ── 12. no-identity: /v1/policies → DENY ─────────────────────────────────────
test_no_identity_v1_policies_denied if {
    not data.system.authz.allow with input as {
        "identity": "",
        "method": "GET",
        "path": ["v1", "policies"],
    }
}

# ── 13. agent: POST /v1/data/yashigani → DENY (not in allowlist) ─────────────
test_agent_eval_attempt_denied if {
    not data.system.authz.allow with input as {
        "identity": _agent_id,
        "method": "POST",
        "path": ["v1", "data", "yashigani", "allow"],
    }
}

# ── 14. agent: PUT /v1/policies/* → DENY ────────────────────────────────────
test_agent_policy_write_denied if {
    not data.system.authz.allow with input as {
        "identity": _agent_id,
        "method": "PUT",
        "path": ["v1", "policies", "agent_policy"],
    }
}

# ── 15. MCP sidecar: POST /v1/data → DENY ────────────────────────────────────
test_mcp_eval_attempt_denied if {
    not data.system.authz.allow with input as {
        "identity": _mcp_id,
        "method": "POST",
        "path": ["v1", "data", "yashigani"],
    }
}

# ── 16. backoffice: DELETE /v1/policies/clients/x → ALLOW ───────────────────
test_backoffice_delete_client_policy_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "DELETE",
        "path": ["v1", "policies", "clients", "old_policy"],
    }
}

# ── 17. backoffice: PATCH /v1/data/yashigani → ALLOW ────────────────────────
test_backoffice_patch_data_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "PATCH",
        "path": ["v1", "data", "yashigani"],
    }
}

# ── 18. gateway: GET /v1/policies → DENY (gateway eval-only, no reads) ──────
test_gateway_get_policy_denied if {
    not data.system.authz.allow with input as {
        "identity": _gateway_spiffe,
        "method": "GET",
        "path": ["v1", "policies"],
    }
}

# ── 19. backoffice: POST /v1/data/<path>/decision (dry-run simulate) ─────────
test_backoffice_post_simulate_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_spiffe,
        "method": "POST",
        "path": ["v1", "data", "yashigani", "allow"],
    }
}

# ── 20. rogue identity string: any method → DENY ─────────────────────────────
test_rogue_identity_denied if {
    not data.system.authz.allow with input as {
        "identity": _rogue_id,
        "method": "PUT",
        "path": ["v1", "policies", "evil"],
    }
}

# ── 21–24. RFC 2253 DN form (OPA 1.x TLS auth, IRIS-AUTHZ-001) ──────────────
# OPA 1.16.1 sets input.identity to the Subject DN in RFC 2253 format,
# NOT the URI SAN. These tests verify the DN-form identities are authorised.

# 21. backoffice RFC 2253 DN: PUT /v1/policies/* → ALLOW
test_backoffice_dn_put_policy_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_dn,
        "method": "PUT",
        "path": ["v1", "policies", "clients", "my_policy"],
    }
}

# 22. backoffice RFC 2253 DN: GET /v1/policies → ALLOW
test_backoffice_dn_get_policies_allowed if {
    data.system.authz.allow with input as {
        "identity": _backoffice_dn,
        "method": "GET",
        "path": ["v1", "policies"],
    }
}

# 23. gateway RFC 2253 DN: POST /v1/data/yashigani → ALLOW
test_gateway_dn_post_eval_allowed if {
    data.system.authz.allow with input as {
        "identity": _gateway_dn,
        "method": "POST",
        "path": ["v1", "data", "yashigani", "allow"],
    }
}

# 24. gateway RFC 2253 DN: PUT /v1/data → DENY (gateway eval-only)
test_gateway_dn_put_data_denied if {
    not data.system.authz.allow with input as {
        "identity": _gateway_dn,
        "method": "PUT",
        "path": ["v1", "data", "yashigani"],
    }
}
