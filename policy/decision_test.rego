# #4 — tests for the OPA decision contract (decision.denials self-description).
# Additive to the existing 223-test suite; the boolean allow gate is tested
# elsewhere. These assert each deny path yields a self-describing denial.
package yashigani

import future.keywords.if
import future.keywords.in

test_denial_path_restricted if {
    d := decision with input as {
        "path": "/admin/secrets", "method": "GET",
        "session_id": "s", "agent_id": "a",
    }
    d.allow == false
    some den in d.denials
    den.policy_id == "yashigani.core.path-restricted"
    den.code == 403
    den.user_message != ""
}

test_denial_default_deny_on_anonymous if {
    d := decision with input as {
        "path": "/v1/chat", "method": "GET",
        "session_id": "", "agent_id": "",
    }
    with data.yashigani.rbac.groups as {}
    d.allow == false
    some den in d.denials
    den.policy_id == "yashigani.core.default-deny"
}

test_allowed_request_has_no_denials if {
    d := decision with input as {
        "path": "/v1/chat", "method": "GET",
        "session_id": "sess-123", "agent_id": "agent-x",
    }
    with data.yashigani.rbac.groups as {}
    d.allow == true
    count(d.denials) == 0
}

test_rbac_denial_self_described if {
    d := decision with input as {
        "path": "/v1/chat", "method": "GET",
        "session_id": "sess-123", "agent_id": "agent-x",
        "session": {"email": "nobody@example.com"},
    }
    with data.yashigani.rbac.groups as {"admins": {"members": ["boss@example.com"], "allow": ["/v1/chat"]}}
    d.allow == false
    some den in d.denials
    den.policy_id == "yashigani.rbac.group-permission"
}
