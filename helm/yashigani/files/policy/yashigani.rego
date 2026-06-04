# Yashigani — OPA policy bundle.
# All policy decisions are local. No cloud delegation. (ASVS V4.2)
#
# Inputs provided by the gateway proxy:
#   input.method        — HTTP method
#   input.path          — request path
#   input.session_id    — caller session token (hashed)
#   input.agent_id      — X-Yashigani-Agent-Id header value
#   input.user_id       — X-Yashigani-User-Id header value
#   input.headers       — sanitized request headers (no Authorization/Cookie)
#
# The gateway's fail-closed behaviour: any OPA error → deny.

package yashigani

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Default: deny unless explicitly allowed
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# Allow authenticated sessions
# ---------------------------------------------------------------------------

allow if {
    # Session ID must be present (non-empty, non-anonymous)
    input.session_id != ""
    input.session_id != "anonymous"

    # Agent ID must be declared
    input.agent_id != ""
    input.agent_id != "unknown"

    # Method must be in the allowed set
    input.method in allowed_methods

    # Path must not match any blocked pattern
    not path_blocked
}

# ---------------------------------------------------------------------------
# Allow MCP broker calls from authenticated human sessions
#
# MCP calls to /mcp/<agent_name> originate from human sessions (browser
# cookie or API key) — NOT from agent-to-agent calls.  Human sessions do
# not carry X-Yashigani-Agent-Id, so the general allow rule above would
# deny them (agent_id = "unknown").
#
# This rule permits /mcp/* access when:
#   1. A valid non-anonymous session is present (cookie or API-key hash).
#   2. The HTTP method is in the allowed set.
#   3. The path is not in the blocked set.
#
# Per-tool authz is enforced AFTER this gate by the MCP broker's own
# enforce() pipeline (broker.py → mcp.rego filesystem_tool_allowed).
# This gate only establishes that a session exists — it is NOT a
# bypass of per-tool policy.
#
# P3 broker E2E gate — J9-ToolsCall / J10-WriteTool (2026-05-30).
# ASVS V4.1.3: access control is default-deny except for explicit allow.
#
# LAURA-OPA-005 (2.25.2): this rule is for HUMAN MCP sessions ONLY. Agent
# principals reach /mcp/* through the agent-to-agent gate (agent_call_allowed),
# whose deny path (deny_agent_call → `allow := false`) would otherwise fire
# simultaneously with a `true` here, producing two complete-rule outputs and an
# OPA eval_conflict_error (HTTP 500 → fail-closed deny, but an opaque one). The
# `principal.type != "agent"` guard makes the allow rules mutually exclusive:
# humans go through this session rule, agents go through agent_call_allowed.
# Cite: OPA complete-rule conflict semantics; ASVS V4.1.3.
# ---------------------------------------------------------------------------

allow if {
    # Human MCP sessions only — agents are gated by agent_call_allowed (see above).
    # `_principal_is_not_agent` is true both when no principal is present (human
    # cookie/API-key session, which carries no principal object) AND when an
    # explicit principal has type != "agent". Using the raw expression
    # `input.principal.type != "agent"` would be UNDEFINED for human sessions
    # (no principal.type) and silently break the human MCP path.
    _principal_is_not_agent
    input.session_id != ""
    input.session_id != "anonymous"
    input.method in allowed_methods
    # FastAPI {path:path} strips the leading slash — accept both forms.
    # Gateway sends "mcp/filesystem-mcp"; direct OPA probes send "/mcp/filesystem-mcp".
    # FIX-OPA-MCP-PATH (2026-05-30): match regardless of leading slash.
    _path_is_mcp
    not path_blocked
}

# True when the caller is NOT an agent principal: either no principal object at
# all (human session), or an explicit principal whose type is not "agent".
_principal_is_not_agent if { not input.principal }
_principal_is_not_agent if { not input.principal.type }
_principal_is_not_agent if { input.principal.type != "agent" }

_path_is_mcp if { startswith(input.path, "/mcp/") }
_path_is_mcp if { startswith(input.path, "mcp/") }

# ---------------------------------------------------------------------------
# Allowed HTTP methods for MCP traffic
# ---------------------------------------------------------------------------

allowed_methods := {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

# ---------------------------------------------------------------------------
# Blocked path patterns
# ---------------------------------------------------------------------------

path_blocked if {
    # Block direct access to internal metadata/admin paths
    startswith(input.path, "/admin")
}

path_blocked if {
    startswith(input.path, "/.well-known/internal")
}

path_blocked if {
    input.path == "/metrics"
}

path_blocked if {
    input.path == "/healthz"
}

# ---------------------------------------------------------------------------
# RBAC enforcement — deny if RBAC data is loaded and user is not permitted
# ---------------------------------------------------------------------------
# When data.yashigani.rbac.groups is non-empty, every request that passed
# the session/method/path checks above must additionally satisfy allow_rbac
# (defined in rbac.rego).  If RBAC data is absent or empty the gate is
# open — this preserves backwards compatibility during roll-out.

deny_rbac if {
    count(data.yashigani.rbac.groups) > 0
    not allow_rbac
}

# Override the default allow: deny when RBAC says no
allow := false if { deny_rbac }

# ---------------------------------------------------------------------------
# Agent-to-agent enforcement
# agent_call_allowed is defined in agents.rego (same package yashigani).
# ---------------------------------------------------------------------------

# Allow agent calls that the agent-to-agent gate (agent_call_allowed, agents.rego)
# explicitly permits. This is the positive counterpart of deny_agent_call below.
# LAURA-OPA-005 (2.25.2): a legit agent reaching /mcp/* must evaluate to a clean
# `allow == true` via the top-level decision, not rely on the human-session rule
# (which is now gated to non-agent principals). Because this rule requires
# `agent_call_allowed` and deny_agent_call requires `not agent_call_allowed`, the
# two are mutually exclusive — no eval_conflict can arise from this pair.
allow if {
    input.principal.type == "agent"
    agent_call_allowed
}

# Deny agent calls that are not explicitly allowed
deny_agent_call if {
    input.principal.type == "agent"
    not agent_call_allowed
}

allow := false if { deny_agent_call }
