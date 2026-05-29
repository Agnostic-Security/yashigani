# Yashigani MCP OPA Policy — P1 W3 Phase 2b-i
#
# Enforces access control for MCP-posture requests proxied through the gateway.
# Covers Shape A (stdio local), Shape B (Streamable-HTTP remote), Shape C
# (multi-hop chained) as defined in the Yashigani manifest schema §3.2.
#
# P-findings implemented:
#   P3  (HIGH)  — MCP input schema + policy (this file)
#   P9  (MEDIUM) — MCP-B per-tool authz enforced at gateway inbound
#
# Input schema: policy/mcp-input.schema.json
# Query path:   /v1/data/yashigani/mcp/mcp_decision
#               /v1/data/yashigani/mcp/allow
#
# Multi-hop identity chain (MCP-C / Lu-Gap-02):
#   Consumed here; populated by the MCP identity JWT in a later chunk (P2/N3).
#   The policy is ready for the JWT landing — test with synthetic input now.
#
# Fail-closed: default allow := false.  Any missing / malformed input → deny.
# Operator overrides: push a data bundle to data.yashigani.mcp.policy.*

package yashigani.mcp

import rego.v1

# ---------------------------------------------------------------------------
# Constants / tunables (operator-overridable via data bundle)
# ---------------------------------------------------------------------------

# Maximum allowed identity-chain depth for MCP-C multi-hop calls.
# Default: 3 (origin + 1 relay + gateway).  Operators may increase this via:
#   data.yashigani.mcp.policy.chain_max_depth = <n>
mcp_chain_max_depth := d if {
    d := data.yashigani.mcp.policy.chain_max_depth
} else := 3

# ---------------------------------------------------------------------------
# Default: deny everything.  Every allow path must be explicit.
# ASVS V4.1.3 — access control must default-deny.
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# _spiffe_present — true when a non-empty SPIFFE URI string is present in input.
# FIX LAURA-MCP-004 (Info): non-string spiffe guard.
# Without is_string, a truthy non-string value (integer 1, boolean true,
# non-empty object) satisfies != "" and passes the SPIFFE check, allowing a
# request with a forged/non-string SPIFFE to reach the allow path.
_spiffe_present if {
    is_string(input.identity.spiffe)
    input.identity.spiffe != ""
}

# _posture_valid — sanity-check the posture string (not in canonical set → deny)
_posture_valid if {
    input.posture in {"mcp-a", "mcp-b", "mcp-c"}
}

# _exactly_one_subject — exactly one of tool / prompt / resource is present.
# Fail-closed: if none are present, the request is incomplete (deny).
# Enforces the oneOf exclusivity from mcp-input.schema.json.
_tool_present     if { input.tool.name != "" }
_prompt_present   if { input.prompt.name != "" }
_resource_present if { input.resource.uri != "" }

_exactly_one_subject if {
    _tool_present
    not _prompt_present
    not _resource_present
}

_exactly_one_subject if {
    _prompt_present
    not _tool_present
    not _resource_present
}

_exactly_one_subject if {
    _resource_present
    not _tool_present
    not _prompt_present
}

# ---------------------------------------------------------------------------
# Identity chain depth guard — MCP-C multi-hop (Lu-Gap-02)
#
# When input.identity.chain is present (non-null, non-empty array), the chain
# depth must not exceed mcp_chain_max_depth.  A chain with depth > max is
# indicative of a routing loop, a confused-deputy attack, or an injection
# attempt — deny and force audit capture.
#
# When input.identity.chain is absent (mcp-a / mcp-b), the guard is skipped.
#
# FIX LAURA-MCP-001 / LU-MCP-01 (HIGH): malformed-chain depth bypass.
# _chain_depth is ONLY computed from an array whose every element is a string.
# An object, array-of-objects, or array-of-ints yields 0 (fail-closed).
# Previously: count(obj) counted object keys, allowing a 1-key object to pass
# a depth ≤ 3 check and reach the mcp-c ALLOW path without a real chain.
# ---------------------------------------------------------------------------

_chain_depth := count(input.identity.chain) if {
    is_array(input.identity.chain)
    every e in input.identity.chain { is_string(e) }
} else := 0

_chain_depth_ok if {
    _chain_depth <= mcp_chain_max_depth
}

# ---------------------------------------------------------------------------
# Core allow rules — posture-aware
# ---------------------------------------------------------------------------

# MCP-A (local stdio, Shape A):
#   - SPIFFE required
#   - Chain absent or depth ≤ max
#   - Valid posture
#   - Exactly one subject (tool OR prompt OR resource)
#   - Action must be a recognised MCP action prefix
#
# NOTE (LAURA-MCP-003 / FIX-5): MCP-A intentionally skips _tool_authz_ok.
# This is safe ONLY under the following BINDING TRANSPORT REQUIREMENTS.
# The transport/JWT chunk invoking this policy path MUST guarantee:
#
#   1. `posture` MUST be derived from the physical channel (OS pipe FD,
#      Unix-socket peer-cred, localhost-only bind) — NEVER from
#      `input.posture` in the request body. A network-arriving request with
#      a body that asserts posture=="mcp-a" MUST be rejected or reassigned
#      to mcp-b/mcp-c at the transport layer BEFORE this policy runs.
#
#   2. If the transport cannot positively guarantee that the request
#      originates from a local-only channel, mcp-a MUST NOT be assigned
#      and the request MUST be evaluated under mcp-b or mcp-c (which
#      enforce _tool_authz_ok).
#
#   3. This is not currently exploitable because no MCP handler invoking
#      this policy exists yet. This comment is an advance binding requirement
#      for the transport chunk authors. See: LAURA-MCP-003 tracked gate.
#      Maxine is registering this as a transport-chunk gate for P2/N-next.
allow if {
    input.posture == "mcp-a"
    _posture_valid
    _spiffe_present
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
}

# MCP-B (remote Streamable-HTTP, Shape B):
#   Same as MCP-A plus per-tool authz gate (_tool_authz_ok).
#   For non-tool actions, the authz check is a no-op (passes through).
allow if {
    input.posture == "mcp-b"
    _posture_valid
    _spiffe_present
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_authz_ok
}

# MCP-C (multi-hop chained, Shape C):
#   Chain MUST be present and non-empty (chain is the core assertion of MCP-C).
#   Chain depth must be within limit.
allow if {
    input.posture == "mcp-c"
    _posture_valid
    _spiffe_present
    # MCP-C requires an explicit chain
    _chain_depth > 0
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_authz_ok
}

# ---------------------------------------------------------------------------
# P9 — MCP-B per-tool authz (exposed tool allowlist)
#
# When data.yashigani.mcp.exposed_tools is populated (operator data bundle),
# it acts as the canonical allowlist of tool names exposed at the gateway
# inbound.  Any tool call for a name NOT in the allowlist → deny.
#
# When the allowlist is absent or empty (default install), the gate is open —
# all tool names are permitted. This preserves backward-compat for installs
# that have not configured a tool allowlist.
#
# Operators populate data.yashigani.mcp.exposed_tools as a set of strings:
#   PUT /v1/data/yashigani/mcp/exposed_tools ["web_search", "code_exec", ...]
# ---------------------------------------------------------------------------

_tool_authz_ok if {
    # No tool subject on this request — authz gate is not applicable
    not _tool_present
}

# Resolve the exposed_tools allowlist — default to empty set when absent in data bundle.
# This makes the gate open (backward-compat) when operators have not loaded a bundle.
_exposed_tools := data.yashigani.mcp.exposed_tools if {
    data.yashigani.mcp.exposed_tools
} else := set()

_tool_authz_ok if {
    # Tool present: allowlist absent or empty → open gate (backward-compat)
    _tool_present
    count(_exposed_tools) == 0
}

_tool_authz_ok if {
    # Tool present: allowlist populated → tool name must be in it
    _tool_present
    count(_exposed_tools) > 0
    input.tool.name in _exposed_tools
}

# ---------------------------------------------------------------------------
# Action recognition
# ---------------------------------------------------------------------------

_recognised_actions := {
    "mcp.tools.call",
    "mcp.tools.list",
    "mcp.prompts.list",
    "mcp.prompts.get",
    "mcp.resources.list",
    "mcp.resources.read",
    "mcp.resources.subscribe",
    "mcp.ping",
    "mcp.initialize",
    "mcp.sampling.createMessage",
}

_action_recognised if {
    input.action in _recognised_actions
}

# ---------------------------------------------------------------------------
# Deny reasons — used by the gateway for audit events and error bodies.
# Only one should fire per request (first matching wins in priority order).
# ---------------------------------------------------------------------------

deny_reason := "ok" if { allow }

deny_reason := "missing_spiffe_identity" if {
    not allow
    not _spiffe_present
}

deny_reason := "invalid_posture" if {
    not allow
    _spiffe_present
    not _posture_valid
}

deny_reason := "chain_depth_exceeded" if {
    not allow
    _spiffe_present
    _posture_valid
    not _chain_depth_ok
}

deny_reason := "multiple_subjects_in_request" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    not _exactly_one_subject
    # At least two of the three subjects are simultaneously present
    _subject_count >= 2
}

deny_reason := "missing_subject" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    not _exactly_one_subject
    _subject_count == 0
}

deny_reason := "unrecognised_action" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    not _action_recognised
}

deny_reason := "tool_not_in_exposed_allowlist" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    _tool_present
    count(_exposed_tools) > 0
    not input.tool.name in _exposed_tools
}

deny_reason := "mcp_c_requires_chain" if {
    not allow
    _spiffe_present
    _posture_valid
    _chain_depth_ok
    _exactly_one_subject
    _action_recognised
    input.posture == "mcp-c"
    _chain_depth == 0
}

# Count how many subjects are present (used by deny_reason selectors above)
_tool_count := 1 if { _tool_present } else := 0
_prompt_count := 1 if { _prompt_present } else := 0
_resource_count := 1 if { _resource_present } else := 0

_subject_count := _tool_count + _prompt_count + _resource_count

# ---------------------------------------------------------------------------
# redact_args — list of tool argument keys to redact before logging
#
# When a tool call is in scope, any argument key whose name contains a
# secret-like pattern is added to the redact list.  The gateway uses this
# list to replace values with "<REDACTED>" before writing audit records.
#
# This covers common patterns (api_key, token, secret, password, credential).
# The source-of-truth redaction of the actual bytes must happen in the gateway
# CHS (Credential Hiding Service) before populating args_redacted in the input.
# This list is a secondary policy-layer assertion for audit enforcement.
# ---------------------------------------------------------------------------

# FIX LAURA-MCP-002 / LU-MCP-02 (MED): secret-redaction gaps.
# Added exact-match entries: aws_secret_access_key, aws_session_token,
# client_secret, refresh_token, session_token, pat, x-api-key.
# Exact-match is intentional — do NOT switch to substring matching, which
# would over-redact innocent keys like sort_key and cache_key.
# Nested-key redaction (e.g. config.api_key inside an object value) is the
# gateway CHS's (Credential Hiding Service) responsibility, not policy.
_secret_key_patterns := {
    "api_key", "apikey", "token", "secret", "password", "passwd", "credential",
    "credentials", "private_key", "private_token", "auth", "authorization",
    "bearer", "key", "access_key", "secret_key",
    "aws_secret_access_key", "aws_session_token", "client_secret",
    "refresh_token", "session_token", "pat", "x-api-key",
}

# FIX LAURA-MCP-004 (Info): non-object args_redacted guard.
# If args_redacted is not an object (e.g. an array or boolean), is_object fails
# and redact_args falls through to the else := set() — audit still emits an
# empty redact list rather than crashing or silently suppressing audit.
redact_args := ra if {
    allow
    _tool_present
    is_object(input.tool.args_redacted)
    ra := {k |
        k := object.keys(input.tool.args_redacted)[_]
        lower(k) in _secret_key_patterns
    }
} else := set()

# ---------------------------------------------------------------------------
# audit_capture — true when gateway must write a full audit record
#
# Always capture on:
#   - Any deny
#   - CONFIDENTIAL / RESTRICTED resource/prompt access
#   - Any chain-depth > 1 (multi-hop)
#   - Any tool call with non-empty redact_args
# ---------------------------------------------------------------------------

default audit_capture := false

audit_capture if { not allow }

audit_capture if {
    allow
    _resource_present
    input.resource.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
}

audit_capture if {
    allow
    _prompt_present
    input.prompt.sensitivity in {"CONFIDENTIAL", "RESTRICTED"}
}

audit_capture if {
    allow
    _chain_depth > 1
}

audit_capture if {
    allow
    _tool_present
    count(redact_args) > 0
}

# ---------------------------------------------------------------------------
# rate_limit_key — bucket key for the gateway rate limiter
#
# Non-null when the gateway should apply a per-caller rate limit for this action.
# Format: "<spiffe_hash>/<action>[/<tool_name>]"
#
# The SPIFFE URI is hashed (sha256 hex) to keep the key short and avoid
# leaking identity topology into the rate-limit store.
# ---------------------------------------------------------------------------

rate_limit_key := k if {
    allow
    _tool_present
    k := sprintf("%s/%s/%s", [
        _spiffe_hash,
        input.action,
        input.tool.name,
    ])
}

rate_limit_key := k if {
    allow
    not _tool_present
    k := sprintf("%s/%s", [
        _spiffe_hash,
        input.action,
    ])
}

default rate_limit_key := null

_spiffe_hash := h if {
    h := crypto.sha256(input.identity.spiffe)
} else := "anonymous"

# ---------------------------------------------------------------------------
# mcp_decision — compound decision document
#
# The gateway queries /v1/data/yashigani/mcp/mcp_decision.
# Shape matches mcp-input.schema.json §definitions.mcp_decision.
# ---------------------------------------------------------------------------

mcp_decision := {
    "allow": allow,
    "deny_reason": deny_reason_value,
    "redact_args": ra,
    "audit_capture": audit_capture,
    "rate_limit_key": rate_limit_key,
}

# Use a safe getter to avoid undefined when allow is true (deny_reason is undefined)
deny_reason_value := deny_reason if { not allow }
deny_reason_value := "ok" if { allow }

ra := redact_args

# ---------------------------------------------------------------------------
# P3 — Filesystem MCP server tool gating (Laura threat model §5)
#
# These rules enforce the filesystem-specific OPA constraints for the
# @modelcontextprotocol/server-filesystem bundle.  They are checked by the
# gateway broker AFTER the global allow path when input.agent.name == "filesystem"
# (or any agent whose name matches a manifest with category=mcp_server).
#
# The global mcp.rego allow path (above) handles posture/SPIFFE/chain checks.
# These rules add the agent-specific per-tool authz layer (P9).
#
# References:
#   LAURA-FS-TM-001  path traversal (§2.2.1)
#   LAURA-FS-TM-003  ReDoS via search_files (§2.3)
#   LAURA-FS-TM-005  list_allowed_directories info-disclosure (§2.2.5)
# ---------------------------------------------------------------------------

# Filesystem read-only tool set (permitted by default)
_fs_readonly_tools := {
    "read_file",
    "read_multiple_files",
    "list_directory",
    "directory_tree",
    "get_file_info",
    "search_files",
}

# Filesystem write/mutating tool set (denied by default; allowed when write_posture=readwrite)
_fs_write_tools := {
    "write_file",
    "edit_file",
    "create_directory",
    "move_file",
}

# ---------------------------------------------------------------------------
# Path argument safety (LAURA-FS-TM-001 §5.1)
#
# Belt-and-suspenders against path traversal. Primary control is the
# named-volume mount boundary (the container has no /etc, no host paths).
# OPA adds a policy-layer pre-call assertion.
#
# Rules:
#   - args.path must not contain "../"
#   - args.path must not start with "/" (absolute paths rejected;
#     the server's --allowed-dir is the root, not the container's root)
#   - When no path arg is present (e.g. list_directory of root), pass.
# ---------------------------------------------------------------------------

_fs_path_arg_safe(args) if {
    is_string(args.path)
    not contains(args.path, "../")
    not startswith(args.path, "/")
}

_fs_path_arg_safe(args) if {
    not args.path
}

# ---------------------------------------------------------------------------
# directory_tree depth cap (LAURA-FS-TM-003 §5.2)
#
# Prevents recursive directory traversal DoS.
# maxDepth must be <= 5 or absent (broker enforces cap when absent).
# ---------------------------------------------------------------------------

_fs_directory_tree_safe(args) if {
    not args.maxDepth
}

_fs_directory_tree_safe(args) if {
    to_number(args.maxDepth) <= 5
}

# ---------------------------------------------------------------------------
# search_files pattern length cap (LAURA-FS-TM-003 §5.3 — ReDoS)
#
# The glob package has had historical ReDoS vulnerabilities.
# Cap pattern length at 256 characters.
# ---------------------------------------------------------------------------

_fs_search_files_safe(args) if {
    is_string(args.pattern)
    count(args.pattern) <= 256
}

_fs_search_files_safe(args) if {
    not args.pattern
}

# ---------------------------------------------------------------------------
# filesystem_tool_allowed — the compound filesystem tool decision
#
# Called from the gateway broker's per-agent authz layer.
# Returns true when the tool call is permitted for the filesystem bundle.
# Fail-closed: default := false means any unmatched combination is denied.
# ---------------------------------------------------------------------------

default filesystem_tool_allowed := false

# Read-only tools: PERMIT (always) with path validation
# Excludes directory_tree (has depth cap) and search_files (has pattern-length cap)
# — both handled by their own dedicated rules below.
filesystem_tool_allowed if {
    input.tool.name in _fs_readonly_tools
    not input.tool.name == "list_allowed_directories"
    not input.tool.name == "directory_tree"
    not input.tool.name == "search_files"
    _fs_path_arg_safe(input.tool.args)
}

# directory_tree: depth cap + path validation
filesystem_tool_allowed if {
    input.tool.name == "directory_tree"
    _fs_path_arg_safe(input.tool.args)
    _fs_directory_tree_safe(input.tool.args)
}

# search_files: path + pattern-length cap
filesystem_tool_allowed if {
    input.tool.name == "search_files"
    _fs_path_arg_safe(input.tool.args)
    _fs_search_files_safe(input.tool.args)
}

# Write tools: PERMIT only when write_posture=readwrite in data bundle
# Operator sets: PUT /v1/data/yashigani/mcp/filesystem_write_posture "readwrite"
_fs_write_posture := p if {
    p := data.yashigani.mcp.filesystem_write_posture
} else := "readonly"

filesystem_tool_allowed if {
    input.tool.name in _fs_write_tools
    _fs_write_posture == "readwrite"
    _fs_path_arg_safe(input.tool.args)
}

# list_allowed_directories: ALWAYS denied (info-disclosure — Laura §2.2.5)
# No allow rule matches for this tool; default := false catches it.

# ---------------------------------------------------------------------------
# filesystem_deny_reason — reason string for denied filesystem tool calls
# ---------------------------------------------------------------------------

filesystem_deny_reason := "fs_path_traversal_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    contains(input.tool.args.path, "../")
}

filesystem_deny_reason := "fs_path_traversal_attempt" if {
    not filesystem_tool_allowed
    is_string(input.tool.args.path)
    startswith(input.tool.args.path, "/")
}

filesystem_deny_reason := "fs_directory_tree_depth_exceeded" if {
    not filesystem_tool_allowed
    input.tool.name == "directory_tree"
    is_number(to_number(input.tool.args.maxDepth))
    to_number(input.tool.args.maxDepth) > 5
}

filesystem_deny_reason := "fs_search_pattern_too_long" if {
    not filesystem_tool_allowed
    input.tool.name == "search_files"
    is_string(input.tool.args.pattern)
    count(input.tool.args.pattern) > 256
}

filesystem_deny_reason := "fs_tool_denied_readonly_posture" if {
    not filesystem_tool_allowed
    input.tool.name in _fs_write_tools
    _fs_write_posture == "readonly"
}

filesystem_deny_reason := "fs_list_allowed_directories_denied" if {
    not filesystem_tool_allowed
    input.tool.name == "list_allowed_directories"
}

default filesystem_deny_reason := "fs_tool_not_permitted"
