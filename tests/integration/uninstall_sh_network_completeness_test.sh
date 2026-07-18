#!/usr/bin/env bash
# uninstall_sh_network_completeness_test.sh — Regression test for
# FINDING-V412-RESTART-004a.
#
# Bug: uninstall.sh's network cleanup relied on a hardcoded
#   _CANONICAL_NETWORKS list ("edge caddy_internal data obs
#   langflow_isolated letta_isolated openclaw_isolated letta_db"). The list
#   drifted every time a compose file gained a network -- three real,
#   compose-defined project networks (demo_mcp_isolated, extractor_svc,
#   ollama_ringfence) were never added. Result: `localhost_demo_mcp_isolated`
#   survived a full `--remove-volumes` nuke while uninstall.sh's own final
#   assertion printed "Network assertion passed — all canonical networks
#   removed." -- a FALSE positive, because the assertion only ever
#   re-checked the same stale list, never the actual runtime state.
#
# Fix: uninstall.sh now derives the network set to remove (and to assert
#   against) from the runtime itself via _list_project_networks() -- a
#   label-filter + name-prefix enumeration mirroring the pre-existing,
#   already-correct _list_project_containers() pattern -- instead of a
#   hardcoded list. This closes the class of bug, not just the one
#   confirmed instance (demo_mcp_isolated).
#
# Verifies:
#   (a) Static: _list_project_networks() is defined in uninstall.sh.
#   (b) Static: the hardcoded _CANONICAL_NETWORKS="..." assignment is GONE
#       (regression guard -- if this reappears, the stale-list bug class is
#       back).
#   (c) Static: the final network completeness assertion re-derives from
#       _list_project_networks (not a static var) -- closes the "passed on
#       a filtered view" false-positive class.
#   (d) Live (any host with podman/docker, no root required -- network
#       create/rm does not need elevated privileges on rootless Podman):
#       stage a network with a name that is intentionally NOT any of the
#       8 entries the old hardcoded list ever contained (proving, by
#       construction, that a pre-fix fixed-list loop would never have found
#       or removed it), confirm the label-filter strategy uninstall.sh now
#       uses actually discovers and can remove it.
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# FINDING-V412-RESTART-004a
# last-updated: 2026-07-18T00:00:00+00:00

set -uo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_skip() { printf "[SKIP] %s\n" "$1"; (( SKIP++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UNINSTALL_SH="${UNINSTALL_SH:-${REPO_ROOT}/uninstall.sh}"

_info "uninstall.sh: ${UNINSTALL_SH}"
_info "repo root:    ${REPO_ROOT}"

if [[ ! -f "$UNINSTALL_SH" ]]; then
    printf "[FAIL] uninstall.sh not found at: %s\n" "$UNINSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Static checks (parse-time — no container runtime required)
# ---------------------------------------------------------------------------
_section "A — Static: _list_project_networks() is defined"

if grep -q '^_list_project_networks() {' "$UNINSTALL_SH"; then
    _pass "(a.1) _list_project_networks() function is defined in uninstall.sh"
else
    _fail "(a.1) _list_project_networks() NOT found — network derivation fix missing"
fi

_section "B — Static: hardcoded _CANONICAL_NETWORKS list is GONE"

if grep -qE '^_CANONICAL_NETWORKS=' "$UNINSTALL_SH"; then
    _fail "(b.1) _CANONICAL_NETWORKS=... assignment still present — stale-list bug class has returned"
else
    _pass "(b.1) No _CANONICAL_NETWORKS=... assignment found (list-based derivation removed)"
fi

_section "C — Static: final network assertion re-derives from the runtime"

if grep -q '_residual_networks="\$(_list_project_networks' "$UNINSTALL_SH"; then
    _pass "(c.1) Final network assertion calls _list_project_networks() (not a static var)"
else
    _fail "(c.1) Final network assertion does not call _list_project_networks() — may still check a filtered/stale view"
fi

# Assert _list_project_networks is DEFINED before its first call site
# (ordering sanity — a forward reference would be a shell bug, not a
# semantic one, but worth guarding since bash reads top-to-bottom).
_def_line="$(grep -n '^_list_project_networks() {' "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"
_call_line="$(grep -n '_net_targets="\$(_list_project_networks' "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"
if [[ -n "$_def_line" && -n "$_call_line" ]]; then
    if [[ "$_def_line" -lt "$_call_line" ]]; then
        _pass "(c.2) _list_project_networks() defined (line ${_def_line}) before first call (line ${_call_line})"
    else
        _fail "(c.2) _list_project_networks() defined (line ${_def_line}) AFTER first call (line ${_call_line})"
    fi
else
    _fail "(c.2) Could not locate both definition and call site (def=${_def_line:-MISSING} call=${_call_line:-MISSING})"
fi

# ---------------------------------------------------------------------------
# Live test — any host with podman or docker (no root required: network
# create/rm/inspect works under rootless Podman, confirmed on this exact
# host during the FINDING-004a fix). Gated only on runtime availability.
# ---------------------------------------------------------------------------
_section "D — Live: label-filter discovery finds a network NOT in the old hardcoded list"

_RUNTIME=""
if command -v podman >/dev/null 2>&1; then
    _RUNTIME="podman"
elif command -v docker >/dev/null 2>&1; then
    _RUNTIME="docker"
fi

if [[ -z "$_RUNTIME" ]]; then
    _skip "(d) Live test skipped: neither podman nor docker found on PATH"
else
    # Old hardcoded list, reproduced here ONLY as a negative-control fixture
    # to prove the test network's name was never a member — this is test
    # scaffolding, not a reintroduction of the production list.
    _OLD_STATIC_LIST="edge caddy_internal data obs langflow_isolated letta_isolated openclaw_isolated letta_db"
    _pfx="regtest$$"
    _TEST_NET="${_pfx}_demo_mcp_isolated"

    _in_old_list=false
    for _n in $_OLD_STATIC_LIST; do
        [[ "${_pfx}_${_n}" == "$_TEST_NET" ]] && _in_old_list=true
    done
    if [[ "$_in_old_list" == "true" ]]; then
        _fail "(d.pre) Test-fixture bug: ${_TEST_NET} collides with the old static list — regenerate fixture name"
    else
        _pass "(d.pre) Test network name '${_TEST_NET}' is confirmed NOT a member of the old hardcoded list"
    fi

    _cleanup_live() {
        "$_RUNTIME" network rm "$_TEST_NET" >/dev/null 2>&1 || true
    }
    trap '_cleanup_live' EXIT

    _info "(d) Creating test network: ${_TEST_NET} (label com.docker.compose.project=${_pfx})"
    if ! "$_RUNTIME" network create --label "com.docker.compose.project=${_pfx}" "$_TEST_NET" >/dev/null 2>&1; then
        _fail "(d) Could not create test network — ${_RUNTIME} network create failed"
    else
        _pass "(d.setup) Test network created"

        # Mirror uninstall.sh's _list_project_networks() label-filter strategy
        # exactly (strategy 1 of 2 — the strategy that matters here since the
        # test network's name uses the SAME prefix convention the name-prefix
        # fallback would also catch; the label filter is what proves runtime-
        # derivation independent of any hardcoded name list).
        _found="$("$_RUNTIME" network ls --filter "label=com.docker.compose.project=${_pfx}" --format "{{.Name}}" 2>/dev/null || true)"
        if [[ "$_found" == "$_TEST_NET" ]]; then
            _pass "(d.discover) Label-filter enumeration found '${_TEST_NET}' — a network the old hardcoded list would NEVER have matched"
        else
            _fail "(d.discover) Label-filter enumeration did NOT find '${_TEST_NET}' (got: '${_found}') — derivation mechanism broken"
        fi

        # Remove it exactly as uninstall.sh's canonical-network-cleanup loop
        # would (network rm on each _list_project_networks() result).
        if "$_RUNTIME" network rm "$_TEST_NET" >/dev/null 2>&1; then
            _pass "(d.remove) Test network removed via network rm"
        else
            _fail "(d.remove) network rm failed on test network"
        fi

        # Re-enumerate: must now be empty (this is the completeness assertion
        # the fix restores — re-derive from the runtime, not a static list).
        _after="$("$_RUNTIME" network ls --filter "label=com.docker.compose.project=${_pfx}" --format "{{.Name}}" 2>/dev/null || true)"
        if [[ -z "$_after" ]]; then
            _pass "(d.assert) Re-derived enumeration is empty after removal — no false 'passed' possible"
        else
            _fail "(d.assert) Re-derived enumeration still shows: '${_after}'"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
_section "Summary"
printf "PASS: %d  FAIL: %d  SKIP: %d\n" "$PASS" "$FAIL" "$SKIP"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
