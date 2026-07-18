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
# CAPTAIN REVIEW REGRESSION (2026-07-18, commit 5ddb0c99 NO-GO): the first
# version of this fix excluded ringfence networks from the strict sweep via
# `grep -v '^ringfence_'` -- an anchor on a BARE, unprefixed name. But
# install.sh's onboard code path (ringfence_net="ringfence_${agent}", no
# `name:` compose override) means the real on-disk network name is ALWAYS
# project-prefixed ("<project>_ringfence_<agent>", e.g.
# localhost_ringfence_git) -- confirmed live by Captain
# (localhost_ringfence_testagent) and independently in this session's own
# install run (localhost_ringfence_openclaw_in). The bare-anchor exclusion
# never matched the real name, so ringfence networks fell into the strict
# sweep's hard exit-1 assertion BEFORE the permissive J12 sweep (Ava
# 2026-05-30) ever ran -- a hard uninstall failure for any customer with an
# active onboarded agent, regressing the previously-shipped soft-WARN
# behaviour. Fix: _RINGFENCE_NAME_PATTERN="ringfence_" (substring, no
# anchor) defined ONCE in uninstall.sh and referenced by BOTH the strict
# sweep's exclusion filter AND the J12 sweep's own `network ls --filter`
# call, so the two sweeps cannot define this boundary independently (and
# therefore cannot drift apart) again.
#
#   (e) Static: _RINGFENCE_NAME_PATTERN is defined exactly once and BOTH the
#       strict-sweep exclusion filter and the J12 sweep's own network-ls
#       filter reference that SAME variable (not independent literals).
#   (f) Live: a project-prefixed ringfence network (the REAL on-disk shape)
#       is (f.1) excluded from the strict sweep / _list_project_networks(),
#       while (f.2) still matched by the J12-style substring filter --
#       proving J12 remains responsible for it.
#   (g) Live: the J12 sweep's core assumption -- "attempt removal once,
#       tolerate failure" -- holds for a REALISTIC precondition: a container
#       attached to the ringfence network makes `network rm` fail (g.1,
#       proving the WARN branch is reachable, not a paranoid fantasy), and
#       once detached, `network rm` succeeds cleanly (g.2, proving the
#       ringfence network is NOT permanently unremovable -- J12 still
#       actually cleans up the common case).
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# FINDING-V412-RESTART-004a
# last-updated: 2026-07-18T00:00:00+00:00 (ringfence-exclusion regression fix)

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
# Static checks — single-source-of-truth ringfence boundary
# ---------------------------------------------------------------------------
_section "E — Static: _RINGFENCE_NAME_PATTERN is the single source of truth"

if grep -qE '^_RINGFENCE_NAME_PATTERN=' "$UNINSTALL_SH"; then
    _pass "(e.1) _RINGFENCE_NAME_PATTERN=... is defined in uninstall.sh"
else
    _fail "(e.1) _RINGFENCE_NAME_PATTERN=... NOT found — shared boundary definition missing"
fi

# Regression guard for the EXACT bug Captain caught: the strict-sweep
# exclusion filter must NOT be a bare-anchored literal ('^ringfence_') —
# it must reference the shared variable.
if grep -q "grep -v \"\$_RINGFENCE_NAME_PATTERN\"" "$UNINSTALL_SH"; then
    _pass "(e.2) Strict-sweep exclusion filter references \$_RINGFENCE_NAME_PATTERN (not a bare-anchored literal)"
else
    _fail "(e.2) Strict-sweep exclusion filter does NOT reference \$_RINGFENCE_NAME_PATTERN — may have regressed to the bare-anchor bug"
fi

if grep -qE "network ls --filter \"name=\\\$\{?_RINGFENCE_NAME_PATTERN\}?\"" "$UNINSTALL_SH"; then
    _pass "(e.3) J12 sweep's network-ls filter references \$_RINGFENCE_NAME_PATTERN (same shared definition, not an independent literal)"
else
    _fail "(e.3) J12 sweep's network-ls filter does NOT reference \$_RINGFENCE_NAME_PATTERN — the two sweeps can drift apart again"
fi

# Extract the ACTUAL pattern value from uninstall.sh for the live tests below
# — never hardcode a second copy of "ringfence_" independently in this test;
# if uninstall.sh's pattern changes, this test must follow it automatically.
_RF_PATTERN="$(grep -oE '^_RINGFENCE_NAME_PATTERN="[^"]*"' "$UNINSTALL_SH" | head -1 | sed -E 's/^_RINGFENCE_NAME_PATTERN="(.*)"$/\1/')"
if [[ -n "$_RF_PATTERN" ]]; then
    _pass "(e.4) Extracted live pattern value from uninstall.sh: '${_RF_PATTERN}'"
else
    _fail "(e.4) Could not extract _RINGFENCE_NAME_PATTERN value from uninstall.sh — live ringfence tests below will be skipped"
fi

# ---------------------------------------------------------------------------
# Live test — project-prefixed ringfence network (the REAL on-disk shape,
# per install.sh's onboard code path with no `name:` compose override).
# Same runtime-availability gate as section D.
# ---------------------------------------------------------------------------
_section "F — Live: project-prefixed ringfence network excluded from strict sweep, still owned by J12"

if [[ -z "$_RUNTIME" ]]; then
    _skip "(f) Live test skipped: neither podman nor docker found on PATH"
elif [[ -z "$_RF_PATTERN" ]]; then
    _skip "(f) Live test skipped: could not extract _RINGFENCE_NAME_PATTERN (see e.4)"
else
    _rf_pfx="regtestrf$$"
    _RF_NET="${_rf_pfx}_ringfence_testagent"

    _cleanup_rf() {
        "$_RUNTIME" network rm "$_RF_NET" >/dev/null 2>&1 || true
    }
    trap '_cleanup_rf' EXIT

    _info "(f) Creating project-prefixed ringfence network: ${_RF_NET} (the REAL install.sh onboard shape)"
    if ! "$_RUNTIME" network create --label "com.docker.compose.project=${_rf_pfx}" "$_RF_NET" >/dev/null 2>&1; then
        _fail "(f) Could not create test ringfence network"
    else
        _pass "(f.setup) Project-prefixed ringfence network created"

        # Mirror _list_project_networks() EXACTLY (label filter + name-prefix
        # fallback + exclusion using the pattern EXTRACTED from uninstall.sh,
        # not a second hardcoded copy).
        _mirror_list_project_networks() {
            local _rt="$1" _pfx2="$2" _names=""
            local _l
            _l="$("$_rt" network ls --filter "label=com.docker.compose.project=${_pfx2}" --format "{{.Name}}" 2>/dev/null || true)"
            [[ -n "$_l" ]] && _names="${_names}${_l}
"
            local _by_name
            _by_name="$("$_rt" network ls --filter "name=^${_pfx2}_" --format "{{.Name}}" 2>/dev/null || true)"
            [[ -n "$_by_name" ]] && _names="${_names}${_by_name}
"
            printf '%s' "$_names" | sort -u | grep -v '^$' | grep -v "$_RF_PATTERN" || true
        }

        _strict_result="$(_mirror_list_project_networks "$_RUNTIME" "$_rf_pfx")"
        if [[ -z "$_strict_result" ]]; then
            _pass "(f.1) Strict sweep (_list_project_networks mirror) correctly EXCLUDES '${_RF_NET}'"
        else
            _fail "(f.1) Strict sweep leaked ringfence network into its result: '${_strict_result}' — the exit-1 assertion would fire on this"
        fi

        _j12_result="$("$_RUNTIME" network ls --filter "name=${_RF_PATTERN}" --format "{{.Name}}" 2>/dev/null | grep -F "$_RF_NET" || true)"
        if [[ "$_j12_result" == "$_RF_NET" ]]; then
            _pass "(f.2) J12-style substring filter still FINDS '${_RF_NET}' — remains J12's responsibility, not orphaned"
        else
            _fail "(f.2) J12-style substring filter did NOT find '${_RF_NET}' — J12 sweep would silently skip it"
        fi

        if "$_RUNTIME" network rm "$_RF_NET" >/dev/null 2>&1; then
            _pass "(f.remove) Detached ringfence network removed cleanly via network rm"
        else
            _fail "(f.remove) network rm failed on a detached ringfence network"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Live test — J12's "attempt once, tolerate failure" assumption under a
# REALISTIC precondition (container attached to the ringfence network).
# ---------------------------------------------------------------------------
_section "G — Live: attached container makes rm fail (WARN case); detached rm succeeds (cleanup case)"

if [[ -z "$_RUNTIME" ]]; then
    _skip "(g) Live test skipped: neither podman nor docker found on PATH"
elif ! "$_RUNTIME" image exists alpine:3.21.3 >/dev/null 2>&1 && ! "$_RUNTIME" image exists docker.io/library/alpine:3.21.3 >/dev/null 2>&1; then
    _skip "(g) Live test skipped: alpine:3.21.3 image not present locally (test does not pull images)"
else
    _rf_pfx2="regtestrfattach$$"
    _RF_NET2="${_rf_pfx2}_ringfence_testagent"
    _RF_CTR="regtestrfctr$$"

    _cleanup_rf2() {
        "$_RUNTIME" rm -f "$_RF_CTR" >/dev/null 2>&1 || true
        "$_RUNTIME" network rm "$_RF_NET2" >/dev/null 2>&1 || true
    }
    trap '_cleanup_rf2' EXIT

    _info "(g) Creating ringfence network + attaching a container to it"
    if ! "$_RUNTIME" network create --label "com.docker.compose.project=${_rf_pfx2}" "$_RF_NET2" >/dev/null 2>&1; then
        _fail "(g) Could not create test ringfence network"
    elif ! "$_RUNTIME" run -d --name "$_RF_CTR" --network "$_RF_NET2" --rm=false alpine:3.21.3 sleep 300 >/dev/null 2>&1; then
        _fail "(g) Could not start test container attached to ringfence network"
    else
        _pass "(g.setup) Ringfence network + attached container created"

        # (g.1) Attached: network rm MUST fail — this is the exact precondition
        # J12's WARN (not exit-1) branch exists to tolerate.
        if "$_RUNTIME" network rm "$_RF_NET2" >/dev/null 2>&1; then
            _fail "(g.1) network rm succeeded while a container was attached — test precondition wrong (or runtime behaviour changed)"
        else
            _pass "(g.1) network rm correctly FAILS while a container is attached — J12's WARN branch is reachable, not a paranoid fallback"
        fi

        # Detach (stop+remove the container), then retry.
        "$_RUNTIME" rm -f "$_RF_CTR" >/dev/null 2>&1
        if "$_RUNTIME" network rm "$_RF_NET2" >/dev/null 2>&1; then
            _pass "(g.2) network rm succeeds once the attached container is removed — J12 still cleans up the common (no-longer-attached) case"
        else
            _fail "(g.2) network rm STILL failed after detaching the container"
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
