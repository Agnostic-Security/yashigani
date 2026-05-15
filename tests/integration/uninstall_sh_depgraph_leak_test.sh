#!/usr/bin/env bash
# uninstall_sh_depgraph_leak_test.sh — Regression test for BUG-UNINSTALL-DEPGRAPH-LEAK.
#
# Verifies that uninstall.sh force-removes dependent containers left in Exited
# state before attempting volume rm. Without the fix, `podman volume rm` fails
# with "still in use" because Exited containers from a depends_on chain still
# hold a reference to the named volume.
#
# Test scenarios:
#   (a) Verify code path exists: confirm the belt-and-braces container-removal
#       block is present in uninstall.sh (compile-time check — no live stack).
#   (b) On Linux with Podman available: simulate Exited containers referencing
#       a named volume, run the container-removal loop code path, assert volumes
#       are freed. Gated to Linux-Podman only (macOS Podman has different VM
#       semantics; Docker Engine auto-removes on compose down).
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# BUG-UNINSTALL-DEPGRAPH-LEAK
# last-updated: 2026-05-15T12:00:00+00:00

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

_info "uninstall.sh:    ${UNINSTALL_SH}"
_info "repo root:       ${REPO_ROOT}"

if [[ ! -f "$UNINSTALL_SH" ]]; then
    printf "[FAIL] uninstall.sh not found at: %s\n" "$UNINSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Platform detection: gate live tests to Linux + rootful Podman only
# ---------------------------------------------------------------------------
_OS="$(uname -s)"
_IS_LINUX=false
_HAS_PODMAN=false
_IS_ROOT=false

[[ "$_OS" == "Linux" ]] && _IS_LINUX=true
command -v podman >/dev/null 2>&1 && _HAS_PODMAN=true
[[ "$(id -u)" == "0" ]] && _IS_ROOT=true

_LIVE_TEST_ELIGIBLE=false
if [[ "$_IS_LINUX" == "true" && "$_HAS_PODMAN" == "true" && "$_IS_ROOT" == "true" ]]; then
    _LIVE_TEST_ELIGIBLE=true
fi

# ---------------------------------------------------------------------------
# CHECK (a): Compile-time — belt-and-braces block is present in uninstall.sh
# ---------------------------------------------------------------------------
_section "CHECK (a): BUG-UNINSTALL-DEPGRAPH-LEAK block exists in uninstall.sh"

# Assert the container-removal loop sentinel comment is present
if grep -q "BUG-UNINSTALL-DEPGRAPH-LEAK" "$UNINSTALL_SH"; then
    _pass "(a.1) BUG-UNINSTALL-DEPGRAPH-LEAK marker present in uninstall.sh"
else
    _fail "(a.1) BUG-UNINSTALL-DEPGRAPH-LEAK marker NOT found in uninstall.sh"
fi

# Assert the runtime ps -a filter call is present (strategy 1: label filter)
if grep -q 'ps -a -q --filter' "$UNINSTALL_SH"; then
    _pass "(a.2) container ps --filter call present in uninstall.sh"
else
    _fail "(a.2) container ps --filter call NOT found in uninstall.sh"
fi

# Assert the force-remove call is present
if grep -q '"$RUNTIME" rm -f' "$UNINSTALL_SH" || grep -q '"$RUNTIME" rm -f "$_cid"' "$UNINSTALL_SH"; then
    _pass "(a.3) container rm -f call present in uninstall.sh"
else
    _fail "(a.3) container rm -f call NOT found in uninstall.sh"
fi

# Assert the block runs BEFORE the volume-rm loop
# (belt-and-braces block must precede the per-volume rm loop)
_belt_line=""
_vol_loop_line=""
while IFS= read -r _line_text; do
    _lineno="${_line_text%%:*}"
    _content="${_line_text#*:}"
    if [[ -z "$_belt_line" ]] && echo "$_content" | grep -q "BUG-UNINSTALL-DEPGRAPH-LEAK"; then
        _belt_line="$_lineno"
    fi
    if [[ -z "$_vol_loop_line" ]] && echo "$_content" | grep -q "UNINSTALL-LEAVES-VOLUMES"; then
        _vol_loop_line="$_lineno"
    fi
done < <(grep -n "BUG-UNINSTALL-DEPGRAPH-LEAK\|UNINSTALL-LEAVES-VOLUMES" "$UNINSTALL_SH" || true)

if [[ -n "$_belt_line" && -n "$_vol_loop_line" ]]; then
    if [[ "$_belt_line" -lt "$_vol_loop_line" ]]; then
        _pass "(a.4) container-removal block (line ${_belt_line}) appears BEFORE volume-rm loop (line ${_vol_loop_line})"
    else
        _fail "(a.4) container-removal block (line ${_belt_line}) appears AFTER volume-rm loop (line ${_vol_loop_line}) — ordering wrong"
    fi
else
    _fail "(a.4) could not locate both block markers to verify ordering (belt=${_belt_line:-MISSING}, vol=${_vol_loop_line:-MISSING})"
fi

# ---------------------------------------------------------------------------
# CHECK (b): Live test — simulate Exited containers referencing a named volume
# Gated to: Linux + rootful Podman only
# ---------------------------------------------------------------------------
_section "CHECK (b): Live simulation — Exited container holds volume ref, belt-and-braces frees it"

if [[ "$_LIVE_TEST_ELIGIBLE" != "true" ]]; then
    if [[ "$_IS_LINUX" != "true" ]]; then
        _skip "(b) Live test skipped: not Linux (macOS Podman VM has different semantics)"
    elif [[ "$_HAS_PODMAN" != "true" ]]; then
        _skip "(b) Live test skipped: Podman not available"
    elif [[ "$_IS_ROOT" != "true" ]]; then
        _skip "(b) Live test skipped: not running as root (rootful Podman required for volume ref test)"
    fi
else
    _TEST_VOL="docker_depgraph_leak_test_$(date +%s)"
    _TEST_CTR="docker_depgraph_test_ctr_$(date +%s)"
    _cleanup_live() {
        podman rm -f "$_TEST_CTR" >/dev/null 2>&1 || true
        podman volume rm -f "$_TEST_VOL" >/dev/null 2>&1 || true
    }
    trap '_cleanup_live' EXIT

    # Create named volume and start a container that mounts it (then exit)
    _info "(b) Creating test volume: $_TEST_VOL"
    if ! podman volume create "$_TEST_VOL" >/dev/null 2>&1; then
        _fail "(b) Could not create test volume — podman volume create failed"
    else
        _pass "(b.setup) Test volume created"

        _info "(b) Running Exited container referencing volume..."
        # Run container, immediately exit — leaves it in Exited state
        if ! podman run --name "$_TEST_CTR" \
               -v "${_TEST_VOL}:/mnt/test:z" \
               --label "io.podman.compose.project=docker" \
               --rm=false \
               busybox:latest sh -c "echo ok" >/dev/null 2>&1; then
            _fail "(b) Could not run test container — busybox run failed"
        else
            _pass "(b.setup) Test container ran and is now Exited"

            # Verify volume rm fails while container exists in Exited state
            if podman volume rm "$_TEST_VOL" >/dev/null 2>&1; then
                _fail "(b.pre) Volume rm succeeded even with Exited container — test precondition wrong"
            else
                _pass "(b.pre) Volume rm correctly fails while Exited container holds ref"

                # Now simulate the belt-and-braces loop from uninstall.sh:
                # enumerate containers by label, force-remove them
                _info "(b) Running belt-and-braces container removal (label filter)..."
                _ids="$(podman ps -a -q --filter "label=io.podman.compose.project=docker" 2>/dev/null || true)"
                _rm_count=0
                if [[ -n "$_ids" ]]; then
                    while IFS= read -r _cid; do
                        [[ -z "$_cid" ]] && continue
                        if podman rm -f "$_cid" >/dev/null 2>&1; then
                            _rm_count=$(( _rm_count + 1 ))
                        fi
                    done <<< "$_ids"
                fi
                _info "(b) Removed ${_rm_count} container(s)"

                # Now volume rm should succeed
                if podman volume rm "$_TEST_VOL" >/dev/null 2>&1; then
                    _pass "(b.post) Volume rm succeeded after force-removing Exited container"
                    # Volume is gone — disarm cleanup trap for volume
                    _TEST_VOL=""
                else
                    _fail "(b.post) Volume rm STILL failed after force-removing Exited container"
                fi

                if [[ "$_rm_count" -ge 1 ]]; then
                    _pass "(b.rm) At least one container was found and removed by label filter"
                else
                    _fail "(b.rm) No containers found by label filter — belt-and-braces may not enumerate correctly"
                fi
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed.\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped.\n" "$PASS" "$SKIP"
exit 0
