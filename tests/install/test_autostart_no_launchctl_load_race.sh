#!/usr/bin/env bash
# tests/install/test_autostart_no_launchctl_load_race.sh
# Regression test for FIND-PODMAN-MAC-1 (2026-08-03).
#
# Root cause: _setup_auto_start_macos() called `launchctl load "$plist"`
# immediately after writing a LaunchAgent plist with RunAtLoad=true. On macOS,
# `launchctl load` on a RunAtLoad=true job EXECUTES it immediately — not just
# "registers" it. That fired a second, uncoordinated `<compose> up -d`
# in the background (using a HARDCODED reduced `-f docker-compose.yml` file
# list, dropping the Podman rootless override / macOS virtiofs :U override /
# any enabled overlay), racing the install's own in-flight bring-up. Live
# 3/3 repro on podman-rootless-macOS: ~/.yashigani/logs/autostart-error.log
# showed the LaunchAgent's own podman-compose hitting "container name already
# in use" / "has dependent containers which must be removed before it"
# against the SAME container IDs the primary install flow had just converged
# — gateway received SIGTERM (exit 143) ~5s after going healthy, backoffice's
# replacement container was stuck in "Created", and
# register_agent_bundles()/run_health_check() failed with "could not find a
# running container for service 'gateway'/'backoffice'".
#
# Tests:
#   (1) Static: _setup_auto_start_macos() does NOT call `launchctl load`.
#       macOS launchd auto-loads every plist under ~/Library/LaunchAgents/ at
#       each real login — no explicit load is needed for the documented
#       "start on next login" behaviour, and the explicit load is what fired
#       the RunAtLoad job immediately during install.
#   (2) Static: _setup_auto_start_macos()'s embedded compose invocation uses
#       the shared _ysg_assemble_compose_files() file list (YSG_COMPOSE_FILE_ARGS),
#       not a hardcoded `-f docker-compose.yml` (which drops the Podman
#       rootless/virtiofs overrides and any enabled overlay).
#   (3) Static: all three auto-start unit/plist generators
#       (_setup_auto_start_macos, _setup_auto_start_podman_rootful,
#       _setup_auto_start_podman_rootless) call _ysg_assemble_compose_files
#       before building their ExecStart/ProgramArguments string — same
#       single-source-of-truth contract as compose_up()/register_agent_bundles()
#       (YSG-RISK-177).
#
# No Docker/Podman daemon required. No network access required.
# Exit codes: 0 = all PASS; 1 = one or more FAIL.
#
# FIND-PODMAN-MAC-1 close — 2026-08-03
# last-updated: 2026-08-03T00:00:00+01:00

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

_info "install.sh: ${INSTALL_SH}"
_info "repo root:  ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

_extract_fn() {
    local fn_name="$1"
    awk -v fn="$fn_name" '
        $0 ~ "^" fn "\\(\\)" {found=1; depth=0}
        found && /\{/{depth++}
        found && /\}/{depth--; if (depth==0){found=0; print; next}}
        found{print}
    ' "$INSTALL_SH" 2>/dev/null
}

_macos_body="$(_extract_fn "_setup_auto_start_macos")"
_rootful_body="$(_extract_fn "_setup_auto_start_podman_rootful")"
_rootless_body="$(_extract_fn "_setup_auto_start_podman_rootless")"

if [[ -z "$_macos_body" ]]; then
    _fail "Could not extract _setup_auto_start_macos function body from install.sh"
fi
if [[ -z "$_rootful_body" ]]; then
    _fail "Could not extract _setup_auto_start_podman_rootful function body from install.sh"
fi
if [[ -z "$_rootless_body" ]]; then
    _fail "Could not extract _setup_auto_start_podman_rootless function body from install.sh"
fi

# ---------------------------------------------------------------------------
# TEST (1): _setup_auto_start_macos() must NOT call `launchctl load`
# ---------------------------------------------------------------------------
_section "TEST (1): no launchctl load call in _setup_auto_start_macos()"

if [[ -n "$_macos_body" ]]; then
    # Strip full-line comments (lines whose first non-whitespace char is '#')
    # before searching — this function's own regression comment legitimately
    # mentions 'launchctl load' in prose; only an actual invocation is a FAIL.
    _load_call="$(echo "$_macos_body" | grep -Ev '^[[:space:]]*#' | grep -E '\blaunchctl[[:space:]]+load\b' || true)"
    if [[ -n "$_load_call" ]]; then
        _fail "(1) _setup_auto_start_macos() still calls 'launchctl load' — RunAtLoad=true means this EXECUTES the job immediately, racing the in-flight install (FIND-PODMAN-MAC-1):"
        printf "    %s\n" "$_load_call" >&2
    else
        _pass "(1) _setup_auto_start_macos() does not call 'launchctl load' (plist relies on launchd's automatic per-login load)"
    fi
fi

# ---------------------------------------------------------------------------
# TEST (2): the plist's embedded compose command uses the shared file-list
# variable, not a bare `-f .../docker-compose.yml` with no other -f args.
# ---------------------------------------------------------------------------
_section "TEST (2): LaunchAgent ProgramArguments use the shared compose file list"

if [[ -n "$_macos_body" ]]; then
    _proglist_line="$(echo "$_macos_body" | grep -E 'ProgramArguments|compose_cmd_str.*up -d|<string>.*up -d.*</string>' | grep 'up -d' || true)"
    if echo "$_macos_body" | grep -qE '_autostart_compose_files_str|YSG_COMPOSE_FILE_ARGS'; then
        _pass "(2) macOS LaunchAgent references the shared compose file-list variable"
    else
        _fail "(2) macOS LaunchAgent does not reference _autostart_compose_files_str/YSG_COMPOSE_FILE_ARGS — likely reverted to a hardcoded reduced -f list"
    fi

    # Guard against the specific regressed pattern: a lone `-f ${WORK_DIR}/docker/docker-compose.yml`
    # immediately followed by `up -d` with no other -f flags anywhere in the embedded string.
    if echo "$_macos_body" | grep -qE -- '-f[[:space:]]+\$\{WORK_DIR\}/docker/docker-compose\.yml[[:space:]]+up[[:space:]]+-d'; then
        _fail "(2.regression) macOS LaunchAgent embeds a hardcoded single-file '-f docker-compose.yml ... up -d' — the exact FIND-PODMAN-MAC-1 pattern"
    else
        _pass "(2.regression) macOS LaunchAgent does not embed the hardcoded single-file compose pattern"
    fi
fi

# ---------------------------------------------------------------------------
# TEST (3): all three auto-start generators call _ysg_assemble_compose_files
# before building their embedded compose command (single source of truth).
# ---------------------------------------------------------------------------
_section "TEST (3): all auto-start generators use _ysg_assemble_compose_files()"

_check_assemble_call() {
    local name="$1" body="$2"
    if [[ -z "$body" ]]; then
        _fail "(3.${name}) function body empty — cannot verify"
        return
    fi
    if echo "$body" | grep -q '_ysg_assemble_compose_files'; then
        _pass "(3.${name}) ${name} calls _ysg_assemble_compose_files()"
    else
        _fail "(3.${name}) ${name} does NOT call _ysg_assemble_compose_files() — risks a reduced/drifted file list (same class as YSG-RISK-177)"
    fi
}

_check_assemble_call "_setup_auto_start_macos" "$_macos_body"
_check_assemble_call "_setup_auto_start_podman_rootful" "$_rootful_body"
_check_assemble_call "_setup_auto_start_podman_rootless" "$_rootless_body"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d ===\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (FIND-PODMAN-MAC-1)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed. (FIND-PODMAN-MAC-1)\n" "$PASS"
exit 0
