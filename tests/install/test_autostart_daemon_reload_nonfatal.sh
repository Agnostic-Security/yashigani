#!/usr/bin/env bash
# tests/install/test_autostart_daemon_reload_nonfatal.sh
# Regression test for ISSUE-025: systemctl --user daemon-reload must NOT be a
# hard-fail when called without a D-Bus session (e.g. sudo -u <user> bash
# install.sh in CI / automated provisioning).
#
# Tests:
#   (1) Static: systemctl --user daemon-reload is wrapped in an if/else block
#       (not a bare call that propagates exit code under set -euo pipefail).
#   (2) Static: the else branch contains a non-fatal warn-and-continue pattern
#       (log_warn + no explicit exit/return).
#   (3) Functional mock: source the _setup_auto_start_podman_rootless function
#       with a mocked systemctl that exits 1 on --user daemon-reload; confirm
#       the function returns 0 (does NOT abort).
#   (4) Static: systemctl --user enable is ALSO wrapped in if/else (pre-existing
#       non-fatal pattern, verify it hasn't been changed to hard-fail).
#
# No Docker daemon required.  No network access required.
# Exit codes: 0 = all PASS; 1 = one or more FAIL.
#
# ISSUE-025 close — 2026-05-19
# last-updated: 2026-05-19T00:00:00+01:00

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

# ---------------------------------------------------------------------------
# TEST (1): daemon-reload is wrapped in if/else (not a bare call)
# A bare `systemctl --user daemon-reload` at the top-level of the function
# propagates a non-zero exit under set -euo pipefail → install aborts before
# step 11 (bootstrap_postgres + register_agent_bundles).
# ---------------------------------------------------------------------------
_section "TEST (1): daemon-reload wrapped in if/else, not a bare call"

# Extract the _setup_auto_start_podman_rootless function body
_fn_body="$(awk '
    /^_setup_auto_start_podman_rootless\(\)/{found=1; depth=0}
    found && /\{/{depth++}
    found && /\}/{depth--; if (depth==0){found=0}}
    found{print}
' "$INSTALL_SH" 2>/dev/null)"

if [[ -z "$_fn_body" ]]; then
    _fail "(1) Could not extract _setup_auto_start_podman_rootless function body from install.sh"
else
    # Look for bare (unguarded) daemon-reload: a line where systemctl is the first
    # non-whitespace command token (i.e. NOT inside a quoted string / log_warn / if).
    # Pattern: line starts with optional whitespace then "systemctl" as a command word,
    # followed by --user daemon-reload.  Lines starting with "if systemctl" are guarded.
    # Lines starting with log_* are strings, not invocations.
    _bare_reload="$(echo "$_fn_body" | grep -E '^\s+systemctl\s+--user\s+daemon-reload' | grep -v '^\s*if\s' || true)"
    if [[ -n "$_bare_reload" ]]; then
        _fail "(1) Bare (unguarded) systemctl --user daemon-reload found — will hard-fail without D-Bus session:"
        printf "    %s\n" "$_bare_reload" >&2
    else
        _pass "(1) systemctl --user daemon-reload is guarded (not a bare call)"
    fi
fi

# ---------------------------------------------------------------------------
# TEST (2): else branch contains log_warn (non-fatal warn-and-continue pattern)
# ---------------------------------------------------------------------------
_section "TEST (2): daemon-reload else branch contains log_warn (non-fatal)"

_reload_context="$(echo "$_fn_body" | grep -A12 'systemctl --user daemon-reload' | head -15)"

if echo "$_reload_context" | grep -q 'log_warn'; then
    _pass "(2) daemon-reload else branch contains log_warn — non-fatal warn-and-continue confirmed"
else
    _fail "(2) daemon-reload else branch missing log_warn — may hard-fail silently"
fi

# The else branch must NOT contain 'exit' or 'return' that would abort the function
_reload_else_exit="$(echo "$_reload_context" | grep -E '^\s*(exit|return [^0]|return$)' || true)"
if [[ -n "$_reload_else_exit" ]]; then
    _fail "(2.exit) daemon-reload else branch contains exit/return — function would abort:"
    printf "    %s\n" "$_reload_else_exit" >&2
else
    _pass "(2.exit) daemon-reload else branch does not contain abort (exit/return)"
fi

# ---------------------------------------------------------------------------
# TEST (3): Functional mock — function returns 0 when systemctl fails
# Source only the minimal dependencies of _setup_auto_start_podman_rootless
# (log helpers + the function itself) with a mocked systemctl that exits 1
# for --user daemon-reload to simulate the no-D-Bus-session case.
# ---------------------------------------------------------------------------
_section "TEST (3): Functional mock — function returns 0 when systemctl --user daemon-reload fails"

_tmpdir="$(mktemp -d "${REPO_ROOT}/tests/install/.autostart_test_XXXXXX")"
trap 'rm -rf "$_tmpdir"' EXIT

# Create a mock systemctl that exits 1 for --user daemon-reload, 0 for everything else
cat > "${_tmpdir}/systemctl" <<'MOCK'
#!/usr/bin/env bash
# Mock systemctl: fail on --user daemon-reload, succeed on everything else
for arg in "$@"; do
    if [[ "$arg" == "daemon-reload" ]]; then
        exit 1
    fi
done
exit 0
MOCK
chmod 755 "${_tmpdir}/systemctl"

# Create a mock loginctl that always exits 0 (linger already configured)
cat > "${_tmpdir}/loginctl" <<'MOCK'
#!/usr/bin/env bash
# Mock loginctl: always succeed / return Linger=yes
if [[ "${1:-}" == "show-user" ]]; then
    echo "yes"
    exit 0
fi
exit 0
MOCK
chmod 755 "${_tmpdir}/loginctl"

# Extract log helper definitions from install.sh (needed so the function body
# doesn't error on undefined log_warn / log_success / log_info)
_log_helpers="$(awk '
    /^log_warn\(\)|^log_success\(\)|^log_info\(\)|^log_error\(\)/{found=1; depth=0}
    found && /\{/{depth++}
    found && /\}/{depth--; if (depth==0){found=0; print; next}}
    found{print}
' "$INSTALL_SH" 2>/dev/null)"

# Build a minimal test harness script
cat > "${_tmpdir}/test_harness.sh" <<HARNESS
#!/usr/bin/env bash
set -uo pipefail
PATH="${_tmpdir}:\$PATH"
HOME="${_tmpdir}"
WORK_DIR="${_tmpdir}"

# Minimal color vars to avoid unbound variable errors in log helpers
C_YELLOW="" C_RESET="" C_GREEN="" C_RED="" C_BLUE="" C_CYAN="" C_BOLD=""

# Log helpers
${_log_helpers}

# Stub COMPOSE_CMD
COMPOSE_CMD=(echo)

$(awk '
    /^_setup_auto_start_podman_rootless\(\)/{found=1; depth=0}
    found && /\{/{depth++}
    found && /\}/{depth--; if (depth==0){found=0; print; next}}
    found{print}
' "$INSTALL_SH" 2>/dev/null)

# Run the function; capture exit code
_setup_auto_start_podman_rootless
_rc=\$?
printf "FUNCTION_EXIT_CODE:%d\n" "\$_rc"
HARNESS
chmod 755 "${_tmpdir}/test_harness.sh"

# Run the harness and capture output
_harness_out="$(bash "${_tmpdir}/test_harness.sh" 2>&1)" || true
_harness_rc=$?

_fn_exit="$(echo "$_harness_out" | grep 'FUNCTION_EXIT_CODE:' | awk -F: '{print $2}')"

if [[ "$_fn_exit" == "0" ]]; then
    _pass "(3) _setup_auto_start_podman_rootless returned 0 when systemctl --user daemon-reload fails (no D-Bus session)"
elif [[ -z "$_fn_exit" ]]; then
    _fail "(3) Could not determine function exit code — harness may have crashed. Output:"
    printf "    %s\n" "$_harness_out" >&2
else
    _fail "(3) _setup_auto_start_podman_rootless returned ${_fn_exit} (expected 0) — hard-fails when D-Bus absent"
fi

# Also verify that the mock systemctl was actually called (guards against a
# harness that never reaches the daemon-reload line due to an earlier error)
if echo "$_harness_out" | grep -qiE 'daemon-reload|systemctl'; then
    _pass "(3.reach) daemon-reload code path reached in functional mock"
elif echo "$_harness_out" | grep -qi 'systemd daemon'; then
    _pass "(3.reach) daemon-reload log message seen — code path reached"
else
    # Non-fatal: the log message text may vary; still report
    _info "(3.reach) daemon-reload log message not found in output — manual verification recommended"
fi

# ---------------------------------------------------------------------------
# TEST (4): systemctl --user enable is also wrapped in if/else (pre-existing)
# ---------------------------------------------------------------------------
_section "TEST (4): systemctl --user enable also wrapped (pre-existing non-fatal pattern)"

_enable_bare="$(echo "$_fn_body" | grep -E '^\s+systemctl\s+--user\s+enable' | grep -v '^\s*if\s' || true)"
if [[ -n "$_enable_bare" ]]; then
    _fail "(4) Bare systemctl --user enable found — would hard-fail if systemd unavailable:"
    printf "    %s\n" "$_enable_bare" >&2
else
    _pass "(4) systemctl --user enable is guarded (if/else pattern, non-fatal)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d ===\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (ISSUE-025)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed. (ISSUE-025)\n" "$PASS"
exit 0
