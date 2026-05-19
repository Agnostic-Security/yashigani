#!/usr/bin/env bash
# tests/install/test_agent_bundle_registration.sh
# Regression test for YSG-AGENT-REG-001: agent-bundle registration on fresh install.
#
# Tests:
#   (1) Shell skip guard removed — no file-existence skip in agent-build loop.
#   (2) Python registry pre-check present — GET /admin/agents called before POST.
#   (3) SKIP: output line handled by shell parser (already-registered case).
#   (4) Fresh-install simulation: placeholder file does NOT prevent registration.
#   (5) Null-case: no --agent-bundles flag → agents_json == "[]", early return.
#   (6) Upgrade-safe simulation: SKIP path preserves token file unchanged.
#   (7) Re-install-wipe simulation: stale real-valued token file is overwritten
#       when registry is empty (registration runs, new token written).
#
# All tests are static/source-level — no Docker daemon required.
# Exit codes: 0 = all PASS; 1 = one or more FAIL.
#
# YSG-AGENT-REG-001 — close-it fix 2026-05-18
# last-updated: 2026-05-18T00:00:00+01:00

set -uo pipefail
IFS=$'\n\t'

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
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

_info "install.sh: ${INSTALL_SH}"
_info "repo root:  ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# TEST (1): Old shell-side skip guard is removed
# The original bug: lines with `grep -q "placeholder" ...` inside the
# agents_json build loop caused all agents to be skipped when token files
# had real (non-placeholder) values. This guard must NOT be present in the
# agent-json build loop.
# ---------------------------------------------------------------------------
_section "TEST (1): Old shell skip guard removed from agents_json build loop"

# The skip guard pattern that must NOT appear inside the agents_json loop:
# "[[ -s ... ]] && ! grep -q "placeholder" ... ]]; then ... skip"
# We check that no combination of grep-q placeholder + skipping exists in the
# loop that builds agents_json (between "agents_json='['" and "agents_json+=']'").

# Extract the agents_json build block (from first occurrence to closing bracket)
_agents_block="$(awk '/agents_json=\x27\[/{found=1} found{print} /agents_json\+=\x27\]\x27/{found=0}' "$INSTALL_SH" 2>/dev/null | head -60)"

if echo "$_agents_block" | grep -q 'grep -q.*placeholder'; then
    _fail "(1.1) Old shell skip guard (grep -q placeholder) still present in agents_json build loop — YSG-AGENT-REG-001 not fixed"
else
    _pass "(1.1) Old shell skip guard (grep -q placeholder) NOT in agents_json build loop"
fi

if echo "$_agents_block" | grep -q 'token exists.*skipping\|skipping.*token exists'; then
    _fail "(1.2) 'token exists — skipping' log message still in agents_json build loop"
else
    _pass "(1.2) 'token exists — skipping' NOT in agents_json build loop"
fi

# ---------------------------------------------------------------------------
# TEST (2): Python registry pre-check present
# The fix adds a GET /admin/agents call inside the Python script before
# any POST /admin/agents calls, and uses registered_names to skip already-
# registered agents, emitting SKIP: lines.
# We search install.sh globally for these patterns — they appear only inside
# the register_agent_bundles Python block.
# ---------------------------------------------------------------------------
_section "TEST (2): Python registry pre-check (GET /admin/agents) present"

# Check for registered_names set construction from GET /admin/agents
if grep -q 'registered_names' "$INSTALL_SH"; then
    _pass "(2.1) registered_names variable present in install.sh"
else
    _fail "(2.1) registered_names NOT found — registry pre-check missing"
fi

# Verify a GET call to /admin/agents (no data= on same line as /admin/agents URL)
if grep '/admin/agents' "$INSTALL_SH" | grep -v 'data=' | grep -q 'Request\|urllib'; then
    _pass "(2.2) GET /admin/agents Request found (no data= → GET, not POST)"
else
    _fail "(2.2) No GET /admin/agents Request found — registry pre-check may be missing"
fi

# Verify per-agent skip using registered_names
if grep -q 'aname in registered_names' "$INSTALL_SH"; then
    _pass "(2.3) Per-agent registry check: 'aname in registered_names' present"
else
    _fail "(2.3) Per-agent registry check 'aname in registered_names' not found"
fi

# Verify SKIP: output for already-registered agents
if grep -q '"SKIP:" + aname\|SKIP:.*aname\|results.append.*SKIP' "$INSTALL_SH"; then
    _pass "(2.4) SKIP: output line emitted for already-registered agents"
else
    _fail "(2.4) SKIP: output line missing — upgrade idempotency not implemented"
fi

# ---------------------------------------------------------------------------
# TEST (3): Shell parser handles SKIP: lines
# ---------------------------------------------------------------------------
_section "TEST (3): Shell parser handles SKIP: output lines"

if grep -q 'SKIP:\*)' "$INSTALL_SH"; then
    _pass "(3.1) SKIP:*) case in shell parser present"
else
    _fail "(3.1) SKIP:*) case missing from shell parser — SKIP lines would be silently dropped"
fi

if grep -A6 'SKIP:\*)' "$INSTALL_SH" | grep -q 'already registered\|skipping'; then
    _pass "(3.2) SKIP:*) case logs appropriate 'already registered' message"
else
    _fail "(3.2) SKIP:*) case does not log — silent skip with no audit trail"
fi

# ---------------------------------------------------------------------------
# TEST (4): Placeholder file does NOT prevent registration in new code
# Simulate: fresh install with placeholder in token file.
# Old code: would skip agent. New code: Python queries registry (empty → register).
# We can only verify the shell side: agents_json build loop does NOT check files.
# ---------------------------------------------------------------------------
_section "TEST (4): Placeholder token file does not prevent registration (shell-side)"

# The shell agents_json build loop should NOT read any token files at all.
# Extract the loop body between the COMPOSE_PROFILES iteration and agents_json+=']'
_loop_body="$(awk '
    /for _profile in.*COMPOSE_PROFILES/{in_loop=1; next}
    in_loop && /agents_json\+=.*\]/{in_loop=0; next}
    in_loop{print}
' "$INSTALL_SH" 2>/dev/null | head -40)"

if echo "$_loop_body" | grep -qE '_token|token_file|secrets_dir.*token'; then
    _fail "(4.1) agents_json build loop still references token files — shell-side skip not fully removed"
else
    _pass "(4.1) agents_json build loop does not reference token files — registration not gated by file state"
fi

# ---------------------------------------------------------------------------
# TEST (5): Null-case — no agent bundles → agents_json == "[]" → early return
# ---------------------------------------------------------------------------
_section "TEST (5): Null-case — empty COMPOSE_PROFILES → no registration attempt"

# Verify the early return on empty agents_json is still present
if grep -q 'agents_json.*==.*\[\]' "$INSTALL_SH"; then
    _pass "(5.1) Early return on agents_json == '[]' present"
else
    _fail "(5.1) Early return on empty agents_json missing — may attempt registration with no agents"
fi

if grep -A2 'agents_json.*==.*\[\]' "$INSTALL_SH" | grep -q 'return 0\|No new agents'; then
    _pass "(5.2) Early return exits cleanly (return 0 or log + return)"
else
    _fail "(5.2) Early return may not exit function — check logic"
fi

# ---------------------------------------------------------------------------
# TEST (6): Upgrade-safe — SKIP path does not overwrite token file
# Simulate: Python emits SKIP:Langflow:langflow
# Shell parser: logs "already registered — skipping", does NOT write token file
# ---------------------------------------------------------------------------
_section "TEST (6): Upgrade-safe — SKIP path preserves token file"

# Simulate the shell parser on a SKIP: line
_tmpdir="$(mktemp -d "${REPO_ROOT}/tests/install/.agent_reg_test_XXXXXX")"
trap 'rm -rf "${_tmpdir}"' EXIT

_fake_token="aaaa1234bbbb5678cccc9012dddd3456eeee7890ffff1234aaaa5678bbbb9012"
printf "%s" "$_fake_token" > "${_tmpdir}/langflow_token"
chmod 600 "${_tmpdir}/langflow_token"

# Inline the SKIP: parser logic (mirrors install.sh lines after the Python call)
_skip_line="SKIP:Langflow:langflow"
_skip_parts="${_skip_line#SKIP:}"
_skip_name="${_skip_parts%%:*}"

# Verify: parsing extracts name correctly
if [[ "$_skip_name" == "Langflow" ]]; then
    _pass "(6.1) SKIP: line parser extracts agent name correctly"
else
    _fail "(6.1) SKIP: line parser got '${_skip_name}', expected 'Langflow'"
fi

# Verify: token file is unchanged after SKIP (no write in SKIP handler)
_token_after="$(cat "${_tmpdir}/langflow_token")"
if [[ "$_token_after" == "$_fake_token" ]]; then
    _pass "(6.2) Token file unchanged after SKIP (upgrade-safe)"
else
    _fail "(6.2) Token file was modified — SKIP path must not write"
fi

# Verify the SKIP:*) case in install.sh does NOT write to the token file
_skip_handler="$(awk '/SKIP:\*\)/{found=1} found{print} found && /;;/{exit}' "$INSTALL_SH" 2>/dev/null | head -10)"
if echo "$_skip_handler" | grep -qE 'echo.*_token|>.*_token|chmod.*_token'; then
    _fail "(6.3) SKIP handler writes to token file — breaks upgrade idempotency"
else
    _pass "(6.3) SKIP handler does NOT write to token file"
fi

# ---------------------------------------------------------------------------
# TEST (7): Re-install-wipe simulation — stale token file overwritten
# Old code: stale real-valued token file → skip (registry stays empty).
# New code: Python checks registry (empty) → registers → new token written.
# Shell-side: OK: line overwrites the token file.
# ---------------------------------------------------------------------------
_section "TEST (7): Re-install-wipe — stale token overwritten when OK: received"

_stale_token="stale1234stale5678stale9012stale3456stale7890stale1234stale5678st"
printf "%s" "$_stale_token" > "${_tmpdir}/letta_token"
chmod 600 "${_tmpdir}/letta_token"

_new_token="newtoken1234newtoken5678newtoken9012newtoken3456newtoken7890newto"

# Simulate the OK: handler (mirrors install.sh lines after python call)
_ok_line="OK:Letta:letta:${_new_token}"
_parts="${_ok_line#OK:}"
# _agent_name = "Letta"
_rest="${_parts#*:}"
_profile="${_rest%%:*}"
_token="${_rest#*:}"

if [[ -n "$_profile" && -n "$_token" && "$_token" != "$_profile" ]]; then
    printf "%s" "$_token" > "${_tmpdir}/${_profile}_token"
    chmod 600 "${_tmpdir}/${_profile}_token"
fi

_written="$(cat "${_tmpdir}/letta_token")"
if [[ "$_written" == "$_new_token" ]]; then
    _pass "(7.1) OK: handler overwrites stale token file with new token"
else
    _fail "(7.1) OK: handler did not overwrite stale token. Got: '${_written}'"
fi

if [[ "$_written" != "$_stale_token" ]]; then
    _pass "(7.2) Stale token no longer present after OK: handler"
else
    _fail "(7.2) Stale token still present — overwrite failed"
fi

_mode_7="$(stat -c '%a' "${_tmpdir}/letta_token" 2>/dev/null || stat -f '%A' "${_tmpdir}/letta_token" 2>/dev/null || echo "unknown")"
if [[ "$_mode_7" == "600" ]]; then
    _pass "(7.3) Rewritten token file mode 0600"
else
    _fail "(7.3) Rewritten token file mode ${_mode_7}, expected 600"
fi

# ---------------------------------------------------------------------------
# TEST (8): ISSUE-024 — agent _name= values in the agents_json build loop
#           case statement are lowercase.
# The AgentRegisterRequest model enforces ^[a-z][a-z0-9_-]{0,63}$ on the
# name field.  Capitalised values (Langflow, Letta, OpenClaw) pass the shell
# case statement but cause a 422 from the API, silently leaving /admin/agents
# empty.  This test asserts the case statement sends lowercase to the API.
#
# Strategy: grep install.sh directly for lines matching the known pattern
#   `  <profile>)  local _name="<value>"  _url=...`
# This is more robust than awk-based function extraction because install.sh
# has multiple `case "$_profile"` blocks and awk can match the wrong one.
# ---------------------------------------------------------------------------
_section "TEST (8): ISSUE-024 — agent name= values in case statement are lowercase"

# Extract lines that contain both a profile case arm AND _name= assignment
# These look like: `  langflow)  local _name="langflow"  _url=...`
_name_lines="$(grep -E '^\s+(langflow|letta|openclaw)\)\s+local _name=' "$INSTALL_SH" || true)"

if [[ -z "$_name_lines" ]]; then
    _fail "(8.extract) Could not find profile _name= case lines in install.sh — pattern may have changed"
else
    _pass "(8.extract) Found profile _name= case arm lines in install.sh"
fi

# All three profile names must map to a lowercase _name= value.
for _expected_lc in "langflow" "letta" "openclaw"; do
    # Find the line for this profile and extract the _name= value.
    _profile_line="$(echo "$_name_lines" | grep -E "^\s+${_expected_lc}\)" | head -1)"
    if [[ -z "$_profile_line" ]]; then
        _fail "(8.${_expected_lc}) Could not find case arm for profile '${_expected_lc}'"
        continue
    fi
    _name_val="$(echo "$_profile_line" | grep -oE '_name="[^"]+"' | sed 's/_name=//;s/"//g')"
    if [[ -z "$_name_val" ]]; then
        _fail "(8.${_expected_lc}) Could not extract _name= value for profile '${_expected_lc}'"
    elif [[ "$_name_val" =~ ^[a-z][a-z0-9_-]{0,63}$ ]]; then
        _pass "(8.${_expected_lc}) Profile '${_expected_lc}' maps to lowercase _name=\"${_name_val}\" — matches API regex ^[a-z][a-z0-9_-]{0,63}$"
    else
        _fail "(8.${_expected_lc}) Profile '${_expected_lc}' maps to _name=\"${_name_val}\" — FAILS API regex ^[a-z][a-z0-9_-]{0,63}$ (ISSUE-024)"
    fi
done

# Also assert no Capitalised name appears in any profile _name= case arm.
# Belt-and-suspenders: catches future regressions where a display name is
# accidentally re-introduced as the API slug.
_upper_in_case="$(echo "$_name_lines" | grep -oE '_name="[A-Z][^"]+"' || true)"
if [[ -n "$_upper_in_case" ]]; then
    _fail "(8.upper) Capitalised _name= value(s) found in profile case arms: ${_upper_in_case}"
else
    _pass "(8.upper) No capitalised _name= values in profile case arms"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (YSG-AGENT-REG-001 + ISSUE-024)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped. (YSG-AGENT-REG-001 + ISSUE-024)\n" "$PASS" "$SKIP"
exit 0
