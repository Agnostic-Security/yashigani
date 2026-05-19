#!/usr/bin/env bash
# tests/install/test_agent_reg_totp_window.sh
# Regression test for ISSUE-020: TOTP window collision on stepup during agent
# bundle registration causes all registrations to fail with step_up_required.
#
# Tests (all static/source-level — no Docker daemon required):
#   (1)  TOTP window sleep is present before stepup code generation.
#   (2)  Sleep expression is correct: 30 - (int(time.time()) % 30) with +1 margin.
#   (3)  stepup_code is computed AFTER the sleep (ordering check).
#   (4)  stepup response is read and body is parsed (not just exception-caught).
#   (5)  stepup_verified field is explicitly checked from response body.
#   (6)  Hard-fail on stepup_verified not True (sys.exit(1) path).
#   (7)  Hard-fail on HTTPError from stepup endpoint (sys.exit(1) path).
#   (8)  Hard-fail on any other Exception from stepup (sys.exit(1) path).
#   (9)  "warn-and-continue" pattern is NOT present in the stepup block.
#   (10) Shell captures reg_exit code separately (not || true globally).
#   (11) Shell hard-fails on ERROR:stepup_* in reg_output when reg_exit != 0.
#   (12) Shell does NOT hard-fail on non-zero reg_exit caused by per-agent FAIL.
#       (i.e. partial-success still completes; only stepup hard-fails the function)
#
# Exit codes: 0 = all PASS; 1 = one or more FAIL.
#
# ISSUE-020 close — 2026-05-19
# last-updated: 2026-05-19T00:00:00+01:00

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0
SKIP=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
# shellcheck disable=SC2329  # _skip kept for parity with sibling tests; invoked indirectly
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

# Extract the Python heredoc block for the register_agent_bundles function.
# The block starts after 'python3 -c' and ends with the closing single-quote line.
# We use the presence of known anchor strings to scope the search.
_py_block="$(awk '
    /import json, os, ssl, sys, time, urllib\.request/{in_py=1}
    in_py{print}
    in_py && /^for r in results:/{found_end=1}
    found_end && /^    print\(r\)/{print; in_py=0; found_end=0}
' "$INSTALL_SH" 2>/dev/null)"

# Also capture the shell body of register_agent_bundles for shell-side checks.
_sh_block="$(awk '
    /^register_agent_bundles\(\)/{in_fn=1}
    in_fn{print}
    in_fn && /^}$/{in_fn=0}
' "$INSTALL_SH" 2>/dev/null)"

# ---------------------------------------------------------------------------
# TEST (1): TOTP window sleep is present before stepup code generation
# ---------------------------------------------------------------------------
_section "TEST (1): TOTP window sleep present before stepup"

if echo "$_py_block" | grep -qE '_remaining.*=.*30.*int\(time\.time\(\)\).*%.*30'; then
    _pass "(1.1) _remaining = 30 - (int(time.time()) % 30) expression present"
else
    _fail "(1.1) _remaining window calculation NOT found — ISSUE-020 sleep missing"
fi

if echo "$_py_block" | grep -qE 'time\.sleep\(_remaining'; then
    _pass "(1.2) time.sleep(_remaining ...) call present"
else
    _fail "(1.2) time.sleep(_remaining ...) NOT found — window sleep missing"
fi

# ---------------------------------------------------------------------------
# TEST (2): Sleep margin includes +1 second buffer
# ---------------------------------------------------------------------------
_section "TEST (2): Sleep margin includes +1 second buffer"

if echo "$_py_block" | grep -qE 'time\.sleep\(_remaining\s*\+\s*1\)'; then
    _pass "(2.1) time.sleep(_remaining + 1) — 1 s margin present"
else
    _fail "(2.1) +1 s margin NOT present in sleep call — window boundary risk"
fi

# ---------------------------------------------------------------------------
# TEST (3): stepup_code computed AFTER the sleep
# Order check: sleep line must precede stepup_code = pyotp... line.
# ---------------------------------------------------------------------------
_section "TEST (3): stepup_code computed after sleep (ordering check)"

_sleep_lineno="$(echo "$_py_block" | grep -n 'time\.sleep(_remaining' | head -1 | cut -d: -f1)"
_stepup_code_lineno="$(echo "$_py_block" | grep -n 'stepup_code = pyotp' | head -1 | cut -d: -f1)"

if [[ -n "$_sleep_lineno" && -n "$_stepup_code_lineno" ]]; then
    if (( _stepup_code_lineno > _sleep_lineno )); then
        _pass "(3.1) stepup_code computed at line ${_stepup_code_lineno} (after sleep at line ${_sleep_lineno})"
    else
        _fail "(3.1) stepup_code at line ${_stepup_code_lineno} is BEFORE sleep at line ${_sleep_lineno} — TOTP generated before window shift"
    fi
else
    _fail "(3.1) Could not locate sleep or stepup_code lines for ordering check"
fi

# ---------------------------------------------------------------------------
# TEST (4): stepup response body is read and parsed
# ---------------------------------------------------------------------------
_section "TEST (4): Stepup response body read and parsed"

if echo "$_py_block" | grep -qE 'stepup_resp\s*=\s*urllib\.request\.urlopen'; then
    _pass "(4.1) stepup response assigned to stepup_resp"
else
    _fail "(4.1) stepup response not captured — cannot check body"
fi

if echo "$_py_block" | grep -qE 'stepup_body\s*=\s*json\.loads\(stepup_resp\.read\(\)\)'; then
    _pass "(4.2) stepup_body parsed from JSON response"
else
    _fail "(4.2) stepup_body JSON parse not found — response body unchecked"
fi

# ---------------------------------------------------------------------------
# TEST (5): stepup_verified field explicitly checked
# ---------------------------------------------------------------------------
_section "TEST (5): stepup_verified field checked"

if echo "$_py_block" | grep -qE 'stepup_body\.get\("stepup_verified"\)|stepup_body\["stepup_verified"\]'; then
    _pass "(5.1) stepup_body.get(\"stepup_verified\") check present"
else
    _fail "(5.1) stepup_verified not checked — stepup response status not validated"
fi

# ---------------------------------------------------------------------------
# TEST (6): Hard-fail (sys.exit(1)) when stepup_verified is not True
# ---------------------------------------------------------------------------
_section "TEST (6): Hard-fail on stepup_verified not True"

# Check: if not stepup_body.get("stepup_verified"): ... sys.exit(1)
_not_verified_block="$(echo "$_py_block" | awk '/not stepup_body\.get\("stepup_verified"\)/{found=1} found{print; if (/sys\.exit\(1\)/) exit}')"

if echo "$_not_verified_block" | grep -q 'sys.exit(1)'; then
    _pass "(6.1) sys.exit(1) on stepup_verified False — hard-fail present"
else
    _fail "(6.1) No sys.exit(1) on stepup_verified False — still warn-and-continue"
fi

if echo "$_not_verified_block" | grep -qE 'ERROR:stepup_not_verified|ERROR:stepup'; then
    _pass "(6.2) ERROR:stepup_not_verified emitted to stderr before exit"
else
    _fail "(6.2) No ERROR:stepup... prefix emitted — failure mode not clearly labelled"
fi

# ---------------------------------------------------------------------------
# TEST (7): Hard-fail on HTTPError from stepup
# ---------------------------------------------------------------------------
_section "TEST (7): Hard-fail on HTTPError from stepup endpoint"

_http_error_block="$(echo "$_py_block" | awk '/urllib\.error\.HTTPError as e:/{found=1} found{print; if (/sys\.exit\(1\)/) {exit}}'| head -10)"

if echo "$_http_error_block" | grep -q 'sys.exit(1)'; then
    _pass "(7.1) sys.exit(1) on HTTPError from /auth/stepup"
else
    _fail "(7.1) No sys.exit(1) on HTTPError — stepup HTTP failures silently continue"
fi

if echo "$_http_error_block" | grep -qE 'ERROR:stepup_failed'; then
    _pass "(7.2) ERROR:stepup_failed emitted on HTTPError"
else
    _fail "(7.2) ERROR:stepup_failed not emitted on HTTPError"
fi

# ---------------------------------------------------------------------------
# TEST (8): Hard-fail on general Exception from stepup
# ---------------------------------------------------------------------------
_section "TEST (8): Hard-fail on general Exception from stepup"

# Find the general Exception handler that follows the stepup request block.
# It must appear BEFORE the YSG-AGENT-REG-001 comment (i.e. in the stepup block).
_gen_exc_block="$(echo "$_py_block" | awk '
    /urllib\.error\.HTTPError as e:/{in_http=1}
    in_http && /^except Exception as e:/{in_gen=1; in_http=0}
    in_gen{print; if (/sys\.exit\(1\)/) exit}
' | head -10)"

if echo "$_gen_exc_block" | grep -q 'sys.exit(1)'; then
    _pass "(8.1) sys.exit(1) on general Exception from stepup"
else
    _fail "(8.1) No sys.exit(1) on general Exception from stepup — transport failures continue silently"
fi

# ---------------------------------------------------------------------------
# TEST (9): "warn-and-continue" pattern NOT present in stepup block
# ---------------------------------------------------------------------------
_section "TEST (9): warn-and-continue removed from stepup block"

if echo "$_py_block" | grep -qE 'warn-and-continue|WARNING:stepup_failed'; then
    _fail "(9.1) warn-and-continue pattern or WARNING:stepup_failed still present — ISSUE-020 fix incomplete"
else
    _pass "(9.1) warn-and-continue and WARNING:stepup_failed NOT present in install.sh"
fi

# ---------------------------------------------------------------------------
# TEST (10): Shell captures reg_exit code separately (not || true globally)
# ---------------------------------------------------------------------------
_section "TEST (10): Shell captures reg_exit separately from reg_output"

if echo "$_sh_block" | grep -qE 'local reg_exit\s*=\s*0|reg_exit=0'; then
    _pass "(10.1) reg_exit variable declared/initialised"
else
    _fail "(10.1) reg_exit variable not found — exit code not captured"
fi

if echo "$_sh_block" | grep -qE '\|\|\s*reg_exit=\$\?'; then
    _pass "(10.2) reg_exit=$? captured on non-zero exit from python3"
else
    _fail "(10.2) reg_exit=\$? pattern not found — stepup exit code lost via || true"
fi

# ---------------------------------------------------------------------------
# TEST (11): Shell hard-fails on ERROR:stepup_* when reg_exit != 0
# ---------------------------------------------------------------------------
_section "TEST (11): Shell hard-fails on ERROR:stepup_* with non-zero reg_exit"

if echo "$_sh_block" | grep -qE 'reg_exit.*-ne.*0.*ERROR:stepup|ERROR:stepup.*reg_exit'; then
    _pass "(11.1) Shell checks ERROR:stepup prefix with non-zero reg_exit guard"
else
    # Also accept the two-line guard pattern
    # SC2016: literal $ in grep pattern is intentional (searching source text)
    # shellcheck disable=SC2016
    if echo "$_sh_block" | grep -q 'ERROR:stepup' && echo "$_sh_block" | grep -qE '\$reg_exit.*-ne.*0|\[\[.*reg_exit'; then
        _pass "(11.1) Shell ERROR:stepup check present alongside reg_exit != 0 guard"
    else
        _fail "(11.1) Shell does not gate ERROR:stepup handling on reg_exit — stepup failures may not abort"
    fi
fi

if echo "$_sh_block" | grep -A5 'ERROR:stepup' | grep -qE 'return 1|log_error'; then
    _pass "(11.2) log_error + return 1 on stepup failure — function aborts install"
else
    _fail "(11.2) return 1 not found after ERROR:stepup handling — install may proceed after stepup failure"
fi

# ---------------------------------------------------------------------------
# TEST (12): Per-agent FAIL lines are still handled non-fatally in shell
# The stepup hard-fail is specific; individual agent POST failures should not
# abort the function (other agents may succeed).
# ---------------------------------------------------------------------------
_section "TEST (12): Per-agent FAIL lines handled non-fatally"

if echo "$_sh_block" | grep -qE 'FAIL:\*\)'; then
    _pass "(12.1) FAIL:*) case present in shell parser"
else
    _fail "(12.1) FAIL:*) case missing — per-agent failures not handled"
fi

if echo "$_sh_block" | grep -A3 'FAIL:\*)' | grep -q 'log_warn'; then
    _pass "(12.2) FAIL:*) case uses log_warn (non-fatal) not return 1"
else
    _fail "(12.2) FAIL:*) case does not log_warn — per-agent failure handling incorrect"
fi

# Verify FAIL:*) does NOT contain return 1 (that would abort on per-agent failure).
if echo "$_sh_block" | grep -A5 'FAIL:\*)' | grep -q 'return 1'; then
    _fail "(12.3) FAIL:*) case contains return 1 — aborts on per-agent POST failure (too strict)"
else
    _pass "(12.3) FAIL:*) case does NOT return 1 — individual agent failures non-fatal"
fi

# ---------------------------------------------------------------------------
# TEST (13): ISSUE-023 regression — parse-probe on the python3 -c block
# Wraps the block in a shell function and runs bash -n on the fragment.
# Rationale: bash -n on the whole file gives a false PASS when apostrophes
# inside a python3 -c '...' block accidentally re-balance later in the file
# (ISSUE-023: server's / window's closed the single-quote string at runtime
# but bash -n reported PASS because the file-level delimiter count balanced).
# This test catches the regression in the specific block we own.
# ---------------------------------------------------------------------------
_section "TEST (13): ISSUE-023 regression — bash -n parse-probe on python3 -c block"

_probe_file=""
# shellcheck disable=SC2329  # _probe_cleanup invoked via trap, not inline
_probe_cleanup() { [[ -n "$_probe_file" ]] && rm -f "$_probe_file"; }
trap _probe_cleanup EXIT

# Locate the python3 -c block in install.sh by its anchor lines.
# The opening line ends with: python3 -c '   (bare single-quote, nothing after)
_py_open_lineno="$(grep -nE "[[:space:]]python3[[:space:]]+-c[[:space:]]+'[[:space:]]*$" "${INSTALL_SH}" | cut -d: -f1 | head -1)"
# The closing line starts with: ' 2>&1 (the closing delimiter of the shell single-quoted string)
_py_close_lineno=""
if [[ -n "$_py_open_lineno" ]]; then
    _py_close_lineno="$(awk -v start="${_py_open_lineno}" 'NR > start && /^'"'"' 2>&1/ { print NR; exit }' "${INSTALL_SH}")"
fi

if [[ -z "$_py_open_lineno" || -z "$_py_close_lineno" ]]; then
    _fail "(13.1) Could not locate python3 -c block boundaries — grep anchors need updating"
else
    _info "(13.1) python3 -c block located at L${_py_open_lineno}-L${_py_close_lineno}"

    _probe_file="$(mktemp "${REPO_ROOT}/tests/install/parse_probe_issue023_XXXXXX.sh")"
    _ctx_start=$(( _py_open_lineno > 2 ? _py_open_lineno - 2 : 1 ))
    _ctx_end=$(( _py_close_lineno + 2 ))

    {
        printf '#!/usr/bin/env bash\n'
        printf '_parse_probe_fn() {\n'
        sed -n "${_ctx_start},${_ctx_end}p" "${INSTALL_SH}"
        printf '\n}\n'
    } > "$_probe_file"

    _parse_out="$(bash -n "$_probe_file" 2>&1)"
    _parse_rc=$?
    if [[ $_parse_rc -eq 0 ]]; then
        _pass "(13.1) bash -n parse-probe on register_agent_bundles python3 -c block PASS (ISSUE-023 not regressed)"
    else
        _fail "(13.1) bash -n parse-probe FAIL on python3 -c block — ISSUE-023 apostrophe regression detected: ${_parse_out}"
    fi

    # Also verify the block body contains no apostrophes (belt-and-suspenders;
    # complements TEST 1 in test_install_sh_lint.sh which covers all blocks).
    _apos_hits="$(sed -n "$(( _py_open_lineno + 1 )),$(( _py_close_lineno - 1 ))p" "${INSTALL_SH}" | grep -n "'")"
    if [[ -n "$_apos_hits" ]]; then
        _fail "(13.2) Apostrophe(s) found in python3 -c block body — ISSUE-023 regression:"
        while IFS= read -r hit; do
            printf "    %s\n" "$hit" >&2
        done <<< "$_apos_hits"
    else
        _pass "(13.2) No apostrophes in python3 -c block body — ISSUE-023 not regressed"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (ISSUE-020 / ISSUE-023)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped. (ISSUE-020 / ISSUE-023)\n" "$PASS" "$SKIP"
exit 0
