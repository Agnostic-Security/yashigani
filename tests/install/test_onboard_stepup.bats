#!/usr/bin/env bats
# tests/install/test_onboard_stepup.bats
#
# P1 W6 — Step-up gate tests for install.sh --onboard / --offboard
#
# Test matrix:
#   G-SYNTAX    bash -n + shellcheck; gate function present
#   G-SECRETS   CWE-214: read -s, --data @file, 0600 tmpfiles, no /tmp
#   G-GATE-COND gate is CONDITIONAL on _is_installed_or_running (FIX-2)
#   G-ABORT     gate failure blocks execution with || exit 1
#   G-ORDER     WORK_DIR before gate; gate before cosign in onboard
#   G-ENDPT     HTTPS + --cacert; reads docker/.env; both /auth/login + /auth/stepup
#   G-SYMMETRY  single function reused by onboard + offboard
#   G-AUDIT     gate emits audit log line with username + ISO-8601 timestamp
#   G-FUNC      gate returns non-zero: CA absent; TOTP invalid; conn refused; tmpdir cleaned up
#   G-TOTP2     FIX-1: login and stepup bodies carry DISTINCT totp_code fields
#   G-RESIDUAL  FIX-2: auth gate uses residuals-based check, not running-state-only check
#   G-CACERT    FIX-3: SIEM sink curl and healthz polls use --cacert (no --insecure/-k)
#
# All static tests are offline. G-FUNC uses a minimal subshell harness.
#
# IMPORTANT: G-TOTP2 asserts static serialisation correctness (distinct fields).
# The live login→stepup interaction (Postgres replay-cache rejection of reused
# codes) requires a running backoffice and is verified during VM smoke before tag.
#
# Requirements: bats-core >= 1.10.0, bash, python3, shellcheck
# Run: bats tests/install/test_onboard_stepup.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_stepup"
EXTRACT_PY="${REPO_ROOT}/tests/install/extract_gate_fragment.py"

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/docker/secrets"
  printf '# mock CA cert\n' > "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  chmod 0644 "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  printf 'YASHIGANI_HTTPS_PORT=19443\n' > "${MOCK_ROOT}/docker/.env"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

# ---------------------------------------------------------------------------
# G-SYNTAX
# ---------------------------------------------------------------------------

@test "G-SYNTAX: install.sh passes bash -n" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "G-SYNTAX: no new shellcheck findings beyond pre-existing SC2188" {
  # Extract only the SC<code> identifiers from the shellcheck output, then
  # filter out the known pre-existing SC2188.  Any remaining SC codes indicate
  # new findings introduced by this branch.
  local findings
  findings="$(shellcheck --enable=all --severity=warning "${INSTALL_SH}" 2>&1 \
      | grep -oE 'SC[0-9]+' \
      | grep -v 'SC2188' \
      || true)"
  [ -z "$findings" ]
}

@test "G-SYNTAX: _ysg_onboard_stepup_gate function defined exactly once" {
  run grep -c '^_ysg_onboard_stepup_gate()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "G-SYNTAX: _gate_cleanup helper defined inside gate function" {
  run grep -c '_gate_cleanup()' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-SECRETS
# ---------------------------------------------------------------------------

@test "G-SECRETS: read -s used at least three times (password + login TOTP + step-up TOTP)" {
  # FIX-1: three silent reads required — password, login TOTP, stepup TOTP
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'read -r?s' || true)"
  [ "$count" -ge 3 ]
}

@test "G-SECRETS: curl uses --data @file not inline credentials on command line" {
  local bad good
  bad="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE -- "--data '\{" || true)"
  [ "$bad" -eq 0 ]
  good="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c -- '--data "@' || true)"
  [ "$good" -ge 1 ]
}

@test "G-SECRETS: credential tmpfiles created with 0600 mode (CWE-732)" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '0o600' || true)"
  [ "$count" -ge 1 ]
}

@test "G-SECRETS: tmpdir is under WORK_DIR, not /tmp (filesystem guardrail)" {
  local in_workdir in_tmp
  in_workdir="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'WORK_DIR.*ysg-gate' || true)"
  [ "$in_workdir" -ge 1 ]
  in_tmp="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'mktemp.*/tmp' || true)"
  [ "$in_tmp" -eq 0 ]
}

@test "G-SECRETS: RETURN trap registered to clean up secrets on all exit paths" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'trap.*RETURN' || true)"
  [ "$count" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-GATE-COND: gate is conditional on _is_installed_or_running (FIX-2)
# ---------------------------------------------------------------------------

@test "G-GATE-COND: onboard auth gate guarded by _is_installed_or_running (not running-state-only check)" {
  # FIX-2: the auth gate must use the residuals-based check, not
  # _is_existing_yashigani_running (which is bypassed by cert removal or
  # stopped containers — Laura F1/F2).
  local onboard_start
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  local guard_line gate_call_line
  guard_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_is_installed_or_running' | head -1 | cut -d: -f1)"
  gate_call_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$guard_line" ]
  [ -n "$gate_call_line" ]
  [ "$gate_call_line" -gt "$guard_line" ]
}

@test "G-GATE-COND: offboard auth gate guarded by _is_installed_or_running (not running-state-only check)" {
  local offboard_start guard_line gate_call_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  guard_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_is_installed_or_running' | head -1 | cut -d: -f1)"
  gate_call_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$guard_line" ]
  [ -n "$gate_call_line" ]
  [ "$gate_call_line" -gt "$guard_line" ]
}

@test "G-GATE-COND: _is_installed_or_running function defined" {
  run grep -c '^_is_installed_or_running()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "G-GATE-COND: _is_existing_yashigani_running still defined (used by preflight port check)" {
  run grep -c '^_is_existing_yashigani_running()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

# ---------------------------------------------------------------------------
# G-ABORT: gate failure blocks execution
# ---------------------------------------------------------------------------

@test "G-ABORT: onboard gate failure aborts with || exit 1" {
  local onboard_start handler_body
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  handler_body="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}')"
  printf '%s' "$handler_body" | grep -q '_ysg_onboard_stepup_gate.*||.*exit 1'
}

@test "G-ABORT: offboard gate failure aborts with || exit 1" {
  local offboard_start handler_body
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  handler_body="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}')"
  printf '%s' "$handler_body" | grep -q '_ysg_onboard_stepup_gate.*||.*exit 1'
}

# ---------------------------------------------------------------------------
# G-ORDER: ordering within handlers
# ---------------------------------------------------------------------------

@test "G-ORDER: WORK_DIR resolved before step-up gate in onboard handler" {
  local onboard_start detect_line gate_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  detect_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n 'detect_working_directory' | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$detect_line" ]
  [ -n "$gate_line" ]
  [ "$detect_line" -lt "$gate_line" ]
}

@test "G-ORDER: step-up gate before cosign gate in onboard handler" {
  local onboard_start gate_line cosign_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  cosign_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_cosign_gate' | head -1 | cut -d: -f1)"
  [ -n "$gate_line" ]
  [ -n "$cosign_line" ]
  [ "$gate_line" -lt "$cosign_line" ]
}

@test "G-ORDER: WORK_DIR resolved before step-up gate in offboard handler" {
  local offboard_start detect_line gate_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  detect_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n 'detect_working_directory' | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$detect_line" ]
  [ -n "$gate_line" ]
  [ "$detect_line" -lt "$gate_line" ]
}

# ---------------------------------------------------------------------------
# G-ENDPT
# ---------------------------------------------------------------------------

@test "G-ENDPT: gate reads YASHIGANI_HTTPS_PORT from docker/.env" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'docker/.env' || true)"
  [ "$count" -ge 1 ]
}

@test "G-ENDPT: gate connects via https:// not plain http://" {
  local https_count http_count
  https_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'https://localhost' || true)"
  [ "$https_count" -ge 1 ]
  http_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'http://localhost' || true)"
  [ "$http_count" -eq 0 ]
}

@test "G-ENDPT: gate uses --cacert, never --insecure" {
  local cacert_count insecure_count
  cacert_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c -- '--cacert' || true)"
  [ "$cacert_count" -ge 1 ]
  # Check non-comment lines only (skip lines starting with optional whitespace + #)
  insecure_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE -- '--insecure| -k | -k$' || true)"
  [ "$insecure_count" -eq 0 ]
}

@test "G-ENDPT: gate calls /auth/login AND /auth/stepup" {
  local login_c stepup_c
  login_c="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '/auth/login' || true)"
  stepup_c="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '/auth/stepup' || true)"
  [ "$login_c" -ge 1 ]
  [ "$stepup_c" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-SYMMETRY
# ---------------------------------------------------------------------------

@test "G-SYMMETRY: offboard gate call uses label 'offboard'" {
  local offboard_start call_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  call_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}' \
      | grep '_ysg_onboard_stepup_gate' || true)"
  printf '%s' "$call_line" | grep -q '"offboard"'
}

@test "G-SYMMETRY: onboard gate call uses label 'onboard'" {
  local onboard_start call_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  call_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}' \
      | grep '_ysg_onboard_stepup_gate' || true)"
  printf '%s' "$call_line" | grep -q '"onboard"'
}

# ---------------------------------------------------------------------------
# G-AUDIT
# ---------------------------------------------------------------------------

@test "G-AUDIT: gate emits audit log with operator identity on success path" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'step-up gate passed for user' || true)"
  [ "$count" -ge 1 ]
}

@test "G-AUDIT: gate emits ISO-8601 timestamp on success path" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'date -u.*%Y-%m-%dT' || true)"
  [ "$count" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-FUNC: runtime unit tests via subshell + extract_gate_fragment.py
# ---------------------------------------------------------------------------

@test "G-FUNC: gate returns non-zero when ca_root.crt is absent" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard'
" 2>&1
  [ "$status" -ne 0 ]
}

@test "G-FUNC: gate error message mentions ca_root.crt when cert absent" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard' 2>&1 || true
" 2>&1
  [[ "$output" == *"CA cert"* ]] || [[ "$output" == *"ca_root.crt"* ]]
}

@test "G-FUNC: tmpdir cleaned up after gate failure (no .ysg-gate-* residual)" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard' 2>/dev/null || true
" 2>/dev/null || true
  local residual
  residual="$(find "${MOCK_ROOT}/docker" -maxdepth 1 -name '.ysg-gate-*' -type d 2>/dev/null | wc -l | tr -d ' ')"
  [ "$residual" -eq 0 ]
}

@test "G-FUNC: gate returns non-zero when backoffice unreachable (conn refused)" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  # Port 19998 should not be listening in any test environment
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
YASHIGANI_HTTPS_PORT=19998
# Mock read() to inject credentials so we reach the curl call
read() {
  local _v=\"\${!#}\"
  case \"\$_v\" in
    _username)     eval \"\$_v='testadmin'\" ;;
    _password)     eval \"\$_v='testpass123'\" ;;
    _totp)         eval \"\$_v='123456'\" ;;
    _stepup_totp)  eval \"\$_v='654321'\" ;;
    *) true ;;
  esac
}
printf() { true; }
_ysg_onboard_stepup_gate 'onboard' 2>&1
" 2>&1
  [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# G-TOTP2: FIX-1 — login and stepup carry DISTINCT totp_code values
# ---------------------------------------------------------------------------

@test "G-TOTP2: Python serialiser receives 6 argv args (adds stepup_totp)" {
  # The python3 call must pass _stepup_totp as argv[6].
  # The argument appears as "$_stepup_totp" on the python3 shell call line.
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cF '"$_stepup_totp"' || true)"
  [ "$count" -ge 1 ]
}

@test "G-TOTP2: stepup.json body uses stepup_totp variable, not login totp" {
  # The Python heredoc must write stepup_totp (not totp) to the stepup file.
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'stepup_totp' || true)"
  [ "$count" -ge 2 ]   # declaration + serialiser reference
}

@test "G-TOTP2: login.json does not use stepup_totp variable" {
  # The login body must use totp (login code), not stepup_totp.
  # Both are in the same heredoc; check the write sequence.
  local heredoc_fragment
  heredoc_fragment="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | awk '/<<.PYJSON/{f=1} f{print} /^PYJSON$/{f=0}')"
  # login body line must reference totp (not stepup_totp)
  printf '%s' "$heredoc_fragment" | grep '"username"' | grep -q '"totp_code": totp'
  # stepup body line must reference stepup_totp
  printf '%s' "$heredoc_fragment" | grep '"totp_code": stepup_totp' | grep -q 'stepup_totp'
}

@test "G-TOTP2: gate prompts operator for step-up TOTP separately from login TOTP" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'step-up.*window\|NEXT.*window\|next.*window' || true)"
  [ "$count" -ge 1 ]
}

@test "G-TOTP2: _stepup_totp is validated as 6 digits before network call" {
  # The validation block must reference _stepup_totp together with a digit-range check.
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep '_stepup_totp' | grep -c '[0-9].*6\|6.*[0-9]' || true)"
  [ "$count" -ge 1 ]
}

@test "G-TOTP2: _stepup_totp is zeroized on failure paths" {
  # All early-return zeroize calls must include _stepup_totp=""
  local count_with count_without
  # Lines that zeroize _totp must also zeroize _stepup_totp
  count_with="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep '_totp=""' | grep -c '_stepup_totp=""' || true)"
  count_without="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep '_totp=""' | grep -cv '_stepup_totp=""' || true)"
  # All _totp="" lines must also include _stepup_totp=""
  [ "$count_with" -ge 1 ]
  [ "$count_without" -eq 0 ]
}

# ---------------------------------------------------------------------------
# G-RESIDUAL: FIX-2 — _is_installed_or_running residuals-based detection
# ---------------------------------------------------------------------------

@test "G-RESIDUAL: _is_installed_or_running checks compose file presence" {
  local count
  count="$(awk '/^_is_installed_or_running\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'docker-compose.yml' || true)"
  [ "$count" -ge 1 ]
}

@test "G-RESIDUAL: _is_installed_or_running checks secrets dir with find (not ca_root.crt)" {
  # Must check for ANY file in secrets dir, not specifically ca_root.crt.
  # Extract function body using brace-depth tracking.
  local _fn_body
  _fn_body="$(awk '
    /^_is_installed_or_running\(\)/{f=1; d=0}
    f { d += gsub(/{/,"{"); d -= gsub(/}/,"}"); print; if (d <= 0 && f==1) {f=0; exit} }
  ' "${INSTALL_SH}")"

  local find_count ca_only_count
  find_count="$(printf '%s' "$_fn_body" | grep -c '\bfind\b' || true)"
  [ "$find_count" -ge 1 ]

  # No non-comment code line may gate on ca_root.crt specifically.
  # (Comments mentioning it as a counter-example are acceptable.)
  ca_only_count="$(printf '%s' "$_fn_body" \
      | grep -vE '^\s*#' \
      | grep -c 'ca_root\.crt' || true)"
  [ "$ca_only_count" -eq 0 ]
}

@test "G-RESIDUAL: detection-spoof F1 (cert removal) — path returns true with other secrets present" {
  # Simulate F1: ca_root.crt removed but other secrets present.
  # _is_installed_or_running must return 0 (auth gate must fire).
  local fragment
  fragment="$(awk '
    /^_is_installed_or_running\(\)/{f=1}
    f{print}
    f && /^\}$/{f=0; exit}
  ' "${INSTALL_SH}")"

  # Setup: compose file + secrets dir with one file that is NOT ca_root.crt
  mkdir -p "${MOCK_ROOT}/docker/secrets"
  printf 'YASHIGANI_HTTPS_PORT=19443\n' > "${MOCK_ROOT}/docker/.env"
  printf 'mock-compose\n' > "${MOCK_ROOT}/docker/docker-compose.yml"
  printf 'mock-other-secret\n' > "${MOCK_ROOT}/docker/secrets/some_other_secret"
  # ca_root.crt deliberately absent (F1 attack condition)

  run bash -c "
set -euo pipefail
WORK_DIR='${MOCK_ROOT}'
${fragment}
_is_installed_or_running
"
  # Must return 0 (true) — auth gate fires even without ca_root.crt
  [ "$status" -eq 0 ]
}

@test "G-RESIDUAL: detection-spoof F2 (stopped containers) — path returns true when compose present" {
  # Simulate F2: compose file + secrets dir present; no running containers.
  # _is_installed_or_running must return 0 — it doesn't check container state.
  local fragment
  fragment="$(awk '
    /^_is_installed_or_running\(\)/{f=1}
    f{print}
    f && /^\}$/{f=0; exit}
  ' "${INSTALL_SH}")"

  mkdir -p "${MOCK_ROOT}/docker/secrets"
  printf 'mock-compose\n' > "${MOCK_ROOT}/docker/docker-compose.yml"
  printf '# mock ca\n' > "${MOCK_ROOT}/docker/secrets/ca_root.crt"

  run bash -c "
set -euo pipefail
WORK_DIR='${MOCK_ROOT}'
${fragment}
_is_installed_or_running
"
  # Must return 0 regardless of container running state
  [ "$status" -eq 0 ]
}

@test "G-RESIDUAL: fresh-install path — no residuals means gate skipped" {
  # Empty WORK_DIR (no compose file, no secrets) → _is_installed_or_running
  # returns 1 (false) → auth gate not triggered on first install.
  local fragment
  fragment="$(awk '
    /^_is_installed_or_running\(\)/{f=1}
    f{print}
    f && /^\}$/{f=0; exit}
  ' "${INSTALL_SH}")"

  # Empty mock root — no compose file, no secrets
  local fresh_root="${MOCK_ROOT}/fresh"
  mkdir -p "${fresh_root}/docker"

  run bash -c "
set -euo pipefail
WORK_DIR='${fresh_root}'
${fragment}
_is_installed_or_running
"
  # Must return non-zero (false) — fresh install skips the gate
  [ "$status" -ne 0 ]
}

# ---------------------------------------------------------------------------
# G-CACERT: FIX-3 — no --insecure/-k in SIEM sink or healthz curl calls
# ---------------------------------------------------------------------------

@test "G-CACERT: SIEM sink curl uses --cacert not --insecure" {
  # The Wazuh alerts/sinks call carries admin session cookie + wazuh password.
  # -k/--insecure here allows loopback MITM to harvest both (Laura F2/HIGH).
  # The curl is multi-line; check the 8-line block containing alerts/sinks.
  local siem_line cacert_c insecure_c
  siem_line="$(grep -n 'alerts/sinks' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  # Check the surrounding 8-line window for --cacert
  cacert_c="$(awk "NR >= ${siem_line}-6 && NR <= ${siem_line}+2" "${INSTALL_SH}" \
      | grep -c -- '--cacert' || true)"
  [ "$cacert_c" -ge 1 ]
  # Same window must not use --insecure or -k
  insecure_c="$(awk "NR >= ${siem_line}-6 && NR <= ${siem_line}+2" "${INSTALL_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE -- '--insecure| -k | -sk' || true)"
  [ "$insecure_c" -eq 0 ]
}

@test "G-CACERT: healthz/login convergence polls use --cacert or guarded fallback (no bare -sk)" {
  # _verify_gateway_healthz must not use bare curl -sk.
  # Use brace-depth tracking to extract only the function body.
  local bad_count
  bad_count="$(awk '
    /^_verify_gateway_healthz\(\)/{f=1; d=0}
    f {
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      print
      if (d <= 0 && f == 1) { f=0; exit }
    }
  ' "${INSTALL_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE 'curl -sk|curl -s -k' || true)"
  [ "$bad_count" -eq 0 ]
}

@test "G-CACERT: healthz function defines _curl_tls_opt variable for TLS control" {
  local count
  count="$(awk '/^_verify_gateway_healthz\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '_curl_tls_opt' || true)"
  [ "$count" -ge 1 ]
}
