#!/usr/bin/env bats
# tests/install/test_agent_dup_registration_guard.bats
#
# FIND-IRIS-DUP-AGENT (batch-fix 2026-08-04) — install.sh-side seam.
#
# Seam contract (documented in install.sh's register_agent_bundles() header):
#   - Tom (fix/v412-batch-product-20260804) owns the actual registry
#     idempotency fix inside yashigani.agents.{registry,durable_store,
#     reconciler} — making the container-side skip decision race-proof
#     against a just-wiped Redis (agent:index:all is non-persistent —
#     `appendonly no`/`save ""`).
#   - Su (this branch) owns: (1) a belt-and-braces PRE-CHECK against durable
#     Postgres directly, so a profile already durably registered is never
#     even offered to the container-side registration step; (2) never
#     silently overwriting an existing host-side token file when the
#     container-side step unexpectedly still returns OK for an
#     already-known name.
#
# This test proves the BASH-SIDE logic in isolation (no live Postgres/Redis/
# backoffice needed): the pre-check skip decision, and the token-file
# clobber-guard. It does not re-test Tom's Python-side fix (out of scope /
# different repo area — owned there).
#
# Run: bats tests/install/test_agent_dup_registration_guard.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_agent_dup"

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

_extract_fn() {
  awk '
    $0 == "register_agent_bundles() {" { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}"
}

# ---------------------------------------------------------------------------
# G-SYNTAX
# ---------------------------------------------------------------------------

@test "G-SYNTAX: install.sh passes bash -n" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "G-SYNTAX: pre-check queries durable agent_registry (not just the fast Redis layer)" {
  local count
  count="$(_extract_fn | grep -c 'FROM agent_registry' || true)"
  [ "${count:-0}" -ge 1 ]
}

@test "G-SYNTAX: skip decision references the pre-check membership string before appending to agents_json" {
  local count
  count="$(_extract_fn | grep -c '"\$_ysg_agent_pre_existing" == \*",\${_name},"\*' || true)"
  [ "${count:-0}" -ge 1 ]
}

@test "G-SYNTAX: pre-check is bash-3.2-safe (no declare -A / local -A associative array)" {
  # scripts/test-installer.sh's own portability gate only greps for
  # "declare -A" and would miss "local -A" — belt-and-braces check both
  # spellings here so this specific fix never regresses that blind spot.
  local count
  count="$(_extract_fn | grep -vE '^\s*#' | grep -cE '\b(declare|local)\s+-A\b' || true)"
  [ "${count:-0}" -eq 0 ]
}

@test "G-PORTABILITY: install.sh parses cleanly under real bash 3.2 (/bin/bash on macOS)" {
  [ -x /bin/bash ] || skip "no /bin/bash on this host"
  run /bin/bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "G-SYNTAX: token-write path never blindly clobbers an existing non-empty token file" {
  local count
  count="$(_extract_fn | grep -c -- '-s "\${secrets_dir}/\${_profile}_token"' || true)"
  [ "${count:-0}" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-LOGIC — isolated reproduction of the two decision points this fix adds
# ---------------------------------------------------------------------------

@test "G-LOGIC: a name present in the pre-existing membership string is skipped, never added to agents_json" {
  run /bin/bash -c '
    set -euo pipefail
    log_info() { echo "INFO: $1"; }
    _ysg_agent_pre_existing=",agent__langflow,"
    agents_json="["
    first=true
    for pair in "langflow:agent__langflow" "letta:letta"; do
      _profile="${pair%%:*}"; _name="${pair#*:}"
      if [[ "$_ysg_agent_pre_existing" == *",${_name},"* ]]; then
        log_info "  ${_name}: already registered (durable Postgres) — skipping (FIND-IRIS-DUP-AGENT guard)"
        continue
      fi
      $first || agents_json+=","
      agents_json+="{\"name\":\"${_name}\"}"
      first=false
    done
    agents_json+="]"
    echo "$agents_json"
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *"already registered (durable Postgres)"* ]]
  # letta (not pre-existing) must still be offered; langflow must NOT appear
  # in the final agents_json line specifically (the log line legitimately
  # mentions the skipped name — check the JSON payload, not the whole output).
  local json_line
  json_line="$(printf '%s\n' "$output" | tail -1)"
  [[ "$json_line" == *'"name":"letta"'* ]]
  [[ "$json_line" != *"agent__langflow"* ]]
}

@test "G-LOGIC: the same membership-string logic runs correctly under real bash 3.2" {
  [ -x /bin/bash ] || skip "no /bin/bash on this host"
  run /bin/bash -c '
    _ysg_agent_pre_existing=",agent__langflow,"
    if [[ "$_ysg_agent_pre_existing" == *",agent__langflow,"* ]]; then echo MATCH; fi
    if [[ "$_ysg_agent_pre_existing" == *",letta,"* ]]; then echo "SHOULD NOT MATCH"; fi
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *"MATCH"* ]]
  [[ "$output" != *"SHOULD NOT MATCH"* ]]
}

@test "G-LOGIC: OK for an already-known name backs up the old token instead of overwriting it silently" {
  local secrets_dir="${MOCK_ROOT}/secrets"
  mkdir -p "$secrets_dir"
  printf 'OLD_TOKEN_VALUE' > "${secrets_dir}/langflow_token"
  chmod 0640 "${secrets_dir}/langflow_token"

  run bash -c "
    set -euo pipefail
    log_error() { echo \"ERROR: \$1\"; }
    secrets_dir='${secrets_dir}'
    _profile=langflow
    _agent_name=agent__langflow
    _token=NEW_TOKEN_VALUE
    if [[ -s \"\${secrets_dir}/\${_profile}_token\" ]]; then
      _dup_backup=\"\${secrets_dir}/\${_profile}_token.dup-\$(date -u +%Y%m%dT%H%M%SZ)\"
      if cp -p \"\${secrets_dir}/\${_profile}_token\" \"\${_dup_backup}\" 2>/dev/null; then
        chmod 0640 \"\${_dup_backup}\" 2>/dev/null || true
        log_error \"FIND-IRIS-DUP-AGENT: \${_agent_name} was registered AGAIN (new agent_id, new token) while a prior token file already existed. Old token preserved at \${_dup_backup}\"
      fi
    fi
    echo \"\$_token\" > \"\${secrets_dir}/\${_profile}_token\"
    ls \"\${secrets_dir}\"
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"FIND-IRIS-DUP-AGENT"* ]]
  [[ "$output" == *"Old token preserved at"* ]]
  # A .dup-<timestamp> backup file must exist alongside the (now-overwritten) live file.
  run bash -c "ls '${secrets_dir}' | grep -c '\.dup-'"
  [ "$status" -eq 0 ]
  [ "$output" -ge 1 ]
  # The backup must contain the ORIGINAL value, not the new one.
  run bash -c "cat '${secrets_dir}'/*.dup-* "
  [[ "$output" == "OLD_TOKEN_VALUE" ]]
  # The live file now holds the new value (overwrite still happens — this is
  # a visibility/backup fix, not a "refuse to register" fix).
  run cat "${secrets_dir}/langflow_token"
  [ "$output" = "NEW_TOKEN_VALUE" ]
}

@test "G-LOGIC: no pre-existing token file and no pre-check hit => no backup noise on a genuinely fresh registration" {
  local secrets_dir="${MOCK_ROOT}/secrets2"
  mkdir -p "$secrets_dir"
  run bash -c "
    set -euo pipefail
    log_error() { echo \"ERROR: \$1\"; }
    _ysg_agent_pre_existing=','
    secrets_dir='${secrets_dir}'
    _profile=langflow
    _agent_name=agent__langflow
    _token=FRESH_TOKEN
    if [[ -s \"\${secrets_dir}/\${_profile}_token\" ]]; then
      echo 'UNEXPECTED backup path taken'
    elif [[ \"\$_ysg_agent_pre_existing\" == *\",\${_agent_name},\"* ]]; then
      echo 'UNEXPECTED pre-existing hit'
    fi
    echo \"\$_token\" > \"\${secrets_dir}/\${_profile}_token\"
  "
  [ "$status" -eq 0 ]
  [[ "$output" != *"UNEXPECTED"* ]]
}
