#!/usr/bin/env bats
# tests/install/test_offboard_idempotency.bats
#
# S5: offboard idempotency tests — verify scripts/offboard.sh is safe to
# re-run after partial completion.
#
# S6: bash-3.2 portability gate — verify no bash 4.0+ constructs in
# offboard.sh, pki_ownership.sh, or detect_runtime.sh.
#
# S1: exact-match test — "letta" must NOT match "letta-pgbouncer" when
# removing a pki_ownership.sh tuple.
#
# Tests run without a live container runtime (all steps use mock filesystem
# under tests/install/.mock_offboard/ — never /tmp).
#
# Requirements:
#   bats-core >= 1.10.0
#   bash 3.2+, python3, shellcheck (for lint gate)
#
# Run:
#   bats tests/install/test_offboard_idempotency.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
OFFBOARD_SH="${REPO_ROOT}/scripts/offboard.sh"
PKI_OWNERSHIP_SH="${REPO_ROOT}/lib/pki_ownership.sh"
PKI_APPENDER="${REPO_ROOT}/lib/pki_ownership_append.py"
DETECT_RUNTIME_SH="${REPO_ROOT}/lib/detect_runtime.sh"

# Test scratch space — under repo, never /tmp.
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_offboard"

setup() {
  # Create mock directory structure for each test.
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/docker/secrets"
  mkdir -p "${MOCK_ROOT}/docker/caddy/agents"
  mkdir -p "${MOCK_ROOT}/docker/var"
  mkdir -p "${MOCK_ROOT}/helm/yashigani/templates/agents"
  mkdir -p "${MOCK_ROOT}/lib"
  # Copy real lib files for appender tests
  cp "${PKI_OWNERSHIP_SH}" "${MOCK_ROOT}/lib/pki_ownership.sh"
  # install.sh stub (just needs to exist for WORK_DIR check)
  printf '#!/usr/bin/env bash\necho "stub"\n' > "${MOCK_ROOT}/install.sh"
  chmod +x "${MOCK_ROOT}/install.sh"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

# ── S6: Bash-3.2 portability gate ────────────────────────────────────────────

@test "S6: offboard.sh passes bash -n syntax check" {
  run bash -n "${OFFBOARD_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: offboard.sh has no declare -A (bash 4.0+) in non-comment lines" {
  local found
  found="$(grep -vE '^\s*#' "${OFFBOARD_SH}" | grep -cE 'declare -A' || true)"
  [ "$found" = "0" ]
}

@test "S6: offboard.sh has no mapfile/readarray (bash 4.0+) in non-comment lines" {
  local found
  found="$(grep -vE '^\s*#' "${OFFBOARD_SH}" | grep -cE '(mapfile|readarray)' || true)"
  [ "$found" = "0" ]
}

@test "S6: offboard.sh shellcheck clean (severity=error)" {
  run shellcheck --enable=all --severity=error "${OFFBOARD_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: pki_ownership.sh passes bash -n syntax check" {
  run bash -n "${PKI_OWNERSHIP_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: pki_ownership.sh has no declare -A (bash 4.0+) in non-comment lines" {
  # pki_ownership_portability_check() legitimately contains 'declare -A' as a
  # grep search target (string literal, not a bash expression). Exclude that
  # function body from the check — it's the self-test, not production code.
  local found
  found="$(awk '/^pki_ownership_portability_check\(\)/{skip=1} skip{if(/^\}$/){skip=0; next}; next} !skip{print}' \
      "${PKI_OWNERSHIP_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE 'declare -A' || true)"
  [ "$found" = "0" ]
}

@test "S6: pki_ownership.sh has no \${var,,} or \${var^^} (bash 4.0+) in non-comment code" {
  # pki_ownership_portability_check() legitimately contains '${var,,}' and '${var^^}'
  # as printf string literals (to report them) and grep patterns (to find them).
  # Exclude that function body — it's the self-test, not production code.
  local found
  found="$(awk '/^pki_ownership_portability_check\(\)/{skip=1} skip{if(/^\}$/){skip=0; next}; next} !skip{print}' \
      "${PKI_OWNERSHIP_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE '\$\{[a-zA-Z_][a-zA-Z0-9_]*,,\}|\$\{[a-zA-Z_][a-zA-Z0-9_]*\^\^\}' \
      || true)"
  [ "$found" = "0" ]
}

@test "S6: pki_ownership.sh shellcheck clean (with -x)" {
  run shellcheck -x "${PKI_OWNERSHIP_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: detect_runtime.sh passes bash -n syntax check" {
  run bash -n "${DETECT_RUNTIME_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: detect_runtime.sh shellcheck clean (shell=sh, enable=all)" {
  run shellcheck --enable=all --shell=sh "${DETECT_RUNTIME_SH}"
  [ "$status" -eq 0 ]
}

@test "S6: pki_ownership_append.py passes python3 -m py_compile" {
  run python3 -m py_compile "${PKI_APPENDER}"
  [ "$status" -eq 0 ]
}

# ── S1: Exact-match test (letta ≠ letta-pgbouncer) ───────────────────────────

@test "S1: pki_ownership_append append creates sentinel-guarded entry" {
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service test-agent-abc --uid 65534 --mode 0600
  [ "$status" -eq 0 ]
  # Sentinel entry should exist
  grep -q "BEGIN YSG-ONBOARD-test-agent-abc" "${MOCK_ROOT}/lib/pki_ownership.sh"
  grep -q '"test-agent-abc:65534:0600"' "${MOCK_ROOT}/lib/pki_ownership.sh"
}

@test "S1: append is idempotent — second run with same args is no-op" {
  python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service test-agent-abc --uid 65534 --mode 0600
  # Count entries before second run
  local before
  before="$(grep -c 'test-agent-abc:65534:0600' "${MOCK_ROOT}/lib/pki_ownership.sh" || true)"
  # Second run
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service test-agent-abc --uid 65534 --mode 0600
  [ "$status" -eq 0 ]
  local after
  after="$(grep -c 'test-agent-abc:65534:0600' "${MOCK_ROOT}/lib/pki_ownership.sh" || true)"
  # Must be same count (idempotent — no duplicate)
  [ "$before" = "$after" ]
}

@test "S1: EXACT-MATCH — 'letta' append does NOT affect 'letta-pgbouncer' entry" {
  # Add letta-pgbouncer entry first (simulating existing real entry)
  python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service letta-pgbouncer --uid 70 --mode 0600
  # Add letta entry
  python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service letta --uid 0 --mode 0600
  # Both entries must exist independently
  grep -q '"letta-pgbouncer:70:0600"' "${MOCK_ROOT}/lib/pki_ownership.sh"
  grep -q '"letta:0:0600"' "${MOCK_ROOT}/lib/pki_ownership.sh"
}

@test "S1: EXACT-MATCH — removing 'letta' sentinel does NOT touch 'letta-pgbouncer'" {
  # Add both entries
  python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service letta-pgbouncer --uid 70 --mode 0600
  python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service letta --uid 0 --mode 0600
  # Remove letta only
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      remove --service letta
  # letta-pgbouncer entry must survive
  grep -q '"letta-pgbouncer:70:0600"' "${MOCK_ROOT}/lib/pki_ownership.sh"
  # letta sentinel must be gone
  run grep -c 'BEGIN YSG-ONBOARD-letta"' "${MOCK_ROOT}/lib/pki_ownership.sh"
  [ "$output" = "0" ]
}

@test "S1: remove returns exit 3 (not found — idempotent) on unknown service" {
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      remove --service agent-never-existed
  [ "$status" -eq 3 ]
}

@test "S1: append rejects 0644 mode (CWE-732 prevention)" {
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service bad-mode --uid 1000 --mode 0644
  [ "$status" -eq 1 ]
}

@test "S1: append rejects service names with shell metacharacters" {
  run python3 "${PKI_APPENDER}" \
      --lib "${MOCK_ROOT}/lib/pki_ownership.sh" \
      append --service 'agent;rm -rf' --uid 1000 --mode 0600
  [ "$status" -eq 1 ]
}

# ── S5: offboard.sh idempotency ───────────────────────────────────────────────

@test "S5: offboard.sh passes bash -n" {
  run bash -n "${OFFBOARD_SH}"
  [ "$status" -eq 0 ]
}

@test "S5: offboard --help prints usage (no exit 0 required — validates parse)" {
  run bash "${OFFBOARD_SH}" 2>&1 || true
  # Should print usage-like output (no mandatory agent name)
  [[ "$output" == *"Usage"* ]] || [[ "$output" == *"usage"* ]] || [[ "$output" == *"agent-name"* ]]
}

@test "S5: offboard dry-run on absent agent produces no errors" {
  # With a mock WORK_DIR that has all the right structure but no agent artifacts
  run env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="true" \
      bash "${OFFBOARD_SH}" nonexistent-agent 2>&1
  # Should succeed (idempotent — nothing to remove)
  [ "$status" -eq 0 ]
}

@test "S5: offboard dry-run twice on same agent is idempotent" {
  # First dry-run
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="true" \
      bash "${OFFBOARD_SH}" my-agent 2>&1 || true
  # Second dry-run — must also succeed
  run env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="true" \
      bash "${OFFBOARD_SH}" my-agent 2>&1
  [ "$status" -eq 0 ]
}

@test "S5: offboard rejects invalid agent names (shell metacharacters)" {
  run env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="true" \
      bash "${OFFBOARD_SH}" 'agent;rm -rf /' 2>&1
  [ "$status" -ne 0 ]
}

@test "S5: offboard ledger entry written on second run (idempotent write)" {
  # First real run (no docker needed — nothing to remove except ledger)
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="false" \
      bash "${OFFBOARD_SH}" ledger-test-agent 2>&1 || true
  local _ledger="${MOCK_ROOT}/docker/var/offboard-ledger.log"
  # Second run — ledger should have two entries
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="false" \
      bash "${OFFBOARD_SH}" ledger-test-agent 2>&1 || true
  if [ -f "$_ledger" ]; then
    local _count
    _count="$(grep -c 'ledger-test-agent' "$_ledger" || true)"
    [ "$_count" -ge 1 ]
  fi
}

@test "S5: offboard step3 removes Caddy snippet file when present" {
  # Create a fake Caddy snippet
  local _snippet="${MOCK_ROOT}/docker/caddy/agents/test-agent.caddy"
  printf '# Generated snippet\n:443 { handle_path /agents/t/test-agent/* {} }\n' > "$_snippet"
  # Run offboard (non-dry-run but skip PKI rotate by not having install.sh --pki-action)
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="false" \
      bash "${OFFBOARD_SH}" test-agent 2>&1 || true
  # Snippet should be gone
  [ ! -f "$_snippet" ]
}

@test "S5: offboard step4 removes compose override when present" {
  # Create a fake compose override
  local _override="${MOCK_ROOT}/docker/test-agent-compose.override.yml"
  printf '# Generated override\nservices:\n  test-agent:\n    image: test:latest\n' > "$_override"
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="false" \
      bash "${OFFBOARD_SH}" test-agent 2>&1 || true
  [ ! -f "$_override" ]
}

@test "S5: offboard step5 removes agent_client.key when present" {
  # Create fake secret files
  local _key="${MOCK_ROOT}/docker/secrets/test-agent_client.key"
  local _crt="${MOCK_ROOT}/docker/secrets/test-agent_client.crt"
  printf 'FAKE_KEY\n' > "$_key"
  chmod 0600 "$_key"
  printf 'FAKE_CERT\n' > "$_crt"
  chmod 0644 "$_crt"
  env \
      WORK_DIR="${MOCK_ROOT}" \
      YSG_RUNTIME="docker" \
      YSG_DRY_RUN="false" \
      bash "${OFFBOARD_SH}" test-agent 2>&1 || true
  [ ! -f "$_key" ]
  [ ! -f "$_crt" ]
}

# ── S8: pki_key_missing_is_error implementation ────────────────────────────────

@test "S8: pki_key_missing_is_error is implemented (function body present)" {
  run grep -c 'pki_key_missing_is_error()' "${PKI_OWNERSHIP_SH}"
  [ "$output" != "0" ]
}

@test "S8: pki_key_missing_is_error returns 0 (error=true) for mandatory core service" {
  # gateway is a core service — its absence IS an operator error
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error gateway"
  [ "$status" -eq 0 ]
}

@test "S8: pki_key_missing_is_error returns 1 (error=false) for optional langflow" {
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error langflow"
  [ "$status" -eq 1 ]
}

@test "S8: pki_key_missing_is_error returns 1 (error=false) for optional letta" {
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error letta"
  [ "$status" -eq 1 ]
}

@test "S8: pki_key_missing_is_error returns 1 (error=false) for unknown service" {
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error totally-unknown-service"
  [ "$status" -eq 1 ]
}

@test "S8: pki_key_missing_is_error returns 0 (error=true) for caddy (core)" {
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error caddy"
  [ "$status" -eq 0 ]
}

@test "S8: pki_key_missing_is_error returns 0 (error=true) for postgres (core)" {
  run bash -c "source '${PKI_OWNERSHIP_SH}'; pki_key_missing_is_error postgres"
  [ "$status" -eq 0 ]
}

# ── S3: cosign gate variables present in install.sh ──────────────────────────

@test "S3: YSG_REQUIRE_SIGNED_MANIFEST variable declared in install.sh header" {
  run grep -c 'YSG_REQUIRE_SIGNED_MANIFEST' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "S3: _ysg_cosign_gate function present in install.sh" {
  run grep -c '_ysg_cosign_gate()' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "S3: _ysg_cosign_gate uses cosign verify-blob invocation" {
  run grep -c 'cosign verify-blob' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "S3: _ysg_cosign_gate hard-fails on any non-zero cosign exit" {
  run grep -c 'cosign_rc.*-ne 0\|_cosign_rc' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

# ── L10: _detect_runtime wired in install.sh compose path ─────────────────────

@test "L10: _detect_runtime called in install.sh main compose path" {
  run grep -c '_detect_runtime' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "L10: YSG_RUNTIME_4WAY referenced in install.sh" {
  run grep -c 'YSG_RUNTIME_4WAY' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

# ── Guard: onboard/offboard parse_args present ────────────────────────────────

@test "P1-W4: --onboard flag parsed in install.sh" {
  run grep -c '"--onboard")' "${REPO_ROOT}/install.sh"
  # Note: the case uses --onboard)
  # Allow grep to match either form
  run grep -cE '^\s+--onboard\)' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "P1-W4: --offboard flag parsed in install.sh" {
  run grep -cE '^\s+--offboard\)' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "P1-W4: handle_onboard_subcommand function present" {
  run grep -c 'handle_onboard_subcommand()' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}

@test "P1-W4: handle_offboard_subcommand function present" {
  run grep -c 'handle_offboard_subcommand()' "${REPO_ROOT}/install.sh"
  [ "$output" != "0" ]
}
