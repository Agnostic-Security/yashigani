#!/usr/bin/env bats
# tests/install/test_hibp_honest_reporting.bats
#
# Regression tests for the HIBP breach-check finding (dispatch item 2,
# 2026-08-16): `_hibp_check_passwords` printed
#   "HIBP breach check complete — all passwords clean"
# UNCONDITIONALLY at the end, regardless of whether any password was ever
# actually checked. `_hibp_check_single` returns 0 (proceed) both when a
# password is positively confirmed clean via the HIBP API AND when the check
# could not happen at all (no curl, no SHA-1 tool, or the API was
# unreachable — its own comment says "air-gapped, offline, etc." but this
# path is NOT gated on --air-gap/--offline: it also fires on a normal online
# install behind a restrictive corporate egress ring-fence, which is
# ironic given Yashigani's own product is an egress-mediation gateway).
# Both outcomes collapsed to the same "clean" claim.
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - AgnosticSecurity Risk Management/yashigani-risks.md YSG-RISK-034 —
#     DIFFERENT issue (SHA-1 use for HIBP k-Anonymity is protocol-mandated
#     and ACCEPTED, not re-filed here; this fix does not touch the SHA-1
#     hashing algorithm choice at all).
#   - docs/operations/air-gap-install.md "HIBP (Have I Been Pwned) in
#     air-gap mode": `--air-gap` implies `--no-hibp` and is DOCUMENTED as
#     skipping the check with explicit operator rotation guidance. That
#     path (AIR_GAP=true / OFFLINE=true, both return early in
#     _hibp_check_passwords before reaching the false-success line) was
#     already honest and is untouched by this fix. The bug is specifically
#     the online-but-unreachable / tooling-missing path, which had no
#     equivalent honesty.
#
# Fix: `_hibp_check_single` now also sets a side-channel `_HIBP_LAST_STATUS`
# (clean | breached | unchecked-no-curl | unchecked-no-hash-tool |
# unchecked-unreachable) without changing its return-code contract (0=
# proceed, 1=breached — retry loops unchanged). `_hibp_tally_result` folds
# each credential's FINAL status into three run-level counters. The summary
# at the end of `_hibp_check_passwords` reports honestly: all-clean only
# when every credential was positively verified; a WARN naming the count
# when some could not be checked; a WARN naming the count when some
# remained breached after exhausting retries.
#
# Requirements: bats-core >= 1.10, bash 4+.
# Run:
#   bats tests/install/test_hibp_honest_reporting.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── extraction helper — same brace-counting technique used throughout this
# test suite (see test_ysg_risk_202_podman_cdi_fail_closed.bats). ──────────
_extract_fn() {
  local fn="$1"
  awk -v fn="$fn" '
    $0 ~ "^"fn"\\(\\)[ \t]*\\{" { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}"
}

setup() {
  local fn_body
  for fn in _hibp_check_single _hibp_tally_result _hibp_check_passwords _hibp_check_and_regen; do
    fn_body="$(_extract_fn "$fn")"
    [[ -n "$fn_body" ]] || { echo "ERROR: ${fn} not found in install.sh" >&2; return 1; }
    eval "$fn_body"
  done

  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }
  log_success() { printf '[OK] %s\n' "$*" >&2; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/hibp-scratch.XXXXXX")"
  mkdir -p "${SCRATCH}/docker/secrets"
  WORK_DIR="${SCRATCH}"
  YASHIGANI_VERSION="test"
  AIR_GAP="false"
  OFFLINE="false"

  GEN_ADMIN1_USERNAME="admin1"
  GEN_ADMIN2_USERNAME="admin2"
  GEN_ADMIN1_PASSWORD="Adm1nCleanPassw0rd!"
  GEN_ADMIN2_PASSWORD="Adm2nCleanPassw0rd!"
  GEN_POSTGRES_PASSWORD="PostgresCleanPassw0rd!"
  GEN_REDIS_PASSWORD="RedisCleanPassw0rd!"
  GEN_GRAFANA_PASSWORD="GrafanaCleanPassw0rd!"
  printf "%s" "$GEN_ADMIN1_PASSWORD" > "${WORK_DIR}/docker/secrets/admin1_password"
  printf "%s" "$GEN_ADMIN2_PASSWORD" > "${WORK_DIR}/docker/secrets/admin2_password"
  printf "%s" "$GEN_POSTGRES_PASSWORD" > "${WORK_DIR}/docker/secrets/postgres_password"
  printf "%s" "$GEN_REDIS_PASSWORD" > "${WORK_DIR}/docker/secrets/redis_password"
  printf "%s" "$GEN_GRAFANA_PASSWORD" > "${WORK_DIR}/docker/secrets/grafana_admin_password"
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

# ── Lint gate ─────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: the unconditional false-success line is gone" {
  run grep -c 'log_success "HIBP breach check complete — all passwords clean"' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: _hibp_check_single sets _HIBP_LAST_STATUS on the unreachable path" {
  run grep -c '_HIBP_LAST_STATUS="unchecked-unreachable"' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

# ── THE ORIGINAL BUG: API unreachable → must NOT claim "clean" ────────────

@test "THE ORIGINAL BUG: HIBP unreachable for every credential -> honest WARN, never 'all clean'" {
  curl() { printf ''; }  # empty response == unreachable, per _hibp_check_single's own contract
  export -f curl

  run _hibp_check_passwords
  [ "$status" -eq 0 ]
  [[ "$output" != *"all passwords clean"* ]]
  [[ "$output" != *"verified clean"* ]]
  [[ "$output" == *"could not verify 5 of 5"* ]]
  [[ "$output" == *"NOT confirmed clean"* ]]
}

@test "unreachable -> _HIBP_UNCHECKED_COUNT tallies all 5 credentials" {
  curl() { printf ''; }
  export -f curl

  _hibp_check_passwords
  [ "$_HIBP_UNCHECKED_COUNT" -eq 5 ]
  [ "$_HIBP_CLEAN_COUNT" -eq 0 ]
  [ "$_HIBP_BREACHED_COUNT" -eq 0 ]
}

# ── Positive path: reachable + genuinely clean -> honest success ──────────

@test "HIBP reachable, no match in response -> genuinely honest 'verified clean'" {
  # A response with a suffix that will never match any real SHA-1 suffix.
  curl() { printf '0000000000000000000000000000000000:1\r\n'; }
  export -f curl

  run _hibp_check_passwords
  [ "$status" -eq 0 ]
  [[ "$output" == *"verified clean via api.pwnedpasswords.com"* ]]
  [[ "$output" != *"could not verify"* ]]
}

@test "reachable + clean -> _HIBP_CLEAN_COUNT=5, others 0" {
  curl() { printf '0000000000000000000000000000000000:1\r\n'; }
  export -f curl

  _hibp_check_passwords
  [ "$_HIBP_CLEAN_COUNT" -eq 5 ]
  [ "$_HIBP_UNCHECKED_COUNT" -eq 0 ]
  [ "$_HIBP_BREACHED_COUNT" -eq 0 ]
}

# ── Still-breached-after-retries path: must not be reported as clean ──────

@test "credential remains breached after max_retries -> honest WARN naming it, never 'clean'" {
  # _gen_password always returns the same fixed value so every retry attempt
  # hashes to the same suffix — deterministic guaranteed-breached across all
  # retries for admin1; other credentials are checked normally (unreachable
  # in this test, to isolate the breached-tally assertion from needing a
  # second real SHA-1 computation).
  _gen_password() { printf 'AlwaysBreachedPassw0rd!'; }

  local _admin1_sha1 _admin1_suffix
  _admin1_sha1="$(printf '%s' "$GEN_ADMIN1_PASSWORD" | { command -v shasum >/dev/null 2>&1 && shasum -a 1 || sha1sum; } | awk '{print toupper($1)}')"
  _admin1_suffix="${_admin1_sha1:5}"

  local _regen_sha1 _regen_suffix
  _regen_sha1="$(printf 'AlwaysBreachedPassw0rd!' | { command -v shasum >/dev/null 2>&1 && shasum -a 1 || sha1sum; } | awk '{print toupper($1)}')"
  _regen_suffix="${_regen_sha1:5}"

  curl() {
    # Match admin1's initial password AND its (fixed) regenerated password —
    # both must appear breached for the retry loop to exhaust deterministically.
    printf '%s:5\r\n%s:5\r\n' "$_admin1_suffix" "$_regen_suffix"
  }
  export -f curl

  run _hibp_check_passwords
  [ "$status" -eq 0 ]
  [[ "$output" == *"remained flagged as breached"* ]]
  [[ "$output" == *"Rotate these credentials"* ]]
  [[ "$output" != *"all"*"passwords clean"* ]]
}
