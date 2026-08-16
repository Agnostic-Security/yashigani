#!/usr/bin/env bats
# tests/install/test_airgap_bundle_sha_fail_closed.bats
#
# Regression tests for the air-gap bundle SHA256 verification fail-open bug
# (dispatch item 1, P0, 2026-08-16): inside `load_airgap_bundle`, when the
# digest could not be computed — `_fips_sha256` failing under FIPS_MODE=1,
# or neither `sha256sum` nor `shasum` being available — the code set
# `actual_sha="$expected_sha"` (manufacturing a match against whatever the
# sidecar claims) and fell through to `log_success "Bundle SHA256
# verified: ..."`. It warned that it was skipping the check, then asserted
# the check had passed.
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - AgnosticSecurity Risk Management/yashigani-risks.md YSG-RISK-037/038/039
#     — "Bundle SHA256 verified at load time" (install.sh Step 7/9) is
#     documented as a COMPENSATING CONTROL underpinning the "NOT EXPLOITABLE"
#     CVA ruling for the air-gap image-digest verification gap (YSG-RISK-038),
#     with a binding re-check clause: "Emergency update if any of the primary
#     integrity controls (bundle SHA256 verification at load ...) are removed
#     or weakened." A control that can be made to assert PASS on a digest it
#     never computed is a control that has been weakened to nothing — this
#     fix restores it to a real fail-closed gate.
#   - git log -S on load_airgap_bundle: 96ac0b6f ("feat(install): air-gap
#     mode + customer-built offline bundle (#58, supply-chain)") — the
#     ORIGINAL commit's own message claims "Verifies bundle SHA256 against
#     sidecar manifest" as fail-closed design intent; the fallback branches
#     contradicted that intent from the start.
#   - lib/yashigani-fips.sh: `_fips_sha256` and
#     `_fips_sha256_manifest_stream` are ALREADY fail-closed on FIPS
#     provider-not-loaded (see tests/integration/test_fips_sha256.sh T6) —
#     this fix makes install.sh's *caller* honour that contract instead of
#     papering over a `return 1` with a manufactured pass.
#   - docs/operations/air-gap-install.md: the "Sidecar manifest not found"
#     and "No SHA256 entry in sidecar manifest" branches are DELIBERATELY
#     left as warn-and-skip (no claim of "verified" is ever printed there) —
#     this fix does not touch those two branches, only the two that
#     asserted success after a computation failure.
#
# Requirements: bats-core >= 1.10, bash 4+.
# Run:
#   bats tests/install/test_airgap_bundle_sha_fail_closed.bats

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
  fn_body="$(_extract_fn "load_airgap_bundle")"
  [[ -n "$fn_body" ]] || { echo "ERROR: load_airgap_bundle not found in install.sh" >&2; return 1; }
  eval "$fn_body"

  # Minimal stand-ins for install.sh's shared plumbing. None of these are
  # under test here — only the SHA-verification block inside
  # load_airgap_bundle is.
  set_step() { :; }
  log_step() { :; }
  dry_print() { :; }
  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }
  log_success() { printf '[OK] %s\n' "$*" >&2; }
  _ysg_register_exit_trap() { :; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/airgap-scratch.XXXXXX")"
  WORK_DIR="${SCRATCH}"
  TOTAL_STEPS=20
  DRY_RUN=false
  FIPS_MODE=0

  mkdir -p "${SCRATCH}/airgap"
  printf 'version: "v1"\n' > "${SCRATCH}/airgap/manifest.yml"

  AIR_GAP_BUNDLE="${SCRATCH}/yashigani-airgap-v1-core.tar.zst"
  printf 'not a real bundle — SHA verification must reject/accept before this content matters\n' \
    > "${AIR_GAP_BUNDLE}"

  local _real_sha
  _real_sha="$(sha256sum "${AIR_GAP_BUNDLE}" | awk '{print $1}')"
  REAL_BUNDLE_SHA="$_real_sha"

  # Sidecar with a CORRECT SHA256 entry, matching the bundle above.
  SIDECAR="${AIR_GAP_BUNDLE%.tar.zst}.manifest"
  printf '# Bundle SHA256: %s\n' "$_real_sha" > "$SIDECAR"
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: no fallback branch manufactures actual_sha=\$expected_sha any more" {
  # Excludes comment lines, which quote the old buggy line verbatim for
  # documentation purposes (see the code comment above the SHA block) —
  # only a live (non-comment) assignment should fail this check.
  run bash -c "grep -v '^[[:space:]]*#' '${INSTALL_SH}' | grep -c 'actual_sha=\"\\\$expected_sha\"'"
  [ "$output" -eq 0 ]
}

# ── THE ORIGINAL BUG (FIPS path): _fips_sha256 failure must abort, never
#    print "Bundle SHA256 verified" ───────────────────────────────────────

@test "THE ORIGINAL BUG: FIPS_MODE=1 with _fips_sha256 failing -> exit 1, never claims verified" {
  FIPS_MODE=1
  _fips_sha256() { return 1; }  # simulates FIPS provider not loaded

  run load_airgap_bundle
  [ "$status" -eq 1 ]
  [[ "$output" == *"BUNDLE INTEGRITY CHECK FAILED"* ]]
  [[ "$output" != *"Bundle SHA256 verified"* ]]
}

# ── THE ORIGINAL BUG (no-tooling path): neither sha256sum nor shasum
#    available -> abort, never claims verified ────────────────────────────

@test "THE ORIGINAL BUG: no sha256sum/shasum on PATH -> exit 1, never claims verified" {
  # Hide sha256sum and shasum specifically (not the whole PATH — tar, awk,
  # grep etc. inside load_airgap_bundle still need to resolve normally).
  sha256sum() { return 127; }
  shasum() { return 127; }
  command() {
    case "$2" in
      sha256sum|shasum) return 1 ;;
      *) builtin command "$@" ;;
    esac
  }

  run load_airgap_bundle
  [ "$status" -eq 1 ]
  [[ "$output" == *"BUNDLE INTEGRITY CHECK FAILED"* ]]
  [[ "$output" == *"Neither sha256sum nor shasum"* ]]
  [[ "$output" != *"Bundle SHA256 verified"* ]]
}

# ── Positive path: digest computable and matches -> genuinely verified,
#    function proceeds past the SHA block (fails later on the fake tar
#    content, which is expected and irrelevant to this test) ─────────────

@test "digest computable and matches sidecar -> genuinely 'Bundle SHA256 verified', proceeds past the check" {
  run load_airgap_bundle
  # Expected to fail LATER (fake bundle isn't a real zstd tar) — that later
  # failure is fine and out of scope; what matters is the SHA block itself
  # printed a genuine verified message before reaching it.
  [[ "$output" == *"Bundle SHA256 verified: ${REAL_BUNDLE_SHA:0:16}"* ]]
  [[ "$output" != *"BUNDLE INTEGRITY CHECK FAILED"* ]]
  [[ "$output" != *"BUNDLE INTEGRITY FAILURE"* ]]
}

@test "digest computable but MISMATCHES sidecar -> BUNDLE INTEGRITY FAILURE, exit 1 (unchanged tamper-detection path)" {
  printf '# Bundle SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n' > "$SIDECAR"

  run load_airgap_bundle
  [ "$status" -eq 1 ]
  [[ "$output" == *"BUNDLE INTEGRITY FAILURE"* ]]
}
