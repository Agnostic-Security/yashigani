#!/usr/bin/env bats
# tests/install/test_ysg_risk_205_compose_recreation_effect.bats
#
# Regression tests for YSG-RISK-205: `install.sh --upgrade` reported SUCCESS
# (both convergence probes GREEN, UPGRADE_EXIT_CODE=0, "CDI probe OK —
# applying Podman CDI GPU overlay" logged) for a container-level config change
# it never actually applied. `podman inspect` showed the ollama container
# `Created` at the PREVIOUS install, `HostConfig.Devices = []`, still
# library=cpu — the overlay was SELECTED but the container was never
# recreated. Isolated by controlled comparison: a clean uninstall + fresh
# install with the identical spec DID produce library=CUDA — proving the
# spec/overlay were correct and the bug is upgrade-path container-recreation,
# not config generation.
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - AgnosticSecurity Risk Management/yashigani-risks.md YSG-RISK-205
#     ("FIX: after compose up, assert every service whose effective compose
#     definition changed has a Created timestamp newer than the upgrade
#     start, and fail otherwise; add a post-deploy effect check for the
#     inference backend").
#   - install.sh scripts/test-installer.sh test_bash_compat: install.sh MUST
#     run on bash 3.2 (macOS default) — no associative arrays. The fix below
#     stores per-service hashes as plain "service hash" text lines, looked up
#     with awk, not a hash-map variable.
#
# Units under test (both standalone, extractable functions — see the
# brace-counting extraction technique already used by every *.bats file in
# this directory, e.g. test_ollama_port_resolution.bats):
#   _ysg_compose_service_hashes       — per-service resolved-config hashing
#   _ysg_iso_to_epoch                 — portable (GNU+BSD) timestamp parsing
#   _ysg_verify_compose_recreation_effect — the assert-or-fail gate itself
#   _ysg_verify_inference_backend_effect  — GPU-specific post-deploy probe
#     (also covered from the RISK-202 fail-closed-contract angle in
#     test_ysg_risk_202_podman_cdi_fail_closed.bats; covered here from the
#     RISK-205 "post-deploy effect check for the inference backend
#     specifically" angle).
#
# Requirements: bats-core >= 1.10, bash 4+, python3 with PyYAML.
# Run:
#   bats tests/install/test_ysg_risk_205_compose_recreation_effect.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

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
  for fn in _ysg_compose_service_hashes _ysg_iso_to_epoch \
            _ysg_verify_compose_recreation_effect _ysg_verify_inference_backend_effect; do
    fn_body="$(_extract_fn "$fn")"
    [[ -n "$fn_body" ]] || { echo "ERROR: ${fn} not found in install.sh" >&2; return 1; }
    eval "$fn_body"
  done

  _compose() { "$@"; }

  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }
  log_success() { printf '[OK] %s\n' "$*" >&2; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/risk205-scratch.XXXXXX")"
  STATE_FILE="${SCRATCH}/.ysg_service_config_hashes"
  YSG_PODMAN_RUNTIME=true
  YSG_GPU_TYPE="nvidia"
  YSG_ALLOW_CPU_INFERENCE=false
  DRY_RUN=false
  COMPOSE_CMD=(fake-compose)
  compose_files=()
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: compose_up snapshots hashes and captures start epoch BEFORE the down/up sequence" {
  local snap_line down_line
  snap_line="$(grep -n '_ysg_pre_up_hashes="\$(_ysg_compose_service_hashes' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  down_line="$(grep -n 'Stopping any existing containers (preserving data volumes)' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$snap_line" ]; [ -n "$down_line" ]
  [ "$snap_line" -lt "$down_line" ]
}

@test "LINT: the convergence assertion runs BEFORE log_success \"Services started\"" {
  local assert_line success_line
  assert_line="$(grep -n '_ysg_verify_compose_recreation_effect "\$_ysg_upgrade_start_epoch"' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  # Anchor to the actual statement, not the pre-existing docblock comment at
  # ~L8443 that also contains the literal string log_success "Services started".
  success_line="$(grep -nE '^\s*log_success "Services started"$' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$assert_line" ]; [ -n "$success_line" ]
  [ "$assert_line" -lt "$success_line" ]
}

@test "LINT: a convergence-check failure aborts compose_up (return 1), no downgrade to warn" {
  run grep -c '_ysg_verify_compose_recreation_effect "\$_ysg_upgrade_start_epoch" "\$_ysg_state_file" "\$_ysg_pre_up_hashes" || return 1' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

# ── _ysg_compose_service_hashes ───────────────────────────────────────────────

@test "(hash) renders per-service hashes from compose config output, sorted by name" {
  fake-compose() {
    cat <<'EOF'
services:
  gateway:
    image: yashigani/gateway:4.1.2
  ollama:
    image: ollama/ollama:0.6.1
    devices:
      - nvidia.com/gpu=0
EOF
  }
  run _ysg_compose_service_hashes -f fake.yml
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | wc -l)" -eq 2 ]
  [[ "$(echo "$output" | sed -n 1p)" == gateway\ * ]]
  [[ "$(echo "$output" | sed -n 2p)" == ollama\ * ]]
}

@test "(hash) is deterministic for identical input" {
  fake-compose() { printf 'services:\n  ollama:\n    image: x\n'; }
  run _ysg_compose_service_hashes -f fake.yml
  local first="$output"
  run _ysg_compose_service_hashes -f fake.yml
  [ "$output" = "$first" ]
}

@test "(hash) THE EXACT REGRESSION SIGNAL: changing only devices: changes the ollama hash" {
  fake-compose() { printf 'services:\n  ollama:\n    devices: ["nvidia.com/gpu=0"]\n'; }
  run _ysg_compose_service_hashes -f fake.yml
  local before="$output"
  fake-compose() { printf 'services:\n  ollama:\n    devices: []\n'; }
  run _ysg_compose_service_hashes -f fake.yml
  local after="$output"
  [ "$before" != "$after" ]
}

@test "(hash) empty/failed compose config → empty output, non-zero (callers must not treat as no-change)" {
  fake-compose() { return 1; }
  run _ysg_compose_service_hashes -f fake.yml
  [ "$status" -ne 0 ]
  [ -z "$output" ]
}

# ── _ysg_iso_to_epoch ──────────────────────────────────────────────────────────

@test "(iso) parses podman-style nanosecond-precision timestamp with offset" {
  run _ysg_iso_to_epoch "2026-08-07T22:48:01.123456789+01:00"
  [ "$status" -eq 0 ]
  [ "$output" = "1786139281" ]
}

@test "(iso) parses Z-suffixed UTC timestamp" {
  run _ysg_iso_to_epoch "2026-08-07T21:48:01Z"
  [ "$status" -eq 0 ]
  [ "$output" = "1786139281" ]
}

@test "(iso) rejects garbage input (fails closed, not zero-epoch)" {
  run _ysg_iso_to_epoch "not-a-timestamp"
  [ "$status" -ne 0 ]
  [ -z "$output" ]
}

# ── _ysg_verify_compose_recreation_effect ─────────────────────────────────────

@test "(convergence) first run ever (no state file) → nothing to compare, PASS, persists baseline" {
  local current="ollama AAA
gateway BBB"
  run _ysg_verify_compose_recreation_effect 1000 "$STATE_FILE" "$current"
  [ "$status" -eq 0 ]
  [ -f "$STATE_FILE" ]
  grep -q "^ollama AAA$" "$STATE_FILE"
}

@test "(convergence) unchanged hash vs prior run → PASS, no container inspect needed" {
  printf 'ollama AAA\ngateway BBB\n' > "$STATE_FILE"
  fake-compose() { echo "SHOULD NOT BE CALLED" >&2; return 1; }
  local current="ollama AAA
gateway BBB"
  run _ysg_verify_compose_recreation_effect 1000 "$STATE_FILE" "$current"
  [ "$status" -eq 0 ]
}

@test "(convergence) THE EXACT ORIGINAL BUG, REPRODUCED AND CAUGHT: hash changed but container Created predates upgrade start → FAILS (rc=1)" {
  printf 'ollama AAA\n' > "$STATE_FILE"
  local current="ollama ZZZ"
  local start_epoch=2000000000
  # container exists but its Created timestamp is from BEFORE the upgrade
  # started — exactly the live evidence: "podman inspect shows the ollama
  # container Created at the PREVIOUS install ... library=cpu".
  fake-compose() {
    if [[ "$1" == "ps" ]]; then echo "old-container-id"; fi
  }
  # YSG_PODMAN_RUNTIME=true (setup default) → the function inspects via
  # `podman`, not `docker` — mock the one actually selected.
  podman() {
    if [[ "$1" == "inspect" ]]; then echo "2020-01-01T00:00:00Z"; fi
  }
  run _ysg_verify_compose_recreation_effect "$start_epoch" "$STATE_FILE" "$current"
  [ "$status" -eq 1 ]
  [[ "$output" == *"YSG-RISK-205 FAIL"* ]]
  [[ "$output" == *"was NOT recreated"* ]]
}

@test "(convergence) hash changed AND container Created is newer than upgrade start → PASS (genuine recreation)" {
  printf 'ollama AAA\n' > "$STATE_FILE"
  local current="ollama ZZZ"
  local start_epoch=1000000000
  fake-compose() {
    if [[ "$1" == "ps" ]]; then echo "new-container-id"; fi
  }
  podman() {
    if [[ "$1" == "inspect" ]]; then echo "2033-01-01T00:00:00Z"; fi
  }
  run _ysg_verify_compose_recreation_effect "$start_epoch" "$STATE_FILE" "$current"
  [ "$status" -eq 0 ]
  [[ "$output" == *"recreated"* ]]
}

@test "(convergence) hash changed but no container found at all → FAILS (rc=1), fail-closed not skip" {
  printf 'ollama AAA\n' > "$STATE_FILE"
  local current="ollama ZZZ"
  fake-compose() {
    if [[ "$1" == "ps" ]]; then echo ""; fi
  }
  run _ysg_verify_compose_recreation_effect 1000000000 "$STATE_FILE" "$current"
  [ "$status" -eq 1 ]
  [[ "$output" == *"NO container after compose up"* ]]
}

@test "(convergence) uses the podman inspect binary when YSG_PODMAN_RUNTIME=true, docker otherwise" {
  printf 'ollama AAA\n' > "$STATE_FILE"
  local current="ollama ZZZ"
  local start_epoch=1000000000
  YSG_PODMAN_RUNTIME=false
  fake-compose() {
    if [[ "$1" == "ps" ]]; then echo "cid"; fi
  }
  docker() { echo "CALLED-DOCKER" >&2; if [[ "$1" == "inspect" ]]; then echo "2033-01-01T00:00:00Z"; fi; }
  podman() { echo "SHOULD NOT BE CALLED" >&2; return 1; }
  run _ysg_verify_compose_recreation_effect "$start_epoch" "$STATE_FILE" "$current"
  [ "$status" -eq 0 ]
}

# ── _ysg_verify_inference_backend_effect (RISK-205 (d): post-deploy effect check) ─

@test "(inference-effect) THE EXACT REGRESSION: overlay believed-applied but ollama still logs library=cpu → FAILS (rc=1)" {
  fake-compose() { printf 'time=2026-08-07 msg=starting library=cpu variant=avx2\n'; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 1 ]
  [[ "$output" == *"library=cpu"* ]]
}

@test "(inference-effect) genuine GPU effect → library=cuda → PASS" {
  fake-compose() { printf 'time=2026-08-07 msg=starting library=cuda variant=v12\n'; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 0 ]
}
