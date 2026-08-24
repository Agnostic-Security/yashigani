#!/usr/bin/env bats
# tests/install/test_ysg_risk_202_podman_cdi_fail_closed.bats
#
# Regression tests for YSG-RISK-202: podman install reported SUCCESS (exit 0)
# with the mandatory LLM layer running CPU-only, because (a) a stale
# root-owned /etc/cdi/nvidia.yaml shadowed the correct user-space CDI spec on
# podman 4.9.3 with no detection or remediation, and (b) a failed CDI probe
# silently degraded to CPU-only ollama and still exited 0.
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - AgnosticSecurity Risk Management/yashigani-risks.md YSG-RISK-202
#   - install.sh git history: commit 4f3858d0 ("rootless-Podman GPU works
#     end-to-end") — original ROOTLESS-CDI-001 design, verified live on a host
#     with NO pre-existing /etc/cdi/nvidia.yaml.
#   - project_yashigani_llm_is_mandatory / feedback_gpu_usage_for_test_stacks
#     memory: CPU-only Ollama on a GPU-detected host is a product-policy
#     violation, not an acceptable default degrade.
#
# Two units are tested directly (both are standalone, extractable functions):
#   _check_stale_etc_cdi_shadow  — the shadow-detection/remediation logic
#   _ysg_verify_inference_backend_effect — the fail-closed-by-default /
#     --allow-cpu-inference-overridable contract RISK-202(c) requires. The
#     inline CDI-probe branch inside compose_up() implements the identical
#     contract but is not independently extractable (compose_up() is too
#     large/stateful to isolate in bats); its wiring is instead asserted via
#     LINT/structural greps below, consistent with this test suite's existing
#     convention (see test_ollama_port_resolution.bats "LINT:" tests).
#
# Requirements: bats-core >= 1.10, bash 4+, python3 with PyYAML.
# Run:
#   bats tests/install/test_ysg_risk_202_podman_cdi_fail_closed.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── extraction helper — same brace-counting technique used throughout this
# test suite (see test_ollama_port_resolution.bats header comment). ─────────
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
  fn_body="$(_extract_fn "_check_stale_etc_cdi_shadow")"
  [[ -n "$fn_body" ]] || { echo "ERROR: _check_stale_etc_cdi_shadow not found" >&2; return 1; }
  eval "$fn_body"

  fn_body="$(_extract_fn "_ysg_verify_inference_backend_effect")"
  [[ -n "$fn_body" ]] || { echo "ERROR: _ysg_verify_inference_backend_effect not found" >&2; return 1; }
  eval "$fn_body"

  # _compose dependency — stub as a passthrough (identical behaviour to the
  # real _compose when YSG_INSTALL_LOCK_FD is unset, which it is in tests).
  _compose() { "$@"; }

  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }
  log_success() { printf '[OK] %s\n' "$*" >&2; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/cdi-scratch.XXXXXX")"
  YSG_GPU_TYPE="nvidia"
  YSG_ALLOW_CPU_INFERENCE=false
  DRY_RUN=false
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=(fake-compose)
  compose_files=()
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: --allow-cpu-inference flag is parsed and sets YSG_ALLOW_CPU_INFERENCE=true" {
  run grep -A4 -- '--allow-cpu-inference)' "${INSTALL_SH}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"YSG_ALLOW_CPU_INFERENCE=true"* ]]
}

@test "LINT: YSG_ALLOW_CPU_INFERENCE defaults to false" {
  run grep -c '^YSG_ALLOW_CPU_INFERENCE=false' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: the CDI-probe-failed branch aborts (return 1) before falling through to devpath, unless --allow-cpu-inference" {
  local allow_line abort_line devpath_line
  allow_line="$(grep -n 'YSG_ALLOW_CPU_INFERENCE:-false}" != "true"' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  abort_line="$(grep -n 'Aborting: GPU detected but not provable live in ollama' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  devpath_line="$(grep -n 'Applying Podman device-path GPU overlay' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$allow_line" ]; [ -n "$abort_line" ]; [ -n "$devpath_line" ]
  [ "$allow_line" -lt "$abort_line" ]
  [ "$abort_line" -lt "$devpath_line" ]
}

@test "LINT: wrong Docker-daemon remediation text for Podman operators is gone" {
  run grep -c 'ensure nvidia-ctk + Docker daemon are available' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: premature log_success before the CDI probe is gone (now log_info, pending runtime probe)" {
  run grep -c 'log_success "Podman GPU CDI ready — user-space spec, no /etc/cdi, no docker, no sudo"' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
  run grep -c 'Podman GPU CDI spec provisioned (user-space) — pending runtime probe' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _setup_podman_cdi_gpu calls _check_stale_etc_cdi_shadow before returning" {
  run grep -c '_check_stale_etc_cdi_shadow "\${_cdi_out}" "\${_podman_major:-4}"' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

# ── _check_stale_etc_cdi_shadow ───────────────────────────────────────────────

@test "(shadow) no /etc/cdi/nvidia.yaml present → not stale, rc=0" {
  YSG_CDI_ETC_SPEC_OVERRIDE="${SCRATCH}/does-not-exist/nvidia.yaml"
  run _check_stale_etc_cdi_shadow "${SCRATCH}/correct-spec.yaml" 4
  [ "$status" -eq 0 ]
  [[ "$output" == *"no shadow risk"* ]]
}

@test "(shadow) /etc/cdi present, referenced library exists on disk → not stale, rc=0" {
  local libdir="${SCRATCH}/lib"
  mkdir -p "$libdir"
  touch "${libdir}/libcuda.so.580.173.02"
  cat > "${SCRATCH}/etc-nvidia.yaml" <<EOF
cdiVersion: "0.6.0"
containerEdits:
  mounts:
    - hostPath: ${libdir}/libcuda.so.580.173.02
      containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.173.02
EOF
  YSG_CDI_ETC_SPEC_OVERRIDE="${SCRATCH}/etc-nvidia.yaml"
  run _check_stale_etc_cdi_shadow "${SCRATCH}/correct-spec.yaml" 4
  [ "$status" -eq 0 ]
  [[ "$output" == *"not stale"* ]]
}

@test "(shadow) THE ORIGINAL BUG: /etc/cdi references a driver library removed by an upgrade, not writable → FAILS LOUD, exports YSG_CDI_ETC_SHADOW_STALE=true" {
  cat > "${SCRATCH}/etc-nvidia.yaml" <<EOF
cdiVersion: "0.6.0"
containerEdits:
  mounts:
    - hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.159.03
      containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.159.03
EOF
  chmod 444 "${SCRATCH}/etc-nvidia.yaml"   # not writable — simulates root:root /etc/cdi
  YSG_CDI_ETC_SPEC_OVERRIDE="${SCRATCH}/etc-nvidia.yaml"
  # Direct call, NOT `run` and NOT $(...) — both create a subshell, and an
  # exported var set inside a subshell never propagates back to test scope
  # (see this suite's established convention, e.g. test_ollama_port_resolution.bats).
  # Redirect to a file instead so the call itself stays in the current shell.
  local _out_file="${SCRATCH}/shadow-check.out"
  _check_stale_etc_cdi_shadow "${SCRATCH}/correct-spec.yaml" 4 > "$_out_file" 2>&1
  local _rc=$?
  [ "$_rc" -eq 0 ]   # the function itself never aborts the install — it signals via the export
  grep -q "STALE" "$_out_file"
  grep -q "libcuda.so.580.159.03" "$_out_file"
  grep -q "sudo install -m 0644" "$_out_file"
  [ "$YSG_CDI_ETC_SHADOW_STALE" = "true" ]
}

@test "(shadow) stale AND writable → auto-refreshes from the correct spec, rc=0, not flagged stale" {
  printf 'cdiVersion: "0.6.0"\ncorrect: true\n' > "${SCRATCH}/correct-spec.yaml"
  cat > "${SCRATCH}/etc-nvidia.yaml" <<EOF
cdiVersion: "0.6.0"
containerEdits:
  mounts:
    - hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.999.99.99
      containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.999.99.99
EOF
  chmod 644 "${SCRATCH}/etc-nvidia.yaml"
  YSG_CDI_ETC_SPEC_OVERRIDE="${SCRATCH}/etc-nvidia.yaml"
  run _check_stale_etc_cdi_shadow "${SCRATCH}/correct-spec.yaml" 4
  [ "$status" -eq 0 ]
  [[ "$output" == *"refreshed"* ]]
  grep -q "correct: true" "${SCRATCH}/etc-nvidia.yaml"
}

@test "(shadow) podman >=5 framing: message says UNTESTED, not confirmed-safe" {
  cat > "${SCRATCH}/etc-nvidia.yaml" <<EOF
cdiVersion: "0.7.0"
containerEdits:
  mounts:
    - hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.159.03
      containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.580.159.03
EOF
  chmod 444 "${SCRATCH}/etc-nvidia.yaml"
  YSG_CDI_ETC_SPEC_OVERRIDE="${SCRATCH}/etc-nvidia.yaml"
  run _check_stale_etc_cdi_shadow "${SCRATCH}/correct-spec.yaml" 5
  [[ "$output" == *"UNTESTED"* ]]
}

# ── _ysg_verify_inference_backend_effect (fail-closed contract, RISK-202 (c)) ─

@test "(effect) THE ORIGINAL BUG CLASS: GPU detected, ollama reports library=cpu, no flag → FAILS CLOSED (rc=1)" {
  fake-compose() { printf 'library=cpu\n'; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 1 ]
  [[ "$output" == *"YSG-RISK-205 inference-backend effect check FAILED"* || "$output" == *"library=cpu"* ]]
}

@test "(effect) GPU detected, ollama reports library=cuda → PASS (rc=0)" {
  fake-compose() { printf 'library=cuda\n'; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 0 ]
  [[ "$output" == *"confirmed live"* ]]
}

@test "(effect) --allow-cpu-inference set → library=cpu is accepted (explicit opt-in), rc=0" {
  YSG_ALLOW_CPU_INFERENCE=true
  fake-compose() { printf 'library=cpu\n'; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 0 ]
  [[ "$output" == *"explicit operator opt-in"* ]]
}

@test "(effect) GPU_TYPE=none → no-op, rc=0, no probe attempted" {
  YSG_GPU_TYPE="none"
  fake-compose() { echo "SHOULD NOT BE CALLED" >&2; return 1; }
  run _ysg_verify_inference_backend_effect
  [ "$status" -eq 0 ]
}
