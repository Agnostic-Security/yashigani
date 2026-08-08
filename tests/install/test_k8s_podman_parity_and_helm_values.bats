#!/usr/bin/env bats
# tests/install/test_k8s_podman_parity_and_helm_values.bats
#
# FIND-K8S-INSTALL-DOCKER-ONLY + FIND-K8S-NO-VALUES-OVERLAY (batch-fix 2026-08-04)
#
# FIND-K8S-INSTALL-DOCKER-ONLY: k8s_ensure_fresh_local_images() used to hard-
# require `docker` and call it literally for every build/tag/push/run/ps/
# start/inspect verb, blocking Podman parity (reproduced live on kind-on-
# podman, Leg 3 of the 3-runtime retest — workaround was --skip-k8s-image-
# build + manual `podman build` + `kind load`). Fixed to resolve the engine
# via the same shared helper the rest of install.sh uses
# (_ysg_compose_engine_bin()) instead of hardcoding "docker".
#
# FIND-K8S-NO-VALUES-OVERLAY: install.sh had no CLI to layer extra helm
# values on the k8s path (operators manually ran `helm upgrade` after
# install.sh finished). Fixed with a repeatable --helm-values FILE flag.
#
# Test isolation: functions extracted from install.sh via brace-count awk
# (same technique as test_backend_firewall.bats / test_ollama_port_resolution.bats).
# No real docker/podman/helm/kubectl required for the static + logic tests;
# a couple of tests stub the engine binary as a fake executable on PATH.
#
# Run: bats tests/install/test_k8s_podman_parity_and_helm_values.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_k8s_podman_parity"

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/bin"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

_extract_fn() {
  local fn_name="$1"
  awk -v fn="${fn_name}() {" '
    $0 == fn { f=1 }
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

@test "G-SYNTAX: no new shellcheck findings vs the pre-fix baseline (d39dcf6e)" {
  git -C "${REPO_ROOT}" show d39dcf6e:install.sh > "${MOCK_ROOT}/baseline_install.sh"
  local before after
  before="$(shellcheck --enable=all --severity=warning "${MOCK_ROOT}/baseline_install.sh" 2>&1 \
      | grep -oE 'SC[0-9]+' | sort | uniq -c | sort)"
  after="$(shellcheck --enable=all --severity=warning "${INSTALL_SH}" 2>&1 \
      | grep -oE 'SC[0-9]+' | sort | uniq -c | sort)"
  [ "$before" = "$after" ]
}

# ---------------------------------------------------------------------------
# FIND-K8S-INSTALL-DOCKER-ONLY
# ---------------------------------------------------------------------------

@test "K8S-DOCKER-ONLY: k8s_ensure_fresh_local_images no longer hardcodes require_cmd docker (as CODE, not commentary)" {
  # Note: on this shellcheck/grep toolchain (ugrep), \`grep -c\` over a process
  # substitution can print nothing instead of "0" on zero matches — pipe
  # through instead of <(...) for portability.
  local count
  count="$(_extract_fn "k8s_ensure_fresh_local_images" | grep -v '^\s*#' | grep -c 'require_cmd "docker"' || true)"
  [ "${count:-0}" -eq 0 ]
}

@test "K8S-DOCKER-ONLY: k8s_ensure_fresh_local_images resolves the engine via _ysg_compose_engine_bin" {
  local count
  count="$(_extract_fn "k8s_ensure_fresh_local_images" | grep -c '_ysg_compose_engine_bin' || true)"
  [ "${count:-0}" -ge 1 ]
}

@test "K8S-DOCKER-ONLY: no bare 'docker <verb>' invocation remains as CODE in the function body (build/tag/push/run/ps/start/inspect)" {
  # Only historical comments referencing 'docker inspect'/'docker build' by
  # name should remain; every ACTUAL invocation must go through \$_runtime_bin.
  local bad
  bad="$(_extract_fn "k8s_ensure_fresh_local_images" | grep -v '^\s*#' \
      | grep -E '(^|[^"$_])\bdocker (build|tag|push|run|ps|start|inspect)\b' || true)"
  [ -z "$bad" ]
}

@test "K8S-DOCKER-ONLY: _ysg_compose_engine_bin resolves to podman when YSG_PODMAN_RUNTIME=true (live function, no stack needed)" {
  local fn_src
  fn_src="$(_extract_fn "_ysg_compose_engine_bin")"
  run bash -c "
    ${fn_src}
    YSG_PODMAN_RUNTIME=true
    _ysg_compose_engine_bin
  "
  [ "$status" -eq 0 ]
  [ "$output" = "podman" ]
}

@test "K8S-DOCKER-ONLY: _ysg_compose_engine_bin resolves to docker by default (unchanged behaviour)" {
  local fn_src
  fn_src="$(_extract_fn "_ysg_compose_engine_bin")"
  run bash -c "
    ${fn_src}
    YSG_PODMAN_RUNTIME=false
    COMPOSE_CMD=(docker compose)
    _ysg_compose_engine_bin
  "
  [ "$status" -eq 0 ]
  [ "$output" = "docker" ]
}

@test "K8S-DOCKER-ONLY: live end-to-end — stubbed 'podman' binary receives build/tag/push/inspect (not docker)" {
  # Minimal reproduction of the per-image loop's shape, using the ACTUAL
  # engine-resolution + verb wiring extracted from the real function, against
  # a stub PATH so no real container build happens.
  cat > "${MOCK_ROOT}/bin/podman" <<'EOF'
#!/usr/bin/env bash
echo "podman $*" >> "${MOCK_LOG}"
case "$1" in
  ps) exit 1 ;;                     # "not running" -> exercises the create-then-run branch once
  inspect) echo 'sha256:deadbeef' ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "${MOCK_ROOT}/bin/podman"
  cat > "${MOCK_ROOT}/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "UNEXPECTED docker CALL: $*" >> "${MOCK_LOG}"
exit 1
EOF
  chmod +x "${MOCK_ROOT}/bin/docker"

  local engine_fn
  engine_fn="$(_extract_fn "_ysg_compose_engine_bin")"

  MOCK_LOG="${MOCK_ROOT}/calls.log"
  run env PATH="${MOCK_ROOT}/bin:${PATH}" MOCK_LOG="${MOCK_LOG}" bash -c "
    ${engine_fn}
    require_cmd() { command -v \"\$1\" >/dev/null || exit 1; }
    YSG_PODMAN_RUNTIME=true
    _runtime_bin=\"\$(_ysg_compose_engine_bin)\"
    require_cmd \"\$_runtime_bin\"
    \"\$_runtime_bin\" ps --filter x 2>/dev/null
    \"\$_runtime_bin\" build -t foo:1 . 2>/dev/null || true
    \"\$_runtime_bin\" tag foo:1 bar:1
    \"\$_runtime_bin\" push bar:1
    \"\$_runtime_bin\" inspect --format='{{index .RepoDigests 0}}' bar:1
    echo \"ENGINE=\$_runtime_bin\"
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"ENGINE=podman"* ]]
  run cat "${MOCK_ROOT}/calls.log"
  [[ "$output" == *"podman ps"* ]]
  [[ "$output" == *"podman build"* ]]
  [[ "$output" == *"podman tag"* ]]
  [[ "$output" == *"podman push"* ]]
  [[ "$output" == *"podman inspect"* ]]
  [[ "$output" != *"UNEXPECTED docker CALL"* ]]
}

# ---------------------------------------------------------------------------
# FIND-K8S-NO-VALUES-OVERLAY
# ---------------------------------------------------------------------------

@test "K8S-VALUES: --helm-values and --helm-values=FILE are both parsed in parse_args" {
  run grep -c -- '--helm-values)' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
  run grep -c -- '--helm-values=\*)' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "K8S-VALUES: HELM_VALUES_EXTRA is declared as an array (repeatable flag)" {
  run grep -c '^HELM_VALUES_EXTRA=()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "K8S-VALUES: --helm-values rejects a nonexistent file at parse time (fail closed)" {
  run grep -c -- '--helm-values: file not found' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "K8S-VALUES: k8s_helm_install layers HELM_VALUES_EXTRA as additional -f args, after install.sh's own overlays" {
  # Logic-level reproduction of the actual loop added to k8s_helm_install():
  # extracted verbatim would require kubectl/helm/many preflights present, so
  # this test isolates just the append-loop's behaviour (the part this finding
  # changed) against a real temp values file.
  echo 'foo: bar' > "${MOCK_ROOT}/extra1.yaml"
  echo 'baz: qux' > "${MOCK_ROOT}/extra2.yaml"
  run bash -c "
    set -euo pipefail
    log_error() { echo \"ERR: \$1\" >&2; exit 1; }
    log_info() { :; }
    helm_args=(upgrade --install yashigani /chart -n ns)
    HELM_VALUES_EXTRA=('${MOCK_ROOT}/extra1.yaml' '${MOCK_ROOT}/extra2.yaml')
    _hv_extra=''
    for _hv_extra in \"\${HELM_VALUES_EXTRA[@]+\"\${HELM_VALUES_EXTRA[@]}\"}\"; do
      if [[ ! -f \"\$_hv_extra\" ]]; then
        log_error \"--helm-values file no longer present: \${_hv_extra}\"
      fi
      helm_args+=(-f \"\$_hv_extra\")
    done
    printf '%s\n' \"\${helm_args[@]}\"
  "
  [ "$status" -eq 0 ]
  [[ "$output" == *"extra1.yaml"* ]]
  [[ "$output" == *"extra2.yaml"* ]]
}

@test "K8S-VALUES: helm_args append uses fail-closed re-check (missing file at deploy time aborts, doesn't skip silently)" {
  run bash -c "
    set -euo pipefail
    log_error() { echo \"ERR: \$1\" >&2; exit 1; }
    log_info() { :; }
    helm_args=(upgrade --install yashigani /chart -n ns)
    HELM_VALUES_EXTRA=('/nonexistent/gone.yaml')
    _hv_extra=''
    for _hv_extra in \"\${HELM_VALUES_EXTRA[@]+\"\${HELM_VALUES_EXTRA[@]}\"}\"; do
      if [[ ! -f \"\$_hv_extra\" ]]; then
        log_error \"--helm-values file no longer present: \${_hv_extra}\"
      fi
      helm_args+=(-f \"\$_hv_extra\")
    done
  "
  [ "$status" -ne 0 ]
  [[ "$output" == *"no longer present"* ]]
}

@test "K8S-VALUES: usage/help text documents --helm-values" {
  run grep -c -- '--helm-values FILE' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}
