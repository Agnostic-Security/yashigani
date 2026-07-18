#!/usr/bin/env bats
# tests/install/test_compose_engine_selection.bats
#
# Unit tests for the Podman compose engine selection logic added in
# feat/v412-podman-fork-wiring (2026-07-18).
#
# Root cause / directive: pip podman-compose (1.6.x's dependency-graph hang)
# and native `podman compose` v2 (which dispatches to whatever external
# docker-compose-compatible binary happens to be on PATH — FINDING-V412-
# RESTART-001's client-side registry-credential hang) are BOTH retired from
# the Podman runtime. install.sh now invokes ONLY the vendored
# podman-compose-ysg fork (vendor/podman-compose-ysg/podman_compose.py, via
# the system python3) as the compose driver on Podman. The fork's own
# artefact-integrity (verify-manifest.sh) is checked, fail-closed, before it
# is ever invoked.
#
# Functions under test:
#   _ysg_fork_compose_dir           — locate the vendored fork directory
#   _ysg_fork_compose_python_ready  — PyYAML + python-dotenv importable check
#   _ysg_verify_fork_manifest       — fail-closed integrity gate
#   _ysg_compose_engine_bin         — engine-binary resolver (podman/docker)
#   resolve_compose_cmd             — top-level selection + flag wiring
#
# Tests are fully hermetic:
#   - Functions extracted from install.sh via brace-count awk (same technique
#     as test_ollama_port_resolution.bats and test_letta_waitloop.bats).
#   - `podman`, `python3`, `bash`, and `command` are stubbed as shell functions.
#   - A throwaway fork directory (with a dummy podman_compose.py +
#     verify-manifest.sh) is created under BATS_TEST_TMPDIR — never /tmp
#     directly, and never inside the repo tree.
#   - No live container daemon or network required.
#
# Call convention (bats subshell behaviour):
#   `run func`  → subshell; captures $status+$output; env changes NOT propagated.
#   `func`      → current scope; env changes propagate; test fails on exit !=0.
#
# Requirements:
#   bats-core >= 1.10.0, bash 4.x+, shellcheck
#
# Run:
#   bats tests/install/test_compose_engine_selection.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── awk function extractor (brace-depth counting) ─────────────────────────────
_extract_fn() {
  local fn_name="$1" src="$2"
  awk -v fn="${fn_name}" '
    $0 ~ "^" fn "\\(\\)[ \t]*\\{" { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "$src"
}

# ── Fixture: a fake vendored-fork directory with a passing manifest ──────────
_make_fake_fork_dir() {
  local _dir="$1"
  mkdir -p "${_dir}/vendor/podman-compose-ysg"
  printf '#!/usr/bin/env python3\nprint("stub fork")\n' \
    > "${_dir}/vendor/podman-compose-ysg/podman_compose.py"
  cat > "${_dir}/vendor/podman-compose-ysg/verify-manifest.sh" <<'EOF'
#!/usr/bin/env bash
# Test stub: always succeeds unless FORCE_MANIFEST_FAIL=1 is set.
if [[ "${FORCE_MANIFEST_FAIL:-0}" == "1" ]]; then
  echo "INTEGRITY FAILURE: stub forced failure" >&2
  exit 1
fi
echo "OK: podman-compose-ysg vendored-fork integrity verified (stub)."
exit 0
EOF
  chmod +x "${_dir}/vendor/podman-compose-ysg/verify-manifest.sh"
}

# ── Setup / teardown ──────────────────────────────────────────────────────────

setup() {
  for _fn in _ysg_fork_compose_dir \
              _ysg_fork_compose_python_ready \
              _ysg_verify_fork_manifest \
              _ysg_compose_engine_bin \
              resolve_compose_cmd; do
    local _body
    _body="$(_extract_fn "$_fn" "${INSTALL_SH}")"
    if [[ -z "$_body" ]]; then
      echo "ERROR: ${_fn}() not found in ${INSTALL_SH}" >&2
      return 1
    fi
    eval "$_body"
  done

  # Global state that install.sh declares at module level.
  YSG_PODMAN_RUNTIME=false
  YSG_PODMAN_COMPOSE_V2=false
  YSG_PODMAN_COMPOSE_FORK=false
  _YSG_FORK_MANIFEST_VERIFIED=false
  COMPOSE_CMD=()
  YSG_RUNTIME=""

  # Fixture fork directory — never under the repo tree, never /tmp directly.
  FAKE_WORK_DIR="${BATS_TEST_TMPDIR}/work"
  mkdir -p "$FAKE_WORK_DIR"
  _make_fake_fork_dir "$FAKE_WORK_DIR"
  WORK_DIR="$FAKE_WORK_DIR"

  # Logging stubs — all to stderr so `run` captures are possible.
  log_info()    { printf '[INFO]    %s\n' "$*" >&2; }
  log_warn()    { printf '[WARN]    %s\n' "$*" >&2; }
  log_error()   { printf '[ERROR]   %s\n' "$*" >&2; }
  log_success() { printf '[SUCCESS] %s\n' "$*" >&2; }

  # `podman` stub: info/compose succeed by default (daemon reachable).
  # shellcheck disable=SC2317
  podman() {
    case "$*" in
      "info"*) return 0 ;;
      *)       return 1 ;;
    esac
  }

  # `python3` stub: `import yaml, dotenv` succeeds unless STUB_PY_DEPS_MISSING=1.
  # shellcheck disable=SC2317
  python3() {
    if [[ "$1" == "-c" && "$2" == "import yaml, dotenv" ]]; then
      [[ "${STUB_PY_DEPS_MISSING:-0}" == "1" ]] && return 1
      return 0
    fi
    return 0
  }

  # `command` stub: podman present, docker absent by default.
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman)  return 0 ;;
        python3) return 0 ;;
        docker)  return 1 ;;
        *)       return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  # Exported: verify-manifest.sh runs as a REAL bash subprocess
  # (`bash "$_verify_script"`), so it only sees exported vars — a plain
  # non-exported assignment in a test body would never reach it.
  export FORCE_MANIFEST_FAIL=0
  STUB_PY_DEPS_MISSING=0
}

teardown() {
  unset YSG_PODMAN_RUNTIME YSG_PODMAN_COMPOSE_V2 YSG_PODMAN_COMPOSE_FORK \
        _YSG_FORK_MANIFEST_VERIFIED COMPOSE_CMD YSG_RUNTIME WORK_DIR \
        FAKE_WORK_DIR FORCE_MANIFEST_FAIL STUB_PY_DEPS_MISSING 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _ysg_fork_compose_dir defined exactly once" {
  run grep -c '^_ysg_fork_compose_dir()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _ysg_verify_fork_manifest defined exactly once" {
  run grep -c '^_ysg_verify_fork_manifest()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _ysg_compose_engine_bin defined exactly once" {
  run grep -c '^_ysg_compose_engine_bin()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: pip podman-compose is never selected as a driver (only referenced in retirement comments/error text)" {
  # No live 'COMPOSE_CMD=("podman-compose"' assignment should remain.
  run grep -c 'COMPOSE_CMD=("podman-compose"' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: native 'podman compose' v2 is never selected as the Podman-path driver (only the pre-existing read-only ps fallback remains)" {
  # No live 'COMPOSE_CMD=("podman" "compose")' assignment should remain.
  run grep -c 'COMPOSE_CMD=("podman" "compose")' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: _podman_compose_usable (retired capability gate) no longer present" {
  run grep -c '^_podman_compose_usable()' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: verify-manifest.sh is invoked from resolve_compose_cmd before any fork invocation" {
  run grep -c '_ysg_verify_fork_manifest "\$_fork_dir"' "${INSTALL_SH}"
  [ "$output" -ge 2 ]   # podman-only branch + auto-detect branch
}

# ── _ysg_fork_compose_dir ──────────────────────────────────────────────────────

@test "fork_dir: found under WORK_DIR" {
  run _ysg_fork_compose_dir
  [ "$status" -eq 0 ]
  [ "$output" = "${FAKE_WORK_DIR}/vendor/podman-compose-ysg" ]
}

@test "fork_dir: returns 1 when absent" {
  WORK_DIR="${BATS_TEST_TMPDIR}/empty"
  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"
  run _ysg_fork_compose_dir
  [ "$status" -eq 1 ]
}

# ── _ysg_fork_compose_python_ready ─────────────────────────────────────────────

@test "python_ready: true when yaml+dotenv importable" {
  STUB_PY_DEPS_MISSING=0
  _ysg_fork_compose_python_ready
}

@test "python_ready: false when yaml+dotenv NOT importable" {
  STUB_PY_DEPS_MISSING=1
  run _ysg_fork_compose_python_ready
  [ "$status" -eq 1 ]
}

@test "python_ready: false when python3 absent" {
  command() {
    if [[ "$1" == "-v" ]]; then
      [[ "$2" == "python3" ]] && return 1
      return 1
    fi
    builtin command "$@"
  }
  run _ysg_fork_compose_python_ready
  [ "$status" -eq 1 ]
}

# ── _ysg_verify_fork_manifest — fail-closed ────────────────────────────────────

@test "manifest: verified OK returns 0 and caches" {
  _ysg_verify_fork_manifest "${FAKE_WORK_DIR}/vendor/podman-compose-ysg"
  [ "$_YSG_FORK_MANIFEST_VERIFIED" = "true" ]
}

@test "manifest: second call is a no-op cache hit (does not re-invoke verify-manifest.sh)" {
  _ysg_verify_fork_manifest "${FAKE_WORK_DIR}/vendor/podman-compose-ysg"
  # Sabotage the script; if the function re-ran it, this would now fail.
  echo 'exit 1' > "${FAKE_WORK_DIR}/vendor/podman-compose-ysg/verify-manifest.sh"
  run _ysg_verify_fork_manifest "${FAKE_WORK_DIR}/vendor/podman-compose-ysg"
  [ "$status" -eq 0 ]
}

@test "manifest: tampered fork ABORTS (exit 1), no downgrade to warning" {
  FORCE_MANIFEST_FAIL=1
  run _ysg_verify_fork_manifest "${FAKE_WORK_DIR}/vendor/podman-compose-ysg"
  [ "$status" -eq 1 ]
  [[ "$output" == *"INTEGRITY VERIFICATION FAILED"* ]]
}

@test "manifest: missing verify-manifest.sh script itself ABORTS (exit 1)" {
  rm -f "${FAKE_WORK_DIR}/vendor/podman-compose-ysg/verify-manifest.sh"
  run _ysg_verify_fork_manifest "${FAKE_WORK_DIR}/vendor/podman-compose-ysg"
  [ "$status" -eq 1 ]
}

# ── _ysg_compose_engine_bin ────────────────────────────────────────────────────

@test "engine_bin: podman when YSG_PODMAN_RUNTIME=true regardless of COMPOSE_CMD[0]" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("python3" "/some/path/podman_compose.py" "--in-pod=false")
  run _ysg_compose_engine_bin
  [ "$output" = "podman" ]
}

@test "engine_bin: docker when YSG_PODMAN_RUNTIME=false and COMPOSE_CMD[0]=docker" {
  YSG_PODMAN_RUNTIME=false
  COMPOSE_CMD=("docker" "compose")
  run _ysg_compose_engine_bin
  [ "$output" = "docker" ]
}

@test "engine_bin: falls back to text-match when YSG_PODMAN_RUNTIME unset (defence in depth)" {
  unset YSG_PODMAN_RUNTIME
  COMPOSE_CMD=("podman-compose")
  run _ysg_compose_engine_bin
  [ "$output" = "podman" ]
}

# ── resolve_compose_cmd: Podman-only branch selects the fork ──────────────────

@test "engine: Podman-only branch selects the vendored fork (python3 + script path + --in-pod=false)" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "python3" ]
  [ "${COMPOSE_CMD[1]}" = "${FAKE_WORK_DIR}/vendor/podman-compose-ysg/podman_compose.py" ]
  [ "${COMPOSE_CMD[2]}" = "--in-pod=false" ]
}

@test "engine: Podman-only branch sets YSG_PODMAN_RUNTIME=true" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "$YSG_PODMAN_RUNTIME" = "true" ]
}

@test "engine: Podman-only branch sets YSG_PODMAN_COMPOSE_FORK=true" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "$YSG_PODMAN_COMPOSE_FORK" = "true" ]
}

@test "engine: Podman-only branch KEEPS YSG_PODMAN_COMPOSE_V2=true (YSG-RISK-074 workaround not retired here)" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "$YSG_PODMAN_COMPOSE_V2" = "true" ]
}

@test "engine: Podman-only branch FAILS LOUD (exit 1) when the fork is not present" {
  YSG_RUNTIME=podman
  WORK_DIR="${BATS_TEST_TMPDIR}/no-fork"
  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"
  run resolve_compose_cmd
  [ "$status" -eq 1 ]
  [[ "$output" == *"vendored podman-compose-ysg fork was"* ]] || [[ "$output" == *"not found"* ]]
}

@test "engine: Podman-only branch FAILS LOUD (exit 1) when manifest verification fails (tamper)" {
  YSG_RUNTIME=podman
  FORCE_MANIFEST_FAIL=1
  run resolve_compose_cmd
  [ "$status" -eq 1 ]
}

@test "engine: Podman-only branch FAILS LOUD (exit 1) when python3 lacks yaml/dotenv" {
  YSG_RUNTIME=podman
  STUB_PY_DEPS_MISSING=1
  run resolve_compose_cmd
  [ "$status" -eq 1 ]
  [[ "$output" == *"PyYAML"* ]] || [[ "$output" == *"pyyaml"* ]]
}

@test "engine: Podman-only branch FAILS LOUD when podman daemon unreachable" {
  YSG_RUNTIME=podman
  podman() { return 1; }
  command() {
    if [[ "$1" == "-v" ]]; then
      [[ "$2" == "podman" ]] && return 0
      return 1
    fi
    builtin command "$@"
  }
  run resolve_compose_cmd
  [ "$status" -eq 1 ]
  [[ "$output" == *"not reachable"* ]]
}

# ── resolve_compose_cmd: auto-detect branch ────────────────────────────────────

@test "auto-detect: selects the vendored fork when Podman + fork both present" {
  YSG_RUNTIME=""
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "python3" ]
  [ "$YSG_PODMAN_RUNTIME" = "true" ]
  [ "$YSG_PODMAN_COMPOSE_FORK" = "true" ]
}

@test "auto-detect: falls through to Docker when fork absent (no hard fail)" {
  YSG_RUNTIME=""
  WORK_DIR="${BATS_TEST_TMPDIR}/no-fork-auto"
  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman) return 0 ;;
        docker) return 0 ;;
        *)      return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  docker() {
    case "$*" in
      "info"*)           return 0 ;;
      "compose version") return 0 ;;
      *)                 return 1 ;;
    esac
  }
  run resolve_compose_cmd
  [ "$status" -eq 0 ]
  [[ "$output" == *"Podman is installed but the vendored podman-compose-ysg fork was"* ]]
}

@test "auto-detect: HARD FAILS (does not silently fall through to Docker) when the fork fails integrity verification" {
  YSG_RUNTIME=""
  FORCE_MANIFEST_FAIL=1
  docker() {
    case "$*" in
      "info"*)           return 0 ;;
      "compose version") return 0 ;;
      *)                 return 1 ;;
    esac
  }
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman) return 0 ;;
        docker) return 0 ;;
        *)      return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  run resolve_compose_cmd
  [ "$status" -eq 1 ]
}

# ── State reset discipline ─────────────────────────────────────────────────────

@test "resolve_compose_cmd resets YSG_PODMAN_COMPOSE_FORK to false at entry" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "$YSG_PODMAN_COMPOSE_FORK" = "true" ]

  # Switch to Docker-only and re-resolve — FORK flag must reset to false.
  YSG_RUNTIME=docker
  command() {
    if [[ "$1" == "-v" ]]; then
      [[ "$2" == "docker" ]] && return 0
      return 1
    fi
    builtin command "$@"
  }
  docker() {
    case "$*" in
      "info"*)    return 0 ;;
      "compose"*) return 0 ;;
      *)          return 1 ;;
    esac
  }
  resolve_compose_cmd
  [ "$YSG_PODMAN_COMPOSE_FORK" = "false" ]
  [ "${COMPOSE_CMD[0]}" = "docker" ]
}
