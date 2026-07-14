#!/usr/bin/env bats
# tests/install/test_compose_engine_selection.bats
#
# Unit tests for the podman compose engine selection logic added in
# fix/v412-podman6-compose.
#
# Root cause: podman-compose 1.6.0 (Homebrew / latest as of 2026-07) breaks the
# dependency graph — single-service 'up' hangs, stack stalls at ~16/26 containers.
# podman compose v2 (docker-compose engine built into Podman 4+) resolves the graph
# correctly but inlines the seccomp JSON → ENAMETOOLONG unless seccomp=unconfined.
# Captain validated 26/26 containers up on podman 6.0.0 with podman compose v2 +
# YASHIGANI_SECCOMP_PROFILE=unconfined.
#
# Functions under test:
#   _podman_compose_version_major_minor  — version string parser
#   _podman_client_major                 — podman client major version
#   _podman_compose_usable               — capability gate
#   resolve_compose_cmd                  — top-level selection + YSG_PODMAN_COMPOSE_V2 flag
#
# Tests are fully hermetic:
#   - Functions extracted from install.sh via brace-count awk (same technique as
#     test_ollama_port_resolution.bats and test_letta_waitloop.bats).
#   - `podman`, `podman-compose`, and `command` are stubbed as shell functions.
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

# ── Setup / teardown ──────────────────────────────────────────────────────────

setup() {
  # Extract all five functions under test from install.sh.
  for _fn in _podman_compose_version_major_minor \
              _podman_client_major \
              _podman_compose_usable \
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
  COMPOSE_CMD=()
  YSG_RUNTIME=""

  # Logging stubs — all to stderr so `run` captures are possible.
  log_info()    { printf '[INFO]    %s\n' "$*" >&2; }
  log_warn()    { printf '[WARN]    %s\n' "$*" >&2; }
  log_error()   { printf '[ERROR]   %s\n' "$*" >&2; }
  log_success() { printf '[SUCCESS] %s\n' "$*" >&2; }

  # Default stubs — override per-test as needed.
  #
  # `podman` stub:
  #   --version → "podman version ${STUB_PODMAN_MAJOR:-6}.0.0"
  #   info      → exit 0  (daemon reachable)
  #   compose version → exit 0  (v2 available)
  # shellcheck disable=SC2317
  podman() {
    case "$*" in
      "--version")      echo "podman version ${STUB_PODMAN_MAJOR:-6}.0.0" ;;
      "info"*)          return 0 ;;
      "compose version") return 0 ;;
      "compose"*)       return 0 ;;
      *)                return 1 ;;
    esac
  }

  # `podman-compose` stub: version controlled by STUB_PC_VERSION.
  # shellcheck disable=SC2317
  podman-compose() {
    case "$1" in
      --version) echo "podman-compose version ${STUB_PC_VERSION:-1.5.0}" ;;
      *)         return 0 ;;
    esac
  }

  # `command` stub: controls which compose tools appear to be installed.
  # Default: both podman and podman-compose present; docker absent.
  # shellcheck disable=SC2317
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman)         return 0 ;;
        podman-compose) return "${STUB_PC_PRESENT:-0}" ;;
        docker)         return 1 ;;
        docker-compose) return 1 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  # Default version stubs — override per-test.
  STUB_PODMAN_MAJOR=6
  STUB_PC_VERSION="1.5.0"
  STUB_PC_PRESENT=0  # 0 = present (command -v succeeds)
}

teardown() {
  unset YSG_PODMAN_RUNTIME YSG_PODMAN_COMPOSE_V2 COMPOSE_CMD YSG_RUNTIME \
        STUB_PODMAN_MAJOR STUB_PC_VERSION STUB_PC_PRESENT 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _podman_compose_usable defined exactly once" {
  run grep -c '^_podman_compose_usable()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _podman_compose_version_major_minor defined exactly once" {
  run grep -c '^_podman_compose_version_major_minor()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _podman_client_major defined exactly once" {
  run grep -c '^_podman_client_major()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: YSG_PODMAN_COMPOSE_V2 global declared before resolve_compose_cmd" {
  local decl_line fn_line
  decl_line="$(grep -n '^YSG_PODMAN_COMPOSE_V2=' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  fn_line="$(grep -n '^resolve_compose_cmd()' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$decl_line" ]
  [ -n "$fn_line" ]
  [ "$decl_line" -lt "$fn_line" ]
}

@test "LINT: podman-compose check still appears before podman compose version (podman branch)" {
  local pc_line pv_line
  pc_line="$(grep -n 'command -v podman-compose' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  pv_line="$(grep -n 'podman compose version' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$pc_line" ]
  [ -n "$pv_line" ]
  [ "$pc_line" -lt "$pv_line" ]
}

@test "LINT: YSG_PODMAN_COMPOSE_V2=true set in both podman-only and auto-detect paths" {
  run grep -c 'YSG_PODMAN_COMPOSE_V2=true' "${INSTALL_SH}"
  # Must appear at least twice: once in each branch (podman-only + auto-detect)
  [ "$output" -ge 2 ]
}

@test "LINT: seccomp block checks YSG_PODMAN_COMPOSE_V2 before file-existence check" {
  local v2_line file_line
  v2_line="$(grep -n 'YSG_PODMAN_COMPOSE_V2.*true' "${INSTALL_SH}" | grep 'if \[\[' | head -1 | cut -d: -f1)"
  file_line="$(grep -n '! -f.*_seccomp_profile' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$v2_line" ]
  [ -n "$file_line" ]
  [ "$v2_line" -lt "$file_line" ]
}

# ── _podman_compose_version_major_minor ───────────────────────────────────────

@test "version_major_minor: 1.5.0 → '1.5'" {
  STUB_PC_VERSION="1.5.0"
  run _podman_compose_version_major_minor
  [ "$status" -eq 0 ]
  [ "$output" = "1.5" ]
}

@test "version_major_minor: 1.6.0 → '1.6'" {
  STUB_PC_VERSION="1.6.0"
  run _podman_compose_version_major_minor
  [ "$status" -eq 0 ]
  [ "$output" = "1.6" ]
}

@test "version_major_minor: 2.0.0 → '2.0'" {
  STUB_PC_VERSION="2.0.0"
  run _podman_compose_version_major_minor
  [ "$status" -eq 0 ]
  [ "$output" = "2.0" ]
}

@test "version_major_minor: absent → returns 1" {
  STUB_PC_PRESENT=1   # command -v podman-compose fails
  run _podman_compose_version_major_minor
  [ "$status" -eq 1 ]
}

# ── _podman_client_major ──────────────────────────────────────────────────────

@test "client_major: podman 6.0.0 → '6'" {
  STUB_PODMAN_MAJOR=6
  run _podman_client_major
  [ "$status" -eq 0 ]
  [ "$output" = "6" ]
}

@test "client_major: podman 5.0.0 → '5'" {
  STUB_PODMAN_MAJOR=5
  run _podman_client_major
  [ "$status" -eq 0 ]
  [ "$output" = "5" ]
}

@test "client_major: podman 4.9.0 → '4'" {
  STUB_PODMAN_MAJOR=4
  run _podman_client_major
  [ "$status" -eq 0 ]
  [ "$output" = "4" ]
}

# ── _podman_compose_usable ────────────────────────────────────────────────────

@test "usable: podman-compose 1.5.x + podman 5 → usable (returns 0)" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  _podman_compose_usable   # direct call — test fails if non-zero
}

@test "usable: podman-compose 1.5.x + podman 4 → usable (returns 0)" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=4
  STUB_PC_PRESENT=0
  _podman_compose_usable
}

@test "usable: podman-compose 1.6.x + podman 5 → NOT usable (returns 1)" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  run _podman_compose_usable
  [ "$status" -eq 1 ]
}

@test "usable: podman-compose 1.5.x + podman 6 → NOT usable (podman 6 prefers v2)" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=6
  STUB_PC_PRESENT=0
  run _podman_compose_usable
  [ "$status" -eq 1 ]
}

@test "usable: podman-compose absent → NOT usable (returns 1)" {
  STUB_PC_PRESENT=1   # command -v fails
  run _podman_compose_usable
  [ "$status" -eq 1 ]
}

@test "usable: podman-compose 1.6.x + podman 6 → NOT usable" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=6
  STUB_PC_PRESENT=0
  run _podman_compose_usable
  [ "$status" -eq 1 ]
}

# ── resolve_compose_cmd: engine selection ─────────────────────────────────────

@test "engine: podman-compose 1.5.x + podman 5 → selects podman-compose" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
}

@test "engine: podman-compose 1.5.x + podman 5 → --in-pod=false included" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [[ " ${COMPOSE_CMD[*]} " == *" --in-pod=false "* ]]
}

@test "engine: podman-compose 1.5.x + podman 5 → YSG_PODMAN_COMPOSE_V2=false" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_COMPOSE_V2}" = "false" ]
}

@test "engine: podman-compose 1.6.x → selects podman compose v2" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${COMPOSE_CMD[1]}" = "compose" ]
}

@test "engine: podman-compose 1.6.x → YSG_PODMAN_COMPOSE_V2=true" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_COMPOSE_V2}" = "true" ]
}

@test "engine: no podman-compose + podman 6 → selects podman compose v2" {
  STUB_PC_PRESENT=1   # podman-compose absent
  STUB_PODMAN_MAJOR=6
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${COMPOSE_CMD[1]}" = "compose" ]
}

@test "engine: no podman-compose + podman 6 → YSG_PODMAN_COMPOSE_V2=true" {
  STUB_PC_PRESENT=1
  STUB_PODMAN_MAJOR=6
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_COMPOSE_V2}" = "true" ]
}

@test "engine: podman-compose 1.5.x + podman 4 → selects podman-compose (4.9 legacy path)" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=4
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
  [ "${YSG_PODMAN_COMPOSE_V2}" = "false" ]
}

@test "engine: podman-compose v2 path does NOT include --in-pod=false" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  # --in-pod=false must not appear (it's a podman-compose-only flag)
  [[ " ${COMPOSE_CMD[*]} " != *"--in-pod=false"* ]]
}

# ── resolve_compose_cmd: auto-detect path ─────────────────────────────────────

@test "auto-detect: podman-compose 1.5.x + podman 5 → podman-compose (auto)" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=""   # auto-detect
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
  [ "${YSG_PODMAN_COMPOSE_V2}" = "false" ]
}

@test "auto-detect: podman-compose 1.6.x → podman compose v2 + YSG_PODMAN_COMPOSE_V2=true" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=""
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${YSG_PODMAN_COMPOSE_V2}" = "true" ]
}

@test "auto-detect: no podman-compose + podman 6 → podman compose v2 + V2=true" {
  STUB_PC_PRESENT=1
  STUB_PODMAN_MAJOR=6
  YSG_RUNTIME=""
  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${YSG_PODMAN_COMPOSE_V2}" = "true" ]
}

# ── YSG_PODMAN_RUNTIME ────────────────────────────────────────────────────────

@test "YSG_PODMAN_RUNTIME=true when podman-compose selected" {
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_RUNTIME}" = "true" ]
}

@test "YSG_PODMAN_RUNTIME=true when podman compose v2 selected" {
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_RUNTIME}" = "true" ]
}

# ── State reset discipline ────────────────────────────────────────────────────

@test "resolve_compose_cmd resets YSG_PODMAN_COMPOSE_V2 to false on each call" {
  # First call sets V2=true (1.6.x broken path)
  STUB_PC_VERSION="1.6.0"
  STUB_PODMAN_MAJOR=5
  STUB_PC_PRESENT=0
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "${YSG_PODMAN_COMPOSE_V2}" = "true" ]

  # Second call with working podman-compose must reset V2 to false
  STUB_PC_VERSION="1.5.0"
  STUB_PODMAN_MAJOR=5
  resolve_compose_cmd
  [ "${YSG_PODMAN_COMPOSE_V2}" = "false" ]
}
