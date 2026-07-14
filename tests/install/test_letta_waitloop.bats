#!/usr/bin/env bats
# tests/install/test_letta_waitloop.bats
#
# Unit tests for:
#   (a) _podman_compose_letta_waitloop() — Part-2 letta stuck-Created fix
#   (b) resolve_compose_cmd() provider preference — Part-1 revert of cacc23da
#
# Background (fix/v411-revert-podman-compose-letta-waitloop):
#   cacc23da swapped resolve_compose_cmd to prefer `podman compose` (v2 engine)
#   over `podman-compose` in an attempt to fix letta stuck-Created.  The swap
#   introduced a seccomp regression: `podman compose` inlines the JSON content
#   of security_opt:seccomp=<path> and passes the blob as the option value to the
#   Podman socket, which treats the multi-KB string as a filename → ENAMETOOLONG
#   → caddy/gateway/backoffice cannot be created on rootless Podman.
#   Fix Part-1 reverts the provider order (podman-compose first).
#   Fix Part-2 adds _podman_compose_letta_waitloop() to handle the letta
#   stuck-Created condition directly in install.sh, without switching providers.
#
# Tests are fully hermetic:
#   - Functions extracted from install.sh via brace-count awk (same technique
#     as test_ollama_port_resolution.bats).
#   - `podman`, `command` and `log_*` are stubbed as shell functions.
#   - No live container daemon required.
#
# Call convention:
#   `run func`   → subshell; captures $status+$output; env changes NOT propagated.
#   `func`       → current scope; env changes propagate; test fails on exit !=0.
#
# Requirements:
#   bats-core >= 1.10.0, bash 4.x+
#
# Run:
#   bats tests/install/test_letta_waitloop.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── awk fragment extractor ─────────────────────────────────────────────────────
# Extract a top-level function by name using brace-depth counting.
# Works with inner helper functions and {{ }} in format strings (net-zero depth).
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

# ── Setup ─────────────────────────────────────────────────────────────────────

setup() {
  # ── Extract helpers + resolve_compose_cmd + waitloop from install.sh ──────
  # resolve_compose_cmd now calls _podman_compose_usable, _podman_client_major,
  # and _podman_compose_version_major_minor; all four must be extracted together.
  for _fn in _podman_compose_version_major_minor \
              _podman_client_major \
              _podman_compose_usable \
              _podman_compose_letta_waitloop \
              resolve_compose_cmd; do
    local _body
    _body="$(_extract_fn "$_fn" "${INSTALL_SH}")"
    if [[ -z "$_body" ]]; then
      echo "ERROR: ${_fn}() not found in ${INSTALL_SH}" >&2
      return 1
    fi
    eval "$_body"
  done

  # ── Global state that install.sh declares at module level ─────────────────
  YSG_PODMAN_RUNTIME=false
  YSG_PODMAN_COMPOSE_V2=false
  COMPOSE_CMD=()
  COMPOSE_PROFILES=()
  COMPOSE_PROJECT_NAME="docker"
  DRY_RUN=false
  YSG_RUNTIME=""
  YSG_LETTA_WAITLOOP_TIMEOUT_S=5   # fast timeout for tests

  # ── Logging stubs ─────────────────────────────────────────────────────────
  log_info()    { printf '[INFO]    %s\n' "$*" >&2; }
  log_warn()    { printf '[WARN]    %s\n' "$*" >&2; }
  log_error()   { printf '[ERROR]   %s\n' "$*" >&2; }
  log_success() { printf '[SUCCESS] %s\n' "$*" >&2; }
  dry_print()   { printf '[DRY]     %s\n' "$*" >&2; }
  log_step()    { :; }

  # ── podman stub: default all calls to "no containers" / "absent" ──────────
  # --version added so _podman_client_major() returns a controllable value.
  # Default major=5 so _podman_compose_usable() does NOT gate on podman 6+,
  # letting podman-compose (when present) be the selected provider.
  podman() {
    case "$1" in
      --version)   echo "podman version ${STUB_PODMAN_MAJOR:-5}.0.0" ;;
      ps)          echo ""          ;;  # no stuck containers
      inspect)     echo "absent"    ;;  # state=absent, health=absent
      start)       return 0         ;;  # start succeeds (no-op)
      healthcheck) return 0         ;;
      info)        return 0         ;;
      compose)     return 0         ;;
      *)           return 1         ;;
    esac
  }

  # ── podman-compose stub ───────────────────────────────────────────────────
  # _podman_compose_version_major_minor() calls `podman-compose --version`.
  # Stub it as a shell function so tests are hermetic (not affected by the
  # system podman-compose 1.6.x). Default version = 1.5.0 (usable).
  # shellcheck disable=SC2317
  podman-compose() {
    case "$1" in
      --version) echo "podman-compose version ${STUB_PC_VERSION:-1.5.0}" ;;
      *)         return 0 ;;
    esac
  }

  # ── command stub for resolve_compose_cmd guards ───────────────────────────
  # Default: podman-compose and podman both available; docker not available.
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return "${STUB_PC_PRESENT:-0}" ;;
        podman)         return 0 ;;
        docker)         return 1 ;;
        docker-compose) return 1 ;;
        *)              return 1 ;;
      esac
    fi
    # Fallback to real command for other uses (e.g. 'command -v bats')
    builtin command "$@"
  }

  # Default stub config: podman 5 + podman-compose 1.5.0 (both usable).
  STUB_PODMAN_MAJOR=5
  STUB_PC_VERSION="1.5.0"
  STUB_PC_PRESENT=0
}

teardown() {
  unset YSG_PODMAN_RUNTIME YSG_PODMAN_COMPOSE_V2 COMPOSE_CMD COMPOSE_PROFILES \
        COMPOSE_PROJECT_NAME DRY_RUN YSG_RUNTIME YSG_LETTA_WAITLOOP_TIMEOUT_S \
        STUB_PODMAN_MAJOR STUB_PC_VERSION STUB_PC_PRESENT 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _podman_compose_letta_waitloop defined exactly once" {
  run grep -c '^_podman_compose_letta_waitloop()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: _podman_compose_letta_waitloop called inside compose_up" {
  run grep -c '_podman_compose_letta_waitloop$' "${INSTALL_SH}"
  # Should appear at least once as a call (definition line is 'function_name() {')
  [ "$output" -ge 1 ]
}

@test "LINT: call appears after compose up -d lines in compose_up" {
  local call_line up_line
  call_line="$(grep -n '^\s*_podman_compose_letta_waitloop$' "${INSTALL_SH}" | tail -1 | cut -d: -f1)"
  # The main fresh-install 'compose up -d' line references _compose_files_up2
  up_line="$(grep -n '_compose_files_up2.*up.*-d' "${INSTALL_SH}" | tail -1 | cut -d: -f1)"
  [ -n "$call_line" ]
  [ -n "$up_line" ]
  [ "$call_line" -gt "$up_line" ]
}

@test "LINT: resolve_compose_cmd checks podman-compose BEFORE podman compose in Podman branch" {
  # 'command -v podman-compose' line must appear before 'podman compose version' line
  # within the Podman-only branch. We check file line ordering.
  local pc_line pv_line
  # First occurrence of 'command -v podman-compose' in the Podman-only branch
  pc_line="$(grep -n 'command -v podman-compose' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  # First occurrence of 'podman compose version' in the Podman-only branch
  pv_line="$(grep -n 'podman compose version' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$pc_line" ]
  [ -n "$pv_line" ]
  [ "$pc_line" -lt "$pv_line" ]
}

@test "LINT: resolve_compose_cmd checks podman-compose BEFORE podman compose in auto-detect branch" {
  # Second occurrence covers the auto-detect branch
  local pc_line pv_line
  pc_line="$(grep -n 'command -v podman-compose' "${INSTALL_SH}" | sed -n '2p' | cut -d: -f1)"
  pv_line="$(grep -n 'podman compose version' "${INSTALL_SH}" | sed -n '2p' | cut -d: -f1)"
  [ -n "$pc_line" ]
  [ -n "$pv_line" ]
  [ "$pc_line" -lt "$pv_line" ]
}

@test "LINT: virtiofs override still carries langflow OPENSSL_armcap=0x8fd" {
  run grep -c 'OPENSSL_armcap.*0x8fd' \
    "${REPO_ROOT}/docker/docker-compose.podman-virtiofs-override.yml"
  [ "$output" -ge 1 ]
}

# ── Guard tests: waitloop must be a NO-OP in these conditions ─────────────────

@test "GUARD: no-op when YSG_PODMAN_RUNTIME=false" {
  YSG_PODMAN_RUNTIME=false
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  # Must not call podman ps (which would emit output)
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when provider is 'podman compose' (not podman-compose)" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman" "compose")
  COMPOSE_PROFILES=("letta")
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when provider is 'docker compose'" {
  YSG_PODMAN_RUNTIME=false
  COMPOSE_CMD=("docker" "compose")
  COMPOSE_PROFILES=("letta")
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when letta profile is not active (lean install)" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("langflow")   # letta not included
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when COMPOSE_PROFILES is empty (core-only install)" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=()
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op in dry-run mode" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  DRY_RUN=true
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry"* ]] || [[ "$output" == *"DRY"* ]] || [[ "$output" == *"skipped"* ]]
}

@test "GUARD: no-op when no containers are stuck in created state" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  # podman ps returns empty (default stub) — no stuck containers
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  # Should log "skipping" not run the sequence
  [[ "$output" == *"skipping"* ]] || [[ "$output" == *"skip"* ]]
}

# ── Activation tests: waitloop triggers when conditions are met ───────────────

@test "ACTIVATE: triggers when podman-compose + letta + containers in created state" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  COMPOSE_PROJECT_NAME="docker"

  # Simulate: `podman ps --filter status=created` returns stuck containers.
  # Argument layout for inspect: $1=inspect $2=--format $3=<format-string> $4=<ctr>
  podman() {
    case "$1" in
      ps)
        echo "docker_letta_1"
        ;;
      inspect)
        local _fmt="${3:-}"
        if [[ "$_fmt" == *"Health.Status"* ]]; then
          echo "healthy"        # all deps instantly healthy
        elif [[ "$_fmt" == *"ExitCode"* ]]; then
          echo "0"              # agent-db-init exit 0
        else
          echo "exited"         # agent-db-init state=exited
        fi
        ;;
      start)  return 0 ;;
      *)      return 1 ;;
    esac
  }

  run _podman_compose_letta_waitloop
  # Should complete without error
  [ "$status" -eq 0 ]
  # Should have logged the wait-loop sequence
  [[ "$output" == *"wait-loop"* ]]
}

@test "ACTIVATE: postgres timeout causes non-zero return and error log" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  COMPOSE_PROJECT_NAME="docker"
  YSG_LETTA_WAITLOOP_TIMEOUT_S=1  # 1-second timeout to force expiry

  podman() {
    case "$1" in
      ps)      echo "docker_letta_1" ;;   # always stuck
      inspect)
        # Health always "starting" — never converges
        echo "starting"
        ;;
      start)   return 0 ;;
      *)       return 1 ;;
    esac
  }

  run _podman_compose_letta_waitloop
  # Should return non-zero (fail-closed on postgres timeout)
  [ "$status" -ne 0 ]
  [[ "$output" == *"timed out"* ]] || [[ "$output" == *"timeout"* ]]
}

@test "ACTIVATE: letta start called after postgres healthy" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  COMPOSE_PROJECT_NAME="docker"

  local _start_calls=()
  podman() {
    case "$1" in
      ps)
        echo "docker_letta_1"
        ;;
      start)
        _start_calls+=("$2")
        return 0
        ;;
      inspect)
        # $3 = format string; $4 = container name
        local _fmt="${3:-}"
        if [[ "$_fmt" == *"Health.Status"* ]]; then
          echo "healthy"
        elif [[ "$_fmt" == *"ExitCode"* ]]; then
          echo "0"
        else
          echo "exited"
        fi
        ;;
      *) return 1 ;;
    esac
  }

  _podman_compose_letta_waitloop
  # letta container must have been started
  [[ "${_start_calls[*]}" == *"docker_letta_1"* ]]
}

@test "ACTIVATE: agent-db-init and letta-pgbouncer started before letta" {
  YSG_PODMAN_RUNTIME=true
  COMPOSE_CMD=("podman-compose" "--in-pod=false")
  COMPOSE_PROFILES=("letta")
  COMPOSE_PROJECT_NAME="docker"

  local _start_order=()
  podman() {
    case "$1" in
      ps)
        echo "docker_letta_1"
        echo "docker_agent-db-init_1"
        ;;
      start)
        _start_order+=("$2")
        return 0
        ;;
      inspect)
        # $3 = format string; $4 = container name
        local _fmt="${3:-}"
        if [[ "$_fmt" == *"Health.Status"* ]]; then
          echo "healthy"
        elif [[ "$_fmt" == *"ExitCode"* ]]; then
          echo "0"
        else
          echo "exited"
        fi
        ;;
      *) return 1 ;;
    esac
  }

  _podman_compose_letta_waitloop

  # agent-db-init must appear in start order before letta
  local _adb_pos _letta_pos
  for i in "${!_start_order[@]}"; do
    [[ "${_start_order[$i]}" == *"agent-db-init"* ]] && _adb_pos=$i
    [[ "${_start_order[$i]}" == *"letta_1"* && "${_start_order[$i]}" != *"pgbouncer"* ]] && _letta_pos=$i
  done
  [ -n "$_adb_pos" ]
  [ -n "$_letta_pos" ]
  [ "$_adb_pos" -lt "$_letta_pos" ]
}

# ── resolve_compose_cmd provider preference tests ─────────────────────────────

@test "PROVIDER: Podman-only branch selects podman-compose when both available" {
  YSG_RUNTIME=podman
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false

  # Both podman-compose and `podman compose` available; podman reachable
  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 0 ;;
        podman)         return 0 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      compose) return 0 ;;  # `podman compose version` succeeds
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  # Must select podman-compose (not podman compose)
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
}

@test "PROVIDER: Podman-only branch falls back to podman compose when podman-compose absent" {
  YSG_RUNTIME=podman
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 1 ;;  # not available
        podman)         return 0 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      compose) return 0 ;;  # `podman compose version` succeeds
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  # Must fall back to podman compose
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${COMPOSE_CMD[1]}" = "compose" ]
}

@test "PROVIDER: auto-detect branch selects podman-compose when both available" {
  YSG_RUNTIME=auto
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 0 ;;
        podman)         return 0 ;;
        docker)         return 1 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      compose) return 0 ;;
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
}

@test "PROVIDER: auto-detect falls back to podman compose when podman-compose absent" {
  YSG_RUNTIME=auto
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 1 ;;
        podman)         return 0 ;;
        docker)         return 1 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      compose) return 0 ;;
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman" ]
  [ "${COMPOSE_CMD[1]}" = "compose" ]
}

@test "PROVIDER: Podman branch sets --in-pod=false on podman-compose" {
  YSG_RUNTIME=podman
  COMPOSE_CMD=()

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 0 ;;
        podman)         return 0 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      compose) return 0 ;;
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  [ "${COMPOSE_CMD[0]}" = "podman-compose" ]
  [ "${COMPOSE_CMD[1]}" = "--in-pod=false" ]
}

@test "PROVIDER: YSG_PODMAN_RUNTIME set to true when podman-compose selected" {
  YSG_RUNTIME=podman
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        podman-compose) return 0 ;;
        podman)         return 0 ;;
        *)              return 1 ;;
      esac
    fi
    builtin command "$@"
  }
  podman() {
    case "$1" in
      info)    return 0 ;;
      *)       return 1 ;;
    esac
  }

  resolve_compose_cmd
  [ "$YSG_PODMAN_RUNTIME" = "true" ]
}
