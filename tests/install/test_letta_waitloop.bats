#!/usr/bin/env bats
# tests/install/test_letta_waitloop.bats
#
# Unit tests for _podman_compose_letta_waitloop() — the letta stuck-Created
# workaround for podman-compose's incomplete depends_on(service_healthy /
# service_completed_successfully) support.
#
# Updated 2026-07-18 (feat/v412-podman-fork-wiring): the guard that gates this
# function used to text-match COMPOSE_CMD[0] == "podman-compose" (the pip
# binary name). As of the fork wiring, the Podman runtime's ONLY compose
# driver is the vendored podman-compose-ysg fork
# (vendor/podman-compose-ysg/podman_compose.py, invoked via python3) — its
# COMPOSE_CMD[0] is "python3", not a driver name, so the guard now checks the
# authoritative YSG_PODMAN_COMPOSE_FORK flag (set by resolve_compose_cmd)
# instead. The fork inherits podman-compose 1.5.0's incomplete
# service_healthy support unchanged (none of AS-FIX-1/2/3 touch dependency-
# condition semantics), so this workaround remains necessary and unchanged in
# its own runtime behaviour — only the SELECTION GUARD changed.
#
# resolve_compose_cmd()'s own engine-selection behaviour (fork-only on
# Podman, fail-closed manifest verification, etc.) has its own comprehensive
# coverage in tests/install/test_compose_engine_selection.bats — this file
# does not duplicate that; it exercises only enough of resolve_compose_cmd to
# confirm YSG_PODMAN_COMPOSE_FORK is wired correctly into the waitloop guard.
#
# Tests are fully hermetic:
#   - Functions extracted from install.sh via brace-count awk (same technique
#     as test_ollama_port_resolution.bats and test_compose_engine_selection.bats).
#   - `podman`, `python3`, `command` and `log_*` are stubbed as shell functions.
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

# ── awk fragment extractor (brace-depth counting) ─────────────────────────────
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

# ── Fixture: a fake vendored-fork directory with a passing manifest ──────────
_make_fake_fork_dir() {
  local _dir="$1"
  mkdir -p "${_dir}/vendor/podman-compose-ysg"
  printf '#!/usr/bin/env python3\nprint("stub fork")\n' \
    > "${_dir}/vendor/podman-compose-ysg/podman_compose.py"
  cat > "${_dir}/vendor/podman-compose-ysg/verify-manifest.sh" <<'EOF'
#!/usr/bin/env bash
echo "OK: podman-compose-ysg vendored-fork integrity verified (stub)."
exit 0
EOF
  chmod +x "${_dir}/vendor/podman-compose-ysg/verify-manifest.sh"
}

# ── Setup ─────────────────────────────────────────────────────────────────────

setup() {
  # ── Extract fork-selection helpers + resolve_compose_cmd + waitloop ───────
  for _fn in _ysg_fork_compose_dir \
              _ysg_fork_compose_python_ready \
              _ysg_verify_fork_manifest \
              _ysg_compose_engine_bin \
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
  YSG_PODMAN_COMPOSE_FORK=false
  _YSG_FORK_MANIFEST_VERIFIED=false
  COMPOSE_CMD=()
  COMPOSE_PROFILES=()
  COMPOSE_PROJECT_NAME="docker"
  DRY_RUN=false
  YSG_RUNTIME=""
  YSG_LETTA_WAITLOOP_TIMEOUT_S=5   # fast timeout for tests

  # Fixture fork directory — never under the repo tree, never /tmp directly.
  FAKE_WORK_DIR="${BATS_TEST_TMPDIR}/work"
  mkdir -p "$FAKE_WORK_DIR"
  _make_fake_fork_dir "$FAKE_WORK_DIR"
  WORK_DIR="$FAKE_WORK_DIR"

  # ── Logging stubs ─────────────────────────────────────────────────────────
  log_info()    { printf '[INFO]    %s\n' "$*" >&2; }
  log_warn()    { printf '[WARN]    %s\n' "$*" >&2; }
  log_error()   { printf '[ERROR]   %s\n' "$*" >&2; }
  log_success() { printf '[SUCCESS] %s\n' "$*" >&2; }
  dry_print()   { printf '[DRY]     %s\n' "$*" >&2; }
  log_step()    { :; }

  # ── podman stub: default all calls to "no containers" / info reachable ────
  podman() {
    case "$1" in
      ps)          echo ""          ;;  # no stuck containers
      inspect)     echo "absent"    ;;  # state=absent, health=absent
      start)       return 0         ;;  # start succeeds (no-op)
      healthcheck) return 0         ;;
      info)        return 0         ;;
      *)           return 1         ;;
    esac
  }

  # ── python3 stub: `import yaml, dotenv` always succeeds in this file — the
  # letta-waitloop tests aren't exercising the python-deps gate (that's
  # covered in test_compose_engine_selection.bats). ─────────────────────────
  python3() {
    if [[ "$1" == "-c" ]]; then return 0; fi
    return 0
  }

  # ── command stub for resolve_compose_cmd guards ───────────────────────────
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
}

teardown() {
  unset YSG_PODMAN_RUNTIME YSG_PODMAN_COMPOSE_V2 YSG_PODMAN_COMPOSE_FORK \
        _YSG_FORK_MANIFEST_VERIFIED COMPOSE_CMD COMPOSE_PROFILES \
        COMPOSE_PROJECT_NAME DRY_RUN YSG_RUNTIME YSG_LETTA_WAITLOOP_TIMEOUT_S \
        WORK_DIR FAKE_WORK_DIR 2>/dev/null || true
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

@test "LINT: guard checks YSG_PODMAN_COMPOSE_FORK, not a COMPOSE_CMD[0] text match" {
  local fn_body
  fn_body="$(_extract_fn "_podman_compose_letta_waitloop" "${INSTALL_SH}")"
  [[ "$fn_body" == *'YSG_PODMAN_COMPOSE_FORK'* ]]
  [[ "$fn_body" != *'COMPOSE_CMD[0]:-}" != "podman-compose"'* ]]
}

@test "LINT: virtiofs override still carries langflow OPENSSL_armcap=0x8fd" {
  run grep -c 'OPENSSL_armcap.*0x8fd' \
    "${REPO_ROOT}/docker/docker-compose.podman-virtiofs-override.yml"
  [ "$output" -ge 1 ]
}

# ── Guard tests: waitloop must be a NO-OP in these conditions ─────────────────

@test "GUARD: no-op when YSG_PODMAN_RUNTIME=false" {
  YSG_PODMAN_RUNTIME=false
  YSG_PODMAN_COMPOSE_FORK=true
  COMPOSE_PROFILES=("letta")
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  # Must not call podman ps (which would emit output)
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when YSG_PODMAN_COMPOSE_FORK=false (e.g. Docker runtime)" {
  YSG_PODMAN_RUNTIME=false
  YSG_PODMAN_COMPOSE_FORK=false
  COMPOSE_PROFILES=("letta")
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when letta profile is not active (lean install)" {
  YSG_PODMAN_RUNTIME=true
  YSG_PODMAN_COMPOSE_FORK=true
  COMPOSE_PROFILES=("langflow")   # letta not included
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op when COMPOSE_PROFILES is empty (core-only install)" {
  YSG_PODMAN_RUNTIME=true
  YSG_PODMAN_COMPOSE_FORK=true
  COMPOSE_PROFILES=()
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" != *"wait-loop"* ]]
}

@test "GUARD: no-op in dry-run mode" {
  YSG_PODMAN_RUNTIME=true
  YSG_PODMAN_COMPOSE_FORK=true
  COMPOSE_PROFILES=("letta")
  DRY_RUN=true
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry"* ]] || [[ "$output" == *"DRY"* ]] || [[ "$output" == *"skipped"* ]]
}

@test "GUARD: no-op when no containers are stuck in created state" {
  YSG_PODMAN_RUNTIME=true
  YSG_PODMAN_COMPOSE_FORK=true
  COMPOSE_PROFILES=("letta")
  # podman ps returns empty (default stub) — no stuck containers
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  # Should log "skipping" not run the sequence
  [[ "$output" == *"skipping"* ]] || [[ "$output" == *"skip"* ]]
}

# ── Activation tests: waitloop triggers when conditions are met ───────────────

@test "ACTIVATE: triggers when fork + letta + containers in created state" {
  YSG_PODMAN_RUNTIME=true
  YSG_PODMAN_COMPOSE_FORK=true
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
  YSG_PODMAN_COMPOSE_FORK=true
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
  YSG_PODMAN_COMPOSE_FORK=true
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
  YSG_PODMAN_COMPOSE_FORK=true
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

# ── resolve_compose_cmd → YSG_PODMAN_COMPOSE_FORK wiring smoke test ───────────
# (resolve_compose_cmd's full engine-selection behaviour — fork-only on
# Podman, fail-closed manifest verification, pip podman-compose / podman
# compose v2 retirement — is comprehensively covered in
# tests/install/test_compose_engine_selection.bats. This is a single smoke
# test confirming the waitloop's guard flag is actually wired end-to-end.)

@test "SMOKE: resolve_compose_cmd(--runtime podman) sets YSG_PODMAN_COMPOSE_FORK=true, and the waitloop guard honours it" {
  YSG_RUNTIME=podman
  resolve_compose_cmd
  [ "$YSG_PODMAN_COMPOSE_FORK" = "true" ]

  COMPOSE_PROFILES=("letta")
  podman() {
    case "$1" in
      ps)      echo "docker_letta_1" ;;
      inspect)
        local _fmt="${3:-}"
        if [[ "$_fmt" == *"Health.Status"* ]]; then
          echo "healthy"
        elif [[ "$_fmt" == *"ExitCode"* ]]; then
          echo "0"
        else
          echo "exited"
        fi
        ;;
      start) return 0 ;;
      info)  return 0 ;;
      *)     return 1 ;;
    esac
  }
  run _podman_compose_letta_waitloop
  [ "$status" -eq 0 ]
  [[ "$output" == *"wait-loop"* ]]
}
