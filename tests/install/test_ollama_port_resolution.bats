#!/usr/bin/env bats
# tests/install/test_ollama_port_resolution.bats
#
# Unit tests for _resolve_host_ollama_port() — feat/v411-mac-ollama-port-detect-ask
#
# Tiago req 2026-07-13: macOS install must detect or ask for the host ollama
# port rather than hardcoding 11434 and aborting.
#
# Resolution order tested:
#   a. YASHIGANI_HOST_OLLAMA_PORT pre-set (env var or --ollama-port flag)
#   b. OLLAMA_HOST env parse — host:port, bare :port, and invalid fallthrough
#   c. Probe 127.0.0.1:11434 (normal case)
#   d. lsof-detect of a non-default port; also the case where lsof finds a
#      port but /api/tags is unreachable — must NOT accept that port
#   e. Non-interactive + unresolved → abort; message names --ollama-port
#
# Tests are fully hermetic:
#   - _resolve_host_ollama_port() extracted from install.sh via awk in setup()
#     and loaded via eval (same technique used by test_onboard_stepup.bats).
#   - curl and lsof overridden as shell functions (bash function lookup precedes
#     PATH; no stub scripts needed; functions inherited by called functions).
#   - log_* helpers write to stderr so manual `2>&1` captures are possible.
#   - NON_INTERACTIVE and YASHIGANI_HOST_OLLAMA_PORT controlled per-test.
#
# Call convention discipline (bats subshell behaviour):
#   `run func`  → captures $status + $output; but exported vars from func
#                 are NOT propagated back (subshell). Use ONLY for rc checks.
#   `func`      → runs in the current test scope; exported vars propagate.
#                 Use for variable-value assertions. Test fails if func exits !=0.
#   `out=$(...) || rc=$?`  → captures stderr+stdout AND exit status manually.
#                 Use when both message content AND rc are needed.
#
# Runs without a live ollama / container daemon.
#
# Requirements:
#   bats-core >= 1.10.0, bash 4.x+, shellcheck
#
# Run:
#   bats tests/install/test_ollama_port_resolution.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── Setup / teardown ──────────────────────────────────────────────────────────

setup() {
  # Extract _resolve_host_ollama_port() from install.sh via brace-count awk.
  # Every {/} inside the embedded lsof|awk subcommand is balanced (2 opens,
  # 2 closes — verified by manual count). Every ${VAR:-} param expansion is
  # also balanced. Net depth returns exactly to 0 at the function's own closing
  # brace, so extraction terminates at the right line.
  local fn_body
  fn_body="$(awk '
    /^_resolve_host_ollama_port\(\)[ \t]*\{/ { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}")"
  if [[ -z "$fn_body" ]]; then
    echo "ERROR: _resolve_host_ollama_port() not found in ${INSTALL_SH}" >&2
    return 1
  fi
  eval "$fn_body"

  # Required globals (normally set at top of install.sh)
  NON_INTERACTIVE=false
  YSG_PODMAN_RUNTIME=false
  YASHIGANI_HOST_OLLAMA_PORT=""
  unset OLLAMA_HOST 2>/dev/null || true

  # Logging stubs — write to stderr so `2>&1` captures in message tests work.
  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }

  # Default stubs — override per-test as needed.
  # curl: fail by default (port not reachable; exit 7 = connection refused)
  curl() { return 7; }
  # lsof: no ollama found by default
  lsof() { return 0; }
}

teardown() {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _resolve_host_ollama_port is defined exactly once in install.sh" {
  run grep -c '^_resolve_host_ollama_port()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: no hardcoded abort-on-11434 message in compose_up GPU blocks" {
  # The old inline probes said "Aborting — host ollama must be running on
  # 127.0.0.1:11434 before install." — replaced by _resolve_host_ollama_port.
  run grep -c 'Aborting — host ollama must be running on 127.0.0.1:11434 before install' "${INSTALL_SH}"
  [ "$output" -eq 0 ]
}

@test "LINT: compose_up calls _resolve_host_ollama_port before Mac Metal overlays" {
  local call_line docker_block_line
  call_line="$(grep -n '_resolve_host_ollama_port || return 1' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  docker_block_line="$(grep -n '_gpu_overlay_mac_metal=' "${INSTALL_SH}" | head -1 | cut -d: -f1)"
  [ -n "$call_line" ]
  [ -n "$docker_block_line" ]
  [ "$call_line" -lt "$docker_block_line" ]
}

# ── (a) Explicit YASHIGANI_HOST_OLLAMA_PORT / --ollama-port ──────────────────
# Success tests: direct call (no `run`) so exported var propagates back.

@test "(a) YASHIGANI_HOST_OLLAMA_PORT=11434 pre-set + reachable → rc=0, port=11434" {
  YASHIGANI_HOST_OLLAMA_PORT=11434
  curl() { return 0; }
  _resolve_host_ollama_port          # implicit rc=0 check; test fails if non-zero
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11434" ]
}

@test "(a) YASHIGANI_HOST_OLLAMA_PORT=19876 pre-set + reachable → rc=0, port=19876" {
  YASHIGANI_HOST_OLLAMA_PORT=19876
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "19876" ]
}

@test "(a) pre-set but unreachable → rc=1 (fail-closed)" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=29999
  # curl stub returns 7 (default: unreachable)
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "(a) abort message names the unreachable port" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=29999
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"29999"* ]]
}

@test "(a) abort message contains --ollama-port or YASHIGANI_HOST_OLLAMA_PORT hint" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=29999
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"--ollama-port"* ]] || [[ "$_out" == *"YASHIGANI_HOST_OLLAMA_PORT"* ]]
}

# ── (b) OLLAMA_HOST env parse ─────────────────────────────────────────────────

@test "(b) OLLAMA_HOST=127.0.0.1:11434 host:port form → port=11434, rc=0" {
  OLLAMA_HOST=127.0.0.1:11434
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11434" ]
}

@test "(b) OLLAMA_HOST=:11434 bare :port form → port=11434, rc=0" {
  OLLAMA_HOST=:11434
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11434" ]
}

@test "(b) OLLAMA_HOST=localhost:19876 non-default port → port=19876, rc=0" {
  OLLAMA_HOST=localhost:19876
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "19876" ]
}

@test "(b) OLLAMA_HOST=noport (no valid port) → falls through; non-interactive aborts with rc=1" {
  # Invalid OLLAMA_HOST falls through to probe step; with nothing reachable and
  # non-interactive, step (e) aborts.
  NON_INTERACTIVE=true
  OLLAMA_HOST=noport
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "(b) OLLAMA_HOST=127.0.0.1:29999 unreachable → rc=1, message names port 29999" {
  # When OLLAMA_HOST parses to a specific port, we try that port at the final
  # reachability gate. If unreachable: abort (fail-closed — do not silently
  # switch to 11434; the user explicitly configured this port).
  NON_INTERACTIVE=true
  OLLAMA_HOST=127.0.0.1:29999
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"29999"* ]]
}

# ── (c) Probe 127.0.0.1:11434 (normal case) ──────────────────────────────────

@test "(c) no env vars set, curl 200 on 11434 → rc=0, port=11434" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  curl() {
    case "$*" in *"127.0.0.1:11434"*) return 0 ;; *) return 7 ;; esac
  }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11434" ]
}

@test "(c) probe 11434 succeeds → lsof is never invoked" {
  # If 11434 is reachable, step (c) short-circuits; lsof must not be called.
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  local lsof_called=0
  curl() {
    case "$*" in *"127.0.0.1:11434"*) return 0 ;; *) return 7 ;; esac
  }
  lsof() { lsof_called=1; return 0; }
  _resolve_host_ollama_port
  [ "$lsof_called" -eq 0 ]
}

# ── (d) lsof-detect of a non-default port ────────────────────────────────────

@test "(d) 11434 not reachable, lsof finds ollama:19876, /api/tags 200 → port=19876, rc=0" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  # Stub lsof: emit a line matching actual lsof -nP -iTCP -sTCP:LISTEN format.
  # Column layout: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
  # NAME column ($9) is "host:PORT" or "*:PORT"; awk extracts the port.
  lsof() {
    echo "ollama  12345 user  3u  IPv4  0x99aabb  0t0  TCP 127.0.0.1:19876 (LISTEN)"
  }
  curl() {
    case "$*" in
      *"127.0.0.1:11434"*) return 7 ;;
      *"127.0.0.1:19876"*) return 0 ;;
      *) return 7 ;;
    esac
  }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "19876" ]
}

@test "(d) lsof finds port 19876 but /api/tags unreachable → must NOT accept; aborts rc=1" {
  # If lsof discovers a port but the API doesn't respond there, the port must
  # not be accepted — fall through to step (e) which aborts non-interactively.
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  lsof() {
    echo "ollama  12345 user  3u  IPv4  0x99aabb  0t0  TCP 127.0.0.1:19876 (LISTEN)"
  }
  # Neither 11434 nor 19876 responds
  curl() { return 7; }
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "(d) lsof wildcard *:19876 bind format → awk extracts port 19876 correctly" {
  # Ollama may bind 0.0.0.0 and lsof shows *:PORT in NAME column; awk must handle.
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  lsof() {
    echo "ollama  12345 user  3u  IPv4  0x99aabb  0t0  TCP *:19876 (LISTEN)"
  }
  curl() {
    case "$*" in
      *"127.0.0.1:11434"*) return 7 ;;
      *"127.0.0.1:19876"*) return 0 ;;
      *) return 7 ;;
    esac
  }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "19876" ]
}

@test "(d) lsof returns no ollama lines → falls through to step (e) abort" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  # lsof returns processes but none named ollama
  lsof() {
    echo "caddy   9999 user  3u  IPv4  0x11223  0t0  TCP *:443 (LISTEN)"
    echo "postgres 8888 user 3u  IPv4  0x44556  0t0  TCP 127.0.0.1:5432 (LISTEN)"
  }
  curl() { return 7; }
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

# ── (e) Non-interactive + unresolved → abort ─────────────────────────────────

@test "(e) non-interactive + all sources fail → rc=1" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  # curl unreachable, lsof finds nothing (both default stubs)
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "(e) abort message contains --ollama-port hint" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"--ollama-port"* ]]
}

@test "(e) abort message contains YASHIGANI_HOST_OLLAMA_PORT env hint" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"YASHIGANI_HOST_OLLAMA_PORT"* ]]
}

@test "(e) abort message contains OLLAMA_HOST alternative hint" {
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  local _out _rc=0
  _out=$(_resolve_host_ollama_port 2>&1) || _rc=$?
  [ "$_rc" -eq 1 ]
  [[ "$_out" == *"OLLAMA_HOST"* ]]
}

# ── Port validation ───────────────────────────────────────────────────────────

@test "port 0 is rejected (out of 1-65535 range)" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=0
  curl() { return 0; }
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "port 65536 is rejected (out of 1-65535 range)" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=65536
  curl() { return 0; }
  run _resolve_host_ollama_port
  [ "$status" -eq 1 ]
}

@test "port 65535 is accepted (upper boundary)" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=65535
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "65535" ]
}

@test "port 1 is accepted (lower boundary)" {
  NON_INTERACTIVE=true
  YASHIGANI_HOST_OLLAMA_PORT=1
  curl() { return 0; }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "1" ]
}

# ── Resolution priority order ─────────────────────────────────────────────────

@test "priority: YASHIGANI_HOST_OLLAMA_PORT wins over OLLAMA_HOST" {
  YASHIGANI_HOST_OLLAMA_PORT=11111
  OLLAMA_HOST=127.0.0.1:22222
  curl() { return 0; }    # both reachable
  _resolve_host_ollama_port
  # Must use 11111 (step a), not 22222 (step b)
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11111" ]
}

@test "priority: OLLAMA_HOST wins over probe-11434; probe not invoked when OLLAMA_HOST resolves" {
  unset YASHIGANI_HOST_OLLAMA_PORT 2>/dev/null || true
  OLLAMA_HOST=127.0.0.1:22222
  local probe_called=0
  curl() {
    case "$*" in
      *"127.0.0.1:22222"*) return 0 ;;
      *"127.0.0.1:11434"*) probe_called=1; return 0 ;;
      *) return 7 ;;
    esac
  }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "22222" ]
  # 11434 probe must not have been called (step b succeeded, step c skipped)
  [ "$probe_called" -eq 0 ]
}

# ── Backward compatibility ────────────────────────────────────────────────────

@test "backward-compat: no flags + ollama on 11434 → port=11434, rc=0" {
  # Normal case: ollama on the default port, no flags set.
  # Behaviour must be identical to pre-v411 (probe succeeds, install continues).
  unset YASHIGANI_HOST_OLLAMA_PORT OLLAMA_HOST 2>/dev/null || true
  NON_INTERACTIVE=true
  curl() {
    case "$*" in *"127.0.0.1:11434"*) return 0 ;; *) return 7 ;; esac
  }
  _resolve_host_ollama_port
  [ "${YASHIGANI_HOST_OLLAMA_PORT}" = "11434" ]
}

# ── Caddyfile env-expansion compatibility ─────────────────────────────────────

@test "Caddyfile.ollama-front uses {YASHIGANI_HOST_OLLAMA_PORT:11434} (env-parameterised)" {
  local caddyfile="${REPO_ROOT}/docker/Caddyfile.ollama-front"
  run grep -c 'reverse_proxy http://ollama:{$YASHIGANI_HOST_OLLAMA_PORT:11434}' "${caddyfile}"
  [ "$output" -ge 1 ]
}

@test "Caddyfile.ollama-front does NOT contain hardcoded reverse_proxy http://ollama:11434" {
  local caddyfile="${REPO_ROOT}/docker/Caddyfile.ollama-front"
  run grep -c 'reverse_proxy http://ollama:11434' "${caddyfile}"
  [ "$output" -eq 0 ]
}

# ── Compose overlay wiring ────────────────────────────────────────────────────

@test "docker-compose.gpu-mac-metal.yml: EGRESS_ALLOWLIST uses variable interpolation" {
  local f="${REPO_ROOT}/docker/docker-compose.gpu-mac-metal.yml"
  run grep -c 'YASHIGANI_CADDY_EGRESS_ALLOWLIST.*\${YASHIGANI_HOST_OLLAMA_PORT' "${f}"
  [ "$output" -ge 1 ]
}

@test "docker-compose.gpu-mac-metal.yml: YASHIGANI_HOST_OLLAMA_PORT passed to caddy container" {
  local f="${REPO_ROOT}/docker/docker-compose.gpu-mac-metal.yml"
  run grep -c 'YASHIGANI_HOST_OLLAMA_PORT.*\${YASHIGANI_HOST_OLLAMA_PORT' "${f}"
  [ "$output" -ge 1 ]
}

@test "docker-compose.gpu-mac-metal-podman.yml: EGRESS_ALLOWLIST uses variable interpolation" {
  local f="${REPO_ROOT}/docker/docker-compose.gpu-mac-metal-podman.yml"
  run grep -c 'YASHIGANI_CADDY_EGRESS_ALLOWLIST.*\${YASHIGANI_HOST_OLLAMA_PORT' "${f}"
  [ "$output" -ge 1 ]
}

@test "docker-compose.gpu-mac-metal-podman.yml: YASHIGANI_HOST_OLLAMA_PORT passed to caddy container" {
  local f="${REPO_ROOT}/docker/docker-compose.gpu-mac-metal-podman.yml"
  run grep -c 'YASHIGANI_HOST_OLLAMA_PORT.*\${YASHIGANI_HOST_OLLAMA_PORT' "${f}"
  [ "$output" -ge 1 ]
}
