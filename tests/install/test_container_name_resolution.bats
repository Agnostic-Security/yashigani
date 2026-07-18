#!/usr/bin/env bats
# tests/install/test_container_name_resolution.bats
#
# Unit tests for the scheme-agnostic container-name resolution added by
# fix/v412-compose-v2-container-naming (FINDING-V412-RESTART-002 / YSG-RISK-091).
#
# Root cause: podman-compose (Python) names containers
# "${project}_${service}_1" (underscore); native `podman compose` v2 /
# `docker compose` name them "${project}-${service}-N" (hyphen). Code that
# CONSTRUCTS a container name by string interpolation instead of asking the
# runtime silently targets a container that does not exist whenever the
# guessed scheme doesn't match the one actually in use.
#
# Functions under test:
#   ysg_resolve_compose_container  — install.sh (byte-identical copy also in
#                                    scripts/health-check.sh; extracted from
#                                    install.sh here, see LINT test below for
#                                    the byte-identity guarantee)
#   _ysg_runtime_bin               — scripts/health-check.sh only
#   _ysg_svc_name_for_label        — scripts/health-check.sh only
#
# Tests are fully hermetic (same technique as test_compose_engine_selection.bats):
#   - Functions extracted via brace-count awk.
#   - `podman`/`docker` are stubbed as shell functions backed by a small
#     fixture table of simulated containers (both naming schemes, both label
#     families, and label-less containers) — the stub parses the SAME
#     --filter arguments the real function passes (including running the
#     real bracket-class regex through bash's own `=~`), so a regression to
#     over-matching (e.g. "redis" filter also matching "budget-redis") would
#     be caught here, not just asserted away.
#   - No live container daemon or network required.
#
# Requirements: bats-core >= 1.10.0, bash 4.x+ (test harness only — the
# functions under test remain bash-3.2-safe, unaffected by the harness).
#
# Run:
#   bats tests/install/test_container_name_resolution.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
HEALTH_CHECK_SH="${REPO_ROOT}/scripts/health-check.sh"

# ── awk function extractor (brace-depth counting; same as
#    test_compose_engine_selection.bats / test_ollama_port_resolution.bats) ──
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

# ── Simulated container inventory ───────────────────────────────────────────
# Format: "name|com_project|com_service|io_project|io_service"
# "-" means the label is absent on that container for that prefix — mirrors
# a container created without that compose implementation's labels.
_FIXTURE_CONTAINERS=(
  # compose-v2 (native `podman compose` / `docker compose`) hyphen scheme,
  # com.docker.compose.* labels only — this is the standing r2 stack's
  # actual shape (confirmed via `podman inspect` on the live fixture).
  "proj1-postgres-1|proj1|postgres|-|-"
  "proj1-redis-1|proj1|redis|-|-"
  "proj1-budget-redis-1|proj1|budget-redis|-|-"
  # podman-compose (Python) underscore scheme, io.podman.compose.* labels
  # ONLY (isolated on purpose to exercise that fallback branch as its own
  # code path — Captain's review of 507acee7 confirmed real podman-compose
  # 1.6.0 ALSO stamps com.docker.compose.* alongside io.podman.compose.*, so
  # this scenario is deliberately narrower than reality: it proves the
  # io.podman.compose branch itself works, independent of whether it is
  # reachable in practice today).
  "legacy_postgres_1|-|-|legacy|postgres"
  # Label-less containers (defensive fallback path) — one of each separator.
  "bare1-widget-1|-|-|-|-"
  "bare2_widget_1|-|-|-|-"
)

# ── Setup / teardown ─────────────────────────────────────────────────────────

setup() {
  local _body

  _body="$(_extract_fn "ysg_resolve_compose_container" "${INSTALL_SH}")"
  if [[ -z "$_body" ]]; then
    echo "ERROR: ysg_resolve_compose_container() not found in ${INSTALL_SH}" >&2
    return 1
  fi
  eval "$_body"

  for _fn in _ysg_runtime_bin _ysg_svc_name_for_label; do
    _body="$(_extract_fn "$_fn" "${HEALTH_CHECK_SH}")"
    if [[ -z "$_body" ]]; then
      echo "ERROR: ${_fn}() not found in ${HEALTH_CHECK_SH}" >&2
      return 1
    fi
    eval "$_body"
  done

  # Fixture-backed `ps` stub shared by docker() and podman() — parses the
  # SAME --filter args the real function passes (two `label=` filters
  # AND'd, or one `name=` regex) and matches against _FIXTURE_CONTAINERS,
  # applying the real bracket-class regex via bash `=~` rather than a canned
  # per-call response — a real over-match regression would surface here.
  # shellcheck disable=SC2317
  _stub_ps() {
    if [[ "$1" != "ps" ]]; then return 1; fi
    shift
    local _filters=() _arg
    while [[ $# -gt 0 ]]; do
      _arg="$1"
      if [[ "$_arg" == "--filter" ]]; then
        shift
        _filters+=("$1")
      fi
      shift
    done

    local _row _name _com_proj _com_svc _io_proj _io_svc _f _match
    for _row in "${_FIXTURE_CONTAINERS[@]}"; do
      IFS='|' read -r _name _com_proj _com_svc _io_proj _io_svc <<< "$_row"
      _match=true
      for _f in "${_filters[@]}"; do
        case "$_f" in
          name=*)
            local _re="${_f#name=}"
            [[ "$_name" =~ $_re ]] || _match=false
            ;;
          label=com.docker.compose.project=*)
            [[ "$_com_proj" == "${_f#label=com.docker.compose.project=}" ]] || _match=false
            ;;
          label=com.docker.compose.service=*)
            [[ "$_com_svc" == "${_f#label=com.docker.compose.service=}" ]] || _match=false
            ;;
          label=io.podman.compose.project=*)
            [[ "$_io_proj" == "${_f#label=io.podman.compose.project=}" ]] || _match=false
            ;;
          label=io.podman.compose.service=*)
            [[ "$_io_svc" == "${_f#label=io.podman.compose.service=}" ]] || _match=false
            ;;
          *)
            _match=false
            ;;
        esac
      done
      [[ "$_match" == "true" ]] && printf '%s\n' "$_name"
    done
    return 0
  }
  # shellcheck disable=SC2317
  podman() { _stub_ps "$@"; }
  # shellcheck disable=SC2317
  docker() { _stub_ps "$@"; }

  # health-check.sh env inputs / logging stubs consumed by _ysg_runtime_bin.
  YSG_PODMAN_RUNTIME=""
  YSG_RUNTIME=""
}

teardown() {
  unset YSG_PODMAN_RUNTIME YSG_RUNTIME STUB_DOCKER_REACHABLE STUB_PODMAN_REACHABLE 2>/dev/null || true
}

# ── LINT: byte-identity guarantee between install.sh and health-check.sh ────

@test "LINT: ysg_resolve_compose_container is byte-identical in install.sh and scripts/health-check.sh" {
  local body_install body_hc
  body_install="$(_extract_fn "ysg_resolve_compose_container" "${INSTALL_SH}")"
  body_hc="$(_extract_fn "ysg_resolve_compose_container" "${HEALTH_CHECK_SH}")"
  [ -n "$body_install" ]
  [ -n "$body_hc" ]
  [ "$body_install" = "$body_hc" ]
}

@test "LINT: install.sh header cross-references scripts/health-check.sh (drift-guard symmetry)" {
  run grep -c 'DUPLICATED in scripts/health-check.sh' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "LINT: scripts/health-check.sh header cross-references install.sh's copy" {
  run grep -c "kept byte-identical to install.sh" "${HEALTH_CHECK_SH}"
  [ "$output" -ge 1 ]
}

# ── ysg_resolve_compose_container: label-based resolution ──────────────────

@test "resolve: com.docker.compose labels (compose-v2 hyphen scheme)" {
  run ysg_resolve_compose_container podman proj1 postgres
  [ "$status" -eq 0 ]
  [ "$output" = "proj1-postgres-1" ]
}

@test "resolve: io.podman.compose labels (podman-compose underscore scheme, isolated)" {
  run ysg_resolve_compose_container podman legacy postgres
  [ "$status" -eq 0 ]
  [ "$output" = "legacy_postgres_1" ]
}

@test "resolve: docker runtime binary also resolves via com.docker.compose labels" {
  run ysg_resolve_compose_container docker proj1 postgres
  [ "$status" -eq 0 ]
  [ "$output" = "proj1-postgres-1" ]
}

# ── ysg_resolve_compose_container: name-pattern fallback (label-less) ───────

@test "resolve: name-pattern fallback matches hyphen-separated literal name" {
  run ysg_resolve_compose_container podman bare1 widget
  [ "$status" -eq 0 ]
  [ "$output" = "bare1-widget-1" ]
}

@test "resolve: name-pattern fallback matches underscore-separated literal name" {
  run ysg_resolve_compose_container podman bare2 widget
  [ "$status" -eq 0 ]
  [ "$output" = "bare2_widget_1" ]
}

# ── ysg_resolve_compose_container: no substring over-match ──────────────────

@test "resolve: 'redis' does NOT over-match 'budget-redis' (label filter)" {
  run ysg_resolve_compose_container podman proj1 redis
  [ "$status" -eq 0 ]
  [ "$output" = "proj1-redis-1" ]
}

@test "resolve: 'budget-redis' resolves to its own container, not plain redis" {
  run ysg_resolve_compose_container podman proj1 budget-redis
  [ "$status" -eq 0 ]
  [ "$output" = "proj1-budget-redis-1" ]
}

# ── ysg_resolve_compose_container: loud failure on unresolvable service ─────

@test "resolve: unresolvable service returns 1 with empty stdout (no name guessed)" {
  run ysg_resolve_compose_container podman proj1 nonexistent-service
  [ "$status" -eq 1 ]
  [ -z "$output" ]
}

@test "resolve: unresolvable project returns 1 with empty stdout" {
  run ysg_resolve_compose_container podman no-such-project postgres
  [ "$status" -eq 1 ]
  [ -z "$output" ]
}

@test "resolve: missing required args fails closed (not a silent empty match)" {
  run ysg_resolve_compose_container podman proj1
  [ "$status" -ne 0 ]
}

# ── _ysg_runtime_bin: explicit overrides ────────────────────────────────────

@test "runtime_bin: YSG_RUNTIME=podman selects podman" {
  YSG_RUNTIME="podman"
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "podman" ]
}

@test "runtime_bin: YSG_RUNTIME=docker selects docker" {
  YSG_RUNTIME="docker"
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "docker" ]
}

@test "runtime_bin: YSG_PODMAN_RUNTIME=true selects podman even without YSG_RUNTIME" {
  YSG_PODMAN_RUNTIME="true"
  YSG_RUNTIME=""
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "podman" ]
}

# ── _ysg_runtime_bin: auto-detect (neither override set) ────────────────────

@test "runtime_bin: auto-detect prefers docker when its daemon is reachable" {
  YSG_RUNTIME=""
  YSG_PODMAN_RUNTIME=""
  # shellcheck disable=SC2317
  command() { [[ "$1" == "-v" && "$2" == "docker" ]] && return 0; return 1; }
  # shellcheck disable=SC2317
  docker() { [[ "$1" == "info" ]] && return 0; _stub_ps "$@"; }
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "docker" ]
}

@test "runtime_bin: auto-detect falls back to podman when docker unreachable" {
  YSG_RUNTIME=""
  YSG_PODMAN_RUNTIME=""
  # shellcheck disable=SC2317
  command() {
    [[ "$1" == "-v" && "$2" == "podman" ]] && return 0
    return 1
  }
  # shellcheck disable=SC2317
  podman() { [[ "$1" == "info" ]] && return 0; _stub_ps "$@"; }
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "podman" ]
}

@test "runtime_bin: last-resort default is docker when nothing is reachable" {
  YSG_RUNTIME=""
  YSG_PODMAN_RUNTIME=""
  # shellcheck disable=SC2317
  command() { return 1; }
  run _ysg_runtime_bin
  [ "$status" -eq 0 ]
  [ "$output" = "docker" ]
}

# ── _ysg_svc_name_for_label: display-label to compose-service-name mapping ──

@test "svc_name_for_label: OPA maps to 'policy' (the real compose service name)" {
  run _ysg_svc_name_for_label "OPA"
  [ "$status" -eq 0 ]
  [ "$output" = "policy" ]
}

@test "svc_name_for_label: Postgres lowercases to 'postgres'" {
  run _ysg_svc_name_for_label "Postgres"
  [ "$status" -eq 0 ]
  [ "$output" = "postgres" ]
}

@test "svc_name_for_label: Redis lowercases to 'redis'" {
  run _ysg_svc_name_for_label "Redis"
  [ "$status" -eq 0 ]
  [ "$output" = "redis" ]
}

@test "svc_name_for_label: Ollama lowercases to 'ollama'" {
  run _ysg_svc_name_for_label "Ollama"
  [ "$status" -eq 0 ]
  [ "$output" = "ollama" ]
}

@test "svc_name_for_label: Gateway lowercases to 'gateway'" {
  run _ysg_svc_name_for_label "Gateway"
  [ "$status" -eq 0 ]
  [ "$output" = "gateway" ]
}

@test "svc_name_for_label: Backoffice lowercases to 'backoffice'" {
  run _ysg_svc_name_for_label "Backoffice"
  [ "$status" -eq 0 ]
  [ "$output" = "backoffice" ]
}

@test "svc_name_for_label: unknown label falls back to plain lowercase" {
  run _ysg_svc_name_for_label "SomethingNew"
  [ "$status" -eq 0 ]
  [ "$output" = "somethingnew" ]
}
