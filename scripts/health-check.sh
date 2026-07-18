#!/usr/bin/env bash
# scripts/health-check.sh — Yashigani v2.1.0
# last-updated: 2026-05-02T22:10:00+01:00 (fix: honour YSG_RUNTIME/YSG_PODMAN_RUNTIME in compose detection — gate #ROOTFUL-2)
# Post-install health verification with retries and spinner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
TIMEOUT=120

while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) shift; TIMEOUT="${1:-120}" ;;
    --help)
      cat <<'EOF'
Usage: scripts/health-check.sh [OPTIONS]

Post-install health check for all Yashigani services.
Polls each service with 5s retries up to --timeout seconds.

Options:
  --timeout SECONDS   Maximum wait time per service (default: 120)
  --help              Print this message

Services checked:
  Gateway   /healthz                    → HTTP 200
  Backoffice /healthz                   → HTTP 200
  Postgres  pg_isready                  → ready
  Redis     redis-cli ping              → PONG
  OPA       /health                     → {"status":"ok"}
  Ollama    /api/tags                   → HTTP 200

Reads YASHIGANI_TLS_DOMAIN from .env in project root (if present).
EOF
      exit 0
      ;;
    *) printf "Unknown option: %s\nRun with --help for usage.\n" "$1" >&2; exit 1 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Source platform detection (for color vars)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Load .env for domain info
# ---------------------------------------------------------------------------
YASHIGANI_TLS_DOMAIN="${YASHIGANI_TLS_DOMAIN:-}"
ENV_FILE="${PROJECT_ROOT}/docker/.env"
[ ! -f "$ENV_FILE" ] && ENV_FILE="${PROJECT_ROOT}/.env"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -o allexport
  # Source only safe KEY=VALUE pairs, ignoring comments and blanks
  while IFS='=' read -r key value; do
    case "$key" in
      ''|\#*) continue ;;
    esac
    # Strip inline comments from value
    value="${value%%#*}"
    # Strip surrounding quotes
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    # Trim trailing whitespace
    value="${value%"${value##*[![:space:]]}"}"
    export "$key"="$value" 2>/dev/null || true
  done < "$ENV_FILE"
  set +o allexport
fi
DOMAIN="${YASHIGANI_TLS_DOMAIN:-localhost}"
# v2.23.1: Caddy maps host port YASHIGANI_HTTPS_PORT → container :443.
# Demo installs default to 8443; production to 443. The external curl check
# must hit the HOST port, not :443.
HTTPS_PORT="${YASHIGANI_HTTPS_PORT:-443}"

# ---------------------------------------------------------------------------
# Color/print helpers
# ---------------------------------------------------------------------------
_ok()    { printf "${YSG_GREEN}[OK]${YSG_RESET}    %s\n"  "$*"; }
_fail()  { printf "${YSG_RED}[FAIL]${YSG_RESET}  %s\n"    "$*" >&2; }
_info()  { printf "${YSG_BLUE}[INFO]${YSG_RESET}  %s\n"   "$*"; }
_warn()  { printf "${YSG_YELLOW}[WARN]${YSG_RESET}  %s\n" "$*"; }

# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------
_spinner_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
_spin_pid=""

_spinner_start() {
  local label="$1"
  if [ -t 1 ]; then
    (
      i=0
      while true; do
        char="${_spinner_chars:$(( i % ${#_spinner_chars} )):1}"
        printf "\r  %s  %s... " "$char" "$label"
        i=$(( i + 1 ))
        sleep 0.1
      done
    ) &
    _spin_pid=$!
  fi
}

_spinner_stop() {
  if [ -n "${_spin_pid:-}" ] && kill -0 "$_spin_pid" 2>/dev/null; then
    kill "$_spin_pid" 2>/dev/null || true
    wait "$_spin_pid" 2>/dev/null || true
    _spin_pid=""
    [ -t 1 ] && printf "\r%60s\r" " "
  fi
}
trap '_spinner_stop' EXIT

# ---------------------------------------------------------------------------
# Retry-with-timeout helper
# $1 = service label
# $2 = check command (string, evaluated)
# Returns 0 on success, 1 on timeout
# ---------------------------------------------------------------------------
_wait_for() {
  local label="$1"
  local check_cmd="$2"
  local deadline=$(( $(date +%s) + TIMEOUT ))

  _spinner_start "$label"

  while [ "$(date +%s)" -lt "$deadline" ]; do
    if eval "$check_cmd" >/dev/null 2>&1; then
      _spinner_stop
      _ok "$label"
      return 0
    fi
    sleep 5
  done

  _spinner_stop
  return 1
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------
FAILED_SERVICES=()

_check_http() {
  local label="$1"
  local url="$2"
  local extra_args="${3:-}"

  if ! _wait_for "$label" \
    "curl --silent --fail --insecure --max-time 5 ${extra_args} '${url}' -o /dev/null"; then
    _fail "$label — timed out after ${TIMEOUT}s: ${url}"
    FAILED_SERVICES+=("$label")
  fi
}

  # ---------------------------------------------------------------------------
# Runtime binary detection (Docker or Podman) — NOT compose-tool selection.
#
# FINDING-V412-RESTART-002 / YSG-RISK-091 (measured, r2 restart leg, macOS
# podman-6 rootless, 2026-07-18): this file used to have its own compose-tool
# selector (_compose_cmd(), picking between "docker compose" / "docker-compose"
# / "podman compose" / "podman-compose") that was independent of, and could
# disagree with, install.sh's resolve_compose_cmd(). In particular it had no
# guard against podman-compose's broken 1.6.x release (install.sh's
# _podman_compose_usable() explicitly excludes that version), so on a host
# with podman-compose 1.6.x installed alongside a podman-6 client, this file
# selected podman-compose (Python — constructs container names as
# "${project}_${service}_1", underscore) even though install.sh actually
# built/brought up the stack via native podman compose v2 ("${project}-
# ${service}-N", hyphen). Every "exec by service name" check then failed
# with "Error: no container with name or ID '<project>_<service>_1' found"
# against a container that was, in fact, up and Healthy under its real
# (hyphen) name — install.sh exited 1 on a fully healthy stack.
#
# Fix: never let a compose tool construct or resolve the container name.
# Detect only the underlying RUNTIME BINARY (podman vs docker — both
# container-naming schemes sit on top of the same binary/socket either way)
# and resolve the actual container via ysg_resolve_compose_container()
# (compose labels, scheme-agnostic — see that function), then exec/logs
# directly against the resolved name. This also fixes a second, independent
# bug in the same code path: the log-tail fallback derived the compose
# service name from the display label ("OPA" -> "opa"), but the real
# compose service is "policy" — see _ysg_svc_name_for_label().
# ---------------------------------------------------------------------------
_ysg_runtime_bin() {
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]]; then
    echo "podman"; return
  fi
  if [[ "${YSG_RUNTIME:-}" == "docker" ]]; then
    echo "docker"; return
  fi
  # Auto-detect: prefer Docker when its daemon is actually reachable.
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "docker"; return
  fi
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    echo "podman"; return
  fi
  echo "docker"  # last-resort fallback, matches prior behaviour
}
RUNTIME_BIN="$(_ysg_runtime_bin)"

# ---------------------------------------------------------------------------
# ysg_resolve_compose_container <runtime-binary> <project> <service>
# Scheme-agnostic container-name resolution. Prints the first matching
# RUNNING container's real name to stdout; prints nothing and returns 1 on
# no match (callers MUST check — never assume a "-1"/"_1" suffix).
#
# Positive derivation over inference: queries the RUNTIME via compose
# labels (stamped by every compose implementation this codebase supports,
# regardless of naming scheme) rather than guessing/constructing a name or
# sniffing the compose-tool version. Falls back to a scheme-agnostic
# name-pattern match (bracket class covers both separators) if labels are
# ever absent. Same pattern already proven in uninstall.sh's
# _list_project_containers() and install.sh's own copy of this function —
# kept byte-identical to install.sh's; if you change one, change both.
# ---------------------------------------------------------------------------
ysg_resolve_compose_container() {
  local _rt="${1:?ysg_resolve_compose_container: runtime binary required}"
  local _proj="${2:?ysg_resolve_compose_container: project required}"
  local _svc="${3:?ysg_resolve_compose_container: service required}"
  local _name="" _label_prefix

  # Primary: compose labels. Stamped by every compose implementation this
  # codebase supports, regardless of container-naming scheme.
  for _label_prefix in "com.docker.compose" "io.podman.compose"; do
    _name="$("$_rt" ps \
      --filter "label=${_label_prefix}.project=${_proj}" \
      --filter "label=${_label_prefix}.service=${_svc}" \
      --format '{{.Names}}' 2>/dev/null | head -1)"
    if [[ -n "$_name" ]]; then
      printf '%s\n' "$_name"
      return 0
    fi
  done

  # Fallback: scheme-agnostic name pattern (bracket class matches either
  # separator) in case labels are ever absent.
  _name="$("$_rt" ps \
    --filter "name=^${_proj}[_-]${_svc}[_-]" \
    --format '{{.Names}}' 2>/dev/null | head -1)"
  if [[ -n "$_name" ]]; then
    printf '%s\n' "$_name"
    return 0
  fi

  return 1
}

# Maps a health-check DISPLAY label to the real compose service name. Only
# OPA differs (compose service is "policy", not "opa") — every other label
# already lowercases to its real service name.
_ysg_svc_name_for_label() {
  case "$1" in
    OPA) echo "policy" ;;
    *) printf '%s' "$1" | tr '[:upper:]' '[:lower:]' ;;
  esac
}

_check_compose_exec() {
  local label="$1"
  local service="$2"
  local cmd="$3"
  local expect="${4:-}"
  local proj="${COMPOSE_PROJECT_NAME:-docker}"

  # Re-resolve the container on every retry (inside _wait_for's eval loop)
  # so a not-yet-created container is tolerated exactly as the old
  # compose-exec retry was — see FINDING-V412-RESTART-002.
  local check
  if [ -n "$expect" ]; then
    check="_ctr=\$(ysg_resolve_compose_container '${RUNTIME_BIN}' '${proj}' '${service}' 2>/dev/null); [ -n \"\$_ctr\" ] && ${RUNTIME_BIN} exec -i \"\$_ctr\" ${cmd} 2>/dev/null | grep -q '${expect}'"
  else
    check="_ctr=\$(ysg_resolve_compose_container '${RUNTIME_BIN}' '${proj}' '${service}' 2>/dev/null); [ -n \"\$_ctr\" ] && ${RUNTIME_BIN} exec -i \"\$_ctr\" ${cmd}"
  fi

  if ! _wait_for "$label" "$check"; then
    _fail "$label — timed out after ${TIMEOUT}s"
    FAILED_SERVICES+=("$label")
  fi
}

# ---------------------------------------------------------------------------
# Run checks
# ---------------------------------------------------------------------------
_info "Starting health checks (timeout: ${TIMEOUT}s per service)..."
printf "\n"

# 1. Gateway — try via Caddy (HTTPS on host port), fall back to container exec.
# v2.23.1: gateway now terminates mTLS, so the container-exec fallback must
# present a client cert from /run/secrets (the in-container healthcheck uses
# the same pattern — see Dockerfile.gateway HEALTHCHECK).
if ! _wait_for "Gateway" \
  "curl --silent --fail --insecure --max-time 5 --resolve '${DOMAIN}:${HTTPS_PORT}:127.0.0.1' 'https://${DOMAIN}:${HTTPS_PORT}/healthz' -o /dev/null 2>/dev/null"; then
  _info "Trying Gateway via container exec..."
  _check_compose_exec "Gateway" "gateway" \
    "python3 -c \"import ssl, urllib.request; c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); c.load_cert_chain('/run/secrets/gateway_client.crt','/run/secrets/gateway_client.key'); urllib.request.urlopen('https://localhost:8080/healthz', context=c)\""
fi

# 2. Backoffice — try via Caddy first, fall back to mTLS container exec.
# v2.23.1 retro #3n: use /login (Caddy-routed to backoffice, unauth-200) instead
# of /admin/healthz which hits the admin-auth wall and always 401s → falls to
# the slow container-exec path. /login 200 proves end-to-end Caddy→backoffice.
if ! _wait_for "Backoffice" \
  "curl --silent --fail --insecure --max-time 5 --resolve '${DOMAIN}:${HTTPS_PORT}:127.0.0.1' 'https://${DOMAIN}:${HTTPS_PORT}/login' -o /dev/null 2>/dev/null"; then
  _info "Trying Backoffice via container exec..."
  _check_compose_exec "Backoffice" "backoffice" \
    "python3 -c \"import ssl, urllib.request; c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); c.load_cert_chain('/run/secrets/backoffice_client.crt','/run/secrets/backoffice_client.key'); urllib.request.urlopen('https://localhost:8443/healthz', context=c)\""
fi

# 3. Postgres
_check_compose_exec "Postgres" "postgres" \
  "pg_isready -U yashigani_admin" "accepting connections"

# 4. Redis — v2.23.1: TLS-only on 6380 with client-cert auth.
# Uses redis_client.crt mounted into the redis container (same cert the
# compose healthcheck uses). See docker/docker-compose.yml redis service.
_check_compose_exec "Redis" "redis" \
  "sh -c 'redis-cli --tls --cert /run/secrets/redis_client.crt --key /run/secrets/redis_client.key --cacert /run/secrets/ca_root.crt -p 6380 -a \"\$(cat /run/secrets/redis_password)\" ping 2>/dev/null'" "PONG"

# 5. OPA — internal network only, check via docker compose exec
_check_compose_exec "OPA" "policy" "/opa eval true"

# 6. Ollama — internal network only, check via docker compose exec
_check_compose_exec "Ollama" "ollama" "bash -c '</dev/tcp/localhost/11434'"

# ---------------------------------------------------------------------------
# On failure: print logs for each failed service
# ---------------------------------------------------------------------------
if [ "${#FAILED_SERVICES[@]}" -gt 0 ]; then
  printf "\n${YSG_RED}The following services failed health checks:${YSG_RESET}\n"
  for svc in "${FAILED_SERVICES[@]}"; do
    printf "  - %s\n" "$svc"
  done

  printf "\n${YSG_YELLOW}Tailing last 20 lines of logs for failed services:${YSG_RESET}\n"
  for svc in "${FAILED_SERVICES[@]}"; do
    # FINDING-V412-RESTART-002 / YSG-RISK-091: resolve the real compose
    # service name (OPA's display label lowercases to "opa" but the real
    # service is "policy") and the real container name (scheme-agnostic —
    # was previously delegated to whichever compose tool _compose_cmd()
    # happened to pick, which could disagree with the tool that actually
    # created the stack) instead of guessing either.
    local_svc_name="$(_ysg_svc_name_for_label "$svc")"
    printf "\n--- %s logs ---\n" "$svc"
    # `|| true` is required here: a "no running container found" result is
    # a legitimate, expected outcome this block explicitly checks for below
    # (not a script-fatal error) — without it, `set -e` would silently abort
    # the whole health-check script the first time resolution comes up
    # empty (e.g. Ollama in host-relay mode, or any other failed service
    # whose container never started at all), before the exit-1 summary and
    # remaining log tails ever print.
    local_ctr="$(ysg_resolve_compose_container "${RUNTIME_BIN}" "${COMPOSE_PROJECT_NAME:-docker}" "$local_svc_name" 2>/dev/null)" || true
    if [ -n "$local_ctr" ]; then
      ${RUNTIME_BIN} logs --tail=20 "$local_ctr" 2>/dev/null || \
        printf "(could not retrieve logs for %s)\n" "$local_svc_name"
    else
      printf "(could not find a running container for service '%s')\n" "$local_svc_name"
    fi
  done

  exit 1
fi

# ---------------------------------------------------------------------------
# Success banner
# ---------------------------------------------------------------------------

# Determine license tier from env
LICENSE_TIER="${YASHIGANI_LICENSE_TIER:-Community (10 agents max)}"

printf "\n"
printf "╔══════════════════════════════════════════╗\n"
printf "║   Yashigani v2.1.0 — Installation OK    ║\n"
printf "╠══════════════════════════════════════════╣\n"
printf "║ %-8s %-33s║\n" "URL:"     "https://${DOMAIN}"
printf "║ %-8s %-33s║\n" "Admin:"   "https://${DOMAIN}/admin"
printf "║ %-8s %-33s║\n" "Grafana:" "https://${DOMAIN}/grafana"
printf "║ %-8s %-33s║\n" "Tier:"    "${LICENSE_TIER}"
printf "╠══════════════════════════════════════════╣\n"
printf "║ Credentials printed at first run:       ║\n"
printf "║   docker compose logs backoffice        ║\n"
printf "╚══════════════════════════════════════════╝\n"
printf "\n"

_ok "All services healthy."
exit 0
