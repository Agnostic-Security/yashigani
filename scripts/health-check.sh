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

  # Detect compose command (Docker or Podman)
# Gate #ROOTFUL-2: honour YSG_RUNTIME / YSG_PODMAN_RUNTIME so the health-check
# uses the same compose backend as the install. Without this, _compose_cmd()
# picks docker compose when docker CLI is installed (even without a running
# daemon), and then _check_compose_exec fails silently for every service
# when the stack was started under rootful/rootless Podman.
_compose_cmd() {
  # Honour explicit runtime override first.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]]; then
    if command -v podman-compose >/dev/null 2>&1; then
      echo "podman-compose"; return
    fi
    if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
      echo "podman compose"; return
    fi
  fi
  if [[ "${YSG_RUNTIME:-}" == "docker" ]]; then
    echo "docker compose"; return
  fi
  # Auto-detect: prefer Docker when available and daemon is reachable;
  # fall back to Podman compose variants.
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "docker-compose"
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    echo "podman compose"
  elif command -v podman-compose >/dev/null 2>&1; then
    echo "podman-compose"
  else
    echo "docker compose"  # last-resort fallback
  fi
}
COMPOSE_CMD="$(_compose_cmd)"

_check_compose_exec() {
  local label="$1"
  local service="$2"
  local cmd="$3"
  local expect="${4:-}"

  local check
  if [ -n "$expect" ]; then
    check="${COMPOSE_CMD} -f '${PROJECT_ROOT}/docker/docker-compose.yml' \
      exec -T ${service} ${cmd} 2>/dev/null | grep -q '${expect}'"
  else
    check="${COMPOSE_CMD} -f '${PROJECT_ROOT}/docker/docker-compose.yml' \
      exec -T ${service} ${cmd}"
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
    # Map display name to compose service name
    local_svc_lower="$(printf '%s' "$svc" | tr '[:upper:]' '[:lower:]')"
    printf "\n--- %s logs ---\n" "$svc"
    ${COMPOSE_CMD} -f "${PROJECT_ROOT}/docker/docker-compose.yml" \
      logs --tail=20 "$local_svc_lower" 2>/dev/null || \
      printf "(could not retrieve logs for %s)\n" "$local_svc_lower"
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
