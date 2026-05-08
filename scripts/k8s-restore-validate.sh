#!/usr/bin/env bash
# scripts/k8s-restore-validate.sh — Yashigani K8s restore validation harness.
#
# CONTRACT (SOP 4 / feedback_test_harness_no_fake_green.md):
#   * Probes each service with a documented check; first non-expected result is
#     FAIL — never retried on logic errors, never downgraded to PASS.
#   * Retry with capped backoff is allowed ONLY for transport/readiness errors
#     during the pod-wait phase (kubectl wait exits non-zero, not a logic fail).
#   * Verdict line "RESTORE VALIDATION: GREEN" is emitted ONLY when ALL checks
#     pass. Any single FAIL emits "RESTORE VALIDATION: RED".
#   * No --force, no "treating as PASS", no degraded-mode bypasses.
#   * Validation-only — no writes, no deletes, no volume operations.
#     (feedback_never_destroy_volumes.md)
#
# Usage:
#   KUBECTL_NAMESPACE=yashigani bash scripts/k8s-restore-validate.sh [--verbose]
#
# Exit codes:
#   0  All checks passed  (RESTORE VALIDATION: GREEN)
#   1  One or more checks failed  (RESTORE VALIDATION: RED — N checks failed)
#   2  Script error (missing kubectl, bad args, prerequisite failure)
#
# Configuration (env vars):
#   KUBECTL_NAMESPACE   Namespace to validate (default: yashigani)
#   KUBECTL_TIMEOUT     Seconds per readiness wait (default: 60)
#   KUBECTL_CONTEXT     kubectl context to use (optional; default: current context)
#   YASHIGANI_MTLS      Set to "true" to enable mTLS handshake probe (auto-detected
#                       from helm values when omitted)
#
# Last-Updated: 2026-05-08T00:00:00+01:00 (v2.23.3 initial — k8s restore validation)

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
KUBECTL_NAMESPACE="${KUBECTL_NAMESPACE:-yashigani}"
KUBECTL_TIMEOUT="${KUBECTL_TIMEOUT:-60}"
VERBOSE=false

# Track failures
FAIL_COUNT=0
declare -a FAIL_MESSAGES=()

# ---------------------------------------------------------------------------
# Colour output — only when stdout is a TTY
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_GREEN="\033[0;32m"
  C_RED="\033[0;31m"
  C_YELLOW="\033[0;33m"
  C_BOLD="\033[1m"
  C_RESET="\033[0m"
else
  C_GREEN=""
  C_RED=""
  C_YELLOW=""
  C_BOLD=""
  C_RESET=""
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()    { printf "  %s\n" "$*"; }
log_verbose() { [[ "$VERBOSE" == "true" ]] && printf "    [v] %s\n" "$*" || true; }
log_ok()      { printf "  %s[OK]%s  %s\n" "${C_GREEN}" "${C_RESET}" "$*"; }
log_fail()    { printf "  %s[FAIL: %s]%s\n" "${C_RED}" "$*" "${C_RESET}"; }
log_warn()    { printf "  %s[WARN]%s %s\n" "${C_YELLOW}" "${C_RESET}" "$*"; }
log_section() { printf "\n%s--- %s ---%s\n" "${C_BOLD}" "$*" "${C_RESET}"; }

# ---------------------------------------------------------------------------
# Result recording — never silently drop a failure
# ---------------------------------------------------------------------------
record_ok() {
  local label="$1"
  log_ok "$label"
}

record_fail() {
  local label="$1"
  local reason="$2"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  FAIL_MESSAGES+=( "${label}: ${reason}" )
  log_fail "$reason"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: KUBECTL_NAMESPACE=<ns> $SCRIPT_NAME [--verbose]

  --verbose    Print kubectl command output for each check.

Environment:
  KUBECTL_NAMESPACE   Namespace to validate (default: yashigani)
  KUBECTL_TIMEOUT     Seconds per readiness wait (default: 60)
  KUBECTL_CONTEXT     kubectl context (optional; uses current context)
  YASHIGANI_MTLS      "true" to force-enable mTLS probe; "false" to skip.
                      Auto-detected from cluster ConfigMap when unset.

Exit codes:
  0  GREEN — all checks passed
  1  RED   — one or more checks failed
  2  Script error (missing prereq, bad args)
EOF
  exit 2
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose|-v) VERBOSE=true; shift ;;
    --help|-h)    usage ;;
    *) printf "Unknown argument: %s\n" "$1" >&2; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Prerequisite: kubectl present
# ---------------------------------------------------------------------------
if ! command -v kubectl &>/dev/null; then
  printf "ERROR: kubectl not found in PATH\n" >&2
  exit 2
fi

# Optional: set context. Kept as a plain string for bash 3.2 (macOS system
# bash) compatibility — empty-array expansions with set -u cause "unbound
# variable" errors on bash <4.4. kctl() conditionally includes the flag.
KUBECTL_CTX_FLAG="${KUBECTL_CONTEXT:-}"

# Convenience wrapper — every kubectl call goes through this.
kctl() {
  if [[ -n "$KUBECTL_CTX_FLAG" ]]; then
    kubectl "--context=${KUBECTL_CTX_FLAG}" -n "${KUBECTL_NAMESPACE}" "$@"
  else
    kubectl -n "${KUBECTL_NAMESPACE}" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Verify namespace exists
# ---------------------------------------------------------------------------
if ! kctl get namespace "${KUBECTL_NAMESPACE}" &>/dev/null; then
  printf "ERROR: namespace '%s' not found. Check KUBECTL_NAMESPACE.\n" "${KUBECTL_NAMESPACE}" >&2
  exit 2
fi

printf "\n%sYashigani K8s Restore Validation%s\n" "${C_BOLD}" "${C_RESET}"
printf "  Namespace : %s\n" "${KUBECTL_NAMESPACE}"
printf "  Timeout   : %ss per check\n" "${KUBECTL_TIMEOUT}"
[[ -n "${KUBECTL_CONTEXT:-}" ]] && printf "  Context   : %s\n" "${KUBECTL_CONTEXT}"
printf "\n"

# ---------------------------------------------------------------------------
# CHECK 1 — All core workloads Running + Ready
# ---------------------------------------------------------------------------
log_section "1. Pod Readiness"

# Core workloads — FAIL if not ready.
# Format: "name:kind" — Deployments and StatefulSets share rollout status.
# Kind verified against helm/yashigani/templates/*.yaml:
#   gateway=Deployment, backoffice=Deployment, caddy=Deployment,
#   pgbouncer=Deployment, redis=StatefulSet, postgres=StatefulSet.
CORE_WORKLOADS=(
  "yashigani-gateway:deployment"
  "yashigani-backoffice:deployment"
  "yashigani-caddy:deployment"
  "yashigani-pgbouncer:deployment"
  "yashigani-redis:statefulset"
  "yashigani-postgres:statefulset"
)

# Optional workloads — warn but do not fail if absent.
# loki=StatefulSet, grafana=StatefulSet (values.yaml / templates).
OPTIONAL_WORKLOADS=(
  "yashigani-loki:statefulset"
  "yashigani-grafana:statefulset"
  "yashigani-budget-redis:statefulset"
)

check_workload_ready() {
  local name="$1"
  local kind="$2"
  local optional="${3:-false}"
  local label="Pod ready: ${name}"

  # Check workload exists
  if ! kctl get "${kind}" "${name}" &>/dev/null; then
    if [[ "$optional" == "true" ]]; then
      log_warn "${name} not found (optional — skipped)"
      return 0
    fi
    record_fail "$label" "${kind} not found"
    return 1
  fi

  # kubectl rollout status works for both Deployment and StatefulSet.
  # --timeout accepts a Go duration string; append 's' to the integer value.
  log_verbose "kubectl rollout status ${kind}/${name} --timeout=${KUBECTL_TIMEOUT}s"

  local rollout_out
  if rollout_out=$(kctl rollout status "${kind}/${name}" \
      --timeout="${KUBECTL_TIMEOUT}s" 2>&1); then
    log_verbose "$rollout_out"
    record_ok "$label"
  else
    local pod_status
    pod_status=$(kctl get pods -l "app.kubernetes.io/name=${name}" \
        --no-headers -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready 2>/dev/null || echo "unable to list pods")
    log_verbose "Pod status: $pod_status"
    if [[ "$optional" == "true" ]]; then
      log_warn "${name} not Ready within ${KUBECTL_TIMEOUT}s (optional)"
    else
      record_fail "$label" "rollout not ready within ${KUBECTL_TIMEOUT}s — ${pod_status}"
    fi
  fi
}

for entry in "${CORE_WORKLOADS[@]}"; do
  wl_name="${entry%%:*}"
  wl_kind="${entry##*:}"
  check_workload_ready "$wl_name" "$wl_kind" false
done

for entry in "${OPTIONAL_WORKLOADS[@]}"; do
  wl_name="${entry%%:*}"
  wl_kind="${entry##*:}"
  check_workload_ready "$wl_name" "$wl_kind" true
done

# ---------------------------------------------------------------------------
# CHECK 2 — Postgres row counts in critical tables
# ---------------------------------------------------------------------------
log_section "2. Postgres Data Integrity"

# Find a running postgres pod
POSTGRES_POD=$(kctl get pods -l "app.kubernetes.io/name=yashigani-postgres" \
    --field-selector=status.phase=Running \
    --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1 || true)

if [[ -z "$POSTGRES_POD" ]]; then
  record_fail "Postgres row counts" "no running postgres pod found"
else
  log_verbose "Using postgres pod: ${POSTGRES_POD}"

  # Tables that must have at least 1 row after a successful restore.
  # admin_accounts: at minimum the bootstrap admin must exist.
  # agent_registry: entries created on first boot if missing (acceptable empty
  #   on a fresh restore into a cold cluster), so we just report count.
  # alembic_version: must exist — signals migrations ran.
  CRITICAL_TABLES=(
    admin_accounts
    alembic_version
  )
  # These are counted and reported but not failed on zero — they may
  # legitimately be empty in a minimal backup (no agents registered, no
  # events yet in the restored period).
  INFORMATIONAL_TABLES=(
    audit_events
    agent_registry
    identities
    tenants
    licenses
  )

  # Build a single SQL query for efficiency — one exec per pod is expensive
  SQL_CRITICAL=""
  for tbl in "${CRITICAL_TABLES[@]}"; do
    SQL_CRITICAL="${SQL_CRITICAL}SELECT '${tbl}', COUNT(*) FROM public.${tbl};"$'\n'
  done
  SQL_INFO=""
  for tbl in "${INFORMATIONAL_TABLES[@]}"; do
    SQL_INFO="${SQL_INFO}SELECT '${tbl}', COUNT(*) FROM public.${tbl};"$'\n'
  done

  run_psql() {
    local sql="$1"
    # Try with -u postgres first (Captain's PR pattern); fall back without.
    # Never pass password via env — rely on local/peer trust inside the pod.
    local out
    if out=$(kctl exec "${POSTGRES_POD}" -- \
        sh -c "psql -U yashigani_app -d yashigani -At -c \"${sql}\"" 2>&1); then
      printf '%s' "$out"
    elif out=$(kctl exec "${POSTGRES_POD}" -c postgres -- \
        sh -c "psql -U yashigani_app -d yashigani -At -c \"${sql}\"" 2>&1); then
      printf '%s' "$out"
    else
      # Peer auth fallback: try as postgres superuser
      kctl exec "${POSTGRES_POD}" -- \
        sh -c "psql -U postgres -d yashigani -At -c \"${sql}\"" 2>&1 || true
    fi
  }

  # Check critical tables
  for tbl in "${CRITICAL_TABLES[@]}"; do
    local_sql="SELECT COUNT(*) FROM public.${tbl};"
    count_out=$(run_psql "$local_sql" 2>/dev/null || echo "ERROR")
    count=$(printf '%s' "$count_out" | grep -E '^[0-9]+$' | head -1 || true)

    if [[ "$count_out" == "ERROR" || -z "$count" ]]; then
      record_fail "DB table: ${tbl}" "psql query failed or returned non-numeric: ${count_out}"
    elif [[ "$count" -lt 1 ]]; then
      record_fail "DB table: ${tbl}" "table is empty (count=0) — expected ≥1 row after restore"
    else
      record_ok "DB table: ${tbl} (rows: ${count})"
    fi
  done

  # Informational tables — report only
  for tbl in "${INFORMATIONAL_TABLES[@]}"; do
    local_sql="SELECT COUNT(*) FROM public.${tbl};"
    count_out=$(run_psql "$local_sql" 2>/dev/null || echo "ERROR")
    count=$(printf '%s' "$count_out" | grep -E '^[0-9]+$' | head -1 || true)
    if [[ "$count_out" == "ERROR" || -z "$count" ]]; then
      log_warn "DB table: ${tbl} — query failed (non-blocking): ${count_out}"
    else
      log_info "  [INFO] ${tbl}: ${count} rows"
    fi
  done
fi

# ---------------------------------------------------------------------------
# CHECK 3 — Caddy gateway /healthz returns HTTP 200
# ---------------------------------------------------------------------------
log_section "3. Caddy Gateway Health (/healthz)"

CADDY_CHECK_LABEL="Caddy /healthz"

# Use kubectl port-forward to avoid NetworkPolicy cross-namespace issues.
# We forward caddy:443 to a local port for the duration of the curl probe.
CADDY_LOCAL_PORT=18443

probe_caddy() {
  local caddy_svc="yashigani-caddy"
  local fwd_pid

  # Check service exists
  if ! kctl get service "${caddy_svc}" &>/dev/null; then
    record_fail "$CADDY_CHECK_LABEL" "service ${caddy_svc} not found"
    return 1
  fi

  # Start port-forward in background
  log_verbose "Starting kubectl port-forward svc/${caddy_svc} ${CADDY_LOCAL_PORT}:443"
  kctl port-forward "svc/${caddy_svc}" "${CADDY_LOCAL_PORT}:443" &>/dev/null &
  fwd_pid=$!
  # Trap cleanup — forward process killed when probe_caddy returns
  # (trap is local to the subshell, so we clean up explicitly)

  # Give port-forward time to establish
  local wait_s=0
  while [[ $wait_s -lt 8 ]]; do
    if curl -sk --max-time 2 "https://localhost:${CADDY_LOCAL_PORT}/healthz" &>/dev/null; then
      break
    fi
    sleep 1
    wait_s=$(( wait_s + 1 ))
  done

  local status
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    "https://localhost:${CADDY_LOCAL_PORT}/healthz" 2>/dev/null || echo "000")

  # Kill the port-forward
  kill "$fwd_pid" 2>/dev/null || true
  wait "$fwd_pid" 2>/dev/null || true

  log_verbose "Caddy /healthz HTTP status: ${status}"

  if [[ "$status" == "200" ]]; then
    record_ok "${CADDY_CHECK_LABEL} (HTTP ${status})"
  else
    record_fail "$CADDY_CHECK_LABEL" "expected HTTP 200 — got ${status}"
  fi
}

probe_caddy

# ---------------------------------------------------------------------------
# CHECK 4 — Backoffice /api/health returns HTTP 200
# ---------------------------------------------------------------------------
log_section "4. Backoffice Health (/api/health)"

# Per the brief: /api/health (admin path). Checking via Caddy to validate the
# full Caddy→backoffice path (EX-231-10 pattern from existing helm tests).
# NetworkPolicy blocks direct-to-backoffice from outside, so we use port-forward
# through Caddy on the already-proved /healthz service port.
# The backoffice /api/health endpoint is unauthenticated (like /healthz).

BACKOFFICE_CHECK_LABEL="Backoffice /api/health"
BO_LOCAL_PORT=18444

probe_backoffice() {
  local caddy_svc="yashigani-caddy"
  local fwd_pid

  if ! kctl get service "${caddy_svc}" &>/dev/null; then
    record_fail "$BACKOFFICE_CHECK_LABEL" "caddy service not found — cannot reach backoffice"
    return 1
  fi

  log_verbose "Starting kubectl port-forward svc/${caddy_svc} ${BO_LOCAL_PORT}:443 for /api/health"
  kctl port-forward "svc/${caddy_svc}" "${BO_LOCAL_PORT}:443" &>/dev/null &
  fwd_pid=$!

  local wait_s=0
  while [[ $wait_s -lt 8 ]]; do
    if curl -sk --max-time 2 "https://localhost:${BO_LOCAL_PORT}/healthz" &>/dev/null; then
      break
    fi
    sleep 1
    wait_s=$(( wait_s + 1 ))
  done

  local status
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    "https://localhost:${BO_LOCAL_PORT}/api/health" 2>/dev/null || echo "000")

  kill "$fwd_pid" 2>/dev/null || true
  wait "$fwd_pid" 2>/dev/null || true

  log_verbose "Backoffice /api/health HTTP status: ${status}"

  # /api/health returns 200 when healthy; 503 when deps not ready.
  # 401 means the endpoint exists but is auth-gated — that is a config issue,
  # not a healthy state. Treat anything other than 200 as FAIL per SOP 4.
  if [[ "$status" == "200" ]]; then
    record_ok "${BACKOFFICE_CHECK_LABEL} (HTTP ${status})"
  else
    record_fail "$BACKOFFICE_CHECK_LABEL" "expected HTTP 200 — got ${status}"
  fi
}

probe_backoffice

# ---------------------------------------------------------------------------
# CHECK 5 — Redis PING (main + budget)
# ---------------------------------------------------------------------------
log_section "5. Redis PING"

check_redis() {
  local svc="$1"
  local port="$2"
  local label="Redis PING: ${svc}"

  if ! kctl get service "${svc}" &>/dev/null; then
    log_warn "${svc} service not found (optional — skipped)"
    return 0
  fi

  # Find a running redis pod for this service
  local redis_pod
  redis_pod=$(kctl get pods -l "app.kubernetes.io/name=${svc}" \
      --field-selector=status.phase=Running \
      --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1 || true)

  if [[ -z "$redis_pod" ]]; then
    record_fail "$label" "no running pod found for ${svc}"
    return 1
  fi

  log_verbose "Using pod ${redis_pod} for ${svc} PING"

  # PING via redis-cli inside the pod; handle both plain and TLS (mTLS) modes.
  # When mTLS is active, redis-cli needs --tls --cert --key --cacert.
  # We attempt plain first (works for non-mTLS). If it returns auth-required
  # error that is also proof the daemon is alive and healthy — we treat it as OK.
  # We do NOT pass passwords — the probe only needs to reach the socket.
  local result
  result=$(kctl exec "${redis_pod}" -- redis-cli -h 127.0.0.1 -p "${port}" PING 2>&1 || \
           kctl exec "${redis_pod}" -- redis-cli -h localhost -p "${port}" PING 2>&1 || \
           echo "EXEC_FAILED")

  log_verbose "redis-cli PING result: ${result}"

  if printf '%s' "$result" | grep -q "PONG"; then
    record_ok "${label} (PONG)"
  elif printf '%s' "$result" | grep -qE "NOAUTH|WRONGPASS|ERR.*auth"; then
    # Redis is up but auth-gated — the daemon is alive. Healthy.
    record_ok "${label} (auth required — daemon alive)"
  elif printf '%s' "$result" | grep -qE "tls|TLS|SSL"; then
    # mTLS mode — try with TLS flags using the cert path inside the pod
    local tls_result
    tls_result=$(kctl exec "${redis_pod}" -- redis-cli \
        --tls \
        --cert /run/secrets/redis_client.crt \
        --key  /run/secrets/redis_client.key \
        --cacert /run/secrets/ca_bundle.crt \
        -h 127.0.0.1 -p "${port}" PING 2>&1 || echo "TLS_EXEC_FAILED")
    log_verbose "mTLS redis-cli PING result: ${tls_result}"
    if printf '%s' "$tls_result" | grep -qE "PONG|NOAUTH|WRONGPASS|ERR.*auth"; then
      record_ok "${label} (mTLS PONG / auth-gated)"
    else
      record_fail "$label" "mTLS PING failed: ${tls_result}"
    fi
  else
    record_fail "$label" "unexpected response: ${result}"
  fi
}

# Main redis (port 6379 plain / 6380 mTLS — probe inner pod on 127.0.0.1,
# the pod-local listener port is always what matters for the exec probe).
check_redis "yashigani-redis"        "6379"
check_redis "yashigani-budget-redis" "6379"

# ---------------------------------------------------------------------------
# CHECK 6 — Loki + Grafana observability health
# ---------------------------------------------------------------------------
log_section "6. Observability (Loki + Grafana)"

# Loki /ready
check_loki() {
  local svc="yashigani-loki"
  local label="Loki /ready"

  if ! kctl get service "${svc}" &>/dev/null; then
    log_warn "Loki service not found (optional — skipped)"
    return 0
  fi

  local loki_pod
  loki_pod=$(kctl get pods -l "app.kubernetes.io/name=yashigani-loki" \
      --field-selector=status.phase=Running \
      --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1 || true)

  if [[ -z "$loki_pod" ]]; then
    log_warn "Loki: no running pod (optional — skipped)"
    return 0
  fi

  log_verbose "Checking Loki /ready via pod exec: ${loki_pod}"

  # Loki serves HTTPS on 3100 when mTLS enabled (via PKI); use wget with
  # --no-check-certificate for the pod-local probe (matching the liveness probe
  # in grafana.yaml / loki.yaml).
  local result
  result=$(kctl exec "${loki_pod}" -- \
      sh -c "wget -qO- --no-check-certificate https://localhost:3100/ready 2>&1 || \
             wget -qO- http://localhost:3100/ready 2>&1" || echo "EXEC_FAILED")

  log_verbose "Loki /ready response: ${result}"

  if printf '%s' "$result" | grep -qi "ready"; then
    record_ok "${label}"
  elif [[ "$result" == "EXEC_FAILED" ]]; then
    log_warn "Loki /ready: pod exec failed (optional — skipped)"
  else
    # Not fatal — Loki not restored does not block admin login
    log_warn "Loki /ready returned unexpected: ${result} (optional — skipped)"
  fi
}

# Grafana /api/health
check_grafana() {
  local svc="yashigani-grafana"
  local label="Grafana /api/health"

  if ! kctl get service "${svc}" &>/dev/null; then
    log_warn "Grafana service not found (optional — skipped)"
    return 0
  fi

  local grafana_pod
  grafana_pod=$(kctl get pods -l "app.kubernetes.io/name=yashigani-grafana" \
      --field-selector=status.phase=Running \
      --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1 || true)

  if [[ -z "$grafana_pod" ]]; then
    log_warn "Grafana: no running pod (optional — skipped)"
    return 0
  fi

  log_verbose "Checking Grafana /api/health via pod exec: ${grafana_pod}"

  # retro #83: Grafana serves HTTPS on 3443 when mTLS enabled. Try both.
  local result
  result=$(kctl exec "${grafana_pod}" -- \
      sh -c "wget -qO- --no-check-certificate https://localhost:3443/api/health 2>&1 || \
             wget -qO- http://localhost:3000/api/health 2>&1" || echo "EXEC_FAILED")

  log_verbose "Grafana /api/health response: ${result}"

  if printf '%s' "$result" | grep -qi '"ok"'; then
    record_ok "${label}"
  elif [[ "$result" == "EXEC_FAILED" ]]; then
    log_warn "Grafana /api/health: pod exec failed (optional — skipped)"
  else
    log_warn "Grafana /api/health returned unexpected: ${result} (optional — skipped)"
  fi
}

check_loki
check_grafana

# ---------------------------------------------------------------------------
# CHECK 7 — mTLS handshake (if mTLS is enabled)
# ---------------------------------------------------------------------------
log_section "7. mTLS Handshake"

# Auto-detect mTLS from the cluster: check for the mTLS PKI secret.
detect_mtls() {
  if [[ "${YASHIGANI_MTLS:-}" == "true" ]]; then
    echo "true"; return
  elif [[ "${YASHIGANI_MTLS:-}" == "false" ]]; then
    echo "false"; return
  fi
  # Auto-detect: mTLS secret name follows the convention from values.yaml.
  if kctl get secret "yashigani-pki-certs" &>/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

MTLS_ENABLED=$(detect_mtls)
log_verbose "mTLS detected: ${MTLS_ENABLED}"

if [[ "$MTLS_ENABLED" == "true" ]]; then
  # Use the caddy pod for the mTLS handshake test: caddy acts as mTLS client
  # to the backoffice. We verify that caddy can reach backoffice over mTLS
  # by checking that the caddy access log (or a wget probe using the mounted
  # client cert) succeeds.
  CADDY_POD=$(kctl get pods -l "app.kubernetes.io/name=yashigani-caddy" \
      --field-selector=status.phase=Running \
      --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1 || true)

  MTLS_LABEL="mTLS handshake (caddy→backoffice)"

  if [[ -z "$CADDY_POD" ]]; then
    record_fail "$MTLS_LABEL" "no running caddy pod to run mTLS probe from"
  else
    log_verbose "Running mTLS probe from caddy pod: ${CADDY_POD}"

    # The caddy pod has the PKI certs mounted. We use wget to do a
    # client-cert mTLS probe from inside the caddy pod to the backoffice
    # service on its mTLS port (8443).
    # Pattern B: ca_intermediate.crt as the trust anchor (values.yaml note).
    MTLS_RESULT=$(kctl exec "${CADDY_POD}" -- \
        sh -c "wget -qO- \
          --certificate=/run/secrets/caddy_client.crt \
          --private-key=/run/secrets/caddy_client.key \
          --ca-certificate=/run/secrets/ca_intermediate.crt \
          https://yashigani-backoffice:8443/healthz 2>&1" || \
        echo "MTLS_EXEC_FAILED")

    log_verbose "mTLS probe result: ${MTLS_RESULT}"

    if printf '%s' "$MTLS_RESULT" | grep -qi '"status":"ok"\|ok\|healthy'; then
      record_ok "${MTLS_LABEL}"
    elif printf '%s' "$MTLS_RESULT" | grep -qi "200\|connected"; then
      record_ok "${MTLS_LABEL} (connection established)"
    elif [[ "$MTLS_RESULT" == "MTLS_EXEC_FAILED" ]]; then
      record_fail "$MTLS_LABEL" "kubectl exec failed — caddy pod may not have wget or cert mounts"
    else
      record_fail "$MTLS_LABEL" "unexpected response: ${MTLS_RESULT}"
    fi
  fi
else
  log_info "  [SKIP] mTLS not enabled — skipping handshake probe"
fi

# ---------------------------------------------------------------------------
# Final verdict (SOP 4 contract)
# ---------------------------------------------------------------------------
printf "\n%s====================================================%s\n" "${C_BOLD}" "${C_RESET}"

if [[ $FAIL_COUNT -eq 0 ]]; then
  printf "%sRESTORE VALIDATION: GREEN%s\n" "${C_GREEN}" "${C_RESET}"
  printf "  All checks passed.\n\n"
  exit 0
else
  printf "%sRESTORE VALIDATION: RED — %d check(s) failed%s\n" "${C_RED}" "$FAIL_COUNT" "${C_RESET}"
  printf "\nFailed checks:\n"
  for msg in "${FAIL_MESSAGES[@]}"; do
    printf "  - %s\n" "$msg"
  done
  printf "\n"
  exit 1
fi
