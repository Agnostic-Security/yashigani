#!/usr/bin/env bash
# lib/pki_ownership.sh — Shared PKI service-key ownership map
# last-updated: 2026-05-22T12:00:00+01:00 (feat(install): YSG-SECRETS-DIST-002 REWORK — 1001:999 0640 for password secrets; fix wrong consumer-table comments — Iris rework + Laura A1)
# last-updated: 2026-05-18T00:00:00+01:00 (fix(secrets): YSG-SECRETS-DIST-001 — document multi-UID consumer class)
# last-updated: 2026-05-10T00:00:00+01:00 (fix(pki): GATE5-BUG-01 — shared ownership map; install + restore unified)
#
# Single source of truth for: service name → (container UID, key file mode).
# Sourced by install.sh and restore.sh. Adding a new service updates ONE place.
#
# Public surface:
#   pki_service_uid  <service>        prints the container UID (e.g. "1001")
#   pki_key_mode     <service>        prints the required key mode (e.g. "0600", "0640")
#   pki_services_all                  prints all known service names, one per line
#   pki_key_missing_is_error <service>
#                                     exits 1 if the service's key is mandatory
#                                     (i.e. its absence is operator error, not silence)
#
# Design note: prometheus_client.key is mode 0640 (group 1001) due to Pentest
# EX-231-10 — prometheus runs as UID 65534 (nobody) with group_add: ["1001"].
# All other service keys are mode 0600 (owner-read-write only).
#
# Multi-UID secret distribution class (YSG-SECRETS-DIST-001, 2026-05-18):
# REWORKED as of v2.24.0 (YSG-SECRETS-DIST-002 REWORK — Iris rework design + Laura GO-with-amendments).
# Prior 999:999 0600 scheme for password secrets caused Ava E2E gate FAIL at tip a3cf4a3:
# gateway + backoffice run as UID 1001 with cap_drop:[ALL] (no DAC_OVERRIDE); file-read
# of 999:999 0600 raised PermissionError → OSError fallback → empty env var → crash-loop.
#
# Corrected ownership in _pki_chown_client_keys() (install.sh):
#
#   redis_password      → 1001:999 0640
#     backoffice + gateway (UID 1001): FILE-READ as owner (primary path — NOT env var).
#       backoffice/entrypoint.py:78-83: open(redis_pwd_file) primary; OSError→env fallback.
#       gateway/_redis_url.py:80-86: open(pwd_file) primary; OSError→env fallback.
#     redis + budget-redis (UID 999, GID 999): read as group at startup (requirepass).
#     backoffice rotator (UID 1001): FILE-WRITE via atomic tmp+chmod(0o640)+os.chown(-1,999)+rename.
#       Rotator MUST chown -1:999 and chmod 0o640 atomically — see secrets/rotator.py (Tom scope,
#       Laura A2 amendment: explicit os.chown on tmp before rename to guarantee GID 999 post-rotation).
#
#   postgres_password   → 1001:999 0640
#     backoffice + gateway (UID 1001): FILE-READ as owner when DSN contains ${POSTGRES_PASSWORD}.
#       backoffice/entrypoint.py:334-341: open(pg_pwd_file) primary; OSError→warning.
#       gateway/entrypoint.py:215-219: same DSN-substitution FILE-READ pattern.
#     postgres (UID 999, GID 999): read as group at startup via POSTGRES_PASSWORD_FILE.
#     Same rotator write constraint as redis_password.
#
#   pgbouncer_authenticator_password → 70:999 0640
#     pgbouncer (UID 70): FILE-READ as owner — auth_query lookup user password source.
#     postgres (UID 999): FILE-READ as group at init time — 10-pgbouncer-auth.sh
#       ALTER ROLE pgbouncer_authenticator PASSWORD '...' creates the role on first init.
#     No rotation consumer (not in src/yashigani/secrets/rotator.py SecretName enum).
#     K8s path: fsGroup: 70 + defaultMode 0440 + postgres UID 70 → owner-read only;
#       no GID-999 needed in K8s (postgres pod runs as UID 70 there via fsGroup).
#     Cap_drop:[ALL] sanity: owner-read (UID 70 match) and group-read (GID 999 match)
#       both work without DAC_OVERRIDE. Symmetric with postgres_password 1001:999 0640.
#     NOT in _YSG_PKI_SERVICE_MAP below (that map covers TLS *_client.key files only).
#
#   yashigani_internal_bearer → 0:2002 0640  (UNCHANGED)
#     open-webui (UID 0) + letta (UID 0): read as owner.
#     langflow (UID 1000): reads via group GID 2002 (group_add:["2002"] retained
#     on langflow only in compose — Captain scope, YSG-SECRETS-DIST-002).
#     gateway + backoffice: ENV-ONLY (os.environ.get — no file DAC needed).
#
# Design authority: iris-v240-ysg-secrets-dist-002-rework-design.md
# Threat model: laura-v240-ysg-secrets-dist-002-rework-threat-model.md (GO-with-amendments)
# cap_drop:[ALL] + CAP_DAC_OVERRIDE interaction: compose lines 588–590.
#
# When adding a new service that reads a secret already owned by another UID,
# prefer a per-consumer dedicated bind-mount (YSG-RISK-049/050 pattern) rather
# than widening to a shared group. Only use GID-based sharing if per-consumer
# mounts are architecturally infeasible — document the reason in this file.
#
# Canonical service → UID reference:
#   caddy:0           Caddy root (cap_drop ALL strips DAC_OVERRIDE — must be 0:0)
#   gateway:1001      Yashigani gateway Python app
#   backoffice:1001   Yashigani backoffice Python app
#   redis:999         Redis official image UID
#   budget-redis:999  Budget Redis (same image)
#   pgbouncer:70      PgBouncer Alpine UID
#   postgres:999      Postgres official image UID
#   policy:1000       OPA (openpolicyagent/opa USER=1000:1000)
#   otel-collector:10001  OpenTelemetry Collector (ARG USER_UID=10001)
#   jaeger:10001      Jaeger all-in-one (ARG USER_UID=10001)
#   loki:10001        Grafana Loki (USER 10001)
#   promtail:0        Promtail root (accesses docker.sock + /var/lib/docker)
#   grafana:472       Grafana (USER 472 upstream Dockerfile)
#   prometheus:1001   Prometheus nobody (65534) + group_add 1001 → 0640 group-read
#   langflow:1000     Bucket-C — langflowai/langflow:1.9.2 USER langflow (UID 1000)
#   letta:0           Bucket-C — letta/letta:0.16.7 root (data at /root/.letta)
#   open-webui:0      Bucket-C — open-webui:v0.9.2 root (runs bash start.sh as root)
#   openclaw:1000     Bucket-C — openclaw Node image USER node (UID 1000); reads
#                     openclaw_gateway_token via env only (not file at runtime)
#
# Do NOT add services here that do NOT read a *_client.key from docker/secrets/.
# Service identities are defined in docker/service_identities.yaml.

# Guard against double-sourcing.
if [[ "${_YSG_PKI_OWNERSHIP_LOADED:-0}" == "1" ]]; then
  return 0
fi
_YSG_PKI_OWNERSHIP_LOADED=1

# ---------------------------------------------------------------------------
# Internal map: service → uid:mode
# Format: "service:uid:mode"
# ---------------------------------------------------------------------------
_YSG_PKI_SERVICE_MAP=(
  # Caddy: root inside container; cap_drop ALL strips DAC_OVERRIDE → must be
  # owned by UID 0 so root can read without DAC_OVERRIDE. V232-SMOKE-019.
  "caddy:0:0600"
  # Gateway + backoffice: Python app runs as UID 1001.
  "gateway:1001:0600"
  "backoffice:1001:0600"
  # Redis: official image UID 999.
  "redis:999:0600"
  "budget-redis:999:0600"
  # PgBouncer: Alpine-based, UID 70.
  "pgbouncer:70:0600"
  # Postgres: official image UID 999. 05-enable-ssl.sh reads key via `install`
  # as the postgres user after chown. Retro #3ad — v2.23.1.
  "postgres:999:0600"
  # pgbouncer-auth: dedicated outbound cert for pgbouncer→postgres (YSG-RISK-050 close).
  # UID 70 = pgbouncer container user. Mode 0600. Both pgbouncer instances read this cert
  # (pgbouncer and pgbouncer-letta share the same outbound server_tls_* cert pair).
  # CN=pgbouncer-auth; clientcert=verify-ca (not verify-full) is required on the pg_hba
  # catch-all — CN does not match role pgbouncer_authenticator.
  "pgbouncer-auth:70:0600"
  # letta-pgbouncer: edoburu/pgbouncer:v1.25.1-p0 — USER pgbouncer (UID 70).
  # Key chowned to 70:70, mode 0600. pgbouncer reads the key as UID 70 at startup.
  # No C4 violation — identical to the existing pgbouncer:70:0600 entry above.
  # Replaces the stunnel letta-stunnel:0:0600 entry (UID contradiction: stunnel
  # ran as UID 101 but pki_ownership.sh recorded UID 0 — clean install would have
  # failed at key-read). YSG-RISK-048 CLOSED 2026-05-20 via pgbouncer sidecar.
  "letta-pgbouncer:70:0600"
  # OPA: openpolicyagent/opa USER=1000:1000. V232-SMOKE-002.
  "policy:1000:0600"
  # OpenTelemetry Collector + Jaeger: ARG USER_UID=10001. V232-SMOKE-002.
  "otel-collector:10001:0600"
  "jaeger:10001:0600"
  # Loki: grafana/loki USER 10001. retro #84 (v2.23.2).
  "loki:10001:0600"
  # Promtail: root inside container (docker.sock access). retro #84 (v2.23.2).
  # chown to 0 is a no-op on Docker hosts (file already root-owned); on rootless
  # Podman hosts virtiofs UID remapping handles access. Key mode 0600.
  "promtail:0:0600"
  # Grafana: USER 472 upstream Dockerfile. retro #83 (v2.23.2).
  "grafana:472:0600"
  # Prometheus: runs as nobody (65534) but has group_add: ["1001"] in compose.
  # Key owned by 1001:1001, mode 0640 → group-readable by prometheus.
  # Pentest EX-231-10 closure.
  "prometheus:1001:0640"
)

# ---------------------------------------------------------------------------
# pki_service_uid <service>
#   Prints the container UID for the named service.
#   Returns 1 (and prints nothing) if service is not in the map.
# ---------------------------------------------------------------------------
pki_service_uid() {
  local _svc="$1"
  local _entry
  for _entry in "${_YSG_PKI_SERVICE_MAP[@]}"; do
    if [[ "${_entry%%:*}" == "$_svc" ]]; then
      # Strip leading service name to get uid:mode, then strip mode.
      local _rest="${_entry#*:}"
      printf '%s' "${_rest%%:*}"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# pki_key_mode <service>
#   Prints the required key file mode for the named service.
#   Returns 1 (and prints nothing) if service is not in the map.
# ---------------------------------------------------------------------------
pki_key_mode() {
  local _svc="$1"
  local _entry
  for _entry in "${_YSG_PKI_SERVICE_MAP[@]}"; do
    if [[ "${_entry%%:*}" == "$_svc" ]]; then
      # Strip service:uid: to get mode.
      local _rest="${_entry#*:}"
      printf '%s' "${_rest#*:}"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# pki_services_all
#   Prints all known service names, one per line.
# ---------------------------------------------------------------------------
pki_services_all() {
  local _entry
  for _entry in "${_YSG_PKI_SERVICE_MAP[@]}"; do
    printf '%s\n' "${_entry%%:*}"
  done
}

# ---------------------------------------------------------------------------
# pki_key_missing_is_error <service>
#   Returns 0 (is_error=true) if the named service's private key MUST exist
#   after PKI bootstrap — i.e. its absence is an operator error, not silence.
#
#   Returns 1 (is_error=false) if the service is unknown or its key is
#   optional (not all services in the map are mandatory on every install;
#   profile-gated services like langflow/letta/openclaw may be absent on
#   lean installs).
#
#   Mandatory services: those that are part of the core control plane and
#   must always have a client cert regardless of install profile.
#   Optional services: profile-gated (open-webui, langflow, letta, openclaw,
#   letta-pgbouncer) — their absence is normal on lean installs.
#
#   S8 (MEDIUM): this function was declared-but-unimplemented in prior versions.
#   Implemented v2.25.0 P1 W4.
# ---------------------------------------------------------------------------
pki_key_missing_is_error() {
  local _svc="$1"
  # If the service is not in the map at all, absence is not our error.
  if ! pki_service_uid "$_svc" >/dev/null 2>&1; then
    return 1
  fi
  # Profile-gated (optional) services — absence is NOT an operator error.
  case "$_svc" in
    open-webui|langflow|letta|letta-pgbouncer|openclaw)
      return 1
      ;;
    *)
      # All other services in the map are mandatory core services.
      return 0
      ;;
  esac
}

# ---------------------------------------------------------------------------
# pki_ownership_portability_check
#   Portability self-test: verify this file uses only bash-3.2-safe constructs.
#   Returns 0 if all checks pass.
#   Used by the S6 test gate in tests/install/test_pki_ownership.sh.
#
#   bash-3.2 incompatible constructs that must NOT appear in this file:
#     declare -A       (associative arrays — bash 4.0+)
#     ${var,,}         (lowercase expansion — bash 4.0+)
#     ${var^^}         (uppercase expansion — bash 4.0+)
#     mapfile / readarray  (bash 4.0+)
#
#   This function is informational — the static grep check in the test suite
#   is the authoritative gate.
# ---------------------------------------------------------------------------
pki_ownership_portability_check() {
  local _self
  _self="${BASH_SOURCE[0]:-${0}}"
  local _fail=0
  if grep -q 'declare -A' "$_self" 2>/dev/null; then
    printf '[pki_ownership] FAIL: declare -A (bash 4.0+) found in %s\n' "$_self" >&2
    _fail=1
  fi
  if grep -qE '\$\{[a-zA-Z_][a-zA-Z0-9_]*,,' "$_self" 2>/dev/null; then
    # Single quotes intentional: printing literal text, not shell-expanding it.
    # shellcheck disable=SC2016
    printf '[pki_ownership] FAIL: ${var,,} (bash 4.0+) found in %s\n' "$_self" >&2
    _fail=1
  fi
  if grep -qE '\$\{[a-zA-Z_][a-zA-Z0-9_]*\^\^' "$_self" 2>/dev/null; then
    # Single quotes intentional: printing literal text, not shell-expanding it.
    # shellcheck disable=SC2016
    printf '[pki_ownership] FAIL: ${var^^} (bash 4.0+) found in %s\n' "$_self" >&2
    _fail=1
  fi
  if grep -qE '^[[:space:]]*(mapfile|readarray)' "$_self" 2>/dev/null; then
    printf '[pki_ownership] FAIL: mapfile/readarray (bash 4.0+) found in %s\n' "$_self" >&2
    _fail=1
  fi
  return "$_fail"
}
