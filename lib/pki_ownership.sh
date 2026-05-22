#!/usr/bin/env bash
# lib/pki_ownership.sh — Shared PKI service-key ownership map
# last-updated: 2026-05-22T00:00:00+01:00 (feat(install): YSG-SECRETS-DIST-002 CLOSED — per-consumer ownership; GID 2002 narrowed to bearer+langflow)
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
# DISSOLVED as of v2.24.0 (YSG-SECRETS-DIST-002 CLOSED, Laura A1 amendment).
#
# All three former multi-UID members are now set to single per-consumer ownership
# in _pki_chown_client_keys(). GID 2002 is narrowed to one file + one service:
#
#   postgres_password   → 999:999 0600
#     Only postgres (UID 999) reads this directly via POSTGRES_PASSWORD_FILE.
#     gateway + backoffice receive it via .env env var — no file read.
#
#   redis_password      → 999:999 0600
#     redis + budget-redis (both UID 999) read as owner. gateway + backoffice
#     receive it via .env env var — no file read.
#
#   yashigani_internal_bearer → 0:2002 0640
#     open-webui (UID 0) + letta (UID 0): read as owner.
#     langflow (UID 1000): reads via group GID 2002 (group_add:["2002"] retained
#     on langflow only in compose — Captain scope, YSG-SECRETS-DIST-002).
#     gateway + backoffice receive it via .env env var — no file read.
#
# Design authority: iris-v240-ysg-secrets-dist-002-close-design.md (Option i)
# Blocking amendment: laura-v240-ysg-secrets-dist-002-close-threat-model.md (A1)
# cap_drop:[ALL] + CAP_DAC_OVERRIDE interaction that drove A1: compose lines 588–590.
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
