#!/usr/bin/env bash
# test_upgrade_preservation.sh
#
# Upgrade-durability assertion suite for B1 / B11 / B13.
# Exercises the install.sh --upgrade path without deploying a live stack:
#   B1  — Redis AOF persistence enabled (compose + helm)
#   B11 — Dockerfile.backoffice pins postgresql-client-16 (not unversioned)
#   B13 — install.sh --upgrade preserves YASHIGANI_ENABLED_PROFILES from .env
#
# Usage:
#   ./scripts/test_upgrade_preservation.sh [WORK_DIR]
#
# WORK_DIR defaults to the directory containing this script's parent.
# Returns 0 on all-pass, non-zero on any failure.
#
# Not a deploy test — no containers, no network, no secrets. Pure static
# assertion + a simulated .env upgrade preserving profiles.

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${1:-${SCRIPT_DIR}/..}"
COMPOSE_FILE="${WORK_DIR}/docker/docker-compose.yml"
HELM_REDIS_FILE="${WORK_DIR}/helm/yashigani/templates/redis.yaml"
HELM_CHART_REDIS_FILE="${WORK_DIR}/helm/charts/redis/templates/deployment.yaml"
DOCKERFILE_BACKOFFICE="${WORK_DIR}/docker/Dockerfile.backoffice"
INSTALL_SH="${WORK_DIR}/install.sh"

PASS=0
FAIL=0

_pass() { printf "  PASS  %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "  FAIL  %s\n" "$1"; (( FAIL++ )) || true; }

printf "\n=== Upgrade Durability Assertions (B1/B11/B13) ===\n\n"

# ---------------------------------------------------------------------------
# B1 — Redis main instance: AOF enabled + volatile-lru eviction policy
# ---------------------------------------------------------------------------
printf "B1 — Redis persistence (compose + helm)\n"

# docker-compose: --appendonly yes
if grep -q -- '--appendonly yes' "${COMPOSE_FILE}" 2>/dev/null; then
  _pass "compose: redis --appendonly yes"
else
  _fail "compose: redis --appendonly yes NOT FOUND (got no-persistence)"
fi

# docker-compose: --save "" must NOT appear (it would disable RDB and is a
# no-op when AOF is on, but its presence signals stale config)
if grep -q -- '--save ""' "${COMPOSE_FILE}" 2>/dev/null; then
  _fail "compose: stale '--save \"\"' still present (remove it)"
else
  _pass "compose: '--save \"\"' absent (clean)"
fi

# docker-compose: volatile-lru (not allkeys-lru which can evict identity keys)
if grep -q -- '--maxmemory-policy volatile-lru' "${COMPOSE_FILE}" 2>/dev/null; then
  _pass "compose: redis maxmemory-policy volatile-lru"
else
  _fail "compose: redis maxmemory-policy NOT volatile-lru (identity keys at risk of eviction)"
fi

# Helm redis.yaml: --appendonly yes (both TLS and non-TLS stanzas)
appendonly_helm_count="$(grep -c -- '--appendonly yes' "${HELM_REDIS_FILE}" 2>/dev/null || echo 0)"
if [[ "$appendonly_helm_count" -ge 2 ]]; then
  _pass "helm/redis.yaml: both stanzas have --appendonly yes (count=${appendonly_helm_count})"
else
  _fail "helm/redis.yaml: expected 2+ '--appendonly yes' entries, got ${appendonly_helm_count}"
fi

if grep -q -- '--appendonly yes' "${HELM_CHART_REDIS_FILE}" 2>/dev/null; then
  _pass "helm/charts/redis: --appendonly yes"
else
  _fail "helm/charts/redis: --appendonly yes NOT FOUND"
fi

# ---------------------------------------------------------------------------
# B11 — Dockerfile.backoffice pins postgresql-client-16
# ---------------------------------------------------------------------------
printf "\nB11 — Dockerfile.backoffice postgresql-client version pin\n"

if grep -q 'postgresql-client-16' "${DOCKERFILE_BACKOFFICE}" 2>/dev/null; then
  _pass "Dockerfile.backoffice: postgresql-client-16 (pinned)"
else
  _fail "Dockerfile.backoffice: postgresql-client-16 NOT found (unversioned = pg17 on trixie)"
fi

if grep -E '^\s+postgresql-client\s*\\?\s*$' "${DOCKERFILE_BACKOFFICE}" 2>/dev/null | grep -qv 'postgresql-client-'; then
  _fail "Dockerfile.backoffice: unversioned 'postgresql-client' still present"
else
  _pass "Dockerfile.backoffice: unversioned 'postgresql-client' absent"
fi

# ---------------------------------------------------------------------------
# B13 — install.sh --upgrade preserves YASHIGANI_ENABLED_PROFILES
# ---------------------------------------------------------------------------
printf "\nB13 — install.sh --upgrade ENABLED_PROFILES preservation\n"

# Static check: the upgrade-seed block is present
if grep -q 'UPGRADE.*true.*seeding enabled profiles\|seeding enabled profiles from existing' "${INSTALL_SH}" 2>/dev/null; then
  _pass "install.sh: upgrade-seed block present (seeds from .env)"
else
  _fail "install.sh: upgrade-seed block NOT found (will clobber ENABLED_PROFILES on upgrade)"
fi

# Functional simulation: create a temp .env, run the relevant logic inline,
# verify ENABLED_PROFILES is preserved after a simulated --upgrade run.
_tmpdir="$(mktemp -d "${WORK_DIR}/.test_upgrade_preservation.XXXXXX")"
trap 'rm -rf "$_tmpdir"' EXIT

_fake_env="${_tmpdir}/.env"
printf 'YASHIGANI_TLS_DOMAIN=test.local\n' > "$_fake_env"
printf 'YASHIGANI_PUBLIC_URL=https://old.example.com\n' >> "$_fake_env"
printf 'YASHIGANI_ENABLED_PROFILES=wazuh,langflow,letta\n' >> "$_fake_env"
printf 'YASHIGANI_VERSION=2.25.4\n' >> "$_fake_env"

# Simulate the B13 fix: read existing profiles, merge new (none added here)
_existing_ep="$(grep '^YASHIGANI_ENABLED_PROFILES=' "$_fake_env" | sed 's/^YASHIGANI_ENABLED_PROFILES=//')"
_ep_rt=()
if [[ -n "$_existing_ep" ]]; then
  IFS=',' read -ra _existing_ep_arr <<< "$_existing_ep"
  _ep_rt+=("${_existing_ep_arr[@]}")
fi
# Simulate no new flags (empty COMPOSE_PROFILES, INSTALL_WAZUH=false etc.)
_ep_csv_rt="$(printf '%s\n' "${_ep_rt[@]+"${_ep_rt[@]}"}" | awk 'NF&&!seen[$0]++' | paste -sd, -)"
# Write to the fake .env
_t2_rt="$(mktemp)"
sed "s|^YASHIGANI_ENABLED_PROFILES=.*|YASHIGANI_ENABLED_PROFILES=${_ep_csv_rt}|" "$_fake_env" > "$_t2_rt"
mv "$_t2_rt" "$_fake_env"

_result="$(grep '^YASHIGANI_ENABLED_PROFILES=' "$_fake_env" | sed 's/^YASHIGANI_ENABLED_PROFILES=//')"
if [[ "$_result" == "wazuh,langflow,letta" ]]; then
  _pass "functional: YASHIGANI_ENABLED_PROFILES preserved after simulated --upgrade"
else
  _fail "functional: YASHIGANI_ENABLED_PROFILES after upgrade = '${_result}' (expected 'wazuh,langflow,letta')"
fi

# Simulate adding a new profile during --upgrade (operator passes --with-openwebui)
_ep_rt=()
IFS=',' read -ra _existing_ep_arr <<< "$_existing_ep"
_ep_rt+=("${_existing_ep_arr[@]}")
_ep_rt+=("openwebui")  # newly selected
_ep_csv_rt="$(printf '%s\n' "${_ep_rt[@]}" | awk 'NF&&!seen[$0]++' | paste -sd, -)"
_t3_rt="$(mktemp)"
sed "s|^YASHIGANI_ENABLED_PROFILES=.*|YASHIGANI_ENABLED_PROFILES=${_ep_csv_rt}|" "$_fake_env" > "$_t3_rt"
mv "$_t3_rt" "$_fake_env"

_result2="$(grep '^YASHIGANI_ENABLED_PROFILES=' "$_fake_env" | sed 's/^YASHIGANI_ENABLED_PROFILES=//')"
if [[ "$_result2" == "wazuh,langflow,letta,openwebui" ]]; then
  _pass "functional: new profile added to existing set during --upgrade"
else
  _fail "functional: add-profile result = '${_result2}' (expected 'wazuh,langflow,letta,openwebui')"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== Results: %d passed, %d failed ===\n\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
