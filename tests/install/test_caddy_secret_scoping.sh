#!/usr/bin/env bash
# tests/install/test_caddy_secret_scoping.sh
# Regression test for YSG-RISK-053 (per-service secret scoping, v4.1):
# caddy_client.{key,crt} + caddy_internal_hmac must live in docker/secrets-caddy/
# (single-file bind-mounted ONLY on caddy / gateway / backoffice), never in the
# flat docker/secrets/ dir shared by ~18 compose services. A compromised
# co-resident (redis, prometheus, langflow, ...) on the flat /run/secrets mount
# must have NO path to the Caddy mesh leaf key or the forward_auth HMAC
# (X-Caddy-Verified-Secret / X-SPIFFE-ID forgery → forward_auth bypass).
# PoC: testing_runs/yashigani/p1-w3p2a-laura-pocs/poc_secrets_key_exposure.sh
# last-updated: 2026-07-06T00:00:00+01:00 (new: YSG-RISK-053 close — scoping gate)
#
# Tests:
#   1.  Static (compose): caddy mounts all three files from ./secrets-caddy/ at
#       the UNCHANGED in-container paths (/run/secrets/<name>).
#   2.  Static (compose): gateway + backoffice mount ONLY the hmac from
#       ./secrets-caddy/.
#   3.  Static (compose): no other service references ./secrets-caddy/ —
#       exactly 5 mount lines in docker-compose.yml (3 caddy + 1 gateway +
#       1 backoffice).
#   4.  Static (install.sh): hmac generation writes to docker/secrets-caddy/.
#   5.  Static (install.sh): _relocate_caddy_scoped_secrets defined AND invoked
#       from _pki_run_issuer (post-mint sweep) AND from bootstrap_internal_pki
#       (legacy-layout upgrade migration).
#   6.  Static (install.sh): URI-SAN drift check resolves the caddy leaf at the
#       scoped path (prevents "missing → forced rotation" loop on upgrades).
#   7.  Behavioural: _relocate_caddy_scoped_secrets (actual install.sh code)
#       moves exactly the three scoped files out of a mock flat dir, leaves
#       INERT mountpoint stubs in their place (runtime requirement: a
#       single-file bind under a ro dir mount fails at container create
#       without an existing mountpoint — verified on Docker 29.4.1), leaves
#       other secrets untouched, and is idempotent on re-run (a stub is never
#       moved over the real scoped file).
#   8.  Static (restore.sh): _restore_caddy_scoped_secrets defined and called
#       (legacy backups must not re-expose the files via the flat dir).
#   9.  Static (uninstall.sh + scripts/uninstall.sh): secrets-caddy wiped on
#       --remove-volumes.
#  10.  install.sh bash -n syntax clean.
#  11.  install.sh + restore.sh + uninstall.sh shellcheck -S error clean
#       (if shellcheck available).
#
# Usage:
#   bash tests/install/test_caddy_secret_scoping.sh
#
# Requirements: bash 3.2+, no container runtime needed.
# Mock dirs live under tests/install/ — never under /tmp per project SOP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
RESTORE_SH="${REPO_ROOT}/restore.sh"
UNINSTALL_SH="${REPO_ROOT}/uninstall.sh"
SCRIPTS_UNINSTALL_SH="${REPO_ROOT}/scripts/uninstall.sh"
COMPOSE_YML="${REPO_ROOT}/docker/docker-compose.yml"

PASS_COUNT=0
FAIL_COUNT=0

_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# Helper: list of services (top-level "  name:" keys) whose volumes contain a
# given mount-source pattern. awk tracks the enclosing service block.
_services_with_mount() {
  local _pattern="$1"
  awk -v pat="$_pattern" '
    /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { svc=$1; sub(/:$/, "", svc) }
    index($0, pat) > 0 && $0 !~ /^[[:space:]]*#/ { print svc }
  ' "$COMPOSE_YML" | sort -u
}

# ---------------------------------------------------------------------------
# Test 1: compose — caddy mounts all three scoped files at unchanged paths
# ---------------------------------------------------------------------------
printf "\n--- Test 1: compose — caddy single-file mounts (3 files, unchanged paths) ---\n"
_t1_ok=true
for _m in \
  "./secrets-caddy/caddy_client.crt:/run/secrets/caddy_client.crt:ro" \
  "./secrets-caddy/caddy_client.key:/run/secrets/caddy_client.key:ro" \
  "./secrets-caddy/caddy_internal_hmac:/run/secrets/caddy_internal_hmac:ro"; do
  if _services_with_mount "$_m" | grep -qx "caddy"; then
    :
  else
    _fail "caddy is missing mount: ${_m}"
    _t1_ok=false
  fi
done
[[ "$_t1_ok" == "true" ]] && _pass "caddy mounts caddy_client.crt/.key + caddy_internal_hmac from ./secrets-caddy/ at unchanged /run/secrets paths"

# ---------------------------------------------------------------------------
# Test 2: compose — gateway + backoffice mount ONLY the hmac from secrets-caddy
# ---------------------------------------------------------------------------
printf "\n--- Test 2: compose — gateway/backoffice hmac-only scoped mounts ---\n"
_t2_ok=true
for _svc in gateway backoffice; do
  if _services_with_mount "./secrets-caddy/caddy_internal_hmac:/run/secrets/caddy_internal_hmac:ro" \
       | grep -qx "$_svc"; then
    :
  else
    _fail "${_svc} is missing the scoped caddy_internal_hmac mount"
    _t2_ok=false
  fi
  if _services_with_mount "./secrets-caddy/caddy_client.key" | grep -qx "$_svc"; then
    _fail "${_svc} mounts caddy_client.key — the mesh leaf key is CADDY-ONLY"
    _t2_ok=false
  fi
done
[[ "$_t2_ok" == "true" ]] && _pass "gateway + backoffice receive ONLY caddy_internal_hmac (no leaf key)"

# ---------------------------------------------------------------------------
# Test 3: compose — no other service references ./secrets-caddy/
# ---------------------------------------------------------------------------
printf "\n--- Test 3: compose — scoped mounts limited to caddy/gateway/backoffice ---\n"
_t3_services="$(_services_with_mount "./secrets-caddy/")"
_t3_unexpected="$(printf '%s\n' "$_t3_services" | grep -vE '^(caddy|gateway|backoffice)$' || true)"
_t3_count="$(grep -cE '^\s*-\s*\./secrets-caddy/' "$COMPOSE_YML" || true)"
if [[ -z "$_t3_unexpected" && "$_t3_count" == "5" ]]; then
  _pass "exactly 5 scoped mount lines, all on {caddy,gateway,backoffice}"
else
  _fail "unexpected ./secrets-caddy/ consumers or count != 5 (count=${_t3_count}; extra: ${_t3_unexpected:-none})"
fi

# ---------------------------------------------------------------------------
# Test 4: install.sh — hmac generated into docker/secrets-caddy/
# ---------------------------------------------------------------------------
printf "\n--- Test 4: install.sh — hmac generation targets docker/secrets-caddy/ ---\n"
if grep -q 'hmac_file="\${WORK_DIR}/docker/secrets-caddy/caddy_internal_hmac"' "$INSTALL_SH" \
   && ! grep -q 'hmac_file="\${secrets_dir}/caddy_internal_hmac"' "$INSTALL_SH"; then
  _pass "both generation sites (fresh + upgrade) write the hmac to docker/secrets-caddy/"
else
  _fail "hmac_file still points at the flat docker/secrets/ dir (or scoped path missing)"
fi

# ---------------------------------------------------------------------------
# Test 5: install.sh — relocation helper defined + wired into PKI flow
# ---------------------------------------------------------------------------
printf "\n--- Test 5: install.sh — _relocate_caddy_scoped_secrets defined + invoked ---\n"
_t5_def="$(grep -c '^_relocate_caddy_scoped_secrets()' "$INSTALL_SH" || true)"
_t5_calls="$(grep -c '_relocate_caddy_scoped_secrets || return 1' "$INSTALL_SH" || true)"
if [[ "$_t5_def" == "1" && "$_t5_calls" -ge 2 ]]; then
  _pass "relocation helper defined once and invoked at ${_t5_calls} fail-closed call sites"
else
  _fail "relocation helper missing or not wired (def=${_t5_def}, fail-closed calls=${_t5_calls})"
fi

# ---------------------------------------------------------------------------
# Test 6: install.sh — drift check resolves caddy leaf at scoped path
# ---------------------------------------------------------------------------
printf "\n--- Test 6: install.sh — URI-SAN drift check caddy special-case ---\n"
if awk '/_pki_detect_uri_san_drift\(\)/,/^}$/' "$INSTALL_SH" \
     | grep -q 'secrets-caddy/\${svc}_client.crt'; then
  _pass "drift check reads the caddy leaf from docker/secrets-caddy/"
else
  _fail "drift check would report the caddy leaf missing → forced rotation every upgrade"
fi

# ---------------------------------------------------------------------------
# Test 7: Behavioural — actual relocation function moves exactly the 3 files
# ---------------------------------------------------------------------------
printf "\n--- Test 7: Behavioural — _relocate_caddy_scoped_secrets (real code) ---\n"

_MOCK_WORK="${SCRIPT_DIR}/.mock_risk053_t7"
rm -rf "${_MOCK_WORK}"
mkdir -p "${_MOCK_WORK}/docker/secrets"
trap 'rm -rf "${_MOCK_WORK}"' EXIT

for _f in caddy_client.key caddy_client.crt caddy_internal_hmac \
          gateway_client.key ca_root.crt postgres_password; do
  printf 'mock-%s' "$_f" > "${_MOCK_WORK}/docker/secrets/${_f}"
done
chmod 0600 "${_MOCK_WORK}/docker/secrets/caddy_client.key"
chmod 0640 "${_MOCK_WORK}/docker/secrets/caddy_internal_hmac"

# Extract the REAL array + helper functions from install.sh (regression against
# the shipped code, not a re-implementation).
_t7_code="$(awk '
  /^_YSG_CADDY_SCOPED_SECRETS=/ { print; next }
  /^_YSG_SCOPED_STUB_MARKER=/ { print; next }
  /^_ysg_is_scoped_stub\(\)/,/^}$/ { print; next }
  /^_ysg_write_scoped_stub\(\)/,/^}$/ { print; next }
  /^_ensure_caddy_secrets_dir\(\)/,/^}$/ { print; next }
  /^_relocate_caddy_scoped_secrets\(\)/,/^}$/ { print; next }
' "$INSTALL_SH")"

_t7_result=$(WORK_DIR="${_MOCK_WORK}" bash -s <<EOF_T7
set -euo pipefail
WORK_DIR="${_MOCK_WORK}"
log_info()  { return 0; }
log_error() { echo "ERR:\$*" >&2; return 0; }
_pki_runtime_cmd() { echo "false"; }   # container fallback must never be needed here
${_t7_code}
_relocate_caddy_scoped_secrets || { echo "RELOCATE_FAILED"; exit 1; }
# Idempotency: second run must succeed as a no-op.
_relocate_caddy_scoped_secrets || { echo "RELOCATE_RERUN_FAILED"; exit 1; }
echo "RELOCATE_OK"
EOF_T7
) || true

_t7_ok=true
echo "$_t7_result" | grep -q "RELOCATE_OK" || { _fail "relocation function did not complete cleanly: ${_t7_result}"; _t7_ok=false; }
for _f in caddy_client.key caddy_client.crt caddy_internal_hmac; do
  # Real secret moved to the scoped dir, with the ORIGINAL mock content.
  if [[ "$(cat "${_MOCK_WORK}/docker/secrets-caddy/${_f}" 2>/dev/null)" != "mock-${_f}" ]]; then
    _fail "${_f}: scoped copy missing or clobbered (stub must never overwrite the real file)"
    _t7_ok=false
  fi
  # Flat path now holds an INERT mountpoint stub (required for the compose
  # single-file overlay under the ro flat mount) — never the real secret.
  if ! head -n 1 "${_MOCK_WORK}/docker/secrets/${_f}" 2>/dev/null | grep -q '^# YSG-RISK-053 mountpoint stub'; then
    _fail "${_f}: flat path is not an inert stub (missing mountpoint, or REAL secret still exposed)"
    _t7_ok=false
  fi
  if grep -q "mock-${_f}" "${_MOCK_WORK}/docker/secrets/${_f}" 2>/dev/null; then
    _fail "${_f}: secret material STILL present in flat docker/secrets/ — exposed to all services"
    _t7_ok=false
  fi
done
for _f in gateway_client.key ca_root.crt postgres_password; do
  [[ "$(cat "${_MOCK_WORK}/docker/secrets/${_f}" 2>/dev/null)" == "mock-${_f}" ]] \
    || { _fail "non-scoped file ${_f} was moved/altered — scope creep"; _t7_ok=false; }
done
# Mode preservation (rename, not copy): hmac stays 0640.
_t7_hmac_mode="$(stat -f '%OLp' "${_MOCK_WORK}/docker/secrets-caddy/caddy_internal_hmac" 2>/dev/null \
  || stat -c '%a' "${_MOCK_WORK}/docker/secrets-caddy/caddy_internal_hmac" 2>/dev/null || echo '')"
[[ "$_t7_hmac_mode" == "640" ]] || { _fail "hmac mode not preserved by relocation (got '${_t7_hmac_mode}', want 640)"; _t7_ok=false; }
[[ "$_t7_ok" == "true" ]] && _pass "real relocation code: 3 scoped files moved, inert stubs left at flat paths, extras untouched, modes preserved, idempotent"

# ---------------------------------------------------------------------------
# Test 8: restore.sh — scoped restore/relocation wired
# ---------------------------------------------------------------------------
printf "\n--- Test 8: restore.sh — _restore_caddy_scoped_secrets defined + called ---\n"
if grep -q '^_restore_caddy_scoped_secrets()' "$RESTORE_SH" \
   && grep -q '_restore_caddy_scoped_secrets "\${backup_dir}" || return 1' "$RESTORE_SH"; then
  _pass "restore.sh restores/relocates Caddy-scoped secrets fail-closed"
else
  _fail "restore.sh missing scoped-secrets restore — legacy backups would re-expose the files"
fi

# ---------------------------------------------------------------------------
# Test 9: uninstall — secrets-caddy wiped on --remove-volumes
# ---------------------------------------------------------------------------
printf "\n--- Test 9: uninstall.sh + scripts/uninstall.sh — secrets-caddy wipe ---\n"
if grep -q 'docker/secrets-caddy' "$UNINSTALL_SH" && grep -q 'docker/secrets-caddy' "$SCRIPTS_UNINSTALL_SH"; then
  _pass "both uninstall scripts wipe docker/secrets-caddy/"
else
  _fail "uninstall path(s) leave docker/secrets-caddy/ residuals"
fi

# ---------------------------------------------------------------------------
# Test 10: bash -n syntax
# ---------------------------------------------------------------------------
printf "\n--- Test 10: bash -n syntax ---\n"
_t10_ok=true
for _s in "$INSTALL_SH" "$RESTORE_SH" "$UNINSTALL_SH" "$SCRIPTS_UNINSTALL_SH"; do
  if ! bash -n "$_s" 2>/dev/null; then
    _fail "bash -n failed: ${_s}"
    _t10_ok=false
  fi
done
[[ "$_t10_ok" == "true" ]] && _pass "install.sh / restore.sh / uninstall.sh / scripts/uninstall.sh parse clean"

# ---------------------------------------------------------------------------
# Test 11: shellcheck -S error (skip if unavailable)
# ---------------------------------------------------------------------------
printf "\n--- Test 11: shellcheck -S error ---\n"
if command -v shellcheck >/dev/null 2>&1; then
  _t11_ok=true
  for _s in "$INSTALL_SH" "$RESTORE_SH" "$UNINSTALL_SH" "$SCRIPTS_UNINSTALL_SH"; do
    if ! shellcheck -S error "$_s" >/dev/null 2>&1; then
      _fail "shellcheck -S error failed: ${_s}"
      _t11_ok=false
    fi
  done
  [[ "$_t11_ok" == "true" ]] && _pass "shellcheck -S error clean on all four scripts"
else
  printf "  SKIP  shellcheck not installed\n"
fi

# ---------------------------------------------------------------------------
printf "\n=== YSG-RISK-053 scoping gate: %d passed, %d failed ===\n" "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
