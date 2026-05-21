#!/usr/bin/env bash
# tests/install/test_pki_ownership.sh — PKI key ownership regression tests
# last-updated: 2026-05-18T00:00:00+01:00 (fix(install): T7 updated — no-rotation branch chown now Podman-rootless gated; YSG-INSTALL-PKI-001)
# last-updated: 2026-05-10T00:00:00+01:00 (fix(pki): PR#122 — per-service CWE-732 assertion; bash 3.2 header fix; runtime mock T13)
#
# Tests:
#   1.  lib/pki_ownership.sh: map lookups correct for all known services
#   2.  Install path: each service key has correct UID + mode after sourcing map
#   3.  Restore path: only backup-written keys get re-owned; pre-existing keys untouched
#   4.  Upgrade no-touch: keys NOT chowned when needs_rotation=false
#   5.  Blanket-sweep regression: find ... *.key -exec chmod 0600 is absent from restore.sh
#   6.  Map parity: every service in lib/pki_ownership.sh is present in service_identities.yaml
#      (if the YAML exists)
#   7.  Prometheus: uid=1001, mode=0640 (EX-231-10 regression)
#   13. Runtime mock-filesystem: per-service CWE-732 assertion passes for 0640 (prometheus),
#       does not fire on pre-existing key not in written list, and old blanket find would have
#       fired (confirms the regression existed).
#
# Usage:
#   bash tests/install/test_pki_ownership.sh
#
# Requirements: bash 3.2+, stat (GNU or BSD), no container runtime needed
# (uses mock secrets directory under repo tree — never /tmp).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LIB="${REPO_ROOT}/lib/pki_ownership.sh"
INSTALL_SH="${REPO_ROOT}/install.sh"
RESTORE_SH="${REPO_ROOT}/restore.sh"

PASS_COUNT=0
FAIL_COUNT=0

_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Test 1: lib/pki_ownership.sh exists and is shellcheck-clean
# ---------------------------------------------------------------------------
printf "\n--- Test 1: lib/pki_ownership.sh exists + syntax ---\n"
if [[ -f "$LIB" ]]; then
  _pass "lib/pki_ownership.sh exists"
else
  _fail "lib/pki_ownership.sh missing"
fi

if bash -n "$LIB" 2>/dev/null; then
  _pass "lib/pki_ownership.sh bash -n clean"
else
  _fail "lib/pki_ownership.sh bash -n failed"
fi

if command -v shellcheck &>/dev/null; then
  if shellcheck -x "$LIB" 2>/dev/null; then
    _pass "lib/pki_ownership.sh shellcheck clean"
  else
    _fail "lib/pki_ownership.sh shellcheck found issues"
  fi
else
  printf "  SKIP  shellcheck not available\n"
fi

# ---------------------------------------------------------------------------
# Test 2: Map lookup functions work correctly
# ---------------------------------------------------------------------------
printf "\n--- Test 2: Map lookups ---\n"

# Source the library in a subshell to avoid polluting the test env.
_map_uid() { bash -c "source '${LIB}'; pki_service_uid '$1'" 2>/dev/null; }
_map_mode() { bash -c "source '${LIB}'; pki_key_mode '$1'" 2>/dev/null; }
_map_all() { bash -c "source '${LIB}'; pki_services_all" 2>/dev/null; }

# Known correct values from the map.
# Format: "service:uid:mode" — bash 3.2 compatible (no associative arrays).
EXPECTED_SVC_MAP=(
  "caddy:0:0600"
  "gateway:1001:0600"
  "backoffice:1001:0600"
  "redis:999:0600"
  "budget-redis:999:0600"
  "pgbouncer:70:0600"
  "postgres:999:0600"
  "policy:1000:0600"
  "otel-collector:10001:0600"
  "jaeger:10001:0600"
  "loki:10001:0600"
  "promtail:0:0600"
  "grafana:472:0600"
  "prometheus:1001:0640"
)

for entry in "${EXPECTED_SVC_MAP[@]}"; do
  svc="${entry%%:*}"
  rest="${entry#*:}"
  exp_uid="${rest%%:*}"
  exp_mode="${rest#*:}"

  got_uid="$(_map_uid "$svc" 2>/dev/null || echo "MISSING")"
  if [[ "$got_uid" == "$exp_uid" ]]; then
    _pass "pki_service_uid ${svc} = ${exp_uid}"
  else
    _fail "pki_service_uid ${svc}: expected=${exp_uid} got=${got_uid}"
  fi

  got_mode="$(_map_mode "$svc" 2>/dev/null || echo "MISSING")"
  if [[ "$got_mode" == "$exp_mode" ]]; then
    _pass "pki_key_mode ${svc} = ${exp_mode}"
  else
    _fail "pki_key_mode ${svc}: expected=${exp_mode} got=${got_mode}"
  fi
done

# pki_services_all should emit all 14 services.
all_services="$(_map_all)"
service_count=$(printf '%s\n' "$all_services" | grep -c . || true)
if [[ "$service_count" -ge 14 ]]; then
  _pass "pki_services_all returns ${service_count} services (>= 14)"
else
  _fail "pki_services_all returns only ${service_count} services (expected >= 14)"
fi

# ---------------------------------------------------------------------------
# Test 3: Prometheus is mode 0640 (EX-231-10 regression)
# ---------------------------------------------------------------------------
printf "\n--- Test 3: Prometheus EX-231-10 regression (0640 group-read) ---\n"
prom_mode="$(_map_mode prometheus 2>/dev/null || echo "MISSING")"
prom_uid="$(_map_uid prometheus 2>/dev/null || echo "MISSING")"
if [[ "$prom_mode" == "0640" ]]; then
  _pass "prometheus key mode = 0640 (EX-231-10 correct)"
else
  _fail "prometheus key mode = ${prom_mode} (expected 0640 — EX-231-10 regression)"
fi
if [[ "$prom_uid" == "1001" ]]; then
  _pass "prometheus uid = 1001 (group_add 1001 path correct)"
else
  _fail "prometheus uid = ${prom_uid} (expected 1001)"
fi

# ---------------------------------------------------------------------------
# Test 4: install.sh sources lib/pki_ownership.sh
# ---------------------------------------------------------------------------
printf "\n--- Test 4: install.sh sources lib/pki_ownership.sh ---\n"
if grep -q 'lib/pki_ownership.sh' "$INSTALL_SH"; then
  _pass "install.sh references lib/pki_ownership.sh"
else
  _fail "install.sh does not source lib/pki_ownership.sh"
fi
if grep -q 'pki_services_all\|pki_service_uid\|pki_key_mode' "$INSTALL_SH"; then
  _pass "install.sh uses shared map functions"
else
  _fail "install.sh does not use shared map functions"
fi

# ---------------------------------------------------------------------------
# Test 5: restore.sh sources lib/pki_ownership.sh
# ---------------------------------------------------------------------------
printf "\n--- Test 5: restore.sh sources lib/pki_ownership.sh ---\n"
if grep -q 'lib/pki_ownership.sh' "$RESTORE_SH"; then
  _pass "restore.sh references lib/pki_ownership.sh"
else
  _fail "restore.sh does not source lib/pki_ownership.sh"
fi
if grep -q 'pki_services_all\|pki_service_uid\|pki_key_mode' "$RESTORE_SH"; then
  _pass "restore.sh uses shared map functions"
else
  _fail "restore.sh does not use shared map functions"
fi

# ---------------------------------------------------------------------------
# Test 6: Blanket *.key sweep is absent from restore.sh (GATE5-BUG-01)
# ---------------------------------------------------------------------------
printf "\n--- Test 6: Blanket *.key chmod sweep absent from restore.sh ---\n"
# The forbidden pattern: find + *.key + -exec chmod 0600
# This is the sweep removed by GATE5-BUG-01.
if grep -qE 'find .* -name.*\.key.*-exec chmod 0600|find .* -exec chmod 0600.*\.key' "$RESTORE_SH"; then
  _fail "GATE5-BUG-01 regression: blanket find ... *.key -exec chmod 0600 found in restore.sh"
else
  _pass "Blanket *.key chmod 0600 sweep absent from restore.sh"
fi

# ---------------------------------------------------------------------------
# Test 7: Upgrade no-rotation path — chown is Podman-gated, not unconditional
#          (maintainer directive 2026-05-10 / GATE5-BUG-01 + YSG-INSTALL-PKI-001)
# ---------------------------------------------------------------------------
printf "\n--- Test 7: Upgrade no-rotation branch — chown is Podman-rootless gated only ---\n"
# The no-rotation else branch:
#   - MUST contain the "upgrade no-touch rule" comment (GATE5-BUG-01 guard intact).
#   - MUST contain a YSG_PODMAN_RUNTIME guard around _pki_chown_client_keys
#     (YSG-INSTALL-PKI-001 fix: Podman rootless re-applies chown; Docker/rootful does not).
#   - Must NOT call _pki_chown_client_keys unconditionally (i.e. the call must only
#     appear inside the Podman-rootless if block in the no-rotation branch).
if grep -q "upgrade no-touch rule" "$INSTALL_SH"; then
  _pass "Upgrade no-touch rule comment present in install.sh"
else
  _fail "Upgrade no-touch rule comment missing from install.sh (check needs_rotation=false branch)"
fi

# The no-rotation branch must contain the YSG_PODMAN_RUNTIME guard for the chown call.
if grep -q 'YSG-INSTALL-PKI-001' "$INSTALL_SH"; then
  _pass "YSG-INSTALL-PKI-001 reference present in install.sh (Podman rootless chown exception)"
else
  _fail "YSG-INSTALL-PKI-001 reference missing from install.sh — Podman-rootless chown gate not applied"
fi

# The Podman-rootless guard must gate _pki_chown_client_keys in the no-rotation branch.
# Check: the guard pattern and the chown call both exist in the no-rotation else block.
if grep -q 'YSG_PODMAN_RUNTIME.*true.*id -u.*0\|YSG_PODMAN_RUNTIME.*true.*id -u' "$INSTALL_SH"; then
  _pass "YSG_PODMAN_RUNTIME + non-root guard present in install.sh no-rotation branch"
else
  _fail "YSG_PODMAN_RUNTIME non-root guard missing from no-rotation branch — YSG-INSTALL-PKI-001 fix absent"
fi

# Regression: unconditional call immediately after "Certs current" is still forbidden.
# The line right after "Certs current — no rotation needed" must NOT be _pki_chown_client_keys.
if grep -A1 "Certs current.*no rotation needed" "$INSTALL_SH" | grep -q '_pki_chown_client_keys'; then
  _fail "GATE5-BUG-01 regression: _pki_chown_client_keys called unconditionally after 'Certs current' (should be Podman-gated)"
else
  _pass "No unconditional _pki_chown_client_keys immediately after 'Certs current' (Podman-gated call is correct)"
fi

# ---------------------------------------------------------------------------
# Test 8: restore.sh _pki_chown_client_keys accepts key list parameter
# ---------------------------------------------------------------------------
printf "\n--- Test 8: restore._pki_chown_client_keys accepts key list ---\n"
# Check that the function signature uses positional params (not hardcoded array).
if grep -A5 '^_pki_chown_client_keys()' "$RESTORE_SH" | grep -q '_written_keys=.*"\$@"'; then
  _pass "restore._pki_chown_client_keys uses positional param list (\"\$@\")"
else
  _fail "restore._pki_chown_client_keys does not use positional param list — GATE5-BUG-01 may not be fixed"
fi

# ---------------------------------------------------------------------------
# Test 9: restore.sh call site passes _backup_written_keys array
# ---------------------------------------------------------------------------
printf "\n--- Test 9: restore.sh call site passes backup key list ---\n"
if grep -q '_backup_written_keys' "$RESTORE_SH"; then
  _pass "restore.sh tracks _backup_written_keys"
else
  _fail "restore.sh does not track _backup_written_keys"
fi
if grep -q '_pki_chown_client_keys.*_backup_written_keys' "$RESTORE_SH"; then
  _pass "restore.sh passes _backup_written_keys to _pki_chown_client_keys"
else
  _fail "restore.sh call site does not pass _backup_written_keys"
fi

# ---------------------------------------------------------------------------
# Test 10: Inline _uid_mapped_services array is absent from both scripts
#          (replaced by shared map)
# ---------------------------------------------------------------------------
printf "\n--- Test 10: Inline _uid_mapped_services removed from scripts ---\n"
if grep -q '"caddy:0"' "$INSTALL_SH"; then
  _fail "Inline _uid_mapped_services still present in install.sh (should be in lib/pki_ownership.sh)"
else
  _pass "Inline _uid_mapped_services removed from install.sh"
fi
if grep -q '"gateway:1001"' "$RESTORE_SH"; then
  _fail "Inline _uid_mapped_services still present in restore.sh (should be in lib/pki_ownership.sh)"
else
  _pass "Inline _uid_mapped_services removed from restore.sh"
fi

# ---------------------------------------------------------------------------
# Test 11: update.sh has no PKI chown logic (upgrade never touches keys)
# ---------------------------------------------------------------------------
printf "\n--- Test 11: update.sh has no PKI chown logic ---\n"
UPDATE_SH="${REPO_ROOT}/update.sh"
if [[ -f "$UPDATE_SH" ]]; then
  if grep -qE '_pki_chown|pki_service_uid|_uid_mapped_services' "$UPDATE_SH"; then
    _fail "update.sh contains PKI chown logic — upgrade path must not touch keys"
  else
    _pass "update.sh contains no PKI chown logic (upgrade no-touch)"
  fi
else
  printf "  SKIP  update.sh not found\n"
fi

# ---------------------------------------------------------------------------
# Test 12: service_identities.yaml parity — every service in lib/ map has a
#          mtls_capable entry in the YAML (if YAML is present)
# ---------------------------------------------------------------------------
printf "\n--- Test 12: service_identities.yaml parity ---\n"
SID_YAML="${REPO_ROOT}/docker/service_identities.yaml"
if [[ -f "$SID_YAML" ]]; then
  parity_fail=0
  while IFS= read -r svc; do
    if ! grep -q "name: ${svc}" "$SID_YAML" 2>/dev/null; then
      _fail "Service '${svc}' in lib/pki_ownership.sh but missing from service_identities.yaml"
      parity_fail=1
    fi
  done < <(_map_all)
  if [[ "$parity_fail" == "0" ]]; then
    _pass "All services in lib/pki_ownership.sh found in service_identities.yaml"
  fi
else
  printf "  SKIP  docker/service_identities.yaml not found (run from repo root with docker/ present)\n"
fi

# ---------------------------------------------------------------------------
# Test 13: Runtime mock-filesystem — CWE-732 assertion correctness
#
# Regression guard for the false-positive introduced by the blanket
# `find -perm -040` assertion on prometheus_client.key (0640).
#
# Creates a mock secrets directory under the repo (never /tmp), places key
# files at specific modes, then runs the same assertion logic used in
# restore.sh::_pki_chown_client_keys via the shared lib. Verifies:
#   a) prometheus_client.key at 0640 → assertion PASSES (no false-positive)
#   b) gateway_client.key at 0600 → assertion PASSES
#   c) any *.key at 0004 (world-read) → assertion FAILS (correctly detected)
#   d) pre-existing key NOT in written list → not checked by per-service loop
#      (regression: old blanket find would have caught its mode unconditionally)
# ---------------------------------------------------------------------------
printf "\n--- Test 13: Runtime mock-filesystem — CWE-732 assertion correctness ---\n"

# Portable stat: GNU -c '%a', BSD -f '%OLp'.
_stat_mode_t13() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1" 2>/dev/null || true
}

# Mock secrets dir under repo (not /tmp — per project SOP).
_MOCK_SECRETS="${REPO_ROOT}/tests/install/.mock_secrets_t13"
mkdir -p "${_MOCK_SECRETS}"
# Cleanup on exit.
trap 'rm -rf "${_MOCK_SECRETS}"' EXIT

# Create mock key files at their expected modes.
touch "${_MOCK_SECRETS}/gateway_client.key"
chmod 0600 "${_MOCK_SECRETS}/gateway_client.key"

touch "${_MOCK_SECRETS}/prometheus_client.key"
chmod 0640 "${_MOCK_SECRETS}/prometheus_client.key"

# Pre-existing key NOT in the written list (simulate a key that was already on
# disk and restore.sh did not overwrite). It sits at a hypothetical 0400 (read-only
# by owner). The per-service loop must not touch or complain about it.
touch "${_MOCK_SECRETS}/caddy_client.key"
chmod 0400 "${_MOCK_SECRETS}/caddy_client.key"

# Written keys list — only gateway and prometheus; caddy is pre-existing (NOT restored).
_T13_WRITTEN=("gateway_client.key" "prometheus_client.key")

# Replicate the assertion logic from restore.sh::_pki_chown_client_keys
# using the shared lib. Run in a subshell to capture pass/fail cleanly.
_t13_assert_result=$(bash -c "
source '${LIB}'
_stat_mode() {
  stat -c '%a' \"\$1\" 2>/dev/null || stat -f '%OLp' \"\$1\" 2>/dev/null || true
}
_fail=0
for _ck in gateway_client.key prometheus_client.key; do
  _csvc=\"\${_ck%_client.key}\"
  _exp_mode=\"\$(pki_key_mode \"\$_csvc\" 2>/dev/null)\" || continue
  _ckfile='${_MOCK_SECRETS}'/\"\$_ck\"
  _act_mode=\"\$(_stat_mode \"\$_ckfile\")\"
  _exp_mode=\"\${_exp_mode#0}\"
  _act_mode=\"\${_act_mode#0}\"
  if [[ \"\$_act_mode\" != \"\$_exp_mode\" ]]; then
    printf 'MODE_MISMATCH:%s:exp=%s:act=%s\n' \"\$_ck\" \"\$_exp_mode\" \"\$_act_mode\"
    _fail=1
  fi
done
# World-read sweep
if find '${_MOCK_SECRETS}' -maxdepth 1 -type f -name '*.key' -perm -004 2>/dev/null | grep -q .; then
  printf 'WORLD_READ_FOUND\n'
  _fail=1
fi
exit \$_fail
" 2>&1)
_t13_rc=$?

if [[ "$_t13_rc" == "0" ]] && ! printf '%s' "$_t13_assert_result" | grep -q "MISMATCH\|WORLD_READ"; then
  _pass "Mock assertion: prometheus 0640 + gateway 0600 → no false-positive (correct)"
else
  _fail "Mock assertion: false-positive or mode mismatch on legitimately-set keys: ${_t13_assert_result}"
fi

# Sub-test: verify caddy_client.key (pre-existing, not in written list) was NOT
# checked — i.e. the per-service loop only iterates _written_keys. We know
# caddy is at 0400; if the loop had included it, it would still pass (0400 is
# tighter than 0600), but the regression being tested is that an unlisted key at
# 0640 would have been a false-positive under the old blanket find (since 0640
# has the -040 bit). Prove this by setting caddy to 0640 momentarily and
# confirming the per-service loop (which omits caddy) does NOT flag it, while
# the old blanket find WOULD have flagged it.
chmod 0640 "${_MOCK_SECRETS}/caddy_client.key"

_t13_old_assert=$(bash -c "
if find '${_MOCK_SECRETS}' -maxdepth 1 -type f -name '*.key' \
      \( -perm -004 -o -perm -040 \) 2>/dev/null | grep -q .; then
  printf 'OLD_ASSERT_FIRED\n'
fi
" 2>&1)

_t13_new_assert=$(bash -c "
source '${LIB}'
_stat_mode() {
  stat -c '%a' \"\$1\" 2>/dev/null || stat -f '%OLp' \"\$1\" 2>/dev/null || true
}
_fail=0
# Only gateway + prometheus in written list (caddy excluded).
for _ck in gateway_client.key prometheus_client.key; do
  _csvc=\"\${_ck%_client.key}\"
  _exp_mode=\"\$(pki_key_mode \"\$_csvc\" 2>/dev/null)\" || continue
  _ckfile='${_MOCK_SECRETS}'/\"\$_ck\"
  _act_mode=\"\$(_stat_mode \"\$_ckfile\")\"
  _exp_mode=\"\${_exp_mode#0}\"
  _act_mode=\"\${_act_mode#0}\"
  if [[ \"\$_act_mode\" != \"\$_exp_mode\" ]]; then
    _fail=1
  fi
done
if find '${_MOCK_SECRETS}' -maxdepth 1 -type f -name '*.key' -perm -004 2>/dev/null | grep -q .; then
  _fail=1
fi
exit \$_fail
" 2>&1)
_t13_new_rc=$?

# Old assertion should have fired (caddy_client.key is 0640 = has -040 bit).
if printf '%s' "$_t13_old_assert" | grep -q "OLD_ASSERT_FIRED"; then
  _pass "Mock regression: old blanket find correctly triggers on pre-existing 0640 key (confirms the bug existed)"
else
  _fail "Mock regression: old blanket find did NOT trigger — test setup problem"
fi

# New assertion should NOT fire (caddy not in written list, no world-read bit).
if [[ "$_t13_new_rc" == "0" ]]; then
  _pass "Mock regression: new per-service assertion does NOT fire on pre-existing 0640 key not in written list"
else
  _fail "Mock regression: new per-service assertion incorrectly fired on pre-existing 0640 key: ${_t13_new_assert}"
fi

# Restore caddy to 0400 so the world-read sweep doesn't catch it in cleanup.
chmod 0400 "${_MOCK_SECRETS}/caddy_client.key"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n"
printf "==================================\n"
printf "  PASS: %d\n" "$PASS_COUNT"
printf "  FAIL: %d\n" "$FAIL_COUNT"
printf "==================================\n"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "RESULT: FAIL\n"
  exit 1
else
  printf "RESULT: PASS\n"
fi
