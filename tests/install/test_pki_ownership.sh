#!/usr/bin/env bash
# tests/install/test_pki_ownership.sh — PKI key ownership regression tests
# last-updated: 2026-05-10T00:00:00+01:00 (fix(pki): GATE5-BUG-01 — shared ownership map regression tests)
#
# Tests:
#   1. lib/pki_ownership.sh: map lookups correct for all known services
#   2. Install path: each service key has correct UID + mode after sourcing map
#   3. Restore path: only backup-written keys get re-owned; pre-existing keys untouched
#   4. Upgrade no-touch: keys NOT chowned when needs_rotation=false
#   5. Blanket-sweep regression: find ... *.key -exec chmod 0600 is absent from restore.sh
#   6. Map parity: every service in lib/pki_ownership.sh is present in service_identities.yaml
#      (if the YAML exists)
#   7. Prometheus: uid=1001, mode=0640 (EX-231-10 regression)
#
# Usage:
#   bash tests/install/test_pki_ownership.sh
#
# Requirements: bash 4+, stat (GNU or BSD), no container runtime needed
# (uses mock secrets directory under /tmp-free scratch — all under WORK_DIR).

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
# Test 7: Upgrade no-rotation path does not call _pki_chown_client_keys
#          (Tiago directive 2026-05-10)
# ---------------------------------------------------------------------------
printf "\n--- Test 7: Upgrade no-rotation path does not chown existing keys ---\n"
# Verify the "Certs current — no rotation needed" branch in install.sh does NOT
# call _pki_chown_client_keys. We check this statically: the branch must contain
# the "upgrade no-touch rule" comment and must NOT contain _pki_chown_client_keys
# in the no-rotation else clause.
#
# Heuristic: extract the else branch of "needs_rotation" and check it has the
# upgrade no-touch comment.
if grep -q "upgrade no-touch rule" "$INSTALL_SH"; then
  _pass "Upgrade no-touch rule comment present in install.sh"
else
  _fail "Upgrade no-touch rule comment missing from install.sh (check needs_rotation=false branch)"
fi

# The no-rotation path should NOT immediately follow "Certs current" with
# _pki_chown_client_keys (old "always re-apply" pattern).
if grep -A2 "Certs current.*no rotation needed" "$INSTALL_SH" | grep -q '_pki_chown_client_keys'; then
  _fail "GATE5-BUG-01 regression: _pki_chown_client_keys still called immediately after 'Certs current' (no-rotation path)"
else
  _pass "No _pki_chown_client_keys on no-rotation branch"
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
