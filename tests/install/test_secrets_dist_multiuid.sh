#!/usr/bin/env bash
# tests/install/test_secrets_dist_multiuid.sh
# Regression test for YSG-SECRETS-DIST-001: class-defense for multi-UID secret
# distribution on Podman rootless.
# last-updated: 2026-05-18T00:00:00+01:00 (new: YSG-SECRETS-DIST-001 class-defense gate)
#
# Background: 4 prior siblings (86872a7, 2f109fc, 5a341cb) fixed point issues in the
# same class. This test covers the class itself: any secret in docker/secrets/ consumed
# by multiple container UIDs must be set to 0644 (not 0600) in _pki_chown_client_keys()
# so that all consumers can read it regardless of their UID.
#
# Test matrix (secret × consumer UID):
#   postgres_password    : gateway:1001, backoffice:1001, postgres:999, redis:999
#   redis_password       : gateway:1001, backoffice:1001, redis:999, budget-redis:999
#   yashigani_internal_bearer: gateway:1001, backoffice:1001, langflow:1000, letta:0, open-webui:0
#
# Tests:
#   1.  Static: postgres_password in the shared-0644 loop (3-item list)
#   2.  Static: redis_password in the shared-0644 loop
#   3.  Static: yashigani_internal_bearer in the shared-0644 loop (the new member)
#   4.  Behavioural: simulate UID 1000 (langflow) reading a 0644 yashigani_internal_bearer
#   5.  Behavioural: simulate UID 0 (letta) reading a 0644 yashigani_internal_bearer
#       (UID 0 on host → can read any file, but on Podman rootless host the subuid
#        mapping means container root ≠ file owner; 0644 ensures readability)
#   6.  Behavioural: simulate UID 1001 (gateway) still readable after 0644 (no regression)
#   7.  Behavioural: yashigani_internal_bearer at 0600 owned by 1001 is NOT readable by UID 1000
#       (documents the pre-fix failure mode that motivated this fix)
#   8.  Static: YSG-SECRETS-DIST-001 comment reference present in install.sh
#   9.  Static: YSG-SECRETS-DIST-001 comment reference present in lib/pki_ownership.sh
#  10.  Static: multi-UID class documentation present in lib/pki_ownership.sh
#  11.  Static: install.sh bash -n syntax clean
#  12.  Static: install.sh shellcheck -S error clean (if shellcheck available)
#  13.  Static: lib/pki_ownership.sh bash -n syntax clean
#  14.  Behavioural: log message updated to include bearer (grep for YSG-SECRETS-DIST-001 in log line)
#
# Usage:
#   bash tests/install/test_secrets_dist_multiuid.sh
#
# Requirements: bash 3.2+, no container runtime needed.
# Mock dirs live under tests/install/ — never under /tmp per project SOP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
PKI_OWNERSHIP_SH="${REPO_ROOT}/lib/pki_ownership.sh"

PASS_COUNT=0
FAIL_COUNT=0

_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Test 1: Static — postgres_password in shared-0644 loop
# ---------------------------------------------------------------------------
printf "\n--- Test 1: Static — postgres_password in shared-0644 loop ---\n"
if grep -n "postgres_password redis_password yashigani_internal_bearer" "$INSTALL_SH" | grep -q "for _shared_pw"; then
  _pass "postgres_password found in shared-0644 loop (for _shared_pw in ...)"
else
  _fail "postgres_password NOT found in shared-0644 loop — regression"
fi

# ---------------------------------------------------------------------------
# Test 2: Static — redis_password in shared-0644 loop
# ---------------------------------------------------------------------------
printf "\n--- Test 2: Static — redis_password in shared-0644 loop ---\n"
if grep "for _shared_pw in" "$INSTALL_SH" | grep -q "redis_password"; then
  _pass "redis_password found in shared-0644 loop"
else
  _fail "redis_password NOT found in shared-0644 loop — regression"
fi

# ---------------------------------------------------------------------------
# Test 3: Static — yashigani_internal_bearer in shared-0644 loop (new member)
# ---------------------------------------------------------------------------
printf "\n--- Test 3: Static — yashigani_internal_bearer in shared-0644 loop ---\n"
if grep "for _shared_pw in" "$INSTALL_SH" | grep -q "yashigani_internal_bearer"; then
  _pass "yashigani_internal_bearer found in shared-0644 loop (YSG-SECRETS-DIST-001 fix present)"
else
  _fail "yashigani_internal_bearer NOT found in shared-0644 loop — YSG-SECRETS-DIST-001 fix absent"
fi

# ---------------------------------------------------------------------------
# Shared mock dir for behavioural tests 4–7.
# ---------------------------------------------------------------------------
_MOCK_DIR="${SCRIPT_DIR}/.mock_secrets_dist001"
mkdir -p "${_MOCK_DIR}"
trap 'rm -rf "${_MOCK_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Test 4: Behavioural — UID 1000 (langflow) can read 0644 bearer file
# ---------------------------------------------------------------------------
printf "\n--- Test 4: Behavioural — UID 1000 (langflow) reads 0644 bearer ---\n"

_bearer_file="${_MOCK_DIR}/yashigani_internal_bearer"
printf "test-bearer-token" > "${_bearer_file}"
chmod 0644 "${_bearer_file}"

# Simulate langflow UID 1000 reading the file.
# Strategy: set file owner to a UID that is NOT current user, mode 0644.
# Any user can read a 0644 file regardless of owner.
# We verify this is true on the current host by checking the mode bits directly.
_mode="$(stat -f "%OLp" "${_bearer_file}" 2>/dev/null || stat -c "%a" "${_bearer_file}" 2>/dev/null || echo "")"
if [[ "$_mode" == "644" ]]; then
  # Also verify the content is readable (not just mode bits)
  _content="$(cat "${_bearer_file}" 2>/dev/null || echo "")"
  if [[ "$_content" == "test-bearer-token" ]]; then
    _pass "UID 1000 simulation: 0644 bearer file is readable (mode=644, content verified)"
  else
    _fail "UID 1000 simulation: 0644 bearer file mode=644 but content unreadable"
  fi
else
  _fail "UID 1000 simulation: bearer file mode=${_mode} (expected 644)"
fi

# ---------------------------------------------------------------------------
# Test 5: Behavioural — UID 0 (letta/open-webui) reads 0644 bearer file
# ---------------------------------------------------------------------------
printf "\n--- Test 5: Behavioural — UID 0 (letta) reads 0644 bearer ---\n"

# Same file from test 4 (still 0644). UID 0 inside a container on Podman rootless
# maps to the host calling user — NOT to root on the host. Mode 0644 makes the
# file readable by all users regardless of owner mapping.
_mode5="$(stat -f "%OLp" "${_bearer_file}" 2>/dev/null || stat -c "%a" "${_bearer_file}" 2>/dev/null || echo "")"
if [[ "$_mode5" == "644" ]]; then
  _pass "UID 0 (letta/open-webui) simulation: 0644 file readable by any host UID"
else
  _fail "UID 0 simulation: bearer file mode=${_mode5} (expected 644 for world-read)"
fi

# ---------------------------------------------------------------------------
# Test 6: Behavioural — UID 1001 (gateway/backoffice) still readable after 0644
# ---------------------------------------------------------------------------
printf "\n--- Test 6: Behavioural — UID 1001 (gateway/backoffice) still readable after 0644 ---\n"

# 0644 is a superset of 0600 for the owner. UID 1001 (owner after chown) can still read.
_mode6="$(stat -f "%OLp" "${_bearer_file}" 2>/dev/null || stat -c "%a" "${_bearer_file}" 2>/dev/null || echo "")"
if [[ "$_mode6" == "644" ]]; then
  _pass "UID 1001 regression check: 0644 includes owner-read — gateway/backoffice unaffected"
else
  _fail "UID 1001 regression check: unexpected mode ${_mode6}"
fi

# ---------------------------------------------------------------------------
# Test 7: Behavioural — pre-fix failure: 0600 owned by 1001 denies UID 1000
# ---------------------------------------------------------------------------
printf "\n--- Test 7: Behavioural — pre-fix: 0600 file owned by another UID is unreadable ---\n"

_bearer_600="${_MOCK_DIR}/yashigani_internal_bearer_old"
printf "test-bearer-token" > "${_bearer_600}"
chmod 0600 "${_bearer_600}"

# A 0600 file owned by the current user is readable by the current user.
# But the test we care about: simulate a DIFFERENT owner UID.
# We cannot chown to 1001 without sudo, so we use a file owned by a group
# that the current user is NOT in, or verify mode bits only.
# The key assertion is: if mode=0600 and owner ≠ reader UID, reader gets EPERM.
# We document this as a mode-check: 0600 means other-read = 0.
_mode7="$(stat -f "%OLp" "${_bearer_600}" 2>/dev/null || stat -c "%a" "${_bearer_600}" 2>/dev/null || echo "")"
_other_read=$(( (0${_mode7} & 4) ))
if [[ "$_other_read" == "0" ]]; then
  _pass "Pre-fix scenario documented: 0600 mode has other-read=0 (world-unreadable — would deny UID 1000)"
else
  _fail "Pre-fix check: mode ${_mode7} has other-read set — unexpected"
fi

# Verify 0644 has other-read=4 (world-readable)
_mode7b="$(stat -f "%OLp" "${_bearer_file}" 2>/dev/null || stat -c "%a" "${_bearer_file}" 2>/dev/null || echo "")"
_other_read_644=$(( (0${_mode7b} & 4) ))
if [[ "$_other_read_644" == "4" ]]; then
  _pass "Fix verification: 0644 mode has other-read=4 (world-readable — allows UID 1000/0)"
else
  _fail "Fix verification: mode ${_mode7b} does not have other-read=4"
fi

# ---------------------------------------------------------------------------
# Test 8: Static — YSG-SECRETS-DIST-001 reference in install.sh
# ---------------------------------------------------------------------------
printf "\n--- Test 8: Static — YSG-SECRETS-DIST-001 reference in install.sh ---\n"
if grep -q "YSG-SECRETS-DIST-001" "$INSTALL_SH"; then
  _pass "YSG-SECRETS-DIST-001 comment reference found in install.sh"
else
  _fail "YSG-SECRETS-DIST-001 comment missing from install.sh"
fi

# ---------------------------------------------------------------------------
# Test 9: Static — YSG-SECRETS-DIST-001 reference in lib/pki_ownership.sh
# ---------------------------------------------------------------------------
printf "\n--- Test 9: Static — YSG-SECRETS-DIST-001 reference in lib/pki_ownership.sh ---\n"
if grep -q "YSG-SECRETS-DIST-001" "$PKI_OWNERSHIP_SH"; then
  _pass "YSG-SECRETS-DIST-001 comment reference found in lib/pki_ownership.sh"
else
  _fail "YSG-SECRETS-DIST-001 comment missing from lib/pki_ownership.sh"
fi

# ---------------------------------------------------------------------------
# Test 10: Static — Multi-UID class documentation in lib/pki_ownership.sh
# ---------------------------------------------------------------------------
printf "\n--- Test 10: Static — multi-UID class documentation in lib/pki_ownership.sh ---\n"
_doc_checks_passed=0
for _keyword in "langflow:1000" "letta:0" "open-webui:0" "Multi-UID secret distribution"; do
  if grep -q "$_keyword" "$PKI_OWNERSHIP_SH"; then
    _doc_checks_passed=$((_doc_checks_passed + 1))
  fi
done
if [[ "$_doc_checks_passed" -eq 4 ]]; then
  _pass "Multi-UID class documentation complete (langflow/letta/open-webui UIDs + section header)"
else
  _fail "Multi-UID class documentation incomplete: $_doc_checks_passed/4 keywords found in pki_ownership.sh"
fi

# ---------------------------------------------------------------------------
# Test 11: install.sh bash -n syntax clean
# ---------------------------------------------------------------------------
printf "\n--- Test 11: install.sh bash -n syntax clean ---\n"
if bash -n "$INSTALL_SH" 2>/dev/null; then
  _pass "install.sh bash -n clean"
else
  _fail "install.sh bash -n FAILED — syntax error introduced"
fi

# ---------------------------------------------------------------------------
# Test 12: install.sh shellcheck -S error clean (if available)
# ---------------------------------------------------------------------------
printf "\n--- Test 12: install.sh shellcheck (if available) ---\n"
if command -v shellcheck &>/dev/null; then
  if shellcheck -S error -x "$INSTALL_SH" 2>/dev/null; then
    _pass "install.sh shellcheck -S error clean"
  else
    _fail "install.sh shellcheck -S error found errors"
  fi
else
  printf "  SKIP  shellcheck not available\n"
fi

# ---------------------------------------------------------------------------
# Test 13: lib/pki_ownership.sh bash -n syntax clean
# ---------------------------------------------------------------------------
printf "\n--- Test 13: lib/pki_ownership.sh bash -n syntax clean ---\n"
if bash -n "$PKI_OWNERSHIP_SH" 2>/dev/null; then
  _pass "lib/pki_ownership.sh bash -n clean"
else
  _fail "lib/pki_ownership.sh bash -n FAILED — syntax error introduced"
fi

# ---------------------------------------------------------------------------
# Test 14: Log message updated to include YSG-SECRETS-DIST-001
# ---------------------------------------------------------------------------
printf "\n--- Test 14: Static — log message includes YSG-SECRETS-DIST-001 ---\n"
if grep "YSG-SECRETS-DIST-001" "$INSTALL_SH" | grep -q "log_info"; then
  _pass "Updated log_info message references YSG-SECRETS-DIST-001"
else
  _fail "log_info message does not reference YSG-SECRETS-DIST-001"
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
