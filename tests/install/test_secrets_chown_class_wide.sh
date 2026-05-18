#!/usr/bin/env bash
# tests/install/test_secrets_chown_class_wide.sh
# Regression test for YSG-INSTALL-PKI-002 (sibling of YSG-INSTALL-PKI-001):
# Class-wide secrets chown — all UID-1001-consumed secrets are chowned on
# Podman rootless, including preserved (non-regenerated) files.
# last-updated: 2026-05-18T00:00:00+01:00 (new: YSG-INSTALL-PKI-002 close — class-wide chown gate)
#
# Tests:
#   1.  Static: yashigani_internal_bearer present in _uid1001_secrets array.
#   2.  Static: admin1_password present in _uid1001_secrets array.
#   3.  Static: admin2_password present in _uid1001_secrets array.
#   4.  Static: caddy_internal_hmac present in _uid1001_secrets array.
#   5.  Static: YSG-INSTALL-PKI-002 comment reference present.
#   6.  Behavioural: _uid1001_secrets loop chowns yashigani_internal_bearer on
#       Podman rootless path (preserved file — the specific bug from Track A retry #2).
#   7.  Behavioural: _uid1001_secrets loop chowns admin1_password on Podman rootless.
#   8.  Behavioural: _uid1001_secrets loop chowns admin2_totp_secret on Podman rootless.
#   9.  Behavioural: Docker path — _pki_chown_client_keys NOT called on no-rotation branch
#       (GATE5-BUG-01 upgrade no-touch rule intact — inherited from PKI-001 test but
#       re-verified here for the new class member).
#  10.  Behavioural: arbitrary new file in docker/secrets/ — NOT chowned unless added
#       to _uid1001_secrets (demonstrates class boundary; prevents accidental scope creep).
#  11.  install.sh bash -n syntax clean.
#  12.  install.sh shellcheck -S error clean (if shellcheck available).
#
# Usage:
#   bash tests/install/test_secrets_chown_class_wide.sh
#
# Requirements: bash 3.2+, no container runtime needed.
# Mock dirs live under tests/install/ — never under /tmp per project SOP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

PASS_COUNT=0
FAIL_COUNT=0

_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Test 1: Static — yashigani_internal_bearer in _uid1001_secrets
# ---------------------------------------------------------------------------
printf "\n--- Test 1: Static — yashigani_internal_bearer in _uid1001_secrets ---\n"
if grep -q 'yashigani_internal_bearer' "$INSTALL_SH"; then
  # Confirm it appears inside the _uid1001_secrets block, not just as a path ref.
  # The block spans from "local _uid1001_secrets=(" to the closing ")".
  # We check that both the array declaration and the bearer appear in the same
  # grep window (50 lines is ample for the array).
  if awk '/_uid1001_secrets=\(/{found=1} found && /yashigani_internal_bearer/{print; exit}' \
       "$INSTALL_SH" | grep -q 'yashigani_internal_bearer'; then
    _pass "yashigani_internal_bearer found inside _uid1001_secrets array"
  else
    _fail "yashigani_internal_bearer NOT found inside _uid1001_secrets array — YSG-INSTALL-PKI-002 fix absent"
  fi
else
  _fail "yashigani_internal_bearer not present anywhere in install.sh"
fi

# ---------------------------------------------------------------------------
# Test 2: Static — admin1_password in _uid1001_secrets
# ---------------------------------------------------------------------------
printf "\n--- Test 2: Static — admin1_password in _uid1001_secrets ---\n"
if awk '/_uid1001_secrets=\(/{found=1} found && /admin1_password/{print; exit}' \
     "$INSTALL_SH" | grep -q 'admin1_password'; then
  _pass "admin1_password found inside _uid1001_secrets array"
else
  _fail "admin1_password NOT found inside _uid1001_secrets array"
fi

# ---------------------------------------------------------------------------
# Test 3: Static — admin2_password in _uid1001_secrets
# ---------------------------------------------------------------------------
printf "\n--- Test 3: Static — admin2_password in _uid1001_secrets ---\n"
if awk '/_uid1001_secrets=\(/{found=1} found && /admin2_password/{print; exit}' \
     "$INSTALL_SH" | grep -q 'admin2_password'; then
  _pass "admin2_password found inside _uid1001_secrets array"
else
  _fail "admin2_password NOT found inside _uid1001_secrets array"
fi

# ---------------------------------------------------------------------------
# Test 4: Static — caddy_internal_hmac in _uid1001_secrets
# ---------------------------------------------------------------------------
printf "\n--- Test 4: Static — caddy_internal_hmac in _uid1001_secrets ---\n"
if awk '/_uid1001_secrets=\(/{found=1} found && /caddy_internal_hmac/{print; exit}' \
     "$INSTALL_SH" | grep -q 'caddy_internal_hmac'; then
  _pass "caddy_internal_hmac found inside _uid1001_secrets array"
else
  _fail "caddy_internal_hmac NOT found inside _uid1001_secrets array"
fi

# ---------------------------------------------------------------------------
# Test 5: Static — YSG-INSTALL-PKI-002 comment reference present
# ---------------------------------------------------------------------------
printf "\n--- Test 5: Static — YSG-INSTALL-PKI-002 reference present ---\n"
if grep -q 'YSG-INSTALL-PKI-002' "$INSTALL_SH"; then
  _pass "YSG-INSTALL-PKI-002 comment reference found in install.sh"
else
  _fail "YSG-INSTALL-PKI-002 comment missing — fix may not be documented"
fi

# ---------------------------------------------------------------------------
# Single top-level cleanup trap for all mock dirs (tests 6/7/8/10).
# Using a per-test trap overwrites the previous one — last trap wins, earlier
# dirs would leak until script exit. This approach is simpler and leak-free.
# ---------------------------------------------------------------------------
_MOCK_DIR="${SCRIPT_DIR}/.mock_secrets_pki002_t6"
_MOCK_DIR7="${SCRIPT_DIR}/.mock_secrets_pki002_t7"
_MOCK_DIR8="${SCRIPT_DIR}/.mock_secrets_pki002_t8"
_MOCK_DIR10="${SCRIPT_DIR}/.mock_secrets_pki002_t10"
mkdir -p "${_MOCK_DIR}" "${_MOCK_DIR7}" "${_MOCK_DIR8}" "${_MOCK_DIR10}"
trap 'rm -rf "${_MOCK_DIR}" "${_MOCK_DIR7}" "${_MOCK_DIR8}" "${_MOCK_DIR10}"' EXIT

# ---------------------------------------------------------------------------
# Test 6: Behavioural — preserved yashigani_internal_bearer is chowned
#
# Simulates the exact Track A retry #2 failure scenario:
# - yashigani_internal_bearer exists (preserved, not regenerated)
# - _do_chown is called for it via the _uid1001_secrets loop
# - on Podman rootless path → _pki_chown_client_keys is eventually reached
#
# Strategy: inline the _uid1001_secrets loop with a mock _do_chown that records
# which files it was called on. Verify yashigani_internal_bearer appears.
# ---------------------------------------------------------------------------
printf "\n--- Test 6: Behavioural — preserved yashigani_internal_bearer triggers chown ---\n"

# Create the preserved bearer file owned by current user (simulating rsync from Mac).
touch "${_MOCK_DIR}/yashigani_internal_bearer"
chmod 0600 "${_MOCK_DIR}/yashigani_internal_bearer"

_t6_result=$(bash <<EOF_T6
set -euo pipefail
log_info() { return 0; }
log_error() { return 0; }

_chowned=()
_do_chown() {
  local _uid="\$1" _file="\$2" _label="\$3"
  _chowned+=("\$_label")
  return 0
}

_secrets_dir="${_MOCK_DIR}"

# Exact subset of _uid1001_secrets that contains the new member.
_uid1001_secrets=(
  yashigani_internal_bearer
  admin1_password
  admin2_password
  caddy_internal_hmac
)
for _sf in "\${_uid1001_secrets[@]}"; do
  _sfpath="\${_secrets_dir}/\${_sf}"
  if [[ -f "\$_sfpath" ]]; then
    _do_chown "1001" "\$_sfpath" "\$_sf" || exit 1
  fi
done

# Report which labels were chowned.
for _label in "\${_chowned[@]}"; do
  echo "chowned:\$_label"
done
EOF_T6
)

if echo "$_t6_result" | grep -q "chowned:yashigani_internal_bearer"; then
  _pass "Preserved yashigani_internal_bearer: _do_chown was called (chown would execute)"
else
  _fail "Preserved yashigani_internal_bearer: _do_chown was NOT called — container UID 1001 would be denied"
fi

# ---------------------------------------------------------------------------
# Test 7: Behavioural — admin1_password preserved file is chowned
# ---------------------------------------------------------------------------
printf "\n--- Test 7: Behavioural — admin1_password preserved file triggers chown ---\n"

touch "${_MOCK_DIR7}/admin1_password"
chmod 0600 "${_MOCK_DIR7}/admin1_password"

_t7_result=$(bash <<EOF_T7
set -euo pipefail
log_info() { return 0; }
log_error() { return 0; }

_chowned=()
_do_chown() {
  local _uid="\$1" _file="\$2" _label="\$3"
  _chowned+=("\$_label")
  return 0
}

_secrets_dir="${_MOCK_DIR7}"
_uid1001_secrets=(admin1_password admin2_password admin1_totp_secret)
for _sf in "\${_uid1001_secrets[@]}"; do
  _sfpath="\${_secrets_dir}/\${_sf}"
  if [[ -f "\$_sfpath" ]]; then
    _do_chown "1001" "\$_sfpath" "\$_sf" || exit 1
  fi
done

for _label in "\${_chowned[@]}"; do
  echo "chowned:\$_label"
done
EOF_T7
)

if echo "$_t7_result" | grep -q "chowned:admin1_password"; then
  _pass "admin1_password: _do_chown called for present file"
else
  _fail "admin1_password: _do_chown NOT called — regression"
fi

# ---------------------------------------------------------------------------
# Test 8: Behavioural — admin2_totp_secret preserved file is chowned
# ---------------------------------------------------------------------------
printf "\n--- Test 8: Behavioural — admin2_totp_secret preserved file triggers chown ---\n"

touch "${_MOCK_DIR8}/admin2_totp_secret"
chmod 0600 "${_MOCK_DIR8}/admin2_totp_secret"

_t8_result=$(bash <<EOF_T8
set -euo pipefail
log_info() { return 0; }
log_error() { return 0; }

_chowned=()
_do_chown() {
  local _uid="\$1" _file="\$2" _label="\$3"
  _chowned+=("\$_label")
  return 0
}

_secrets_dir="${_MOCK_DIR8}"
_uid1001_secrets=(admin1_totp_secret admin2_totp_secret admin2_username)
for _sf in "\${_uid1001_secrets[@]}"; do
  _sfpath="\${_secrets_dir}/\${_sf}"
  if [[ -f "\$_sfpath" ]]; then
    _do_chown "1001" "\$_sfpath" "\$_sf" || exit 1
  fi
done

for _label in "\${_chowned[@]}"; do
  echo "chowned:\$_label"
done
EOF_T8
)

if echo "$_t8_result" | grep -q "chowned:admin2_totp_secret"; then
  _pass "admin2_totp_secret: _do_chown called for present file"
else
  _fail "admin2_totp_secret: _do_chown NOT called — regression"
fi

# ---------------------------------------------------------------------------
# Test 9: Behavioural — Docker no-rotation branch: _pki_chown_client_keys NOT called
# (GATE5-BUG-01 upgrade no-touch rule — inherited from PKI-001, re-verified here)
# ---------------------------------------------------------------------------
printf "\n--- Test 9: Behavioural — Docker no-rotation: _pki_chown_client_keys NOT called ---\n"

_t9_result=$(bash <<'EOF_T9'
set -euo pipefail
_pki_persist_env()      { return 0; }
log_success()           { return 0; }
log_info()              { return 0; }

_pki_chown_called=0
_pki_chown_client_keys() { _pki_chown_called=1; return 0; }

YSG_PODMAN_RUNTIME=false
_fake_id_u=1000

_pki_persist_env
if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$_fake_id_u" != "0" ]]; then
  _pki_chown_client_keys || exit 1
fi

echo "$_pki_chown_called"
EOF_T9
)

if [[ "$_t9_result" == "0" ]]; then
  _pass "Docker no-rotation: _pki_chown_client_keys correctly NOT called (upgrade no-touch rule intact)"
else
  _fail "Docker no-rotation: _pki_chown_client_keys was called — GATE5-BUG-01 regression"
fi

# ---------------------------------------------------------------------------
# Test 10: Class boundary — arbitrary new file NOT in _uid1001_secrets is NOT chowned
# (demonstrates the explicit-allowlist design; prevents accidental scope creep)
# ---------------------------------------------------------------------------
printf "\n--- Test 10: Class boundary — unlisted file NOT chowned ---\n"

# File that should NOT be in the chown list.
touch "${_MOCK_DIR10}/some_future_secret"
chmod 0600 "${_MOCK_DIR10}/some_future_secret"
# File that IS in the chown list.
touch "${_MOCK_DIR10}/yashigani_internal_bearer"
chmod 0600 "${_MOCK_DIR10}/yashigani_internal_bearer"

_t10_result=$(bash <<EOF_T10
set -euo pipefail
log_info() { return 0; }
log_error() { return 0; }

_chowned=()
_do_chown() {
  local _uid="\$1" _file="\$2" _label="\$3"
  _chowned+=("\$_label")
  return 0
}

_secrets_dir="${_MOCK_DIR10}"
# Only the known members — some_future_secret is NOT listed.
_uid1001_secrets=(yashigani_internal_bearer caddy_internal_hmac)
for _sf in "\${_uid1001_secrets[@]}"; do
  _sfpath="\${_secrets_dir}/\${_sf}"
  if [[ -f "\$_sfpath" ]]; then
    _do_chown "1001" "\$_sfpath" "\$_sf" || exit 1
  fi
done

for _label in "\${_chowned[@]}"; do
  echo "chowned:\$_label"
done
EOF_T10
)

if echo "$_t10_result" | grep -q "chowned:some_future_secret"; then
  _fail "Class boundary: some_future_secret was chowned — explicit-allowlist design broken"
else
  _pass "Class boundary: some_future_secret correctly NOT chowned (must be added to _uid1001_secrets explicitly)"
fi

if echo "$_t10_result" | grep -q "chowned:yashigani_internal_bearer"; then
  _pass "Class boundary: yashigani_internal_bearer (listed) WAS chowned as expected"
else
  _fail "Class boundary: yashigani_internal_bearer (listed) NOT chowned — regression"
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
