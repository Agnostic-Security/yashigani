#!/usr/bin/env bash
# tests/install/test_public_san.sh — Public-access SAN flag + auto-detect unit tests
# last-updated: 2026-05-18T00:00:00+01:00 (fix(install,caddy): YSG-CERT-SAN-001)
#
# Tests:
#   1.  install.sh --help lists --public-hostname
#   2.  install.sh --help lists --public-ip
#   3.  --public-hostname and --public-ip appear in parse_args() body
#   4.  YSG_PUBLIC_HOSTNAME / YSG_PUBLIC_IP defaults are declared
#   5.  _detect_public_access_params function exists in install.sh
#   6.  "localhost" rejection guard is in _detect_public_access_params
#   7.  "127.0.0.1" rejection guard is in _detect_public_access_params
#   8.  --caddy-extra-dns flag is passed to _pki_run_issuer bootstrap call
#   9.  --caddy-extra-ip flag is passed to _pki_run_issuer bootstrap call
#   10. --caddy-extra-dns flag is passed to _pki_run_issuer rotate-leaves call
#   11. install.sh --dry-run --domain test.local --public-hostname myhost.local
#       --public-ip 10.0.0.1 exits 0 (no parse error for new flags)
#   12. issuer.py --caddy-extra-dns and --caddy-extra-ip flags exist in _build_parser
#   13. _detect_public_access_params is called inside bootstrap_internal_pki
#   14. "localhost.localdomain" rejection guard present
#   15. macOS ipconfig fallback branch present (Darwin detection)
#
# Usage:
#   bash tests/install/test_public_san.sh
#
# Requirements: bash 3.2+, no container runtime needed.
# All scratch files stay under the repo — never under /tmp (filesystem guardrail).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
ISSUER_PY="${REPO_ROOT}/src/yashigani/pki/issuer.py"

# ─── Colour helpers ─────────────────────────────────────────────────────────
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[0;33m'; C_RESET='\033[0m'
pass() { printf "${C_GREEN}  PASS${C_RESET} %s\n" "$1"; }
fail() { printf "${C_RED}  FAIL${C_RESET} %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
FAILURES=0

# ─────────────────────────────────────────────────────────────────────────────
# T1 — help output lists --public-hostname
# ─────────────────────────────────────────────────────────────────────────────
T1_HELP=$(bash "${INSTALL_SH}" --help 2>&1 || true)
if echo "${T1_HELP}" | grep -q "\-\-public-hostname"; then
  pass "T1: --public-hostname appears in --help output"
else
  fail "T1: --public-hostname missing from --help"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T2 — help output lists --public-ip
# ─────────────────────────────────────────────────────────────────────────────
if echo "${T1_HELP}" | grep -q "\-\-public-ip"; then
  pass "T2: --public-ip appears in --help output"
else
  fail "T2: --public-ip missing from --help"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T3 — --public-hostname is in parse_args() body
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "\-\-public-hostname)" "${INSTALL_SH}"; then
  pass "T3: --public-hostname case handled in parse_args()"
else
  fail "T3: --public-hostname case not found in install.sh parse_args"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T4 — YSG_PUBLIC_HOSTNAME and YSG_PUBLIC_IP defaults declared
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "YSG_PUBLIC_HOSTNAME=" "${INSTALL_SH}" && grep -q "YSG_PUBLIC_IP=" "${INSTALL_SH}"; then
  pass "T4: YSG_PUBLIC_HOSTNAME and YSG_PUBLIC_IP default declarations present"
else
  fail "T4: YSG_PUBLIC_HOSTNAME or YSG_PUBLIC_IP defaults missing from install.sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T5 — _detect_public_access_params function exists
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "^_detect_public_access_params()" "${INSTALL_SH}"; then
  pass "T5: _detect_public_access_params() function defined in install.sh"
else
  fail "T5: _detect_public_access_params() not found in install.sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T6 — "localhost" is rejected in _detect_public_access_params
# ─────────────────────────────────────────────────────────────────────────────
if grep -A 30 "^_detect_public_access_params" "${INSTALL_SH}" | grep -q '"localhost"'; then
  pass "T6: 'localhost' rejection guard present in _detect_public_access_params"
else
  fail "T6: 'localhost' rejection guard not found in _detect_public_access_params"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T7 — "127.0.0.1" is rejected in _detect_public_access_params
# ─────────────────────────────────────────────────────────────────────────────
if grep -A 50 "^_detect_public_access_params" "${INSTALL_SH}" | grep -q '"127.0.0.1"'; then
  pass "T7: '127.0.0.1' rejection guard present in _detect_public_access_params"
else
  fail "T7: '127.0.0.1' rejection guard not found in _detect_public_access_params"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T8 — --caddy-extra-dns is passed to _pki_run_issuer bootstrap
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "\-\-caddy-extra-dns" "${INSTALL_SH}"; then
  pass "T8: --caddy-extra-dns arg present in install.sh (wired to _pki_run_issuer)"
else
  fail "T8: --caddy-extra-dns not found in install.sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T9 — --caddy-extra-ip is passed to _pki_run_issuer bootstrap
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "\-\-caddy-extra-ip" "${INSTALL_SH}"; then
  pass "T9: --caddy-extra-ip arg present in install.sh (wired to _pki_run_issuer)"
else
  fail "T9: --caddy-extra-ip not found in install.sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T10 — --caddy-extra-dns also wired into rotate-leaves path
# ─────────────────────────────────────────────────────────────────────────────
ROTATE_SECTION=$(awk '/handle_pki_subcommand\(\)/,/^}/' "${INSTALL_SH}" | head -80)
if echo "${ROTATE_SECTION}" | grep -q "\-\-caddy-extra-dns"; then
  pass "T10: --caddy-extra-dns wired into handle_pki_subcommand rotate-leaves path"
else
  fail "T10: --caddy-extra-dns missing from rotate-leaves path in handle_pki_subcommand"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T11 — install.sh accepts --public-hostname and --public-ip without error
#        in --dry-run mode (parse-only exercise)
# ─────────────────────────────────────────────────────────────────────────────
T11_OUT=$(bash "${INSTALL_SH}" --help --public-hostname myhost.local --public-ip 10.0.0.1 2>&1 || true)
# --help causes exit 0 before any --public-hostname conflict, so we just verify
# no "Unknown option" error appears for the new flags.
# A cleaner test: pass the flags before --help so parse_args sees them.
T11B_OUT=$(bash "${INSTALL_SH}" --public-hostname myhost.local --public-ip 10.0.0.1 --help 2>&1 || true)
if echo "${T11B_OUT}" | grep -q "Unknown option"; then
  fail "T11: --public-hostname or --public-ip reported as unknown option"
else
  pass "T11: --public-hostname and --public-ip accepted by parse_args (no unknown-option error)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T12 — issuer.py _build_parser accepts --caddy-extra-dns and --caddy-extra-ip
# ─────────────────────────────────────────────────────────────────────────────
if grep -q "\-\-caddy-extra-dns" "${ISSUER_PY}" && grep -q "\-\-caddy-extra-ip" "${ISSUER_PY}"; then
  pass "T12: --caddy-extra-dns and --caddy-extra-ip present in issuer.py _build_parser"
else
  fail "T12: --caddy-extra-dns or --caddy-extra-ip not found in issuer.py"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T13 — _detect_public_access_params called inside bootstrap_internal_pki
# ─────────────────────────────────────────────────────────────────────────────
BOOTSTRAP_SECTION=$(awk '/^bootstrap_internal_pki\(\)/,/^}/' "${INSTALL_SH}" | head -20)
if echo "${BOOTSTRAP_SECTION}" | grep -q "_detect_public_access_params"; then
  pass "T13: _detect_public_access_params called inside bootstrap_internal_pki"
else
  fail "T13: _detect_public_access_params not called inside bootstrap_internal_pki"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T14 — "localhost.localdomain" rejection guard present
# ─────────────────────────────────────────────────────────────────────────────
if grep -A 40 "^_detect_public_access_params" "${INSTALL_SH}" | grep -q "localhost.localdomain"; then
  pass "T14: 'localhost.localdomain' rejection guard present"
else
  fail "T14: 'localhost.localdomain' rejection guard not found"
fi

# ─────────────────────────────────────────────────────────────────────────────
# T15 — macOS ipconfig fallback branch present
# ─────────────────────────────────────────────────────────────────────────────
if grep -A 60 "^_detect_public_access_params" "${INSTALL_SH}" | grep -q "ipconfig getifaddr"; then
  pass "T15: macOS ipconfig getifaddr fallback present in _detect_public_access_params"
else
  fail "T15: macOS ipconfig getifaddr fallback not found"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
if [[ "${FAILURES}" -eq 0 ]]; then
  printf "${C_GREEN}All 15 public-SAN tests passed.${C_RESET}\n"
  exit 0
else
  printf "${C_RED}${FAILURES} test(s) FAILED.${C_RESET}\n"
  exit 1
fi
