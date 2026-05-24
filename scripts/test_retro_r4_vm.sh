#!/usr/bin/env bash
# RETRO-R4 VM integration test
# Tests R4-1 (CA bundle content check), R4-3 (backup sign/verify).
# Run on the VM: bash scripts/test_retro_r4_vm.sh
set -euo pipefail

WORK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

# Source FIPS helpers — manifest build is an integrity-verification path
# (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2 directive 2026-05-24).
# shellcheck source=../lib/yashigani-fips.sh
if [[ -f "${WORK_DIR}/lib/yashigani-fips.sh" ]]; then
  # shellcheck disable=SC1091
  source "${WORK_DIR}/lib/yashigani-fips.sh"
else
  echo "  SKIP: lib/yashigani-fips.sh not found — test cannot run" >&2
  exit 1
fi

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }

echo ""
echo "=== RETRO-R4 VM Integration Test ==="
echo "Work dir: ${WORK_DIR}"
echo ""

# ---- RETRO-R4-1: CA bundle content verification ----
echo "--- RETRO-R4-1: CA bundle grep check ---"
# Verify restore.sh uses cat concatenation, not solo install for root.crt
if grep -q 'cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt' "${WORK_DIR}/restore.sh"; then
  pass "restore.sh contains concatenated CA bundle"
else
  fail "restore.sh missing concatenated CA bundle (RETRO-R4-1)"
fi

if ! grep -Pq 'install\s+-m\s+0644[^\n]*ca_root\.crt[^\n]*PGDATA[^\n]*/root\.crt' "${WORK_DIR}/restore.sh" 2>/dev/null; then
  pass "restore.sh has no solo ca_root.crt -> root.crt install call"
else
  fail "restore.sh still has solo ca_root.crt install pattern (RETRO-R4-1)"
fi

# ---- RETRO-R4-3: Backup signing and verification ----
echo ""
echo "--- RETRO-R4-3: Backup signing and verification ---"

CA_KEY="${WORK_DIR}/docker/secrets/ca_intermediate.key"
CA_CERT="${WORK_DIR}/docker/secrets/ca_intermediate.crt"
DOTENV="${WORK_DIR}/docker/.env"

if [[ ! -f "$CA_KEY" ]]; then
  echo "  SKIP: ca_intermediate.key not found at ${CA_KEY} — PKI not bootstrapped on this VM"
else
  TESTBAK="${WORK_DIR}/backups/retro_r4_test_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "${TESTBAK}"

  # Minimal backup: copy a few secret files + .env
  mkdir -p "${TESTBAK}/secrets"
  for f in ca_root.crt ca_intermediate.crt ca_root.key ca_intermediate.key; do
    [[ -f "${WORK_DIR}/docker/secrets/${f}" ]] && \
      cp "${WORK_DIR}/docker/secrets/${f}" "${TESTBAK}/secrets/" || true
  done
  # Find at least one _client.key
  for f in "${WORK_DIR}/docker/secrets/"*_client.key; do
    [[ -f "$f" ]] && cp "$f" "${TESTBAK}/secrets/" && break
  done
  [[ -f "$DOTENV" ]] && cp "$DOTENV" "${TESTBAK}/.env" || printf 'YASHIGANI_TLS_DOMAIN=test\nPOSTGRES_PASSWORD=test\nYASHIGANI_DB_AES_KEY=test\n' > "${TESTBAK}/.env"
  chmod 0700 "${TESTBAK}"
  find "${TESTBAK}/secrets" -maxdepth 1 -type f -name '*.key' -exec chmod 0400 {} \;

  # Build manifest
  MANIFEST="${TESTBAK}/MANIFEST.sha256"
  SIG="${TESTBAK}/MANIFEST.sha256.sig"
  # _fips_sha256_manifest_stream routes through OpenSSL FIPS Provider when FIPS_MODE=1
  # (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2).
  (
    cd "${TESTBAK}" && \
    find . -type f ! -name 'MANIFEST.sha256' ! -name 'MANIFEST.sha256.sig' -print0 | \
      sort -z | \
      _fips_sha256_manifest_stream > MANIFEST.sha256
  )
  chmod 0400 "${MANIFEST}"

  # Sign
  if openssl dgst -sha256 -sign "${CA_KEY}" -out "${SIG}" "${MANIFEST}" 2>/dev/null; then
    chmod 0400 "${SIG}"
    pass "Manifest signed with ca_intermediate.key"
  else
    fail "openssl dgst -sign failed"
  fi

  # Verify signature (good manifest)
  PUBKEY="$(mktemp)"
  trap 'rm -f "${PUBKEY}"' EXIT
  openssl x509 -in "${CA_CERT}" -noout -pubkey > "${PUBKEY}" 2>/dev/null
  if openssl dgst -sha256 -verify "${PUBKEY}" -signature "${SIG}" "${MANIFEST}" >/dev/null 2>&1; then
    pass "Signature verification of untampered manifest passed"
  else
    fail "Signature verification failed on untampered manifest"
  fi

  # Tamper detection — use a temp copy (MANIFEST is 0400; can't append directly)
  TAMPERED_MANIFEST="$(mktemp)"
  cp "${MANIFEST}" "${TAMPERED_MANIFEST}"
  echo "TAMPERED" >> "${TAMPERED_MANIFEST}"
  if openssl dgst -sha256 -verify "${PUBKEY}" -signature "${SIG}" "${TAMPERED_MANIFEST}" >/dev/null 2>&1; then
    fail "Tampered manifest passed verification (CRITICAL: signature check broken)"
  else
    pass "Tampered manifest correctly rejected"
  fi
  rm -f "${TAMPERED_MANIFEST}"

  rm -f "${PUBKEY}"
  trap - EXIT

  # Full validate_backup dry-run — write a helper script and invoke it.
  # We can't do `bash -c "source restore.sh; ..."` cleanly because restore.sh
  # runs detect_runtime() at the bottom which calls docker/podman. Write a
  # dedicated helper that sources only the functions we need via awk extraction.
  chmod u+w "${MANIFEST}" "${SIG}" 2>/dev/null || true
  # _fips_sha256_manifest_stream routes through OpenSSL FIPS Provider when FIPS_MODE=1
  # (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2).
  (
    cd "${TESTBAK}" && \
    find . -type f ! -name 'MANIFEST.sha256' ! -name 'MANIFEST.sha256.sig' -print0 | \
      sort -z | \
      _fips_sha256_manifest_stream > MANIFEST.sha256
  )
  chmod 0400 "${MANIFEST}"
  openssl dgst -sha256 -sign "${CA_KEY}" -out "${SIG}" "${MANIFEST}" 2>/dev/null
  chmod 0400 "${SIG}"

  # Write a minimal validate_backup harness
  VTEST_SCRIPT="$(mktemp)"
  cat > "${VTEST_SCRIPT}" << VTEST_HEREDOC
#!/usr/bin/env bash
set -uo pipefail
C_GREEN=""; C_RED=""; C_YELLOW=""; C_BOLD=""; C_RESET=""
log_info()    { printf "    --> %s\n" "\$*"; }
log_success() { printf "    ok  %s\n" "\$*"; }
log_error()   { printf "    !!  ERROR: %s\n" "\$*" >&2; }
log_warn()    { printf "    !!  WARNING: %s\n" "\$*"; }
source <(awk '/^validate_backup\(\)/{p=1} p{print} /^\}$/{if(p){p=0}}' '${WORK_DIR}/restore.sh')
validate_backup "\$1"
VTEST_HEREDOC
  chmod 755 "${VTEST_SCRIPT}"

  if bash "${VTEST_SCRIPT}" "${TESTBAK}" 2>&1 | grep -q "Backup validation passed"; then
    pass "validate_backup passed on well-formed signed backup"
  else
    fail "validate_backup failed on well-formed signed backup"
  fi
  rm -f "${VTEST_SCRIPT}"

  # Clean up
  rm -rf "${TESTBAK}"
  pass "Test backup cleaned up"
fi

echo ""
echo "=== Summary ==="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""

[[ "${FAIL}" -eq 0 ]] && echo "RETRO-R4 VM test: ALL GREEN" || { echo "RETRO-R4 VM test: FAIL"; exit 1; }
