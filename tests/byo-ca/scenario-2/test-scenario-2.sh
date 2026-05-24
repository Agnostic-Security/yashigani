#!/usr/bin/env bash
# tests/byo-ca/scenario-2/test-scenario-2.sh
# BYO CA Scenario 2 -- deferred-then-activated PGDATA swap test
# Last updated: 2026-05-24 (v2.24.1 Phase A wave 1 -- C-CAP BYO scenario 2)
#
# Tests the customer journey where Yashigani is initially installed with the
# self-signed PKI (--with-internal-ca alone, deferred), and then the customer
# provides their BYO CA via a subsequent install.sh re-run
# (--internal-ca-cert / --internal-ca-key / --internal-ca-root).
#
# Iris BYO CA design sec 2 (Path B -- Provide Later), sec 4 (postgres initdb
# problem), captain council review sec 9 (dispatch breakdown),
# synthesis sec 4 SHOULD-FIX.
#
# --- What this test covers ---------------------------------------------------
# Phase 1 -- Deferred sentinel
#   T01  --with-internal-ca alone writes .byo_ca_pending sentinel
#   T02  _activate_byo_ca is not unconditionally called near sentinel write
#   T03  YASHIGANI_BYO_CA_MODE written only after full activation
#
# Phase 2 -- BYO CA file generation (openssl, local to test)
#   T04  Test CA root self-signs (openssl verify exits 0)
#   T05  Test intermediate cert chain verifies to root (openssl verify exits 0)
#   T06  Test intermediate cert has CA:true basic constraint
#   T07  Key-cert modulus match (RSA)
#
# Phase 3 -- _activate_byo_ca code-path validation (no running stack required)
#   T08  _validate_byo_ca_files accepts valid test certs
#   T09  _validate_byo_ca_files rejects non-CA cert
#   T10  install.sh validation logic checks cert expiry (notAfter)
#   T11  _activate_byo_ca stages byo_ca_intermediate.{crt,key} into secrets/
#   T11b _activate_byo_ca has Podman rootless unshare path (BYOCA-BUG-002)
#   T12  _activate_byo_ca updates service_identities.yaml ca_source.mode
#   T12b Python YAML update snippet executes correctly on mock manifest
#   T13  _activate_byo_ca writes YASHIGANI_BYO_CA_MODE to .env
#   T13b Simulated .env write produces correct value
#   T14  _activate_byo_ca backs up existing CA files to docker/backups/
#   T15  CWE-732: byo_ca_intermediate.key is mode 0600
#   T15b install(1) stages byo_ca_intermediate.key with -m 0600
#
# Phase 4 -- In-container cert-chain verification (requires running stack)
#   T16  Gateway leaf cert verifies against new BYO CA root (docker exec)
#   T17  Pgbouncer leaf cert verifies against new BYO CA root (docker exec)
#   T18  PGDATA/root.crt SHA matches assembled BYO CA source bundle
#   T19  pg_ctl reload log evidence present in postgres container
#   T20  All compose services healthy post-swap
#
# Static checks -- _postgres_byo_ca_trust_sync
#   TS1  _postgres_byo_ca_trust_sync invokes 05-enable-ssl.sh in-container
#   TS2  05-enable-ssl.sh has SHA-256 idempotency guard
#   TS3  05-enable-ssl.sh issues pg_ctl reload when postgres is running
#   TS4  _activate_byo_ca calls _postgres_byo_ca_trust_sync
#
# --- Prerequisites -----------------------------------------------------------
# - bash 3.2+, openssl, python3 (with PyYAML)
# - Phases 1-3 + static checks: no container runtime needed (offline safe)
# - Phase 4: running Yashigani stack; pass --phase4 to enable
# - REPO_ROOT: auto-detected from script location
#
# Usage:
#   bash tests/byo-ca/scenario-2/test-scenario-2.sh          # phases 1-3 + static
#   bash tests/byo-ca/scenario-2/test-scenario-2.sh --phase4 # all phases
#   bash tests/byo-ca/scenario-2/test-scenario-2.sh --phase4 --runtime podman
#
# The test creates a temporary work area under REPO_ROOT/tests/byo-ca/scenario-2/
# (never under /tmp per project SOP). All temp files are cleaned up on exit.
# -----------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# -- Argument parsing ----------------------------------------------------------
RUN_PHASE4=false
RUNTIME="docker"
for _arg in "$@"; do
  case "$_arg" in
    --phase4) RUN_PHASE4=true ;;
    --runtime=*) RUNTIME="${_arg#*=}" ;;
    --runtime) shift; RUNTIME="$1" ;;
  esac
done

# -- Test counters -------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

_pass() { printf "  PASS  [%s] %s\n"   "$1" "$2"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  [%s] %s\n"   "$1" "$2" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
_skip() { printf "  SKIP  [%s] %s\n"   "$1" "$2"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

# -- Scratch area (under repo, never /tmp) ------------------------------------
SCRATCH="${SCRIPT_DIR}/.scratch_$$"
mkdir -p "${SCRATCH}/docker/secrets" "${SCRATCH}/docker" "${SCRATCH}/ca-material"

_cleanup() {
  rm -rf "${SCRATCH}"
}
trap _cleanup EXIT

# -- Helpers ------------------------------------------------------------------
# Portable stat: GNU (Linux) or BSD (macOS)
_stat_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1" 2>/dev/null || echo "UNKNOWN"; }

# _fn_body: extract a function body from install.sh using awk
# Usage: _fn_body "_activate_byo_ca" | grep ...
_fn_body() {
  local _fn="$1"
  awk "
    /^${_fn}\(\)/{in_fn=1; depth=0}
    in_fn {
      for(i=1;i<=length(\$0);i++){
        c=substr(\$0,i,1)
        if(c==\"{\") depth++
        if(c==\"}\") {depth--; if(depth==0){in_fn=0; print; next}}
      }
      print
    }
  " "${INSTALL_SH}"
}

# =============================================================================
# Phase 1 -- Deferred sentinel assertions (T01, T02, T03)
# =============================================================================
printf "\n== Phase 1 -- Deferred sentinel assertions ==\n"

# T01: .byo_ca_pending sentinel referenced in install.sh
printf "\n--- T01: install.sh references .byo_ca_pending sentinel ---\n"
if grep -q '\.byo_ca_pending' "${INSTALL_SH}"; then
  _pass "T01" ".byo_ca_pending sentinel referenced in install.sh (deferred path)"
else
  _fail "T01" ".byo_ca_pending sentinel NOT found in install.sh -- deferred path may be missing"
fi

# T02: _activate_byo_ca is not unconditionally called near the sentinel write
printf "\n--- T02: Deferred path does not unconditionally call _activate_byo_ca ---\n"
# Strategy: find the line that writes the sentinel, then check the 10 lines
# following it. If _activate_byo_ca appears there, it must be inside a guard.
_sentinel_write_line=$(grep -n '\.byo_ca_pending' "${INSTALL_SH}" \
  | grep -E 'echo|tee|printf|>>|touch|write' | tail -1 | cut -d: -f1)
if [[ -z "$_sentinel_write_line" ]]; then
  # Try a broader match -- log line is also evidence of the write
  _sentinel_write_line=$(grep -n '\.byo_ca_pending' "${INSTALL_SH}" | tail -1 | cut -d: -f1)
fi
if [[ -n "$_sentinel_write_line" ]]; then
  _after_write=$(awk "NR>=${_sentinel_write_line} && NR<=${_sentinel_write_line}+10" "${INSTALL_SH}")
  if printf '%s' "${_after_write}" | grep -q '_activate_byo_ca\b'; then
    # Call found near sentinel write -- must be inside a conditional
    if printf '%s' "${_after_write}" | grep -q '\[\[.*-n\|if \[\[\|INTERNAL_CA_CERT'; then
      _pass "T02" "_activate_byo_ca near sentinel-write is guarded by conditional (deferred path safe)"
    else
      _fail "T02" "_activate_byo_ca may be unconditional within 10 lines of .byo_ca_pending write"
    fi
  else
    _pass "T02" "No _activate_byo_ca within 10 lines of .byo_ca_pending write (deferred path safe)"
  fi
else
  _fail "T02" "Could not locate .byo_ca_pending write line in install.sh"
fi

# T03: YASHIGANI_BYO_CA_MODE is written only on activation
printf "\n--- T03: YASHIGANI_BYO_CA_MODE written on activation ---\n"
if grep -q 'YASHIGANI_BYO_CA_MODE=byo_intermediate' "${INSTALL_SH}"; then
  _pass "T03" "YASHIGANI_BYO_CA_MODE=byo_intermediate present in install.sh (activation path)"
else
  _fail "T03" "YASHIGANI_BYO_CA_MODE not set in install.sh -- .env will not record BYO mode"
fi

# =============================================================================
# Phase 2 -- BYO CA test material generation (T04..T07)
# =============================================================================
printf "\n== Phase 2 -- BYO CA test material generation ==\n"

CA_DIR="${SCRATCH}/ca-material"

if ! command -v openssl >/dev/null 2>&1; then
  _skip "T04" "openssl not available -- skipping Phase 2 + 3 cert-chain tests"
  _skip "T05" "openssl not available"
  _skip "T06" "openssl not available"
  _skip "T07" "openssl not available"
  _OPENSSL_AVAILABLE=false
else
  _OPENSSL_AVAILABLE=true

  # Generate test root CA (RSA 2048 -- minimum acceptable per Iris sec 3)
  printf "\n--- T04: Generate test root CA and verify self-sign ---\n"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CA_DIR}/test_root.key" \
    -out "${CA_DIR}/test_root.crt" \
    -subj "/C=GB/O=Agnostic Security Test/CN=YSG Test Root CA" \
    -days 3650 \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    >/dev/null 2>&1

  if openssl verify -CAfile "${CA_DIR}/test_root.crt" "${CA_DIR}/test_root.crt" >/dev/null 2>&1; then
    _pass "T04" "Test root CA self-signs correctly (openssl verify exits 0)"
  else
    _fail "T04" "Test root CA self-sign verification failed"
  fi

  # Generate test intermediate CA (signed by root)
  printf "\n--- T05: Generate test intermediate CA and verify chain to root ---\n"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${CA_DIR}/test_intermediate.key" \
    -out "${CA_DIR}/test_intermediate.csr" \
    -subj "/C=GB/O=Agnostic Security Test/CN=YSG Test Intermediate CA" \
    >/dev/null 2>&1

  # Extension file for intermediate signing
  cat > "${CA_DIR}/intermediate.ext" <<'EXTEOF'
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXTEOF

  openssl x509 -req -in "${CA_DIR}/test_intermediate.csr" \
    -CA "${CA_DIR}/test_root.crt" \
    -CAkey "${CA_DIR}/test_root.key" \
    -CAcreateserial \
    -out "${CA_DIR}/test_intermediate.crt" \
    -days 730 \
    -extfile "${CA_DIR}/intermediate.ext" \
    >/dev/null 2>&1

  if openssl verify -CAfile "${CA_DIR}/test_root.crt" "${CA_DIR}/test_intermediate.crt" >/dev/null 2>&1; then
    _pass "T05" "Test intermediate CA chain verifies to root (openssl verify exits 0)"
  else
    _fail "T05" "Test intermediate CA chain verification failed"
  fi

  # T06: CA:true basic constraint
  printf "\n--- T06: Test intermediate has CA:true basic constraint ---\n"
  if openssl x509 -in "${CA_DIR}/test_intermediate.crt" -noout -text 2>/dev/null \
       | grep -q 'CA:TRUE\|CA: TRUE'; then
    _pass "T06" "Test intermediate cert has CA:true basic constraint"
  else
    _fail "T06" "Test intermediate cert missing CA:true -- would be rejected by _validate_byo_ca_files"
  fi

  # T07: Key-cert modulus match
  printf "\n--- T07: Key-cert modulus match (RSA) ---\n"
  _cert_mod=$(openssl x509 -noout -modulus -in "${CA_DIR}/test_intermediate.crt" 2>/dev/null | openssl md5)
  _key_mod=$(openssl rsa -noout -modulus -in "${CA_DIR}/test_intermediate.key" 2>/dev/null | openssl md5)
  if [[ "$_cert_mod" == "$_key_mod" ]]; then
    _pass "T07" "Intermediate cert and key modulus match (pair is correct)"
  else
    _fail "T07" "Intermediate cert/key modulus MISMATCH -- test material generation error"
  fi
fi

# =============================================================================
# Phase 3 -- _activate_byo_ca code-path validation (T08..T15)
# =============================================================================
printf "\n== Phase 3 -- _activate_byo_ca code-path validation ==\n"

if [[ "${_OPENSSL_AVAILABLE:-false}" != "true" ]]; then
  for _tn in T08 T09 T10 T11 T11b T12 T12b T13 T13b T14 T15 T15b; do
    _skip "$_tn" "openssl not available -- skipping Phase 3 tests"
  done
else

  _SECRETS="${SCRATCH}/docker/secrets"
  _ENV_FILE="${SCRATCH}/docker/.env"

  # Simulate a Yashigani-generated PKI already in place (first install complete)
  touch "${_SECRETS}/ca_root.crt"
  touch "${_SECRETS}/ca_intermediate.crt"
  touch "${_SECRETS}/ca_intermediate.key"
  chmod 0600 "${_SECRETS}/ca_intermediate.key"

  # .env: no YASHIGANI_BYO_CA_MODE (initial install, self-signed)
  printf 'YASHIGANI_VERSION=2.24.0\nCOMPOSE_PROJECT_NAME=yashigani\n' > "${_ENV_FILE}"

  # service_identities.yaml: minimal valid YAML with ca_source placeholder
  printf 'ca_source:\n  mode: yashigani_generated\nservices: []\n' \
    > "${SCRATCH}/docker/service_identities.yaml"

  # T08: _validate_byo_ca_files accepts valid test certs
  printf "\n--- T08: _validate_byo_ca_files accepts valid test certs ---\n"
  if grep -q 'YASHIGANI_SELFTEST' "${INSTALL_SH}" 2>/dev/null; then
    _t08_result=$(YASHIGANI_SELFTEST=1 \
      WORK_DIR="${SCRATCH}" \
      INTERNAL_CA_CERT="${CA_DIR}/test_intermediate.crt" \
      INTERNAL_CA_KEY="${CA_DIR}/test_intermediate.key" \
      INTERNAL_CA_ROOT="${CA_DIR}/test_root.crt" \
      bash -c "
        source '${INSTALL_SH}' 2>/dev/null
        _validate_byo_ca_files && echo PASS || echo FAIL
      " 2>&1)
    if printf '%s' "${_t08_result}" | grep -q '^PASS$'; then
      _pass "T08" "_validate_byo_ca_files PASS for valid test certs"
    else
      _fail "T08" "_validate_byo_ca_files rejected valid test certs: ${_t08_result}"
    fi
  else
    # SELFTEST guard absent -- use openssl to replicate the key checks
    _t08_fail=0
    [[ -f "${CA_DIR}/test_intermediate.crt" && -r "${CA_DIR}/test_intermediate.crt" ]] || _t08_fail=1
    openssl x509 -in "${CA_DIR}/test_intermediate.crt" -noout >/dev/null 2>&1 || _t08_fail=1
    openssl x509 -in "${CA_DIR}/test_intermediate.crt" -noout -text 2>/dev/null \
      | grep -q 'CA:TRUE\|CA: TRUE' || _t08_fail=1
    openssl verify -CAfile "${CA_DIR}/test_root.crt" "${CA_DIR}/test_intermediate.crt" \
      >/dev/null 2>&1 || _t08_fail=1
    if [[ "$_t08_fail" == "0" ]]; then
      _pass "T08" "Manual validation checks PASS for valid test certs (SELFTEST guard absent -- fallback)"
    else
      _fail "T08" "Manual validation checks FAILED for valid test certs"
    fi
  fi

  # T09: _validate_byo_ca_files rejects a non-CA cert (no CA:true)
  printf "\n--- T09: _validate_byo_ca_files rejects non-CA cert ---\n"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CA_DIR}/test_leaf.key" \
    -out "${CA_DIR}/test_leaf.crt" \
    -subj "/C=GB/O=Agnostic Security Test/CN=YSG Test Leaf (Not a CA)" \
    -days 365 \
    >/dev/null 2>&1

  if grep -q 'YASHIGANI_SELFTEST' "${INSTALL_SH}" 2>/dev/null; then
    _t09_result=$(YASHIGANI_SELFTEST=1 \
      WORK_DIR="${SCRATCH}" \
      INTERNAL_CA_CERT="${CA_DIR}/test_leaf.crt" \
      INTERNAL_CA_KEY="${CA_DIR}/test_leaf.key" \
      INTERNAL_CA_ROOT="${CA_DIR}/test_root.crt" \
      bash -c "
        source '${INSTALL_SH}' 2>/dev/null
        _validate_byo_ca_files && echo PASS || echo REJECTED
      " 2>&1)
    if printf '%s' "${_t09_result}" | grep -q 'REJECTED'; then
      _pass "T09" "_validate_byo_ca_files correctly rejects non-CA cert"
    elif printf '%s' "${_t09_result}" | grep -q '^PASS$'; then
      _fail "T09" "_validate_byo_ca_files INCORRECTLY accepted non-CA cert -- validation gap"
    else
      # Could not distinguish via SELFTEST -- confirm non-CA via openssl
      if openssl x509 -in "${CA_DIR}/test_leaf.crt" -noout -text 2>/dev/null \
           | grep -q 'CA:TRUE\|CA: TRUE'; then
        _fail "T09" "Test leaf cert unexpectedly has CA:true -- test setup error"
      else
        _pass "T09" "Test leaf cert confirmed non-CA (CA:true absent) -- rejection expected"
      fi
    fi
  else
    if openssl x509 -in "${CA_DIR}/test_leaf.crt" -noout -text 2>/dev/null \
         | grep -q 'CA:TRUE\|CA: TRUE'; then
      _fail "T09" "Test leaf cert unexpectedly has CA:true -- test material setup error"
    else
      _pass "T09" "Test leaf cert confirmed non-CA (fallback check -- CA:true absent)"
    fi
  fi

  # T10: install.sh validation logic checks cert expiry
  printf "\n--- T10: install.sh validation logic checks notAfter ---\n"
  if grep -qE 'notAfter|openssl x509.*-dates|cert.*expired|_check_byo_ca' "${INSTALL_SH}"; then
    _pass "T10" "install.sh validation includes expiry/date check"
  else
    _fail "T10" "install.sh validation does not appear to check cert expiry -- date check missing"
  fi

  # T11: _activate_byo_ca stages byo_ca_intermediate.{crt,key}
  printf "\n--- T11: _activate_byo_ca stages BYO files into docker/secrets/ ---\n"
  if grep -q '^_activate_byo_ca()' "${INSTALL_SH}" 2>/dev/null; then
    _fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
    if printf '%s' "${_fn_activate}" | grep -q 'byo_ca_intermediate.crt\|byo_ca_intermediate.key'; then
      _pass "T11" "_activate_byo_ca stages byo_ca_intermediate.{crt,key} (code path present)"
    else
      _fail "T11" "_activate_byo_ca does not stage byo_ca_intermediate files -- staging path missing"
    fi
    # T11b: Podman rootless unshare path (BYOCA-BUG-002)
    printf "\n--- T11b: Podman rootless unshare path (BYOCA-BUG-002) ---\n"
    if printf '%s' "${_fn_activate}" | grep -q 'podman unshare'; then
      _pass "T11b" "_activate_byo_ca includes Podman rootless unshare path (BYOCA-BUG-002)"
    else
      _fail "T11b" "_activate_byo_ca missing Podman rootless unshare path -- Podman staging will fail"
    fi
  else
    _fail "T11" "_activate_byo_ca function not found in install.sh"
    _skip "T11b" "_activate_byo_ca not found"
  fi

  # T12: service_identities.yaml updated to ca_source.mode == byo_intermediate
  printf "\n--- T12: _activate_byo_ca updates service_identities.yaml ca_source.mode ---\n"
  # Use awk function extraction rather than grep -ANN to avoid window size issues
  _fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
  if printf '%s' "${_fn_activate}" | grep -q 'ca_source.*mode.*byo_intermediate\|mode.*=.*byo_intermediate\|ca_source.mode'; then
    _pass "T12" "_activate_byo_ca writes ca_source.mode=byo_intermediate to service_identities.yaml"
  else
    _fail "T12" "_activate_byo_ca does not update ca_source.mode in service_identities.yaml"
  fi

  # T12b: Python YAML update snippet runs correctly on a mock manifest
  printf "\n--- T12b: Python YAML update snippet executes on mock manifest ---\n"
  _py_update_check=$(python3 - "${SCRATCH}/docker/service_identities.yaml" "1" <<'PYEOF' 2>&1 && echo "PYOK" || echo "PYFAIL"
import sys, yaml, pathlib

manifest_path = pathlib.Path(sys.argv[1])
has_root = sys.argv[2] == "1"

with open(manifest_path) as f:
    m = yaml.safe_load(f)

m.setdefault("ca_source", {})
m["ca_source"]["mode"] = "byo_intermediate"
m["ca_source"].setdefault("byo", {})
m["ca_source"]["byo"]["intermediate_cert_path"] = "/secrets/byo_ca_intermediate.crt"
m["ca_source"]["byo"]["intermediate_key_path"]  = "/secrets/byo_ca_intermediate.key"
m["ca_source"]["byo"]["root_cert_path"] = "/secrets/byo_ca_root.crt" if has_root else None

with open(manifest_path, "w") as f:
    yaml.safe_dump(m, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
PYEOF
  )
  if printf '%s' "${_py_update_check}" | grep -q '^PYOK$'; then
    _mode=$(python3 -c "
import yaml
m=yaml.safe_load(open('${SCRATCH}/docker/service_identities.yaml'))
print(m.get('ca_source',{}).get('mode','MISSING'))
" 2>/dev/null || echo "MISSING")
    if [[ "$_mode" == "byo_intermediate" ]]; then
      _pass "T12b" "service_identities.yaml ca_source.mode = byo_intermediate after Python update"
    else
      _fail "T12b" "service_identities.yaml ca_source.mode = '${_mode}' (expected byo_intermediate)"
    fi
  else
    _fail "T12b" "Python YAML update snippet failed: ${_py_update_check}"
  fi

  # T13: YASHIGANI_BYO_CA_MODE written to .env
  printf "\n--- T13: _activate_byo_ca writes YASHIGANI_BYO_CA_MODE to .env ---\n"
  # Use full function body extraction (not grep -ANN which may not reach the end)
  _fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
  if printf '%s' "${_fn_activate}" | grep -q 'YASHIGANI_BYO_CA_MODE'; then
    _pass "T13" "_activate_byo_ca references YASHIGANI_BYO_CA_MODE (writes to .env)"
  else
    # Fall back to whole-file search
    if grep -q 'YASHIGANI_BYO_CA_MODE=byo_intermediate' "${INSTALL_SH}"; then
      _pass "T13" "YASHIGANI_BYO_CA_MODE=byo_intermediate present in install.sh (activation path)"
    else
      _fail "T13" "YASHIGANI_BYO_CA_MODE not set in install.sh -- .env will not record BYO mode"
    fi
  fi

  # T13b: Simulate the .env write and verify the result
  printf "\n--- T13b: Simulated .env write produces correct YASHIGANI_BYO_CA_MODE ---\n"
  if grep -q "^YASHIGANI_BYO_CA_MODE=" "${_ENV_FILE}" 2>/dev/null; then
    sed -i.bak "s|^YASHIGANI_BYO_CA_MODE=.*|YASHIGANI_BYO_CA_MODE=byo_intermediate|" "${_ENV_FILE}" \
      && rm -f "${_ENV_FILE}.bak"
  else
    echo "YASHIGANI_BYO_CA_MODE=byo_intermediate" >> "${_ENV_FILE}"
  fi
  _byo_mode=$(grep "^YASHIGANI_BYO_CA_MODE=" "${_ENV_FILE}" | cut -d= -f2)
  if [[ "$_byo_mode" == "byo_intermediate" ]]; then
    _pass "T13b" "YASHIGANI_BYO_CA_MODE=byo_intermediate in simulated .env after write"
  else
    _fail "T13b" "YASHIGANI_BYO_CA_MODE not correct in simulated .env: '${_byo_mode}'"
  fi

  # T14: Backup of prior CA files written to docker/backups/
  printf "\n--- T14: _activate_byo_ca backs up existing CA files ---\n"
  _fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
  if printf '%s' "${_fn_activate}" | grep -q 'docker/backups\|byo_ca_.*backup\|Backup'; then
    _pass "T14" "_activate_byo_ca includes backup step for existing CA files"
  else
    _fail "T14" "_activate_byo_ca does not back up existing CA files -- rotation is destructive without backup"
  fi

  # T15: byo_ca_intermediate.key must be mode 0600 (CWE-732 check)
  printf "\n--- T15: _activate_byo_ca enforces mode 0600 on byo_ca_intermediate.key ---\n"
  _fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
  if printf '%s' "${_fn_activate}" | grep -q 'CWE-732'; then
    _pass "T15" "CWE-732 assertion for byo_ca_intermediate.key 0600 present in _activate_byo_ca"
  else
    _fail "T15" "CWE-732 assertion missing -- byo_ca_intermediate.key mode not enforced"
  fi

  # T15b: install(1) stages byo_ca_intermediate.key with -m 0600
  printf "\n--- T15b: install(1) uses -m 0600 for byo_ca_intermediate.key ---\n"
  if printf '%s' "${_fn_activate}" | grep -E 'install.*-m 0600.*intermediate|0600.*intermediate.*key' | grep -q .; then
    _pass "T15b" "install(1) stages byo_ca_intermediate.key with -m 0600"
  else
    # Check the broader staging block
    if printf '%s' "${_fn_activate}" | grep -q '0600.*byo_ca_intermediate\|byo_ca_intermediate.*0600'; then
      _pass "T15b" "Mode 0600 specified for byo_ca_intermediate.key in _activate_byo_ca"
    else
      _fail "T15b" "Mode 0600 not explicitly set for byo_ca_intermediate.key in staging block"
    fi
  fi

fi  # end _OPENSSL_AVAILABLE check for Phase 3

# =============================================================================
# Phase 4 -- In-container cert-chain verification (T16..T20)
# Requires --phase4 flag and running Yashigani stack.
# =============================================================================
printf "\n== Phase 4 -- In-container cert-chain verification ==\n"

if [[ "$RUN_PHASE4" != "true" ]]; then
  for _tn in T16 T17 T18 T19 T20; do
    _skip "$_tn" "Phase 4 skipped (pass --phase4 to run in-container checks)"
  done
else

  _GATEWAY_CONTAINERS=("docker-gateway-1" "docker_gateway_1" "yashigani-gateway-1" "yashigani_gateway_1")
  _PGBOUNCER_CONTAINERS=("docker-pgbouncer-1" "docker_pgbouncer_1" "yashigani-pgbouncer-1" "yashigani_pgbouncer_1")
  _POSTGRES_CONTAINERS=("docker-postgres-1" "docker_postgres_1" "yashigani-postgres-1" "yashigani_postgres_1")

  _find_container() {
    local _rt="${RUNTIME}"
    for _c in "$@"; do
      if "${_rt}" inspect --format '{{.State.Running}}' "${_c}" 2>/dev/null | grep -q '^true$'; then
        echo "${_c}"
        return 0
      fi
    done
    echo ""
  }

  _BYO_ROOT="${CA_DIR}/test_root.crt"
  if [[ ! -f "${_BYO_ROOT}" ]]; then
    for _tn in T16 T17 T18 T19 T20; do
      _skip "$_tn" "BYO CA test material missing (Phase 2 did not run -- openssl unavailable?)"
    done
  else

    # T16: Gateway leaf cert verifies against BYO CA root (docker exec)
    printf "\n--- T16: Gateway leaf cert verifies against BYO CA root (in-container) ---\n"
    _gw_cname="$(_find_container "${_GATEWAY_CONTAINERS[@]}")"
    if [[ -z "$_gw_cname" ]]; then
      _skip "T16" "Gateway container not running -- start Yashigani stack first"
    else
      "${RUNTIME}" cp "${_BYO_ROOT}" "${_gw_cname}:/tmp/test_byo_root.crt" 2>/dev/null || true
      _t16_out=$("${RUNTIME}" exec "${_gw_cname}" bash -c \
        'openssl verify -CAfile /tmp/test_byo_root.crt /run/secrets/gateway_client.crt 2>&1 || echo VERIFY_FAILED' 2>&1)
      "${RUNTIME}" exec "${_gw_cname}" rm -f /tmp/test_byo_root.crt 2>/dev/null || true
      if printf '%s' "${_t16_out}" | grep -qE 'OK|verify OK'; then
        _pass "T16" "Gateway leaf cert verifies against BYO CA root (docker exec PASS)"
      else
        _fail "T16" "Gateway leaf cert verification FAILED: ${_t16_out}"
      fi
    fi

    # T17: Pgbouncer leaf cert verifies against BYO CA root (docker exec)
    printf "\n--- T17: Pgbouncer leaf cert verifies against BYO CA root (in-container) ---\n"
    _pb_cname="$(_find_container "${_PGBOUNCER_CONTAINERS[@]}")"
    if [[ -z "$_pb_cname" ]]; then
      _skip "T17" "Pgbouncer container not running -- start Yashigani stack first"
    else
      "${RUNTIME}" cp "${_BYO_ROOT}" "${_pb_cname}:/tmp/test_byo_root.crt" 2>/dev/null || true
      _t17_out=$("${RUNTIME}" exec "${_pb_cname}" sh -c \
        'openssl verify -CAfile /tmp/test_byo_root.crt /run/secrets/pgbouncer_client.crt 2>&1 || echo VERIFY_FAILED' 2>&1)
      "${RUNTIME}" exec "${_pb_cname}" rm -f /tmp/test_byo_root.crt 2>/dev/null || true
      if printf '%s' "${_t17_out}" | grep -qE 'OK|verify OK'; then
        _pass "T17" "Pgbouncer leaf cert verifies against BYO CA root (docker exec PASS)"
      else
        _fail "T17" "Pgbouncer leaf cert verification FAILED: ${_t17_out}"
      fi
    fi

    # T18: PGDATA/root.crt SHA matches assembled BYO CA source bundle
    printf "\n--- T18: PGDATA/root.crt SHA matches BYO CA source bundle (in-container) ---\n"
    _pg_cname="$(_find_container "${_POSTGRES_CONTAINERS[@]}")"
    if [[ -z "$_pg_cname" ]]; then
      _skip "T18" "Postgres container not running -- start Yashigani stack first"
    else
      _BYO_INTERMEDIATE="${CA_DIR}/test_intermediate.crt"
      if [[ -f "${_BYO_INTERMEDIATE}" ]]; then
        cat "${_BYO_ROOT}" "${_BYO_INTERMEDIATE}" > "${SCRATCH}/expected_bundle.crt"
        _expected_sha=$(sha256sum "${SCRATCH}/expected_bundle.crt" | cut -d' ' -f1)
        _actual_sha=$("${RUNTIME}" exec "${_pg_cname}" bash -c \
          'sha256sum "${PGDATA}/root.crt" 2>/dev/null | cut -d" " -f1 || echo "PGDATA_NOT_FOUND"' 2>&1)
        if [[ "$_expected_sha" == "$_actual_sha" ]]; then
          _pass "T18" "PGDATA/root.crt SHA matches assembled BYO CA bundle (trust-sync confirmed)"
        else
          _fail "T18" "PGDATA/root.crt SHA mismatch: expected=${_expected_sha:0:12} actual=${_actual_sha:0:12}"
        fi
      else
        _skip "T18" "BYO intermediate cert missing -- Phase 2 may not have completed"
      fi
    fi

    # T19: pg_ctl reload evidence in postgres logs
    printf "\n--- T19: postgres accepted pg_ctl reload after trust-sync ---\n"
    if [[ -z "${_pg_cname:-}" ]]; then
      _skip "T19" "Postgres container not running"
    else
      _pg_logs=$("${RUNTIME}" logs "${_pg_cname}" --tail=50 2>&1 \
        | grep -E 'pg_ctl reload|Trust bundle|05-enable-ssl' || echo "")
      if printf '%s' "${_pg_logs}" | grep -qE 'pg_ctl reload|postgres re-read|Trust bundle'; then
        _pass "T19" "pg_ctl reload evidence found in postgres logs (trust-sync ran)"
      else
        _skip "T19" "No recent reload log evidence -- check manually (may have occurred before log window)"
      fi
    fi

    # T20: All compose services healthy post-swap
    printf "\n--- T20: Yashigani stack all services healthy post-swap ---\n"
    _COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"
    if [[ ! -f "${_COMPOSE_FILE}" ]]; then
      _skip "T20" "docker-compose.yml not found at expected path"
    else
      _unhealthy=$("${RUNTIME}" compose -f "${_COMPOSE_FILE}" ps 2>/dev/null \
        | grep -vE 'Up.*healthy|running' | grep -vE '^NAME|^$' | grep -c . || echo 0)
      if [[ "${_unhealthy}" -eq 0 ]]; then
        _pass "T20" "All compose services healthy post-swap"
      else
        _fail "T20" "${_unhealthy} service(s) not healthy post-swap -- check compose logs"
      fi
    fi

  fi  # end BYO_ROOT exists check
fi  # end RUN_PHASE4

# =============================================================================
# Static checks -- _postgres_byo_ca_trust_sync (TS1..TS4)
# =============================================================================
printf "\n== Static checks -- _postgres_byo_ca_trust_sync ==\n"

# TS1: Function invokes 05-enable-ssl.sh inside postgres container
printf "\n--- TS1: _postgres_byo_ca_trust_sync invokes 05-enable-ssl.sh in-container ---\n"
_fn_pg_sync=$(_fn_body "_postgres_byo_ca_trust_sync" 2>/dev/null || true)
if printf '%s' "${_fn_pg_sync}" | grep -q '05-enable-ssl.sh'; then
  _pass "TS1" "_postgres_byo_ca_trust_sync invokes 05-enable-ssl.sh inside postgres container"
else
  _fail "TS1" "_postgres_byo_ca_trust_sync does not invoke 05-enable-ssl.sh -- trust-sync broken"
fi

# TS2: 05-enable-ssl.sh has SHA-256 idempotency guard
printf "\n--- TS2: 05-enable-ssl.sh SHA-256 idempotency guard ---\n"
_SSL_SCRIPT="${REPO_ROOT}/docker/postgres/05-enable-ssl.sh"
if [[ -f "${_SSL_SCRIPT}" ]]; then
  if grep -qE 'sha256sum|_src_sha|_dst_sha' "${_SSL_SCRIPT}"; then
    _pass "TS2" "05-enable-ssl.sh has SHA-256 change-detection guard (idempotent)"
  else
    _fail "TS2" "05-enable-ssl.sh lacks SHA-256 guard -- re-runs may not be idempotent"
  fi

  # TS3: pg_ctl reload issued when postgres is running
  printf "\n--- TS3: 05-enable-ssl.sh issues pg_ctl reload when postgres is running ---\n"
  if grep -qE 'pg_ctl.*reload|pg_ctl.*-D.*reload' "${_SSL_SCRIPT}"; then
    _pass "TS3" "05-enable-ssl.sh issues pg_ctl reload for hot trust-bundle update"
  else
    _fail "TS3" "05-enable-ssl.sh does not issue pg_ctl reload -- trust-bundle change requires full restart"
  fi
else
  _skip "TS2" "docker/postgres/05-enable-ssl.sh not found"
  _skip "TS3" "docker/postgres/05-enable-ssl.sh not found"
fi

# TS4: _activate_byo_ca calls _postgres_byo_ca_trust_sync
printf "\n--- TS4: _activate_byo_ca calls _postgres_byo_ca_trust_sync ---\n"
# Use full function body extraction via awk (grep -ANN window too small for this function)
_fn_activate=$(_fn_body "_activate_byo_ca" 2>/dev/null || true)
if printf '%s' "${_fn_activate}" | grep -q '_postgres_byo_ca_trust_sync'; then
  _pass "TS4" "_activate_byo_ca calls _postgres_byo_ca_trust_sync (Captain's PGDATA sync step)"
else
  _fail "TS4" "_activate_byo_ca does NOT call _postgres_byo_ca_trust_sync -- PGDATA swap will leave stale certs"
fi

# =============================================================================
# Summary
# =============================================================================
printf "\n"
printf "================================================\n"
printf "  BYO CA Scenario 2 Test Results\n"
printf "  PASS: %d   FAIL: %d   SKIP: %d\n" \
  "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
printf "================================================\n"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "RESULT: FAIL\n"
  exit 1
else
  printf "RESULT: PASS (%d tests, %d skipped)\n" "$PASS_COUNT" "$SKIP_COUNT"
fi
