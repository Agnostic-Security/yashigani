#!/usr/bin/env bash
# tests/integration/test_fips_sha256.sh — N2 regression: _fips_sha256 + _fips_sha256_manifest_stream
#
# Verifies:
#   (1) FIPS_MODE=0: _fips_sha256 produces the same hex digest as `sha256sum`.
#   (2) FIPS_MODE=1: _fips_sha256 produces the same hex digest (OpenSSL dgst path)
#       when OpenSSL is available AND the FIPS provider is loaded.
#       When FIPS provider is NOT loaded: function exits 1 with a clear error (fail-closed).
#   (3) FIPS_MODE=0: _fips_sha256_manifest_stream output matches `sha256sum`-based manifest.
#   (4) FIPS_MODE=1 without FIPS provider: _fips_sha256_manifest_stream exits 1 (fail-closed).
#   (5) Compile-time: all five FIPS-enabled call sites are wired in the correct files.
#
# Prerequisites: openssl(1) and sha256sum(1) must be available (standard on macOS + Linux).
#                On macOS, sha256sum may require coreutils (brew install coreutils) or falls
#                back to shasum. The test auto-detects.
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2 directive 2026-05-24.

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { printf "  PASS: %s\n" "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf "  FAIL: %s\n" "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { printf "  SKIP: %s\n" "$*"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Locate repo root and source the FIPS helper
# ---------------------------------------------------------------------------
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "${_SCRIPT_DIR}/../.." && pwd)"
_FIPS_LIB="${_REPO_ROOT}/lib/yashigani-fips.sh"

if [[ ! -f "$_FIPS_LIB" ]]; then
  printf "FATAL: %s not found\n" "$_FIPS_LIB" >&2
  exit 1
fi
# shellcheck source=../../lib/yashigani-fips.sh
# shellcheck disable=SC1091
source "$_FIPS_LIB"

# ---------------------------------------------------------------------------
# Determine sha256sum availability (macOS may only have shasum)
# ---------------------------------------------------------------------------
_sha256sum_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  _sha256sum_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  _sha256sum_cmd="shasum -a 256"
fi

# ---------------------------------------------------------------------------
# Create a deterministic test fixture
# ---------------------------------------------------------------------------
_tmpdir="$(mktemp -d "${_REPO_ROOT}/tests/integration/.fips-test-XXXXXX")"
trap 'rm -rf "$_tmpdir"' EXIT

printf 'Yashigani FIPS test fixture 2026-05-24\nline two\n' > "${_tmpdir}/test_file.txt"
printf 'second test file content\n'                         > "${_tmpdir}/test_file2.txt"

printf "\n=== test_fips_sha256.sh ===\n\n"

# ---------------------------------------------------------------------------
# T1: FIPS_MODE=0 — _fips_sha256 matches sha256sum
# ---------------------------------------------------------------------------
printf '%s\n' "--- T1: FIPS_MODE=0 produces same digest as sha256sum ---"
if [[ -z "$_sha256sum_cmd" ]]; then
  skip "T1: sha256sum/shasum not available on this host"
else
  _expected="$(${_sha256sum_cmd} "${_tmpdir}/test_file.txt" | awk '{print $1}')"
  _got="$(FIPS_MODE=0 _fips_sha256 "${_tmpdir}/test_file.txt")"
  if [[ "$_expected" == "$_got" ]]; then
    pass "T1: FIPS_MODE=0 digest matches sha256sum (${_got:0:16}...)"
  else
    fail "T1: FIPS_MODE=0 digest mismatch — expected ${_expected}, got ${_got}"
  fi
fi

# ---------------------------------------------------------------------------
# T2: FIPS_MODE=1 with OpenSSL available — verify digest matches sha256sum
# ---------------------------------------------------------------------------
printf '%s\n' "--- T2: FIPS_MODE=1 with OpenSSL (non-FIPS provider) produces same digest ---"
if ! command -v openssl >/dev/null 2>&1; then
  skip "T2: openssl not available on this host"
else
  # Simulate FIPS_MODE=1 by patching _fips_assert_provider_loaded temporarily.
  # We do NOT require an actual FIPS-certified provider installed — we test that
  # the openssl dgst code path produces the correct hash value.
  # Technique: define a local override that always returns 0, source the helper
  # again in a sub-shell with the override, and compare output.
  _openssl_digest="$(openssl dgst -sha256 -hex "${_tmpdir}/test_file.txt" 2>/dev/null \
    | awk -F'= ' '{print $NF}')"

  # Call _fips_sha256 via a sub-shell with _fips_assert_provider_loaded overridden.
  _got_fips="$(
    # shellcheck disable=SC1090,SC1091
    source "$_FIPS_LIB"
    _fips_assert_provider_loaded() { return 0; }
    FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt"
  )"

  if [[ "$_openssl_digest" == "$_got_fips" ]]; then
    pass "T2: FIPS_MODE=1 openssl dgst path produces correct digest (${_got_fips:0:16}...)"
  else
    fail "T2: FIPS_MODE=1 digest mismatch — openssl direct=${_openssl_digest}, via helper=${_got_fips}"
  fi
fi

# ---------------------------------------------------------------------------
# T3: Identical hash value: FIPS_MODE=0 vs FIPS_MODE=1 (both code paths)
# ---------------------------------------------------------------------------
printf '%s\n' "--- T3: FIPS_MODE=0 and FIPS_MODE=1 produce identical hash for same file ---"
if ! command -v openssl >/dev/null 2>&1 || [[ -z "$_sha256sum_cmd" ]]; then
  skip "T3: openssl or sha256sum/shasum not available"
else
  _hash_mode0="$(FIPS_MODE=0 _fips_sha256 "${_tmpdir}/test_file.txt")"
  _hash_mode1="$(
    # shellcheck disable=SC1090,SC1091
    source "$_FIPS_LIB"
    _fips_assert_provider_loaded() { return 0; }
    FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt"
  )"
  if [[ "$_hash_mode0" == "$_hash_mode1" ]]; then
    pass "T3: Both code paths produce identical hash (${_hash_mode0:0:16}...)"
  else
    fail "T3: Code path divergence — FIPS_MODE=0: ${_hash_mode0}, FIPS_MODE=1: ${_hash_mode1}"
  fi
fi

# ---------------------------------------------------------------------------
# T4: FIPS_MODE=1 with FIPS provider NOT loaded — fail-closed
# ---------------------------------------------------------------------------
printf '%s\n' "--- T4: FIPS_MODE=1 without FIPS provider -> exit 1 with error message ---"
if ! command -v openssl >/dev/null 2>&1; then
  skip "T4: openssl not available on this host"
else
  # Verify that when the FIPS provider is genuinely not loaded, the helper exits 1.
  # On most development hosts the FIPS provider will NOT be loaded, so this test
  # can run directly.
  #
  # If by chance this host DOES have the FIPS provider installed (rare), we simulate
  # its absence by overriding _fips_assert_provider_loaded to return 1.
  _fips_provider_present=0
  if openssl list -providers 2>/dev/null | grep -qi 'name: fips'; then
    _fips_provider_present=1
  fi

  if [[ "$_fips_provider_present" -eq 1 ]]; then
    # Host has FIPS provider — simulate its absence in sub-shell.
    _error_output="$(
      # shellcheck disable=SC1090,SC1091
      source "$_FIPS_LIB"
      _fips_assert_provider_loaded() {
        printf 'ERROR: FIPS_MODE=1 but OpenSSL FIPS provider not loaded (CMVP #4985 boundary breach — CMMC SC.L2-3.13.11)\n' >&2
        return 1
      }
      FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt" 2>&1 || true
    )"
  else
    # Standard case: FIPS provider not installed on this host.
    _error_output="$(FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt" 2>&1 || true)"
  fi

  # The command must exit 1 — verify by capturing in a sub-shell.
  _exit_code=0
  if [[ "$_fips_provider_present" -eq 1 ]]; then
    (
      # shellcheck disable=SC1090,SC1091
      source "$_FIPS_LIB"
      _fips_assert_provider_loaded() { return 1; }
      FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt" >/dev/null 2>&1
    ) && _exit_code=0 || _exit_code=$?
  else
    (FIPS_MODE=1 _fips_sha256 "${_tmpdir}/test_file.txt" >/dev/null 2>&1) \
      && _exit_code=0 || _exit_code=$?
  fi

  if [[ "$_exit_code" -ne 0 ]]; then
    pass "T4: FIPS_MODE=1 without provider exits non-zero (exit=${_exit_code})"
  else
    fail "T4: FIPS_MODE=1 without provider returned 0 (fail-open — CRITICAL)"
  fi

  if printf '%s\n' "$_error_output" | grep -qi 'FIPS'; then
    pass "T4: Error message mentions FIPS boundary"
  else
    fail "T4: Error message does not mention FIPS — got: ${_error_output}"
  fi
fi

# ---------------------------------------------------------------------------
# T5: _fips_sha256_manifest_stream FIPS_MODE=0 — output matches sha256sum manifest
# ---------------------------------------------------------------------------
printf '%s\n' "--- T5: _fips_sha256_manifest_stream FIPS_MODE=0 matches sha256sum output ---"
if [[ -z "$_sha256sum_cmd" ]]; then
  skip "T5: sha256sum/shasum not available on this host"
else
  _fixture_subdir="${_tmpdir}/manifest_test"
  mkdir -p "${_fixture_subdir}"
  printf 'alpha content\n'  > "${_fixture_subdir}/alpha.txt"
  printf 'beta content\n'   > "${_fixture_subdir}/beta.txt"
  printf 'gamma content\n'  > "${_fixture_subdir}/gamma.txt"

  # Reference: what sha256sum would produce (two-space separator, path stripped of ./)
  _expected_manifest="$(
    cd "${_fixture_subdir}" && \
    find . -type f -print0 | sort -z | \
    xargs -0 ${_sha256sum_cmd} | \
    awk '{gsub(/^\.\//, "", $2); print}' | sort
  )"

  # Test: what _fips_sha256_manifest_stream produces
  _got_manifest="$(
    cd "${_fixture_subdir}" && \
    find . -type f -print0 | sort -z | \
    FIPS_MODE=0 _fips_sha256_manifest_stream | sort
  )"

  if [[ "$_expected_manifest" == "$_got_manifest" ]]; then
    pass "T5: _fips_sha256_manifest_stream FIPS_MODE=0 output matches sha256sum manifest"
  else
    fail "T5: Manifest output mismatch"
    printf "    Expected:\n%s\n    Got:\n%s\n" "$_expected_manifest" "$_got_manifest" >&2
  fi
fi

# ---------------------------------------------------------------------------
# T6: _fips_sha256_manifest_stream FIPS_MODE=1 fail-closed (no FIPS provider)
# ---------------------------------------------------------------------------
printf '%s\n' "--- T6: _fips_sha256_manifest_stream FIPS_MODE=1 without provider -> exit 1 ---"
if ! command -v openssl >/dev/null 2>&1; then
  skip "T6: openssl not available on this host"
else
  _fips_provider_present=0
  if openssl list -providers 2>/dev/null | grep -qi 'name: fips'; then
    _fips_provider_present=1
  fi

  _fixture_subdir2="${_tmpdir}/manifest_test2"
  mkdir -p "${_fixture_subdir2}"
  printf 'stream test\n' > "${_fixture_subdir2}/file.txt"

  _stream_exit=0
  if [[ "$_fips_provider_present" -eq 1 ]]; then
    (
      # shellcheck disable=SC1090,SC1091
      source "$_FIPS_LIB"
      _fips_assert_provider_loaded() { return 1; }
      cd "${_fixture_subdir2}" && \
      find . -type f -print0 | FIPS_MODE=1 _fips_sha256_manifest_stream >/dev/null 2>&1
    ) && _stream_exit=0 || _stream_exit=$?
  else
    (
      cd "${_fixture_subdir2}" && \
      find . -type f -print0 | FIPS_MODE=1 _fips_sha256_manifest_stream >/dev/null 2>&1
    ) && _stream_exit=0 || _stream_exit=$?
  fi

  if [[ "$_stream_exit" -ne 0 ]]; then
    pass "T6: _fips_sha256_manifest_stream FIPS_MODE=1 without provider exits non-zero (exit=${_stream_exit})"
  else
    fail "T6: _fips_sha256_manifest_stream FIPS_MODE=1 without provider returned 0 (fail-open — CRITICAL)"
  fi
fi

# ---------------------------------------------------------------------------
# T7: Compile-time — all five call sites wired in correct files
# ---------------------------------------------------------------------------
printf '%s\n' "--- T7: Call-site inventory -- all five FIPS wiring sites present ---"

_check_site() {
  local _label="$1" _file="$2" _pattern="$3"
  if grep -q "$_pattern" "$_file" 2>/dev/null; then
    pass "T7.${_label}: ${_file##*/} — ${_pattern}"
  else
    fail "T7.${_label}: ${_file##*/} — missing pattern: ${_pattern}"
  fi
}

_check_site "1a" "${_REPO_ROOT}/install.sh" \
  "source.*lib/yashigani-fips.sh"
_check_site "1b" "${_REPO_ROOT}/install.sh" \
  "_fips_sha256_manifest_stream"
_check_site "1c" "${_REPO_ROOT}/install.sh" \
  "_fips_sha256.*AIR_GAP_BUNDLE"
_check_site "2a" "${_REPO_ROOT}/restore.sh" \
  "source.*lib/yashigani-fips.sh"
_check_site "2b" "${_REPO_ROOT}/restore.sh" \
  "_fips_sha256.*_fpath"
_check_site "3a" "${_REPO_ROOT}/scripts/prepare-airgap-bundle.sh" \
  "_fips_sha256.*bundle_path"
_check_site "3b" "${_REPO_ROOT}/scripts/prepare-airgap-bundle.sh" \
  "source.*lib/yashigani-fips.sh"
_check_site "4a" "${_REPO_ROOT}/scripts/test_retro_r4_vm.sh" \
  "source.*lib/yashigani-fips.sh"
_check_site "4b" "${_REPO_ROOT}/scripts/test_retro_r4_vm.sh" \
  "_fips_sha256_manifest_stream"

# ---------------------------------------------------------------------------
# T8: Compile-time — no residual bare sha256sum in integrity-verification paths
# ---------------------------------------------------------------------------
printf '%s\n' "--- T8: No residual bare sha256sum in integrity-verification paths ---"
_residual_found=0

# install.sh: the two attestation-chain paths must not contain bare sha256sum
# (other sha256sum calls in install.sh are out-of-scope: bcrypt, OCI digests, etc.)
if grep -n "xargs -0 sha256sum" "${_REPO_ROOT}/install.sh" | grep -v "^#" | grep -q .; then
  fail "T8: Residual 'xargs -0 sha256sum' found in install.sh (attestation-chain path)"
  _residual_found=1
fi

# restore.sh: the manifest content hash loop must not use bare sha256sum
if grep -n 'sha256sum "\$_fpath"' "${_REPO_ROOT}/restore.sh" 2>/dev/null | grep -q .; then
  fail "T8: Residual 'sha256sum \"\$_fpath\"' found in restore.sh"
  _residual_found=1
fi

# prepare-airgap-bundle.sh: the bundle hash computation must not use bare SHA256CMD
if grep -n '${SHA256CMD}.*bundle_path' "${_REPO_ROOT}/scripts/prepare-airgap-bundle.sh" 2>/dev/null | grep -q .; then
  fail "T8: Residual '\${SHA256CMD}.*bundle_path' found in prepare-airgap-bundle.sh"
  _residual_found=1
fi

# test_retro_r4_vm.sh: manifest build must not use bare xargs sha256sum
if grep -n "xargs -0 sha256sum" "${_REPO_ROOT}/scripts/test_retro_r4_vm.sh" 2>/dev/null | grep -q .; then
  fail "T8: Residual 'xargs -0 sha256sum' found in test_retro_r4_vm.sh"
  _residual_found=1
fi

if [[ "$_residual_found" -eq 0 ]]; then
  pass "T8: No residual bare sha256sum in integrity-verification paths"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== Results ===\n"
printf "  PASS: %d\n" "$PASS_COUNT"
printf "  FAIL: %d\n" "$FAIL_COUNT"
printf "  SKIP: %d\n" "$SKIP_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "\nRESULT: FAIL (%d failure(s))\n" "$FAIL_COUNT" >&2
  exit 1
fi
printf "\nRESULT: PASS\n"
exit 0
