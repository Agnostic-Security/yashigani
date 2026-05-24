#!/usr/bin/env bash
# lib/yashigani-fips.sh — FIPS-aware SHA-256 helpers for integrity-verification paths
# last-updated: 2026-05-24T00:00:00+01:00 (feat(fips): N2 — route --confirm SHA-256 through OpenSSL FIPS Provider when FIPS_MODE=1)
#
# FIPS compliance boundary
# -------------------------
# Routes through CMVP #4985 OpenSSL FIPS Provider when FIPS_MODE=1.
# Falls back to BusyBox/coreutils sha256sum for non-FIPS deployments.
# Citation: CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4
#
# Usage
# -----
# Source this file in scripts that compute integrity-verification SHA-256 hashes:
#
#   # shellcheck source=lib/yashigani-fips.sh
#   source "$(dirname "$(realpath "$0")")/../lib/yashigani-fips.sh"
#
# Then replace:
#   sha256sum "$file" | awk '{print $1}'
# with:
#   _fips_sha256 "$file"
#
# For computing the hash of multiple files into a manifest (xargs -0 sha256sum pattern):
#   Use _fips_sha256_manifest_stream — see below.
#
# Environment
# -----------
# FIPS_MODE=1    Force OpenSSL FIPS Provider path (fail-closed if provider not loaded)
# FIPS_MODE=0    Use coreutils sha256sum (default; suitable for BusyBox containers)
# FIPS_MODE unset — same as FIPS_MODE=0
#
# Auto-detection: when FIPS_MODE is unset OR 0, if `openssl version` reports FIPS
# the helper will still use the OpenSSL path to avoid silent downgrade.
#
# Scope restriction (SOP — do not relax)
# ----------------------------------------
# _fips_sha256 and _fips_sha256_manifest_stream are ONLY for paths inside the
# FIPS-asserted attestation chain:
#   - Backup MANIFEST.sha256 generation (install.sh + restore.sh RETRO-R4-3)
#   - Air-gap bundle integrity verification (install.sh --airgap)
#   - Air-gap bundle sidecar manifest hash (scripts/prepare-airgap-bundle.sh)
#   - Test harness manifest build (scripts/test_retro_r4_vm.sh)
#
# Do NOT route session IDs, cache keys, or other non-attestation hashes through
# these helpers. BusyBox portability is acceptable there; FIPS overhead is not needed.

set -euo pipefail

# ---------------------------------------------------------------------------
# _fips_assert_provider_loaded
# ---------------------------------------------------------------------------
# Returns 0 if the OpenSSL FIPS provider is loaded, 1 otherwise.
# When FIPS_MODE=1, the caller MUST call this first (fail-closed contract).
# ---------------------------------------------------------------------------
_fips_assert_provider_loaded() {
  if openssl list -providers 2>/dev/null | grep -qi 'name: fips'; then
    return 0
  fi
  printf 'ERROR: FIPS_MODE=1 but OpenSSL FIPS provider not loaded ' >&2
  printf '(CMVP #4985 boundary breach — CMMC SC.L2-3.13.11)\n' >&2
  return 1
}

# ---------------------------------------------------------------------------
# _fips_sha256 <file>
# ---------------------------------------------------------------------------
# Prints the lowercase hex SHA-256 digest of <file> to stdout.
# When FIPS_MODE=1: uses `openssl dgst -sha256` (routes through FIPS provider).
# Otherwise:        uses `sha256sum` (coreutils / BusyBox portable).
#
# Auto-FIPS: when FIPS_MODE is unset/0 but `openssl version` reports FIPS,
# promote to OpenSSL path automatically (guards against silent mode mismatch).
#
# Returns 1 on error (file not found, provider not loaded, digest failure).
# ---------------------------------------------------------------------------
_fips_sha256() {
  local _file="${1:?_fips_sha256 requires a file argument}"

  local _use_fips="${FIPS_MODE:-0}"

  # Auto-promote: if openssl itself is running in FIPS mode, honour that even
  # when FIPS_MODE env var is not set — prevents a silent sha256sum fallback
  # while the system is FIPS-configured.
  if [ "$_use_fips" != "1" ] && openssl version 2>/dev/null | grep -qi 'fips'; then
    _use_fips="1"
  fi

  if [ "$_use_fips" = "1" ]; then
    _fips_assert_provider_loaded || return 1
    # openssl dgst -sha256 -hex output: "SHA2-256(<file>)= <hex>"
    # awk extracts the hex value after the last '= ' delimiter.
    openssl dgst -sha256 -hex "$_file" 2>/dev/null \
      | awk -F'= ' '{print $NF}' \
      || { printf 'ERROR: _fips_sha256: openssl dgst failed for %s\n' "$_file" >&2; return 1; }
  else
    sha256sum "$_file" 2>/dev/null \
      | awk '{print $1}' \
      || { printf 'ERROR: _fips_sha256: sha256sum failed for %s\n' "$_file" >&2; return 1; }
  fi
}

# ---------------------------------------------------------------------------
# _fips_sha256_manifest_stream
# ---------------------------------------------------------------------------
# Replacement for the pipe: xargs -0 sha256sum | awk '{gsub(/^\.\//, "", $2); print}'
# Reads NUL-delimited file paths from stdin; for each file prints:
#   "<hexdigest>  <path-with-./-stripped>"
#
# Identical output format to `sha256sum` (two-space separator, relative path)
# so the MANIFEST.sha256 consumers are unchanged.
#
# When FIPS_MODE=1: uses openssl dgst per file (FIPS provider path).
# Otherwise:        passes the NUL-separated list to xargs -0 sha256sum.
#
# Usage (replaces: xargs -0 sha256sum | awk '{gsub(/^\.\//, "", $2); print}'):
#   find . -type f ... -print0 | sort -z | _fips_sha256_manifest_stream
# ---------------------------------------------------------------------------
_fips_sha256_manifest_stream() {
  local _use_fips="${FIPS_MODE:-0}"

  if [ "$_use_fips" != "1" ] && openssl version 2>/dev/null | grep -qi 'fips'; then
    _use_fips="1"
  fi

  if [ "$_use_fips" = "1" ]; then
    _fips_assert_provider_loaded || return 1
    # Read NUL-delimited paths; compute hash per file; emit manifest-format line.
    while IFS= read -r -d '' _path; do
      local _hex
      _hex="$(_fips_sha256 "$_path")" || return 1
      # Strip leading ./ from path to match sha256sum output convention.
      local _clean_path="${_path#./}"
      printf '%s  %s\n' "$_hex" "$_clean_path"
    done
  else
    # Portable fast path: pass all paths to xargs sha256sum in one shot.
    xargs -0 sha256sum | awk '{gsub(/^\.\//, "", $2); print}'
  fi
}
