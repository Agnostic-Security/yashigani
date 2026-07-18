#!/usr/bin/env bash
# verify-manifest.sh — fail-closed integrity verification for the
# podman-compose-ysg vendored fork.
#
# Last-Updated: 2026-07-18
#
# Mirrors the existing airgap image-digest verification pattern
# (install.sh:load_airgap_bundle(), ~line 6153-6398): hard-abort (non-zero
# exit) on ANY mismatch or missing file. No downgrade-to-warning path — an
# integrity failure here means the vendored GPL-2.0 tool that podman
# deploys will invoke may have been tampered with or corrupted; that is
# never something to "proceed with a warning" on (S1/SOP4 discipline: no
# `treating as PASS` clauses).
#
# NOT yet called by install.sh (documented, future wiring point — see
# vendor-integrity.md). Runnable standalone today:
#   bash vendor/podman-compose-ysg/verify-manifest.sh
#
# Exit codes: 0 = all files verified; 1 = integrity failure (mismatch,
# missing file, or missing manifest) — always fail-closed, never silent.
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/MANIFEST.sha256"

if [[ ! -f "$MANIFEST" ]]; then
  echo "INTEGRITY FAILURE: ${MANIFEST} not found — cannot verify the vendored fork. ABORTING." >&2
  exit 1
fi

cd "$SCRIPT_DIR"

_verify() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$MANIFEST"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$MANIFEST"
  else
    echo "INTEGRITY FAILURE: neither sha256sum nor shasum found — cannot verify. ABORTING." >&2
    exit 1
  fi
}

# Both sha256sum -c and shasum -a 256 -c ignore comment lines (leading '#')
# and exit non-zero on ANY failed/missing entry — exactly the fail-closed
# contract this script exists to enforce. No retry, no "assuming OK".
if _verify; then
  echo "OK: podman-compose-ysg vendored-fork integrity verified ($(grep -c '^[0-9a-f]' "$MANIFEST") files)."
  exit 0
else
  echo "INTEGRITY FAILURE: one or more vendored-fork files do not match MANIFEST.sha256. ABORTING." >&2
  exit 1
fi
