#!/usr/bin/env bash
# generate-manifest.sh — (re)generate MANIFEST.sha256 for podman-compose-ysg.
#
# Last-Updated: 2026-07-18
#
# Run this after any change to the vendored fork's source files (patches,
# doc updates) and commit the regenerated MANIFEST.sha256 as part of the
# same change. This is a build-time tool, not invoked by install.sh.
#
# macOS/Linux portable: uses sha256sum if present (Linux, Homebrew coreutils),
# falls back to `shasum -a 256` (macOS default).
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/MANIFEST.sha256"

_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    echo "generate-manifest.sh: neither sha256sum nor shasum found" >&2
    exit 1
  fi
}

cd "$SCRIPT_DIR"

# Manifest covers: podman_compose.py (the patched source), the GPL/notice
# artefacts, this generator + the verifier, and the regression tests.
# Deliberately excludes: MANIFEST.sha256 itself (no self-reference),
# __pycache__/.pytest_cache (build artefacts, not source).
files=(
  "podman_compose.py"
  "LICENSE"
  "CHANGES.agnostic.md"
  "NOTICE.md"
  "README.md"
  "vendor-integrity.md"
  "generate-manifest.sh"
  "verify-manifest.sh"
)
while IFS= read -r -d '' f; do
  files+=("${f#./}")
done < <(find tests -type f -print0 | sort -z)

: > "$MANIFEST"
{
  echo "# MANIFEST.sha256 — podman-compose-ysg 1.5.0+ysg.1 vendored-fork integrity manifest"
  echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) by generate-manifest.sh"
  echo "# Format: standard sha256sum(1) output — verify with:"
  echo "#   (cd vendor/podman-compose-ysg && sha256sum -c MANIFEST.sha256)"
  echo "# or use verify-manifest.sh for the fail-closed wrapper with clear errors."
} >> "$MANIFEST"

for f in "${files[@]}"; do
  [[ -f "$f" ]] || { echo "generate-manifest.sh: missing file: $f" >&2; exit 1; }
  _sha256 "$f" >> "$MANIFEST"
done

echo "Wrote $(grep -c '^[0-9a-f]' "$MANIFEST") entries to ${MANIFEST}"
