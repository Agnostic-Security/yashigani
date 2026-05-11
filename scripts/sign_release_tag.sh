#!/usr/bin/env bash
# sign_release_tag.sh — GPG-sign (or re-sign) a Yashigani release tag
# Last updated: 2026-05-02T00:00:00+01:00
#
# Usage:
#   bash scripts/sign_release_tag.sh <tag> <commit-sha>
#
# Examples:
#   # Sign a new tag at the current release SHA:
#   bash scripts/sign_release_tag.sh v2.23.2 3b49d0e
#
#   # Retroactively sign an existing unsigned tag:
#   bash scripts/sign_release_tag.sh v2.23.1 733c362
#
# Prerequisites:
#   1. A GPG signing key for releases@agnosticsec.com must exist:
#        gpg --list-secret-keys releases@agnosticsec.com
#      Generate one if missing.
#   2. Git must be configured to use that key:
#        git config --global user.signingkey <KEY_ID>
#      Or set SIGNING_KEY_ID env var before running this script.
#   3. You must have push access to origin with write permission on tags.
#
# Signing method: GPG (git tag -s)
#   - Produces a standard PGP-signed annotated tag object.
#   - Verifiable offline: git tag -v <tag>
#   - Verifiable by anyone with the Agnostic Security public key.
#   - No external network dependency for verification.
#   - Public key exported to: docs/release-signing-key.asc
#
# CI alternative: the tag-sign.yml workflow signs tags keylessly via
#   GitHub Actions OIDC + Sigstore Rekor (see .github/workflows/tag-sign.yml).
#   That path is used for new release tags created in CI.
#   This script is for local signing by a team member with key access.
#
# Force-update note:
#   Re-signing an existing tag requires --force. Force-updating a pushed
#   tag is a one-time corrective action (documented in V232-NEG02).
#   Consumers who have already fetched the old tag will need:
#     git fetch --tags --force origin

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

if [[ $# -ne 2 ]]; then
    echo "Usage: bash scripts/sign_release_tag.sh <tag> <commit-sha>" >&2
    echo "Example: bash scripts/sign_release_tag.sh v2.23.1 733c362" >&2
    exit 1
fi

TAG="$1"
COMMIT="$2"

# Validate tag format
if ! echo "${TAG}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
    error "Tag '${TAG}' does not match expected format vN.N.N or vN.N.N-rc.N"
fi

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

if ! command -v gpg &>/dev/null && ! command -v gpg2 &>/dev/null; then
    error "gpg not found in PATH.
Install it:
  macOS:  brew install gnupg
  Linux:  sudo apt-get install gnupg  (Debian/Ubuntu)
          sudo dnf install gnupg2      (RHEL/Fedora)
After installing, import the Agnostic Security release signing key:
  gpg --import docs/release-signing-key.asc
Then confirm with:
  gpg --list-secret-keys releases@agnosticsec.com"
fi

GPG_CMD=$(command -v gpg2 2>/dev/null || command -v gpg)

# Determine signing key
SIGNING_KEY_ID="${SIGNING_KEY_ID:-}"
if [[ -z "${SIGNING_KEY_ID}" ]]; then
    # Try to read from git config
    SIGNING_KEY_ID=$(git config --global user.signingkey 2>/dev/null || true)
fi

if [[ -z "${SIGNING_KEY_ID}" ]]; then
    # Auto-detect from expected release identity
    SIGNING_KEY_ID=$(${GPG_CMD} --list-secret-keys --with-colons 'releases@agnosticsec.com' 2>/dev/null \
        | awk -F: '/^sec/ { print $5 }' | head -1 || true)
fi

if [[ -z "${SIGNING_KEY_ID}" ]]; then
    error "No GPG signing key found.
Expected identity: releases@agnosticsec.com
Generate a key:
  gpg --full-generate-key
  # Choose: RSA (sign only), 4096 bits, expires 2y
  # Name: Agnostic Security Releases
  # Email: releases@agnosticsec.com

Then export and store the public key:
  gpg --armor --export releases@agnosticsec.com > docs/release-signing-key.asc
  git add docs/release-signing-key.asc
  git commit -m 'chore(pki): add GPG release signing public key'

Store the private key in GitHub Secrets as GPG_PRIVATE_KEY and the
passphrase as GPG_PASSPHRASE for CI signing."
fi

info "Using signing key: ${SIGNING_KEY_ID}"

# Verify the commit exists
if ! git rev-parse --verify "${COMMIT}^{commit}" &>/dev/null; then
    error "Commit '${COMMIT}' not found in local repository. Run: git fetch origin"
fi

FULL_SHA=$(git rev-parse "${COMMIT}^{commit}")
info "Resolved commit: ${FULL_SHA}"

# ---------------------------------------------------------------------------
# Fetch existing tag message (if re-signing an existing tag)
# ---------------------------------------------------------------------------

TAG_MSG=""
if git rev-parse --verify "refs/tags/${TAG}" &>/dev/null; then
    warn "Tag '${TAG}' already exists locally."
    EXISTING_TYPE=$(git cat-file -t "refs/tags/${TAG}" 2>/dev/null || echo "unknown")

    if [[ "${EXISTING_TYPE}" == "tag" ]]; then
        # Preserve the existing annotated tag message
        TAG_MSG=$(git cat-file tag "refs/tags/${TAG}" | sed '1,/^$/d')
        info "Existing tag message preserved."
    fi

    warn "Deleting existing local tag to re-sign..."
    git tag -d "${TAG}"
else
    info "No existing local tag '${TAG}'. Creating fresh."
fi

# ---------------------------------------------------------------------------
# Create signed tag
# ---------------------------------------------------------------------------

# Build tag annotation
if [[ -z "${TAG_MSG}" ]]; then
    TAG_MSG="Yashigani ${TAG}"
fi

info "Creating signed tag: ${TAG} -> ${FULL_SHA}"

GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-Agnostic Security Releases}"
GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-releases@agnosticsec.com}"
export GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

git tag -s "${TAG}" "${FULL_SHA}" \
    --local-user "${SIGNING_KEY_ID}" \
    -m "${TAG_MSG}"

info "Tag created. Verifying locally..."

# ---------------------------------------------------------------------------
# Verify the signature
# ---------------------------------------------------------------------------

if git tag -v "${TAG}" 2>&1 | grep -q "Good signature"; then
    info "Signature verified: GOOD"
else
    # git tag -v exits non-zero even on good signatures in some versions;
    # check the output text instead
    VERIFY_OUT=$(git tag -v "${TAG}" 2>&1)
    echo "${VERIFY_OUT}"
    if echo "${VERIFY_OUT}" | grep -qiE "(good signature|gpg: Signature made)"; then
        info "Signature verified: GOOD"
    else
        error "Signature verification FAILED. Do not push this tag.
Full output:
${VERIFY_OUT}"
    fi
fi

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------

info "Pushing ${TAG} to origin (--force for re-sign)..."
git push origin "refs/tags/${TAG}" --force

info ""
info "Done. Tag ${TAG} is now GPG-signed and pushed."
info ""
info "Consumers who previously fetched this tag must run:"
info "  git fetch --tags --force origin"
info ""
info "Verification command for anyone with the Agnostic Security public key:"
info "  # Import key (once):"
info "  gpg --import docs/release-signing-key.asc"
info "  # Verify tag:"
info "  git tag -v ${TAG}"
