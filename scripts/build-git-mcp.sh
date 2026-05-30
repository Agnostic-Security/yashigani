#!/usr/bin/env bash
# scripts/build-git-mcp.sh — build the git-mcp bundle image
#                            and emit the digest for bundles/git-mcp.yaml.
#
# Usage:
#   bash scripts/build-git-mcp.sh
#   bash scripts/build-git-mcp.sh --platform linux/amd64
#   bash scripts/build-git-mcp.sh --platform linux/amd64,linux/arm64  # multi-arch via buildx
#
# Outputs:
#   - Built image tagged as:
#       registry.yashigani.internal/bundles/mcp-git:latest
#   - On success, prints the sha256 digest to stdout for copy-paste into
#     bundles/git-mcp.yaml spec.image.digest.
#
# CIS Docker Benchmark 4.6 / M6: digest pinning is mandatory for all bundle images.
# This script verifies the built image and writes its digest so the operator can
# update the bundle YAML before the onboarding ceremony.
#
# last-updated: 2026-05-30T00:00:00+01:00 (feat(p3): build-git-mcp.sh — git-mcp build helper)

set -euo pipefail

IFS=$'\n\t'

# Hardened PATH — never trust inherited PATH for privileged scripts.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Validate prerequisites ────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
  printf 'ERROR: neither docker nor podman found in PATH\n' >&2
  exit 1
fi

# Prefer docker; fall back to podman.
CONTAINER_CMD="${CONTAINER_CMD:-}"
if [[ -z "$CONTAINER_CMD" ]]; then
  if command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
  else
    CONTAINER_CMD="podman"
  fi
fi

# ── Parameters ────────────────────────────────────────────────────────────────
IMAGE_NAME="${IMAGE_NAME:-registry.yashigani.internal/bundles/mcp-git}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
# Argument parsing — the documented interface is `--platform <value>` (see usage above).
PLATFORM=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="${2:-}"
      if [[ -z "$PLATFORM" ]]; then
        printf 'ERROR: --platform requires a value (e.g. linux/arm64)\n' >&2
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      sed -n '2,18p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      printf 'ERROR: unknown argument: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done
DOCKERFILE="${REPO_ROOT}/docker/Dockerfile.git-mcp"

if [[ ! -f "$DOCKERFILE" ]]; then
  printf 'ERROR: Dockerfile not found: %s\n' "$DOCKERFILE" >&2
  exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
printf '[build-git-mcp] Building %s:%s\n' "$IMAGE_NAME" "$IMAGE_TAG"
printf '[build-git-mcp] Runtime: %s\n' "$CONTAINER_CMD"
printf '[build-git-mcp] Dockerfile: %s\n' "$DOCKERFILE"
printf '[build-git-mcp] Context: %s\n' "$REPO_ROOT"

BUILD_ARGS=()

# Platform flag — if supplied, use buildx (multi-arch) or --platform (single).
if [[ -n "$PLATFORM" ]]; then
  # Multi-arch with BuildKit / buildx
  if [[ "$PLATFORM" == *","* ]]; then
    printf '[build-git-mcp] Multi-arch build via buildx: %s\n' "$PLATFORM"
    if ! "$CONTAINER_CMD" buildx version >/dev/null 2>&1; then
      printf 'ERROR: multi-arch build requires docker buildx (BuildKit)\n' >&2
      exit 1
    fi
    # For multi-arch we must push to a registry to get a combined manifest.
    # The caller is responsible for buildx create --use if needed.
    "$CONTAINER_CMD" buildx build \
      --platform "$PLATFORM" \
      -f "$DOCKERFILE" \
      -t "${IMAGE_NAME}:${IMAGE_TAG}" \
      --push \
      "$REPO_ROOT"
    printf '\n[build-git-mcp] Multi-arch push complete.\n'
    printf '[build-git-mcp] Inspect the registry digest with:\n'
    printf '  docker manifest inspect %s:%s | jq .\n' "$IMAGE_NAME" "$IMAGE_TAG"
    exit 0
  else
    BUILD_ARGS+=("--platform" "$PLATFORM")
    # Extract TARGETARCH from platform string (e.g. linux/amd64 → amd64)
    _arch="${PLATFORM##*/}"
    BUILD_ARGS+=("--build-arg" "TARGETARCH=${_arch}")
  fi
fi

"$CONTAINER_CMD" build \
  "${BUILD_ARGS[@]}" \
  -f "$DOCKERFILE" \
  -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  "$REPO_ROOT"

# ── Capture digest ────────────────────────────────────────────────────────────
printf '\n[build-git-mcp] Capturing image digest...\n'

DIGEST="$("$CONTAINER_CMD" inspect --format '{{index .RepoDigests 0}}' "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null \
  | sed 's/.*@//' || true)"

if [[ -z "$DIGEST" ]]; then
  # Fallback: use image ID as digest (local build without registry push has no RepoDigest).
  # The operator must push the image to get a stable digest for bundles/git-mcp.yaml.
  IMAGE_ID="$("$CONTAINER_CMD" inspect --format '{{.Id}}' "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true)"
  printf '\n[build-git-mcp] WARNING: No RepoDigest available (image not pushed to registry).\n'
  printf '[build-git-mcp] Image ID: %s\n' "$IMAGE_ID"
  printf '\n[build-git-mcp] To get a stable digest for bundles/git-mcp.yaml:\n'
  printf '  1. Push the image: docker push %s:%s\n' "$IMAGE_NAME" "$IMAGE_TAG"
  printf '  2. Get the digest: docker manifest inspect %s:%s | jq -r '"'"'.[0].Digest'"'"'\n' "$IMAGE_NAME" "$IMAGE_TAG"
  printf '  3. Update bundles/git-mcp.yaml spec.image.digest with the sha256 value.\n'
else
  printf '\n[build-git-mcp] Image digest (copy into bundles/git-mcp.yaml):\n'
  printf '  spec.image.digest: "%s"\n\n' "$DIGEST"
  printf '[build-git-mcp] Full image reference:\n'
  printf '  %s:%s@%s\n\n' "$IMAGE_NAME" "$IMAGE_TAG" "$DIGEST"
fi

printf '[build-git-mcp] Build complete.\n'
printf '[build-git-mcp] M6 reminder: update bundles/git-mcp.yaml spec.image.digest\n'
printf '             before running the onboarding ceremony.\n'
