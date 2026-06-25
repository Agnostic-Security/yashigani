#!/usr/bin/env bash
# scripts/build-demo-mcp.sh — build the "cloud-9" demo-mcp upstream image.
#
# Usage:
#   bash scripts/build-demo-mcp.sh
#   IMAGE_TAG=2.25.3 bash scripts/build-demo-mcp.sh
#   CONTAINER_CMD=podman bash scripts/build-demo-mcp.sh
#
# Output: image tagged yashigani/demo-mcp:${IMAGE_TAG:-2.25.3}. The compose
# demo-mcp service (profile: demo-mcp) also builds it via its build: directive,
# so this helper is only needed for a standalone/pre-build.
#
# last-updated: 2026-06-20T00:00:00+01:00 (feat: build-demo-mcp.sh — codify the demo MCP upstream)

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONTAINER_CMD="${CONTAINER_CMD:-}"
if [[ -z "$CONTAINER_CMD" ]]; then
  if command -v docker >/dev/null 2>&1; then CONTAINER_CMD="docker"
  elif command -v podman >/dev/null 2>&1; then CONTAINER_CMD="podman"
  else printf 'ERROR: neither docker nor podman found in PATH\n' >&2; exit 1; fi
fi

IMAGE_NAME="${IMAGE_NAME:-yashigani/demo-mcp}"
IMAGE_TAG="${IMAGE_TAG:-2.25.3}"
DOCKERFILE="${REPO_ROOT}/docker/Dockerfile.demo-mcp"

if [[ ! -f "$DOCKERFILE" ]]; then
  printf 'ERROR: Dockerfile not found: %s\n' "$DOCKERFILE" >&2; exit 1
fi

printf '[build-demo-mcp] Building %s:%s (%s)\n' "$IMAGE_NAME" "$IMAGE_TAG" "$CONTAINER_CMD"
"$CONTAINER_CMD" build -f "$DOCKERFILE" -t "${IMAGE_NAME}:${IMAGE_TAG}" "$REPO_ROOT"
printf '[build-demo-mcp] Built %s:%s\n' "$IMAGE_NAME" "$IMAGE_TAG"
