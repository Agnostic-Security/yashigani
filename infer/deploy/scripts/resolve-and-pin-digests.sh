#!/usr/bin/env bash
# infer/deploy/scripts/resolve-and-pin-digests.sh
#
# THE required step before any live build of the infer/deploy/docker/Dockerfile.infer-*
# images (Verification Protocol #7: never guess a version). This script does NOT run in the
# offline-authoring session that produced it — Captain has no rig/internet access here
# (dispatch brief: "OFFLINE AUTHORING ONLY ... do NOT build or run any image or touch a
# rig; infra-gated; flag before any"). Running this script requires:
#   1. A rig with internet/registry access, and
#   2. Explicit Maxine/Tiago authorisation per the runtime-workaround SOP (this is not a
#      "runtime tool failed, patch it" situation, but resolving external registry state
#      is exactly the kind of live-infra action that stays flagged, not assumed).
#
# What it does, when run:
#   - `docker manifest inspect` / `skopeo inspect docker://` every base image tag named in
#     the Dockerfiles + build manifest, replacing every "@sha256:PLACEHOLDER-RESOLVE-AT-BUILD-TIME"
#     with the real resolved digest.
#   - Clones the pinned llama.cpp tag, resolves LLAMA_CPP_COMMIT_SHA, and (--cve-check) greps
#     the commit against a locally-maintained disclosed-GGUF-advisory list before allowing
#     the pin to land (Captain finding #2 standing CVE gate).
#   - (--emit-manifest) writes the sha256 build-flag manifest for the signed release tag.
#
# This script is a SHAPE/CONTRACT definition, not a magic resolver — it names exactly what
# must be checked and in what order; the actual registry credentials/network access are a
# rig-time concern.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # infer/deploy

usage() {
    cat >&2 <<'EOF'
usage: resolve-and-pin-digests.sh [--check-only] [--cve-check] [--emit-manifest]

  --check-only     Report every unresolved PLACEHOLDER-RESOLVE-AT-BUILD-TIME digest and
                    every PIN-ME llama.cpp tag/commit reference across infer/deploy/. Exit
                    non-zero if any remain. Safe to run offline (no network needed) — this
                    is the mode this authoring session actually verified.
  --cve-check      (REQUIRES NETWORK) Cross-check the resolved LLAMA_CPP_COMMIT_SHA against
                    disclosed GGUF-loader advisories before allowing the pin.
  --emit-manifest  (REQUIRES NETWORK + a real build) Write the sha256 build-flag manifest.

Without a flag, prints this usage and exits 2.
EOF
}

check_placeholders() {
    local status=0
    echo "Scanning infer/deploy/ for unresolved placeholders (offline-safe check)..."
    if grep -rn "PLACEHOLDER-RESOLVE-AT-BUILD-TIME" "$REPO_ROOT" --include="Dockerfile.*" --include="*.yaml" --include="*.yml" 2>/dev/null; then
        echo "^^ unresolved base-image digest placeholders found above." >&2
        status=1
    fi
    if grep -rln "PIN-ME" "$REPO_ROOT" --include="Dockerfile.*" 2>/dev/null; then
        echo "^^ unresolved LLAMA_CPP_TAG/LLAMA_CPP_COMMIT_SHA placeholders found above." >&2
        status=1
    fi
    if [ "$status" -eq 0 ]; then
        echo "OK: no unresolved placeholders found."
    else
        echo "FAIL: unresolved placeholders remain — do not build until resolved (Rule 7, never guess a version)." >&2
    fi
    return "$status"
}

mode="${1:-}"
case "$mode" in
    --check-only)
        check_placeholders
        ;;
    --cve-check)
        echo "ERROR: --cve-check requires network access to the GitHub advisory/Huntr feeds." >&2
        echo "       Not runnable in this offline-authoring session. Run on a rig with" >&2
        echo "       explicit Maxine/Tiago authorisation." >&2
        exit 3
        ;;
    --emit-manifest)
        echo "ERROR: --emit-manifest requires a real build (llama.cpp checkout + cmake build)." >&2
        echo "       Not runnable in this offline-authoring session." >&2
        exit 3
        ;;
    *)
        usage
        exit 2
        ;;
esac
