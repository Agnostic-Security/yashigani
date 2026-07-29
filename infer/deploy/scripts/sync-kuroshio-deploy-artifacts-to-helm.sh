#!/usr/bin/env bash
# infer/deploy/scripts/sync-kuroshio-deploy-artifacts-to-helm.sh
#
# Single-source discipline (Iris F5 pattern, matches scripts/sync-caddyfile-egress-helm.sh):
# docker/Caddyfile.kuroshio-front and docker/seccomp/kuroshio-llama-server.json are CANONICAL.
# Helm cannot .Files.Get outside the chart root, so byte-identical mirrors live under
# helm/yashigani-kuroshio/files/ and are maintained ONLY by this script (one-way:
# infer/deploy/docker/ -> infer/deploy/helm/yashigani-kuroshio/files/).
#
# Usage:
#   scripts/sync-kuroshio-deploy-artifacts-to-helm.sh           # sync
#   scripts/sync-kuroshio-deploy-artifacts-to-helm.sh --check   # verify only; exit 1 on drift

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # infer/deploy

# Parallel indexed arrays, not an associative array (`declare -A`) — macOS ships bash 3.2 by
# default (no associative-array support), and this script must work identically on macOS and
# Linux without requiring an interpreter upgrade (feedback_local_test_must_work_on_macos_and_linux).
CANONICALS=(
    "$REPO_ROOT/docker/Caddyfile.kuroshio-front"
    "$REPO_ROOT/docker/seccomp/kuroshio-llama-server.json"
)
MIRRORS=(
    "$REPO_ROOT/helm/yashigani-kuroshio/files/Caddyfile.kuroshio-front"
    "$REPO_ROOT/helm/yashigani-kuroshio/files/seccomp/kuroshio-llama-server.json"
)

mode="${1:-sync}"
status=0

i=0
while [ "$i" -lt "${#CANONICALS[@]}" ]; do
    canonical="${CANONICALS[$i]}"
    mirror="${MIRRORS[$i]}"
    i=$((i + 1))
    if [ ! -f "$canonical" ]; then
        echo "ERROR: canonical file not found: $canonical" >&2
        status=1
        continue
    fi
    case "$mode" in
        --check)
            if [ ! -f "$mirror" ]; then
                echo "DRIFT: helm mirror missing: $mirror" >&2
                status=1
                continue
            fi
            if ! cmp -s "$canonical" "$mirror"; then
                echo "DRIFT: $mirror differs from canonical $canonical:" >&2
                diff "$canonical" "$mirror" | head -20 >&2
                status=1
            else
                echo "OK: $mirror byte-identical to canonical."
            fi
            ;;
        sync)
            mkdir -p "$(dirname "$mirror")"
            cp "$canonical" "$mirror"
            # cp then chmod: the mirror is data, never executable (iCloud +x residue rule).
            chmod 0644 "$mirror"
            echo "synced: $mirror"
            ;;
        *)
            echo "usage: $0 [--check]" >&2
            exit 2
            ;;
    esac
done

exit "$status"

