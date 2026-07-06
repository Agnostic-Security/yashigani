#!/usr/bin/env bash
# scripts/sync-caddyfile-egress-helm.sh
#
# v4.1 unified-sidecar must-fix #9 (Captain C5): :18790 single-sourcing.
#
# docker/Caddyfile.openclaw-egress is the CANONICAL static :18790 listener
# (openclaw egress gateway).  The Helm chart cannot .Files.Get outside the
# chart root, so a byte-identical mirror lives at
#   helm/yashigani/files/Caddyfile.openclaw-egress
# and helm/yashigani/templates/configmaps.yaml renders it via .Files.Get with
# four documented template substitutions (service name, trust anchor, SPIFFE
# trust domain, telegram bot-ID default) — see the canonical file header.
#
# This script maintains the mirror (one-way: docker/ → helm/files/).
# Same pattern as the mcp.rego → helm policy-bundle fix
# (scripts/check-opa-helm-parity.sh).
#
# Usage:
#   scripts/sync-caddyfile-egress-helm.sh           # sync (copy canonical → mirror)
#   scripts/sync-caddyfile-egress-helm.sh --check   # verify only; exit 1 on drift
#
# Drift is ALSO caught by tests/contracts/test_openclaw_egress_single_source.py
# (byte-parity contract test) — this script is the fix path, the test is the gate.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANONICAL="$REPO_ROOT/docker/Caddyfile.openclaw-egress"
MIRROR="$REPO_ROOT/helm/yashigani/files/Caddyfile.openclaw-egress"

if [ ! -f "$CANONICAL" ]; then
    echo "ERROR: canonical file not found: $CANONICAL" >&2
    exit 1
fi

mode="${1:-sync}"

case "$mode" in
    --check)
        if [ ! -f "$MIRROR" ]; then
            echo "DRIFT: helm mirror missing: $MIRROR" >&2
            echo "FIX: scripts/sync-caddyfile-egress-helm.sh" >&2
            exit 1
        fi
        if ! cmp -s "$CANONICAL" "$MIRROR"; then
            echo "DRIFT: helm mirror differs from canonical docker/Caddyfile.openclaw-egress:" >&2
            diff "$CANONICAL" "$MIRROR" | head -20 >&2
            echo "FIX: edit ONLY the canonical file, then run scripts/sync-caddyfile-egress-helm.sh" >&2
            exit 1
        fi
        echo ":18790 helm mirror parity OK (byte-identical)."
        ;;
    sync)
        mkdir -p "$(dirname "$MIRROR")"
        # cp then chmod: the mirror is data, never executable (iCloud +x residue
        # rule — executable bits on helm files are a defect).
        cp "$CANONICAL" "$MIRROR"
        chmod 0644 "$MIRROR"
        echo "synced: $MIRROR (byte-identical to canonical)"
        ;;
    *)
        echo "usage: $0 [--check]" >&2
        exit 2
        ;;
esac
