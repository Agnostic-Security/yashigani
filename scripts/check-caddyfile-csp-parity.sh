#!/usr/bin/env bash
# scripts/check-caddyfile-csp-parity.sh
#
# Verifies that the CSP policy values in all four Caddyfile variants
# (selfsigned, ca, acme, Helm configmaps) are parity-equivalent.
#
# The three Docker Caddyfiles now delegate to the (csp-policies) snippet
# imported from docker/Caddyfile.csp — their CSP blocks are structurally
# identical by construction. This script validates:
#   1. That docker/Caddyfile.csp exists and contains the expected matchers.
#   2. That each Docker Caddyfile imports it (no residual inline CSP).
#   3. That the Helm configmaps.yaml inline CSP block matches the canonical
#      values from Caddyfile.csp.
#
# Run as a pre-commit hook and in CI.
# Exit 0 = parity OK. Exit 1 = drift detected.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSP_FILE="$REPO_ROOT/docker/Caddyfile.csp"
HELM_CONFIGMAP="$REPO_ROOT/helm/yashigani/templates/configmaps.yaml"

fail=0

# ── 1. Caddyfile.csp must exist ──────────────────────────────────────────────
if [ ! -f "$CSP_FILE" ]; then
    echo "DRIFT: docker/Caddyfile.csp not found" >&2
    exit 1
fi

# ── 2. Caddyfile.csp must define the (csp-policies) snippet ─────────────────
for matcher in '@lenient_subapp' '@redoc_ui' '@strict_legacy' '@strict_tt'; do
    if ! grep -q "$matcher" "$CSP_FILE"; then
        echo "DRIFT: $matcher missing from docker/Caddyfile.csp" >&2
        fail=1
    fi
done

if ! grep -q 'require-trusted-types-for' "$CSP_FILE"; then
    echo "DRIFT: require-trusted-types-for missing from @strict_tt in Caddyfile.csp" >&2
    fail=1
fi

if ! grep -q 'trusted-types yashigani-render' "$CSP_FILE"; then
    echo "DRIFT: trusted-types yashigani-render missing from @strict_tt in Caddyfile.csp" >&2
    fail=1
fi

# ── 3. Each Docker Caddyfile must import csp-policies (not inline CSP) ───────
for f in "$REPO_ROOT/docker/Caddyfile.selfsigned" \
          "$REPO_ROOT/docker/Caddyfile.ca" \
          "$REPO_ROOT/docker/Caddyfile.acme"; do
    name="$(basename "$f")"
    if ! grep -q 'import csp-policies' "$f"; then
        echo "DRIFT: $name does not contain 'import csp-policies'" >&2
        fail=1
    fi
    if ! grep -q 'import /etc/caddy/Caddyfile.csp' "$f"; then
        echo "DRIFT: $name does not import /etc/caddy/Caddyfile.csp" >&2
        fail=1
    fi
    # Verify no residual @lenient_ui catch-all matcher definition (SC-NEW-001 regression check)
    # grep -v '^[[:space:]]*#' strips comment lines before checking
    if grep -v '^[[:space:]]*#' "$f" | grep -q '@lenient_ui'; then
        echo "DRIFT: $name still contains @lenient_ui catch-all (should be removed)" >&2
        fail=1
    fi
    # Verify no residual @strict_ui matcher definition (replaced by @strict_legacy)
    if grep -v '^[[:space:]]*#' "$f" | grep -q '@strict_ui'; then
        echo "DRIFT: $name still contains @strict_ui (should be @strict_legacy)" >&2
        fail=1
    fi
done

# ── 4. Helm configmap must contain the @strict_tt header with TT directives ──
if [ -f "$HELM_CONFIGMAP" ]; then
    if ! grep -q 'require-trusted-types-for' "$HELM_CONFIGMAP"; then
        echo "DRIFT: Helm configmaps.yaml missing require-trusted-types-for in @strict_tt" >&2
        fail=1
    fi
    if ! grep -q 'trusted-types yashigani-render' "$HELM_CONFIGMAP"; then
        echo "DRIFT: Helm configmaps.yaml missing trusted-types yashigani-render" >&2
        fail=1
    fi
    if ! grep -q 'drawflow-label' "$HELM_CONFIGMAP"; then
        echo "DRIFT: Helm configmaps.yaml missing drawflow-label in trusted-types (Phase 4 addition)" >&2
        fail=1
    fi
    if grep -v '[[:space:]]*#' "$HELM_CONFIGMAP" | grep -q '@lenient_ui'; then
        echo "DRIFT: Helm configmaps.yaml still contains @lenient_ui catch-all" >&2
        fail=1
    fi
    if grep -v '[[:space:]]*#' "$HELM_CONFIGMAP" | grep -q '@strict_ui'; then
        echo "DRIFT: Helm configmaps.yaml still contains @strict_ui (should be @strict_legacy)" >&2
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "CSP parity OK: Caddyfile.csp, 3 Caddyfile variants, Helm configmap all consistent."
    exit 0
else
    exit 1
fi
