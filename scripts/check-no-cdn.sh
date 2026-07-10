#!/usr/bin/env bash
# scripts/check-no-cdn.sh
#
# Fails if any template or static JS references an external CDN or font host.
# Complements the CSP-level enforcement with a build-time fail-fast.
#
# Run as a pre-commit hook and in CI on any commit touching src/ or templates.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# CDN hostname pattern — add to the alternation if new CDN domains appear
CDN_PATTERN="https?://(cdn\.|unpkg\.|jsdelivr\.|skypack\.|esm\.sh|fonts\.(google|gstatic)\.|cdnjs\.cloudflare\.com|raw\.githubusercontent\.com)"

# Exclude the pre-existing swagger-ui/ directory: redoc.standalone.js and
# swagger-ui-bundle.js are documented KNOWN FAIL items (RISK-115 / vendor-audit-log.md).
# Their CDN references are in bundled library source, not authored by this project.
# Remove this exclusion once the swagger-ui production rebuild is complete (Phase 1 §3.6).
hits=$(grep -rEn "$CDN_PATTERN" \
    "$REPO_ROOT/src/yashigani/backoffice/templates/" \
    "$REPO_ROOT/src/yashigani/backoffice/static/" \
    2>/dev/null \
    | grep -v '/static/swagger-ui/' \
    || true)

if [ -n "$hits" ]; then
    echo "FAIL: CDN reference found — violates no-CDN sole-egress policy:" >&2
    echo "$hits" >&2
    echo "" >&2
    echo "All third-party JS/CSS must be vendored under static/vendor/ (same-origin)." >&2
    exit 1
fi

# Also check for external <link rel="preconnect"> or <link rel="preload">
preconnect_hits=$(grep -rEn '<link[^>]+(preconnect|preload)[^>]+https?://' \
    "$REPO_ROOT/src/yashigani/backoffice/templates/" \
    2>/dev/null || true)

if [ -n "$preconnect_hits" ]; then
    echo "FAIL: external preconnect/preload found — violates no-CDN policy:" >&2
    echo "$preconnect_hits" >&2
    exit 1
fi

echo "No CDN references found. OK."
