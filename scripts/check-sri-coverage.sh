#!/usr/bin/env bash
# scripts/check-sri-coverage.sh
#
# Finds any <script src="/static/vendor/..."> or <link href="/static/vendor/...">
# in HTML templates that are missing an integrity= attribute.
# Exits 1 if any found; exits 0 if all vendored asset references carry SRI.
#
# Run as a pre-commit hook and in CI.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATES_DIR="$REPO_ROOT/src/yashigani/backoffice/templates"

if [ ! -d "$TEMPLATES_DIR" ]; then
    echo "SKIP: templates directory not found at $TEMPLATES_DIR"
    exit 0
fi

# Find <script src="/static/vendor/..."> or <link ... href="/static/vendor/...">
# that do NOT have an integrity= attribute on the same line or nearby.
# We do a two-pass: find all vendor references, then filter for missing integrity=.
missing=$(grep -rEn '<(script[^>]+src|link[^>]+href)="/static/vendor/[^"]*"' \
    "$TEMPLATES_DIR" \
    2>/dev/null \
    | grep -v 'integrity=' || true)

if [ -n "$missing" ]; then
    echo "FAIL: vendored asset references missing SRI integrity= attribute:"
    echo "$missing"
    echo ""
    echo "Add integrity=\"sha384-<hash>\" crossorigin=\"anonymous\" to each reference."
    echo "Hashes are in scripts/vendor-integrity.lock."
    exit 1
fi

echo "SRI coverage OK: all vendored asset references carry integrity= attributes."
