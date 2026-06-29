#!/usr/bin/env bash
# scripts/audit-vendor-eval.sh <file>
#
# Pre-vendoring eval-class audit for JavaScript bundles.
# Exits 0 if no eval-class patterns found. Exits 1 if any match.
#
# Run BEFORE adding any JS bundle to static/vendor/ and record the result
# in scripts/vendor-audit-log.md.
#
# Patterns that are blocked by script-src 'self' (no 'unsafe-eval') + TT:
#   eval(...)               — direct eval (any form)
#   new Function(...)       — dynamic function construction
#   setTimeout("...",)      — string-form timer (eval-equivalent)
#   setInterval("...",)     — string-form timer (eval-equivalent)
#   document.write(...)     — legacy document write (CSP-blocked)
#
# KNOWN FAILURES:
#   swagger-ui-bundle.js    — KNOWN FAIL (webpack eval source-maps). Remediation:
#                             rebuild with devtool:false. See spec §3.6.
#   redoc.standalone.js     — run and record result before vendoring.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

file="${1:?Usage: audit-vendor-eval.sh <file>}"

if [ ! -f "$file" ]; then
    echo "ERROR: file not found: $file" >&2
    exit 1
fi

echo "=== Eval audit: $file ==="

hits=$(grep -En \
    "eval[[:space:]]*\(|new Function[[:space:]]*\(|setTimeout[[:space:]]*\([[:space:]]*['\"]|setInterval[[:space:]]*\([[:space:]]*['\"]|document\.write[[:space:]]*\(" \
    "$file" || true)

if [ -n "$hits" ]; then
    echo "FAIL: eval-class patterns found in $file:"
    echo "$hits"
    exit 1
fi

echo "PASS: no eval-class patterns in $file"
