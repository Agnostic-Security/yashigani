#!/usr/bin/env bash
# scripts/check-opa-helm-parity.sh
#
# SEAM-1d-helm-opa-01: Verifies that every production OPA policy file in
# policy/ has a byte-identical copy in helm/yashigani/files/policy/.
#
# Background: OPA policies ship as a bundle (policy/*.rego + system/ subdir)
# baked into the Docker image at build time AND as a helm ConfigMap (files in
# helm/yashigani/files/policy/). Two copies means two drift risk points. This
# gate catches divergence at pre-commit / CI time so it never reaches a tag.
#
# EXCLUDED (from both sides):
#   *_test.rego     — unit tests; helm does NOT ship tests into the bundle
#   *.schema.json   — MCP JSON-Schema; helm does not ship it (OPA does not need it)
#   data/           — OPA data directory; helm uses a separate ConfigMap for data
#   examples/       — illustrative snippets; never shipped to either runtime
#
# Run as a pre-commit hook and in CI.
# Exit 0 = parity OK. Exit 1 = drift detected.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_POLICY="$REPO_ROOT/policy"
HELM_POLICY="$REPO_ROOT/helm/yashigani/files/policy"

fail=0

# ── 1. Sanity: both directories must exist ───────────────────────────────────
if [ ! -d "$DOCKER_POLICY" ]; then
    echo "DRIFT-GATE ERROR: policy/ directory not found at $DOCKER_POLICY" >&2
    exit 1
fi
if [ ! -d "$HELM_POLICY" ]; then
    echo "DRIFT-GATE ERROR: helm policy directory not found at $HELM_POLICY" >&2
    exit 1
fi

# ── 2. Build sorted lists of production .rego files (excluded as above) ──────
# Use find + sort for reproducibility; strip leading path prefix for comparison.
list_rego() {
    local base="$1"
    # -printf '%P\n' is GNU find only; macOS BSD find omits it.
    # Strip the base path prefix portably: find outputs full paths, sed strips prefix.
    find "$base" \
        -name '*.rego' \
        ! -name '*_test.rego' \
        ! -path '*/data/*' \
        ! -path '*/examples/*' \
        2>/dev/null \
    | sed "s|^${base}/||" \
    | sort
}

docker_files="$(list_rego "$DOCKER_POLICY")"
helm_files="$(list_rego "$HELM_POLICY")"

# ── 3. File-set parity check ─────────────────────────────────────────────────
# Every production .rego in docker must exist in helm and vice-versa.

while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    if ! echo "$helm_files" | grep -qxF "$rel"; then
        echo "DRIFT: policy/$rel present in docker bundle but MISSING from helm bundle" >&2
        fail=1
    fi
done <<< "$docker_files"

while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    if ! echo "$docker_files" | grep -qxF "$rel"; then
        echo "DRIFT: helm/yashigani/files/policy/$rel present in helm bundle but MISSING from docker bundle" >&2
        fail=1
    fi
done <<< "$helm_files"

# ── 4. Content parity check ───────────────────────────────────────────────────
# For each file that exists on both sides, content must be byte-identical.
while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    docker_f="$DOCKER_POLICY/$rel"
    helm_f="$HELM_POLICY/$rel"
    if [ -f "$docker_f" ] && [ -f "$helm_f" ]; then
        if ! diff -q "$docker_f" "$helm_f" > /dev/null 2>&1; then
            echo "DRIFT: $rel content differs between policy/ and helm/yashigani/files/policy/" >&2
            diff "$docker_f" "$helm_f" | head -20 >&2
            fail=1
        fi
    fi
done <<< "$docker_files"

# ── 5. system/ subdirectory parity ───────────────────────────────────────────
# The system/ directory ships data.json + authz helper stubs. Both copies must
# be identical (not just .rego files — everything in system/ is production).
docker_sys="$DOCKER_POLICY/system"
helm_sys="$HELM_POLICY/system"

if [ -d "$docker_sys" ] || [ -d "$helm_sys" ]; then
    if [ ! -d "$docker_sys" ]; then
        echo "DRIFT: policy/system/ exists in helm but not in docker bundle" >&2
        fail=1
    elif [ ! -d "$helm_sys" ]; then
        echo "DRIFT: policy/system/ exists in docker bundle but not in helm" >&2
        fail=1
    else
        # Exclude *_test.rego from system/ comparison (same exclusion as the .rego check above).
        # diff -rq has no --exclude for specific extensions portably; use find+sort+diff loop.
        docker_sys_files="$(find "$docker_sys" -type f ! -name '*_test.rego' | sed "s|^${docker_sys}/||" | sort)"
        helm_sys_files="$(find "$helm_sys"   -type f ! -name '*_test.rego' | sed "s|^${helm_sys}/||"   | sort)"
        if [ "$docker_sys_files" != "$helm_sys_files" ]; then
            echo "DRIFT: policy/system/ file-set differs (excluding test files):" >&2
            diff <(echo "$docker_sys_files") <(echo "$helm_sys_files") >&2
            fail=1
        else
            while IFS= read -r sys_rel; do
                [ -z "$sys_rel" ] && continue
                if ! diff -q "$docker_sys/$sys_rel" "$helm_sys/$sys_rel" > /dev/null 2>&1; then
                    echo "DRIFT: policy/system/$sys_rel content differs between docker and helm" >&2
                    diff "$docker_sys/$sys_rel" "$helm_sys/$sys_rel" | head -20 >&2
                    fail=1
                fi
            done <<< "$docker_sys_files"
        fi
    fi
fi

# ── Result ────────────────────────────────────────────────────────────────────
if [ "$fail" -eq 0 ]; then
    echo "OPA helm parity OK: $(echo "$docker_files" | grep -c .) production .rego file(s) + system/ match between docker and helm bundles."
    exit 0
else
    echo "" >&2
    echo "FIX: keep policy/ and helm/yashigani/files/policy/ in sync." >&2
    echo "     Production (non-test) .rego files must be byte-identical on both sides." >&2
    echo "     Re-run after syncing: scripts/check-opa-helm-parity.sh" >&2
    exit 1
fi
