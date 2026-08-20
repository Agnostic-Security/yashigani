#!/usr/bin/env bash
# infer/deploy/scripts/verify-offline.sh
#
# Umbrella offline-verify gate for the infer/deploy/ deliverables — everything runnable
# WITHOUT building or running a yashigani image, and without touching a rig (per this
# dispatch's OFFLINE AUTHORING ONLY constraint):
#   1. hadolint            — every Dockerfile.kuroshio-*
#   2. shellcheck           — every *.sh under infer/deploy/
#   3. helm lint            — infer/deploy/helm/yashigani-kuroshio
#   4. helm template        — render with default + a GPU-backend values override
#   5. caddy adapt           — Caddyfile.kuroshio-front (assert :443-style discipline: every
#                              dial explicit, no :80, no insecure_skip_verify)
#   6. jq seccomp validity   — infer/deploy/scripts/verify-seccomp-json.sh
#   7. helm-mirror parity    — infer/deploy/scripts/sync-kuroshio-deploy-artifacts-to-helm.sh --check
#
# Exits non-zero if ANY gate fails. Prints a per-gate PASS/FAIL summary at the end.

set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin:/Users/max/.local/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # infer/deploy
RESULTS=()
overall=0

record() {
    local name="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        RESULTS+=("PASS  $name")
    else
        RESULTS+=("FAIL  $name")
        overall=1
    fi
}

echo "== 1. hadolint =="
if command -v hadolint >/dev/null 2>&1; then
    rc=0
    for f in "$REPO_ROOT"/docker/Dockerfile.kuroshio-*; do
        echo "--- $f ---"
        hadolint --config "$REPO_ROOT/../../.hadolint.yaml" "$f" || rc=1
    done
    record "hadolint" "$rc"
else
    echo "hadolint not found on PATH — SKIPPED (not a fatal offline gate failure, but should be installed before merge)."
    record "hadolint (skipped — not installed)" 1
fi

echo
echo "== 2. shellcheck =="
rc=0
while IFS= read -r -d '' f; do
    echo "--- $f ---"
    shellcheck "$f" || rc=1
done < <(find "$REPO_ROOT" -name '*.sh' -print0)
record "shellcheck" "$rc"

echo
echo "== 3. helm lint =="
helm lint "$REPO_ROOT/helm/yashigani-kuroshio"
record "helm lint (default values)" "$?"

echo
echo "== 4. helm template (default + cuda backend) =="
helm template kuroshio-test "$REPO_ROOT/helm/yashigani-kuroshio" >/dev/null
record "helm template (default: cpu backend)" "$?"
helm template kuroshio-test "$REPO_ROOT/helm/yashigani-kuroshio" \
    --set backend=cuda \
    --set gpu.resourceName=nvidia.com/gpu \
    --set supervisorRbac.enabled=true \
    --set admissionPolicies.enabled=false \
    --set seccomp.installViaDaemonSet=true >/dev/null
record "helm template (cuda + supervisorRbac + seccomp DaemonSet)" "$?"

echo
echo "== 5. caddy adapt =="
if command -v caddy >/dev/null 2>&1; then
    tmp_caddyfile="$(mktemp -d)/Caddyfile.kuroshio-front.standalone"
    # Caddyfile.kuroshio-front is a snippet+site-block designed to be `import`ed — wrap it in a
    # minimal top-level file so `caddy adapt` can parse it standalone for the discipline
    # checks (explicit :11436 dial, no :80, no insecure_skip_verify) without the rest of the
    # real Caddyfile.{selfsigned,ca,acme} context.
    cp "$REPO_ROOT/docker/Caddyfile.kuroshio-front" "$tmp_caddyfile"
    adapt_out="$(caddy adapt --config "$tmp_caddyfile" --adapter caddyfile 2>&1)"
    adapt_rc=$?
    echo "$adapt_out" | head -5
    rc=0
    if [ "$adapt_rc" -ne 0 ]; then
        echo "caddy adapt FAILED to parse Caddyfile.kuroshio-front:" >&2
        echo "$adapt_out" >&2
        rc=1
    else
        if grep -qE '":80"|:80"' "$REPO_ROOT/docker/Caddyfile.kuroshio-front"; then
            echo "FAIL: :80 found in Caddyfile.kuroshio-front" >&2
            rc=1
        fi
        if grep -qi "insecure_skip_verify" "$REPO_ROOT/docker/Caddyfile.kuroshio-front"; then
            echo "FAIL: insecure_skip_verify found in Caddyfile.kuroshio-front" >&2
            rc=1
        fi
        if ! grep -q ":11436" "$REPO_ROOT/docker/Caddyfile.kuroshio-front"; then
            echo "FAIL: expected explicit :11436 listener dial not found" >&2
            rc=1
        fi
    fi
    record "caddy adapt + :443-style discipline" "$rc"
else
    echo "caddy not found on PATH — SKIPPED."
    record "caddy adapt (skipped — not installed)" 1
fi

echo
echo "== 6. seccomp JSON validity =="
"$REPO_ROOT/scripts/verify-seccomp-json.sh"
record "seccomp JSON validity" "$?"

echo
echo "== 7. helm-mirror parity =="
"$REPO_ROOT/scripts/sync-kuroshio-deploy-artifacts-to-helm.sh" --check
record "helm-mirror parity (Caddyfile + seccomp)" "$?"

echo
echo "===================== SUMMARY ====================="
for r in "${RESULTS[@]}"; do
    echo "$r"
done
echo "====================================================="
exit "$overall"
