#!/usr/bin/env bash
# infer/deploy/scripts/verify-seccomp-json.sh
#
# Offline-verifiable check (Verification Protocol item 12/"seccomp JSON validity" in the
# dispatch brief): every seccomp profile under infer/deploy/docker/seccomp/ AND its helm
# mirror parses as valid JSON and has the expected top-level shape
# (defaultAction/archMap/syscalls). This does NOT require a running container or a rig —
# pure static JSON validation, run with `jq`.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # infer/deploy

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required for this check and is not on PATH." >&2
    exit 2
fi

status=0
files=(
    "$REPO_ROOT/docker/seccomp/kuroshio-llama-server.json"
    "$REPO_ROOT/docker/seccomp/kuroshio-first-parse-jail.json"
    "$REPO_ROOT/helm/yashigani-kuroshio/files/seccomp/kuroshio-llama-server.json"
)

for f in "${files[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing $f" >&2
        status=1
        continue
    fi
    if ! jq -e '.defaultAction and .archMap and .syscalls' "$f" >/dev/null 2>&1; then
        echo "ERROR: $f failed JSON-validity/shape check (defaultAction/archMap/syscalls)" >&2
        status=1
        continue
    fi
    default_action="$(jq -r '.defaultAction' "$f")"
    if [ "$default_action" != "SCMP_ACT_ERRNO" ]; then
        echo "ERROR: $f defaultAction is '$default_action', expected SCMP_ACT_ERRNO (default-deny)" >&2
        status=1
        continue
    fi
    echo "OK: $f (valid JSON, defaultAction=SCMP_ACT_ERRNO)"
done

exit "$status"
