#!/usr/bin/env bash
# rotate-secret.sh — Yashigani operator CLI for admin-triggered secret rotation.
#
# Usage:
#   scripts/rotate-secret.sh <secret-name> [options]
#
# secret-name: postgres_password | redis_password | jwt_signing_key | hmac_key | all
#
# Authentication:
#   The script wraps POST /api/v1/admin/secrets/rotate. The caller must have:
#     1. A valid admin session cookie (__Host-yashigani_admin_session).
#     2. A fresh step-up TOTP (POST /auth/stepup first, or use --totp-code).
#
#   Passing the session token (choose ONE method — ordered by preference):
#
#     Method 1 (preferred — no process-table leak):
#       export YASHIGANI_SESSION_TOKEN="eyJhbGci..."
#       scripts/rotate-secret.sh postgres_password --totp-code 123456
#
#     Method 2 (stdin — useful in automated pipelines):
#       echo "eyJhbGci..." | scripts/rotate-secret.sh postgres_password --totp-code 123456
#       (script reads token from stdin if YASHIGANI_SESSION_TOKEN is not set)
#
#     Method 3 (0600 temp file — for scripted non-interactive use):
#       echo "eyJhbGci..." > /tmp/token && chmod 0600 /tmp/token
#       YASHIGANI_SESSION_TOKEN="$(cat /tmp/token)" scripts/rotate-secret.sh ...
#       rm /tmp/token
#
#   NOTE: --session-token CLI arg was REMOVED (B3 fix, Iris audit 2026-05-08).
#   Passing credentials as CLI args exposes them in /proc/<pid>/cmdline (visible
#   to all users via `ps aux` for the duration of the curl call). Use env var
#   or stdin instead. Per feedback_security_company_no_shortcuts.md.
#
#   Options:
#     --host <url>           Backoffice base URL (default: https://localhost:8443)
#     --totp-code <code>     Performs step-up first, then rotation
#     --ca-cert <path>       CA cert for TLS verification (default: docker/secrets/ca_root.crt)
#     --dry-run              Print the request without sending it
#
# Example:
#   export YASHIGANI_SESSION_TOKEN="$(cat /run/secrets/session_token)"
#   scripts/rotate-secret.sh postgres_password \
#     --host https://yashigani.local:8443 \
#     --totp-code 123456
#
# After rotation, the script runs docker/podman compose restart for the affected
# service (requires docker/podman access from the host where this script runs).
#
# Last updated: 2026-05-08T00:00:00+01:00
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${REPO_ROOT}/docker"

SECRET_NAME=""
HOST="https://localhost:8443"
SESSION_TOKEN=""
TOTP_CODE=""
CA_CERT="${DOCKER_DIR}/secrets/ca_root.crt"
CLIENT_CERT="${DOCKER_DIR}/secrets/backoffice_client.crt"
CLIENT_KEY="${DOCKER_DIR}/secrets/backoffice_client.key"
DRY_RUN=0

VALID_SECRETS="postgres_password redis_password jwt_signing_key hmac_key all"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: rotate-secret.sh <secret-name> [options]"
    echo ""
    echo "Secrets: ${VALID_SECRETS}"
    echo ""
    echo "Options:"
    echo "  --host <url>       Backoffice base URL (default: https://localhost:8443)"
    echo "  --totp-code <code> TOTP code for step-up (required before rotation)"
    echo "  --ca-cert <path>   CA cert path (default: docker/secrets/ca_root.crt)"
    echo "  --dry-run          Print request without sending"
    echo ""
    echo "Session token (required — choose one method):"
    echo "  export YASHIGANI_SESSION_TOKEN=<token>     (preferred)"
    echo "  echo <token> | rotate-secret.sh ...         (stdin)"
    echo ""
    echo "  --session-token was REMOVED: CLI credential args are visible in"
    echo "  'ps aux' for all users. Use env var or stdin instead."
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SECRET_NAME="$1"
shift

# Validate secret name
VALID=0
for s in ${VALID_SECRETS}; do
    if [[ "${SECRET_NAME}" == "${s}" ]]; then
        VALID=1
        break
    fi
done
if [[ ${VALID} -eq 0 ]]; then
    echo "ERROR: Unknown secret '${SECRET_NAME}'. Valid: ${VALID_SECRETS}" >&2
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2";      shift 2 ;;
        --totp-code)      TOTP_CODE="$2"; shift 2 ;;
        --ca-cert)        CA_CERT="$2";   shift 2 ;;
        --dry-run)        DRY_RUN=1;      shift ;;
        --session-token)
            echo "ERROR: --session-token was removed (B3 security fix, 2026-05-08)." >&2
            echo "  Passing credentials as CLI args exposes them in 'ps aux'." >&2
            echo "  Use: export YASHIGANI_SESSION_TOKEN=<token>" >&2
            echo "  Or:  echo <token> | $0 ${SECRET_NAME} [options]" >&2
            exit 1
            ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve session token — env var (preferred) or stdin
# ---------------------------------------------------------------------------
# B3 fix: never accept token as CLI arg (visible in ps aux / /proc/cmdline).
# Priority: YASHIGANI_SESSION_TOKEN env var > stdin pipe.
if [[ -n "${YASHIGANI_SESSION_TOKEN:-}" ]]; then
    SESSION_TOKEN="${YASHIGANI_SESSION_TOKEN}"
elif [[ ! -t 0 ]]; then
    # stdin is a pipe (not a terminal) — read token from it
    SESSION_TOKEN="$(cat)"
    SESSION_TOKEN="${SESSION_TOKEN//[$'\n\r']/}"  # strip newlines
fi

if [[ -z "${SESSION_TOKEN}" ]]; then
    echo "ERROR: No session token provided." >&2
    echo "" >&2
    echo "  Set YASHIGANI_SESSION_TOKEN env var (preferred):" >&2
    echo "    export YASHIGANI_SESSION_TOKEN=<token>" >&2
    echo "    ${0##*/} ${SECRET_NAME} [options]" >&2
    echo "" >&2
    echo "  Or pipe it via stdin:" >&2
    echo "    echo <token> | ${0##*/} ${SECRET_NAME} [options]" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# TLS and auth options for curl
# ---------------------------------------------------------------------------
CURL_OPTS=(
    --silent
    --show-error
    --fail-with-body
    --max-time 60
)

# CA cert for server TLS verification
if [[ -f "${CA_CERT}" ]]; then
    CURL_OPTS+=(--cacert "${CA_CERT}")
else
    echo "WARNING: CA cert not found at ${CA_CERT} — using system trust store" >&2
fi

# Client cert for mTLS (if available)
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
    CURL_OPTS+=(--cert "${CLIENT_CERT}" --key "${CLIENT_KEY}")
fi

COOKIE_HEADER="__Host-yashigani_admin_session=${SESSION_TOKEN}"

# ---------------------------------------------------------------------------
# Step 1: Perform step-up TOTP if --totp-code provided
# ---------------------------------------------------------------------------
if [[ -n "${TOTP_CODE}" ]]; then
    echo "[1/3] Performing step-up TOTP..." >&2

    STEPUP_BODY="{\"code\": \"${TOTP_CODE}\"}"
    STEPUP_URL="${HOST}/auth/stepup"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        echo "DRY-RUN: POST ${STEPUP_URL}" >&2
        echo "DRY-RUN: body=${STEPUP_BODY}" >&2
    else
        STEPUP_RESPONSE=$(curl "${CURL_OPTS[@]}" \
            -X POST "${STEPUP_URL}" \
            -H "Content-Type: application/json" \
            -H "Cookie: ${COOKIE_HEADER}" \
            -d "${STEPUP_BODY}" 2>&1) || {
            echo "ERROR: Step-up TOTP failed: ${STEPUP_RESPONSE}" >&2
            exit 1
        }
        echo "Step-up OK" >&2
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: Call the rotation API
# ---------------------------------------------------------------------------
ROTATE_BODY="{\"secret\": \"${SECRET_NAME}\"}"
ROTATE_URL="${HOST}/api/v1/admin/secrets/rotate"

if [[ ${DRY_RUN} -eq 1 ]]; then
    echo "DRY-RUN: POST ${ROTATE_URL}" >&2
    echo "DRY-RUN: body=${ROTATE_BODY}" >&2
    exit 0
fi

echo "[2/3] Calling rotation API for '${SECRET_NAME}'..." >&2

ROTATE_RESPONSE=$(curl "${CURL_OPTS[@]}" \
    -X POST "${ROTATE_URL}" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${COOKIE_HEADER}" \
    -d "${ROTATE_BODY}" 2>&1) || {
    echo "ERROR: Rotation API call failed: ${ROTATE_RESPONSE}" >&2
    exit 1
}

echo "${ROTATE_RESPONSE}"

# Parse success from JSON (basic grep; jq not required)
if echo "${ROTATE_RESPONSE}" | grep -q '"success": true'; then
    echo "" >&2
    echo "[3/3] Rotation reported SUCCESS." >&2
else
    echo "" >&2
    echo "WARNING: Rotation reported failure. Check response above." >&2
    # Exit 1 so CI pipelines detect failure
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Host-side service restart (if docker/podman available)
# ---------------------------------------------------------------------------
# Map secret to the services that need restarting on the host.
declare -A SERVICE_MAP
SERVICE_MAP["postgres_password"]="pgbouncer"
SERVICE_MAP["redis_password"]="redis"
SERVICE_MAP["jwt_signing_key"]="gateway"
SERVICE_MAP["hmac_key"]="caddy gateway backoffice"
SERVICE_MAP["all"]="pgbouncer redis gateway caddy backoffice"

SERVICES_TO_RESTART="${SERVICE_MAP[${SECRET_NAME}]:-}"

if [[ -n "${SERVICES_TO_RESTART}" ]]; then
    echo "" >&2
    echo "Services requiring restart: ${SERVICES_TO_RESTART}" >&2

    # Detect runtime: prefer podman, fall back to docker
    RUNTIME=""
    if command -v podman &>/dev/null; then
        RUNTIME="podman"
    elif command -v docker &>/dev/null; then
        RUNTIME="docker"
    fi

    if [[ -z "${RUNTIME}" ]]; then
        echo "WARNING: Neither docker nor podman found. Restart these services manually:" >&2
        echo "  ${SERVICES_TO_RESTART}" >&2
    else
        cd "${DOCKER_DIR}"
        for svc in ${SERVICES_TO_RESTART}; do
            echo "Restarting ${svc}..." >&2
            "${RUNTIME}" compose restart "${svc}" || {
                echo "WARNING: Failed to restart ${svc}" >&2
            }
        done
        echo "Done." >&2
    fi
fi

exit 0
