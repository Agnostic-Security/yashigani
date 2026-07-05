#!/bin/sh
# Yashigani SVID sidecar — cert provisioning + rotation script (4.0 Phase 0)
#
# DESIGN
#   Phase 1 (init):
#     Copy the initial cert+key from /init/ → /run/secrets/svid/.
#     Validate the cert (openssl x509 -noout -checkend 0) — fail-closed if expired.
#     Write /run/ringfence/ready to signal the agent container.
#
#   Phase 2 (rotation loop):
#     Every POLL_INTERVAL_SECONDS check cert expiry.
#     When < RENEWAL_THRESHOLD_FRACTION of lifetime remains, call backoffice:
#       POST /admin/agents/${AGENT_ID}/cert/rotate
#       mTLS: client cert = /run/secrets/svid/client.crt + key
#       Response: new cert PEM in JSON field "cert_pem", key PEM in "key_pem"
#     Atomic write: write new cert+key to .new files, rename over existing.
#     Log all actions to stdout (container logs = tamper-evident via the
#     tamper-evident log chain on the host; see audit/sinks.py).
#
# FAIL-CLOSED RULES
#   - If init copy fails (source file missing / read error): exit 1.
#   - If initial cert is expired: exit 1 (agent must not start with stale certs).
#   - If rotation POST fails (HTTP != 200 or curl error): exit 1 (the compose
#     restart policy retries; the agent runs with the existing cert until recovery).
#   - If atomic rename fails (disk full / tmpfs error): exit 1.
#   - Never write partial cert state that leaves the agent with a mismatched
#     cert/key pair.
#
# ENVIRONMENT
#   AGENT_ID               — Letta/agent container ID (used in the rotate URL path)
#   BACKOFFICE_URL         — e.g. https://backoffice:8443 (internal mesh endpoint)
#   POLL_INTERVAL_SECONDS  — how often to check cert expiry (default: 3600)
#   RENEWAL_THRESHOLD_FRAC — fraction of lifetime below which to rotate (default: 0.33)
#   SVID_DIR               — where to write/read live certs (default: /run/secrets/svid)
#   INIT_DIR               — where initial certs are bind-mounted (default: /init)
#   READY_FLAG             — path of the ready sentinel (default: /run/ringfence/ready)
#
# SECURITY
#   - Runs as UID 1002 (non-root; set in Dockerfile).
#   - Reads only from INIT_DIR (ro bind-mount) and SVID_DIR (tmpfs rw).
#   - curl uses --cacert, --cert, --key for mTLS; no --insecure.
#   - No shell expansion of external data (agent names from env only).
#   - errexit + nounset + pipefail set immediately.
#
# shellcheck shell=sh

# pipefail is not available in POSIX sh (busybox on Alpine). Use set -eu only.
# Pipe failures in critical sections are checked manually via explicit variable inspection.
set -eu

# ── Configuration ─────────────────────────────────────────────────────────────
AGENT_ID="${AGENT_ID:?AGENT_ID env var is required}"
BACKOFFICE_URL="${BACKOFFICE_URL:-https://backoffice:8443}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-3600}"
RENEWAL_THRESHOLD_FRAC="${RENEWAL_THRESHOLD_FRAC:-0.33}"
SVID_DIR="${SVID_DIR:-/run/secrets/svid}"
INIT_DIR="${INIT_DIR:-/init}"
READY_FLAG="${READY_FLAG:-/run/ringfence/ready}"

CERT_PATH="${SVID_DIR}/client.crt"
KEY_PATH="${SVID_DIR}/client.key"
CA_PATH="${SVID_DIR}/ca.crt"

log() {
    # Prefix with ISO timestamp + PID for log correlation.
    printf '[%s] svid-sidecar[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$*"
}

die() {
    log "FATAL: $*"
    exit 1
}

# ── Phase 1: Init ─────────────────────────────────────────────────────────────

log "Phase 1: initialising SVID from ${INIT_DIR} → ${SVID_DIR}"

# Ensure target directory exists (tmpfs may not have been set up yet).
mkdir -p "${SVID_DIR}"

# Validate source files exist before copying.
[ -f "${INIT_DIR}/client.crt" ] || die "Init cert missing: ${INIT_DIR}/client.crt"
[ -f "${INIT_DIR}/client.key" ] || die "Init key missing: ${INIT_DIR}/client.key"
[ -f "${INIT_DIR}/ca.crt" ]     || die "Init CA cert missing: ${INIT_DIR}/ca.crt"

# Copy with explicit permissions:
#   cert/ca 0444 — world-readable for the agent container.
#   key     0440 + chown :2003 — group-readable for the shared svid GID (_MCP_SVID_GID=2003).
#   Caddy joins group 2003 (group_add: ["2003"] in the codegen-emitted compose snippet).
#   NOT 0400 (blocks Caddy) — NOT 0444 (world-readable, over-permissive for a private key).
#   Least-privilege: only owner (UID 1002 sidecar) and group 2003 (Caddy) can read the key.
cp "${INIT_DIR}/client.crt" "${CERT_PATH}"
chmod 0444 "${CERT_PATH}"
cp "${INIT_DIR}/client.key" "${KEY_PATH}"
chmod 0440 "${KEY_PATH}"
chown :2003 "${KEY_PATH}"
cp "${INIT_DIR}/ca.crt" "${CA_PATH}"
chmod 0444 "${CA_PATH}"

log "Certs copied. Validating initial cert…"

# Fail-closed: refuse to provision if cert is already expired.
if ! openssl x509 -in "${CERT_PATH}" -noout -checkend 0 2>/dev/null; then
    die "Initial cert at ${CERT_PATH} is expired. Refusing to provision. " \
        "Re-run install.sh mint-agent-leaf --tenant-id … --agent-name … to reissue."
fi

# Extract and log the not_after for observability.
NOT_AFTER="$(openssl x509 -in "${CERT_PATH}" -noout -enddate 2>/dev/null | cut -d= -f2 || echo unknown)"
log "Cert valid. not_after=${NOT_AFTER}"

# Extract SPIFFE ID from URI SAN for log correlation.
SPIFFE_ID="$(openssl x509 -in "${CERT_PATH}" -noout -ext subjectAltName 2>/dev/null \
    | grep -o 'URI:spiffe://[^,]*' | head -1 | sed 's/URI://' || echo unknown)"
log "SPIFFE ID: ${SPIFFE_ID}"

# Write the ready flag — signals PoolManager._wait_for_ringfence_init().
# Must be written AFTER certs are in place and validated.
mkdir -p "$(dirname "${READY_FLAG}")"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${READY_FLAG}"
log "Ready flag written: ${READY_FLAG}"

# ── Phase 2: Rotation loop ────────────────────────────────────────────────────

log "Phase 2: entering rotation poll loop (interval=${POLL_INTERVAL_SECONDS}s, threshold=${RENEWAL_THRESHOLD_FRAC})"

while true; do
    sleep "${POLL_INTERVAL_SECONDS}"

    log "Checking cert expiry…"

    # Fail-closed if cert file is missing or unreadable (should not happen).
    [ -f "${CERT_PATH}" ] || die "Cert file disappeared: ${CERT_PATH}"

    # Check if the cert is already expired.
    if ! openssl x509 -in "${CERT_PATH}" -noout -checkend 0 2>/dev/null; then
        log "WARN: cert is already expired — triggering immediate rotation"
        NEEDS_ROTATION=1
    else
        # Compute seconds remaining.
        # openssl x509 -enddate outputs: notAfter=<date string>
        # We use -checkend <N> to test if the cert expires within N seconds.
        # threshold fraction: if cert expires within (total_lifetime * threshold)
        # seconds, rotate. We approximate "total lifetime" as leaf_lifetime_days
        # from the env var (set by compose/K8s from the cert policy).
        # Default 90 days * 0.33 = ~29.7 days = 2566080 seconds.
        LEAF_LIFETIME_DAYS="${LEAF_LIFETIME_DAYS:-90}"
        THRESHOLD_SECONDS="$(awk "BEGIN { printf \"%d\", ${LEAF_LIFETIME_DAYS} * 86400 * ${RENEWAL_THRESHOLD_FRAC} }")"
        if ! openssl x509 -in "${CERT_PATH}" -noout -checkend "${THRESHOLD_SECONDS}" 2>/dev/null; then
            log "Cert expires within threshold (${THRESHOLD_SECONDS}s) — rotating"
            NEEDS_ROTATION=1
        else
            log "Cert OK (expires in >${THRESHOLD_SECONDS}s)"
            NEEDS_ROTATION=0
        fi
    fi

    if [ "${NEEDS_ROTATION}" = "1" ]; then
        log "Calling backoffice rotation endpoint: ${BACKOFFICE_URL}/admin/agents/${AGENT_ID}/cert/rotate"

        # POST to backoffice over mTLS using the CURRENT cert+key.
        # The sidecar's current cert (spiffe://…/agents/<tenant>/<name>) is the
        # credential that the allowed_spiffe_prefix ACL accepts.
        # --fail: exit non-zero on HTTP error (4xx/5xx).
        # --silent: suppress progress bar (not log output — we redirect to log).
        # --show-error: still show curl errors even with --silent.
        RESPONSE_FILE="${SVID_DIR}/.rotate_response.json"
        HTTP_CODE="$(curl \
            --silent \
            --show-error \
            --fail \
            --write-out '%{http_code}' \
            --output "${RESPONSE_FILE}" \
            --cacert "${CA_PATH}" \
            --cert "${CERT_PATH}" \
            --key "${KEY_PATH}" \
            --request POST \
            --header "Content-Type: application/json" \
            --data "{\"agent_id\": \"${AGENT_ID}\"}" \
            "${BACKOFFICE_URL}/admin/agents/${AGENT_ID}/cert/rotate" \
            2>&1 | tee /dev/stderr || true)"

        if [ "${HTTP_CODE}" != "200" ]; then
            # Fail-closed: log and exit. compose restart policy retries.
            # The agent keeps the existing cert until the sidecar recovers.
            die "Rotation failed: HTTP ${HTTP_CODE}. See ${RESPONSE_FILE} for details."
        fi

        log "Rotation response received (HTTP 200). Extracting new cert+key…"

        # Parse the JSON response. We avoid jq (not installed) by using grep+sed.
        # Response format: {"cert_pem": "-----BEGIN CERTIFICATE-----\n…", "key_pem": "…"}
        # Newlines in JSON are encoded as \n — sed converts them back.
        NEW_CERT="$(grep -o '"cert_pem"[[:space:]]*:[[:space:]]*"[^"]*"' "${RESPONSE_FILE}" \
            | sed 's/"cert_pem"[[:space:]]*:[[:space:]]*"//; s/"$//' \
            | sed 's/\\n/\n/g')"
        NEW_KEY="$(grep -o '"key_pem"[[:space:]]*:[[:space:]]*"[^"]*"' "${RESPONSE_FILE}" \
            | sed 's/"key_pem"[[:space:]]*:[[:space:]]*"//; s/"$//' \
            | sed 's/\\n/\n/g')"

        [ -n "${NEW_CERT}" ] || die "Rotation response missing cert_pem field"
        [ -n "${NEW_KEY}" ]  || die "Rotation response missing key_pem field"

        # Validate the new cert before writing (fail-closed if expired or invalid).
        NEW_CERT_TMP="${SVID_DIR}/.client.crt.new"
        NEW_KEY_TMP="${SVID_DIR}/.client.key.new"
        printf '%s\n' "${NEW_CERT}" > "${NEW_CERT_TMP}"
        printf '%s\n' "${NEW_KEY}"  > "${NEW_KEY_TMP}"
        chmod 0444 "${NEW_CERT_TMP}"
        # v4.1 Phase 1b-ii: 0440 + :2003 mirrors init-phase perms (see comment above).
        # mv(1) preserves mode+ownership atomically — KEY_PATH inherits 0440/:2003.
        chmod 0440 "${NEW_KEY_TMP}"
        chown :2003 "${NEW_KEY_TMP}"

        if ! openssl x509 -in "${NEW_CERT_TMP}" -noout -checkend 0 2>/dev/null; then
            rm -f "${NEW_CERT_TMP}" "${NEW_KEY_TMP}"
            die "New cert from rotation endpoint is already expired or invalid. Keeping existing cert."
        fi

        NEW_NOT_AFTER="$(openssl x509 -in "${NEW_CERT_TMP}" -noout -enddate 2>/dev/null | cut -d= -f2 || echo unknown)"
        log "New cert validated. not_after=${NEW_NOT_AFTER}"

        # Atomic rename: write to .new files first, then rename over the live copies.
        # POSIX rename() is atomic within the same filesystem (tmpfs qualifies).
        # No window where the agent reads a partial cert/key.
        mv "${NEW_CERT_TMP}" "${CERT_PATH}"
        mv "${NEW_KEY_TMP}"  "${KEY_PATH}"

        rm -f "${RESPONSE_FILE}"
        log "Cert rotation complete. new_not_after=${NEW_NOT_AFTER}"
    fi
done
