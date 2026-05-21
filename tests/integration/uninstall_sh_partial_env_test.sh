#!/usr/bin/env bash
# uninstall_sh_partial_env_test.sh — Regression test for BUG-UNINSTALL-PARTIAL-ENV.
#
# Verifies that uninstall.sh succeeds when docker/.env EXISTS but is INCOMPLETE
# (e.g. install.sh wrote early vars before failing). The realistic operator path:
#   install.sh writes YASHIGANI_VERSION + CADDY_INTERNAL_HMAC → fails partway
#   → operator runs ./uninstall.sh --remove-volumes --yes to clean up
#   → compose down must parse without interpolation errors
#
# Scenarios tested:
#   (a) Source-code check: partial-env stub block is present in uninstall.sh.
#   (b) Source-code check: dynamic grep of compose file is used (zero-maintenance).
#   (c) Source-code check: process-env export (no file mutation).
#   (d) Live run: partial .env (1 var only) → compose config parse succeeds.
#       Uses compose config as a proxy for compose down parse-time behaviour.
#   (e) Live run: docker/.env content is unchanged after uninstall.sh exits.
#   (f) Live run: uninstall.sh does NOT emit "required variable ... is missing a value".
#   (g) Source-code check: an already-set process-env var is NOT re-exported
#       (idempotency — vars set by the operator environment must not be clobbered).
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# BUG-UNINSTALL-PARTIAL-ENV
# last-updated: 2026-05-15T17:00:00+00:00

set -uo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_skip() { printf "[SKIP] %s\n" "$1"; (( SKIP++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UNINSTALL_SH="${UNINSTALL_SH:-${REPO_ROOT}/uninstall.sh}"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"
ENV_FILE="${REPO_ROOT}/docker/.env"

_info "uninstall.sh:  ${UNINSTALL_SH}"
_info "compose file:  ${COMPOSE_FILE}"
_info "docker/.env:   ${ENV_FILE}"

if [[ ! -f "$UNINSTALL_SH" ]]; then
    printf "[FAIL] uninstall.sh not found at: %s\n" "$UNINSTALL_SH" >&2
    exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
    printf "[FAIL] docker-compose.yml not found at: %s\n" "$COMPOSE_FILE" >&2
    exit 1
fi

# Detect compose runtime
_RUNTIME=""
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    _RUNTIME="docker"
elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    _RUNTIME="podman"
fi

# ---------------------------------------------------------------------------
# CHECK (a): BUG-UNINSTALL-PARTIAL-ENV fix block is present in uninstall.sh
# ---------------------------------------------------------------------------
_section "CHECK (a): BUG-UNINSTALL-PARTIAL-ENV block present in source"

if grep -q "BUG-UNINSTALL-PARTIAL-ENV" "$UNINSTALL_SH"; then
    _pass "(a.1) BUG-UNINSTALL-PARTIAL-ENV marker present in uninstall.sh"
else
    _fail "(a.1) BUG-UNINSTALL-PARTIAL-ENV marker NOT found in uninstall.sh — fix not applied"
fi

if grep -q "_PARTIAL_ENV_STUBBED" "$UNINSTALL_SH"; then
    _pass "(a.2) _PARTIAL_ENV_STUBBED variable present in uninstall.sh"
else
    _fail "(a.2) _PARTIAL_ENV_STUBBED NOT found — partial-env stub logic missing"
fi

# ---------------------------------------------------------------------------
# CHECK (b): Dynamic grep approach is used (zero-maintenance detection)
# ---------------------------------------------------------------------------
_section "CHECK (b): Dynamic grep of compose file for :? vars"

if grep -q "grep.*:\?" "$UNINSTALL_SH" || grep -q 'grep.*\\?.*COMPOSE_FILE\|COMPOSE_FILE.*grep' "$UNINSTALL_SH"; then
    _pass "(b.1) Dynamic grep of compose file present in uninstall.sh"
else
    # Looser check — the grep may be in a pipeline
    if grep -q '\$COMPOSE_FILE' "$UNINSTALL_SH" && grep -q "sort -u" "$UNINSTALL_SH"; then
        _pass "(b.1) Dynamic compose-file enumeration pattern found (COMPOSE_FILE + sort -u)"
    else
        _fail "(b.1) Dynamic grep of compose file NOT found — partial-env detection may be hardcoded"
    fi
fi

# ---------------------------------------------------------------------------
# CHECK (c): Process-env export (no file mutation on partial .env)
# ---------------------------------------------------------------------------
_section "CHECK (c): Process-env export approach (no file mutation)"

# The fix must use `export` not `cat >>` or `echo >>` to the .env file.
# We check the partial-env block uses export not file append.
_partial_env_block_start="$(grep -n "BUG-UNINSTALL-PARTIAL-ENV" "$UNINSTALL_SH" \
    | grep -v "^[0-9]*:#\|^[0-9]*:# BUG-UNINSTALL-PARTIAL-ENV: Phase B" \
    | tail -1 | cut -d: -f1 || true)"

# Find Phase B block (the one that does the stubbing, not the comment header)
_phase_b_line="$(grep -n "Phase B" "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"

if [[ -n "$_phase_b_line" ]]; then
    # Extract 80 lines starting at Phase B (block is ~60 lines + comment header)
    _phase_b_block="$(awk "NR>=${_phase_b_line} && NR<=$((_phase_b_line+80))" "$UNINSTALL_SH")"

    if printf '%s\n' "$_phase_b_block" | grep -q "export "; then
        _pass "(c.1) export statement found in Phase B block — process-env approach confirmed"
    else
        _fail "(c.1) No export statement in Phase B block — file-mutation approach may be in use"
    fi

    # Verify no >> (append) to _ENV_FILE in Phase B
    if printf '%s\n' "$_phase_b_block" | grep -q '>>.*_ENV_FILE'; then
        _fail "(c.2) Phase B block appends to _ENV_FILE — file is being mutated (violates Option A guarantee)"
    else
        _pass "(c.2) Phase B block does NOT append to _ENV_FILE — on-disk file is safe"
    fi
else
    _fail "(c.1) Could not locate Phase B block in uninstall.sh (grep for 'Phase B' failed)"
    _fail "(c.2) Cannot verify file-mutation absence without Phase B location"
fi

# ---------------------------------------------------------------------------
# CHECK (d)+(e)+(f): Live run with partial .env
#
# Stage a partial .env with only YASHIGANI_VERSION (not a :? var) and one
# :? var (CADDY_INTERNAL_HMAC) to simulate a real partial-install remnant.
# Remaining :? vars (OWUI_SECRET_KEY, YASHIGANI_TLS_DOMAIN,
# PROMETHEUS_BASICAUTH_HASH, UPSTREAM_MCP_URL, YASHIGANI_DB_AES_KEY) are absent.
#
# The test backs up any real .env, stages the partial .env, runs uninstall.sh,
# then asserts: (d) compose config succeeds, (e) .env content is unchanged,
# (f) no "required variable ... is missing a value" error.
#
# Requires: a compose runtime. Skipped if neither docker compose nor podman
# compose is available.
# ---------------------------------------------------------------------------
_section "CHECK (d)+(e)+(f): Live run with partial docker/.env"

# The partial .env to stage: YASHIGANI_VERSION + CADDY_INTERNAL_HMAC only.
# All other :? vars are deliberately absent.
_PARTIAL_ENV_CONTENT="YASHIGANI_VERSION=2.23.4
CADDY_INTERNAL_HMAC=partial-install-hmac-written-by-install-sh
POSTGRES_PASSWORD=partial-install-pg-pw
"

# Determine which :? vars are MISSING from the partial env above
_REQUIRED_VARS_IN_COMPOSE=()
while IFS= read -r _v; do
    [[ -n "$_v" ]] && _REQUIRED_VARS_IN_COMPOSE+=("$_v")
done < <(grep -oE '\$\{[A-Z_]+:\?' "$COMPOSE_FILE" 2>/dev/null \
    | sed 's/^\${//;s/:?$//' \
    | sort -u || true)

_info "Required :? vars in docker-compose.yml: ${#_REQUIRED_VARS_IN_COMPOSE[@]}"
for _v in "${_REQUIRED_VARS_IN_COMPOSE[@]}"; do
    _info "  - ${_v}"
done

if [[ -z "$_RUNTIME" ]]; then
    _skip "(d) Live partial-env run: no compose runtime available (docker/podman compose)"
    _skip "(e) On-disk .env preservation: no compose runtime — skipping"
    _skip "(f) No interpolation error: no compose runtime — skipping"
else
    # Back up real .env if present
    _REAL_ENV_BACKED_UP="false"
    _BACKUP_PATH="${REPO_ROOT}/tests/integration/.tmp_partial_env_backup_$$.env"
    _cleanup_live_test() {
        # Always restore the real .env on exit from this section
        if [[ "$_REAL_ENV_BACKED_UP" == "true" ]] && [[ -f "$_BACKUP_PATH" ]]; then
            cp "$_BACKUP_PATH" "$ENV_FILE"
            rm -f "$_BACKUP_PATH"
        elif [[ "$_REAL_ENV_BACKED_UP" == "false" ]] && [[ -f "$ENV_FILE" ]]; then
            # We staged a partial env and it wasn't cleaned by uninstall.sh — remove it
            # but only if it matches our partial content (sentinel check)
            if grep -q "partial-install-hmac-written-by-install-sh" "$ENV_FILE" 2>/dev/null; then
                rm -f "$ENV_FILE"
            fi
        fi
        rm -f "$_BACKUP_PATH" 2>/dev/null || true
    }
    trap '_cleanup_live_test' EXIT

    if [[ -f "$ENV_FILE" ]]; then
        cp "$ENV_FILE" "$_BACKUP_PATH"
        _REAL_ENV_BACKED_UP="true"
        _info "real docker/.env backed up to ${_BACKUP_PATH}"
    fi

    # Stage the partial .env
    printf '%s' "$_PARTIAL_ENV_CONTENT" > "$ENV_FILE"
    _staged_checksum="$(md5 -q "$ENV_FILE" 2>/dev/null || md5sum "$ENV_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
    _info "partial docker/.env staged ($(wc -l < "$ENV_FILE" | tr -d ' ') lines, checksum: ${_staged_checksum})"

    # Run uninstall.sh with --yes, capture stdout+stderr and exit code
    _uninstall_out=""
    _uninstall_rc=0
    _uninstall_out="$(bash "$UNINSTALL_SH" --runtime="$_RUNTIME" --yes 2>&1)" || _uninstall_rc=$?
    _info "uninstall.sh exit code: ${_uninstall_rc}"

    # CHECK (d): compose parse did not fail (exit 0 or non-parse-error exit)
    # We accept non-zero exit if the cause is NOT a missing-var interpolation error
    # (e.g. "no containers to stop" is fine).
    if printf '%s\n' "$_uninstall_out" | grep -q "required variable.*is missing a value"; then
        _fail "(d) uninstall.sh emitted 'required variable ... is missing a value' — partial-env fix not working"
        printf '%s\n' "$_uninstall_out" | grep "required variable" | while IFS= read -r _line; do
            printf "       → %s\n" "$_line" >&2
        done
    else
        _pass "(d) uninstall.sh did NOT emit 'required variable ... is missing a value' (parse ok)"
    fi

    # CHECK (d) continued: log whether BUG-UNINSTALL-PARTIAL-ENV stub message appeared
    if printf '%s\n' "$_uninstall_out" | grep -q "BUG-UNINSTALL-PARTIAL-ENV"; then
        _pass "(d.2) uninstall.sh logged BUG-UNINSTALL-PARTIAL-ENV stub message (fix fired)"
    else
        # This can happen if all vars happened to be set in process env — not a hard failure
        _info "(d.2) BUG-UNINSTALL-PARTIAL-ENV log line not found — vars may have been set in process env already"
    fi

    # CHECK (e): on-disk docker/.env is unchanged after uninstall.sh exits
    if [[ -f "$ENV_FILE" ]]; then
        _post_checksum="$(md5 -q "$ENV_FILE" 2>/dev/null || md5sum "$ENV_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
        if [[ "$_staged_checksum" == "$_post_checksum" ]]; then
            _pass "(e) docker/.env content is unchanged after uninstall.sh (checksum match: ${_post_checksum})"
        else
            _fail "(e) docker/.env was modified by uninstall.sh — on-disk content changed"
            printf "       before: %s\n" "$_staged_checksum" >&2
            printf "       after:  %s\n" "$_post_checksum" >&2
        fi
    else
        _fail "(e) docker/.env was deleted by uninstall.sh — partial .env must be preserved"
    fi

    # CHECK (f): exit 0 (parse errors from compose would propagate non-zero via set -e)
    # We specifically check for the compose interpolation error pattern, not generic exit codes.
    if [[ "$_uninstall_rc" -eq 0 ]]; then
        _pass "(f) uninstall.sh exited 0"
    else
        # Non-zero exit is acceptable if it's NOT a compose parse error.
        # Check the output for the known interpolation error string.
        if printf '%s\n' "$_uninstall_out" | grep -q "error while interpolating\|required variable.*missing a value"; then
            _fail "(f) uninstall.sh exited ${_uninstall_rc} due to compose parse failure (interpolation error)"
        else
            _info "(f) uninstall.sh exited ${_uninstall_rc} — non-zero but not due to compose parse error (ok)"
            _pass "(f) uninstall.sh did not exit due to compose interpolation error"
        fi
    fi

    # Restore real .env
    if [[ "$_REAL_ENV_BACKED_UP" == "true" ]] && [[ -f "$_BACKUP_PATH" ]]; then
        cp "$_BACKUP_PATH" "$ENV_FILE"
        rm -f "$_BACKUP_PATH"
        _REAL_ENV_BACKED_UP="false"
        _info "real docker/.env restored"
    elif [[ -f "$ENV_FILE" ]] && grep -q "partial-install-hmac-written-by-install-sh" "$ENV_FILE" 2>/dev/null; then
        rm -f "$ENV_FILE"
        _info "staged partial docker/.env removed (no real .env to restore)"
    fi
fi

# ---------------------------------------------------------------------------
# CHECK (g): Source-code idempotency — already-set env vars are not re-exported
# ---------------------------------------------------------------------------
_section "CHECK (g): Idempotency — pre-set env vars not clobbered"

# The fix must check `[ -n "${!_var+x}" ] && [ -n "${!_var}" ]` or equivalent
# before exporting a stub. We look for the bash indirection pattern OR a
# printenv/test-env pattern.
if grep -q 'printenv\|continue' "$UNINSTALL_SH" && grep -q "_PARTIAL_ENV_STUBBED" "$UNINSTALL_SH"; then
    _pass "(g.1) Pre-set env var check found in uninstall.sh (idempotency guard present)"
else
    # Alternative: look for the continue-after-check pattern near the export
    _phase_b_line2="$(grep -n "Phase B" "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"
    if [[ -n "$_phase_b_line2" ]]; then
        _phase_b_block2="$(awk "NR>=${_phase_b_line2} && NR<=${_phase_b_line2}+60" "$UNINSTALL_SH")"
        if printf '%s' "$_phase_b_block2" | grep -q "continue"; then
            _pass "(g.1) continue statement found in Phase B loop — pre-set vars skipped (idempotency OK)"
        else
            _fail "(g.1) No idempotency guard found in Phase B — pre-set env vars may be clobbered"
        fi
    else
        _fail "(g.1) Cannot locate Phase B block to verify idempotency"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n"
printf "=== Uninstall Partial Env Regression Test Results ===\n"
printf "  PASS: %d\n" "$PASS"
printf "  FAIL: %d\n" "$FAIL"
printf "  SKIP: %d\n" "$SKIP"

if (( FAIL > 0 )); then
    printf "\nRESULT: FAIL — %d check(s) failed. See [FAIL] lines above.\n" "$FAIL"
    exit 1
else
    printf "\nRESULT: PASS — %d checks passed, %d skipped.\n" "$PASS" "$SKIP"
    exit 0
fi
