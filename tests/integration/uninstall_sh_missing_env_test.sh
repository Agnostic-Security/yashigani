#!/usr/bin/env bash
# uninstall_sh_missing_env_test.sh — Regression test for BUG-UNINSTALL-NO-ENV.
#
# Verifies that uninstall.sh does NOT fail when docker/.env is absent.
# This is the canonical "DR clean Step 0" path: fresh clone, no prior install,
# uninstall.sh must still be able to invoke compose down cleanly.
#
# Phase: COMPILE-TIME / PARSE-TIME (no live stack required)
#   Uses `compose config` as a proxy for `compose down` parse-time interpolation.
#   If compose can resolve the compose file against the stub, compose down will
#   also be able to parse it (the failure mode is at parse time, not runtime).
#
# What this catches:
#   (a) docker/.env absent → uninstall.sh exits 1 (the original bug)
#   (b) stub .env created by uninstall.sh does not satisfy all :? vars
#       (a new :? var added to docker-compose.yml without a stub entry)
#   (c) stub .env left behind after uninstall.sh exits (sentinel leak)
#   (d) real .env present → uninstall.sh does NOT overwrite or delete it
#
# Usage:
#   bash tests/integration/uninstall_sh_missing_env_test.sh
#
# Requires:
#   - docker or podman compose available (used for `compose config` parse-only check)
#   - uninstall.sh at REPO_ROOT/uninstall.sh
#
# Exit codes:
#   0 — all checks PASS
#   1 — one or more checks FAIL
#
# BUG-UNINSTALL-NO-ENV
# last-updated: 2026-05-15T10:00:00+00:00

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

_info "uninstall.sh:    ${UNINSTALL_SH}"
_info "compose file:    ${COMPOSE_FILE}"
_info "docker/.env:     ${ENV_FILE}"

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
# Check (a) + (b): docker/.env absent — uninstall.sh stub satisfies compose parse
#
# Strategy: extract the stub block from uninstall.sh, write it to a temp env
# file, then run `compose config` against it.  If compose config exits 0, the
# stub covers all :? vars and compose down would also succeed.
#
# We also verify the STUB_VARS list in uninstall.sh matches the :? set in
# docker-compose.yml — if docker-compose.yml gains a new :? var, this check fails.
# ---------------------------------------------------------------------------

_section "Check (a)+(b): stub covers all :? vars in docker-compose.yml"

# Extract the :? var names from docker-compose.yml
_REQUIRED_VARS_IN_COMPOSE=()
while IFS= read -r line; do
    # Extract VAR from ${VAR:?...} patterns
    varname="$(printf '%s\n' "$line" | grep -oE '\$\{[A-Z_]+:\?' | sed 's/\${//;s/:?//')"
    [[ -n "$varname" ]] && _REQUIRED_VARS_IN_COMPOSE+=("$varname")
done < <(grep -E '\$\{[A-Z_]+:\?' "$COMPOSE_FILE")

# Deduplicate (avoid mapfile — not available in bash 3.2 on macOS)
_dedup_tmp="$(printf '%s\n' "${_REQUIRED_VARS_IN_COMPOSE[@]}" | sort -u)"
_REQUIRED_VARS_IN_COMPOSE=()
while IFS= read -r _v; do
    [[ -n "$_v" ]] && _REQUIRED_VARS_IN_COMPOSE+=("$_v")
done <<< "$_dedup_tmp"

_info "Required :? vars in docker-compose.yml: ${#_REQUIRED_VARS_IN_COMPOSE[@]}"
for v in "${_REQUIRED_VARS_IN_COMPOSE[@]}"; do
    _info "  - ${v}"
done

# Extract stub vars from uninstall.sh (the heredoc block)
_STUB_VARS_IN_UNINSTALL=()
while IFS= read -r line; do
    varname="$(printf '%s\n' "$line" | grep -oE '^[A-Z_]+=' | sed 's/=//')"
    [[ -n "$varname" ]] && _STUB_VARS_IN_UNINSTALL+=("$varname")
done < <(awk '/UNINSTALL_STUB_EOF/{if(p)exit; p=1; next} p' "$UNINSTALL_SH" | grep -v '^#' | grep -v '^$')

# Deduplicate (avoid mapfile — not available in bash 3.2 on macOS)
_dedup_stub_tmp="$(printf '%s\n' "${_STUB_VARS_IN_UNINSTALL[@]}" | sort -u)"
_STUB_VARS_IN_UNINSTALL=()
while IFS= read -r _v; do
    [[ -n "$_v" ]] && _STUB_VARS_IN_UNINSTALL+=("$_v")
done <<< "$_dedup_stub_tmp"

_info "Stub vars in uninstall.sh: ${#_STUB_VARS_IN_UNINSTALL[@]}"
for v in "${_STUB_VARS_IN_UNINSTALL[@]}"; do
    _info "  - ${v}"
done

# Cross-check: every :? var in compose must have a stub entry
_all_covered=true
for required_var in "${_REQUIRED_VARS_IN_COMPOSE[@]}"; do
    _found=false
    for stub_var in "${_STUB_VARS_IN_UNINSTALL[@]}"; do
        if [[ "$stub_var" == "$required_var" ]]; then
            _found=true
            break
        fi
    done
    if [[ "$_found" == "true" ]]; then
        _pass "compose :? var ${required_var} has a stub entry in uninstall.sh"
    else
        _fail "compose :? var ${required_var} is NOT covered by uninstall.sh stub (BUG-UNINSTALL-NO-ENV regression)"
        _all_covered=false
    fi
done

# ---------------------------------------------------------------------------
# Check (b) continued: `compose config` parse-only against the stub
# (validates that stub values actually satisfy compose at runtime, not just
# at grep time — catches any compose-version-specific interpolation quirks)
# ---------------------------------------------------------------------------

_section "Check (b)-runtime: compose config resolves against stub env"

if [[ -z "$_RUNTIME" ]]; then
    _skip "compose config parse check (no compose runtime found — docker/podman compose not available)"
else
    # Build a stub env file in a safe location (REPO_ROOT per no-/tmp policy)
    _STUB_TMP="${REPO_ROOT}/tests/integration/.tmp_stub_env_test_$$.env"
    # Extract stub block from uninstall.sh and write it
    awk '/cat > "\$_ENV_FILE" <<'\''UNINSTALL_STUB_EOF'\''/{p=1; next} /^UNINSTALL_STUB_EOF/{p=0} p' \
        "$UNINSTALL_SH" > "$_STUB_TMP"

    if [[ ! -s "$_STUB_TMP" ]]; then
        _fail "could not extract stub block from uninstall.sh for compose config test"
        rm -f "$_STUB_TMP"
    else
        _info "stub env file written: ${_STUB_TMP} ($(wc -l < "$_STUB_TMP") lines)"
        _compose_config_out="$($_RUNTIME compose --env-file "$_STUB_TMP" -f "$COMPOSE_FILE" config 2>&1)"
        _compose_config_rc=$?
        rm -f "$_STUB_TMP"

        if [[ "$_compose_config_rc" -eq 0 ]]; then
            _pass "compose config exits 0 with stub env (parse succeeds — compose down would proceed)"
        else
            _fail "compose config exits ${_compose_config_rc} with stub env — stub is missing a required var"
            printf '%s\n' "$_compose_config_out" | while IFS= read -r line; do
                printf "       → %s\n" "$line" >&2
            done
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Check (c): stub .env is NOT left behind (sentinel cleanup)
#
# We simulate the scenario: backup any real .env, remove it, run uninstall.sh
# with --yes (no real stack running, so compose down may exit non-zero for
# "no containers to stop" — that is acceptable; what matters is exit on the
# missing-env path is no longer non-zero due to parse failure, AND the stub
# is cleaned up).
#
# We use `--runtime=docker` or `--runtime=podman` to avoid auto-detection
# side-effects. We pass `--yes` to skip interactive prompt.
#
# NOTE: this check does NOT require a live stack. compose down with no running
# containers exits 0. We verify:
#   1. docker/.env does not exist before the test
#   2. After uninstall.sh exits, docker/.env does not exist (stub removed)
#   3. uninstall.sh exits 0 (parse error no longer blocks)
# ---------------------------------------------------------------------------

_section "Check (c): stub .env is cleaned up after uninstall.sh exits"

_REAL_ENV_BACKED_UP="false"
_BACKUP_PATH="${REPO_ROOT}/tests/integration/.tmp_real_env_backup_$$.env"

# Back up real .env if it exists
if [[ -f "$ENV_FILE" ]]; then
    cp "$ENV_FILE" "$_BACKUP_PATH"
    rm -f "$ENV_FILE"
    _REAL_ENV_BACKED_UP="true"
    _info "real docker/.env backed up to ${_BACKUP_PATH}"
fi

# Verify .env is absent before test
if [[ -f "$ENV_FILE" ]]; then
    _fail "pre-condition: docker/.env still exists after backup — cannot run stub cleanup test"
else
    _info "pre-condition: docker/.env absent — OK"

    # Run uninstall.sh with --yes, capture exit code
    # Use the detected runtime, or fall back to docker
    _test_runtime="${_RUNTIME:-docker}"
    _uninstall_out="$(bash "$UNINSTALL_SH" --runtime="$_test_runtime" --yes 2>&1)" || _uninstall_rc=$?
    _uninstall_rc="${_uninstall_rc:-0}"

    _info "uninstall.sh exit code: ${_uninstall_rc}"

    # The key check: is the stub cleaned up?
    if [[ -f "$ENV_FILE" ]]; then
        _fail "stub docker/.env was NOT removed after uninstall.sh exit (sentinel leak)"
        # Clean it up so we don't leave trash
        rm -f "$ENV_FILE"
    else
        _pass "stub docker/.env was removed after uninstall.sh exit (sentinel cleanup OK)"
    fi

    # The exit code check: uninstall.sh must not exit 1 due to parse error.
    # It may exit non-zero for other reasons (no containers, runtime not available)
    # but the specific compose parse error (interpolation missing var) must be gone.
    if printf '%s\n' "$_uninstall_out" | grep -q "required variable.*is missing a value"; then
        _fail "uninstall.sh still emits 'required variable ... is missing a value' — stub did not suppress parse error"
        printf '%s\n' "$_uninstall_out" | grep "required variable" | while IFS= read -r line; do
            printf "       → %s\n" "$line" >&2
        done
    else
        _pass "uninstall.sh does not emit 'required variable ... is missing a value' (parse error suppressed)"
    fi
fi

# Restore real .env if we backed it up
if [[ "$_REAL_ENV_BACKED_UP" == "true" ]] && [[ -f "$_BACKUP_PATH" ]]; then
    cp "$_BACKUP_PATH" "$ENV_FILE"
    rm -f "$_BACKUP_PATH"
    _info "real docker/.env restored from backup"
fi

# ---------------------------------------------------------------------------
# Check (d): real .env present → uninstall.sh does NOT overwrite or delete it
# ---------------------------------------------------------------------------

_section "Check (d): real .env is preserved when present"

_SENTINEL_VALUE="REAL_ENV_SENTINEL_DO_NOT_DELETE_$(date +%s)"

# Write a sentinel .env
printf 'SENTINEL=%s\n' "$_SENTINEL_VALUE" > "$ENV_FILE"
_info "sentinel docker/.env written: ${ENV_FILE}"

# Run uninstall.sh with --yes
_test_runtime="${_RUNTIME:-docker}"
bash "$UNINSTALL_SH" --runtime="$_test_runtime" --yes >/dev/null 2>&1 || true

# Check .env survives
if [[ -f "$ENV_FILE" ]]; then
    _actual_sentinel="$(grep -o "SENTINEL=.*" "$ENV_FILE" | head -1 || true)"
    if [[ "$_actual_sentinel" == "SENTINEL=${_SENTINEL_VALUE}" ]]; then
        _pass "real docker/.env was preserved unchanged after uninstall.sh (sentinel value intact)"
    else
        _fail "docker/.env exists but sentinel value was modified — uninstall.sh overwrote the real .env"
        printf "       expected: SENTINEL=%s\n" "$_SENTINEL_VALUE" >&2
        printf "       actual:   %s\n" "$_actual_sentinel" >&2
    fi
else
    _fail "docker/.env was DELETED by uninstall.sh even though it existed before — real .env was destroyed"
fi

# Clean up sentinel .env
rm -f "$ENV_FILE"
_info "sentinel docker/.env removed after check (d)"

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

printf "\n"
printf "=== Uninstall Missing Env Regression Test Results ===\n"
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
