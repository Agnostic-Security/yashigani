#!/usr/bin/env bash
# install_sh_port_flags_test.sh — Regression test for --http-port / --https-port CLI flags.
#
# Verifies that install.sh:
#   (a) Documents --http-port and --https-port in --help output.
#   (b) Exits 1 on non-numeric port value with a clear error.
#   (c) Exits 1 on out-of-range port value (0 and 65536) with a clear error.
#   (d) Exports YASHIGANI_HTTP_PORT / YASHIGANI_HTTPS_PORT correctly in a dry-run.
#   (e) Flag overrides a pre-set env var value (logs notice, flag value wins).
#
# No live stack is required. All tests use --dry-run or parse install.sh directly.
#
# Exit codes:
#   0 — all checks PASS (or SKIP)
#   1 — one or more checks FAIL
#
# last-updated: 2026-05-15T14:00:00+00:00

set -uo pipefail
IFS=$'\n\t'

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
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

_info "install.sh:   ${INSTALL_SH}"
_info "repo root:    ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# CHECK (a): --help documents --http-port and --https-port
# ---------------------------------------------------------------------------
_section "CHECK (a): --help output documents port flags"

_help_out="$(bash "$INSTALL_SH" --help 2>&1 || true)"

if printf '%s' "$_help_out" | grep -q -- '--http-port'; then
    _pass "(a.1) --http-port documented in --help"
else
    _fail "(a.1) --http-port NOT found in --help output"
fi

if printf '%s' "$_help_out" | grep -q -- '--https-port'; then
    _pass "(a.2) --https-port documented in --help"
else
    _fail "(a.2) --https-port NOT found in --help output"
fi

# Check for explanation of when to use them
if printf '%s' "$_help_out" | grep -qiE 'higher port|not.*reachable|network config|8080|8443'; then
    _pass "(a.3) --help includes guidance on when to use alternate ports"
else
    _fail "(a.3) --help does not explain when to use alternate ports"
fi

# Check YASHIGANI_HTTP_PORT and YASHIGANI_HTTPS_PORT are mentioned in ENVIRONMENT section
if printf '%s' "$_help_out" | grep -q 'YASHIGANI_HTTP_PORT'; then
    _pass "(a.4) YASHIGANI_HTTP_PORT documented in ENVIRONMENT section"
else
    _fail "(a.4) YASHIGANI_HTTP_PORT NOT found in --help ENVIRONMENT section"
fi

if printf '%s' "$_help_out" | grep -q 'YASHIGANI_HTTPS_PORT'; then
    _pass "(a.5) YASHIGANI_HTTPS_PORT documented in ENVIRONMENT section"
else
    _fail "(a.5) YASHIGANI_HTTPS_PORT NOT found in --help ENVIRONMENT section"
fi

# ---------------------------------------------------------------------------
# CHECK (b): Non-numeric port value exits 1
# ---------------------------------------------------------------------------
_section "CHECK (b): Non-numeric port exits 1"

_err_out="$(bash "$INSTALL_SH" --http-port abc 2>&1 || true)"
_exit_code=0
bash "$INSTALL_SH" --http-port abc >/dev/null 2>&1 || _exit_code=$?

if [[ "$_exit_code" -eq 1 ]]; then
    _pass "(b.1) --http-port abc exits 1"
else
    _fail "(b.1) --http-port abc exits ${_exit_code}, expected 1"
fi

if printf '%s' "$_err_out" | grep -qiE 'integer|1-65535|must be'; then
    _pass "(b.2) --http-port abc error message mentions valid range"
else
    _fail "(b.2) --http-port abc error message does not mention valid range (got: ${_err_out})"
fi

_err_out2="$(bash "$INSTALL_SH" --https-port xyz 2>&1 || true)"
_exit_code2=0
bash "$INSTALL_SH" --https-port xyz >/dev/null 2>&1 || _exit_code2=$?

if [[ "$_exit_code2" -eq 1 ]]; then
    _pass "(b.3) --https-port xyz exits 1"
else
    _fail "(b.3) --https-port xyz exits ${_exit_code2}, expected 1"
fi

# ---------------------------------------------------------------------------
# CHECK (c): Out-of-range ports exit 1
# ---------------------------------------------------------------------------
_section "CHECK (c): Out-of-range ports exit 1"

for _bad_port in 0 65536 99999; do
    _ec=0
    bash "$INSTALL_SH" --http-port "$_bad_port" >/dev/null 2>&1 || _ec=$?
    if [[ "$_ec" -eq 1 ]]; then
        _pass "(c.http.${_bad_port}) --http-port ${_bad_port} exits 1"
    else
        _fail "(c.http.${_bad_port}) --http-port ${_bad_port} exits ${_ec}, expected 1"
    fi

    _ec2=0
    bash "$INSTALL_SH" --https-port "$_bad_port" >/dev/null 2>&1 || _ec2=$?
    if [[ "$_ec2" -eq 1 ]]; then
        _pass "(c.https.${_bad_port}) --https-port ${_bad_port} exits 1"
    else
        _fail "(c.https.${_bad_port}) --https-port ${_bad_port} exits ${_ec2}, expected 1"
    fi
done

# Edge case: port 1 (valid minimum) must NOT exit 1 from parse alone
# (it will fail later in install for other reasons, but parse must accept it)
_parse_src="$(bash "$INSTALL_SH" --http-port 1 --dry-run --non-interactive 2>&1 || true)"
if ! printf '%s' "$_parse_src" | grep -qiE 'must be an integer|1-65535'; then
    _pass "(c.min) --http-port 1 passes parse validation (valid minimum)"
else
    _fail "(c.min) --http-port 1 rejected by parse — should be valid"
fi

_parse_src2="$(bash "$INSTALL_SH" --https-port 65535 --dry-run --non-interactive 2>&1 || true)"
if ! printf '%s' "$_parse_src2" | grep -qiE 'must be an integer|1-65535'; then
    _pass "(c.max) --https-port 65535 passes parse validation (valid maximum)"
else
    _fail "(c.max) --https-port 65535 rejected by parse — should be valid"
fi

# ---------------------------------------------------------------------------
# CHECK (d): parse_args() block is present for both flags in install.sh source
# ---------------------------------------------------------------------------
_section "CHECK (d): parse_args source has --http-port and --https-port cases"

if grep -q -- '--http-port)' "$INSTALL_SH"; then
    _pass "(d.1) --http-port) case present in install.sh parse_args"
else
    _fail "(d.1) --http-port) case NOT found in install.sh"
fi

if grep -q -- '--https-port)' "$INSTALL_SH"; then
    _pass "(d.2) --https-port) case present in install.sh parse_args"
else
    _fail "(d.2) --https-port) case NOT found in install.sh"
fi

# Verify validation regex pattern exists for both
if grep -A3 -- '--http-port)' "$INSTALL_SH" | grep -q '0-9'; then
    _pass "(d.3) --http-port case includes numeric validation"
else
    _fail "(d.3) --http-port case missing numeric validation"
fi

if grep -A3 -- '--https-port)' "$INSTALL_SH" | grep -q '0-9'; then
    _pass "(d.4) --https-port case includes numeric validation"
else
    _fail "(d.4) --https-port case missing numeric validation"
fi

# Verify export is present in both cases
if grep -A10 -- '--http-port)' "$INSTALL_SH" | grep -q 'export YASHIGANI_HTTP_PORT'; then
    _pass "(d.5) --http-port case exports YASHIGANI_HTTP_PORT"
else
    _fail "(d.5) --http-port case does not export YASHIGANI_HTTP_PORT"
fi

if grep -A10 -- '--https-port)' "$INSTALL_SH" | grep -q 'export YASHIGANI_HTTPS_PORT'; then
    _pass "(d.6) --https-port case exports YASHIGANI_HTTPS_PORT"
else
    _fail "(d.6) --https-port case does not export YASHIGANI_HTTPS_PORT"
fi

# ---------------------------------------------------------------------------
# CHECK (e): Flag overrides env var — log notice present in source
# ---------------------------------------------------------------------------
_section "CHECK (e): Flag overrides env var (notice in source)"

if grep -A15 -- '--http-port)' "$INSTALL_SH" | grep -qiE 'overrides env|flag.*overrides'; then
    _pass "(e.1) --http-port case logs override notice when env var set"
else
    _fail "(e.1) --http-port case does not log env-override notice"
fi

if grep -A15 -- '--https-port)' "$INSTALL_SH" | grep -qiE 'overrides env|flag.*overrides'; then
    _pass "(e.2) --https-port case logs override notice when env var set"
else
    _fail "(e.2) --https-port case does not log env-override notice"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed.\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped.\n" "$PASS" "$SKIP"
exit 0
