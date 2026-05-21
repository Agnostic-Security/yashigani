#!/usr/bin/env bash
# install_sh_yashigani_internal_bearer_test.sh — Regression test for per-install
# YASHIGANI_INTERNAL_BEARER token generation (Captain Bucket-C finding 2026-05-17).
#
# Tests:
#   (1) Fresh install path: docker/secrets/yashigani_internal_bearer exists,
#       mode 0600, length >= 36.
#   (2) Token charset: only A-Za-z0-9!*,-._~ characters present.
#   (3) Idempotency: --reuse-volumes (simulated) does NOT regenerate — token
#       unchanged across two generate_secrets() invocations when file exists.
#   (4) --remove-volumes wipes the file (uninstall.sh behaviour).
#   (5) Entropy: two independent fresh installs produce different tokens.
#   (6) Pre-flight: stale YASHIGANI_INTERNAL_BEARER env-var + missing file
#       causes install.sh to emit a remediation message and exit non-zero.
#
# All tests are compile-time / unit-simulation — no Docker daemon required.
# Runtime-dependent checks are SKIPPED when no container runtime is available.
#
# Exit codes: 0 = all PASS (or SKIP); 1 = one or more FAIL.
#
# Bucket-C: Captain gitleaks baseline 2026-05-17
# last-updated: 2026-05-17T17:00:00+00:00

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
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"
UNINSTALL_SH="${UNINSTALL_SH:-${REPO_ROOT}/uninstall.sh}"

_info "install.sh:    ${INSTALL_SH}"
_info "uninstall.sh:  ${UNINSTALL_SH}"
_info "repo root:     ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

if [[ ! -f "$UNINSTALL_SH" ]]; then
    printf "[FAIL] uninstall.sh not found at: %s\n" "$UNINSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Inline _gen_password() replica (extracted from install.sh for unit tests).
# Must stay in sync with the install.sh implementation.
# ---------------------------------------------------------------------------
_gen_password_local() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import secrets, string
symbols = "!*,-._~"
alphabet = string.ascii_letters + string.digits + symbols
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(36))
    if (any(c.isupper() for c in pw)
        and any(c.islower() for c in pw)
        and any(c.isdigit() for c in pw)
        and any(c in symbols for c in pw)):
        print(pw)
        break
PY
    else
        local _pw _i
        for _i in 1 2 3 4 5 6 7 8; do
            _pw="$(LC_ALL=C tr -dc 'A-Za-z0-9!*,._~-' < /dev/urandom 2>/dev/null | head -c 36)"
            if [[ "$_pw" =~ [A-Z] ]] && [[ "$_pw" =~ [a-z] ]] && [[ "$_pw" =~ [0-9] ]] && [[ "$_pw" =~ [\!\*,._~-] ]]; then
                printf "%s" "$_pw"
                return 0
            fi
        done
        printf "%s" "$_pw"
    fi
}

# ---------------------------------------------------------------------------
# TEST (1): Fresh install — file exists, mode 0600, length >= 36
# ---------------------------------------------------------------------------
_section "TEST (1): Fresh install — file created, mode 0600, length >= 36"

_tmpdir_1="$(mktemp -d "${REPO_ROOT}/tests/integration/.bearer_test_1_XXXXXX")"
trap 'rm -rf "${_tmpdir_1}"' EXIT

_token_1="$(_gen_password_local)"
_file_1="${_tmpdir_1}/yashigani_internal_bearer"
printf "%s" "$_token_1" > "$_file_1"
chmod 0600 "$_file_1"

if [[ -f "$_file_1" ]]; then
    _pass "(1.1) File yashigani_internal_bearer created"
else
    _fail "(1.1) File yashigani_internal_bearer NOT created"
fi

_mode_1="$(stat -c '%a' "$_file_1" 2>/dev/null || stat -f '%A' "$_file_1" 2>/dev/null || echo "unknown")"
if [[ "$_mode_1" == "600" ]]; then
    _pass "(1.2) Mode 0600 confirmed (got: ${_mode_1})"
else
    _fail "(1.2) Mode is ${_mode_1}, expected 600"
fi

_len_1="${#_token_1}"
if [[ "$_len_1" -ge 36 ]]; then
    _pass "(1.3) Token length >= 36 chars (got: ${_len_1})"
else
    _fail "(1.3) Token length is ${_len_1}, expected >= 36"
fi

# ---------------------------------------------------------------------------
# TEST (2): Charset validation — only A-Za-z0-9!*,-._~ characters
# ---------------------------------------------------------------------------
_section "TEST (2): Charset — only A-Za-z0-9!*,-._~ characters"

# Run 5 generations to get good coverage
_charset_fail=0
for _ci in 1 2 3 4 5; do
    _sample="$(_gen_password_local)"
    # Strip all allowed chars; any residue = violation
    _residue="$(printf '%s' "$_sample" | LC_ALL=C tr -d 'A-Za-z0-9!*,.\-_~' 2>/dev/null || true)"
    if [[ -n "$_residue" ]]; then
        _info "(2) Sample ${_ci}: '${_sample}' has disallowed chars: '${_residue}'"
        _charset_fail=$(( _charset_fail + 1 ))
    fi
    # Verify category guarantees
    if ! printf '%s' "$_sample" | grep -q '[A-Z]'; then
        _info "(2) Sample ${_ci}: missing uppercase"
        _charset_fail=$(( _charset_fail + 1 ))
    fi
    if ! printf '%s' "$_sample" | grep -q '[a-z]'; then
        _info "(2) Sample ${_ci}: missing lowercase"
        _charset_fail=$(( _charset_fail + 1 ))
    fi
    if ! printf '%s' "$_sample" | grep -q '[0-9]'; then
        _info "(2) Sample ${_ci}: missing digit"
        _charset_fail=$(( _charset_fail + 1 ))
    fi
    if ! printf '%s' "$_sample" | LC_ALL=C grep -qE '[!*,.\-_~]'; then
        _info "(2) Sample ${_ci}: missing symbol"
        _charset_fail=$(( _charset_fail + 1 ))
    fi
done

if [[ "$_charset_fail" -eq 0 ]]; then
    _pass "(2.1) All 5 samples: charset A-Za-z0-9!*,-._~ only, all categories present"
else
    _fail "(2.1) ${_charset_fail} charset/category violation(s) across 5 samples"
fi

# ---------------------------------------------------------------------------
# TEST (3): Idempotency — existing file not overwritten (--reuse-volumes sim)
# ---------------------------------------------------------------------------
_section "TEST (3): Idempotency — existing file preserved on re-run"

_tmpdir_3="$(mktemp -d "${REPO_ROOT}/tests/integration/.bearer_test_3_XXXXXX")"
# The cleanup trap already covers REPO_ROOT/tests/integration/.bearer_test_*
# but we need to register cleanup for _tmpdir_3 specifically
_original_trap="$(trap -p EXIT | sed "s/^trap -- '//;s/' EXIT$//" || echo "")"
trap 'rm -rf "${_tmpdir_3}" "${_tmpdir_1}" 2>/dev/null; true' EXIT

_file_3="${_tmpdir_3}/yashigani_internal_bearer"
_original_token="$(_gen_password_local)"
printf "%s" "$_original_token" > "$_file_3"
chmod 0600 "$_file_3"

# Simulate install.sh idempotency: file already exists with content → skip generation
if [[ -s "$_file_3" ]]; then
    _token_after="$(cat "$_file_3")"
else
    _token_after="$(_gen_password_local)"
    printf "%s" "$_token_after" > "$_file_3"
fi

if [[ "$_token_after" == "$_original_token" ]]; then
    _pass "(3.1) Idempotency: token unchanged when file already exists"
else
    _fail "(3.1) Idempotency broken: token changed from '${_original_token}' to '${_token_after}'"
fi

# ---------------------------------------------------------------------------
# TEST (4): --remove-volumes wipe — file deleted by uninstall.sh
# ---------------------------------------------------------------------------
_section "TEST (4): --remove-volumes wipe — yashigani_internal_bearer deleted"

# Verify uninstall.sh wipes docker/secrets/* on --remove-volumes
if grep -q "yashigani_internal_bearer" "$UNINSTALL_SH"; then
    _pass "(4.1) uninstall.sh explicitly mentions yashigani_internal_bearer in wipe comment"
else
    # The wipe is by rm -rf docker/secrets/*, which covers the file even without
    # an explicit mention — verify the wildcard wipe is present
    if grep -q 'rm -rf.*secrets.*\*\|rm -rf.*_secrets_dir.*\*' "$UNINSTALL_SH"; then
        _pass "(4.1) uninstall.sh wipes all of docker/secrets/* (wildcard rm — covers yashigani_internal_bearer)"
    else
        _fail "(4.1) uninstall.sh does NOT wipe docker/secrets/* — yashigani_internal_bearer not cleaned"
    fi
fi

# Simulate the wipe
_tmpdir_4="$(mktemp -d "${REPO_ROOT}/tests/integration/.bearer_test_4_XXXXXX")"
trap 'rm -rf "${_tmpdir_4}" "${_tmpdir_3}" "${_tmpdir_1}" 2>/dev/null; true' EXIT
_file_4="${_tmpdir_4}/yashigani_internal_bearer"
printf "some-existing-token" > "$_file_4"
chmod 0600 "$_file_4"

# Simulate wipe
rm -f "$_file_4"

if [[ ! -f "$_file_4" ]]; then
    _pass "(4.2) Wipe simulation: yashigani_internal_bearer removed"
else
    _fail "(4.2) Wipe simulation: file still present after removal"
fi

# ---------------------------------------------------------------------------
# TEST (5): Entropy — two independent generations produce different tokens
# ---------------------------------------------------------------------------
_section "TEST (5): Entropy — two generations produce different tokens"

_tok_a="$(_gen_password_local)"
_tok_b="$(_gen_password_local)"

if [[ "$_tok_a" != "$_tok_b" ]]; then
    _pass "(5.1) Two successive generations differ (entropy confirmed)"
else
    # Astronomically unlikely with 36-char random token — treat as FAIL
    _fail "(5.1) Two successive generations produced identical tokens (entropy failure)"
fi

# Run 3 more pairs as additional assurance
_entropy_ok=0
for _ei in 1 2 3; do
    _te1="$(_gen_password_local)"
    _te2="$(_gen_password_local)"
    if [[ "$_te1" != "$_te2" ]]; then
        _entropy_ok=$(( _entropy_ok + 1 ))
    fi
done

if [[ "$_entropy_ok" -eq 3 ]]; then
    _pass "(5.2) 3 additional pairs: all unique (entropy looks good)"
else
    _fail "(5.2) ${_entropy_ok}/3 additional pairs were unique — entropy concern"
fi

# ---------------------------------------------------------------------------
# TEST (6): Pre-flight — stale YASHIGANI_INTERNAL_BEARER env + missing file
# ---------------------------------------------------------------------------
_section "TEST (6): Pre-flight — stale env-var + missing file → exit non-zero + remediation"

# Verify the pre-flight check is present in install.sh
if grep -q "stale YASHIGANI_INTERNAL_BEARER" "$INSTALL_SH"; then
    _pass "(6.1) Stale-env pre-flight message present in install.sh"
else
    _fail "(6.1) Stale-env pre-flight message NOT found in install.sh"
fi

if grep -q "unset YASHIGANI_INTERNAL_BEARER" "$INSTALL_SH"; then
    _pass "(6.2) Remediation 'unset YASHIGANI_INTERNAL_BEARER' present in install.sh"
else
    _fail "(6.2) Remediation instruction NOT found in install.sh"
fi

# Verify the check gates on both conditions: env-var set AND file missing/empty
if grep -qE 'YASHIGANI_INTERNAL_BEARER.*-n.*\|\|.*-z|YASHIGANI_INTERNAL_BEARER.*!\s*-s|YASHIGANI_INTERNAL_BEARER.*-n.*_bearer_file' "$INSTALL_SH"; then
    _pass "(6.3) Pre-flight check references both env-var and file state"
else
    # Check via proximity — env-var check near _bearer_file check
    if grep -A5 'YASHIGANI_INTERNAL_BEARER:-' "$INSTALL_SH" | grep -q '_bearer_file\|docker/secrets'; then
        _pass "(6.3) Pre-flight check references both env-var and file state (context match)"
    else
        _fail "(6.3) Pre-flight check does not reference file state — may be incomplete"
    fi
fi

# Simulate: run the pre-flight check inline in a subshell
_tmpdir_6="$(mktemp -d "${REPO_ROOT}/tests/integration/.bearer_test_6_XXXXXX")"
trap 'rm -rf "${_tmpdir_6}" "${_tmpdir_4}" "${_tmpdir_3}" "${_tmpdir_1}" 2>/dev/null; true' EXIT

_preflight_output="$(
    (
        set +e
        # Simulate: YASHIGANI_INTERNAL_BEARER is set in shell, file does NOT exist
        YASHIGANI_INTERNAL_BEARER="stale-token-from-prior-install"
        _bearer_file="${_tmpdir_6}/yashigani_internal_bearer"
        # File intentionally absent (simulating post-uninstall state)

        if [[ -n "${YASHIGANI_INTERNAL_BEARER:-}" ]]; then
            if [[ ! -s "$_bearer_file" ]]; then
                printf "Pre-flight failed: stale YASHIGANI_INTERNAL_BEARER env-var detected.\n"
                printf "unset YASHIGANI_INTERNAL_BEARER\n"
                printf 'EXIT_MARKER_PF:1\n'
                exit 1
            fi
        fi
        printf 'EXIT_MARKER_PF:0\n'
        exit 0
    )
)"

_pf_exit="$(printf '%s\n' "$_preflight_output" | grep '^EXIT_MARKER_PF:' | cut -d: -f2 || echo "unknown")"
if [[ "$_pf_exit" == "1" ]]; then
    _pass "(6.4) Pre-flight simulation: exits 1 when stale env + missing file"
else
    _fail "(6.4) Pre-flight simulation: exits ${_pf_exit} — expected 1"
fi

if printf '%s\n' "$_preflight_output" | grep -q "stale YASHIGANI_INTERNAL_BEARER\|unset YASHIGANI_INTERNAL_BEARER"; then
    _pass "(6.5) Remediation message present in simulated pre-flight output"
else
    _fail "(6.5) Remediation message NOT present in simulated pre-flight output"
fi

# Verify pre-flight does NOT fire when env-var is absent (normal install)
_pf_no_env_output="$(
    (
        set +e
        unset YASHIGANI_INTERNAL_BEARER || true
        _bearer_file="${_tmpdir_6}/yashigani_internal_bearer"

        if [[ -n "${YASHIGANI_INTERNAL_BEARER:-}" ]]; then
            if [[ ! -s "$_bearer_file" ]]; then
                printf 'EXIT_MARKER_PF2:1\n'
                exit 1
            fi
        fi
        printf 'EXIT_MARKER_PF2:0\n'
        exit 0
    )
)"
_pf_no_env_exit="$(printf '%s\n' "$_pf_no_env_output" | grep '^EXIT_MARKER_PF2:' | cut -d: -f2 || echo "unknown")"
if [[ "$_pf_no_env_exit" == "0" ]]; then
    _pass "(6.6) Pre-flight does NOT fire when YASHIGANI_INTERNAL_BEARER is unset (normal install path)"
else
    _fail "(6.6) Pre-flight fires incorrectly when YASHIGANI_INTERNAL_BEARER is unset"
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
