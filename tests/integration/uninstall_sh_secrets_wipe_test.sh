#!/usr/bin/env bash
# uninstall_sh_secrets_wipe_test.sh — Regression test for BUG-3-MULTI-USER-INSTALL-PKI.
#
# Verifies that uninstall.sh --remove-volumes wipes docker/secrets/* and that
# the path-validation guard prevents accidental rm of unrelated directories.
#
# Scenarios:
#   (a) Source-code presence check: wipe block exists in uninstall.sh.
#   (b) Source-code safety check: path-validation guard present before rm.
#   (c) Populated secrets dir + --remove-volumes → directory empty after.
#       (Requires write access to SCRIPT_DIR/docker/secrets — live test, skipped
#       if not running as root or if SCRIPT_DIR is not writable.)
#   (d) Populated secrets dir + no flag → preserved.
#   (e) Missing secrets dir + --remove-volumes → no error.
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# BUG-3-MULTI-USER-INSTALL-PKI
# last-updated: 2026-05-15T20:50:00+00:00 (fix: replace /tmp/ with REPO_ROOT-relative paths — V232-NEG04)

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
UNINSTALL_SH="${UNINSTALL_SH:-${REPO_ROOT}/uninstall.sh}"

_info "uninstall.sh: ${UNINSTALL_SH}"
_info "repo root:    ${REPO_ROOT}"

if [[ ! -f "$UNINSTALL_SH" ]]; then
    printf "[FAIL] uninstall.sh not found at: %s\n" "$UNINSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# CHECK (a): BUG-3-MULTI-USER-INSTALL-PKI block is present in uninstall.sh
# ---------------------------------------------------------------------------
_section "CHECK (a): BUG-3-MULTI-USER-INSTALL-PKI block present"

if grep -q "BUG-3-MULTI-USER-INSTALL-PKI" "$UNINSTALL_SH"; then
    _pass "(a.1) BUG-3-MULTI-USER-INSTALL-PKI marker present in uninstall.sh"
else
    _fail "(a.1) BUG-3-MULTI-USER-INSTALL-PKI marker NOT found in uninstall.sh"
fi

if grep -q 'sudo rm -rf' "$UNINSTALL_SH"; then
    _pass "(a.2) sudo rm -rf call present (handles cross-user ownership)"
else
    _fail "(a.2) sudo rm -rf NOT found — cross-user ownership bug not fixed"
fi

if grep -q 'docker/secrets' "$UNINSTALL_SH"; then
    _pass "(a.3) docker/secrets path referenced in uninstall.sh"
else
    _fail "(a.3) docker/secrets NOT referenced in uninstall.sh"
fi

# ---------------------------------------------------------------------------
# CHECK (b): Path-validation guard is present BEFORE the rm
# ---------------------------------------------------------------------------
_section "CHECK (b): Path-validation guard present before secrets rm"

if grep -q '_secrets_dir.*!=.*SCRIPT_DIR' "$UNINSTALL_SH" || \
   grep -q '"${_secrets_dir}" != "${SCRIPT_DIR}/docker/secrets"' "$UNINSTALL_SH"; then
    _pass "(b.1) Path-validation guard found in uninstall.sh"
else
    _fail "(b.1) Path-validation guard NOT found — unsafe to remove arbitrary paths"
fi

# Verify: path-validation guard appears BEFORE the sudo rm -rf line
_guard_line="$(grep -n '_secrets_dir.*!=\|"${_secrets_dir}" != "${SCRIPT_DIR}' "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"
_rm_line="$(grep -n 'sudo rm -rf.*secrets' "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"

if [[ -n "$_guard_line" && -n "$_rm_line" ]]; then
    if [[ "$_guard_line" -lt "$_rm_line" ]]; then
        _pass "(b.2) Path-validation guard (line ${_guard_line}) is BEFORE sudo rm (line ${_rm_line})"
    else
        _fail "(b.2) Path-validation guard (line ${_guard_line}) is AFTER sudo rm (line ${_rm_line}) — wrong order"
    fi
else
    _fail "(b.2) Could not locate guard + rm lines (guard=${_guard_line:-MISSING}, rm=${_rm_line:-MISSING})"
fi

# Verify: secrets wipe block lives inside the REMOVE_VOLUMES = true conditional block.
# The block starts with 'if [ "$REMOVE_VOLUMES" = "true" ]' and the rm is inside it.
# We check that BUG-3-MULTI-USER-INSTALL-PKI appears within that block by confirming
# the REMOVE_VOLUMES gate appears before the rm line in the file.
_rv_gate_line="$(grep -n 'REMOVE_VOLUMES.*true\|remove_volumes.*true' "$UNINSTALL_SH" | \
    awk -F: -v rm_line="$_rm_line" '$1 < rm_line {last=$1} END {print last}' || true)"
if [[ -n "$_rv_gate_line" && -n "$_rm_line" && "$_rv_gate_line" -lt "$_rm_line" ]]; then
    _pass "(b.3) sudo rm secrets gated on REMOVE_VOLUMES check (gate line ${_rv_gate_line}, rm line ${_rm_line})"
else
    _fail "(b.3) Could not confirm REMOVE_VOLUMES gate before sudo rm secrets (gate=${_rv_gate_line:-MISSING}, rm=${_rm_line:-MISSING})"
fi

# ---------------------------------------------------------------------------
# CHECK (c)/(d)/(e): Live tests — require write access + sudo
# ---------------------------------------------------------------------------
_OS="$(uname -s)"
_IS_LINUX=false
_IS_ROOT=false
[[ "$_OS" == "Linux" ]] && _IS_LINUX=true
[[ "$(id -u)" == "0" ]] && _IS_ROOT=true

_LIVE_ELIGIBLE=false
if [[ "$_IS_LINUX" == "true" && "$_IS_ROOT" == "true" ]]; then
    _LIVE_ELIGIBLE=true
fi

_section "CHECK (c): --remove-volumes wipes docker/secrets contents"
if [[ "$_LIVE_ELIGIBLE" != "true" ]]; then
    if [[ "$_IS_LINUX" != "true" ]]; then
        _skip "(c) Live test skipped: not Linux"
    else
        _skip "(c) Live test skipped: not running as root (sudo rm requires root)"
    fi
else
    # Create a temporary test clone directory to run uninstall.sh against.
    # Use REPO_ROOT-relative path per no-/tmp policy (V232-NEG04).
    _TEST_DIR="$(mktemp -d "${REPO_ROOT}/tests/integration/.tmp_secrets_wipe_c_XXXXXX")"
    _cleanup_c() { rm -rf "$_TEST_DIR"; }
    trap '_cleanup_c' EXIT

    # Minimal directory structure needed by uninstall.sh
    mkdir -p "${_TEST_DIR}/docker/secrets"
    mkdir -p "${_TEST_DIR}/docker"

    # Create a stub docker-compose.yml + stub .env so compose down doesn't fail
    cp "${REPO_ROOT}/docker/docker-compose.yml" "${_TEST_DIR}/docker/docker-compose.yml" 2>/dev/null || \
        echo "version: '3'" > "${_TEST_DIR}/docker/docker-compose.yml"
    cat > "${_TEST_DIR}/docker/.env" <<'STUBEOF'
YASHIGANI_TLS_DOMAIN=test.local
PROMETHEUS_BASICAUTH_HASH=stub
CADDY_INTERNAL_HMAC=stub
UPSTREAM_MCP_URL=http://stub:9999
OWUI_SECRET_KEY=stub
YASHIGANI_DB_AES_KEY=stub
STUBEOF

    # Populate secrets dir with test files
    echo "fake-ca-key" > "${_TEST_DIR}/docker/secrets/ca.key"
    echo "fake-ca-cert" > "${_TEST_DIR}/docker/secrets/ca.crt"
    echo "fake-admin-pass" > "${_TEST_DIR}/docker/secrets/admin1_password"
    _info "(c) Created test secrets: $(ls "${_TEST_DIR}/docker/secrets/" | tr '\n' ' ')"

    # Run uninstall.sh from the test directory with --remove-volumes --yes
    # We pass --runtime=docker to avoid container ops (we just want the secrets path)
    # The compose down will likely fail silently (no real stack) but that's OK —
    # we only care about the secrets wipe logic.
    SCRIPT_DIR_ORIG="${SCRIPT_DIR}"
    _UNINSTALL_EXIT=0
    UNINSTALL_SH_COPY="${_TEST_DIR}/uninstall.sh"
    cp "$UNINSTALL_SH" "$UNINSTALL_SH_COPY"
    chmod +x "$UNINSTALL_SH_COPY"

    # Run with SCRIPT_DIR override via symlink trick:
    # uninstall.sh resolves SCRIPT_DIR from ${BASH_SOURCE[0]} location, so
    # running the copy from _TEST_DIR sets SCRIPT_DIR=_TEST_DIR correctly.
    bash "$UNINSTALL_SH_COPY" --remove-volumes --yes --runtime=docker 2>/dev/null || _UNINSTALL_EXIT=$?
    _info "(c) uninstall.sh exit code: ${_UNINSTALL_EXIT}"

    # Check secrets dir is empty (directory itself preserved)
    if [[ -d "${_TEST_DIR}/docker/secrets" ]]; then
        _pass "(c.1) docker/secrets/ directory preserved after --remove-volumes"
    else
        _fail "(c.1) docker/secrets/ directory was removed entirely (should be preserved)"
    fi

    _remaining="$(ls -A "${_TEST_DIR}/docker/secrets/" 2>/dev/null || echo 'MISSING')"
    if [[ -z "$_remaining" ]]; then
        _pass "(c.2) docker/secrets/ is empty after --remove-volumes"
    else
        _fail "(c.2) docker/secrets/ still has contents after --remove-volumes: ${_remaining}"
    fi
fi

_section "CHECK (d): No --remove-volumes → secrets preserved"
if [[ "$_LIVE_ELIGIBLE" != "true" ]]; then
    # Fall back to source-code check: wipe block is gated on REMOVE_VOLUMES
    if grep -q 'REMOVE_VOLUMES.*true' "$UNINSTALL_SH" && grep -q 'sudo rm -rf.*secrets' "$UNINSTALL_SH"; then
        _pass "(d.1) Wipe block gated on REMOVE_VOLUMES (source check — live skipped)"
    else
        _fail "(d.1) Cannot confirm wipe is gated on REMOVE_VOLUMES"
    fi
else
    # Use REPO_ROOT-relative path per no-/tmp policy (V232-NEG04).
    _TEST_DIR2="$(mktemp -d "${REPO_ROOT}/tests/integration/.tmp_secrets_wipe_d_XXXXXX")"
    _cleanup_d() { rm -rf "$_TEST_DIR2"; }
    trap '_cleanup_d' EXIT

    mkdir -p "${_TEST_DIR2}/docker/secrets"
    echo "fake-key" > "${_TEST_DIR2}/docker/secrets/test.key"
    cat > "${_TEST_DIR2}/docker/.env" <<'STUBEOF'
YASHIGANI_TLS_DOMAIN=test.local
PROMETHEUS_BASICAUTH_HASH=stub
CADDY_INTERNAL_HMAC=stub
UPSTREAM_MCP_URL=http://stub:9999
OWUI_SECRET_KEY=stub
YASHIGANI_DB_AES_KEY=stub
STUBEOF
    cp "$UNINSTALL_SH" "${_TEST_DIR2}/uninstall.sh"
    chmod +x "${_TEST_DIR2}/uninstall.sh"

    bash "${_TEST_DIR2}/uninstall.sh" --yes --runtime=docker 2>/dev/null || true

    _still_there="${_TEST_DIR2}/docker/secrets/test.key"
    if [[ -f "$_still_there" ]]; then
        _pass "(d.1) docker/secrets/test.key preserved when --remove-volumes not passed"
    else
        _fail "(d.1) docker/secrets/test.key was removed without --remove-volumes"
    fi
fi

_section "CHECK (e): Missing docker/secrets/ + --remove-volumes → no error"
# Source-code check: the block must handle missing directory gracefully.
# The wipe block starts with the comment '# BUG-3-MULTI-USER-INSTALL-PKI: wipe'
# (distinct from the header line which references the bug tag differently).
# We look for the LAST occurrence so the header match is skipped.
_wipe_block_start="$(grep -n '# BUG-3-MULTI-USER-INSTALL-PKI: wipe\|_secrets_dir=.*docker/secrets' "$UNINSTALL_SH" | head -1 | cut -d: -f1 || true)"
if [[ -n "$_wipe_block_start" ]]; then
    _wipe_block="$(awk "NR>=${_wipe_block_start} && NR<=${_wipe_block_start}+35" "$UNINSTALL_SH")"
    if printf '%s' "$_wipe_block" | grep -q '! -d\|does not exist\|not exist\|elif'; then
        _pass "(e.1) Missing secrets dir handled gracefully in source"
    else
        _fail "(e.1) Missing secrets dir guard NOT found in wipe block (lines ${_wipe_block_start}-$((_wipe_block_start+35)))"
    fi
else
    _fail "(e.1) Could not locate wipe block start in uninstall.sh"
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
