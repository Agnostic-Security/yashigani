#!/usr/bin/env bash
# tests/install/test_agent_reg_service_account.sh
# Regression test for ISSUE-AGENT-REG-STALE-PW (Iris, 2026-06-10).
#
# Bug: register_agent_bundles() authenticated as the human admin1 using
#      docker/secrets/admin1_password. After the human's FORCED first-login
#      password rotation (an intentional ASVS control), admin1_password on disk
#      is stale (the new hash lands in Postgres only, never back to disk). Any
#      post-rotation re-run — notably the Redis-durability agent re-registration
#      after a redis recreate wipes the agent registry — then authenticated with
#      a dead password and broke.
#
# Fix (option a): a dedicated NON-INTERACTIVE install-path service account
#      (svc_admin_*) seeded with force_password_change=false /
#      force_totp_provision=false, whose on-disk credential is never rotated by a
#      human. register_agent_bundles() authenticates as this account instead.
#      The human's forced first-login rotation is UNCHANGED.
#
# These are STATIC source checks — no running stack / Docker daemon required.
# They re-fail on the original bug (admin1_password in the auth block; no
# service account seeded; seed gated behind the first-boot guard).
#
# last-updated: 2026-06-10T00:00:00+01:00

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"
APP_PY="${REPO_ROOT}/src/yashigani/backoffice/app.py"
PG_AUTH_PY="${REPO_ROOT}/src/yashigani/auth/pg_auth.py"

for _f in "$INSTALL_SH" "$APP_PY" "$PG_AUTH_PY"; do
    if [[ ! -f "$_f" ]]; then
        printf "[FAIL] required file not found: %s\n" "$_f" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
_section "TEST 1: install.sh generates svc_admin_* secrets via CSPRNG helpers"
# ---------------------------------------------------------------------------
if grep -q 'GEN_SVC_ADMIN_PASSWORD="\$(_gen_password)"' "$INSTALL_SH" \
   && grep -q 'svc_admin_password' "$INSTALL_SH" \
   && grep -q 'svc_admin_username' "$INSTALL_SH" \
   && grep -q 'GEN_SVC_ADMIN_TOTP_SECRET="\$(_gen_totp_secret)"' "$INSTALL_SH"; then
    _pass "(1) install.sh generates svc_admin_{username,password,totp_secret} via _gen_password/_gen_totp_secret"
else
    _fail "(1) install.sh does NOT generate svc_admin_* secrets via the CSPRNG helpers"
fi

# ---------------------------------------------------------------------------
_section "TEST 2: register_agent_bundles authenticates as svc_admin_*, not admin1"
# ---------------------------------------------------------------------------
# The auth block must read svc_admin_* as the PRIMARY credential.
if grep -q 'user = read_secret("svc_admin_username")' "$INSTALL_SH" \
   && grep -q 'pw = read_secret("svc_admin_password")' "$INSTALL_SH" \
   && grep -q 'totp_secret = read_secret("svc_admin_totp_secret")' "$INSTALL_SH"; then
    _pass "(2) register_agent_bundles reads svc_admin_* as the primary auth credential"
else
    _fail "(2) register_agent_bundles does NOT read svc_admin_* — original stale-admin1 bug present"
fi

# ---------------------------------------------------------------------------
_section "TEST 3: service account seeded with force_password_change=False"
# ---------------------------------------------------------------------------
# The seed must pass force_password_change=False AND force_totp_provision=False
# so the credential is never subject to human rotation.
# Isolate the create_admin(...) call inside _bootstrap_service_account and assert
# both no-rotate kwargs are passed there.
_svc_create_block="$(awk '
    /^async def _bootstrap_service_account/{f=1}
    f && /await auth_service\.create_admin\(/{c=1}
    c{print}
    c && /\)$/{exit}
' "$APP_PY")"
if echo "$_svc_create_block" | grep -q 'force_password_change=False' \
   && echo "$_svc_create_block" | grep -q 'force_totp_provision=False'; then
    _pass "(3) service account seeded force_password_change=False / force_totp_provision=False"
else
    _fail "(3) service account seed missing the no-rotate flags"
fi

# ---------------------------------------------------------------------------
_section "TEST 4: service-account seed is guard-INDEPENDENT (runs on existing stacks)"
# ---------------------------------------------------------------------------
# _bootstrap_service_account must be invoked BEFORE the total_admin_count()!=0
# early-return, so it seeds on existing/upgraded stacks too (the re-registration
# scenario this fix targets). If it sits after the guard it never runs on an
# existing deployment.
_svc_call_line="$(grep -n 'await _bootstrap_service_account' "$APP_PY" | head -1 | cut -d: -f1)"
_guard_line="$(grep -n 'total_admin_count() != 0' "$APP_PY" | head -1 | cut -d: -f1)"
if [[ -n "$_svc_call_line" && -n "$_guard_line" && "$_svc_call_line" -lt "$_guard_line" ]]; then
    _pass "(4) _bootstrap_service_account runs before the total_admin_count guard (line $_svc_call_line < $_guard_line)"
else
    _fail "(4) service-account seed is gated behind the first-boot guard — never runs on existing stacks"
fi

# ---------------------------------------------------------------------------
_section "TEST 5: human forced first-login rotation is UNCHANGED (control preserved)"
# ---------------------------------------------------------------------------
# create_admin defaults must remain force_password_change=True so admin1 still
# rotates. The fix must NOT have flipped the default.
if grep -q 'force_password_change: bool = True' "$PG_AUTH_PY" \
   && grep -q 'force_totp_provision: bool = True' "$PG_AUTH_PY"; then
    _pass "(5) create_admin still defaults to forced rotation + TOTP provision (human control intact)"
else
    _fail "(5) create_admin default rotation control weakened — REGRESSION"
fi

# ---------------------------------------------------------------------------
_section "TEST 6: svc_admin_* are 0600 (NOT in restore.sh public-0644 list)"
# ---------------------------------------------------------------------------
# CWE-732 / S1: the service account is a live admin credential — it must never be
# widened to world-readable. Assert it is absent from restore.sh's _public_secrets
# 0644 loop.
RESTORE_SH="${REPO_ROOT}/restore.sh"
if [[ -f "$RESTORE_SH" ]]; then
    if awk '/_public_secrets=\(/{f=1} f{print} /^  \)/{f=0}' "$RESTORE_SH" \
         | grep -q 'svc_admin'; then
        _fail "(6) CWE-732: svc_admin_* present in restore.sh 0644 public list — would world-read a live credential"
    else
        _pass "(6) svc_admin_* absent from restore.sh public-0644 list (stays 0600)"
    fi
else
    _pass "(6) restore.sh not present — skip (no public-list to violate)"
fi

# ---------------------------------------------------------------------------
_section "TEST 7: UPGRADE PATH — svc_admin_* backfill creates all three + idempotent"
# ---------------------------------------------------------------------------
# BLOCKER (Iris, 2026-06-10): generate_secrets() short-circuits the upgrade case
# (postgres_password + redis_password already exist) and RETURNs before the
# fresh-install svc_admin_* block. Without an upgrade backfill, an already-rotated
# stack never gets svc_admin_* → register_agent_bundles() falls back to the stale
# admin1 password (ISSUE-AGENT-REG-STALE-PW).
#
# This test exercises the REAL backfill region extracted verbatim from install.sh
# between its BEGIN/END markers (not a copy), against a sandbox secrets dir that
# mimics an upgraded stack (postgres+redis present, svc_admin_* absent). It then
# re-runs the same region to prove idempotency (no rotation of existing secrets).

# 7a: the backfill region must exist between the documented markers.
_BACKFILL_BEGIN='# BEGIN ISSUE-AGENT-REG-STALE-PW-UPGRADE-BACKFILL'
_BACKFILL_END='# END ISSUE-AGENT-REG-STALE-PW-UPGRADE-BACKFILL'
_backfill_region="$(awk -v b="$_BACKFILL_BEGIN" -v e="$_BACKFILL_END" '
    index($0,b){f=1; next}
    index($0,e){f=0}
    f{print}
' "$INSTALL_SH")"
if [[ -z "$_backfill_region" ]]; then
    _fail "(7a) upgrade-path svc_admin_* backfill region not found in install.sh — BLOCKER unfixed"
else
    _pass "(7a) upgrade-path svc_admin_* backfill region present in install.sh"

    # 7b: extract the two real CSPRNG helpers so the region runs unmodified.
    _gen_pw_fn="$(awk '/^_gen_password\(\) \{/{f=1} f{print} f&&/^\}/{exit}'   "$INSTALL_SH")"
    _gen_totp_fn="$(awk '/^_gen_totp_secret\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$INSTALL_SH")"

    # Sandbox under a caller-provided scratch root (never /tmp, never inside the
    # repo — directory-structure rule). Defaults to the durable testing_runs tree.
    _scratch_root="${TEST_SCRATCH_DIR:-${HOME}/Documents/Claude/testing_runs/yashigani/.test-scratch}"
    mkdir -p "$_scratch_root"
    _sbx="$(mktemp -d "${_scratch_root}/svc_admin_upgrade.XXXXXX")"
    mkdir -p "${_sbx}/docker/secrets"
    # Mimic an upgraded, already-rotated stack: core secrets present, svc absent.
    printf 'pg-existing'    > "${_sbx}/docker/secrets/postgres_password"
    printf 'redis-existing' > "${_sbx}/docker/secrets/redis_password"

    # Run the REAL region in a subshell with the real helpers + stubs.
    # The region uses `local` declarations, so it must execute inside a function;
    # `secrets_dir` is the loop-local the region references (set as it is in
    # generate_secrets). WORK_DIR unused by the region but defined for safety.
    #
    # _do_chown is STUBBED to record every invocation (uid<TAB>file) to a record
    # file. The stub also performs the real chmod-equivalent ownership intent by
    # logging only — it does NOT actually chown (the harness is unprivileged and
    # cannot chown to UID 1001). TEST 8 reads this record to assert the backfill
    # invokes _do_chown 1001 for each svc file — a behavioural assertion that
    # re-fails if the chown is dropped (ISSUE-AGENT-REG-STALE-PW regression).
    _chown_record="${_sbx}/_do_chown.record"
    : > "$_chown_record"
    _run_backfill() {
        bash -c '
            set -uo pipefail
            log_info() { :; }
            _do_chown() { printf "%s\t%s\n" "$1" "$2" >> "'"$_chown_record"'"; return 0; }
            '"$_gen_pw_fn"'
            '"$_gen_totp_fn"'
            _exercise_region() {
                local secrets_dir="'"${_sbx}/docker/secrets"'"
                local WORK_DIR="'"${_sbx}"'"
                '"$_backfill_region"'
            }
            _exercise_region
        '
    }

    _run_backfill
    _bf_rc=$?

    _all_present=1
    for _sf in svc_admin_username svc_admin_password svc_admin_totp_secret; do
        [[ -s "${_sbx}/docker/secrets/${_sf}" ]] || _all_present=0
    done
    # mode check (portable: GNU stat here; format is %a)
    _all_0600=1
    for _sf in svc_admin_username svc_admin_password svc_admin_totp_secret; do
        _m="$(stat -c '%a' "${_sbx}/docker/secrets/${_sf}" 2>/dev/null || echo '???')"
        [[ "$_m" == "600" ]] || _all_0600=0
    done
    if [[ "$_bf_rc" -eq 0 && "$_all_present" -eq 1 && "$_all_0600" -eq 1 ]]; then
        _pass "(7b) upgrade backfill created svc_admin_{username,password,totp_secret} at 0600"
    else
        _fail "(7b) upgrade backfill did NOT create all three svc_admin_* at 0600 (rc=$_bf_rc present=$_all_present mode0600=$_all_0600)"
    fi

    # 7c: idempotency — capture values, re-run, prove no rotation.
    _u1="$(cat "${_sbx}/docker/secrets/svc_admin_username")"
    _p1="$(cat "${_sbx}/docker/secrets/svc_admin_password")"
    _t1="$(cat "${_sbx}/docker/secrets/svc_admin_totp_secret")"
    _run_backfill
    _u2="$(cat "${_sbx}/docker/secrets/svc_admin_username")"
    _p2="$(cat "${_sbx}/docker/secrets/svc_admin_password")"
    _t2="$(cat "${_sbx}/docker/secrets/svc_admin_totp_secret")"
    if [[ "$_u1" == "$_u2" && "$_p1" == "$_p2" && "$_t1" == "$_t2" ]]; then
        _pass "(7c) upgrade backfill is idempotent — existing svc_admin_* preserved (no rotation)"
    else
        _fail "(7c) upgrade backfill ROTATED an existing svc_admin_* secret on re-run — not idempotent"
    fi

    # 7d: username parity with the fresh-install value (install_svc).
    if [[ "$_u1" == "install_svc" ]]; then
        _pass "(7d) upgrade svc_admin_username == 'install_svc' (parity with fresh-install identity)"
    else
        _fail "(7d) upgrade svc_admin_username='$_u1' != 'install_svc' — identity drift from fresh case"
    fi

    # -----------------------------------------------------------------------
    _section "TEST 8: UPGRADE PATH — backfill chowns each svc_admin_* to UID 1001"
    # -----------------------------------------------------------------------
    # BLOCKER (Iris re-gate, 2026-06-10): on the DOMINANT Docker-rootful upgrade
    # (certs current → bootstrap_internal_pki no-rotation branch), the upgrade
    # no-touch rule SKIPS _pki_chown_client_keys, so the _uid1001_secrets set
    # never runs. If the backfill only chmod-600s (no chown), the svc_admin_*
    # files stay root:root → backoffice (UID 1001, cap_drop:[ALL], no
    # DAC_OVERRIDE) EACCESes → _bootstrap_service_account early-returns →
    # register_agent_bundles() falls back to the stale admin1 password = the
    # exact ISSUE-AGENT-REG-STALE-PW bug reproduced on the no-rotation path.
    #
    # The fix is to chown each svc file to UID 1001 at creation time in the
    # backfill itself (mirroring the pgbouncer backfill), so fresh and upgrade
    # converge to UID 1001 0600 independently of whether the PKI chown runs.
    #
    # The harness is unprivileged and cannot observe real ownership, so this is
    # a BEHAVIOURAL assertion: _do_chown was stubbed (above) to record every
    # (uid, file) it was called with during the FIRST backfill run. Assert that
    # each of the three svc files was chowned with uid field "1001" (uid or
    # uid:gid form — match the leading "1001" with an exact boundary).
    _chown_ok=1
    for _sf in svc_admin_username svc_admin_password svc_admin_totp_secret; do
        # A line is: <uid>\t<file>. Match uid == "1001" exactly (allow "1001:gid"
        # for forward-compat) AND the file path ending in /<_sf>.
        if ! awk -F'\t' -v sf="/${_sf}" '
                $1 ~ /^1001(:[0-9]+)?$/ && index($2, sf)==(length($2)-length(sf)+1) {found=1}
                END{exit !found}
             ' "$_chown_record"; then
            _chown_ok=0
            printf "    (8) missing _do_chown 1001 for %s\n" "$_sf" >&2
        fi
    done
    if [[ "$_chown_ok" -eq 1 ]]; then
        _pass "(8) upgrade backfill invokes _do_chown 1001 for each svc_admin_* — no-rotation upgrade leaves them UID-1001-owned, not root:root"
    else
        _fail "(8) upgrade backfill did NOT chown one or more svc_admin_* to UID 1001 — ISSUE-AGENT-REG-STALE-PW reproduces on the no-rotation upgrade branch"
    fi

    rm -rf "$_sbx"
fi

# ---------------------------------------------------------------------------
printf "\n=== RESULTS: %d passed, %d failed ===\n" "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
