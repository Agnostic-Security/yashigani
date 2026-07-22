#!/usr/bin/env bash
# tests/install/test_caddy_quarantine_reconcile.sh
# Regression test for FINDING-V412-CADDY-SIDECAR-RACE (2026-07-21):
# on a fresh onboard's scoped `up -d <agent> <agent>-svid-sidecar caddy`,
# Caddy can reach its boot-time config-load step BEFORE the sibling
# svid-sidecar has written /run/secrets/svid/<t>/<s>/client.crt. The prior
# fix (FINDING-V412-CADDYADMIN-002) already quarantines that one dynamic
# route file at boot so Caddy stays up + every OTHER route loads — but
# before THIS fix, the quarantined route stayed dead until an operator ran
# `podman restart caddy` once the cert existed (~50% of fresh onboards hit
# this, per Ava's measured live evidence).
#
# This test proves the self-heal: it extracts the REAL functions verbatim
# out of docker/caddy/caddy-entrypoint.sh (never re-typed/approximated —
# a sed line-range keyed on function-name markers, so it tracks the shipped
# file) and drives them against the REAL `caddy` binary + a real admin unix
# socket. No container runtime needed — isolates exactly the code path the
# fix touches (see docker/caddy/caddy-entrypoint.sh's
# _reconcile_quarantined_routes / _extract_admin_socket_path).
#
# Tests:
#   1. Boot-time quarantine still fires exactly as before (regression guard
#      on FINDING-V412-CADDYADMIN-002 — this fix must never weaken it).
#   2. Quarantined route is NOT reachable immediately after boot.
#   3. Background reconcile loop, once the cert appears, hot-reloads the
#      route WITHOUT restarting Caddy (same PID before/after) and the route
#      becomes reachable (200) with no manual restart.
#   4. Negative control: if the cert NEVER appears, the loop bounds itself
#      (does not poll forever) and never fakes a recovery — no "AUTO-
#      RECOVERED" line is emitted, ever.
#   5. caddy-entrypoint.sh: bash -n + shellcheck -S error clean.
#
# Usage:
#   bash tests/install/test_caddy_quarantine_reconcile.sh
#
# Requirements: bash 3.2+, the `caddy` binary on PATH (skips gracefully with
# an explicit SKIP line — never a silent pass — if absent, matching the
# LAURA-005 absent-caddy-binary posture used elsewhere in this repo).
# Runtime artifacts (sockets/certs) are ephemeral, mktemp'd, and torn down
# on exit via trap — nothing is written under tests/ itself.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENTRYPOINT_SH="${REPO_ROOT}/docker/caddy/caddy-entrypoint.sh"

PASS_COUNT=0
FAIL_COUNT=0

_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

if ! command -v caddy >/dev/null 2>&1; then
  printf "  SKIP  caddy binary not on PATH — self-heal behavioural tests need the real\n"
  printf "        binary (same posture as codegen.py's LAURA-005 C10 gate). Install\n"
  printf "        caddy and re-run to exercise Tests 1-4. Test 5 (static) still runs.\n"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ysg-caddy-quarantine-test.XXXXXX")"
trap '
  [[ -n "${CADDY_PID:-}" ]] && kill "$CADDY_PID" 2>/dev/null || true
  [[ -n "${RECONCILE_PID:-}" ]] && kill "$RECONCILE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
' EXIT

# ---------------------------------------------------------------------------
# Extract the real functions verbatim (never re-typed) out of
# caddy-entrypoint.sh, keyed on function-name markers so it survives future
# edits to the file (no hardcoded line numbers).
# ---------------------------------------------------------------------------
_extract_lib() {
  local start_log start_vars end_vars
  start_log="$(grep -n '^log() {' "$ENTRYPOINT_SH" | head -n1 | cut -d: -f1)"
  start_vars="$(grep -n '^_CADDY_CONFIG_SRC=' "$ENTRYPOINT_SH" | head -n1 | cut -d: -f1)"
  end_vars="$(grep -n '^if resolve_effective_caddy_config' "$ENTRYPOINT_SH" | head -n1 | cut -d: -f1)"
  {
    printf '#!/bin/sh\nset -eu\n'
    sed -n "${start_log},$((start_log + 6))p" "$ENTRYPOINT_SH"   # log()/warn()
    sed -n "${start_vars},$((end_vars - 1))p" "$ENTRYPOINT_SH"   # vars + all helper fns
  } > "$WORK/lib.sh"
}
_extract_lib

# ---------------------------------------------------------------------------
# Fixture: monolith Caddyfile (admin socket path RELATIVE — sockaddr_un's
# ~104-108 byte sun_path limit makes an absolute path under a deep mktemp
# tree unreliable; relative resolves fine since we cd into $WORK before
# `caddy run`/curl, same as any real deployment's fixed short /run/caddy*
# path) + one always-good dynamic route + one racy dynamic route whose TLS
# cert does not exist yet (the exact race: Caddy reaches its cert-load step
# before the sidecar writes client.crt/client.key).
# ---------------------------------------------------------------------------
mkdir -p "$WORK/agents-dynamic" "$WORK/certs" "$WORK/runsock"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/certs-init.key" \
  -out "$WORK/certs-init.crt" -days 2 -subj "/CN=repro-agent" >/dev/null 2>&1

cat > "$WORK/Caddyfile" <<EOF
{
    admin unix/runsock/admin.sock|0666
}

:19101 {
    respond "static-ok" 200
}

import ${WORK}/agents-dynamic/*.caddy
EOF

cat > "$WORK/agents-dynamic/good-agent.caddy" <<EOF
:19102 {
    respond "good-agent-ok" 200
}
EOF

cat > "$WORK/agents-dynamic/racy-agent.caddy" <<EOF
:19103 {
    tls ${WORK}/certs/client.crt ${WORK}/certs/client.key
    respond "racy-agent-ok" 200
}
EOF

if command -v caddy >/dev/null 2>&1; then
  (
    cd "$WORK"
    . "$WORK/lib.sh"
    _CADDY_CONFIG_SRC="$WORK/Caddyfile"
    _AGENTS_DYNAMIC_DIR="$WORK/agents-dynamic"
    _AGENTS_DYNAMIC_IMPORT_LINE="import ${WORK}/agents-dynamic/*.caddy"
    _RUNTIME_SCRATCH=""
    _EFFECTIVE_CONFIG_PATH="$_CADDY_CONFIG_SRC"
    _QUARANTINE_COUNT=0
    YASHIGANI_CADDY_QUARANTINE_REPOLL_INTERVAL_SECONDS=1
    YASHIGANI_CADDY_QUARANTINE_REPOLL_MAX_ATTEMPTS=8
    export YASHIGANI_CADDY_QUARANTINE_REPOLL_INTERVAL_SECONDS YASHIGANI_CADDY_QUARANTINE_REPOLL_MAX_ATTEMPTS

    # ---- Test 1: boot-time quarantine unweakened ----
    if resolve_effective_caddy_config 2>"$WORK/resolve.log" && [ "$_QUARANTINE_COUNT" -eq 1 ]; then
      echo "T1_PASS" >> "$WORK/results"
    else
      echo "T1_FAIL" >> "$WORK/results"
    fi
    echo "$_EFFECTIVE_CONFIG_PATH" > "$WORK/effective_path"

    _EFFECTIVE_CONFIG_PATH="$(cat "$WORK/effective_path")"
    caddy run --config "$_EFFECTIVE_CONFIG_PATH" --adapter caddyfile \
      > "$WORK/caddy.log" 2>&1 &
    echo $! > "$WORK/caddy.pid"

    i=0
    while [ ! -S "$WORK/runsock/admin.sock" ]; do
      i=$((i + 1)); [ "$i" -lt 100 ] || break
      sleep 0.1
    done

    # ---- Test 2: quarantined route unreachable pre-recovery ----
    code_pre=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 1 \
      https://127.0.0.1:19103/ 2>/dev/null || echo "000")
    if [ "$code_pre" != "200" ]; then
      echo "T2_PASS" >> "$WORK/results"
    else
      echo "T2_FAIL" >> "$WORK/results"
    fi

    _reconcile_quarantined_routes > "$WORK/reconcile.log" 2>&1 &
    echo $! > "$WORK/reconcile.pid"

    sleep 2
    cp "$WORK/certs-init.crt" "$WORK/certs/client.crt"
    cp "$WORK/certs-init.key" "$WORK/certs/client.key"

    j=0
    while [ "$j" -lt 30 ]; do
      j=$((j + 1))
      grep -q "AUTO-RECOVERED" "$WORK/reconcile.log" 2>/dev/null && break
      sleep 0.5
    done

    # ---- Test 3: self-heal — live + no restart ----
    code_post=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:19103/ 2>/dev/null || echo "000")
    caddy_pid_now="$(cat "$WORK/caddy.pid")"
    if [ "$code_post" = "200" ] && grep -q "AUTO-RECOVERED" "$WORK/reconcile.log" \
       && kill -0 "$caddy_pid_now" 2>/dev/null; then
      echo "T3_PASS" >> "$WORK/results"
    else
      echo "T3_FAIL" >> "$WORK/results"
    fi

    kill "$(cat "$WORK/reconcile.pid")" 2>/dev/null || true
    kill "$caddy_pid_now" 2>/dev/null || true
    wait 2>/dev/null || true
  )

  # ---- Test 4: negative control — cert never appears, loop bounds itself ----
  (
    cd "$WORK"
    rm -f "$WORK/certs/client.crt" "$WORK/certs/client.key"
    . "$WORK/lib.sh"
    _CADDY_CONFIG_SRC="$WORK/Caddyfile"
    _AGENTS_DYNAMIC_DIR="$WORK/agents-dynamic"
    _AGENTS_DYNAMIC_IMPORT_LINE="import ${WORK}/agents-dynamic/*.caddy"
    _RUNTIME_SCRATCH=""
    _EFFECTIVE_CONFIG_PATH="$_CADDY_CONFIG_SRC"
    _QUARANTINE_COUNT=0
    YASHIGANI_CADDY_QUARANTINE_REPOLL_INTERVAL_SECONDS=1
    YASHIGANI_CADDY_QUARANTINE_REPOLL_MAX_ATTEMPTS=2
    export YASHIGANI_CADDY_QUARANTINE_REPOLL_INTERVAL_SECONDS YASHIGANI_CADDY_QUARANTINE_REPOLL_MAX_ATTEMPTS
    resolve_effective_caddy_config >/dev/null 2>&1 || true
    if _reconcile_quarantined_routes > "$WORK/reconcile_negative.log" 2>&1; then
      if grep -q "window elapsed" "$WORK/reconcile_negative.log" \
         && ! grep -q "AUTO-RECOVERED" "$WORK/reconcile_negative.log"; then
        echo "T4_PASS" >> "$WORK/results"
      else
        echo "T4_FAIL" >> "$WORK/results"
      fi
    else
      echo "T4_FAIL" >> "$WORK/results"
    fi
  )

  printf "\n--- Test 1: boot-time quarantine unweakened (exactly 1 quarantined) ---\n"
  grep -qx "T1_PASS" "$WORK/results" 2>/dev/null && _pass "resolve_effective_caddy_config quarantines the racy file, boots on the rest" \
    || _fail "boot-time quarantine did not behave as expected (see $WORK/resolve.log)"

  printf "\n--- Test 2: quarantined route unreachable immediately after boot ---\n"
  grep -qx "T2_PASS" "$WORK/results" 2>/dev/null && _pass "racy-agent route correctly absent pre-recovery" \
    || _fail "racy-agent route was unexpectedly reachable pre-recovery"

  printf "\n--- Test 3: self-heal — hot reload live, zero restart ---\n"
  grep -qx "T3_PASS" "$WORK/results" 2>/dev/null && _pass "cert appears -> AUTO-RECOVERED logged -> route 200 -> caddy PID unchanged (no restart)" \
    || _fail "self-heal did not bring the route live without a restart (see $WORK/reconcile.log)"

  printf "\n--- Test 4: negative control — bounded window, never fakes recovery ---\n"
  grep -qx "T4_PASS" "$WORK/results" 2>/dev/null && _pass "loop exits after its bounded window and never emits AUTO-RECOVERED when the cert never appears" \
    || _fail "loop did not fail closed on a cert that never appears (see $WORK/reconcile_negative.log)"
fi

# ---------------------------------------------------------------------------
# Test 5: static — bash -n + shellcheck -S error clean
# ---------------------------------------------------------------------------
printf "\n--- Test 5: caddy-entrypoint.sh syntax + shellcheck ---\n"
_t5_ok=true
if ! bash -n "$ENTRYPOINT_SH" 2>/dev/null; then
  _fail "bash -n failed: $ENTRYPOINT_SH"
  _t5_ok=false
fi
if command -v shellcheck >/dev/null 2>&1; then
  if ! shellcheck -s sh -S error "$ENTRYPOINT_SH" >/dev/null 2>&1; then
    _fail "shellcheck -S error failed: $ENTRYPOINT_SH"
    _t5_ok=false
  fi
else
  printf "  SKIP  shellcheck not installed\n"
fi
[[ "$_t5_ok" == "true" ]] && _pass "caddy-entrypoint.sh bash -n + shellcheck -S error clean"

printf "\n=== FINDING-V412-CADDY-SIDECAR-RACE gate: %d passed, %d failed ===\n" "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
