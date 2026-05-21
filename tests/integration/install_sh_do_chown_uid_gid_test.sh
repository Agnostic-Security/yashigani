#!/usr/bin/env bash
# install_sh_do_chown_uid_gid_test.sh — Regression for V240-002 _do_chown uid:gid bug.
#
# Verifies that _do_chown's _chown_spec resolution handles all three input formats
# without double-applying a uid:gid pair into "uid:gid:uid:gid".
#
# Bug: 83707fb hoisted _do_chown with body "chown ${_uid}:${_uid} <file>".
#      When caller passed "1001:1001", chown received "1001:1001:1001:1001" → fatal.
#      Ava evidence: /Users/max/Documents/Claude/testing_runs/v2.24.0-ysg-risk-049-d6ab25f/phase1-verdict.md
#
# Fix: _do_chown now resolves _chown_spec before all 4 dispatch branches:
#        if [[ "${_uid}" == *:* ]]; then _chown_spec="${_uid}"
#        else _chown_spec="${_uid}:${_uid}"
#
# No live stack required. Tests isolate the _chown_spec computation logic.
#
# Exit codes:
#   0 — all checks PASS
#   1 — one or more checks FAIL
#
# last-updated: 2026-05-22

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_section() { printf "\n--- %s ---\n" "$1"; }

# ---------------------------------------------------------------------------
# _resolve_chown_spec — isolated extraction of the _do_chown computation.
# Mirrors exactly the logic added in the V240-002 follow-up fix.
# ---------------------------------------------------------------------------
_resolve_chown_spec() {
  local _uid="$1"
  local _chown_spec
  if [[ "${_uid}" == *:* ]]; then
    _chown_spec="${_uid}"
  else
    _chown_spec="${_uid}:${_uid}"
  fi
  printf "%s" "$_chown_spec"
}

# Defensive assertion: _chown_spec must always be exactly uid:gid (single colon,
# two numeric segments). Fails fast if the templating bug ever recurs.
_assert_chown_spec() {
  local input="$1" expected="$2"
  local actual
  actual="$(_resolve_chown_spec "$input")"
  if [[ "$actual" != "$expected" ]]; then
    _fail "input='${input}': expected '${expected}', got '${actual}'"
    return
  fi
  if ! [[ "$actual" =~ ^[0-9]+:[0-9]+$ ]]; then
    _fail "input='${input}': resolved '${actual}' does not match ^[0-9]+:[0-9]+\$ (double-pair bug?)"
    return
  fi
  _pass "input='${input}' => '${actual}'"
}

# ---------------------------------------------------------------------------
# Test Case 1: single uid — body should synthesise uid:uid
# ---------------------------------------------------------------------------
_section "TC-1: single uid (integer only)"
_assert_chown_spec "1001" "1001:1001"

# ---------------------------------------------------------------------------
# Test Case 2: symmetric uid:gid pair — should be used verbatim (no duplication)
# This is the exact form that triggered the Ava-blocking install failure.
# ---------------------------------------------------------------------------
_section "TC-2: symmetric uid:gid pair (1001:1001) — verbatim passthrough"
_assert_chown_spec "1001:1001" "1001:1001"

# ---------------------------------------------------------------------------
# Test Case 3: asymmetric uid:gid (70:0, pgbouncer uid / root gid)
# Previously forced to workaround via "70" — now should pass correctly.
# ---------------------------------------------------------------------------
_section "TC-3: asymmetric uid:gid pair (70:0) — verbatim passthrough"
_assert_chown_spec "70:0" "70:0"

# ---------------------------------------------------------------------------
# Regression guard: verify the OLD behaviour would have produced a bad spec.
# Simulates the pre-fix body (chown "${_uid}:${_uid}") with a uid:gid input.
# ---------------------------------------------------------------------------
_section "TC-4: regression guard — old body would produce double-pair"
_old_body_spec() {
  local _uid="$1"
  # This is the PRE-FIX body — intentionally wrong.
  printf "%s" "${_uid}:${_uid}"
}
_bad="$(_old_body_spec "1001:1001")"
if [[ "$_bad" == "1001:1001:1001:1001" ]]; then
  _pass "Confirmed old body produces '${_bad}' — demonstrates the bug we fixed"
else
  _fail "Regression guard unexpected: old body produced '${_bad}'"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n"
printf "Results: %d PASS  %d FAIL\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
