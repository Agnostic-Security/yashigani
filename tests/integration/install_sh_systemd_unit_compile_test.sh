#!/usr/bin/env bash
# install_sh_systemd_unit_compile_test.sh — Compile-time regression test for the
# systemd unit templates embedded in install.sh _setup_auto_start_podman_rootful
# and _setup_auto_start_podman_rootless.
#
# Phase: COMPILE-TIME (no live install, no running system required on macOS)
# Pairs with: tests/integration/reboot_auto_start_test.sh (install-time / VM-time)
#
# What this catches:
#   (a) _PLACEHOLDER literals left in the rendered unit (missed substitution)
#   (b) Any unresolved ${...} variable reference in the rendered unit
#   (c) *.socket.service double-suffix bug (e.g. podman.socket.service is WRONG;
#       podman.socket is correct)
#   (d) systemd-analyze verify syntax errors [Linux only]
#   (e) Unresolvable Requires= targets on systemctl list-unit-files [Linux only]
#
# Platform behaviour:
#   Linux  — all 5 checks run
#   macOS  — checks (a)(b)(c) run; (d)(e) skipped with explicit message
#
# Bug class locked out: Phase 3 FAIL caused by podman.socket.service typo passing
# a prior reproducer. This test detects that class at diff-review time, before
# any live install.
#
# Usage:
#   bash tests/integration/install_sh_systemd_unit_compile_test.sh
#   # Inject deliberate bug to verify detection:
#   INJECT_SOCKET_BUG=1 bash tests/integration/install_sh_systemd_unit_compile_test.sh
#   INJECT_PLACEHOLDER_BUG=1 bash tests/integration/install_sh_systemd_unit_compile_test.sh
#
# Exit codes:
#   0 — all checks PASS
#   1 — one or more checks FAIL
#
# BUG-REBOOT-NO-AUTO-START / ACS-RISK-046
# last-updated: 2026-05-14T00:00:00+00:00

set -euo pipefail
IFS=$'\n\t'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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

# Resolve install.sh relative to this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

if [[ ! -f "$INSTALL_SH" ]]; then
  printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
  printf "  Set INSTALL_SH=/path/to/install.sh to override.\n" >&2
  exit 1
fi

_info "install.sh: ${INSTALL_SH}"

# Work directory — stays under /Users/max/Documents/Claude per repo policy (macOS)
# On Linux CI this resolves to a path under the repo root, which is fine.
WORK_DIR_TEST="/opt/yashigani"
COMPOSE_CMD_TEST="podman-compose"

_OS="$(uname -s)"

# ---------------------------------------------------------------------------
# Extraction helper: pull the heredoc body from a named function in install.sh.
#
# Strategy:
#   1. Use awk to isolate the function body (from "^_FUNCNAME\(\)" to "^}").
#   2. Within that range, extract lines between "<<EOF" and "^EOF".
#   This is safe as long as each function has exactly one <<EOF...EOF block,
#   which is true for _setup_auto_start_podman_{rootful,rootless}.
# ---------------------------------------------------------------------------

_extract_heredoc() {
  local funcname="$1"
  local file="$2"

  # Phase 1: isolate function body
  # awk state machine: start collecting on "^funcname()", stop on "^}" at depth 0.
  local func_body
  func_body="$(awk -v fn="${funcname}" '
    /^[[:space:]]*'"${funcname}"'[[:space:]]*\(\)/ { inside=1; depth=0 }
    inside {
      # Count braces to track function boundaries
      n = split($0, chars, "")
      for (i = 1; i <= n; i++) {
        if (chars[i] == "{") depth++
        if (chars[i] == "}") {
          depth--
          if (depth == 0) { inside=0; print; next }
        }
      }
      print
    }
  ' "$file")"

  if [[ -z "$func_body" ]]; then
    printf "[FAIL] Could not extract function body for: %s\n" "$funcname" >&2
    return 1
  fi

  # Phase 2: extract heredoc body (lines between <<EOF and ^EOF)
  printf '%s\n' "$func_body" | awk '
    /<<EOF/ { collecting=1; next }
    /^EOF$/ { if (collecting) { collecting=0 } }
    collecting { print }
  '
}

# ---------------------------------------------------------------------------
# Render helper: substitute the bash variable patterns install.sh uses.
#
# install.sh writes heredocs with live bash expansions: ${WORK_DIR}, ${compose_cmd_str}.
# We replace those with test-fixture values to produce a renderable unit.
#
# If INJECT_SOCKET_BUG=1 is set, also replace "podman.socket" with
# "podman.socket.service" to verify the detection check catches it.
# If INJECT_PLACEHOLDER_BUG=1 is set, leave a _PLACEHOLDER literal in.
# ---------------------------------------------------------------------------

_render_unit() {
  local raw="$1"
  local rendered

  # Replace the two variable references install.sh embeds
  rendered="$(printf '%s\n' "$raw" \
    | sed "s|\${WORK_DIR}|${WORK_DIR_TEST}|g" \
    | sed "s|\${compose_cmd_str}|${COMPOSE_CMD_TEST}|g")"

  # Inject deliberate bugs for regression verification (only when env vars set)
  # Note: printf to stderr so the _info message does not contaminate stdout
  # (this function's stdout is captured into a variable by callers).
  if [[ "${INJECT_SOCKET_BUG:-0}" == "1" ]]; then
    printf "[INFO]   [inject] Replacing podman.socket with podman.socket.service (deliberate bug)\n" >&2
    # BSD sed (macOS) does not support \b word boundaries; use two-pass replacement:
    # pass 1: replace podman.socket followed by a non-dot character (e.g. newline, space)
    # pass 2: replace podman.socket at true end-of-line
    rendered="$(printf '%s\n' "$rendered" \
      | sed 's|podman\.socket\([^.]\)|podman.socket.service\1|g' \
      | sed 's|podman\.socket$|podman.socket.service|g')"
  fi

  if [[ "${INJECT_PLACEHOLDER_BUG:-0}" == "1" ]]; then
    printf "[INFO]   [inject] Adding WORK_DIR_PLACEHOLDER literal (deliberate bug)\n" >&2
    rendered="$(printf '%s\n' "$rendered")
WorkingDirectory=WORK_DIR_PLACEHOLDER"
  fi

  printf '%s\n' "$rendered"
}

# ---------------------------------------------------------------------------
# Check (a): No _PLACEHOLDER literal remains in the rendered unit
# ---------------------------------------------------------------------------

_check_no_placeholder() {
  local label="$1"
  local rendered="$2"

  if printf '%s\n' "$rendered" | grep -q '_PLACEHOLDER'; then
    _fail "${label}: _PLACEHOLDER literal found in rendered unit — variable substitution incomplete"
    printf '%s\n' "$rendered" | grep '_PLACEHOLDER' | while IFS= read -r line; do
      printf "       → %s\n" "$line" >&2
    done
  else
    _pass "${label}: no _PLACEHOLDER literal in rendered unit"
  fi
}

# ---------------------------------------------------------------------------
# Check (b): No unresolved ${...} variable reference remains
# ---------------------------------------------------------------------------

_check_no_unresolved_vars() {
  local label="$1"
  local rendered="$2"

  if printf '%s\n' "$rendered" | grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*\}'; then
    _fail "${label}: unresolved \${...} variable reference(s) in rendered unit"
    printf '%s\n' "$rendered" | grep -E '\$\{[A-Za-z_][A-Za-z0-9_]*\}' | \
      while IFS= read -r line; do
        printf "       → %s\n" "$line" >&2
      done
  else
    _pass "${label}: no unresolved \${...} references in rendered unit"
  fi
}

# ---------------------------------------------------------------------------
# Check (c): No *.socket.service double-suffix pattern
# ---------------------------------------------------------------------------

_check_no_socket_service_suffix() {
  local label="$1"
  local rendered="$2"

  if printf '%s\n' "$rendered" | grep -qE '\.socket\.service'; then
    _fail "${label}: found .socket.service double-suffix — *.socket is correct, *.socket.service is WRONG"
    printf '%s\n' "$rendered" | grep -E '\.socket\.service' | \
      while IFS= read -r line; do
        printf "       → %s\n" "$line" >&2
      done
  else
    _pass "${label}: no .socket.service double-suffix found"
  fi
}

# ---------------------------------------------------------------------------
# Check (d): systemd-analyze verify — Linux only
# ---------------------------------------------------------------------------

_check_systemd_analyze() {
  local label="$1"
  local rendered="$2"
  local tmpfile="$3"

  if [[ "$_OS" != "Linux" ]]; then
    _skip "${label}: systemd-analyze verify (not Linux — skipped)"
    return 0
  fi

  if ! command -v systemd-analyze >/dev/null 2>&1; then
    _skip "${label}: systemd-analyze not found — skipped"
    return 0
  fi

  printf '%s\n' "$rendered" > "$tmpfile"
  local _result
  if _result="$(systemd-analyze verify "$tmpfile" 2>&1)"; then
    _pass "${label}: systemd-analyze verify clean"
  else
    _fail "${label}: systemd-analyze verify failed"
    printf '%s\n' "$_result" | while IFS= read -r line; do
      printf "       → %s\n" "$line" >&2
    done
  fi
}

# ---------------------------------------------------------------------------
# Check (e): Requires= targets resolve via systemctl list-unit-files — Linux only
# ---------------------------------------------------------------------------

_check_requires_resolve() {
  local label="$1"
  local rendered="$2"
  local user_flag="${3:-}"   # "--user" for rootless, "" for rootful

  if [[ "$_OS" != "Linux" ]]; then
    _skip "${label}: Requires= resolution (not Linux — skipped)"
    return 0
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    _skip "${label}: systemctl not found — Requires= resolution skipped"
    return 0
  fi

  # Extract all Requires= values (space-separated on one line, or multiple lines)
  local _req_units
  _req_units="$(printf '%s\n' "$rendered" | awk -F= '/^Requires=/ { print $2 }' | tr ' ' '\n' | sed '/^[[:space:]]*$/d')"

  if [[ -z "$_req_units" ]]; then
    _skip "${label}: no Requires= entries found (nothing to resolve)"
    return 0
  fi

  while IFS= read -r _req_unit; do
    [[ -z "$_req_unit" ]] && continue
    # shellcheck disable=SC2086
    if systemctl ${user_flag} list-unit-files "$_req_unit" 2>/dev/null | grep -q "^${_req_unit}"; then
      _pass "${label}: Requires=${_req_unit} resolves (systemctl list-unit-files)"
    else
      # Fallback: status query (catches generated/transient units not in list-unit-files)
      # shellcheck disable=SC2086
      if systemctl ${user_flag} status "$_req_unit" >/dev/null 2>&1; then
        _pass "${label}: Requires=${_req_unit} resolves (systemctl status)"
      else
        _fail "${label}: Requires=${_req_unit} does NOT resolve — unit unknown; systemd will refuse to start yashigani.service"
      fi
    fi
  done <<< "$_req_units"
}

# ---------------------------------------------------------------------------
# Structural check: unit has required sections
# ---------------------------------------------------------------------------

_check_unit_sections() {
  local label="$1"
  local rendered="$2"

  local _missing=0
  for section in "[Unit]" "[Service]" "[Install]"; do
    if ! printf '%s\n' "$rendered" | grep -qF "$section"; then
      _fail "${label}: missing section ${section}"
      _missing=1
    fi
  done
  if [[ "$_missing" == "0" ]]; then
    _pass "${label}: [Unit] [Service] [Install] sections present"
  fi
}

# ---------------------------------------------------------------------------
# Main: run all checks for rootful template
# ---------------------------------------------------------------------------

_section "Rootful template (_setup_auto_start_podman_rootful)"

_ROOTFUL_RAW="$(_extract_heredoc "_setup_auto_start_podman_rootful" "$INSTALL_SH")"

if [[ -z "$_ROOTFUL_RAW" ]]; then
  _fail "rootful: could not extract heredoc body from install.sh"
else
  _info "rootful: extracted $(printf '%s\n' "$_ROOTFUL_RAW" | wc -l | tr -d ' ') lines from heredoc"
  _ROOTFUL_RENDERED="$(_render_unit "$_ROOTFUL_RAW")"

  _check_no_placeholder       "rootful" "$_ROOTFUL_RENDERED"
  _check_no_unresolved_vars   "rootful" "$_ROOTFUL_RENDERED"
  _check_no_socket_service_suffix "rootful" "$_ROOTFUL_RENDERED"
  _check_unit_sections        "rootful" "$_ROOTFUL_RENDERED"

  # Write to a named temp path for systemd-analyze (no /tmp per repo policy)
  _ROOTFUL_TMP="${REPO_ROOT}/tests/integration/.tmp_rootful_unit_$$.service"
  # Ensure cleanup even on exit
  trap 'rm -f "${_ROOTFUL_TMP:-}" "${_ROOTLESS_TMP:-}"' EXIT

  _check_systemd_analyze      "rootful" "$_ROOTFUL_RENDERED" "$_ROOTFUL_TMP"
  _check_requires_resolve     "rootful" "$_ROOTFUL_RENDERED" ""
fi

# ---------------------------------------------------------------------------
# Main: run all checks for rootless template
# ---------------------------------------------------------------------------

_section "Rootless template (_setup_auto_start_podman_rootless)"

_ROOTLESS_RAW="$(_extract_heredoc "_setup_auto_start_podman_rootless" "$INSTALL_SH")"

if [[ -z "$_ROOTLESS_RAW" ]]; then
  _fail "rootless: could not extract heredoc body from install.sh"
else
  _info "rootless: extracted $(printf '%s\n' "$_ROOTLESS_RAW" | wc -l | tr -d ' ') lines from heredoc"
  _ROOTLESS_RENDERED="$(_render_unit "$_ROOTLESS_RAW")"

  _check_no_placeholder       "rootless" "$_ROOTLESS_RENDERED"
  _check_no_unresolved_vars   "rootless" "$_ROOTLESS_RENDERED"
  _check_no_socket_service_suffix "rootless" "$_ROOTLESS_RENDERED"
  _check_unit_sections        "rootless" "$_ROOTLESS_RENDERED"

  _ROOTLESS_TMP="${REPO_ROOT}/tests/integration/.tmp_rootless_unit_$$.service"
  _check_systemd_analyze      "rootless" "$_ROOTLESS_RENDERED" "$_ROOTLESS_TMP"
  _check_requires_resolve     "rootless" "$_ROOTLESS_RENDERED" "--user"
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

printf "\n"
printf "=== Systemd Unit Compile Test Results ===\n"
printf "  PASS: %d\n" "$PASS"
printf "  FAIL: %d\n" "$FAIL"
printf "  SKIP: %d\n" "$SKIP"
printf "  OS:   %s\n" "$_OS"

if (( FAIL > 0 )); then
  printf "\nRESULT: FAIL — %d check(s) failed. See [FAIL] lines above.\n" "$FAIL"
  exit 1
else
  printf "\nRESULT: PASS — %d checks passed, %d skipped.\n" "$PASS" "$SKIP"
  exit 0
fi
