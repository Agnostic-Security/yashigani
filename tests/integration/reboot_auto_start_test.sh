#!/usr/bin/env bash
# reboot_auto_start_test.sh — Verify auto-start artifacts installed by install.sh
#
# Usage: bash tests/integration/reboot_auto_start_test.sh
#
# What this script tests:
#   1. Yashigani is installed and /healthz returns HTTP 200.
#   2. The runtime class is detected (mirrors install.sh _setup_auto_start logic).
#   3. The appropriate auto-start artifact exists and is in the expected enabled state.
#   4. Outputs PASS or FAIL with explicit evidence per artifact.
#
# What this script does NOT test:
#   Actual reboot validation. Tom pairs this script with a `sudo systemctl reboot`
#   cycle in Phase 3 VM validation. This script is the pre-reboot and
#   post-reboot assertion harness — run it both before and after the reboot.
#
# IMPORTANT: This script never reboots the host itself. Reboot is out of scope.
#
# Runtime classes handled:
#   Linux Podman rootful  → systemctl is-enabled yashigani.service
#   Linux Podman rootless → systemctl --user is-enabled + loginctl Linger check
#   Linux Docker          → systemctl is-enabled docker
#   macOS Podman          → launchctl list | grep yashigani
#   K8s                   → skip (pod restart is controller-native)
#
# Exit codes:
#   0 — all checks PASS
#   1 — one or more checks FAIL
#
# BUG-REBOOT-NO-AUTO-START / ACS-RISK-046
# last-updated: 2026-05-14T21:00:00+00:00

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
HEALTHZ_URL="${HEALTHZ_URL:-https://localhost/healthz}"
HEALTHZ_TIMEOUT="${HEALTHZ_TIMEOUT:-30}"

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_warn() { printf "[WARN] %s\n" "$1" >&2; }

# ---------------------------------------------------------------------------
# Step 1: Verify /healthz returns 200
# ---------------------------------------------------------------------------
_info "Step 1: /healthz check (${HEALTHZ_URL})"
_http_code="$(curl -sk --max-time "${HEALTHZ_TIMEOUT}" \
  -o /dev/null -w "%{http_code}" "${HEALTHZ_URL}" 2>/dev/null || echo '000')"
if [[ "$_http_code" == "200" ]]; then
  _pass "/healthz returned HTTP 200"
else
  _fail "/healthz returned HTTP ${_http_code} (expected 200)"
fi

# ---------------------------------------------------------------------------
# Step 2: Detect runtime class (mirrors install.sh _setup_auto_start logic)
# ---------------------------------------------------------------------------
_info "Step 2: Runtime class detection"

_os="$(uname -s)"
_runtime_class="unknown"

if [[ "$_os" == "Darwin" ]]; then
  _runtime_class="macos"
elif command -v systemctl >/dev/null 2>&1; then
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    if [[ "$(id -u)" == "0" ]]; then
      _runtime_class="podman_rootful"
    else
      _runtime_class="podman_rootless"
    fi
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    _runtime_class="docker_linux"
  fi
fi

_info "  Detected runtime class: ${_runtime_class}"

# Check for K8s override env (mirrors install.sh MODE/YSG_RUNTIME check)
if [[ "${YSG_RUNTIME:-}" == "k8s" || "${MODE:-}" == "k8s" ]]; then
  _info "K8s runtime detected — auto-start is controller-native. No artifact check needed."
  printf "\nRESULT: PASS (K8s — no auto-start artifact expected)\n"
  exit 0
fi

# ---------------------------------------------------------------------------
# Step 3: Verify auto-start artifact per runtime class
# ---------------------------------------------------------------------------
_info "Step 3: Auto-start artifact verification (class: ${_runtime_class})"

case "$_runtime_class" in

  podman_rootful)
    _unit="/etc/systemd/system/yashigani.service"

    if [[ -f "$_unit" ]]; then
      _pass "Unit file exists: ${_unit}"
    else
      _fail "Unit file missing: ${_unit}"
    fi

    _enabled="$(systemctl is-enabled yashigani.service 2>/dev/null || echo 'not-found')"
    if [[ "$_enabled" == "enabled" ]]; then
      _pass "systemctl is-enabled yashigani.service → ${_enabled}"
    else
      _fail "systemctl is-enabled yashigani.service → ${_enabled} (expected: enabled)"
    fi

    # Verify After= and Requires= for podman.socket.service dependency
    if grep -q "Requires=podman.socket.service" "$_unit" 2>/dev/null; then
      _pass "Unit declares Requires=podman.socket.service"
    else
      _fail "Unit missing Requires=podman.socket.service — reboot ordering may be broken"
    fi
    ;;

  podman_rootless)
    _user_unit="${HOME}/.config/systemd/user/yashigani.service"

    if [[ -f "$_user_unit" ]]; then
      _pass "User unit file exists: ${_user_unit}"
    else
      _fail "User unit file missing: ${_user_unit}"
    fi

    _enabled="$(systemctl --user is-enabled yashigani.service 2>/dev/null || echo 'not-found')"
    if [[ "$_enabled" == "enabled" ]]; then
      _pass "systemctl --user is-enabled yashigani.service → ${_enabled}"
    else
      _fail "systemctl --user is-enabled yashigani.service → ${_enabled} (expected: enabled)"
    fi

    _current_user="$(id -un)"
    _linger="$(loginctl show-user "$_current_user" --property=Linger --value 2>/dev/null || echo 'unknown')"
    if [[ "$_linger" == "yes" ]]; then
      _pass "loginctl Linger=${_linger} for ${_current_user}"
    else
      _fail "loginctl Linger=${_linger} for ${_current_user} (expected: yes) — containers will NOT auto-start on boot"
    fi
    ;;

  docker_linux)
    _docker_enabled="$(systemctl is-enabled docker 2>/dev/null || echo 'not-found')"
    if [[ "$_docker_enabled" == "enabled" || "$_docker_enabled" == "static" ]]; then
      _pass "systemctl is-enabled docker → ${_docker_enabled}"
    else
      _fail "systemctl is-enabled docker → ${_docker_enabled} (expected: enabled or static)"
    fi

    _info "  Docker relies on restart: unless-stopped policy in docker-compose.yml (no unit file written)"
    ;;

  macos)
    _plist="${HOME}/Library/LaunchAgents/io.yashigani.autostart.plist"

    if [[ -f "$_plist" ]]; then
      _pass "LaunchAgent plist exists: ${_plist}"
    else
      _fail "LaunchAgent plist missing: ${_plist}"
    fi

    # launchctl list shows loaded agents; grep for our label
    if launchctl list 2>/dev/null | grep -q "io.yashigani.autostart"; then
      _pass "launchctl: io.yashigani.autostart is loaded"
    else
      _warn "launchctl: io.yashigani.autostart not found in list (may be unloaded between sessions)"
      _info "  Run: launchctl load ${_plist} to load manually"
    fi

    _warn "macOS v2.23.4 limitation: LaunchAgent fires at USER LOGIN, not at boot."
    _warn "  Boot-time auto-start (LaunchDaemon) is deferred to v2.23.5+."
    ;;

  unknown)
    _fail "Could not detect runtime class. Manual verification required."
    ;;

esac

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
printf "\n"
printf "=== Reboot Auto-Start Test Results ===\n"
printf "  PASS: %d\n" "$PASS"
printf "  FAIL: %d\n" "$FAIL"

if (( FAIL > 0 )); then
  printf "\nRESULT: FAIL — %d check(s) failed. See [FAIL] lines above.\n" "$FAIL"
  exit 1
else
  printf "\nRESULT: PASS — all %d checks passed.\n" "$PASS"
  exit 0
fi
