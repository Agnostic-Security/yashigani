#!/usr/bin/env bash
# uninstall.sh — Tear down the Yashigani stack.
# Usage: ./uninstall.sh [--remove-volumes] [--runtime=docker|podman] [--yes|-y]
# Last updated: 2026-05-26T00:00:00+00:00 (feat(uninstall): runtime-aware refactor — separate paths per runtime + user-context guard — BUG-UNINSTALL-SUDO-ROOTLESS / Tiago directive 2026-05-26)
# Last updated: 2026-05-26T00:00:00+00:00 (fix(uninstall): depend-first removal + retry pass + final assertion — BUG-UNINSTALL-DEPEND-ORDER-2026-05-26)
# Last updated: 2026-05-17T17:00:00+00:00 (fix(uninstall): document yashigani_internal_bearer in secrets-wipe comment — Bucket-C)
# Last updated: 2026-05-17T10:00:00+00:00 (fix(uninstall): add wazuh-compose volumes to canonical list + prune dangling anon volumes — ANON-VOL-LEAK)
# Last updated: 2026-05-15T14:00:00+00:00 (fix(uninstall): wipe docker/secrets/ on --remove-volumes + final straggler pass — BUG-3-MULTI-USER-INSTALL-PKI + BUG-1-REDIS-STRAGGLER)
# Last updated: 2026-05-15T12:00:00+00:00 (fix(uninstall): force-remove dependent containers before volume rm — BUG-UNINSTALL-DEPGRAPH-LEAK)
# Last updated: 2026-05-15T10:00:00+00:00 (fix(uninstall): stub docker/.env for compose-down in DR scenario — BUG-UNINSTALL-NO-ENV)
# Last updated: 2026-05-15T00:00:00+00:00 (fix(uninstall): drop privileged-linger shortcut from disable-linger, copy-pasteable remediation — Q2 / lint-sudo-pattern fix)
# Last updated: 2026-05-14T23:00:00+00:00 (fix: gate linger-disable on --remove-volumes — Q3 asymmetry)

set -euo pipefail

# Hardened PATH — never trust inherited PATH for privileged scripts.
# BUG-UNINSTALL-PATH-MISSING-PODMAN-MAC-2026-05-27: prior PATH excluded
# /opt/homebrew/bin (Apple Silicon Homebrew) and /opt/homebrew/sbin where
# Podman Desktop installs `podman` on macOS — uninstall.sh hit
# "podman: command not found", _list_project_containers silently returned
# empty (|| true), _assert_no_containers_remain said "all clear" while 15
# containers were still running. Live verify on Mac/Podman Desktop 2026-05-27.
# Adding the standard macOS Homebrew + Podman Desktop locations preserves
# the hardening intent while making the script actually work on Mac.
PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/opt/podman/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Minimal logging helper — mirrors the install.sh format exactly.
# log_info is called in the state-file runtime-detection block (57ea226);
# without this definition, set -euo pipefail aborts before any cleanup runs.
# (UNINSTALL-LOG_INFO-BUG — Ava phase2-verdict.md:69, v2.23.4)
log_info() { printf "    --> %s\n" "$1"; }
log_warn() { printf "    !!  %s\n" "$1" >&2; }
log_error() { printf "    XX  %s\n" "$1" >&2; }
log_success() { printf "    ok  %s\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.yml"
REMOVE_VOLUMES="false"
RUNTIME="${RUNTIME:-}"
YES="false"
# Multi-instance (3.0 — scoping-draft §4a): explicit --project=<name> override to
# target a specific named instance. When empty, the project is read from the install
# state file's PROJECT field (which falls back to "docker" for legacy installs).
PROJECT_FLAG="${PROJECT_FLAG:-}"

# MI-4 (step-up on destructive lifecycle ops / YSG-RISK-061): proof that a fresh
# step-up TOTP verification was performed before this privileged mutation. May be
# supplied via --stepup-token=<value> or the YASHIGANI_STEPUP_TOKEN env var; the
# explicit --i-have-stepped-up acknowledgement is an interactive-operator escape
# for the host-shell path where no token is minted. See _require_stepup_mi4.
STEPUP_TOKEN="${STEPUP_TOKEN:-${YASHIGANI_STEPUP_TOKEN:-}}"
STEPUP_ACK="${STEPUP_ACK:-false}"

# ---------------------------------------------------------------------------
# Canonical named volumes declared in docker/docker-compose.yml top-level
# volumes: section.  These are the names as declared (without the project
# prefix).  The project prefix is derived from the compose file's parent
# directory name (docker/) → prefix "docker".
#
# UNINSTALL-LEAVES-VOLUMES (#8): podman-compose ≤1.3.x does NOT honour the
# --volumes flag for named volumes — it only removes anonymous volumes.
# docker compose ≥2.x does honour it, but we cannot rely on that being
# available.  The explicit per-volume rm loop below is the reliable fallback
# that works on both runtimes.
#
# When adding/removing named volumes in docker-compose.yml, keep this list
# in sync.
# ---------------------------------------------------------------------------
_CANONICAL_VOLUMES=(
    audit_data
    bootstrap_data
    redis_data
    ollama_data
    prometheus_data
    grafana_data
    caddy_data
    caddy_config
    postgres_data
    alertmanager_data
    loki_data
    keycloak_data
    openclaw_data
    langflow_data
    letta_data
    openwebui_data
    budget_redis_data
    step_ca_data
    wazuh_api_configuration
    wazuh_etc
    wazuh_logs
    wazuh_queue
    wazuh_var_multigroups
    wazuh_integrations
    wazuh_active_response
    wazuh_agentless
    wazuh_wodles
    filebeat_etc
    filebeat_var
    wazuh_indexer_data
    wazuh_dashboard_config
    wazuh_dashboard_custom
    # docker-compose.wazuh.yml volumes — missing from original list (ANON-VOL-LEAK)
    wazuh_manager_config
    wazuh_manager_logs
    wazuh_manager_queue
)

# ---------------------------------------------------------------------------
# _remove_auto_start — disables and removes OS-level auto-start artifacts
# installed by install.sh _setup_auto_start.
#
# Called BEFORE compose down so that a reboot mid-uninstall does not
# re-start the stack.
#
# Tiago directive 2026-05-14 (Q3): loginctl disable-linger is gated on
# --remove-volumes. Plain uninstall preserves linger so a re-install picks
# up the user systemd instance cleanly. --remove-volumes is the full-clean
# exit path that removes data + linger together.
# BUG-REBOOT-NO-AUTO-START / YSG-RISK-046
# ---------------------------------------------------------------------------
_remove_auto_start() {
  echo "=== Removing auto-start configuration ==="
  local _os
  _os="$(uname -s)"

  # macOS LaunchAgent
  if [[ "$_os" == "Darwin" ]]; then
    local _plist="${HOME}/Library/LaunchAgents/io.yashigani.autostart.plist"
    if [[ -f "$_plist" ]]; then
      launchctl unload "$_plist" 2>/dev/null || true
      rm -f "$_plist"
      echo "  [removed] LaunchAgent: ${_plist}"
    else
      echo "  [skip]    LaunchAgent not found: ${_plist}"
    fi
    return 0
  fi

  # Linux — systemd present?
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "  [skip] systemctl not found — no auto-start units to remove"
    return 0
  fi

  # Rootful unit: /etc/systemd/system/yashigani.service
  local _sys_unit="/etc/systemd/system/yashigani.service"
  if [[ -f "$_sys_unit" ]]; then
    systemctl disable yashigani.service 2>/dev/null || true
    systemctl stop yashigani.service 2>/dev/null || true
    rm -f "$_sys_unit"
    systemctl daemon-reload 2>/dev/null || true
    echo "  [removed] System unit: ${_sys_unit}"
  else
    echo "  [skip]    System unit not found: ${_sys_unit}"
  fi

  # Rootless unit: ~/.config/systemd/user/yashigani.service
  local _user_unit="${HOME}/.config/systemd/user/yashigani.service"
  if [[ -f "$_user_unit" ]]; then
    systemctl --user disable yashigani.service 2>/dev/null || true
    systemctl --user stop yashigani.service 2>/dev/null || true
    rm -f "$_user_unit"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "  [removed] User unit: ${_user_unit}"
  else
    echo "  [skip]    User unit not found: ${_user_unit}"
  fi

  # Linger: gated on --remove-volumes (Tiago directive 2026-05-14 Q3).
  # Plain uninstall preserves linger so a re-install picks up the user
  # systemd instance cleanly. --remove-volumes is the full-clean exit path.
  if [[ "${REMOVE_VOLUMES:-false}" == "true" ]]; then
    local _current_user
    _current_user="$(id -un)"
    local _linger_state
    _linger_state="$(loginctl show-user "$_current_user" --property=Linger --value 2>/dev/null || echo 'unknown')"
    if [[ "$_linger_state" == "yes" ]]; then
      if loginctl disable-linger "$_current_user" 2>/dev/null; then
        echo "  [removed] Linger disabled for ${_current_user}"
      else
        echo "  [warn]    Linger could NOT be disabled for ${_current_user}." >&2
        echo "  [warn]    To remove, run as root:" >&2
        echo "  [warn]        sudo loginctl disable-linger ${_current_user}" >&2
      fi
    else
      echo "  [skip]    Linger not active for ${_current_user} (state: ${_linger_state})"
    fi
  else
    echo "  [skip]    Linger left enabled — pass --remove-volumes to disable"
  fi
}

# ---------------------------------------------------------------------------
# _list_project_containers — enumerate ALL project containers (running OR
# exited) using two complementary strategies:
#
#   1. Label filter: compose-label variants for both Podman and Docker.
#   2. Name-prefix fallback: docker_* or docker-* naming conventions.
#
# Outputs deduplicated container IDs, one per line, to stdout.
# Returns 0 regardless of whether any were found.
#
# Args: $1 = runtime binary (podman or docker)
#       $2 = project prefix (default: "docker")
# ---------------------------------------------------------------------------
_list_project_containers() {
  local _rt="${1:?_list_project_containers: runtime required}"
  local _pfx="${2:-docker}"
  local _ids=""

  for _label_key in "io.podman.compose.project" "com.docker.compose.project"; do
    local _l
    _l="$("$_rt" ps -a -q --filter "label=${_label_key}=${_pfx}" 2>/dev/null || true)"
    if [ -n "$_l" ]; then
      _ids="${_ids}${_l}
"
    fi
  done

  local _by_name
  _by_name="$("$_rt" ps -a -q --filter "name=^${_pfx}[_-]" 2>/dev/null || true)"
  if [ -n "$_by_name" ]; then
    _ids="${_ids}${_by_name}
"
  fi

  printf '%s' "$_ids" | sort -u | grep -v '^$' || true
}

# ---------------------------------------------------------------------------
# _remove_containers — stop then force-remove a newline-separated list of
# container IDs. Uses --depend first (Podman >=4.x), falls back to plain
# rm -f (Docker / older Podman).
#
# BUG-UNINSTALL-DEPEND-ORDER-2026-05-26: --depend FIRST is mandatory.
# See Maxine's commit 82f356c for root-cause analysis.
#
# Args: $1 = runtime binary
#       $2 = newline-separated container IDs
# Side-effects: prints per-container result to stdout/stderr.
# Returns 0 always (callers check residuals separately).
# ---------------------------------------------------------------------------
_remove_containers() {
  local _rt="${1:?_remove_containers: runtime required}"
  local _ids="${2:-}"
  [ -z "$_ids" ] && return 0

  local _count
  _count="$(printf '%s\n' "$_ids" | grep -c '.' || echo 0)"
  echo "  [stop] Stopping ${_count} container(s)..."
  while IFS= read -r _cid; do
    [ -z "$_cid" ] && continue
    "$_rt" stop --time 0 "$_cid" >/dev/null 2>&1 || true
  done <<< "$_ids"

  echo "  [rm] Force-removing ${_count} container(s) (--depend first)..."
  while IFS= read -r _cid; do
    [ -z "$_cid" ] && continue
    local _cname
    _cname="$("$_rt" inspect --format '{{.Name}}' "$_cid" 2>/dev/null | sed 's|^/||' || echo "$_cid")"
    if "$_rt" rm -f --depend "$_cid" >/dev/null 2>&1; then
      echo "  [removed] ${_cname} (${_cid})"
    elif "$_rt" rm -f "$_cid" >/dev/null 2>&1; then
      # --depend unsupported (Docker / older Podman) — plain rm -f fallback
      echo "  [removed] ${_cname} (${_cid})"
    else
      echo "  [WARN] could not remove container: ${_cname} (${_cid})" >&2
    fi
  done <<< "$_ids"
}

# ---------------------------------------------------------------------------
# _assert_no_containers_remain — final assertion gate.
#
# Re-enumerates project containers after all removal passes. If ANY remain,
# prints a detailed error with manual remediation and exits 1.
# This is the contract that closes the "silent exit-0" hole.
#
# BUG-UNINSTALL-SILENT-SUCCESS-2026-05-26 / BUG-UNINSTALL-SUDO-ROOTLESS
#
# Args: $1 = runtime binary
#       $2 = project prefix
#       $3 = human-readable runtime label (for error messages)
# ---------------------------------------------------------------------------
_assert_no_containers_remain() {
  local _rt="${1:?}"
  local _pfx="${2:-docker}"
  local _label="${3:-${_rt}}"
  local _residual
  _residual="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_residual" ]; then
    local _cnt
    _cnt="$(printf '%s\n' "$_residual" | grep -c '.' || echo 0)"
    printf '\n' >&2
    printf 'ERROR: uninstall.sh FAILED — %d project container(s) remain after all removal passes.\n' "$_cnt" >&2
    printf 'Runtime: %s\n' "$_label" >&2
    while IFS= read -r _cid; do
      [ -z "$_cid" ] && continue
      local _detail
      _detail="$("$_rt" inspect --format '{{.Name}} state={{.State.Status}} restarts={{.RestartCount}}' "$_cid" 2>/dev/null \
                 | sed 's|^/||' || echo "${_cid} (inspect failed)")"
      printf '  - %s (%s)\n' "$_detail" "$_cid" >&2
    done <<< "$_residual"
    printf '\n' >&2
    printf 'Manual remediation:\n' >&2
    # shellcheck disable=SC2016
    # SC2016: literal $() in single quotes is intentional -- copy-paste remediation for operator
    printf '  %s rm -f --depend $(%s ps -a -q --filter '"'"'name=^%s[_-]'"'"')\n' \
           "$_rt" "$_rt" "$_pfx" >&2
    printf '  %s system prune -af --volumes\n' "$_rt" >&2
    printf '\n' >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# _assert_no_volumes_remain — final volume assertion gate.
#
# After volume removal, re-checks every canonical volume. If ANY still exist,
# prints a detailed error and exits 1.
#
# This closes the volume-parallel of the container silent-exit-0 hole.
# Previously the script logged [WARN] on individual volume rm failures and
# continued to exit 0 — operators assumed clean state but volumes remained.
#
# Args: $1 = runtime binary
#       $2 = project prefix
# ---------------------------------------------------------------------------
_assert_no_volumes_remain() {
  local _rt="${1:?}"
  local _pfx="${2:-docker}"
  local _leftover=()
  for _vol in "${_CANONICAL_VOLUMES[@]}"; do
    local _full="${_pfx}_${_vol}"
    if "$_rt" volume inspect "$_full" >/dev/null 2>&1; then
      _leftover+=("$_full")
    fi
  done
  if [ "${#_leftover[@]}" -gt 0 ]; then
    printf '\n' >&2
    printf 'ERROR: uninstall.sh FAILED — %d named volume(s) remain after removal pass:\n' \
           "${#_leftover[@]}" >&2
    for _v in "${_leftover[@]}"; do
      printf '  - %s\n' "$_v" >&2
    done
    printf '\n' >&2
    printf 'Manual remediation:\n' >&2
    for _v in "${_leftover[@]}"; do
      printf '  %s volume rm %s\n' "$_rt" "$_v" >&2
    done
    printf '\n' >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# _teardown_podman_rootless — container teardown for Podman rootless.
#
# Key properties of this path:
# - Containers live in the CALLING USER's user namespace.
# - "sudo podman" sees root's namespace which has ZERO containers — it MUST
#   NOT be used (BUG-UNINSTALL-SUDO-ROOTLESS).
# - compose down signals graceful shutdown; belt-and-braces rm loop is the
#   reliable fallback for podman-compose ≤1.3.x parity gaps.
# - Retry pass handles restart-policy=always respawn between stop and rm.
# ---------------------------------------------------------------------------
_teardown_podman_rootless() {
  local _rt="podman"
  local _pfx="${_PROJECT_PREFIX}"
  local _label
  _label="podman-rootless (UID=$(id -u))"

  echo "=== Podman rootless teardown ==="

  # Step 1: compose down (graceful).
  echo "  [compose] Stopping services via compose down..."
  # shellcheck disable=SC2086
  $COMPOSE -f "$COMPOSE_FILE" ${_COMPOSE_ENV_ARGS} down $DOWN_ARGS 2>&1 || true

  # Step 2: belt-and-braces — first pass.
  echo "  [cleanup] Belt-and-braces first pass..."
  local _ids
  _ids="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_ids" ]; then
    _remove_containers "$_rt" "$_ids"
  else
    echo "  [ok] No remaining containers after compose down."
  fi

  # Step 3: retry pass (handles restart-policy=always respawn race).
  local _residual
  _residual="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_residual" ]; then
    echo "  [retry] Residual containers detected — retry pass..."
    _remove_containers "$_rt" "$_residual"
  fi

  # Step 4: final assertion — MUST be zero or we exit 1.
  _assert_no_containers_remain "$_rt" "$_pfx" "$_label"
  echo "  [ok] All project containers removed."
}

# ---------------------------------------------------------------------------
# _teardown_podman_rootful — container teardown for Podman rootful.
#
# Rootful Podman (called as root or via sudo) can see and manage all
# containers in the system namespace. The teardown logic mirrors rootless
# but does not gate on SUDO_USER since the caller intentionally has root.
# ---------------------------------------------------------------------------
_teardown_podman_rootful() {
  local _rt="podman"
  local _pfx="${_PROJECT_PREFIX}"
  local _label="podman-rootful (UID=0)"

  echo "=== Podman rootful teardown ==="

  # Step 1: compose down (graceful).
  echo "  [compose] Stopping services via compose down..."
  # shellcheck disable=SC2086
  $COMPOSE -f "$COMPOSE_FILE" ${_COMPOSE_ENV_ARGS} down $DOWN_ARGS 2>&1 || true

  # Step 2: belt-and-braces — first pass.
  local _ids
  _ids="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_ids" ]; then
    _remove_containers "$_rt" "$_ids"
  else
    echo "  [ok] No remaining containers after compose down."
  fi

  # Step 3: retry pass.
  local _residual
  _residual="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_residual" ]; then
    echo "  [retry] Residual containers detected — retry pass..."
    _remove_containers "$_rt" "$_residual"
  fi

  # Step 4: final assertion.
  _assert_no_containers_remain "$_rt" "$_pfx" "$_label"
  echo "  [ok] All project containers removed."
}

# ---------------------------------------------------------------------------
# _teardown_docker_desktop — container teardown for Docker Desktop (macOS).
#
# Docker Desktop runs a Linux VM managed by the Desktop application.
# The daemon is accessible via the standard socket but the namespacing is
# different from Linux native Docker Engine: containers are always "rootful"
# from Docker's perspective regardless of the host user's UID.
#
# Key differences vs docker-engine:
# - `docker info` shows ServerVersion and Name: desktop-linux.
# - There is no rootless path — Docker Desktop manages everything internally.
# - "sudo docker" and "docker" are equivalent (both talk to the Desktop daemon).
# ---------------------------------------------------------------------------
_teardown_docker_desktop() {
  local _rt="docker"
  local _pfx="${_PROJECT_PREFIX}"
  local _label="docker-desktop (macOS)"

  echo "=== Docker Desktop teardown ==="

  # Step 1: compose down (graceful).
  echo "  [compose] Stopping services via compose down..."
  # shellcheck disable=SC2086
  $COMPOSE -f "$COMPOSE_FILE" ${_COMPOSE_ENV_ARGS} down $DOWN_ARGS 2>&1 || true

  # Step 2: belt-and-braces — first pass.
  local _ids
  _ids="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_ids" ]; then
    _remove_containers "$_rt" "$_ids"
  else
    echo "  [ok] No remaining containers after compose down."
  fi

  # Step 3: retry pass.
  local _residual
  _residual="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_residual" ]; then
    echo "  [retry] Residual containers detected — retry pass..."
    _remove_containers "$_rt" "$_residual"
  fi

  # Step 4: final assertion.
  _assert_no_containers_remain "$_rt" "$_pfx" "$_label"
  echo "  [ok] All project containers removed."
}

# ---------------------------------------------------------------------------
# _teardown_docker_engine — container teardown for Linux native Docker Engine.
#
# Docker Engine on Linux can run rootful (standard daemon) or rootless
# (docker rootless mode, separate user-level daemon). In the rootless case
# the daemon is owned by the calling user and "sudo docker" would reach a
# different daemon — same namespace mismatch as Podman rootless.
#
# Rootless Docker Engine detection: XDG_RUNTIME_DIR-based socket path is
# present when docker rootless is active. We check this at detection time
# and store in RUNTIME_SUBTYPE=docker-engine-rootless vs docker-engine.
# ---------------------------------------------------------------------------
_teardown_docker_engine() {
  local _rt="docker"
  local _pfx="${_PROJECT_PREFIX}"
  local _label="${RUNTIME_SUBTYPE:-docker-engine}"

  echo "=== Docker Engine teardown (${_label}) ==="

  # Step 1: compose down (graceful).
  echo "  [compose] Stopping services via compose down..."
  # shellcheck disable=SC2086
  $COMPOSE -f "$COMPOSE_FILE" ${_COMPOSE_ENV_ARGS} down $DOWN_ARGS 2>&1 || true

  # Step 2: belt-and-braces — first pass.
  local _ids
  _ids="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_ids" ]; then
    _remove_containers "$_rt" "$_ids"
  else
    echo "  [ok] No remaining containers after compose down."
  fi

  # Step 3: retry pass.
  local _residual
  _residual="$(_list_project_containers "$_rt" "$_pfx")"
  if [ -n "$_residual" ]; then
    echo "  [retry] Residual containers detected — retry pass..."
    _remove_containers "$_rt" "$_residual"
  fi

  # Step 4: final assertion.
  _assert_no_containers_remain "$_rt" "$_pfx" "$_label"
  echo "  [ok] All project containers removed."
}

# ---------------------------------------------------------------------------
# _teardown_k8s — helm/kubectl teardown for Kubernetes.
#
# K8s path: helm uninstall + namespace drain. Container-level rm is replaced
# by kubectl delete pod --all --force in the namespace. Volume cleanup uses
# kubectl delete pvc --all in the namespace.
#
# This path is entered when RUNTIME=k8s in the install state file OR when
# --runtime=k8s is passed explicitly.
#
# IMPORTANT: Kubernetes volumes are PersistentVolumeClaims — named volumes
# in the compose sense do not exist. The --remove-volumes flag triggers PVC
# deletion here instead of the compose volume rm loop.
# ---------------------------------------------------------------------------
_teardown_k8s() {
  local _ns="${YASHIGANI_NAMESPACE:-yashigani}"
  local _release="${YASHIGANI_HELM_RELEASE:-yashigani}"

  echo "=== Kubernetes (Helm) teardown ==="
  echo "  Namespace: ${_ns}"
  echo "  Helm release: ${_release}"

  # Step 1: helm uninstall (removes Deployment, Service, ConfigMap, Secrets, etc.)
  if command -v helm >/dev/null 2>&1; then
    if helm status "$_release" -n "$_ns" >/dev/null 2>&1; then
      echo "  [helm] Uninstalling release ${_release}..."
      helm uninstall "$_release" -n "$_ns" --wait --timeout 120s 2>&1 || true
    else
      echo "  [skip] Helm release ${_release} not found in namespace ${_ns}"
    fi
  else
    echo "  [WARN] helm not found — skipping helm uninstall" >&2
  fi

  # Step 2: drain any residual pods via kubectl.
  if command -v kubectl >/dev/null 2>&1; then
    local _pod_count
    _pod_count="$(kubectl get pods -n "$_ns" --no-headers 2>/dev/null | grep -c . || echo 0)"
    if [ "$_pod_count" -gt 0 ]; then
      echo "  [kubectl] Force-deleting ${_pod_count} residual pod(s)..."
      kubectl delete pods --all -n "$_ns" --force --grace-period=0 2>&1 || true
    else
      echo "  [ok] No residual pods in namespace ${_ns}."
    fi

    # Step 3: remove PVCs when --remove-volumes is set.
    if [ "$REMOVE_VOLUMES" = "true" ]; then
      local _pvc_count
      _pvc_count="$(kubectl get pvc -n "$_ns" --no-headers 2>/dev/null | grep -c . || echo 0)"
      if [ "$_pvc_count" -gt 0 ]; then
        echo "  [kubectl] Deleting ${_pvc_count} PersistentVolumeClaim(s)..."
        kubectl delete pvc --all -n "$_ns" --wait=true --timeout=60s 2>&1 || true
      else
        echo "  [ok] No PVCs found in namespace ${_ns}."
      fi

      # Step 4: delete the namespace itself.
      if kubectl get namespace "$_ns" >/dev/null 2>&1; then
        echo "  [kubectl] Deleting namespace ${_ns}..."
        kubectl delete namespace "$_ns" --wait=true --timeout=60s 2>&1 || true
      fi
    fi

    # Step 5: final assertion — no pods should remain.
    local _remaining_pods
    _remaining_pods="$(kubectl get pods -n "$_ns" --no-headers 2>/dev/null | grep -v Terminating | grep -c . || echo 0)"
    if [ "$_remaining_pods" -gt 0 ]; then
      printf '\n' >&2
      printf 'ERROR: uninstall.sh FAILED — %d pod(s) remain in namespace %s\n' \
             "$_remaining_pods" "$_ns" >&2
      kubectl get pods -n "$_ns" >&2 || true
      printf '\nManual remediation:\n' >&2
      printf '  kubectl delete pods --all -n %s --force --grace-period=0\n' "$_ns" >&2
      printf '  kubectl delete namespace %s\n' "$_ns" >&2
      printf '\n' >&2
      exit 1
    fi
    echo "  [ok] All pods removed."
  else
    echo "  [WARN] kubectl not found — cannot verify pod drain" >&2
  fi
}

# ===========================================================================
# Argument parsing
# ===========================================================================
for arg in "$@"; do
    case "$arg" in
        --remove-volumes) REMOVE_VOLUMES="true" ;;
        --runtime=*)      RUNTIME="${arg#*=}" ;;
        --project=*)      PROJECT_FLAG="${arg#*=}" ;;
        --yes|-y)         YES="true" ;;
        # MI-4 (step-up on destructive lifecycle ops): operator proof that a fresh
        # step-up TOTP verification was performed for this privileged mutation. The
        # API/WebUI path enforces step-up via auth/stepup.py (Tom's shared gate) and
        # passes the resulting token here; on the host-shell path the operator sets
        # --stepup-token=<value> or YASHIGANI_STEPUP_TOKEN. See _require_stepup_mi4.
        --stepup-token=*) STEPUP_TOKEN="${arg#*=}" ;;
        --i-have-stepped-up) STEPUP_ACK="true" ;;
        --help|-h)
            cat <<'EOF'
Usage: ./uninstall.sh [OPTIONS]

Stops the Yashigani stack and optionally removes all data.

Options:
  --remove-volumes    Also permanently delete all data volumes
                      (Redis, audit logs, Ollama models, metrics history)
  --runtime=RUNTIME   Force a specific container runtime
                      (docker|podman|k8s — normally auto-detected)
  --project=NAME      Target a specific named instance (multi-instance hosts).
                      Normally read from the install state file's PROJECT field;
                      use this to uninstall one of several side-by-side instances.
  --yes, -y           Skip confirmation prompts (for unattended/CI use).
                      Safety note: when combined with --remove-volumes this
                      will DELETE ALL DATA without prompting. Pass both flags
                      only when you are certain data loss is acceptable.
  --stepup-token=TOK  MI-4 step-up proof for this destructive mutation. The
                      admin API/WebUI mints this after a fresh TOTP step-up
                      (auth/stepup.py) and passes it through. Also read from the
                      YASHIGANI_STEPUP_TOKEN environment variable.
  --i-have-stepped-up Interactive-operator acknowledgement that a step-up was
                      performed out-of-band (host-shell path with no token). Only
                      honoured on an interactive TTY; never in unattended --yes runs.
  --help, -h          Print this message and exit
EOF
            exit 0
            ;;
        *) printf "Unknown option: %s\nRun with --help for usage.\n" "$arg" >&2; exit 1 ;;
    esac
done

# ===========================================================================
# Runtime detection — four sources, in precedence order:
#
#   1. --runtime= flag (already parsed above into RUNTIME)
#   2. State file: docker/.yashigani-install-state written by install.sh
#   3. Auto-detect: podman preferred over docker (mirrors install.sh order)
#   4. Hard error if nothing found
#
# RUNTIME_SUBTYPE is derived AFTER the base runtime is known:
#   podman-rootless   — podman + caller UID != 0
#   podman-rootful    — podman + caller UID == 0
#   docker-desktop    — docker + macOS OR docker info Name: desktop-linux
#   docker-engine     — docker + Linux native daemon
#   docker-engine-rootless — docker + rootless mode (XDG_RUNTIME_DIR socket)
#   k8s               — Kubernetes (helm/kubectl)
# ===========================================================================

# Source 2: state-file runtime detection (Iris IRIS-ARCH-001 / Laura LAURA-TM-CLEANUP-001).
# B1-fix (GAP 1+10+11): also read NAMESPACE and HELM_RELEASE so _teardown_k8s
# uses the namespace the operator originally installed into, not the env-var
# default. Without this, custom-namespace k8s installs used the wrong namespace
# on uninstall (YASHIGANI_NAMESPACE defaulted to "yashigani" while the actual
# namespace was e.g. "prod-yashigani").
_STATE_FILE="${SCRIPT_DIR}/docker/.yashigani-install-state"
_INSTALL_UID=""
_INSTALL_USER=""
# Multi-instance (3.0): the compose project read from the state file. Empty until
# the state file is parsed; feeds _PROJECT_PREFIX below. `|| true` guards the
# no-match case (legacy state files have no PROJECT= line) under set -euo pipefail.
_state_project=""
# MI-2: per-instance identity token from this tree's state file (empty for legacy).
_state_instance_id=""

if [ -f "$_STATE_FILE" ] && [ -r "$_STATE_FILE" ]; then
    _state_runtime="$(grep -E '^RUNTIME=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    _INSTALL_UID="$(grep -E '^INSTALL_UID=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    _INSTALL_USER="$(grep -E '^INSTALL_USER=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    # Multi-instance (3.0): the project name to tear down. cut -d= -f2- preserves
    # any '=' (project names never contain it, but be defensive). || true: legacy
    # state files predate this field — absent line leaves _state_project empty.
    _state_project="$(grep -E '^PROJECT=' "$_STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
    # MI-2 (authenticated lifecycle target): the per-instance identity token this
    # tree was installed with. Used to PROVE that a teardown targets the instance
    # this tree owns, rather than a sibling instance named via a free-form
    # --project string. Legacy state files have none → empty → backward-compat
    # single-instance behaviour (no binding to enforce). `|| true` for set -e.
    _state_instance_id="$(grep -E '^INSTANCE_ID=' "$_STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
    # #21 FIX: grep exits 1 when the pattern is absent (compose state files have
    # no NAMESPACE= or HELM_RELEASE= lines).  Under `set -euo pipefail` the
    # command substitution propagates the non-zero exit and the script aborts
    # silently before printing any error output — the customer sees nothing and
    # has to tear the stack down manually.  `|| true` guards each no-match path;
    # the variable is left empty and the k8s-only propagation block below is a
    # no-op for compose runtimes (correct behaviour).
    _state_namespace="$(grep -E '^NAMESPACE=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
    _state_helm_release="$(grep -E '^HELM_RELEASE=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
    if [ -z "$RUNTIME" ] && { [ "$_state_runtime" = "docker" ] || [ "$_state_runtime" = "podman" ] || [ "$_state_runtime" = "k8s" ]; }; then
        RUNTIME="$_state_runtime"
        log_info "Using runtime from install state file: $RUNTIME"
        [ -n "$_INSTALL_USER" ] && log_info "Install was performed by user: ${_INSTALL_USER} (UID: ${_INSTALL_UID:-unknown})"
    fi
    # Propagate k8s-specific values — only when state file was written by a k8s install
    # and the operator has not overridden via env var (honour explicit env over state file).
    if [ "$_state_runtime" = "k8s" ]; then
        if [ -n "$_state_namespace" ] && [ -z "${YASHIGANI_NAMESPACE:-}" ]; then
            YASHIGANI_NAMESPACE="$_state_namespace"
            log_info "Using namespace from install state file: $YASHIGANI_NAMESPACE"
        fi
        if [ -n "$_state_helm_release" ] && [ -z "${YASHIGANI_HELM_RELEASE:-}" ]; then
            YASHIGANI_HELM_RELEASE="$_state_helm_release"
            log_info "Using Helm release from install state file: $YASHIGANI_HELM_RELEASE"
        fi
    fi
fi

# Source 3: auto-detect (only when RUNTIME is still empty after state-file check).
if [ -z "$RUNTIME" ]; then
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        RUNTIME="podman"
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        RUNTIME="docker"
    else
        echo "ERROR: No container runtime found (tried podman, docker)." >&2
        echo "Install podman or docker and ensure the daemon/service is running." >&2
        exit 1
    fi
fi

# Source 4: validate the runtime value is one of the known strings.
case "$RUNTIME" in
  docker|podman|k8s) ;;
  *)
    printf 'ERROR: Unknown runtime %q — expected docker, podman, or k8s.\n' "$RUNTIME" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# RUNTIME_SUBTYPE detection
# ---------------------------------------------------------------------------
RUNTIME_SUBTYPE=""
_CALLER_UID="$(id -u)"

if [ "$RUNTIME" = "podman" ]; then
  if [ "$_CALLER_UID" = "0" ]; then
    RUNTIME_SUBTYPE="podman-rootful"
  else
    RUNTIME_SUBTYPE="podman-rootless"
  fi
elif [ "$RUNTIME" = "docker" ]; then
  # Docker Desktop detection: present on macOS or when docker info reports
  # the server name "docker-desktop" or context name "desktop-linux".
  _docker_os="$(uname -s)"
  _docker_context_name="$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo '')"
  _docker_server_name="$(docker info --format '{{.Name}}' 2>/dev/null || echo '')"
  if [ "$_docker_os" = "Darwin" ] \
     || [ "$_docker_context_name" = "desktop-linux" ] \
     || [ "$_docker_server_name" = "docker-desktop" ]; then
    RUNTIME_SUBTYPE="docker-desktop"
  else
    # Check for rootless Docker Engine: rootless daemon uses a user-level socket.
    _xdg_socket="${XDG_RUNTIME_DIR:-}/docker.sock"
    if [ -S "$_xdg_socket" ]; then
      RUNTIME_SUBTYPE="docker-engine-rootless"
    else
      RUNTIME_SUBTYPE="docker-engine"
    fi
  fi
elif [ "$RUNTIME" = "k8s" ]; then
  RUNTIME_SUBTYPE="k8s"
fi

COMPOSE="$RUNTIME compose"

# ===========================================================================
# BUG-UNINSTALL-SUDO-ROOTLESS guard
#
# When uninstall.sh is invoked via `sudo` AND the target runtime is rootless
# Podman, the script runs as root (UID 0) but the Podman containers live in
# the non-root user's namespace. Root's Podman sees ZERO containers — the
# script would report "nothing to clean" and exit 0 falsely, leaving the
# entire stack running.
#
# Detection:
#   - SUDO_USER is set (we were invoked via sudo)
#   - RUNTIME = podman
#   - Effective UID = 0 (we are root now)
#   - Install state file records the install was done by a non-root user
#     (or state file absent — we conservatively refuse on any rootless podman + sudo)
#
# Action: REFUSE with a clear error. Do NOT silently re-exec as SUDO_USER
# because that could re-invoke with wrong env (PATH, HOME, XDG_RUNTIME_DIR).
# The safe path is to tell the operator to re-run without sudo.
#
# Tiago directive 2026-05-26: separate paths for podman, docker, k8s.
# Maxine session 2026-05-26: root namespace saw ZERO containers during cycle 8 VM test.
# ===========================================================================
if [ "${SUDO_USER:-}" != "" ] && [ "$RUNTIME" = "podman" ] && [ "$_CALLER_UID" = "0" ]; then
  _install_owner="${_INSTALL_USER:-${SUDO_USER}}"
  printf '\n' >&2
  printf 'ERROR: uninstall.sh invoked via sudo against rootless Podman.\n' >&2
  printf '\n' >&2
  printf 'Rootless Podman containers live in user '"'"'%s'"'"''"'"'s namespace,\n' \
         "$_install_owner" >&2
  printf 'not root'"'"'s. Root'"'"'s Podman sees ZERO containers and uninstall would exit 0 falsely.\n' >&2
  printf '\n' >&2
  printf 'Re-run WITHOUT sudo as the install-owning user:\n' >&2
  printf '    bash uninstall.sh\n' >&2
  if [ "${_install_owner}" != "${SUDO_USER}" ]; then
    printf '\n' >&2
    printf 'If you need to run as that user:\n' >&2
    printf '    su - %s -c "bash %s"\n' "$_install_owner" "$0" >&2
  fi
  printf '\n' >&2
  exit 1
fi

# ===========================================================================
# Docker Engine rootless — same namespace-mismatch risk.
#
# When running rootless Docker Engine and invoked via sudo, the root user
# talks to the system Docker socket (/var/run/docker.sock) which is a
# different daemon from the user's rootless socket. Refuse with same class
# of error.
# ===========================================================================
if [ "${SUDO_USER:-}" != "" ] && [ "$RUNTIME_SUBTYPE" = "docker-engine-rootless" ] && [ "$_CALLER_UID" = "0" ]; then
  _install_owner="${_INSTALL_USER:-${SUDO_USER}}"
  printf '\n' >&2
  printf 'ERROR: uninstall.sh invoked via sudo against rootless Docker Engine.\n' >&2
  printf '\n' >&2
  printf 'Rootless Docker containers live in user '"'"'%s'"'"''"'"'s namespace.\n' \
         "$_install_owner" >&2
  printf 'Re-run WITHOUT sudo as the install-owning user:\n' >&2
  printf '    bash uninstall.sh\n' >&2
  printf '\n' >&2
  exit 1
fi

# ===========================================================================
# Banner
# ===========================================================================
echo "=== Yashigani Uninstaller ==="
echo "Runtime:     $RUNTIME"
echo "Subtype:     ${RUNTIME_SUBTYPE}"
echo "Caller UID:  ${_CALLER_UID} ($(id -un))"
[ -n "$_INSTALL_USER" ] && echo "Install user: ${_INSTALL_USER} (UID: ${_INSTALL_UID:-unknown})"
echo ""

# ===========================================================================
# MI-4 (step-up on destructive lifecycle ops / YSG-RISK-061)
# ---------------------------------------------------------------------------
# Uninstall is a privileged mutation. The shared step-up gate lives in
# src/yashigani/auth/stepup.py (Tom's surface) and is enforced on the API/WebUI
# path that triggers a lifecycle op: that path performs a fresh TOTP step-up and
# passes the resulting token here via --stepup-token / YASHIGANI_STEPUP_TOKEN.
#
# Host-shell path (operator runs uninstall.sh directly): no FastAPI session
# exists, so we cannot call the Python gate. We require an explicit step-up proof
# nonetheless so an unattended/automated destructive run cannot silently skip the
# step-up that the product mandates for this action:
#   * --stepup-token / YASHIGANI_STEPUP_TOKEN present  → accepted (API-minted proof),
#   * interactive TTY + --i-have-stepped-up            → accepted (operator ack),
#   * interactive TTY without --yes                    → prompt for the ack inline,
#   * unattended (--yes) with neither token nor ack    → REFUSE (fail-closed).
#
# DEPENDENCY FLAG: Tom's shared gate is to expose a named `privileged_mutation`
# entry point + a token-mint/verify contract. Until that lands, this validates
# *presence* of a step-up proof (not its cryptographic freshness). When the gate
# lands, wire token verification here (verify the token against the running
# instance's step-up secret) — do NOT duplicate the gate logic.
# ===========================================================================
_require_stepup_mi4() {
    # Token supplied (API-minted or operator-provided) → accept. Cryptographic
    # verification is deferred to Tom's gate (flagged above); presence is enforced.
    if [ -n "${STEPUP_TOKEN:-}" ]; then
        log_info "MI-4: step-up token supplied — privileged mutation authorised."
        return 0
    fi
    # Interactive operator acknowledgement (only on a real TTY — never honoured in
    # an unattended pipeline where stdin is not a terminal).
    if [ "${STEPUP_ACK:-false}" = "true" ] && [ -t 0 ]; then
        log_info "MI-4: interactive operator step-up acknowledgement accepted."
        return 0
    fi
    # Interactive TTY, no --yes: prompt for the acknowledgement inline.
    if [ -t 0 ] && [ "$YES" != "true" ]; then
        printf 'MI-4 step-up: confirm you have completed a fresh TOTP step-up for this destructive action.\n'
        printf 'Type STEPPED-UP to proceed: '
        read -r _su_ack || _su_ack=""
        if [ "$_su_ack" = "STEPPED-UP" ]; then
            log_info "MI-4: interactive step-up confirmation accepted."
            return 0
        fi
        log_error "MI-4: step-up not confirmed — aborting destructive lifecycle op."
        exit 1
    fi
    # Unattended (no TTY or --yes) with no token and no ack → fail closed.
    log_error "MI-4 safety stop: destructive lifecycle op requires step-up proof."
    log_error "  Supply --stepup-token=<value> (or YASHIGANI_STEPUP_TOKEN) minted by"
    log_error "  the admin API after a fresh TOTP step-up, or run interactively with"
    log_error "  --i-have-stepped-up. Refusing to proceed unattended without step-up."
    exit 1
}
# Only gate genuinely destructive runs: a volume-removing teardown, or any teardown
# of a non-legacy named instance (multi-instance hosts — tearing down the wrong one
# is the high-impact mistake). A plain stop of the single legacy instance keeps the
# existing UX. k8s teardown is also destructive — gate it the same way.
if [ "$REMOVE_VOLUMES" = "true" ] \
   || { [ -n "${_PROJECT_PREFIX:-}" ] && [ "${_PROJECT_PREFIX}" != "docker" ]; } \
   || [ "$RUNTIME" = "k8s" ]; then
    _require_stepup_mi4
fi

if [ "$REMOVE_VOLUMES" = "true" ]; then
    echo "WARNING: --remove-volumes will PERMANENTLY DELETE all data:"
    echo "  - Redis data (sessions, RBAC, rate-limit state)"
    echo "  - Audit logs"
    echo "  - Ollama models (large download on next start)"
    echo "  - Grafana/Prometheus metrics history"
    echo ""
    if [ "$YES" = "false" ]; then
        read -rp "Type 'yes' to confirm permanent data deletion: " confirm
        if [ "$confirm" != "yes" ]; then
            echo "Cancelled. No data was deleted."
            exit 0
        fi
    else
        echo "Skipping confirmation (--yes supplied)."
    fi
    DOWN_ARGS="--volumes --remove-orphans"
else
    echo "Stopping services (volumes preserved)."
    echo "Use --remove-volumes to also delete all data."
    DOWN_ARGS="--remove-orphans"
fi

# Step 1: Remove auto-start units BEFORE stopping containers.
# Disabling first prevents a reboot mid-uninstall from re-starting the stack.
# BUG-REBOOT-NO-AUTO-START / YSG-RISK-046
_remove_auto_start

# ===========================================================================
# Step 2: Environment stub setup for compose down
#
# BUG-UNINSTALL-NO-ENV + BUG-UNINSTALL-PARTIAL-ENV:
# docker-compose.yml uses ${VAR:?} declarations. Without a populated .env,
# compose refuses to parse the file and exits non-zero. Fix: stub missing
# vars for the duration of this shell only.
#
# This setup is shared across all runtime subtypes that use compose.
# K8s path does not use compose and skips this block.
# ===========================================================================
_ENV_FILE="${SCRIPT_DIR}/docker/.env"
_STUB_ENV_CREATED="false"
_ENV_READABLE="true"
_COMPOSE_ENV_ARGS=""

if [ "$RUNTIME_SUBTYPE" != "k8s" ]; then
  # Cross-UID guard: if .env exists but is owned by a different UID, skip parsing.
  if [ -f "$_ENV_FILE" ] && [ ! -r "$_ENV_FILE" ]; then
      _ENV_READABLE="false"
      echo "  [warn] docker/.env present but unreadable (cross-UID ownership) — skipping partial-env parse (BUG-UNINSTALL-PARTIAL-ENV cross-UID)"
  fi

  if [ ! -f "$_ENV_FILE" ]; then
      echo "  [info] docker/.env not found — writing uninstall stub (BUG-UNINSTALL-NO-ENV)"
      cat > "$_ENV_FILE" <<'UNINSTALL_STUB_EOF'
# !! UNINSTALL STUB — DO NOT USE FOR INSTALL !!
# Written by uninstall.sh when docker/.env was absent (BUG-UNINSTALL-NO-ENV).
# Removed automatically after compose down completes.
# All values are non-functional placeholders to satisfy compose parse-time
# ${VAR:?} declarations in docker/docker-compose.yml.
YASHIGANI_TLS_DOMAIN=uninstall-stub.local
PROMETHEUS_BASICAUTH_HASH=uninstall-stub-hash
CADDY_INTERNAL_HMAC=uninstall-stub-hmac
UPSTREAM_MCP_URL=http://uninstall-stub-upstream:9999
OWUI_SECRET_KEY=uninstall-stub-owui-key
YASHIGANI_DB_AES_KEY=uninstall-stub-aes-key
UNINSTALL_STUB_EOF
      _STUB_ENV_CREATED="true"
  fi

  # Ensure stub is removed on exit (success, failure, or signal).
  _cleanup_stub() {
      if [ "$_STUB_ENV_CREATED" = "true" ] && [ -f "$_ENV_FILE" ]; then
          rm -f "$_ENV_FILE"
          echo "  [info] uninstall stub docker/.env removed (BUG-UNINSTALL-NO-ENV)"
      fi
  }
  trap _cleanup_stub EXIT

  # Phase B: export stub values for any :? var absent from process env + .env.
  _PARTIAL_ENV_STUBBED=""
  if [ -f "$COMPOSE_FILE" ]; then
      _required_vars="$(grep -oE '\$\{[A-Z_]+:\?' "$COMPOSE_FILE" 2>/dev/null \
          | sed 's/^\${//;s/:?$//' \
          | sort -u || true)"
      while IFS= read -r _var; do
          [ -z "$_var" ] && continue
          if [ -n "${!_var+x}" ] && [ -n "${!_var}" ]; then
              continue
          fi
          if [ "$_ENV_READABLE" = "true" ] && [ -f "$_ENV_FILE" ] && grep -qE "^${_var}=.+" "$_ENV_FILE" 2>/dev/null; then
              continue
          fi
          export "${_var}=__yashigani_uninstall_stub__"
          _PARTIAL_ENV_STUBBED="${_PARTIAL_ENV_STUBBED} ${_var}"
      done <<< "$_required_vars"
  fi
  if [ -n "$_PARTIAL_ENV_STUBBED" ]; then
      echo "  [info] Partial docker/.env — stubbed missing vars for compose parse:${_PARTIAL_ENV_STUBBED}"
      echo "  [info] docker/.env on disk is unchanged."
  fi

  # Override compose .env load when file is cross-UID unreadable.
  if [ "$_ENV_READABLE" = "false" ]; then
      _COMPOSE_ENV_ARGS="--env-file /dev/null"
  fi
fi

# ===========================================================================
# Project prefix for container/volume enumeration
# ---------------------------------------------------------------------------
# Multi-instance (3.0 — scoping-draft §4a): the compose project that scopes the
# container/volume/network names to tear down. Precedence:
#   1. --project=<name> flag (operator explicitly targets one instance)
#   2. PROJECT from the install state file (the install recorded its own name)
#   3. "docker" (legacy single-instance default — pre-3.0 installs had no PROJECT)
# This makes `uninstall.sh --project apac` tear down exactly that named instance
# while leaving every other instance on a shared host untouched.
# ===========================================================================
if [ -n "${PROJECT_FLAG:-}" ]; then
    _PROJECT_PREFIX="$PROJECT_FLAG"
    log_info "Targeting instance project: ${_PROJECT_PREFIX} (from --project flag)"
elif [ -n "${_state_project:-}" ]; then
    _PROJECT_PREFIX="$_state_project"
    log_info "Targeting instance project: ${_PROJECT_PREFIX} (from install state file)"
else
    _PROJECT_PREFIX="docker"
fi
# ===========================================================================
# MI-2 (authenticated lifecycle target / YSG-RISK-061)
# ---------------------------------------------------------------------------
# A bare --project string must NOT let an operator tear down a SIBLING instance
# from the wrong install tree. Bind the teardown target to this tree's recorded
# identity: if the running gateway container for the resolved project carries a
# com.yashigani.instance-id label that DIFFERS from the INSTANCE_ID in THIS tree's
# state file, refuse — this tree is not authoritative for that instance.
#
# Enforced ONLY when BOTH tokens are present:
#   * this tree's state file has INSTANCE_ID  (3.0+ install), AND
#   * the running container exposes a non-empty instance-id label.
# Legacy installs (no token either side) fall through unchanged (single-instance
# backward-compat). A missing/stopped container (no label to read) is NOT a
# mismatch — teardown of an already-stopped instance from its own tree is allowed.
# ===========================================================================
_mi2_validate_target() {
  # Only meaningful for compose runtimes (k8s isolates by namespace/release).
  case "$RUNTIME" in docker|podman) : ;; *) return 0 ;; esac
  # Nothing to bind to if this tree predates MI-2.
  [ -n "${_state_instance_id:-}" ] || return 0
  local _rt
  _rt="$(command -v "$RUNTIME" 2>/dev/null || true)"
  [ -n "$_rt" ] || return 0

  # Read the instance-id label off the running gateway container for the target
  # project. Try both compose-project label keys (docker/podman). Read-only.
  local _running_id="" _lk _cid
  for _lk in "com.docker.compose.project" "io.podman.compose.project"; do
    _cid="$("$_rt" ps -q \
        --filter "label=${_lk}=${_PROJECT_PREFIX}" \
        --filter "name=gateway" 2>/dev/null | head -n1 || true)"
    if [ -n "$_cid" ]; then
      _running_id="$("$_rt" inspect --format '{{ index .Config.Labels "com.yashigani.instance-id" }}' "$_cid" 2>/dev/null | tr -d '\r\n[:space:]' || true)"
      break
    fi
  done

  # No running container / no label → not a mismatch (allow self-teardown of a
  # stopped instance from its own tree; the project-prefix scoping still applies).
  [ -n "$_running_id" ] || return 0

  if [ "$_running_id" != "$_state_instance_id" ]; then
    log_error "MI-2 safety stop: refusing to tear down project '${_PROJECT_PREFIX}'."
    log_error "  The running instance's identity token does not match this install tree's."
    log_error "  running com.yashigani.instance-id=${_running_id}"
    log_error "  this tree INSTANCE_ID=${_state_instance_id}"
    log_error "  You are operating from the wrong instance's directory. Run uninstall.sh"
    log_error "  from the install tree that owns project '${_PROJECT_PREFIX}'."
    exit 1
  fi
  log_info "MI-2: lifecycle target authenticated (instance-id matches install tree)."
}
_mi2_validate_target

# Export COMPOSE_PROJECT_NAME so the graceful `compose down` in the teardown
# functions targets THIS project (compose otherwise derives the project from the
# compose-file directory name, "docker", and would skip a renamed instance —
# the label-based belt-and-braces passes would then do all the work). Both Docker
# and Podman compose honour COMPOSE_PROJECT_NAME. Only meaningful for compose
# runtimes; harmless on k8s (helm/kubectl ignore it).
export COMPOSE_PROJECT_NAME="$_PROJECT_PREFIX"

# ===========================================================================
# Step 3: Runtime-specific teardown
# ===========================================================================
case "$RUNTIME_SUBTYPE" in
  podman-rootless)
    _teardown_podman_rootless
    ;;
  podman-rootful)
    _teardown_podman_rootful
    ;;
  docker-desktop)
    _teardown_docker_desktop
    ;;
  docker-engine|docker-engine-rootless)
    _teardown_docker_engine
    ;;
  k8s)
    _teardown_k8s
    ;;
  *)
    # Fallback: should not be reached given validation above, but be safe.
    printf 'ERROR: Unhandled runtime subtype %q\n' "$RUNTIME_SUBTYPE" >&2
    exit 1
    ;;
esac

# ===========================================================================
# Step 4: Named volume cleanup (compose-runtime paths only; k8s uses PVCs)
# ===========================================================================
if [ "$REMOVE_VOLUMES" = "true" ] && [ "$RUNTIME_SUBTYPE" != "k8s" ]; then
    # ---------------------------------------------------------------------------
    # Explicit per-volume rm — UNINSTALL-LEAVES-VOLUMES (#8)
    #
    # podman-compose ≤1.3.x ignores --volumes for named volumes.
    # docker compose ≥2.x honours it, but the explicit loop is idempotent and
    # safe on both runtimes: `volume rm` exits 0 when the volume doesn't exist.
    # ---------------------------------------------------------------------------
    echo "=== Removing named volumes (UNINSTALL-LEAVES-VOLUMES #8 explicit loop) ==="
    _removed=0
    _skipped=0
    for _vol in "${_CANONICAL_VOLUMES[@]}"; do
        _full="${_PROJECT_PREFIX}_${_vol}"
        if "$RUNTIME" volume inspect "$_full" >/dev/null 2>&1; then
            if "$RUNTIME" volume rm "$_full" >/dev/null 2>&1; then
                echo "  [removed] $_full"
                _removed=$(( _removed + 1 ))
            else
                echo "  [WARN] failed to remove $_full (in use?)" >&2
            fi
        else
            echo "  [skip]    $_full (not present)"
            _skipped=$(( _skipped + 1 ))
        fi
    done
    echo "Volume cleanup complete: ${_removed} removed, ${_skipped} not present."

    # ---------------------------------------------------------------------------
    # Straggler volume retry pass.
    #
    # After the container teardown and initial volume rm, re-check all canonical
    # volumes. A container that was respawned by restart-policy=always between the
    # belt-and-braces loop and the volume rm may have held the volume reference.
    # Now that all containers are confirmed gone (per _assert_no_containers_remain),
    # any still-present volumes can be freed.
    # ---------------------------------------------------------------------------
    echo "=== Volume retry pass (straggler volumes) ==="
    _retry_removed=0
    for _vol in "${_CANONICAL_VOLUMES[@]}"; do
        _full="${_PROJECT_PREFIX}_${_vol}"
        if "$RUNTIME" volume inspect "$_full" >/dev/null 2>&1; then
            if "$RUNTIME" volume rm "$_full" >/dev/null 2>&1; then
                echo "  [removed] (retry) ${_full}"
                _retry_removed=$(( _retry_removed + 1 ))
            else
                echo "  [WARN] (retry) failed to remove ${_full}" >&2
            fi
        fi
    done
    if [ "$_retry_removed" -gt 0 ]; then
        echo "  Volume retry: ${_retry_removed} additional volume(s) removed."
    else
        echo "  [ok] No straggler volumes found."
    fi

    # ---------------------------------------------------------------------------
    # Final volume assertion — closes the volume-parallel of the container
    # silent-exit-0 hole. Any canonical volume that still exists after two
    # removal passes is a failure. Exit 1 with remediation instructions.
    # ---------------------------------------------------------------------------
    _assert_no_volumes_remain "$RUNTIME" "$_PROJECT_PREFIX"
    echo "=== Volume assertion passed — all canonical volumes removed. ==="
fi

# ---------------------------------------------------------------------------
# Canonical network cleanup — BUG-UNINSTALL-LEAVES-NETWORKS-2026-05-26.
# Su's refactor (23755da) treated network teardown as compose-down territory;
# but `podman-compose down` does NOT always remove user-defined networks
# (varies by version + restart-policy state). Result: post-uninstall enumeration
# shows containers=0 volumes=0 BUT networks=7 — operator sees stale networks
# in `podman network ls`, gets confused on re-install (false "already exists").
# Fix: explicit network removal of every canonical compose project network,
# regardless of REMOVE_VOLUMES flag (networks hold no data; safe to remove).
# Final assertion exits 1 if any survive.
# ---------------------------------------------------------------------------
_PROJECT_PREFIX="${_PROJECT_PREFIX:-docker}"
_CANONICAL_NETWORKS="edge caddy_internal data obs langflow_isolated letta_isolated openclaw_isolated demo_mcp_isolated extractor_svc"

echo "=== Canonical network cleanup ==="
_net_removed=0
_net_skipped=0
_net_failed=0
for _net in $_CANONICAL_NETWORKS; do
    _full="${_PROJECT_PREFIX}_${_net}"
    if "$RUNTIME" network inspect "$_full" >/dev/null 2>&1; then
        if "$RUNTIME" network rm "$_full" >/dev/null 2>&1; then
            echo "  [removed] $_full"
            _net_removed=$(( _net_removed + 1 ))
        else
            echo "  [WARN] network rm failed: $_full (in-use by foreign container?)" >&2
            _net_failed=$(( _net_failed + 1 ))
        fi
    else
        _net_skipped=$(( _net_skipped + 1 ))
    fi
done
echo "Network cleanup: ${_net_removed} removed, ${_net_skipped} not present, ${_net_failed} failed."

# Final network assertion.
_residual_networks=""
for _net in $_CANONICAL_NETWORKS; do
    _full="${_PROJECT_PREFIX}_${_net}"
    if "$RUNTIME" network inspect "$_full" >/dev/null 2>&1; then
        _residual_networks="${_residual_networks}${_full}\n"
    fi
done
if [ -n "$_residual_networks" ]; then
    echo "" >&2
    echo "ERROR: ${_net_failed} canonical network(s) survived removal:" >&2
    printf '%b' "$_residual_networks" | sed 's/^/      /' >&2
    echo "" >&2
    echo "Likely cause: a non-yashigani container is attached to one of these networks." >&2
    echo "Manual remediation:" >&2
    echo "  ${RUNTIME} network inspect <name>  # find what's attached" >&2
    echo "  ${RUNTIME} network rm <name>       # after detaching foreign containers" >&2
    echo "" >&2
    echo "Yashigani uninstall INCOMPLETE — network residual. Exit 1." >&2
    exit 1
fi
echo "=== Network assertion passed — all canonical networks removed. ==="

# ---------------------------------------------------------------------------
# ROOTLESS-CDI-002 (2026-06-27): sweep stale CNI config FILES.
# On the CNI backend, rootless podman reads ~/.config/cni/net.d/*.conflist.
# `network rm` usually deletes the matching .conflist, but orphaned project
# configs accumulate across install/teardown cycles and POISON the next install:
# a leftover *.conflist referencing a missing plugin (e.g. 'dnsname') wedges
# every container at create-time, so the stack hangs half-up. Removing networks
# alone is NOT enough — the config files must go too. Remove OUR project's
# leftover .conflist here; list foreign ones as WARN (never auto-remove).
# ---------------------------------------------------------------------------
_cni_dir="${HOME}/.config/cni/net.d"
if [ -d "$_cni_dir" ] && [ -n "${_PROJECT_PREFIX:-}" ]; then
    echo "=== CNI config-file cleanup (${_cni_dir}) ==="
    _cni_removed=0
    for _cf in "${_cni_dir}/${_PROJECT_PREFIX}_"*.conflist "${_cni_dir}/ringfence_"*.conflist; do
        [ -e "$_cf" ] || continue
        rm -f "$_cf" && { echo "  [removed] $(basename "$_cf")"; _cni_removed=$(( _cni_removed + 1 )); }
    done
    echo "  CNI config files removed: ${_cni_removed}"
    _cni_foreign="$(ls "${_cni_dir}"/*.conflist 2>/dev/null | grep -vE "/(87-podman|${_PROJECT_PREFIX}_|ringfence_)" || true)"
    if [ -n "$_cni_foreign" ]; then
        echo "  [WARN] foreign CNI configs remain (not this project — review/remove if unused):" >&2
        echo "$_cni_foreign" | sed 's/^/    /' >&2
        echo "    On the CNI backend a stale config (missing plugin) can wedge installs." >&2
    fi
fi

# ---------------------------------------------------------------------------
# J12 FIX (Ava 2026-05-30): remove ringfence_<agent> networks created by
# `yashigani onboard` (Shape-C MCP agents).  These networks are NOT in the
# hardcoded _CANONICAL_NETWORKS list above because they are dynamically named
# at onboard time (ringfence_git, ringfence_filesystem, etc.).
#
# Discovery: `docker/podman network ls --filter name=ringfence_` lists all
# networks whose name contains "ringfence_".  We then remove each one.
#
# The assertion below logs residuals as WARN (not exit-1): a ringfence network
# may survive removal if a non-yashigani container joined it.  The operator
# is told exactly what to do.  We do not block uninstall for onboard residuals.
# ---------------------------------------------------------------------------
echo "=== Ringfence network cleanup (J12) ==="
_ringfence_removed=0
_ringfence_failed=0

# Use process substitution compatible with bash 3.2 (no readarray/mapfile).
while IFS= read -r _rfnet; do
    if [ -z "$_rfnet" ]; then
        continue
    fi
    if "$RUNTIME" network rm "$_rfnet" >/dev/null 2>&1; then
        echo "  [removed] ringfence: $_rfnet"
        _ringfence_removed=$(( _ringfence_removed + 1 ))
    else
        echo "  [WARN] ringfence network rm failed: $_rfnet (may be in use)" >&2
        _ringfence_failed=$(( _ringfence_failed + 1 ))
    fi
done < <("$RUNTIME" network ls --filter "name=ringfence_" --format "{{.Name}}" 2>/dev/null || true)

if [ "$_ringfence_removed" -gt 0 ] || [ "$_ringfence_failed" -gt 0 ]; then
    echo "Ringfence network cleanup: ${_ringfence_removed} removed, ${_ringfence_failed} failed."
    if [ "$_ringfence_failed" -gt 0 ]; then
        echo "  [WARN] Some ringfence networks could not be removed (in use by a foreign container?)." >&2
        echo "  Manual remediation:" >&2
        echo "    ${RUNTIME} network ls --filter name=ringfence_   # list survivors" >&2
        echo "    ${RUNTIME} network rm <name>                     # after detaching foreign containers" >&2
    fi
else
    echo "  [ok] No ringfence networks found."
fi

# ---------------------------------------------------------------------------
# BUG-3-MULTI-USER-INSTALL-PKI / BACKLOG-V240-006: wipe docker/secrets/ on
# --remove-volumes (sudo-free, container-fallback — Iris+Laura 2026-05-21).
#
# Symptom: uninstall.sh --remove-volumes leaves docker/secrets/ populated with
# PKI files owned by the install user. A subsequent install from a different
# user (e.g. root vs tom) fails because the new installer cannot overwrite
# files it does not own.
#
# Fix: three-tier fallback (no sudo):
#   1. Direct rm -rf (same-user / root caller — common clean-install case)
#   2. podman unshare rm -rf (Podman rootless path; lighter than container)
#   3. Ephemeral container as UID 0 (required for mixed-UID secrets ownership:
#      maxine, root, ava, 472, 70, 10001, dnsmasq). --pull=never first;
#      pull fallback for airgap/post-prune paths.
#   HARD WARN if all fail — operator told exactly what to do; never silent.
#
# _ALPINE_IMAGE: hoisted here so it is available to BOTH the secrets-wipe
# block (BACKLOG-V240-006) and the bind-mount cleanup block (BACKLOG-V240-003)
# below. MUST match install.sh _alpine_image — co-rotate on any digest update.
# Search: grep -n "_ALPINE_IMAGE\|_alpine_image" uninstall.sh install.sh
# ---------------------------------------------------------------------------
# Alpine digest: MUST match install.sh _alpine_image (SIB-2D-02 co-rotation).
_ALPINE_IMAGE="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

if [ "$REMOVE_VOLUMES" = "true" ] && [ "$RUNTIME_SUBTYPE" != "k8s" ]; then
    _secrets_dir="${SCRIPT_DIR}/docker/secrets"
    # Path-validation guard: only proceed if the resolved path is exactly canonical.
    if [ "${_secrets_dir}" != "${SCRIPT_DIR}/docker/secrets" ]; then
        echo "  [WARN] docker/secrets path resolved unexpectedly (${_secrets_dir}) — skipping PKI wipe for safety" >&2
    elif [ ! -d "${_secrets_dir}" ]; then
        echo "  [skip] docker/secrets/ does not exist — nothing to wipe"
    else
        echo "Removing PKI secrets — fresh install will regenerate keys + admin credentials (BUG-3-MULTI-USER-INSTALL-PKI)"
        _secrets_wiped=false

        # Tier 1: direct rm (same-user / root — common clean-install case)
        if rm -rf "${_secrets_dir:?}/"* "${_secrets_dir:?}"/.[!.]* "${_secrets_dir:?}"/..?* 2>/dev/null; then
            echo "  [removed] docker/secrets/* — direct rm reported success"
            _secrets_wiped=true
        fi

        # NEW-BUG-E FIX (Ava 2026-05-30): "rm reported success" ≠ "files are gone".
        # On rootless Podman, secrets_dir contains files owned by subuid-remapped
        # UIDs (e.g. UID 101000).  host-side rm exits 0 on glob-expand-to-nothing
        # even when files remain.  Container-fallback rm also exits 0 (due to
        # '; true') but cannot delete subuid-remapped files without :U.
        # Fix: verify the directory is actually empty after EACH tier before
        # declaring success.  If residuals remain, proceed to the next tier.
        _secrets_verify() {
            # Returns 0 (success) when secrets_dir has no remaining files.
            local _d="$1"
            # NEW-BUG-E FIX (cascade audit 2026-05-30): the old expression
            #   find DIR -maxdepth 1 -not -name .
            # ALWAYS returns at least one line — the directory's own absolute
            # path — because -not -name . only excludes the "." entry returned
            # when find descends into the dir, NOT the initial DIR argument at
            # depth 0.  On BSD/macOS find, `find /a/b -maxdepth 1 -not -name .`
            # always outputs "/a/b" even when the directory is empty.
            # This made _secrets_verify always return 1 (fail), so Tier-1 and
            # Tier-2 always appeared to fail and all three tiers ran every time.
            # Fix: use -mindepth 1 which truly restricts to children only.
            local _found
            _found="$(find "${_d}" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)"
            [ -z "$_found" ]
        }

        if [ "$_secrets_wiped" = "true" ] && ! _secrets_verify "${_secrets_dir}"; then
            echo "  [WARN] Direct rm exited 0 but files remain (subuid-remapped UIDs) — proceeding to podman unshare tier" >&2
            _secrets_wiped=false
        fi

        # Tier 2: podman unshare rm (rootless Podman — namespace-root can delete subuid files)
        if [ "$_secrets_wiped" = "false" ] && [ "$RUNTIME" = "podman" ] && command -v podman >/dev/null 2>&1; then
            if podman unshare sh -c "rm -rf '${_secrets_dir:?}'/* '${_secrets_dir:?}'/.[!.]* '${_secrets_dir:?}'/..?* 2>/dev/null; true" 2>/dev/null; then
                if _secrets_verify "${_secrets_dir}"; then
                    echo "  [removed] docker/secrets/* — podman unshare rm succeeded"
                    _secrets_wiped=true
                else
                    echo "  [WARN] podman unshare rm exited 0 but files remain — proceeding to container tier" >&2
                fi
            fi
        fi

        # Tier 3: ephemeral container with :U flag (maps container UID 0 to subuid range)
        # NEW-BUG-E FIX: add :U so Podman remaps container UID 0 → caller's subuid root,
        # allowing rm to delete files owned by any UID in the caller's subuid range.
        if [ "$_secrets_wiped" = "false" ]; then
            _run_container_rm() {
                local _pull_flag="$1"  # "--pull=never" or ""
                if [ "$RUNTIME" = "podman" ]; then
                    # :U remaps; :Z SELinux label
                    "$RUNTIME" run --rm ${_pull_flag:+"$_pull_flag"} \
                        --volume "${_secrets_dir}:/t:rw,U,Z" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/* /t/.[!.]* /t/..?* 2>/dev/null; true' 2>/dev/null
                else
                    # Docker: run as UID 0 inside container (root in default bridge)
                    "$RUNTIME" run --rm ${_pull_flag:+"$_pull_flag"} \
                        --user 0:0 \
                        --volume "${_secrets_dir}:/t:rw" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/* /t/.[!.]* /t/..?* 2>/dev/null; true' 2>/dev/null
                fi
            }
            if _run_container_rm "--pull=never" || _run_container_rm ""; then
                if _secrets_verify "${_secrets_dir}"; then
                    echo "  [removed] docker/secrets/* — container-fallback rm succeeded"
                    _secrets_wiped=true
                else
                    echo "  [WARN] container-fallback rm exited 0 but ${_secrets_dir} still has files" >&2
                fi
            fi
        fi

        if [ "$_secrets_wiped" = "false" ]; then
            # Final residual check — count files for the operator.
            _residual_count="$(find "${_secrets_dir}" -maxdepth 1 -not -name . 2>/dev/null | wc -l | tr -d ' ')"
            printf '[ERROR] secrets/ cleanup failed — %s file(s) remain:\n' "${_residual_count}" >&2
            printf '[ERROR]   rm -rf '"'"'%s'"'"'  (as root or file owner)\n' "${_secrets_dir}" >&2
            printf '[ERROR]   or: podman unshare rm -rf '"'"'%s'"'"'\n' "${_secrets_dir}" >&2
            printf '[ERROR] Fresh install by a different user will fail until secrets/ is clean.\n' >&2
        fi

        rmdir "${_secrets_dir}" 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Bind-mount directory cleanup — chown-fallback (BACKLOG-V240-003)
#
# install.sh chowns docker/{data,certs,logs} to UID 1001 (or subuid-mapped
# equivalent) so PKI/service containers can write to them.  After uninstall the
# operator cannot `rm -rf` those dirs from the host without privilege
# escalation (EPERM from non-root shell).
#
# Fix: attempt host-side rm -rf first; on failure use:
#   Podman rootless → podman unshare rm -rf (no daemon root needed)
#   Podman rootless fallback / Docker → ephemeral container (mirrors the
#     cycle-3 install-side chown pattern at install.sh:_alpine_image,
#     GO'd by Laura 2026-05-21).
#
# Alpine digest: SAME pin as install.sh _alpine_image variable.
# CO-ROTATION NOTE (SIB-2D-02): when install.sh rotates the alpine digest,
# update _ALPINE_IMAGE here in the same commit.
# Search: grep -n "_ALPINE_IMAGE\|_alpine_image" uninstall.sh install.sh
# ---------------------------------------------------------------------------
if [ "$REMOVE_VOLUMES" = "true" ] && [ "$RUNTIME_SUBTYPE" != "k8s" ]; then
    echo "=== Bind-mount directory cleanup (BACKLOG-V240-003) ==="
    for _bm_dir in \
            "${SCRIPT_DIR}/docker/data" \
            "${SCRIPT_DIR}/docker/certs" \
            "${SCRIPT_DIR}/docker/logs" \
            "${SCRIPT_DIR}/docker/wazuh-mtls"; do
        [ -d "$_bm_dir" ] || { echo "  [skip] $_bm_dir (absent)"; continue; }
        if rm -rf "$_bm_dir" 2>/dev/null; then
            echo "  [removed] $_bm_dir"
        else
            echo "  [info]   $_bm_dir: host rm failed (likely chowned to UID 1001) — using container fallback"
            if [ "$RUNTIME" = "podman" ]; then
                if podman unshare rm -rf "$_bm_dir" 2>/dev/null; then
                    echo "  [removed] $_bm_dir (podman unshare)"
                else
                    if podman run --rm \
                           -v "${_bm_dir}:/t:rw" \
                           "$_ALPINE_IMAGE" rm -rf /t 2>/dev/null \
                       && rm -rf "$_bm_dir" 2>/dev/null; then
                        echo "  [removed] $_bm_dir (podman container fallback)"
                    else
                        echo "  [WARN] Cannot remove $_bm_dir" >&2
                        echo "  [WARN] Manual cleanup: podman unshare rm -rf '$_bm_dir'" >&2
                    fi
                fi
            else
                if "$RUNTIME" run --rm \
                       -v "${_bm_dir}:/t" \
                       --user 1001:1001 \
                       "$_ALPINE_IMAGE" \
                       sh -c 'rm -rf /t/*' 2>/dev/null \
                   && rm -rf "$_bm_dir" 2>/dev/null; then
                    echo "  [removed] $_bm_dir (docker container fallback)"
                else
                    echo "  [WARN] Cannot remove $_bm_dir" >&2
                    echo "  [WARN] Manual cleanup: sudo rm -rf '$_bm_dir'" >&2
                fi
            fi
        fi
    done
fi

# ---------------------------------------------------------------------------
# Dangling / anonymous volume prune — ANON-VOL-LEAK
#
# Compose may create anonymous volumes for tmpfs-backed service paths or
# for volumes not listed in the top-level `volumes:` section (e.g. volumes
# declared in an opt-in compose override like docker-compose.wazuh.yml that
# were not started via the primary compose file). These have SHA-like names
# and are NOT cleaned up by the named-volume loop above.
# ---------------------------------------------------------------------------
if [ "$REMOVE_VOLUMES" = "true" ] && [ "$RUNTIME_SUBTYPE" != "k8s" ]; then
    echo "=== Dangling volume prune (ANON-VOL-LEAK) ==="
    _dangling_pruned=0

    if [ "$RUNTIME" = "podman" ]; then
        _dangling_ids="$("$RUNTIME" volume ls --noheading -q --filter dangling=true \
            --filter "label=io.podman.compose.project=${_PROJECT_PREFIX}" 2>/dev/null || true)"
        if [ -z "$_dangling_ids" ]; then
            _dangling_ids="$("$RUNTIME" volume ls --noheading -q --filter dangling=true 2>/dev/null \
                | grep -E "^[0-9a-f]{64}$" || true)"
        fi
        if [ -n "$_dangling_ids" ]; then
            while IFS= read -r _vid; do
                [ -z "$_vid" ] && continue
                if "$RUNTIME" volume rm "$_vid" >/dev/null 2>&1; then
                    echo "  [removed] dangling volume: ${_vid}"
                    _dangling_pruned=$(( _dangling_pruned + 1 ))
                else
                    echo "  [skip]    dangling volume not removable (in use?): ${_vid}" >&2
                fi
            done <<< "$_dangling_ids"
        fi
    elif [ "$RUNTIME" = "docker" ]; then
        _docker_prune_out="$("$RUNTIME" volume prune \
            --filter "label=com.docker.compose.project=${_PROJECT_PREFIX}" \
            -f 2>/dev/null || true)"
        if echo "$_docker_prune_out" | grep -q "Total reclaimed space"; then
            _dangling_pruned=1
            echo "  [pruned] docker dangling volumes: ${_docker_prune_out}"
        fi
    fi

    if [ "$_dangling_pruned" -eq 0 ]; then
        echo "  [ok]    No dangling project volumes found."
    else
        echo "  Dangling volumes pruned: ${_dangling_pruned}."
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Install-time state file cleanup — BUG-UNINSTALL-LEAVES-STATEFILES-2026-05-27
#
# install.sh creates two state files in the WORK_DIR's docker/ subdirectory:
#   - docker/.env                          (compose env file with per-install secrets/config)
#   - docker/.yashigani-install-state      (runtime mode + admin/license metadata)
#
# Both were surfaced by live-verify on Mac and VM 2026-05-27 — prior to this
# fix, uninstall.sh left them behind even on --remove-volumes. Result:
#   1. Next install reads stale .env values (DB_AES_KEY, OWUI_SECRET_KEY,
#      FIPS_MODE, YASHIGANI_TLS_MODE, etc.) instead of regenerating.
#   2. .yashigani-install-state misleads runtime-detection on a fresh install
#      (especially the k8s mode flag — Su's refactor reads RUNTIME from here).
#   3. Operator running uninstall expects "all install artefacts gone";
#      finding .env still on disk with secrets is a real-world security
#      surprise.
#
# Wipe both files always (not gated on --remove-volumes). They are install-
# time artefacts; uninstall = inverse of install.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Podman GPU CDI spec cleanup — task #40 / ROOTLESS-CDI-001
#
# install.sh generates CDI spec files at docker/cdi/ (nvidia-raw.yaml from
# nvidia-ctk, nvidia.yaml as the 0.6.0-transformed version) and writes the
# transformed spec to /etc/cdi/nvidia.yaml with 0644 permissions via the
# Docker Engine daemon (no interactive sudo).
#
# On uninstall: remove the docker/cdi/ working dir. /etc/cdi/nvidia.yaml is
# intentionally left in place — it is a system-level CDI spec that any CUDA
# workload on the host can use; clearing it would break non-Yashigani uses.
# To reset /etc/cdi manually after uninstall: sudo nvidia-ctk cdi generate.
# ---------------------------------------------------------------------------
echo "=== Podman GPU CDI spec cleanup (task #40) ==="
_cdi_dir="${SCRIPT_DIR}/docker/cdi"
if [ -d "${_cdi_dir}" ]; then
    rm -rf "${_cdi_dir}" && echo "  [removed] ${_cdi_dir}" || echo "  [WARN] could not remove ${_cdi_dir}" >&2
else
    echo "  [ok]    ${_cdi_dir} not present"
fi

echo "=== Install-time state file cleanup ==="
_statefile_removed=0
for _statefile in \
        "${SCRIPT_DIR}/docker/.env" \
        "${SCRIPT_DIR}/docker/.yashigani-install-state"; do
    if [ -e "$_statefile" ]; then
        if rm -f "$_statefile" 2>/dev/null; then
            echo "  [removed] $_statefile"
            _statefile_removed=$(( _statefile_removed + 1 ))
        else
            echo "  [WARN] could not remove $_statefile (permission?)" >&2
        fi
    fi
done
if [ "$_statefile_removed" -eq 0 ]; then
    echo "  [ok]    No install-time state files present."
fi

echo ""
echo "Yashigani stopped."
[ "$REMOVE_VOLUMES" = "true" ] && echo "All volumes deleted." || echo "Data volumes preserved."
