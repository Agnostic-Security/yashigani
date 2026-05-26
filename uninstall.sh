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
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Minimal logging helper — mirrors the install.sh format exactly.
# log_info is called in the state-file runtime-detection block (57ea226);
# without this definition, set -euo pipefail aborts before any cleanup runs.
# (UNINSTALL-LOG_INFO-BUG — Ava phase2-verdict.md:69, v2.23.4)
log_info() { printf "    --> %s\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.yml"
REMOVE_VOLUMES="false"
RUNTIME="${RUNTIME:-}"
YES="false"

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
        --yes|-y)         YES="true" ;;
        --help|-h)
            cat <<'EOF'
Usage: ./uninstall.sh [OPTIONS]

Stops the Yashigani stack and optionally removes all data.

Options:
  --remove-volumes    Also permanently delete all data volumes
                      (Redis, audit logs, Ollama models, metrics history)
  --runtime=RUNTIME   Force a specific container runtime
                      (docker|podman|k8s — normally auto-detected)
  --yes, -y           Skip confirmation prompts (for unattended/CI use).
                      Safety note: when combined with --remove-volumes this
                      will DELETE ALL DATA without prompting. Pass both flags
                      only when you are certain data loss is acceptable.
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
_STATE_FILE="${SCRIPT_DIR}/docker/.yashigani-install-state"
_INSTALL_UID=""
_INSTALL_USER=""

if [ -f "$_STATE_FILE" ] && [ -r "$_STATE_FILE" ]; then
    _state_runtime="$(grep -E '^RUNTIME=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    _INSTALL_UID="$(grep -E '^INSTALL_UID=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    _INSTALL_USER="$(grep -E '^INSTALL_USER=' "$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]')"
    if [ -z "$RUNTIME" ] && { [ "$_state_runtime" = "docker" ] || [ "$_state_runtime" = "podman" ] || [ "$_state_runtime" = "k8s" ]; }; then
        RUNTIME="$_state_runtime"
        log_info "Using runtime from install state file: $RUNTIME"
        [ -n "$_INSTALL_USER" ] && log_info "Install was performed by user: ${_INSTALL_USER} (UID: ${_INSTALL_UID:-unknown})"
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
# ===========================================================================
_PROJECT_PREFIX="docker"

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
        if rm -rf "${_secrets_dir:?}/"* "${_secrets_dir:?}"/.[!.]* "${_secrets_dir:?}"/..?* 2>/dev/null; then
            echo "  [removed] docker/secrets/* — direct rm succeeded"
        else
            _secrets_wiped=false
            if [ "$RUNTIME" = "podman" ] && command -v podman >/dev/null 2>&1; then
                if podman unshare rm -rf "${_secrets_dir:?}/"* "${_secrets_dir:?}"/.[!.]* "${_secrets_dir:?}"/..?* 2>/dev/null; then
                    echo "  [removed] docker/secrets/* — podman unshare rm succeeded"
                    _secrets_wiped=true
                fi
            fi
            if [ "$_secrets_wiped" = "false" ]; then
                if "$RUNTIME" run --rm --pull=never \
                        --volume "${_secrets_dir}:/t:rw" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/* /t/.[!.]* /t/..?* 2>/dev/null; true' 2>/dev/null \
                   || "$RUNTIME" run --rm \
                        --volume "${_secrets_dir}:/t:rw" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/* /t/.[!.]* /t/..?* 2>/dev/null; true' 2>/dev/null; then
                    echo "  [removed] docker/secrets/* — container-fallback rm succeeded"
                    _secrets_wiped=true
                fi
            fi
            if [ "$_secrets_wiped" = "false" ]; then
                printf '[ERROR] secrets/ cleanup failed — manual remediation required:\n' >&2
                printf '[ERROR]   rm -rf '"'"'%s'"'"'  (as root or file owner)\n' "${_secrets_dir}" >&2
                printf '[ERROR]   or: podman unshare rm -rf '"'"'%s'"'"'\n' "${_secrets_dir}" >&2
                printf '[ERROR] Fresh install by a different user will fail until secrets/ is clean.\n' >&2
            fi
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
            "${SCRIPT_DIR}/docker/logs"; do
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
echo "Yashigani stopped."
[ "$REMOVE_VOLUMES" = "true" ] && echo "All volumes deleted." || echo "Data volumes preserved."
