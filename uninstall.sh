#!/usr/bin/env bash
# uninstall.sh — Tear down the Yashigani stack.
# Usage: ./uninstall.sh [--remove-volumes] [--runtime=docker|podman] [--yes|-y]
# Last updated: 2026-05-15T10:00:00+00:00 (fix(uninstall): stub docker/.env for compose-down in DR scenario — BUG-UNINSTALL-NO-ENV)
# Last updated: 2026-05-15T00:00:00+00:00 (fix(uninstall): drop privileged-linger shortcut from disable-linger, copy-pasteable remediation — Q2 / lint-sudo-pattern fix)
# Last updated: 2026-05-14T23:00:00+00:00 (fix: gate linger-disable on --remove-volumes — Q3 asymmetry)

set -euo pipefail
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
# BUG-REBOOT-NO-AUTO-START / ACS-RISK-046
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
  --runtime=RUNTIME   Force a specific container runtime (docker|podman)
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

# Detect runtime
if [ -z "$RUNTIME" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        RUNTIME="podman"
    else
        echo "ERROR: No container runtime found."
        exit 1
    fi
fi
COMPOSE="$RUNTIME compose"

echo "=== Yashigani Uninstaller ==="
echo "Runtime: $RUNTIME"
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
# BUG-REBOOT-NO-AUTO-START / ACS-RISK-046
_remove_auto_start

# Step 2: Stop the compose stack
#
# BUG-UNINSTALL-NO-ENV: docker-compose.yml uses ${VAR:?} fail-closed declarations
# for 6 required variables. Without a populated docker/.env, compose refuses to
# parse the file and exits non-zero before sending any down/stop signals to
# containers. This breaks the canonical DR "clean Step 0" path (fresh clone,
# no prior install.sh run in this checkout).
#
# Fix: if docker/.env is absent, write a stub file with placeholder values for
# all required vars before calling compose down. The stub is removed immediately
# after compose returns (success or failure). A sentinel flag (_STUB_ENV_CREATED)
# ensures we NEVER delete a real .env that was already present.
#
# The :? declarations in docker-compose.yml are kept intact — they are the
# correct fail-closed posture for install-time. This fix is local to uninstall.sh.
#
# Regression guard: the test in tests/integration/uninstall_sh_missing_env_test.sh
# runs `compose config` against the stub to catch any new :? var added to
# docker-compose.yml without a matching stub entry here.
# ---------------------------------------------------------------------------

_ENV_FILE="${SCRIPT_DIR}/docker/.env"
_STUB_ENV_CREATED="false"

if [ ! -f "$_ENV_FILE" ]; then
    echo "  [info] docker/.env not found — writing uninstall stub to allow compose parse (BUG-UNINSTALL-NO-ENV)"
    # ---------------------------------------------------------------------------
    # Stub values for ALL ${VAR:?} required variables in docker/docker-compose.yml.
    # These are placeholder-only — no real secrets, no install-time validation.
    # grep 'docker/docker-compose.yml' for '\$\{[A-Z_]+:\?' to enumerate if new
    # vars are added.  Keep this list in sync with that grep.
    # ---------------------------------------------------------------------------
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
# We only remove if WE created it — never touch a real .env.
_cleanup_stub() {
    if [ "$_STUB_ENV_CREATED" = "true" ] && [ -f "$_ENV_FILE" ]; then
        rm -f "$_ENV_FILE"
        echo "  [info] uninstall stub docker/.env removed (BUG-UNINSTALL-NO-ENV)"
    fi
}
trap _cleanup_stub EXIT

# ---------------------------------------------------------------------------
# shellcheck disable=SC2086
$COMPOSE -f "$COMPOSE_FILE" down $DOWN_ARGS

# ---------------------------------------------------------------------------
# Explicit per-volume cleanup — UNINSTALL-LEAVES-VOLUMES (#8)
#
# podman-compose ≤1.3.x ignores --volumes for named volumes.
# docker compose ≥2.x honours it, but the explicit loop is idempotent and
# safe on both runtimes: `volume rm` exits 0 when the volume doesn't exist
# (--force / ignore-not-found).  We log each removal so it is auditable.
#
# The project prefix is the compose file's parent directory name: "docker".
# ---------------------------------------------------------------------------
if [ "$REMOVE_VOLUMES" = "true" ]; then
    _PROJECT_PREFIX="docker"
    echo "Removing named volumes (UNINSTALL-LEAVES-VOLUMES #8 explicit loop):"
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
fi

echo ""
echo "Yashigani stopped."
[ "$REMOVE_VOLUMES" = "true" ] && echo "All volumes deleted." || echo "Data volumes preserved."
