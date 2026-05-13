#!/usr/bin/env bash
# uninstall.sh — Tear down the Yashigani stack.
# Usage: ./uninstall.sh [--remove-volumes] [--runtime=docker|podman] [--yes|-y]
# Last updated: 2026-05-13T00:00:00+01:00 (fix: UNINSTALL-LEAVES-VOLUMES #8 — explicit volume rm loop)

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
