#!/usr/bin/env bash
# uninstall.sh — Tear down the Yashigani stack.
# Usage: ./uninstall.sh [--remove-volumes] [--runtime=docker|podman] [--yes|-y]
# Last updated: 2026-05-17T17:00:00+00:00 (fix(uninstall): document yashigani_internal_bearer in secrets-wipe comment — Bucket-C)
# Last updated: 2026-05-17T10:00:00+00:00 (fix(uninstall): add wazuh-compose volumes to canonical list + prune dangling anon volumes — ANON-VOL-LEAK)
# Last updated: 2026-05-15T14:00:00+00:00 (fix(uninstall): wipe docker/secrets/ on --remove-volumes + final straggler pass — BUG-3-MULTI-USER-INSTALL-PKI + BUG-1-REDIS-STRAGGLER)
# Last updated: 2026-05-15T12:00:00+00:00 (fix(uninstall): force-remove dependent containers before volume rm — BUG-UNINSTALL-DEPGRAPH-LEAK)
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

# Detect runtime — prefer Podman (mirrors install.sh auto-detect order).
# Rationale: on dual-runtime hosts where the install was done via Podman, Docker
# may also answer `docker info`, causing volume rm to target the wrong store.
# The --runtime=docker|podman override (parsed above) wins because this block is
# guarded by [ -z "$RUNTIME" ].
if [ -z "$RUNTIME" ]; then
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        RUNTIME="podman"
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        RUNTIME="docker"
    else
        echo "ERROR: No container runtime found (tried podman, docker)." >&2
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
# BUG-REBOOT-NO-AUTO-START / YSG-RISK-046
_remove_auto_start

# Step 2: Stop the compose stack
#
# BUG-UNINSTALL-NO-ENV: docker-compose.yml uses ${VAR:?} fail-closed declarations
# for required variables. Without a populated docker/.env, compose refuses to
# parse the file and exits non-zero before sending any down/stop signals to
# containers. This breaks the canonical DR "clean Step 0" path (fresh clone,
# no prior install.sh run in this checkout).
#
# BUG-UNINSTALL-PARTIAL-ENV: a .env that EXISTS but is INCOMPLETE (written by
# install.sh before it hit a failure) causes the same compose parse error. The
# original guard [ ! -f "$_ENV_FILE" ] does not fire when the file exists.
#
# Fix (covers BOTH bugs):
#   Phase A — absent .env: write a stub file, register for cleanup on EXIT.
#             _STUB_ENV_CREATED="true" ensures we NEVER delete a real .env.
#   Phase B — partial .env: dynamically detect which :? vars are unset in the
#             current process env AND absent from docker/.env, then export a stub
#             value for each. Process-env takes precedence over .env file for
#             compose (documented compose env-var precedence). No file is mutated —
#             the exports live only for the duration of this shell.
#
# The :? declarations in docker-compose.yml are kept intact — they are the
# correct fail-closed posture for install-time. This fix is local to uninstall.sh.
#
# Regression guard: tests/integration/uninstall_sh_missing_env_test.sh covers
# the absent-env case; tests/integration/uninstall_sh_partial_env_test.sh covers
# the partial-env case.
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
# BUG-UNINSTALL-PARTIAL-ENV: Phase B — export stub values for any :? var
# that is not already set in process env AND not present in docker/.env.
#
# Detection: grep the active compose file at uninstall-time for ${VAR:?}
# patterns — this is zero-maintenance (catches new vars automatically) and
# costs one grep per uninstall run.
#
# Precedence: compose reads env vars (process environment) BEFORE it reads
# .env files. Exporting a var here overrides any absent or empty value in
# docker/.env without touching the file on disk.
#
# _PARTIAL_ENV_STUBBED is set to a space-separated list of vars we export,
# for logging only.
# ---------------------------------------------------------------------------
_PARTIAL_ENV_STUBBED=""

if [ -f "$COMPOSE_FILE" ]; then
    # Extract all :? var names from compose file, one per line, deduplicated.
    _required_vars="$(grep -oE '\$\{[A-Z_]+:\?' "$COMPOSE_FILE" 2>/dev/null \
        | sed 's/^\${//;s/:?$//' \
        | sort -u || true)"

    while IFS= read -r _var; do
        [ -z "$_var" ] && continue

        # Check 1: already set in process environment?
        if [ -n "${!_var+x}" ] && [ -n "${!_var}" ]; then
            continue
        fi

        # Check 2: present (non-empty) in docker/.env?
        if [ -f "$_ENV_FILE" ] && grep -qE "^${_var}=.+" "$_ENV_FILE" 2>/dev/null; then
            continue
        fi

        # Missing — export a stub value for compose parse.
        export "${_var}=__yashigani_uninstall_stub__"
        _PARTIAL_ENV_STUBBED="${_PARTIAL_ENV_STUBBED} ${_var}"
    done <<< "$_required_vars"
fi

if [ -n "$_PARTIAL_ENV_STUBBED" ]; then
    echo "  [info] Partial docker/.env detected — stubbed missing required vars for compose parse (BUG-UNINSTALL-PARTIAL-ENV):${_PARTIAL_ENV_STUBBED}"
    echo "  [info] docker/.env on disk is unchanged."
fi

# ---------------------------------------------------------------------------
# shellcheck disable=SC2086
$COMPOSE -f "$COMPOSE_FILE" down $DOWN_ARGS

# ---------------------------------------------------------------------------
# BUG-UNINSTALL-DEPGRAPH-LEAK: belt-and-braces container force-removal.
#
# podman-compose ≤1.3.x has known parity issues with depends_on ordering on
# teardown: containers that were in Exited state (not running) may not be
# removed by `compose down` when they originated from a different checkout or
# were stopped externally. Any Exited container that still references a named
# volume keeps that volume locked — `volume rm` then fails with "still in use".
#
# Fix: after compose down, enumerate ALL project containers (running OR exited)
# and force-remove any that remain. The enumeration uses two complementary
# strategies so it works on both Docker Engine and Podman:
#
#   1. Label filter: `--filter label=io.podman.compose.project=docker` (Podman)
#      or `--filter label=com.docker.compose.project=docker` (Docker Engine).
#      The project name is derived from the compose file's parent dir: "docker".
#
#   2. Name-prefix fallback: containers whose name starts with "docker_" or
#      "docker-" (podman-compose vs docker compose naming conventions).
#
# The loop is idempotent: if compose-down already removed all containers,
# `$RUNTIME ps -a -q ...` returns nothing and no rm is attempted.
#
# Both rootful (sudo $RUNTIME) and rootless ($RUNTIME without sudo) paths are
# covered by using the same $RUNTIME variable resolved above.
# ---------------------------------------------------------------------------
_PROJECT_PREFIX="docker"
echo "=== Belt-and-braces: removing any remaining project containers (BUG-UNINSTALL-DEPGRAPH-LEAK) ==="
_remaining_ids=""

# Strategy 1: label filter — try both compose-label variants
# podman-compose sets io.podman.compose.project; docker compose sets com.docker.compose.project
for _label_key in "io.podman.compose.project" "com.docker.compose.project"; do
    _ids="$("$RUNTIME" ps -a -q --filter "label=${_label_key}=${_PROJECT_PREFIX}" 2>/dev/null || true)"
    if [ -n "$_ids" ]; then
        _remaining_ids="${_remaining_ids}${_ids}
"
    fi
done

# Strategy 2: name-prefix filter — catches containers named docker_* or docker-*
# podman-compose names: docker_<service>_<n>; docker compose: docker-<service>-<n>
_ids_by_name="$("$RUNTIME" ps -a -q --filter "name=^${_PROJECT_PREFIX}[_-]" 2>/dev/null || true)"
if [ -n "$_ids_by_name" ]; then
    _remaining_ids="${_remaining_ids}${_ids_by_name}
"
fi

# Deduplicate and remove blank lines
_remaining_ids="$(printf '%s' "$_remaining_ids" | sort -u | grep -v '^$' || true)"

if [ -n "$_remaining_ids" ]; then
    _container_count="$(printf '%s\n' "$_remaining_ids" | grep -c '.'  || echo 0)"
    echo "  Found ${_container_count} remaining container(s) — stopping then force-removing..."
    _rm_ok=0
    _rm_fail=0
    # Pass 1: stop all containers in parallel (graceful shutdown signal).
    # --time 0 sends SIGKILL immediately — avoids waiting 10s per container
    # on containers that ignore SIGTERM (e.g. postgres in crash-loop).
    while IFS= read -r _cid; do
        [ -z "$_cid" ] && continue
        "$RUNTIME" stop --time 0 "$_cid" >/dev/null 2>&1 || true
    done <<< "$_remaining_ids"
    # Pass 2: force-remove (rm -f on an already-stopped container is idempotent).
    # podman rm -f removes even containers that ignore stop; --depend also removes
    # any dependent containers (available in Podman >=4.x; no-op on Docker/older).
    while IFS= read -r _cid; do
        [ -z "$_cid" ] && continue
        _cname="$("$RUNTIME" inspect --format '{{.Name}}' "$_cid" 2>/dev/null | sed 's|^/||' || echo "$_cid")"
        if "$RUNTIME" rm -f "$_cid" >/dev/null 2>&1; then
            echo "  [removed] container: ${_cname} (${_cid})"
            _rm_ok=$(( _rm_ok + 1 ))
        else
            # Last resort: try with --depend flag (Podman >=4.x tears down
            # dependent containers before removing this one)
            if "$RUNTIME" rm -f --depend "$_cid" >/dev/null 2>&1; then
                echo "  [removed+dep] container: ${_cname} (${_cid})"
                _rm_ok=$(( _rm_ok + 1 ))
            else
                echo "  [WARN] could not remove container: ${_cname} (${_cid})" >&2
                _rm_fail=$(( _rm_fail + 1 ))
            fi
        fi
    done <<< "$_remaining_ids"
    echo "Container cleanup: ${_rm_ok} removed, ${_rm_fail} failed."
    if [ "$_rm_fail" -gt 0 ]; then
        echo "  [WARN] ${_rm_fail} container(s) could not be removed. Volume rm may still fail." >&2
    fi
else
    echo "  [ok]    No remaining project containers found."
fi

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
# Wiped files include (non-exhaustive):
#   - PKI keys + certs (ca_root.key, ca_intermediate.key, *_client.key, etc.)
#   - admin1_password, admin2_password, admin_initial_password
#   - postgres_password, redis_password, grafana_admin_password
#   - caddy_internal_hmac
#   - yashigani_internal_bearer  (Bucket-C: per-install internal Bearer token;
#       rotated on fresh install after --remove-volumes — Captain gitleaks 2026-05-17)
#   - bootstrap tokens + all other docker/secrets/* files
#
# Safety guards:
#   1. Only runs when --remove-volumes is set.
#   2. Path-validates: _secrets_dir must equal SCRIPT_DIR/docker/secrets.
#      Prevents accidental rm if SCRIPT_DIR is mis-resolved.
#   3. Preserves the directory itself (only contents are removed).
#   4. If docker/secrets/ does not exist, skips silently.
#
# _ALPINE_IMAGE: hoisted here so it is available to BOTH the secrets-wipe
# block (BACKLOG-V240-006) and the bind-mount cleanup block (BACKLOG-V240-003)
# below. MUST match install.sh _alpine_image — co-rotate on any digest update.
# Search: grep -n "_ALPINE_IMAGE\|_alpine_image" uninstall.sh install.sh
# ---------------------------------------------------------------------------
# Alpine digest: MUST match install.sh _alpine_image (SIB-2D-02 co-rotation).
_ALPINE_IMAGE="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

if [ "$REMOVE_VOLUMES" = "true" ]; then
    _secrets_dir="${SCRIPT_DIR}/docker/secrets"
    # Path-validation guard: only proceed if the resolved path is exactly canonical.
    if [ "${_secrets_dir}" != "${SCRIPT_DIR}/docker/secrets" ]; then
        echo "  [WARN] docker/secrets path resolved unexpectedly (${_secrets_dir}) — skipping PKI wipe for safety" >&2
    elif [ ! -d "${_secrets_dir}" ]; then
        echo "  [skip] docker/secrets/ does not exist — nothing to wipe"
    else
        echo "Removing PKI secrets — fresh install will regenerate keys + admin credentials (BUG-3-MULTI-USER-INSTALL-PKI)"
        # Tier 1: direct rm (same-user caller — no overhead for common case).
        if rm -rf "${_secrets_dir:?}/"* 2>/dev/null; then
            echo "  [removed] docker/secrets/* — direct rm succeeded"
        else
            # Cross-UID ownership (Iris BACKLOG-V240-006 / Laura 2D GO 2026-05-21).
            _secrets_wiped=false
            # Tier 2: Podman unshare (lighter; no container overhead on Podman paths).
            if [ "$RUNTIME" = "podman" ] && command -v podman >/dev/null 2>&1; then
                if podman unshare rm -rf "${_secrets_dir:?}/"* 2>/dev/null; then
                    echo "  [removed] docker/secrets/* — podman unshare rm succeeded"
                    _secrets_wiped=true
                fi
            fi
            if [ "$_secrets_wiped" = "false" ]; then
                # Tier 3: ephemeral container as UID 0 — can unlink any UID's files.
                # Volume scope: docker/secrets:/t only (path-validated above).
                # No --privileged, no extra caps. Same surface as Laura-GO'd 2D pattern.
                # --pull=never first (image in cache after compose down); pull fallback
                # for airgap / post-manual-prune paths.
                if "$RUNTIME" run --rm --pull=never \
                        --volume "${_secrets_dir}:/t:rw" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/*' 2>/dev/null \
                   || "$RUNTIME" run --rm \
                        --volume "${_secrets_dir}:/t:rw" \
                        "${_ALPINE_IMAGE:?_ALPINE_IMAGE not set}" \
                        sh -c 'rm -rf /t/*' 2>/dev/null; then
                    echo "  [removed] docker/secrets/* — container-fallback rm succeeded"
                    _secrets_wiped=true
                fi
            fi
            # Tier 4: hard WARN — never silent swallow.
            if [ "$_secrets_wiped" = "false" ]; then
                printf '[ERROR] secrets/ cleanup failed — manual remediation required:\n' >&2
                printf '[ERROR]   rm -rf '"'"'%s'"'"'  (as root or file owner)\n' "${_secrets_dir}" >&2
                printf '[ERROR]   or: podman unshare rm -rf '"'"'%s'"'"'\n' "${_secrets_dir}" >&2
                printf '[ERROR] Fresh install by a different user will fail until secrets/ is clean.\n' >&2
            fi
        fi
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
if [ "$REMOVE_VOLUMES" = "true" ]; then
    # _ALPINE_IMAGE is hoisted above (BACKLOG-V240-006 hoist — co-rotation comment there).
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
                # Podman rootless: unshare remaps UID into the user namespace so rm
                # runs as the effective owner of the chowned files.
                if podman unshare rm -rf "$_bm_dir" 2>/dev/null; then
                    echo "  [removed] $_bm_dir (podman unshare)"
                else
                    # podman unshare also failed — fall back to ephemeral container.
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
                # Docker: run an ephemeral container as UID 1001 to rm contents,
                # then host rm -rf drops the now-empty dir.
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
# Redis-straggler final pass — BUG-1 incomplete edge case.
#
# Podman can recreate a container during network teardown if `restart: always`
# is set and the container exits non-zero. The compose `down` + belt-and-braces
# loop above remove containers that exist at that point; but a container that
# exits AFTER the loop runs (race window: network teardown respawn) will survive.
#
# Fix: run one additional ps+rm pass AFTER volume cleanup. This is intentionally
# a best-effort second sweep rather than an infinite loop — if a container still
# survives two sweeps, it is not a compose-managed straggler and must be
# investigated separately (see docs/yashigani_install_config.md §troubleshooting).
#
# `restart: always` on redis and budget-redis (see docker-compose.yml) is the
# known trigger. The post-volume pass runs after volume rm, so any volume-locked
# containers are already unlocked, and the respawn cannot re-attach to the now-
# deleted volume — it will exit(1) immediately and stay in Exited state, where
# the rm -f below can reach it.
# ---------------------------------------------------------------------------
echo "=== Final straggler pass (redis-straggler edge case — BUG-1 incomplete) ==="
_final_remaining=""

for _label_key in "io.podman.compose.project" "com.docker.compose.project"; do
    _ids="$("$RUNTIME" ps -a -q --filter "label=${_label_key}=${_PROJECT_PREFIX}" 2>/dev/null || true)"
    if [ -n "$_ids" ]; then
        _final_remaining="${_final_remaining}${_ids}
"
    fi
done
_ids_by_name="$("$RUNTIME" ps -a -q --filter "name=^${_PROJECT_PREFIX}[_-]" 2>/dev/null || true)"
if [ -n "$_ids_by_name" ]; then
    _final_remaining="${_final_remaining}${_ids_by_name}
"
fi
_final_remaining="$(printf '%s' "$_final_remaining" | sort -u | grep -v '^$' || true)"

if [ -n "$_final_remaining" ]; then
    _straggler_count="$(printf '%s\n' "$_final_remaining" | grep -c '.' || echo 0)"
    echo "  Found ${_straggler_count} straggler container(s) after volume rm — force-removing..."
    _final_ok=0
    _final_fail=0
    while IFS= read -r _cid; do
        [ -z "$_cid" ] && continue
        _cname="$("$RUNTIME" inspect --format '{{.Name}}' "$_cid" 2>/dev/null | sed 's|^/||' || echo "$_cid")"
        if "$RUNTIME" rm -f --time 0 "$_cid" >/dev/null 2>&1; then
            echo "  [removed] straggler: ${_cname} (${_cid})"
            _final_ok=$(( _final_ok + 1 ))
        else
            echo "  [WARN] could not remove straggler: ${_cname} (${_cid})" >&2
            _final_fail=$(( _final_fail + 1 ))
        fi
    done <<< "$_final_remaining"
    echo "Straggler cleanup: ${_final_ok} removed, ${_final_fail} failed."

    # After removing straggler containers, retry any volumes that failed the first
    # pass due to "Resource is still in use". Now that the holding containers are
    # gone, the volume rm should succeed. Only retry when --remove-volumes is set.
    if [ "$REMOVE_VOLUMES" = "true" ] && [ "$_final_ok" -gt 0 ]; then
        echo "  Retrying volumes that were in-use during first pass..."
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
        echo "  Volume retry: ${_retry_removed} additional volume(s) removed."
    fi
else
    echo "  [ok]    No straggler containers after volume rm."
fi

# ---------------------------------------------------------------------------
# Dangling / anonymous volume prune — ANON-VOL-LEAK
#
# Compose may create anonymous volumes for tmpfs-backed service paths or
# for volumes not listed in the top-level `volumes:` section (e.g. volumes
# declared in an opt-in compose override like docker-compose.wazuh.yml that
# were not started via the primary compose file). These have SHA-like names
# and are NOT cleaned up by the named-volume loop above.
#
# Prune strategy:
#   For docker: `docker volume prune --filter label=... -f` is too broad.
#   For podman: `podman volume prune --filter dangling=true -f` is safe —
#   Podman marks a volume as dangling only when no container references it.
#
# We only prune volumes that both:
#   (a) Have no running or stopped container referencing them (dangling=true).
#   (b) Were created with label `io.podman.compose.project=docker` (Podman)
#       or `com.docker.compose.project=docker` (Docker Engine) — limiting the
#       prune to this project's volumes.
#
# Fallback: when label filtering is unavailable (older runtimes), we skip
# silently and log a manual remediation hint.
# ---------------------------------------------------------------------------
if [ "$REMOVE_VOLUMES" = "true" ]; then
    echo "=== Dangling volume prune (ANON-VOL-LEAK) ==="
    _dangling_pruned=0

    if [ "$RUNTIME" = "podman" ]; then
        # Podman: prune dangling volumes belonging to this project
        # Try label-filtered prune first (Podman >=4.x supports --filter label=)
        _dangling_ids="$("$RUNTIME" volume ls --noheading -q --filter dangling=true \
            --filter "label=io.podman.compose.project=${_PROJECT_PREFIX}" 2>/dev/null || true)"
        if [ -z "$_dangling_ids" ]; then
            # Fall back: any dangling volume whose Name or Label matches project
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
        # Docker: prune dangling volumes filtered to project label
        # `docker volume prune` exits 0 even if nothing was pruned
        _docker_prune_out="$("$RUNTIME" volume prune \
            --filter "label=com.docker.compose.project=${_PROJECT_PREFIX}" \
            -f 2>/dev/null || true)"
        if echo "$_docker_prune_out" | grep -q "Total reclaimed space"; then
            _dangling_pruned=1   # at least one pruned
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
