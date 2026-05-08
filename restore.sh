#!/usr/bin/env bash
set -euo pipefail
# Last updated: 2026-05-08T00:00:00+01:00 (fix: K8s verify path — trigger rollout restart + wait + healthz probe after K8s secret restore; PR #67 followup)
# Last updated: 2026-05-07T09:00:00+01:00 (fix: validate_backup BACKUP_DIR→backup_dir variable mismatch — signed backups failed validation without --force)
# Last updated: 2026-05-03T12:45:00+01:00 (V232-SMOKE-010: exclude .gitkeep from empty-file check; V232-SMOKE-011: podman unshare chown -R before cp restore; V232-SMOKE-012: secrets dir 0751→0755)

# Tight umask so any files/dirs created during restore inherit 0600/0700.
# Overrides the host default (often 022) which would leave intermediate
# artefacts (pre-restore snapshots, temp extractions) world-readable.
umask 077

# =============================================================================
# Yashigani Restore Script
#
# Restores a backup created by install.sh (upgrade detection).
# Backup location: ./backups/<timestamp>/
#
# Usage:
#   bash restore.sh                          # list available backups
#   bash restore.sh <backup_dir>             # restore from specific backup
#   bash restore.sh --latest                 # restore from most recent backup
#   bash restore.sh --latest --k8s -n ns     # restore into Kubernetes
#
# Supported platforms:
#   - Docker Compose (Linux/macOS)
#   - Podman Compose (Linux/macOS)
#   - Kubernetes (via kubectl)
#
# What gets restored:
#   - docker/secrets/    (admin passwords, TOTP secrets, service tokens)
#   - docker/.env        (environment variables, database passwords)
#   - postgres_dump.sql  (database — if available in backup)
#
# What does NOT get restored (by design):
#   - Container images (rebuilt from source)
#   - Docker/Podman volumes other than Postgres (recreated on startup)
#   - OPA policies (loaded from git)
# =============================================================================

# ---------------------------------------------------------------------------
# Color output — only when stdout is a TTY
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_GREEN="\033[0;32m"
  C_RED="\033[0;31m"
  C_YELLOW="\033[0;33m"
  C_BOLD="\033[1m"
  C_RESET="\033[0m"
else
  C_GREEN=""
  C_RED=""
  C_YELLOW=""
  C_BOLD=""
  C_RESET=""
fi

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUPS_DIR="${WORK_DIR}/backups"
K8S_MODE=false
K8S_NAMESPACE="yashigani"

log_info()    { printf "    --> %s\n" "$*"; }
log_success() { printf "    ${C_GREEN}ok${C_RESET}  %s\n" "$*"; }
log_error()   { printf "    ${C_RED}!!  ERROR: %s${C_RESET}\n" "$*" >&2; }
log_warn()    { printf "    ${C_YELLOW}!!  WARNING: %s${C_RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Detect container runtime (same logic as install.sh)
# ---------------------------------------------------------------------------
detect_runtime() {
  if [[ "$K8S_MODE" == "true" ]]; then
    RUNTIME="k8s"
    return
  fi

  # Honour explicit override — same env var as install.sh uses.
  # Prevents auto-detection from picking Docker when Podman containers are
  # running (both daemons present on the same host, e.g. CI / test VMs).
  if [[ "${YSG_RUNTIME:-}" == "podman" ]]; then
    RUNTIME="podman"
    if command -v docker-compose &>/dev/null; then
      COMPOSE_CMD=("docker-compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    else
      COMPOSE_CMD=("podman" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    fi
    return
  fi
  if [[ "${YSG_RUNTIME:-}" == "docker" ]]; then
    RUNTIME="docker"
    COMPOSE_CMD=("docker" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    return
  fi

  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    RUNTIME="docker"
    COMPOSE_CMD=("docker" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
  elif command -v podman &>/dev/null; then
    RUNTIME="podman"
    # Prefer docker-compose standalone if available (Podman uses it via plugin)
    if command -v docker-compose &>/dev/null; then
      COMPOSE_CMD=("docker-compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    else
      COMPOSE_CMD=("podman" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    fi
  else
    RUNTIME="none"
    COMPOSE_CMD=()
  fi
}

# =============================================================================
# Pre-flight hard-stop (P0-14 — mirrors check_installer_preflight in install.sh)
#
# The restore body runs zero sudo.  These two checks ensure the operator has
# done any required privileged setup before we touch the live secrets dir.
# Exits non-zero with a copy-pasteable remediation block on first failure.
# Skipped for Kubernetes (K8s manages its own RBAC and bind-mounts).
# =============================================================================
check_restore_preflight() {
  # K8s restore path does not use Docker group or host bind-mount dirs.
  if [[ "$K8S_MODE" == "true" ]]; then
    return 0
  fi

  # --- Check 1: docker group membership (Docker runtime only) ----------------
  # restore.sh body never runs sudo, so the current user must reach the Docker
  # daemon without elevated privilege.
  if [[ "${RUNTIME}" == "docker" ]]; then
    if ! docker info >/dev/null 2>&1; then
      printf "\nPre-flight failed: your user cannot run docker without sudo.\n\n"
      printf "  sudo groupadd docker          # creates the group if it doesn't exist\n"
      printf "  sudo usermod -aG docker \$USER # adds you to the group\n"
      printf "  newgrp docker                 # activate without logout (or log out and back in)\n\n"
      printf "Then re-run this restore script.\n\n"
      exit 1
    fi
  fi

  # --- Check 2: bind-mount directory ownership (UID 1001) --------------------
  # PKI issuer and backoffice services run as UID 1001 inside containers and
  # write to bind-mounted host dirs.  restore.sh no longer runs chown via sudo —
  # the operator must do this once before running the restore.
  #
  # Podman rootless: container UID 1001 maps to host UID (subuid_start + 1000).
  # `podman unshare chown 1001:1001` is the correct operator command; the
  # resulting host UID is the subuid-remapped value, not literal 1001. Accept
  # either literal 1001 (Docker / rootful) or the subuid-remapped UID.
  local _bm_failed=0
  local _expected_uid="1001"
  local _is_rootless_podman=false
  if [[ "${RUNTIME}" == "podman" ]] && [[ "$(id -u)" != "0" ]]; then
    _is_rootless_podman=true
    local _subuid_start
    _subuid_start="$(awk -F: -v u="$(id -un)" '$1==u{print $2; exit}' /etc/subuid 2>/dev/null || echo "")"
    if [[ -n "$_subuid_start" ]]; then
      _expected_uid=$(( _subuid_start + 1001 - 1 ))
    fi
  fi

  for _bm_dir in "${WORK_DIR}/docker/data" "${WORK_DIR}/docker/certs" "${WORK_DIR}/docker/logs"; do
    if [[ ! -d "$_bm_dir" ]]; then
      _bm_failed=1
      break
    fi
    # shellcheck disable=SC2012
    local _uid
    _uid="$(ls -nd "$_bm_dir" 2>/dev/null | awk '{print $3}')"
    if [[ "$_uid" != "1001" && "$_uid" != "$_expected_uid" ]]; then
      _bm_failed=1
      break
    fi
  done

  if [[ "$_bm_failed" -eq 1 ]]; then
    printf "\nPre-flight failed: bind-mount directories missing or wrong owner.\n\n"
    if [[ "$_is_rootless_podman" == "true" ]]; then
      printf "  cd %s\n" "${WORK_DIR}"
      printf "  mkdir -p docker/data docker/certs docker/logs\n"
      printf "  podman unshare chown 1001:1001 docker/data docker/certs docker/logs\n\n"
      printf "(Podman rootless: use 'podman unshare chown', not 'sudo chown -R 1001:1001'.)\n\n"
    else
      printf "  mkdir -p docker/data docker/certs docker/logs\n"
      printf "  sudo chown -R 1001:1001 docker/data docker/certs docker/logs\n\n"
    fi
    printf "Then re-run this restore script.\n\n"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Find the Postgres container/pod
# ---------------------------------------------------------------------------
find_pg_container() {
  case "$RUNTIME" in
    docker)
      docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'postgres' | grep -v pgbouncer | head -1
      ;;
    podman)
      podman ps --format '{{.Names}}' 2>/dev/null | grep -E 'postgres' | grep -v pgbouncer | head -1
      ;;
    k8s)
      kubectl get pods -n "$K8S_NAMESPACE" -l app.kubernetes.io/name=postgres \
        --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || \
      kubectl get pods -n "$K8S_NAMESPACE" -o name 2>/dev/null | grep postgres | grep -v pgbouncer | head -1 | sed 's|pod/||'
      ;;
    *)
      echo ""
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Execute psql in the Postgres container/pod
# ---------------------------------------------------------------------------
pg_exec() {
  local pg_name="$1"
  shift
  case "$RUNTIME" in
    docker)
      docker exec -i "$pg_name" "$@"
      ;;
    podman)
      podman exec -i "$pg_name" "$@"
      ;;
    k8s)
      kubectl exec -i -n "$K8S_NAMESPACE" "$pg_name" -- "$@"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# List available backups
# ---------------------------------------------------------------------------
list_backups() {
  if [[ ! -d "$BACKUPS_DIR" ]]; then
    echo "No backups directory found at ${BACKUPS_DIR}"
    exit 1
  fi

  local backups
  backups=$(find "${BACKUPS_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
  if [[ -z "$backups" ]]; then
    echo "No backups found in ${BACKUPS_DIR}"
    exit 1
  fi

  printf "\n${C_BOLD}Available backups:${C_RESET}\n\n"
  local i=1
  while IFS= read -r dir; do
    local ts
    ts=$(basename "$dir")
    local has_secrets="no"
    local has_env="no"
    local has_db="no"
    local size="0K"
    [[ -d "${dir}/secrets" ]] && has_secrets="yes"
    [[ -f "${dir}/.env" ]] && has_env="yes"
    [[ -f "${dir}/postgres_dump.sql" ]] && has_db="yes"
    size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}')
    printf "  %d) %s  [%s]  (secrets=%s, env=%s, db=%s)\n" "$i" "$ts" "$size" "$has_secrets" "$has_env" "$has_db"
    i=$((i + 1))
  done <<< "$backups"
  printf "\nUsage:\n"
  printf "  bash restore.sh <timestamp>            # restore a specific backup\n"
  printf "  bash restore.sh --latest               # restore the most recent\n"
  printf "  bash restore.sh --latest --k8s -n ns   # restore into Kubernetes\n\n"
}

# ---------------------------------------------------------------------------
# Validate backup integrity
# ---------------------------------------------------------------------------
validate_backup() {
  local backup_dir="$1"
  local errors=0

  # Hard fail: backup must have at minimum secrets/ AND .env
  if [[ ! -d "${backup_dir}/secrets" ]]; then
    log_error "Backup missing required directory: secrets/"
    errors=$((errors + 1))
  fi
  if [[ ! -f "${backup_dir}/.env" ]]; then
    log_error "Backup missing required file: .env"
    errors=$((errors + 1))
  fi

  # If structural fails, no point checking contents.
  if [[ "$errors" -gt 0 ]]; then
    return 1
  fi

  # Hard fail: v2.23.1-mtls backups MUST carry the CA keypair and at least
  # one service leaf key. Without these, restoring and then running install.sh
  # will regenerate a NEW CA that does not match any surviving leaves — every
  # mTLS peer breaks silently. See CLAUDE.md §4 Docker+Podman+Helm parity.
  for ca_file in ca_root.key ca_root.crt ca_intermediate.key ca_intermediate.crt; do
    if [[ ! -f "${backup_dir}/secrets/${ca_file}" ]]; then
      log_error "Backup missing required CA material: secrets/${ca_file}"
      errors=$((errors + 1))
    fi
  done
  # At least one *_client.key must exist (proves leaves were backed up)
  local leaf_count
  leaf_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f -name '*_client.key' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$leaf_count" -lt 1 ]]; then
    log_error "Backup contains no *_client.key leaves — service mTLS certs missing"
    errors=$((errors + 1))
  fi

  # Hard fail: empty secret files indicate corruption.
  # Exclude .gitkeep (an intentionally-empty git placeholder present in the
  # committed docker/secrets/ directory and preserved in every backup by cp -rp).
  local empty_count
  empty_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f -empty ! -name '.gitkeep' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$empty_count" -gt 0 ]]; then
    log_error "${empty_count} secret file(s) are empty — backup is corrupt"
    errors=$((errors + 1))
  fi

  # Hard fail: .env must carry the env keys the app NEEDs to boot.
  for key in YASHIGANI_TLS_DOMAIN POSTGRES_PASSWORD YASHIGANI_DB_AES_KEY; do
    if ! grep -q "^${key}=" "${backup_dir}/.env" 2>/dev/null; then
      log_error "Backup .env missing required key: ${key}"
      errors=$((errors + 1))
    fi
  done

  # Soft: postgres_dump.sql is optional (backup may predate DB data), but if
  # present it must be non-trivial (>100 bytes — empty file is suspicious).
  if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
    local dump_bytes
    dump_bytes=$(wc -c < "${backup_dir}/postgres_dump.sql" 2>/dev/null | tr -d ' ')
    if [[ -z "$dump_bytes" || "$dump_bytes" -lt 100 ]]; then
      log_error "postgres_dump.sql present but empty or truncated (${dump_bytes} bytes) — backup is corrupt"
      errors=$((errors + 1))
    fi
  else
    log_warn "No postgres_dump.sql in backup — DB will start empty post-restore"
  fi

  # RETRO-R4-3: verify backup manifest signature if present.
  # install.sh signs the manifest with the CA intermediate private key.
  # We verify using the public key extracted from ca_intermediate.crt.
  #
  # If both MANIFEST.sha256 and MANIFEST.sha256.sig are present, the
  # signature MUST be valid — a bad signature is a hard FAIL (evidence of
  # tampering). If the manifest is absent, emit a warning (unsigned backup
  # from a pre-RETRO-R4-3 install or --force recovery scenario).
  local _manifest="${backup_dir}/MANIFEST.sha256"
  local _sig="${backup_dir}/MANIFEST.sha256.sig"
  local _ca_cert="${backup_dir}/secrets/ca_intermediate.crt"

  if [[ -f "$_manifest" && -f "$_sig" ]]; then
    if [[ ! -f "$_ca_cert" ]]; then
      log_error "RETRO-R4-3: MANIFEST.sha256.sig present but ca_intermediate.crt missing from backup/secrets/ — cannot verify"
      errors=$((errors + 1))
    else
      # Extract public key from the intermediate cert, then verify.
      # openssl dgst -verify reads a raw public key PEM file (not a cert).
      local _pubkey_file
      # V232-NEG04: never use /tmp — place temp pubkey alongside backup dir
      _pubkey_file=$(mktemp "${backup_dir}/.ysg-pubkey-XXXXXXXX.pem" 2>/dev/null \
        || mktemp "${HOME}/.ysg-pubkey-XXXXXXXX.pem")
      trap 'rm -f "$_pubkey_file"' RETURN
      if ! openssl x509 -in "$_ca_cert" -noout -pubkey > "$_pubkey_file" 2>/dev/null; then
        log_error "RETRO-R4-3: Failed to extract public key from ca_intermediate.crt"
        errors=$((errors + 1))
      elif ! openssl dgst -sha256 -verify "$_pubkey_file" -signature "$_sig" "$_manifest" >/dev/null 2>&1; then
        log_error "RETRO-R4-3: Backup signature verification FAILED — backup may be tampered"
        log_error "  Manifest: ${_manifest}"
        log_error "  Signature: ${_sig}"
        log_error "  Cert: ${_ca_cert}"
        errors=$((errors + 1))
      else
        log_success "Backup manifest signature verified (RETRO-R4-3)"
        # Also verify manifest content hashes match current files on disk.
        # This catches partial writes / truncations even without sig tampering.
        local _hash_errors=0
        while IFS= read -r _line; do
          local _hash _relpath
          _hash="${_line%% *}"
          _relpath="${_line##* }"
          local _fpath="${backup_dir}/${_relpath}"
          if [[ ! -f "$_fpath" ]]; then
            log_error "RETRO-R4-3: Manifest references missing file: ${_relpath}"
            _hash_errors=$((_hash_errors + 1))
          else
            local _actual_hash
            _actual_hash=$(sha256sum "$_fpath" | awk '{print $1}')
            if [[ "$_actual_hash" != "$_hash" ]]; then
              log_error "RETRO-R4-3: Manifest hash mismatch for ${_relpath} (expected ${_hash}, got ${_actual_hash})"
              _hash_errors=$((_hash_errors + 1))
            fi
          fi
        done < "$_manifest"
        if [[ "$_hash_errors" -gt 0 ]]; then
          log_error "RETRO-R4-3: ${_hash_errors} file(s) do not match manifest — backup is corrupt"
          errors=$((errors + _hash_errors))
        else
          log_success "Backup manifest content hashes verified (${_hash_errors} mismatches)"
        fi
      fi
      rm -f "$_pubkey_file" 2>/dev/null || true
      trap - RETURN
    fi
  elif [[ -f "$_sig" && ! -f "$_manifest" ]]; then
    log_error "RETRO-R4-3: MANIFEST.sha256.sig present but MANIFEST.sha256 missing — backup is corrupt"
    errors=$((errors + 1))
  else
    log_warn "RETRO-R4-3: Backup has no manifest signature (pre-RETRO-R4-3 backup or unsigned)"
    log_warn "  Integrity cannot be cryptographically verified. Use --force to proceed."
    log_warn "  New backups created by install.sh >= RETRO-R4-3 include a signed manifest."
    # Not a hard error — operator may be restoring a legacy backup.
    # --force callers are already warned by the outer validate_backup caller.
  fi

  if [[ "$errors" -gt 0 ]]; then
    log_error "Backup validation: ${errors} failure(s) detected"
    return 1
  fi
  log_success "Backup validation passed"
  return 0
}

# ---------------------------------------------------------------------------
# Restore from a specific backup
# ---------------------------------------------------------------------------
restore_backup() {
  local backup_dir="$1"

  if [[ ! -d "$backup_dir" ]]; then
    log_error "Backup directory not found: ${backup_dir}"
    exit 1
  fi

  printf "\n${C_BOLD}Restoring from: $(basename "${backup_dir}")${C_RESET}\n"
  printf "  Runtime:     %s\n" "${RUNTIME}"
  if [[ "$K8S_MODE" == "true" ]]; then
    printf "  Namespace:   %s\n" "${K8S_NAMESPACE}"
  fi
  printf "\n"

  # Pre-flight hard-stop (P0-14): docker group + bind-mount ownership.
  # Mirrors check_installer_preflight in install.sh.  Exits with a
  # copy-pasteable remediation block if the operator environment is not ready.
  check_restore_preflight

  # Validate backup before restoring. --force bypasses validation for
  # genuine recovery scenarios (e.g. manually-assembled partial backup).
  if ! validate_backup "$backup_dir"; then
    if [[ "$FORCE" == "true" ]]; then
      log_warn "Backup validation failed but --force specified. Proceeding at operator risk."
    else
      log_error "Backup validation failed. Use --force to restore anyway (NOT recommended for production)."
      exit 1
    fi
  fi

  # Safety: snapshot current state before overwriting
  local pre_restore_dir="${BACKUPS_DIR}/pre-restore-$(date +%Y%m%d_%H%M%S)"
  if [[ -d "${WORK_DIR}/docker/secrets" ]]; then
    log_info "Saving current state to ${pre_restore_dir}..."
    mkdir -p "${pre_restore_dir}"
    # BUG-3 (v2.23.1): preserve ownership/mode in pre-restore snapshot so a
    # rollback restores the original uids the containers expect, not root:root.
    cp -rp "${WORK_DIR}/docker/secrets" "${pre_restore_dir}/secrets" 2>/dev/null || true
    cp "${WORK_DIR}/docker/.env" "${pre_restore_dir}/.env" 2>/dev/null || true
    log_success "Pre-restore snapshot saved"
  fi

  # 1. Restore secrets (preserve source mode; reapply canonical modes after copy)
  if [[ -d "${backup_dir}/secrets" ]]; then
    log_info "Restoring secrets..."
    mkdir -p "${WORK_DIR}/docker/secrets"

    # RESTORE-3 (v2.23.1 gate): the secrets dir may be owned by a subuid-range UID
    # left from a previous Podman rootless install (e.g. UID 363144 = container UID
    # 1001 in the PKI issuer's namespace). If the current user does not own it,
    # `chmod 751` below will fail with EPERM → restore aborts before touching any
    # secrets. Fix: if Podman rootless mode AND the dir is not owned by the current
    # user, use `podman unshare chown` (which maps the installer's UID to 0 inside
    # the user namespace, giving it root-equivalent privilege over the subuid range).
    # This mirrors the stale-install guard in install.sh.
    # Never sudo here — restore.sh runs zero sudo (P0-14).
    local _secrets_dir_owner
    _secrets_dir_owner=$(stat -c '%u' "${WORK_DIR}/docker/secrets" 2>/dev/null || echo "")
    if [[ -n "$_secrets_dir_owner" && "$_secrets_dir_owner" != "$(id -u)" ]]; then
      if [[ "${RUNTIME}" == "podman" ]] && command -v podman >/dev/null 2>&1; then
        log_info "Secrets dir owned by UID ${_secrets_dir_owner} (not current user $(id -u)) — resetting via podman unshare"
        # Chown dir to UID 0 inside the user namespace = current user on the host.
        if ! podman unshare chown 0:0 "${WORK_DIR}/docker/secrets" 2>/dev/null; then
          log_warn "podman unshare chown on secrets dir failed — chmod 751 may fail; pre-run: sudo chown $(id -un):$(id -gn) '${WORK_DIR}/docker/secrets'"
        fi
        # Also reset any existing files so cp -rp can overwrite them.
        # RESTORE-4 (V232-SMOKE-011): existing files are sub-UID-owned; plain
        # chmod u+w leaves them sub-UID-owned so tom cannot overwrite them.
        # Remap ownership to uid 0 (= tom on the host) inside the user namespace
        # so cp -rp from the backup can create/overwrite files in the live dir.
        # _pki_chown_client_keys re-applies container sub-UID ownership after copy.
        podman unshare chown -R 0:0 "${WORK_DIR}/docker/secrets" 2>/dev/null || true
        find "${WORK_DIR}/docker/secrets" -maxdepth 1 -type f \
          -exec podman unshare chmod u+w {} \; 2>/dev/null || true
      else
        log_warn "Secrets dir owned by UID ${_secrets_dir_owner} (not current user $(id -u))."
        log_warn "  chmod 751 will fail unless you fix it first:"
        log_warn "    sudo chown $(id -un):$(id -gn) '${WORK_DIR}/docker/secrets'"
      fi
    fi

    # RC-6 (v2.23.1): secrets directory must be world-readable (0755) so
    # container processes running as non-root UIDs (pgbouncer=70, redis=999,
    # OPA=1000, etc.) can both traverse AND read-list the directory.
    # OPA requires read on the dir to inotify-watch TLS certs for hot-reload;
    # 0751 (world-traverse-only) prevented the inotify watcher → OPA unhealthy.
    # restore.sh runs with umask 077, which would create the dir as 0700 — set
    # explicitly to 0755. The outer home directory provides the primary access
    # control; making the inner secrets/ directory readable is intentional and safe.
    # V232-SMOKE-012 fix: changed 0751 → 0755.
    chmod 755 "${WORK_DIR}/docker/secrets"
    # Ensure any pre-existing read-only files in the destination are writable
    # before we overwrite them. On macOS (BSD cp), cp -rp fails to overwrite
    # a 0400 file even when you own it — unlike GNU cp which can force-overwrite
    # owner-writable-by-permission.  The original filter was *.key/*.pem only,
    # but token files, hmac files, and password files are also installed 0400
    # by install.sh — all need u+w for the cp to succeed.  This is idempotent:
    # we restore canonical permissions in _pki_chown_client_keys immediately
    # after the copy.  Bug caught: R4 macOS Podman gate 2026-04-30.
    find "${WORK_DIR}/docker/secrets" -maxdepth 1 -type f \
      -exec chmod u+w {} \; 2>/dev/null || true
    # cp -p preserves source mode/ownership timestamps.
    if ! cp -rp "${backup_dir}/secrets/"* "${WORK_DIR}/docker/secrets/"; then
      log_error "Failed to copy secrets from backup"
      return 1
    fi
    local secret_count
    secret_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f | wc -l | tr -d ' ')
    log_success "Secrets copied from backup (${secret_count} files)"

    # BUG-58B-04a + BUG-58B-04b (v2.23.1): reapply canonical file modes and
    # re-own service private keys to the container UIDs that must read them.
    # Old backups (pre-fix) used 'chmod -R 600' which clobbered intentionally-
    # 0644 public secrets. New backups only tighten *.key to 0400. Either way,
    # calling _pki_chown_client_keys here normalises modes and ownership so that
    # every service container can read exactly the files it needs to.
    _pki_chown_client_keys
  else
    log_warn "No secrets directory in backup — skipping"
  fi

  # 2. Restore .env
  if [[ -f "${backup_dir}/.env" ]]; then
    log_info "Restoring .env..."
    cp "${backup_dir}/.env" "${WORK_DIR}/docker/.env"
    log_success ".env restored"
  else
    log_warn "No .env file in backup — skipping"
  fi

  # 3. BUG-4 / BUG-58B-04c (v2.23.1): refresh PGDATA-cached CA + server cert
  #    BEFORE the Postgres dump replay. The replay reconnects through pgbouncer;
  #    without this refresh the restored secrets/ CA differs from the in-PGDATA
  #    CA and every reconnect fails mTLS handshake.
  _refresh_pgdata_ca || log_warn "PGDATA CA refresh failed -- postgres mTLS may be broken until manual fix"

  # 4. Restore Postgres dump
  if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
    _restore_postgres "${backup_dir}/postgres_dump.sql"
  else
    log_info "No Postgres dump in backup — skipping database restore"
  fi

  # 5. BUG-58B-04d (v2.23.1): update the live yashigani_app role password to
  #    match the restored secret. After a restore, docker/secrets/postgres_password
  #    now contains the backup's password but the cluster was initialised with the
  #    fresh-install password. Every subsequent DB connection from the app fails
  #    with "password authentication failed". Fix: ALTER ROLE idempotently.
  _restore_pg_role_password

  # 6. For K8s: update secrets in the cluster
  if [[ "$K8S_MODE" == "true" && -d "${backup_dir}/secrets" ]]; then
    _restore_k8s_secrets "${backup_dir}/secrets"
    # 6b. Patch yashigani-postgres-secrets with the restored postgres_password.
    #     backoffice/gateway/pgbouncer deployments read POSTGRES_PASSWORD via
    #     valueFrom.secretKeyRef(name=yashigani-postgres-secrets, key=postgres_password).
    #     _restore_k8s_secrets recreates the flat yashigani-secrets generic secret
    #     but does NOT touch yashigani-postgres-secrets, so the fresh-install
    #     password remains live and every post-restore pod startup fails with
    #     "password authentication failed". (retro #3ca)
    _restore_k8s_postgres_secrets "${backup_dir}/secrets"
    # 6c. PR #67 K8s verify path (v2.23.3 retro gap):
    #     Restart all Yashigani deployments so pods pick up the restored K8s
    #     secrets, then wait for rollout + probe /healthz. Previously this was
    #     only printed as "next steps" — operators forgot to run it and ran into
    #     auth failures with a nominally-successful restore.
    _k8s_post_restore_verify
  fi

  printf "\n${C_GREEN}${C_BOLD}Restore complete.${C_RESET}\n\n"

  # Platform-specific next steps
  case "$RUNTIME" in
    docker)
      printf "  Next steps:\n"
      printf "    1. Restart services: docker compose -f docker/docker-compose.yml up -d\n"
      printf "    2. Verify: curl -sk https://\$(grep YASHIGANI_TLS_DOMAIN docker/.env | cut -d= -f2)/healthz\n"
      printf "    3. Log in to admin UI and verify credentials work\n"
      ;;
    podman)
      printf "  Next steps:\n"
      printf "    1. Restart services: podman compose -f docker/docker-compose.yml up -d\n"
      printf "    2. Verify: curl -sk https://\$(grep YASHIGANI_TLS_DOMAIN docker/.env | cut -d= -f2)/healthz\n"
      printf "    3. Log in to admin UI and verify credentials work\n"
      ;;
    k8s)
      printf "  K8s restore steps completed automatically:\n"
      printf "    - Secrets updated: kubectl rollout restart deployment -n ${K8S_NAMESPACE} (done)\n"
      printf "    - Rollout awaited: kubectl rollout status deployment --timeout=300s (done)\n"
      printf "    - Gateway healthz probed (see output above)\n"
      printf "  If healthz probe was empty or a deployment timed out above:\n"
      printf "    kubectl get pods -n ${K8S_NAMESPACE}\n"
      printf "    kubectl exec -n ${K8S_NAMESPACE} deployment/yashigani-gateway -- curl -sf http://localhost:8080/healthz\n"
      printf "  Then log in to admin UI and verify credentials work.\n"
      ;;
    *)
      printf "  Secrets and .env restored. Start your services manually.\n"
      ;;
  esac
  printf "\n"
  printf "  Pre-restore backup saved at: ${pre_restore_dir}\n"
  printf "  If something went wrong, restore from there.\n\n"
}

# ---------------------------------------------------------------------------
# BUG-58B-04b (v2.23.1): Re-own service private keys to container UIDs after
# PKI restore. install.sh's _backup_existing_data now only sets *.key to 0400
# (not a blanket chmod -R 600), but the backup still carries root:root ownership
# from the initial cp -rp. When restore.sh extracts keys, they land as root:root
# 0400; service containers (pgbouncer=UID70, redis=UID999, gateway/backoffice=
# UID1001) get EACCES on their own key.
#
# Same service→UID map as install.sh:_pki_chown_client_keys.
# Runs after secrets are restored on every supported runtime.
# ---------------------------------------------------------------------------
_pki_chown_client_keys() {
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # Canonical UID map: service name → container UID.
  local _uid_mapped_services=(
    "gateway:1001"
    "backoffice:1001"
    "redis:999"
    "budget-redis:999"
    "pgbouncer:70"
    "postgres:999"
  )

  # Determine chown mode: root can chown directly; non-root uses podman unshare
  # (Podman rootless user-namespace). Docker non-root: restore.sh never runs
  # sudo (P0-14) — warn with a copy-pasteable remediation block instead.
  # check_restore_preflight() has already verified docker group membership; the
  # key re-own step is the one operation that still requires host privilege when
  # backup keys land as root:root.
  local _chown_mode="direct"
  if [[ "$(id -u)" != "0" ]]; then
    if [[ "${RUNTIME}" == "podman" ]]; then
      _chown_mode="unshare"
    else
      # Docker non-root: warn-only — never sudo (P0-14 / feedback_security_company_no_shortcuts).
      _chown_mode="warn"
    fi
  fi

  log_info "Re-owning service private keys to container UIDs (mode: ${_chown_mode})"

  for _svc_uid in "${_uid_mapped_services[@]}"; do
    local _svc="${_svc_uid%%:*}"
    local _uid="${_svc_uid#*:}"
    local _keyfile="${_secrets_dir}/${_svc}_client.key"
    if [[ ! -f "$_keyfile" ]]; then
      continue
    fi
    case "$_chown_mode" in
      direct)
        if ! chown "${_uid}:${_uid}" "$_keyfile"; then
          log_warn "chown failed on ${_svc} key — container may fail to start"
        else
          chmod 0600 "$_keyfile" || log_warn "chmod 0600 failed on ${_svc} key (not fatal for direct mode)"
        fi
        ;;
      unshare)
        # RESTORE-1 (v2.23.1 gate): after `podman unshare chown ${_uid}:${_uid}`,
        # the file is owned by a subuid-range UID on the host. A subsequent
        # host-side `chmod` fails with EPERM because the calling user (su/UID 1004)
        # does not own the file. Fix: do the chmod INSIDE the podman unshare
        # namespace (where the chowned UID maps to 0 = the invoking user), alongside
        # the chown. This matches the pattern used in install.sh's _do_chown.
        local _key_basename
        _key_basename=$(basename "$_keyfile")
        local _key_dir
        _key_dir=$(dirname "$_keyfile")
        if ! podman unshare sh -c \
              "chown ${_uid}:${_uid} '${_keyfile}' && chmod 0600 '${_keyfile}'" 2>/dev/null; then
          log_warn "podman unshare chown/chmod failed on ${_svc} key — container may fail to start"
        fi
        ;;
      warn)
        log_warn "Non-root Docker: cannot chown ${_svc} key to UID ${_uid} without sudo."
        log_warn "  Run manually if ${_svc} fails to start:"
        log_warn "    sudo chown ${_uid}:${_uid} \"${_keyfile}\""
        ;;
    esac
  done

  # Reapply canonical cert modes: certs are public material (0644); keys are 0600.
  # Note: for 'unshare' mode, service keys were already chowned+chmod'd above
  # inside the user namespace. These host-side find commands will fail silently
  # on files owned by subuid-range UIDs (EPERM) — that is expected and harmless
  # because the correct mode was already applied inside unshare.
  find "${_secrets_dir}" -maxdepth 1 -type f \
    \( -name '*_client.crt' -o -name 'ca_*.crt' \) \
    -exec chmod 0644 {} \; 2>/dev/null || true
  find "${_secrets_dir}" -maxdepth 1 -type f -name '*.key' \
    -exec chmod 0600 {} \; 2>/dev/null || true
  # CA private keys are even tighter — only the PKI issuer (root/UID1001) reads
  # them. 0400 prevents accidental overwrite even by the owning UID.
  for _ca_key in ca_root.key ca_intermediate.key; do
    if [[ -f "${_secrets_dir}/${_ca_key}" ]]; then
      chmod 0400 "${_secrets_dir}/${_ca_key}" 2>/dev/null || true
    fi
  done

  # BUG-58B-04a: reapply 0644 to public password/token files that the backup's
  # per-file chmod may have tightened to 0400 (as of the BUG-58B-04a fix above,
  # backup only tightens *.key; but pre-fix backups on disk tightened everything
  # to 0600 via chmod -R 600). Reapply explicitly so restore is idempotent
  # against both old and new backup formats.
  local _public_secrets=(
    "admin_initial_password"
    "admin1_password"
    "admin1_username"
    "admin1_totp_secret"
    "admin2_password"
    "admin2_username"
    "admin2_totp_secret"
    "postgres_password"
    "redis_password"
    "grafana_admin_password"
    "openclaw_gateway_token"
    "wazuh_indexer_password"
    "wazuh_api_password"
    "wazuh_dashboard_password"
  )
  for _f in "${_public_secrets[@]}"; do
    if [[ -f "${_secrets_dir}/${_f}" ]]; then
      chmod 0644 "${_secrets_dir}/${_f}"
    fi
  done
  # bootstrap_token files (glob — one per service registered in manifest)
  find "${_secrets_dir}" -maxdepth 1 -type f -name '*_bootstrap_token' \
    -exec chmod 0644 {} \;

  log_success "Service key ownership + canonical file modes reapplied"

  # Defensive assertion: no world/group-readable private key files (S1 / CWE-732).
  if find "${_secrets_dir}" -maxdepth 1 -type f -name '*.key' \
        \( -perm -004 -o -perm -040 \) 2>/dev/null | grep -q .; then
    log_error "CWE-732: group/world-readable *.key file(s) under ${_secrets_dir} after chown step"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# BUG-4 (v2.23.1): Refresh PGDATA-cached CA + server cert after PKI restore
# ---------------------------------------------------------------------------
# Postgres caches the CA trust bundle + server leaf inside PGDATA at first initdb.
# install.sh (05-enable-ssl.sh upgrade path) writes:
#   cat ca_root.crt ca_intermediate.crt > ${PGDATA}/root.crt   (trust bundle)
#   postgres_client.crt -> server.crt
#   postgres_client.key -> server.key
# On a fresh install the bundle in PGDATA and the CAs in /run/secrets/ are
# the same. After a restore, /run/secrets/ now carries the BACKUP's CAs but
# PGDATA still has the in-place install bundle -- every mTLS handshake against
# pgbouncer fails because pgbouncer presents a leaf signed by the restored CA
# while PGDATA root.crt only trusts the in-place CA.
#
# RETRO-R4-1: root.crt is a concatenated bundle (root + intermediate). The
# previous restore wrote only ca_root.crt, leaving a partial chain that
# postgres rejected for verify-ca peer-cert validation.
#
# Fix: cat both certs (matching install.sh exactly), install postgres leaf,
# pg_ctl reload (no restart needed -- TLS material is hot-reloadable).
#
# Pattern-sweep result: ONLY postgres caches CA-in-volume. redis, pgbouncer,
# gateway, backoffice, caddy, grafana all read /run/secrets/ca_root.crt or
# bind-mounts at runtime and pick up the new CA on a normal compose restart.
# Helm chart equivalent runs the same 05-enable-ssl.sh logic in the postgres
# init job, so the K8s path uses the same install + reload sequence via
# kubectl exec.
# ---------------------------------------------------------------------------
_refresh_pgdata_ca() {
  local pg_target=""
  pg_target=$(find_pg_container)

  if [[ -z "$pg_target" ]]; then
    log_warn "Postgres not running -- PGDATA CA refresh deferred."
    log_warn "  After bringing postgres up, exec into the postgres container and run:"
    log_warn "    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > \${PGDATA}/root.crt"
    log_warn "    chown postgres:postgres \${PGDATA}/root.crt && chmod 0640 \${PGDATA}/root.crt"
    log_warn "    install -m0644 -o postgres -g postgres /run/secrets/postgres_client.crt \${PGDATA}/server.crt"
    log_warn "    install -m0600 -o postgres -g postgres /run/secrets/postgres_client.key \${PGDATA}/server.key"
    log_warn "    pg_ctl -D \${PGDATA} reload"
    return 0
  fi

  log_info "Refreshing PGDATA-cached CA + server cert in ${pg_target}..."

  # RETRO-R4-1: install.sh writes root.crt as a CONCATENATED bundle:
  #   cat ca_root.crt ca_intermediate.crt > ${PGDATA}/root.crt
  # restore.sh previously wrote only ca_root.crt, leaving postgres with a
  # trust store missing the intermediate. pgbouncer presents leaves signed
  # by the intermediate; postgres's ssl_ca_file rejects them because the
  # chain is incomplete. Fix: match install.sh exactly — cat both PEMs.
  if ! pg_exec "$pg_target" sh -c '
    set -e
    PGDATA="${PGDATA:-/var/lib/postgresql/data/pgdata}"
    : "${PGDATA:?PGDATA env var unset in postgres container}"
    # Trust bundle: root + intermediate concatenated (must match install.sh line that
    # does: cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > ${PGDATA}/root.crt)
    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > "${PGDATA}/root.crt"
    chown postgres:postgres "${PGDATA}/root.crt"
    chmod 0640 "${PGDATA}/root.crt"
    install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
    install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${PGDATA}/server.key"
    # pg_ctl cannot run as root. Use gosu if available (official postgres image),
    # fall back to su -s /bin/sh postgres for other distros. Both drop to the
    # postgres UID before invoking pg_ctl. Compose/VM paths exec as the postgres
    # user natively; only K8s kubectl exec arrives as root.
    if command -v gosu >/dev/null 2>&1; then
      gosu postgres pg_ctl -D "${PGDATA}" reload
    else
      su -s /bin/sh postgres -c "pg_ctl -D \"${PGDATA}\" reload"
    fi
  '; then
    log_error "PGDATA CA refresh failed. mTLS between pgbouncer and postgres may be broken."
    log_error "  Manual recovery: exec into postgres, run:"
    log_error "    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > \${PGDATA}/root.crt"
    log_error "    chown postgres:postgres \${PGDATA}/root.crt && chmod 0640 \${PGDATA}/root.crt"
    log_error "    install -m0644 -o postgres -g postgres /run/secrets/postgres_client.crt \${PGDATA}/server.crt"
    log_error "    install -m0600 -o postgres -g postgres /run/secrets/postgres_client.key \${PGDATA}/server.key"
    log_error "    pg_ctl -D \${PGDATA} reload"
    return 1
  fi

  log_success "PGDATA CA + server cert refreshed; postgres reloaded TLS material"
}

# ---------------------------------------------------------------------------
# BUG-58B-04d (v2.23.1): Update the live yashigani_app role password to match
# the restored postgres_password secret.
#
# Why this is needed:
#   * Fresh install creates the cluster with password A (random, generated).
#   * The cluster persists the SCRAM hash of A in pg_authid; the file
#     POSTGRES_PASSWORD_FILE is only consulted at initdb time.
#   * Restore overwrites docker/secrets/postgres_password with backup's
#     password B. pgbouncer's auto-generated userlist.txt regenerates with B
#     on its next container start; the app reads B from the same secret.
#   * But the live cluster still authenticates against A → every TCP
#     connection from pgbouncer/app fails with "password authentication
#     failed for user yashigani_app".
#
# Fix: ALTER ROLE on the live cluster, idempotently, via the local Unix
# socket inside the postgres container. pg_hba.conf entry installed by
# docker/postgres/05-enable-ssl.sh is 'local all all trust' so password-
# less auth is permitted there (and only there).
#
# SQL is fed via stdin so the password never appears in process args (ps).
# Single quotes inside the password are escaped by doubling
# (standard_conforming_strings is on by default in modern postgres).
# ---------------------------------------------------------------------------
_restore_pg_role_password() {
  local _secret_file="${WORK_DIR}/docker/secrets/postgres_password"
  if [[ ! -f "$_secret_file" ]]; then
    log_warn "postgres_password secret missing — skipping role password update"
    return 0
  fi
  local _new_pw
  _new_pw=$(<"$_secret_file")
  if [[ -z "$_new_pw" ]]; then
    log_warn "postgres_password is empty — skipping role password update"
    return 0
  fi

  local _pg_container
  _pg_container=$(find_pg_container)
  if [[ -z "$_pg_container" ]]; then
    log_warn "Postgres not running -- role password update deferred."
    log_warn "  After bringing postgres up, run inside the postgres container:"
    log_warn "    psql -U yashigani_app -d postgres"
    log_warn "    ALTER ROLE \"yashigani_app\" WITH PASSWORD '<contents of docker/secrets/postgres_password>';"
    return 0
  fi

  # Determine the DB role from the restored .env (default yashigani_app —
  # the same default install.sh writes).
  local _db_user="yashigani_app"
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    local _dsn
    _dsn=$(grep "^YASHIGANI_DB_DSN=" "${WORK_DIR}/docker/.env" 2>/dev/null | head -1 || true)
    if [[ -n "$_dsn" ]]; then
      local _parsed
      _parsed=$(echo "$_dsn" | sed -n 's|.*://\([^:]*\):.*|\1|p')
      [[ -n "$_parsed" ]] && _db_user="$_parsed"
    fi
  fi

  # Escape single quotes in the password for SQL string literal.
  local _pw_escaped="${_new_pw//\'/\'\'}"

  log_info "Updating live ${_db_user} role password to match restored secret..."

  # Pipe SQL via stdin so the password never appears in process args.
  # Connect via local Unix socket → trust auth (per pg_hba.conf line 1
  # installed by docker/postgres/05-enable-ssl.sh).
  if ! printf '%s\n' "ALTER ROLE \"${_db_user}\" WITH PASSWORD '${_pw_escaped}';" \
        | pg_exec "$_pg_container" psql -U "$_db_user" -d postgres \
            -v ON_ERROR_STOP=1 -q --no-psqlrc >/dev/null; then
    log_error "Failed to update ${_db_user} role password on live cluster."
    log_error "  Manual recovery (run on host):"
    log_error "    ${RUNTIME} exec -it ${_pg_container} psql -U ${_db_user} -d postgres"
    log_error "    ALTER ROLE \"${_db_user}\" WITH PASSWORD '<contents of docker/secrets/postgres_password>';"
    return 1
  fi
  log_success "Role ${_db_user} password updated on live cluster"

  # RESTORE-2 (v2.23.1 gate): sync .env POSTGRES_PASSWORD + POSTGRES_PASSWORD_URLENC
  # to match the restored postgres_password secret.
  #
  # Root cause: install.sh generates an initial password, writes it to both .env and
  # docker/secrets/postgres_password. bootstrap_postgres.py (run by install.sh step 11)
  # regenerates the password and writes only to docker/secrets/postgres_password — .env
  # is NOT updated. After a restore, docker/secrets/postgres_password holds the backup's
  # final password but .env still has the initial install-time password. The backoffice
  # and gateway containers read YASHIGANI_DB_DSN from .env (which uses
  # POSTGRES_PASSWORD_URLENC), while pgbouncer's auto-generated userlist.txt reads from
  # the secrets file. These diverge → auth fails on every connection after compose up.
  #
  # Fix: after ALTER ROLE succeeds (live cluster authenticated against the secret),
  # update POSTGRES_PASSWORD and POSTGRES_PASSWORD_URLENC in .env to match.
  # URL-encode using Python (always available in backoffice image; or system python3).
  local _env_file="${WORK_DIR}/docker/.env"
  if [[ -f "$_env_file" ]]; then
    local _pw_urlenc
    _pw_urlenc=$(python3 -c \
      "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=''))" \
      "$_new_pw" 2>/dev/null || echo "")
    if [[ -n "$_pw_urlenc" ]]; then
      # Update or append POSTGRES_PASSWORD
      if grep -q "^POSTGRES_PASSWORD=" "$_env_file"; then
        # macOS BSD sed requires an explicit backup-extension arg (can be empty string).
        # GNU sed accepts sed -i "..." but BSD sed treats the pattern as the extension.
        # Use sed -i "" for portability across both.
        sed -i "" "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${_new_pw}|" "$_env_file" 2>/dev/null || \
          sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${_new_pw}|" "$_env_file"
      else
        printf 'POSTGRES_PASSWORD=%s\n' "$_new_pw" >> "$_env_file"
      fi
      # Update or append POSTGRES_PASSWORD_URLENC
      if grep -q "^POSTGRES_PASSWORD_URLENC=" "$_env_file"; then
        sed -i "" "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${_pw_urlenc}|" "$_env_file" 2>/dev/null || \
          sed -i "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${_pw_urlenc}|" "$_env_file"
      else
        printf 'POSTGRES_PASSWORD_URLENC=%s\n' "$_pw_urlenc" >> "$_env_file"
      fi
      log_success ".env POSTGRES_PASSWORD[_URLENC] synced to match restored secret (RESTORE-2 fix)"
    else
      log_warn "Could not URL-encode postgres password — .env POSTGRES_PASSWORD_URLENC not updated."
      log_warn "  Manual fix: update POSTGRES_PASSWORD and POSTGRES_PASSWORD_URLENC in ${_env_file}"
      log_warn "  to match: $(cat "${_secret_file}" 2>/dev/null || echo '<read docker/secrets/postgres_password>')"
    fi
  fi

  # Note: ALTER ROLE on a missing role would have errored out via
  # ON_ERROR_STOP=1 above. A loopback verify (psql -h 127.0.0.1) would NOT
  # actually validate the new password because pg_hba.conf has
  # 'host all all 127.0.0.1/32 trust'. A meaningful TCP verify requires
  # an SSL+client-cert handshake — out of scope for this helper. Operators
  # can verify by restarting pgbouncer + the app and confirming successful
  # connections in the logs.
}

# ---------------------------------------------------------------------------
# Restore Postgres dump (runtime-aware)
# ---------------------------------------------------------------------------
_restore_postgres() {
  local dump_file="$1"
  local dump_size dump_bytes
  dump_size=$(du -h "$dump_file" 2>/dev/null | awk '{print $1}')
  dump_bytes=$(wc -c < "$dump_file" 2>/dev/null | tr -d ' ')
  if [[ -z "$dump_bytes" || "$dump_bytes" -lt 100 ]]; then
    log_error "Postgres dump is empty or truncated (${dump_bytes} bytes) — refusing to restore"
    return 1
  fi
  log_info "Postgres dump found (${dump_size}). Attempting restore..."

  # Read DB user/name from .env if available (preserve existing parse)
  local db_user="yashigani_app"
  local db_name="yashigani"
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    local dsn
    dsn=$(grep "^YASHIGANI_DB_DSN=" "${WORK_DIR}/docker/.env" 2>/dev/null | head -1 || echo "")
    if [[ -n "$dsn" ]]; then
      # Extract user from postgresql://user:pass@host:port/db
      db_user=$(echo "$dsn" | sed -n 's|.*://\([^:]*\):.*|\1|p')
      db_name=$(echo "$dsn" | sed -n 's|.*/\([^?]*\).*|\1|p')
    fi
  fi

  # Read postgres superuser password from docker/secrets/postgres_password.
  # docker-compose.yml runs postgres as POSTGRES_USER=yashigani_app with
  # POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password, so yashigani_app
  # IS the superuser for this container — no separate super account.
  local pg_password=""
  if [[ -f "${WORK_DIR}/docker/secrets/postgres_password" ]]; then
    pg_password=$(<"${WORK_DIR}/docker/secrets/postgres_password")
  fi
  if [[ -z "$pg_password" ]]; then
    log_error "Cannot read docker/secrets/postgres_password — required for drop+recreate. Abort."
    return 1
  fi

  local pg_container
  pg_container=$(find_pg_container)

  if [[ -z "$pg_container" ]]; then
    log_warn "Postgres not running — dump saved for manual restore:"
    log_warn "  ${dump_file}"
    log_warn "  Manual (after 'compose up -d postgres'):"
    log_warn "    cat ${dump_file} | <runtime> exec -i <postgres_container> psql --single-transaction -v ON_ERROR_STOP=1 -U ${db_user} -d ${db_name}"
    return 0
  fi

  log_info "Found Postgres: ${pg_container}"
  log_info "Preparing target database '${db_name}' (terminate connections, drop, recreate)..."

  # Step 1: drop + recreate the target DB to guarantee clean schema-free state.
  # Connect to the 'postgres' system DB (always exists). Terminate any existing
  # connections to the target first, else DROP DATABASE hangs.
  #
  # Risk: this IS destructive — existing app state in "${db_name}" is wiped.
  # That is the intended semantics of a restore ("replace with backup").
  if ! pg_exec "$pg_container" env PGPASSWORD="$pg_password" \
        psql -U "$db_user" -d postgres -v ON_ERROR_STOP=1 -q <<EOF
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
  WHERE datname = '${db_name}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${db_name}";
CREATE DATABASE "${db_name}" OWNER "${db_user}";
EOF
  then
    log_error "Failed to drop+recreate '${db_name}'. Target DB may still have active connections from app containers."
    log_error "Remediation: stop app containers first (e.g. 'podman compose stop gateway backoffice'), then re-run restore."
    return 1
  fi
  log_success "Target database '${db_name}' recreated clean"

  # Step 2: feed dump with --single-transaction + ON_ERROR_STOP=1.
  # Any error aborts the whole transaction — no silent partial restore.
  # Do NOT swallow stderr with 2>/dev/null; surface errors to the operator.
  log_info "Loading dump into ${db_name} (single-transaction, fail-fast)..."
  if pg_exec "$pg_container" env PGPASSWORD="$pg_password" \
       psql --single-transaction -v ON_ERROR_STOP=1 \
            -U "$db_user" -d "$db_name" < "$dump_file"; then
    log_success "Postgres database restored (single-transaction, fail-fast)"
  else
    log_error "Postgres restore failed. Transaction was rolled back — database is back to the recreated-empty state."
    log_error "Review dump at: ${dump_file}"
    log_error "To investigate: cat ${dump_file} | <runtime> exec -i ${pg_container} psql -U ${db_user} -d ${db_name}"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Restore K8s secrets
# ---------------------------------------------------------------------------
_restore_k8s_secrets() {
  local secrets_dir="$1"
  log_info "Updating Kubernetes secrets in namespace '${K8S_NAMESPACE}'..."

  # Build --from-file args for all secret files
  local from_files=()
  for f in "${secrets_dir}"/*; do
    [[ -f "$f" ]] && from_files+=("--from-file=$(basename "$f")=$f")
  done

  if [[ ${#from_files[@]} -eq 0 ]]; then
    log_warn "No secret files to restore"
    return 0
  fi

  # Delete and recreate the secret (kubectl create --dry-run + apply is cleaner
  # but some clusters don't support dry-run=client)
  if kubectl -n "$K8S_NAMESPACE" delete secret yashigani-secrets 2>/dev/null; then
    log_info "Deleted existing yashigani-secrets"
  fi

  if kubectl -n "$K8S_NAMESPACE" create secret generic yashigani-secrets "${from_files[@]}" 2>/dev/null; then
    log_success "Kubernetes secrets restored (${#from_files[@]} files)"
  else
    log_error "Failed to create Kubernetes secret — check permissions"
  fi
}

# Patch the yashigani-postgres-secrets K8s secret with the restored postgres_password.
# This is separate from yashigani-secrets (the flat generic secret that holds all
# backup secret files) because the backoffice/gateway/pgbouncer deployments reference
# postgres_password via secretKeyRef on yashigani-postgres-secrets specifically.
# Without this patch the fresh-install password persists and all pods crash with
# "password authentication failed" after restore. (retro #3ca, gate #58c Round 12)
_restore_k8s_postgres_secrets() {
  local secrets_dir="$1"
  local pw_file="${secrets_dir}/postgres_password"

  if [[ ! -f "$pw_file" ]]; then
    log_warn "_restore_k8s_postgres_secrets: ${pw_file} not found — skipping yashigani-postgres-secrets patch"
    return 0
  fi

  local pw
  pw=$(<"$pw_file")
  if [[ -z "$pw" ]]; then
    log_warn "_restore_k8s_postgres_secrets: postgres_password is empty — skipping"
    return 0
  fi

  local pw_b64
  pw_b64=$(printf '%s' "$pw" | base64)

  log_info "Patching yashigani-postgres-secrets with restored postgres_password..."
  if kubectl -n "$K8S_NAMESPACE" patch secret yashigani-postgres-secrets \
      --type='json' \
      -p="[{\"op\":\"replace\",\"path\":\"/data/postgres_password\",\"value\":\"${pw_b64}\"}]"; then
    log_success "yashigani-postgres-secrets patched"
  else
    log_error "Failed to patch yashigani-postgres-secrets — post-restore pods will fail to connect to postgres"
  fi

  # retro #3cc (gate #58c Round 13): The K8s pre-existing chart bug workaround
  # (BUG-K1) patches the pgbouncer deployment's DATABASE_URL env to a LITERAL
  # password string (via kubectl set env). After a restore the secret is updated
  # but the deployment spec still carries the old literal, so pgbouncer userlist.txt
  # is populated with the stale password → postgres auth fails.
  # Fix: after patching the secret, also update DATABASE_URL in the pgbouncer
  # deployment spec to the restored password, so the next rollout gets the right
  # password regardless of whether BUG-K1 was previously applied.
  local db_user="yashigani_app"
  local pg_host="yashigani-postgres"
  local pg_db="yashigani"
  local new_db_url="postgresql://${db_user}:${pw}@${pg_host}:5432/${pg_db}"
  log_info "Updating pgbouncer DATABASE_URL to restored password..."
  if kubectl -n "$K8S_NAMESPACE" set env deployment/yashigani-pgbouncer \
      "DATABASE_URL=${new_db_url}" 2>/dev/null; then
    log_success "pgbouncer DATABASE_URL updated (restored password)"
  else
    log_warn "kubectl set env on pgbouncer failed — pgbouncer may not accept restored password. Manual: kubectl set env deployment/yashigani-pgbouncer -n ${K8S_NAMESPACE} 'DATABASE_URL=${new_db_url}'"
  fi
}

# ---------------------------------------------------------------------------
# PR #67 K8s verify path (retro K8s gap, v2.23.3):
#
# After _restore_k8s_secrets + _restore_k8s_postgres_secrets update the K8s
# secrets and patch pgbouncer's DATABASE_URL, the running pods still have the
# OLD secret values in their environment (K8s does not hot-reload secrets into
# running pods unless the pods are restarted). Without an explicit rollout
# restart + wait, the restore "succeeds" while every pod continues to use the
# pre-restore credentials → auth failures on the next request.
#
# This function:
#   1. Triggers `kubectl rollout restart deployment` across all Yashigani
#      deployments in the namespace.
#   2. Waits for each deployment to reach its desired state with a 300s
#      timeout (enough for rolling restart on Docker Desktop / kind; extend
#      with KUBECTL_ROLLOUT_TIMEOUT if needed).
#   3. Probes the gateway's /healthz endpoint via `kubectl exec` to confirm
#      the restored pod is serving. A non-200 response is surfaced as a
#      warning — the restore is already committed, but the operator must
#      investigate before declaring success.
# ---------------------------------------------------------------------------
_k8s_post_restore_verify() {
  local _ns="${K8S_NAMESPACE}"
  local _timeout="${KUBECTL_ROLLOUT_TIMEOUT:-300s}"

  log_info "K8s post-restore: restarting deployments in namespace '${_ns}'..."

  # Collect all Yashigani-owned deployments.
  local _deployments
  _deployments=$(kubectl get deployments -n "${_ns}" \
    -l "app.kubernetes.io/instance=yashigani" \
    -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)

  if [[ -z "${_deployments}" ]]; then
    # Fall back to all deployments in the namespace if the label selector
    # returns nothing (e.g. label not present on all resources).
    _deployments=$(kubectl get deployments -n "${_ns}" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  fi

  if [[ -z "${_deployments}" ]]; then
    log_warn "No deployments found in namespace '${_ns}' — skipping rollout restart"
    return 0
  fi

  if ! kubectl rollout restart deployment -n "${_ns}" >/dev/null 2>&1; then
    log_warn "kubectl rollout restart failed — pods may still carry pre-restore credentials. Manual: kubectl rollout restart deployment -n ${_ns}"
  else
    log_info "Rollout restart triggered. Waiting for deployments to become ready (timeout: ${_timeout})..."
  fi

  # Wait for each deployment individually so we can report per-deployment failures.
  local _failed=0
  for _dep in ${_deployments}; do
    if ! kubectl rollout status deployment/"${_dep}" \
        --namespace "${_ns}" \
        --timeout="${_timeout}" >/dev/null 2>&1; then
      log_warn "Deployment ${_dep} did not reach Ready within ${_timeout} — check: kubectl get pods -n ${_ns} -l app.kubernetes.io/name=${_dep}"
      _failed=$((_failed + 1))
    else
      log_info "  deployment/${_dep}: Ready"
    fi
  done

  if [[ "${_failed}" -gt 0 ]]; then
    log_warn "${_failed} deployment(s) did not stabilise — restore committed but service may be degraded. Investigate before use."
    return 0  # non-fatal: restore data is already in place
  fi

  log_info "All deployments ready. Probing gateway /healthz..."

  # Probe via kubectl exec to avoid network dependency (no port-forward required).
  local _healthz
  _healthz=$(kubectl exec -n "${_ns}" deployment/yashigani-gateway -- \
    curl -sf --max-time 5 http://localhost:8080/healthz 2>/dev/null || true)

  if [[ -z "${_healthz}" ]]; then
    log_warn "Gateway /healthz probe returned no output — service may be starting up. Retry: kubectl exec -n ${_ns} deployment/yashigani-gateway -- curl -sf http://localhost:8080/healthz"
  else
    log_success "Gateway /healthz OK: ${_healthz}"
  fi
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
RESTORE_TARGET=""
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s|--kubernetes)
      K8S_MODE=true
      shift
      ;;
    -n|--namespace)
      K8S_NAMESPACE="$2"
      shift 2
      ;;
    --latest)
      RESTORE_TARGET="--latest"
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Yashigani Restore Script

Usage:
  bash restore.sh                              List available backups
  bash restore.sh <backup_dir>                 Restore from specific backup
  bash restore.sh --latest                     Restore most recent backup
  bash restore.sh --latest --k8s -n yashigani  Restore into Kubernetes

Options:
  --k8s, --kubernetes   Restore into a Kubernetes cluster
  -n, --namespace NS    Kubernetes namespace (default: yashigani)
  --latest              Use most recent backup
  --force               Skip validation warnings
  --help                Show this help

Supported platforms:
  - Docker Compose (Linux/macOS)
  - Podman Compose (Linux/macOS rootless)
  - Kubernetes (via kubectl)
EOF
      exit 0
      ;;
    *)
      RESTORE_TARGET="$1"
      shift
      ;;
  esac
done

detect_runtime

case "${RESTORE_TARGET}" in
  "")
    list_backups
    ;;
  --latest)
    latest=$(find "${BACKUPS_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -1)
    if [[ -z "$latest" ]]; then
      log_error "No backups found"
      exit 1
    fi
    restore_backup "$latest"
    ;;
  *)
    if [[ -d "$RESTORE_TARGET" ]]; then
      restore_backup "$RESTORE_TARGET"
    elif [[ -d "${BACKUPS_DIR}/${RESTORE_TARGET}" ]]; then
      restore_backup "${BACKUPS_DIR}/${RESTORE_TARGET}"
    else
      log_error "Backup not found: ${RESTORE_TARGET}"
      list_backups
      exit 1
    fi
    ;;
esac
