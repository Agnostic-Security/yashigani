#!/usr/bin/env bash
# update.sh — Yashigani v2.23.4
# last-updated: 2026-05-21T00:00:00+00:00 (v2.23.4 release: bump header from 2.23.3)
# last-updated: 2026-05-04T00:00:00+01:00 (feat: verify_health + auto-rollback wiring — retro #59)
# Updates an existing Yashigani installation to the latest version.
#
# Usage:
#   ./update.sh                          # Interactive update
#   ./update.sh --target 2.1.0           # Update to specific version
#   ./update.sh --skip-backup            # Skip pre-update backup
#   ./update.sh --dry-run                # Show what would happen
#   ./update.sh --rollback               # Rollback to previous version
#   ./update.sh --health-timeout 180     # Per-service health-check timeout
#   ./update.sh --no-auto-rollback       # Disable auto-rollback on health failure

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_VERSION="2.1.0"
REPO_URL="${YASHIGANI_REPO_URL:-https://github.com/agnosticsec-com/yashigani.git}"
RELEASES_API="https://api.github.com/repos/agnosticsec-com/yashigani/releases/latest"

# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET="\033[0m"; C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"
  C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"; C_BOLD="\033[1m"
else
  C_RESET=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""
fi

log_step()    { printf "${C_BLUE}[ %s ] %s${C_RESET}\n" "$1" "$2"; }
log_info()    { printf "${C_BOLD}    --> %s${C_RESET}\n" "$1"; }
log_success() { printf "${C_GREEN}    ok  %s${C_RESET}\n" "$1"; }
log_warn()    { printf "${C_YELLOW}    !!  WARNING: %s${C_RESET}\n" "$1" >&2; }
log_error()   { printf "${C_RED}    !!  ERROR: %s${C_RESET}\n" "$1" >&2; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TARGET_VERSION=""
SKIP_BACKUP=false
DRY_RUN=false
ROLLBACK=false
NO_AUTO_ROLLBACK=false
HEALTH_TIMEOUT=120
INSTALL_DIR=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BOLD}Yashigani Updater v${CURRENT_VERSION}${C_RESET}

USAGE
  update.sh [OPTIONS]

OPTIONS
  --target VERSION       Update to a specific version (default: latest release)
  --skip-backup          Skip pre-update backup of config and data
  --dry-run              Show what would happen without making changes
  --rollback             Rollback to the previous version (from backup)
  --health-timeout SECS  Per-service health-check timeout in seconds (default: 120)
  --no-auto-rollback     On health-check failure, do NOT auto-rollback. Caller
                         must inspect and run \`./update.sh --rollback\` manually.
  --help                 Show this help and exit

EXAMPLES
  ./update.sh                     # Update to latest
  ./update.sh --target 0.9.2      # Update to v0.9.2
  ./update.sh --rollback          # Rollback to previous version
  ./update.sh --no-auto-rollback  # Update; skip auto-rollback if health fails
EOF
  exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)          TARGET_VERSION="$2";   shift 2 ;;
    --skip-backup)     SKIP_BACKUP=true;      shift ;;
    --dry-run)         DRY_RUN=true;          shift ;;
    --rollback)        ROLLBACK=true;         shift ;;
    --health-timeout)  HEALTH_TIMEOUT="$2";   shift 2 ;;
    --no-auto-rollback) NO_AUTO_ROLLBACK=true; shift ;;
    --help|-h)         usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Detect installation directory
# ---------------------------------------------------------------------------
detect_install_dir() {
  log_step "1/8" "Detecting Yashigani installation..."

  # Check if we're inside the repo
  if [[ -f "${SCRIPT_DIR}/docker/docker-compose.yml" ]]; then
    INSTALL_DIR="$SCRIPT_DIR"
    log_success "Found installation: ${INSTALL_DIR}"
    return 0
  fi

  # Check common install location
  local default_dir="${YSG_INSTALL_DIR:-$HOME/.yashigani}"
  if [[ -d "$default_dir" && -f "${default_dir}/docker/docker-compose.yml" ]]; then
    INSTALL_DIR="$default_dir"
    log_success "Found installation: ${INSTALL_DIR}"
    return 0
  fi

  log_error "No Yashigani installation found."
  log_error "Run this script from within the Yashigani directory, or set YSG_INSTALL_DIR."
  exit 1
}

# ---------------------------------------------------------------------------
# Detect current installed version
# ---------------------------------------------------------------------------
detect_current_version() {
  log_step "2/8" "Checking installed version..."

  local installed_version=""

  # Try install.sh version string
  if [[ -f "${INSTALL_DIR}/install.sh" ]]; then
    installed_version="$(grep -oE 'YASHIGANI_VERSION="[0-9]+\.[0-9]+\.[0-9]+"' "${INSTALL_DIR}/install.sh" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")"
  fi

  # Try docker image label
  if [[ -z "$installed_version" ]] && command -v docker >/dev/null 2>&1; then
    installed_version="$(docker inspect --format='{{index .Config.Labels "org.opencontainers.image.version"}}' yashigani-gateway 2>/dev/null || echo "")"
  fi

  if [[ -z "$installed_version" ]]; then
    installed_version="unknown"
  fi

  CURRENT_VERSION="$installed_version"
  log_info "Installed version: v${CURRENT_VERSION}"
}

# ---------------------------------------------------------------------------
# Check for latest version
# ---------------------------------------------------------------------------
check_latest_version() {
  log_step "3/8" "Checking for updates..."

  if [[ -n "$TARGET_VERSION" ]]; then
    log_info "Target version specified: v${TARGET_VERSION}"
    return 0
  fi

  # Try GitHub API for latest release
  if command -v curl >/dev/null 2>&1; then
    local latest
    latest="$(curl -sSL "$RELEASES_API" 2>/dev/null | grep -oE '"tag_name"\s*:\s*"v?[0-9]+\.[0-9]+\.[0-9]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")"
    if [[ -n "$latest" ]]; then
      TARGET_VERSION="$latest"
      log_info "Latest available: v${TARGET_VERSION}"
    fi
  fi

  # Try git tags if in a git repo
  if [[ -z "$TARGET_VERSION" ]] && [[ -d "${INSTALL_DIR}/.git" ]] && command -v git >/dev/null 2>&1; then
    git -C "$INSTALL_DIR" fetch --tags --quiet 2>/dev/null || true
    local latest_tag
    latest_tag="$(git -C "$INSTALL_DIR" tag -l 'v*' --sort=-v:refname 2>/dev/null | head -1 | sed 's/^v//' || echo "")"
    if [[ -n "$latest_tag" ]]; then
      TARGET_VERSION="$latest_tag"
      log_info "Latest tag: v${TARGET_VERSION}"
    fi
  fi

  if [[ -z "$TARGET_VERSION" ]]; then
    log_error "Could not determine latest version. Use --target VERSION to specify."
    exit 1
  fi

  # Compare versions
  if [[ "$CURRENT_VERSION" == "$TARGET_VERSION" ]]; then
    log_success "Already running v${CURRENT_VERSION} — nothing to update."
    exit 0
  fi

  log_info "Update available: v${CURRENT_VERSION} → v${TARGET_VERSION}"
}

# ---------------------------------------------------------------------------
# Backup current installation
# ---------------------------------------------------------------------------
backup_current() {
  log_step "4/8" "Backing up current installation..."

  if [[ "$SKIP_BACKUP" == "true" ]]; then
    log_warn "Skipping backup (--skip-backup)"
    return 0
  fi

  local backup_dir="${INSTALL_DIR}/backups"
  local backup_name="pre-update-v${CURRENT_VERSION}-$(date +%Y%m%d-%H%M%S)"
  local backup_path="${backup_dir}/${backup_name}"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would create backup at: ${backup_path}"
    return 0
  fi

  mkdir -p "$backup_path"

  # Backup configuration files
  local files_to_backup=(
    "docker/docker-compose.yml"
    "docker/.env"
    "docker/Caddyfile.acme"
    "docker/Caddyfile.ca"
    "docker/Caddyfile.selfsigned"
    "config/opa/rbac.rego"
    "config/opa/data.json"
    "helm/yashigani/values.yaml"
  )

  for f in "${files_to_backup[@]}"; do
    local src="${INSTALL_DIR}/${f}"
    if [[ -f "$src" ]]; then
      local dest_dir="${backup_path}/$(dirname "$f")"
      mkdir -p "$dest_dir"
      cp "$src" "${backup_path}/${f}"
    fi
  done

  # Backup licence file if present
  if [[ -f "${INSTALL_DIR}/keys/license.ysg" ]]; then
    mkdir -p "${backup_path}/keys"
    cp "${INSTALL_DIR}/keys/license.ysg" "${backup_path}/keys/"
  fi

  # Save current docker-compose state
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "${INSTALL_DIR}/docker/docker-compose.yml" config > "${backup_path}/compose-resolved.yml" 2>/dev/null || true
  fi

  # Record the version we're upgrading from
  echo "$CURRENT_VERSION" > "${backup_path}/VERSION"

  log_success "Backup created: ${backup_path}"

  # Keep only the last 5 backups
  local backup_count
  backup_count="$(ls -1d "${backup_dir}"/pre-update-* 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$backup_count" -gt 5 ]]; then
    log_info "Cleaning old backups (keeping last 5)..."
    ls -1dt "${backup_dir}"/pre-update-* 2>/dev/null | tail -n +"6" | xargs rm -rf
  fi
}

# ---------------------------------------------------------------------------
# Pull new version
# ---------------------------------------------------------------------------
pull_update() {
  log_step "5/8" "Pulling v${TARGET_VERSION}..."

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would pull version v${TARGET_VERSION}"
    return 0
  fi

  # Git-based update
  if [[ -d "${INSTALL_DIR}/.git" ]] && command -v git >/dev/null 2>&1; then
    log_info "Updating via git..."

    # Stash any local changes to config files
    local has_changes=false
    if ! git -C "$INSTALL_DIR" diff --quiet 2>/dev/null; then
      has_changes=true
      log_info "Stashing local config changes..."
      git -C "$INSTALL_DIR" stash push -m "pre-update-v${TARGET_VERSION}" --include-untracked 2>/dev/null || true
    fi

    # Fetch and checkout target version
    git -C "$INSTALL_DIR" fetch --tags --quiet 2>/dev/null
    if git -C "$INSTALL_DIR" rev-parse "v${TARGET_VERSION}" >/dev/null 2>&1; then
      git -C "$INSTALL_DIR" checkout "v${TARGET_VERSION}" --quiet
      log_success "Checked out v${TARGET_VERSION}"
    elif git -C "$INSTALL_DIR" rev-parse "origin/main" >/dev/null 2>&1; then
      git -C "$INSTALL_DIR" pull --ff-only origin main --quiet
      log_success "Pulled latest from main"
    else
      log_error "Could not find tag v${TARGET_VERSION} or branch main"
      exit 1
    fi

    # Reapply stashed changes
    if [[ "$has_changes" == "true" ]]; then
      log_info "Reapplying local config changes..."
      git -C "$INSTALL_DIR" stash pop 2>/dev/null || {
        log_warn "Could not auto-merge config changes. Check git stash list."
      }
    fi

  # Tarball-based update
  elif command -v curl >/dev/null 2>&1; then
    log_info "Updating via tarball download..."
    local tarball_url="https://github.com/agnosticsec-com/yashigani/archive/refs/tags/v${TARGET_VERSION}.tar.gz"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    curl -sSL "$tarball_url" | tar xz -C "$tmp_dir" --strip-components=1

    if [[ ! -f "${tmp_dir}/docker/docker-compose.yml" ]]; then
      log_error "Downloaded archive does not look like a Yashigani release"
      rm -rf "$tmp_dir"
      exit 1
    fi

    # Preserve user config, overwrite everything else
    local preserve_files=(
      "docker/.env"
      "config/opa/data.json"
      "keys/license.ysg"
    )
    for f in "${preserve_files[@]}"; do
      if [[ -f "${INSTALL_DIR}/${f}" ]]; then
        local dest_dir="${tmp_dir}/$(dirname "$f")"
        mkdir -p "$dest_dir"
        cp "${INSTALL_DIR}/${f}" "${tmp_dir}/${f}"
      fi
    done

    # Replace installation
    rsync -a --delete \
      --exclude 'backups/' \
      --exclude '.env' \
      --exclude 'keys/' \
      --exclude 'config/opa/data.json' \
      "${tmp_dir}/" "${INSTALL_DIR}/"

    rm -rf "$tmp_dir"
    log_success "Files updated to v${TARGET_VERSION}"

  else
    log_error "No git or curl available — cannot pull update"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Pull new container images
# ---------------------------------------------------------------------------
pull_images() {
  log_step "6/8" "Pulling updated container images..."

  local compose_file="${INSTALL_DIR}/docker/docker-compose.yml"

  if [[ ! -f "$compose_file" ]]; then
    log_warn "docker-compose.yml not found — skipping image pull"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would run: docker compose pull"
    return 0
  fi

  # Detect runtime
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      docker compose -f "$compose_file" pull 2>&1 | tail -5
    elif command -v docker-compose >/dev/null 2>&1; then
      docker-compose -f "$compose_file" pull 2>&1 | tail -5
    fi
  elif command -v podman >/dev/null 2>&1; then
    if command -v podman-compose >/dev/null 2>&1; then
      podman-compose -f "$compose_file" pull 2>&1 | tail -5
    fi
  else
    log_warn "No container runtime available — skipping image pull"
    return 0
  fi

  log_success "Container images updated"
}

# ---------------------------------------------------------------------------
# Restart services
# ---------------------------------------------------------------------------
restart_services() {
  log_step "7/8" "Restarting services..."

  local compose_file="${INSTALL_DIR}/docker/docker-compose.yml"

  if [[ ! -f "$compose_file" ]]; then
    log_warn "docker-compose.yml not found — skipping restart"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would run: docker compose up -d --remove-orphans"
    return 0
  fi

  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      docker compose -f "$compose_file" up -d --remove-orphans
    elif command -v docker-compose >/dev/null 2>&1; then
      docker-compose -f "$compose_file" up -d --remove-orphans
    fi
  elif command -v podman >/dev/null 2>&1 && command -v podman-compose >/dev/null 2>&1; then
    podman-compose -f "$compose_file" up -d --remove-orphans
  else
    log_warn "Could not restart services — no runtime available"
    log_info "Manually run: docker compose -f ${compose_file} up -d"
    return 0
  fi

  log_success "Services restarted on v${TARGET_VERSION}"
}

# ---------------------------------------------------------------------------
# Verify health (post-restart)
# ---------------------------------------------------------------------------
# retro #59 — runs scripts/health-check.sh after services restart and returns
# its exit code. main() consumes that code to decide whether to auto-rollback.
# Returns 0 on healthy, non-zero on unhealthy or missing health-check.sh.
# ---------------------------------------------------------------------------
verify_health() {
  log_step "8/8" "Verifying service health..."

  local hc="${INSTALL_DIR}/scripts/health-check.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would run: ${hc} --timeout ${HEALTH_TIMEOUT}"
    return 0
  fi

  if [[ ! -x "$hc" ]]; then
    log_warn "Health check script not found or not executable: ${hc}"
    log_warn "Skipping verification — install MAY be unhealthy and auto-rollback is disabled."
    return 0
  fi

  log_info "Running ${hc} --timeout ${HEALTH_TIMEOUT}"
  if "$hc" --timeout "$HEALTH_TIMEOUT"; then
    log_success "Health check PASSED — upgrade is healthy."
    return 0
  fi

  log_error "Health check FAILED on v${TARGET_VERSION}."
  return 1
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------
# TODO(v2.24.0 #47): Wire YASHIGANI_BACKUPS_DIR + POST /admin/backup/verify here.
# Rollback currently invokes restore.sh directly via shell; the backoffice
# container is not guaranteed to be running during an upgrade window.
# Track: https://github.com/agnosticsec-com/yashigani/issues/47
do_rollback() {
  log_step "1/3" "Finding latest backup..."

  local backup_dir="${INSTALL_DIR}/backups"
  if [[ ! -d "$backup_dir" ]]; then
    log_error "No backups directory found at ${backup_dir}"
    exit 1
  fi

  local latest_backup
  latest_backup="$(ls -1dt "${backup_dir}"/pre-update-* 2>/dev/null | head -1 || echo "")"
  if [[ -z "$latest_backup" || ! -d "$latest_backup" ]]; then
    log_error "No backup found to rollback to"
    exit 1
  fi

  local rollback_version
  rollback_version="$(cat "${latest_backup}/VERSION" 2>/dev/null || echo "unknown")"
  log_info "Rolling back to v${rollback_version} from backup: $(basename "$latest_backup")"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would restore files from ${latest_backup}"
    return 0
  fi

  # Restore backed-up config files
  log_step "2/3" "Restoring configuration..."
  local restore_count=0
  # Use find + exec instead of process substitution (bash 3.2 compatible)
  find "$latest_backup" -type f -print 2>/dev/null | while IFS= read -r f; do
    rel_path="${f#${latest_backup}/}"
    dest="${INSTALL_DIR}/${rel_path}"
    dest_dir="$(dirname "$dest")"
    mkdir -p "$dest_dir"
    cp "$f" "$dest"
    restore_count=$((restore_count + 1))
  done
  # Count files restored (pipe runs in subshell so restore_count doesn't propagate)
  restore_count="$(find "$latest_backup" -type f 2>/dev/null | wc -l | tr -d ' ')"
  log_success "Restored ${restore_count} files"

  # If git repo, checkout the old version tag
  if [[ -d "${INSTALL_DIR}/.git" ]] && command -v git >/dev/null 2>&1; then
    if [[ "$rollback_version" != "unknown" ]]; then
      git -C "$INSTALL_DIR" checkout "v${rollback_version}" --quiet 2>/dev/null || true
    fi
  fi

  # Restart services
  log_step "3/3" "Restarting services on v${rollback_version}..."
  local compose_file="${INSTALL_DIR}/docker/docker-compose.yml"
  if [[ -f "$compose_file" ]] && command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      docker compose -f "$compose_file" up -d --remove-orphans
    elif command -v docker-compose >/dev/null 2>&1; then
      docker-compose -f "$compose_file" up -d --remove-orphans
    fi
  fi

  log_success "Rollback to v${rollback_version} complete"
}

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
print_summary() {
  printf "\n"
  printf "${C_GREEN}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_GREEN}║    Update complete: v%-8s → v%-8s        ║${C_RESET}\n" "$CURRENT_VERSION" "$TARGET_VERSION"
  printf "${C_GREEN}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"
  printf "  ${C_BOLD}What was updated:${C_RESET}\n"
  printf "    - Source files and scripts\n"
  printf "    - Container images\n"
  printf "    - Services restarted\n"
  printf "\n"
  printf "  ${C_BOLD}What was preserved:${C_RESET}\n"
  printf "    - Your .env configuration\n"
  printf "    - Your OPA policies (data.json)\n"
  printf "    - Your licence key\n"
  printf "    - Your database (PostgreSQL data volume)\n"
  printf "\n"
  printf "  ${C_BOLD}Rollback:${C_RESET}\n"
  printf "    If something went wrong: ${C_YELLOW}./update.sh --rollback${C_RESET}\n"
  printf "\n"
  printf "  ${C_BOLD}Verify:${C_RESET}\n"
  printf "    Health check:  ${C_BLUE}bash scripts/health-check.sh${C_RESET}\n"
  printf "    Gateway logs:  ${C_BLUE}docker compose -f docker/docker-compose.yml logs -f gateway${C_RESET}\n"
  printf "\n"

  if [[ "$DRY_RUN" == "true" ]]; then
    printf "  ${C_YELLOW}This was a dry run — no changes were made.${C_RESET}\n\n"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  printf "\n"
  printf "${C_BLUE}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_BLUE}║    Yashigani Updater                              ║${C_RESET}\n"
  printf "${C_BLUE}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  detect_install_dir

  if [[ "$ROLLBACK" == "true" ]]; then
    do_rollback
    exit 0
  fi

  detect_current_version
  check_latest_version
  backup_current
  pull_update
  pull_images
  restart_services

  # retro #59 — wire health check + auto-rollback on failure.
  if ! verify_health; then
    if [[ "$NO_AUTO_ROLLBACK" == "true" ]]; then
      log_warn "--no-auto-rollback set: leaving v${TARGET_VERSION} running for inspection."
      log_warn "Run \`./update.sh --rollback\` once you are ready to revert."
      exit 1
    fi
    log_warn "Auto-rollback engaged: reverting to v${CURRENT_VERSION}..."
    do_rollback
    log_error "Upgrade to v${TARGET_VERSION} aborted; rolled back to v${CURRENT_VERSION}."
    exit 1
  fi

  print_summary
}

# Sourceable guard: tests can `source update.sh` with YSG_UPDATE_NO_AUTORUN=1
# to exercise functions in isolation without main() running.
if [[ "${YSG_UPDATE_NO_AUTORUN:-0}" != "1" ]]; then
  main "$@"
fi
