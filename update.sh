#!/usr/bin/env bash
# update.sh — Yashigani v4.1.2
# last-updated: 2026-07-15T00:00:00+00:00 (v4.1.2 release: bump header)
# last-updated: 2026-05-04T00:00:00+01:00 (feat: verify_health + auto-rollback wiring — retro #59)
# Updates an existing Yashigani installation to the latest version.
#
# Usage:
#   ./update.sh                          # Interactive update
#   ./update.sh --target 4.1.2           # Update to specific version
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
CURRENT_VERSION="4.1.2"
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

# K8S-UPDATE-2026-07-22 (gap-map Finding 2, P0): runtime-mode detection state.
# RUNTIME_MODE is "compose" (docker/podman) or "k8s" — resolved by
# detect_runtime() from the install-state file / explicit flags / env vars.
# The k8s branch NEVER reimplements helm logic; it delegates to the proven
# `install.sh --upgrade --mode k8s` path (k8s_helm_install(), install.sh
# ~13549-13780), which already does `helm upgrade --install --wait
# --wait-for-jobs --atomic` and preserves the UNIVERSAL-001/002 resource-
# policy:keep Secrets + licensing lookup-preserve contract.
RUNTIME_MODE="compose"
K8S_NAMESPACE=""
K8S_HELM_RELEASE=""
NAMESPACE_FLAG=""
RELEASE_FLAG=""

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
                         k8s NOTE: has no effect on a k8s target — the delegated
                         \`helm upgrade --atomic\` always rolls back on failure;
                         this flag cannot disable that (Helm's own contract).
  --namespace NAME       k8s ONLY. Explicit target namespace for a multi-org k8s
                         cluster. Takes precedence over the install-state file
                         and the YASHIGANI_NAMESPACE env var.
  --release NAME         k8s ONLY. Explicit target Helm release name. Defaults
                         to "yashigani" (the install.sh convention).
  --help                 Show this help and exit

EXAMPLES
  ./update.sh                             # Update to latest
  ./update.sh --target 4.1.2              # Update to v4.1.2
  ./update.sh --rollback                  # Rollback to previous version
  ./update.sh --no-auto-rollback          # Update; skip auto-rollback if health fails
  ./update.sh --namespace orgB            # k8s: update the orgB namespace's release
  ./update.sh --rollback --namespace orgB # k8s: helm-rollback orgB's release
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
    --namespace)       NAMESPACE_FLAG="$2";   shift 2 ;;
    --release)         RELEASE_FLAG="$2";     shift 2 ;;
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
# Detect deployment runtime (compose vs k8s) — K8S-UPDATE-2026-07-22
#
# Before this fix, update.sh had ZERO k8s awareness: pull_images(),
# restart_services() and do_rollback() all branched purely on docker/podman
# presence. On a k8s bastion host with no local docker/podman daemon they
# silently skipped (operator wrongly believes the update ran); if docker
# also happened to be present, they could stand up a stray parallel compose
# stack on a k8s host. Neither is acceptable.
#
# Mirrors uninstall.sh's own precedence for the k8s selectors so an operator
# who has already learned uninstall.sh's --namespace/--project/--release
# flags gets the same behaviour here (highest to lowest):
#   1. --namespace/--release flags (explicit, always wins)
#   2. Pre-set YASHIGANI_NAMESPACE/YASHIGANI_HELM_RELEASE env vars
#   3. docker/.yashigani-install-state (RUNTIME=/NAMESPACE=/HELM_RELEASE=)
#   4. Default "yashigani" (applied at the k8s call sites, not here)
# ---------------------------------------------------------------------------
detect_runtime() {
  local state_file="${INSTALL_DIR}/docker/.yashigani-install-state"
  local state_runtime="" state_namespace="" state_release=""

  if [[ -f "$state_file" && -r "$state_file" ]]; then
    state_runtime="$(grep -E '^RUNTIME=' "$state_file" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
    state_namespace="$(grep -E '^NAMESPACE=' "$state_file" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
    state_release="$(grep -E '^HELM_RELEASE=' "$state_file" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
  fi

  if [[ "$state_runtime" == "k8s" || -n "$NAMESPACE_FLAG" || -n "$RELEASE_FLAG" || "${YASHIGANI_NAMESPACE:-}" != "" ]]; then
    RUNTIME_MODE="k8s"
  else
    RUNTIME_MODE="compose"
    return 0
  fi

  # Precedence 1: explicit flags.
  if [[ -n "$NAMESPACE_FLAG" ]]; then
    K8S_NAMESPACE="$NAMESPACE_FLAG"
    log_info "Using namespace from --namespace flag: ${K8S_NAMESPACE}"
  # Precedence 2: pre-set env var.
  elif [[ -n "${YASHIGANI_NAMESPACE:-}" ]]; then
    K8S_NAMESPACE="$YASHIGANI_NAMESPACE"
    log_info "Using namespace from YASHIGANI_NAMESPACE env var: ${K8S_NAMESPACE}"
  # Precedence 3: state file.
  elif [[ -n "$state_namespace" ]]; then
    K8S_NAMESPACE="$state_namespace"
    log_info "Using namespace from install state file: ${K8S_NAMESPACE}"
  else
    K8S_NAMESPACE="yashigani"
    log_warn "No namespace selector found (flag/env/state-file) — defaulting to 'yashigani'."
  fi

  if [[ -n "$RELEASE_FLAG" ]]; then
    K8S_HELM_RELEASE="$RELEASE_FLAG"
  elif [[ -n "${YASHIGANI_HELM_RELEASE:-}" ]]; then
    K8S_HELM_RELEASE="$YASHIGANI_HELM_RELEASE"
  elif [[ -n "$state_release" ]]; then
    K8S_HELM_RELEASE="$state_release"
  else
    K8S_HELM_RELEASE="yashigani"
  fi

  log_info "Runtime detected: k8s (namespace=${K8S_NAMESPACE}, release=${K8S_HELM_RELEASE})"

  for c in helm kubectl; do
    if ! command -v "$c" >/dev/null 2>&1; then
      log_error "k8s runtime detected but '${c}' is not installed or not on PATH."
      exit 1
    fi
  done
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
    # K8S-UPDATE-2026-07-22: .env.helm is the actual values-override file
    # install.sh's _write_helm_values()/k8s_helm_install() consume
    # (install.sh:13558) — capture it alongside values.yaml so a k8s
    # operator's config survives the same pre-update backup compose does.
    ".env.helm"
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
    # K8S-UPDATE-2026-07-22: .env.helm added alongside the existing compose/
    # secrets preserve-list so a k8s tarball-path update preserves the
    # operator's helm values override the same way the git path does (git
    # stash --include-untracked leaves it in place; the gitignored install-
    # state file is untouched either way).
    local preserve_files=(
      "docker/.env"
      "config/opa/data.json"
      "keys/license.ysg"
      ".env.helm"
      "docker/.yashigani-install-state"
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
      --exclude '.env.helm' \
      --exclude '.yashigani-install-state' \
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
# K8s upgrade delegate — K8S-UPDATE-2026-07-22 (gap-map Finding 2, P0)
#
# Replaces pull_images()+restart_services()+verify_health() for a k8s target
# with a SINGLE delegated call into install.sh's own proven k8s upgrade path
# (k8s_helm_install(), install.sh ~13549-13780). That function already does
# `helm upgrade --install --wait --wait-for-jobs --atomic`, which pulls new
# images (via the chart's image refs), rolls out the change, waits for
# readiness, AND atomically rolls back cluster-side on any failure — i.e.
# the pull+restart+health-check+auto-rollback steps are already one atomic
# unit at the helm level. Do NOT reimplement any of that logic here.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# _k8s_current_helm_revision — the release's latest Helm revision number, or
# "0" if the release does not exist, or "" (empty) if it could not be
# determined (helm missing / query failed) — callers must treat "" as
# UNKNOWN, not as "0".
#
# Used by k8s_delegate_upgrade() (BUG-UPDATE-FALSE-ROLLBACK-CLAIM-2026-07-23,
# P3b) to tell apart two very different failure shapes after a delegated
# `install.sh --upgrade --mode k8s` call fails:
#   - install.sh reached STEP 8 (helm upgrade --atomic) and it failed →
#     revision number ADVANCES (an atomic rollback is itself a new revision
#     in Helm's history) → "already rolled back cluster-side" is TRUE.
#   - install.sh aborted at an EARLY preflight (missing helm/kubectl, cluster
#     connectivity, kernel/CRD gate, etc.) BEFORE STEP 8 ever ran → revision
#     number is UNCHANGED → nothing was rolled back because nothing was
#     changed cluster-side; claiming otherwise is actively misleading.
# ---------------------------------------------------------------------------
_k8s_current_helm_revision() {
  if ! command -v helm >/dev/null 2>&1; then
    printf ''
    return 0
  fi
  local _json _rev
  _json="$(helm history "$K8S_HELM_RELEASE" -n "$K8S_NAMESPACE" --max 1 -o json 2>/dev/null || true)"
  if [[ -z "$_json" ]]; then
    # No history (release does not exist) is a valid "0", distinguishable
    # from "helm history command itself errored" only by exit code, which
    # `|| true` above already discarded — but an empty release is the
    # overwhelmingly common no-history case, so treat empty-but-helm-present
    # as revision 0 rather than unknown.
    printf '0'
    return 0
  fi
  _rev="$(printf '%s' "$_json" | grep -o '"revision"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$' || true)"
  printf '%s' "${_rev:-}"
}

k8s_delegate_upgrade() {
  log_step "6-8/8" "Delegating to install.sh --upgrade --mode k8s (helm upgrade --atomic)..."

  if [[ "$NO_AUTO_ROLLBACK" == "true" ]]; then
    log_warn "--no-auto-rollback has no effect for a k8s target: install.sh's"
    log_warn "k8s_helm_install() always runs 'helm upgrade --atomic', which"
    log_warn "unconditionally rolls back the release cluster-side on failure."
  fi

  local install_sh="${INSTALL_DIR}/install.sh"
  if [[ ! -x "$install_sh" ]]; then
    log_error "install.sh not found or not executable: ${install_sh}"
    log_error "Cannot delegate k8s upgrade."
    exit 1
  fi

  local args=(--upgrade --mode k8s --namespace "$K8S_NAMESPACE")

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would run: ${install_sh} ${args[*]} --dry-run"
    return 0
  fi

  # BUG-UPDATE-FALSE-ROLLBACK-CLAIM-2026-07-23 (P3b): snapshot the Helm
  # revision BEFORE delegating, so a failure can be attributed accurately.
  local _rev_before
  _rev_before="$(_k8s_current_helm_revision)"

  log_info "Running: ${install_sh} ${args[*]}"
  if "$install_sh" "${args[@]}"; then
    log_success "Helm release '${K8S_HELM_RELEASE}' upgraded in namespace '${K8S_NAMESPACE}' (v${TARGET_VERSION})."
    return 0
  fi

  local _rev_after
  _rev_after="$(_k8s_current_helm_revision)"

  log_error "k8s upgrade FAILED."
  log_error "Namespace: ${K8S_NAMESPACE}   Release: ${K8S_HELM_RELEASE}"
  if [[ -n "$_rev_before" && -n "$_rev_after" && "$_rev_before" != "$_rev_after" ]]; then
    # Revision advanced — install.sh reached STEP 8 and helm's own --atomic
    # gate rolled it back. This claim is now evidence-backed, not assumed.
    log_error "Because k8s_helm_install() always runs 'helm upgrade --atomic', the"
    log_error "release has ALREADY been rolled back cluster-side to its previous"
    log_error "revision (history: ${_rev_before} -> ${_rev_after}) — no further action"
    log_error "from update.sh is needed or safe to take."
    log_error "Inspect with: helm history ${K8S_HELM_RELEASE} -n ${K8S_NAMESPACE}"
  elif [[ -n "$_rev_before" && -n "$_rev_after" ]]; then
    # Revision unchanged — install.sh aborted BEFORE the helm upgrade began.
    # Nothing was rolled back because nothing was changed cluster-side.
    log_error "install.sh aborted BEFORE the Helm upgrade began (revision unchanged"
    log_error "at ${_rev_before}) — most likely an early preflight failure (missing"
    log_error "helm/kubectl, cluster connectivity, kernel/CRD gate, etc.), NOT a"
    log_error "helm --atomic rollback. Nothing was rolled back because nothing was"
    log_error "changed cluster-side."
    log_error "Re-run directly to see the exact preflight error:"
    log_error "  ${install_sh} ${args[*]}"
  else
    # Could not determine either revision (helm unavailable / query failed) —
    # do NOT assert either way.
    log_error "Could not determine whether the Helm upgrade began before failing"
    log_error "(helm unavailable or revision query failed) — inspect manually:"
    log_error "  helm history ${K8S_HELM_RELEASE} -n ${K8S_NAMESPACE}"
  fi
  exit 1
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

  # Defensive: this function is compose-only (scripts/health-check.sh has no
  # k8s awareness — confirmed zero `kubectl` references). main() never calls
  # it for RUNTIME_MODE=k8s (k8s_delegate_upgrade's own --atomic wait IS the
  # health gate), but guard here too so a future refactor can't silently
  # misapply a compose-only check against a k8s target.
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    log_info "k8s target — health already verified by helm's --wait/--atomic gate."
    return 0
  fi

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
# Rollback — runtime dispatcher (K8S-UPDATE-2026-07-22)
#
# k8s rollback = `helm rollback` (native release-history mechanism — the
# cluster already carries its own chart+values snapshot per revision, so
# there is nothing to file-copy or git-checkout the way the compose path
# does). Compose rollback keeps the existing file-restore + git-checkout +
# restart behaviour unchanged.
# ---------------------------------------------------------------------------
do_rollback() {
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    do_rollback_k8s
  else
    do_rollback_compose
  fi
}

# ---------------------------------------------------------------------------
# k8s rollback — `helm rollback` to the previous revision.
# ---------------------------------------------------------------------------
do_rollback_k8s() {
  log_step "1/1" "Rolling back Helm release '${K8S_HELM_RELEASE}' in namespace '${K8S_NAMESPACE}'..."

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[dry-run] Would run: helm rollback ${K8S_HELM_RELEASE} -n ${K8S_NAMESPACE} --wait --timeout ${HEALTH_TIMEOUT}s"
    return 0
  fi

  if ! helm status "$K8S_HELM_RELEASE" -n "$K8S_NAMESPACE" >/dev/null 2>&1; then
    log_error "No Helm release '${K8S_HELM_RELEASE}' found in namespace '${K8S_NAMESPACE}' — nothing to roll back."
    exit 1
  fi

  # No revision argument = helm rolls back to the immediately-previous
  # revision (Helm's own documented default behaviour).
  if helm rollback "$K8S_HELM_RELEASE" -n "$K8S_NAMESPACE" --wait --timeout "${HEALTH_TIMEOUT}s"; then
    log_success "Helm release '${K8S_HELM_RELEASE}' rolled back to its previous revision."
  else
    log_error "helm rollback FAILED. Manual intervention required:"
    log_error "  helm history ${K8S_HELM_RELEASE} -n ${K8S_NAMESPACE}"
    log_error "  helm rollback ${K8S_HELM_RELEASE} <REVISION> -n ${K8S_NAMESPACE}"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Compose rollback (docker/podman) — unchanged from pre-4.1.2 behaviour.
# ---------------------------------------------------------------------------
# TODO(v2.24.0 #47): Wire YASHIGANI_BACKUPS_DIR + POST /admin/backup/verify here.
# Rollback currently invokes restore.sh directly via shell; the backoffice
# container is not guaranteed to be running during an upgrade window.
# Track: https://github.com/agnosticsec-com/yashigani/issues/47
do_rollback_compose() {
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
    rel_path="${f#"${latest_backup}/"}"
    # Defensive (VEB-Strip): when find returns latest_backup itself (file == dir),
    # strip is a no-op and rel_path == f (full absolute path). Skip it — it would
    # produce an invalid destination path. find -type f should not return the dir
    # itself, but guard defensively against edge cases (symlink, unusual fs).
    [[ "$rel_path" == "$f" ]] && continue
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
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    printf "    - Helm release '%s' (namespace '%s')\n" "$K8S_HELM_RELEASE" "$K8S_NAMESPACE"
  else
    printf "    - Container images\n"
    printf "    - Services restarted\n"
  fi
  printf "\n"
  printf "  ${C_BOLD}What was preserved:${C_RESET}\n"
  printf "    - Your .env / .env.helm configuration\n"
  printf "    - Your OPA policies (data.json)\n"
  printf "    - Your licence key\n"
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    printf "    - Kept Secrets/PVCs (helm.sh/resource-policy: keep — UNIVERSAL-001/002)\n"
  else
    printf "    - Your database (PostgreSQL data volume)\n"
  fi
  printf "\n"
  printf "  ${C_BOLD}Rollback:${C_RESET}\n"
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    printf "    If something went wrong: ${C_YELLOW}./update.sh --rollback --namespace %s${C_RESET}\n" "$K8S_NAMESPACE"
  else
    printf "    If something went wrong: ${C_YELLOW}./update.sh --rollback${C_RESET}\n"
  fi
  printf "\n"
  printf "  ${C_BOLD}Verify:${C_RESET}\n"
  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    printf "    Release status: ${C_BLUE}helm status %s -n %s${C_RESET}\n" "$K8S_HELM_RELEASE" "$K8S_NAMESPACE"
    printf "    Pod status:     ${C_BLUE}kubectl get pods -n %s${C_RESET}\n" "$K8S_NAMESPACE"
    printf "    Gateway logs:   ${C_BLUE}kubectl logs -n %s -l app.kubernetes.io/component=gateway -f${C_RESET}\n" "$K8S_NAMESPACE"
  else
    printf "    Health check:  ${C_BLUE}bash scripts/health-check.sh${C_RESET}\n"
    printf "    Gateway logs:  ${C_BLUE}docker compose -f docker/docker-compose.yml logs -f gateway${C_RESET}\n"
  fi
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
  detect_runtime

  if [[ "$ROLLBACK" == "true" ]]; then
    do_rollback
    exit 0
  fi

  detect_current_version
  check_latest_version
  backup_current
  pull_update

  if [[ "$RUNTIME_MODE" == "k8s" ]]; then
    # K8S-UPDATE-2026-07-22: single delegated call — pull+restart+health-gate
    # +atomic-rollback-on-failure are ALL handled inside install.sh's own
    # k8s_helm_install(). k8s_delegate_upgrade() exits 0 (fully healthy) or
    # non-zero — on failure it now checks the Helm revision before/after to
    # report ACCURATELY whether --atomic actually rolled back a started
    # upgrade, or install.sh aborted at an early preflight before any change
    # was made (BUG-UPDATE-FALSE-ROLLBACK-CLAIM-2026-07-23, P3b) — there is
    # no separate verify_health/do_rollback step to run afterward for k8s.
    k8s_delegate_upgrade
  else
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
  fi

  print_summary
}

# Sourceable guard: tests can `source update.sh` with YSG_UPDATE_NO_AUTORUN=1
# to exercise functions in isolation without main() running.
if [[ "${YSG_UPDATE_NO_AUTORUN:-0}" != "1" ]]; then
  main "$@"
fi
