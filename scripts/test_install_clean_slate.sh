#!/usr/bin/env bash
# scripts/test_install_clean_slate.sh — Yashigani install.sh clean-slate runner
# Retro #34 — automated clean-slate install test for every release.
#
# PURPOSE
#   Provides an automated, evidence-producing clean-slate install test.
#   Nuke → install → healthcheck → admin-login probe → tear down.
#   Exits non-zero on any failure. Never emits "GREEN" without verified probes.
#
# DESIGN — VM TARGET (not nested-VM)
#   This runner targets ysgvm-su (192.168.64.2, Ubuntu 24.04 aarch64) via SSH,
#   using it as the clean-slate environment. A nested-VM approach via multipass
#   was the original brief, but multipass is not available on the macOS host and
#   cannot be installed on ysgvm-su (snapd inactive, disk constraints). The VM is
#   dedicated disposable test infra; "clean slate" is achieved by wiping the
#   install dir before each run. If multipass becomes available, the VM-provision
#   phase can be added before the "wipe + clone" step without changing the rest of
#   the runner.
#
# USAGE
#   scripts/test_install_clean_slate.sh [OPTIONS]
#
#   --runtime docker|podman   Container runtime to test (default: podman)
#   --branch BRANCH           Git branch to clone (default: current branch)
#   --keep-install            Do NOT tear down at end (for debugging)
#   --evidence-dir DIR        Override evidence output directory
#   --timeout SECONDS         Overall timeout for install + healthchecks (default: 900)
#   --no-probe                Skip admin-login probe (structural test only)
#   --help                    Print this message
#
# EVIDENCE
#   Written to Internal/Compliance/yashigani/v2.23.2/runtime-<RUNTIME>-rootless/
#   clean-slate-evidence-<timestamp>.txt
#   The evidence file contains:
#     - Install log tail
#     - Container state (podman ps / docker ps)
#     - /healthz HTTP responses
#     - Literal "Admin1 login HTTP: 200" and "Admin2 login HTTP: 200" (SOP 4 grep contract)
#     - Final verdict line: CLEAN SLATE GREEN or CLEAN SLATE FAIL
#
# SECURITY
#   - sudo via stdin-file pattern (feedback_sudo_password_handling.md)
#   - Secrets copied to VM over SSH (never in process argv)
#   - Evidence files written 0600
#   - VM-side sudo password stored in 0600 tempfile, shredded on exit
#   - VM clone dir cleaned up on exit (unless --keep-install)
#
# IDEMPOTENCY
#   A previous hung or partial run leaves the install dir. The wipe step at the
#   start removes it unconditionally. Running twice in a row is safe.
#
# OUT OF SCOPE FOR THIS SCRIPT
#   - Fixing install.sh bugs. If the runner fails on install.sh bugs, new retro
#     issues are filed manually and the exit is non-zero.
#   - Docker rootful / K8s runtimes. Parameterise --runtime to extend later.
#   - CI integration. Local runner only; GitHub Actions wiring is follow-up work.
#
# REQUIREMENTS (host-side)
#   - SSH access to ysgvm-su via ysgvm-su alias (key: /Users/max/.ssh/yashigani-vm/su_ed25519)
#   - git
#   - realpath (coreutils; comes with macOS 12+)
#
# REQUIREMENTS (VM-side, confirmed present on ysgvm-su)
#   - podman >= 4.9.3 with rootless subuid mapping for user 'su'
#   - python3 with pyotp (for release_gate_probe.sh)
#   - git
#   - sudo rights for 'su' user
#
# Version: v2.23.2
# Last-Updated: 2026-05-07T00:00:00+01:00

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Hardened PATH — never trust inherited
# ---------------------------------------------------------------------------
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# ---------------------------------------------------------------------------
# Script location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RUNTIME="podman"
BRANCH=""
KEEP_INSTALL=false
EVIDENCE_BASE_DIR="/Users/max/Documents/Claude/Internal/Compliance/yashigani/v2.23.2"
TIMEOUT=900
NO_PROBE=false

# VM coordinates — must match feedback_sudo_password_handling.md (SOP Pattern A)
VM_SSH_ALIAS="ysgvm-su"
VM_SSH_KEY="/Users/max/.ssh/yashigani-vm/su_ed25519"
VM_USER="su"
VM_HOST="192.168.64.2"
VM_CLONE_DIR="/home/su/yashigani-clean-slate-test"

# Admin email for non-interactive install — not a real address, test-only
INSTALL_ADMIN_EMAIL="test@yashigani.local"
INSTALL_DOMAIN="localhost"

# ---------------------------------------------------------------------------
# Color helpers (TTY-only)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_GREEN='\033[1;32m'; C_RED='\033[1;31m'; C_YELLOW='\033[1;33m'
  C_BLUE='\033[1;34m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
else
  C_GREEN=''; C_RED=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''; C_RESET=''
fi

_info()    { printf "${C_BLUE}[INFO]${C_RESET}  %s\n"   "$*"; }
_ok()      { printf "${C_GREEN}[OK]${C_RESET}    %s\n"   "$*"; }
_warn()    { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n"  "$*" >&2; }
_fail()    { printf "${C_RED}[FAIL]${C_RESET}  %s\n"    "$*" >&2; }
_section() { printf "\n${C_BOLD}=== %s ===${C_RESET}\n\n" "$*"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  sed -n '/#.*USAGE/,/^# EVIDENCE/p' "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \?//'
  exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      RUNTIME="${2:?'--runtime requires docker or podman'}"
      case "$RUNTIME" in docker|podman) ;; *)
        _fail "--runtime must be docker or podman"; exit 1 ;;
      esac
      shift 2 ;;
    --branch)
      BRANCH="${2:?'--branch requires a branch name'}"
      shift 2 ;;
    --keep-install)
      KEEP_INSTALL=true; shift ;;
    --evidence-dir)
      EVIDENCE_BASE_DIR="${2:?'--evidence-dir requires a path'}"
      shift 2 ;;
    --timeout)
      TIMEOUT="${2:?'--timeout requires a number'}"; shift 2 ;;
    --no-probe)
      NO_PROBE=true; shift ;;
    --help|-h)
      usage ;;
    *)
      _fail "Unknown option: $1"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Resolve branch: default to current git branch
# ---------------------------------------------------------------------------
if [[ -z "$BRANCH" ]]; then
  BRANCH="$(git -C "${REPO_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "2.23.x")"
fi
_info "Target branch: ${BRANCH}"

# ---------------------------------------------------------------------------
# Resolve and validate evidence directory
# ---------------------------------------------------------------------------
# realpath -m (GNU) creates nonexistent paths; macOS realpath doesn't support -m.
# Use mkdir -p first, then realpath (which requires the path to exist).
mkdir -p "${EVIDENCE_BASE_DIR}"
EVIDENCE_BASE_DIR="$(realpath "${EVIDENCE_BASE_DIR}")"
EVIDENCE_DIR="${EVIDENCE_BASE_DIR}/runtime-${RUNTIME}-rootless"
TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
EVIDENCE_FILE="${EVIDENCE_DIR}/clean-slate-evidence-${TIMESTAMP}.txt"

# Validate evidence base is under /Users/max/Documents/Claude/ (feedback_no_tmp.md)
case "${EVIDENCE_BASE_DIR}" in
  /Users/max/Documents/Claude/*) ;;
  *)
    _fail "Evidence dir must be under /Users/max/Documents/Claude/ — got: ${EVIDENCE_BASE_DIR}"
    exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Sudo password setup — SOP Pattern A
# (feedback_sudo_password_handling.md — NEVER echo-pipe)
# ---------------------------------------------------------------------------
# The VM sudo password is stored in memory as project_vm_team_accounts.md.
# We write it to a 0600 tempfile under /Users/max/Documents/Claude/ (never /tmp).
SUDO_PWD_FILE="/Users/max/Documents/Claude/yashigani/.sudo_pw_$$"
# Ensure cleanup on any exit path
# shellcheck disable=SC2317  # trap function — not unreachable
_cleanup_sudo_pw() {
  if [[ -f "${SUDO_PWD_FILE}" ]]; then
    # shred if available; fall back to overwrite + unlink
    if command -v shred >/dev/null 2>&1; then
      shred -u "${SUDO_PWD_FILE}" 2>/dev/null || rm -f "${SUDO_PWD_FILE}"
    else
      dd if=/dev/urandom of="${SUDO_PWD_FILE}" bs=64 count=1 2>/dev/null || true
      rm -f "${SUDO_PWD_FILE}"
    fi
  fi
}

# VM-side cleanup is best-effort (teardown via uninstall is the real cleanup)
# shellcheck disable=SC2317  # trap function — not unreachable
_vm_cleanup() {
  if [[ "${KEEP_INSTALL}" == "true" ]]; then
    _warn "Skipping VM cleanup (--keep-install set). Clone at: ${VM_CLONE_DIR}"
    return 0
  fi
  _info "VM teardown: stopping containers and removing clone..."
  # Run teardown via uninstall.sh (best-effort — don't fail the runner on teardown errors)
  # --yes skips the interactive confirmation added in #87.
  _vm_ssh "
    if [[ -f '${VM_CLONE_DIR}/uninstall.sh' ]]; then
      cd '${VM_CLONE_DIR}' && \
      YSG_RUNTIME=${RUNTIME} bash uninstall.sh --remove-volumes --yes 2>&1 || true
    fi
    ${RUNTIME} unshare rm -rf '${VM_CLONE_DIR}' 2>/dev/null || rm -rf '${VM_CLONE_DIR}' || true
    ${RUNTIME} system prune -f 2>/dev/null || true
    ${RUNTIME} volume prune -f 2>/dev/null || true
  " 2>&1 || _warn "VM cleanup had errors (non-fatal)"
  _ok "VM teardown complete"
}

# Register cleanup handlers — fire in reverse order: sudo pw first, then VM
trap '_cleanup_sudo_pw' EXIT
# Note: we add VM cleanup dynamically after confirming SSH works

# Write password (su's VM sudo password from project_vm_team_accounts.md)
umask 077
printf '%s\n' 'r4vs70jrs_gUIMhuDw9wuKO8PZV9' > "${SUDO_PWD_FILE}"
umask 022

# ---------------------------------------------------------------------------
# SSH helper — all VM commands go through this
# ---------------------------------------------------------------------------
# shellcheck disable=SC2317  # used by all phases below
_vm_ssh() {
  local cmd="$1"
  ssh -i "${VM_SSH_KEY}" \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=10 \
      -o BatchMode=yes \
      "${VM_USER}@${VM_HOST}" \
      "bash -c $(printf '%q' "$cmd")"
}

# SSH with sudo — uses stdin file, never argv
# shellcheck disable=SC2317  # referenced function — not unreachable
_vm_sudo() {
  local cmd="$1"
  ssh -i "${VM_SSH_KEY}" \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=10 \
      -o BatchMode=yes \
      "${VM_USER}@${VM_HOST}" \
      "sudo -S bash -c $(printf '%q' "$cmd")" \
      < "${SUDO_PWD_FILE}"
}

# ---------------------------------------------------------------------------
# Evidence file helpers
# ---------------------------------------------------------------------------
_evidence_mkdir() {
  mkdir -p "${EVIDENCE_DIR}"
  chmod 700 "${EVIDENCE_DIR}"
  touch "${EVIDENCE_FILE}"
  chmod 600 "${EVIDENCE_FILE}"
}

_ev() {
  # Write to evidence file; also print to stdout
  printf '%s\n' "$*" | tee -a "${EVIDENCE_FILE}"
}

_ev_section() {
  _ev ""
  _ev "=== $* ==="
  _ev ""
}

# ---------------------------------------------------------------------------
# PHASE 0: Connectivity check
# ---------------------------------------------------------------------------
_section "Phase 0: Connectivity"

_info "Checking SSH to ${VM_SSH_ALIAS}..."
if ! _vm_ssh "echo ok" >/dev/null 2>&1; then
  _fail "Cannot reach ${VM_SSH_ALIAS} — check SSH alias and key"
  exit 1
fi
_ok "SSH to ${VM_SSH_ALIAS} is up"

# Register VM cleanup now that SSH is confirmed
trap '_vm_cleanup; _cleanup_sudo_pw' EXIT

# ---------------------------------------------------------------------------
# PHASE 1: Prepare evidence directory
# ---------------------------------------------------------------------------
_section "Phase 1: Evidence directory"
_evidence_mkdir
_ev "CLEAN SLATE TEST EVIDENCE"
_ev "Runner:    $(basename "${BASH_SOURCE[0]}")"
_ev "Branch:    ${BRANCH}"
_ev "Runtime:   ${RUNTIME}"
_ev "VM:        ${VM_USER}@${VM_HOST}"
_ev "Timestamp: ${TIMESTAMP}"
_ev "Commit:    $(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"
_ev ""
_ok "Evidence file: ${EVIDENCE_FILE}"

# ---------------------------------------------------------------------------
# PHASE 2: Wipe any previous install on VM (clean-slate guarantee)
# ---------------------------------------------------------------------------
_section "Phase 2: Wipe previous state on VM"

_info "Stopping any running stack..."
_vm_ssh "
  if [[ -f '${VM_CLONE_DIR}/uninstall.sh' ]]; then
    cd '${VM_CLONE_DIR}' && \
    YSG_RUNTIME=${RUNTIME} bash uninstall.sh --remove-volumes 2>&1 || true
  elif [[ -f \"\${HOME}/.yashigani/uninstall.sh\" ]]; then
    cd \"\${HOME}/.yashigani\" && \
    YSG_RUNTIME=${RUNTIME} bash uninstall.sh --remove-volumes 2>&1 || true
  fi
" 2>&1 | tee -a "${EVIDENCE_FILE}" || true

_info "Removing clone directory (podman unshare rm for namespace-owned files)..."
# install.sh uses 'podman unshare chown 1001:1001' on bind-mount dirs, so secret
# files and data dirs are owned by subuid-mapped uids (mode 0400). Plain rm -rf
# as the host user fails with EPERM. Running rm inside the user namespace via
# 'podman unshare rm -rf' works because the uid mapping makes the files appear
# owned by the process.
_vm_ssh "
  if [[ -d '${VM_CLONE_DIR}' ]]; then
    ${RUNTIME} unshare rm -rf '${VM_CLONE_DIR}' 2>/dev/null || rm -rf '${VM_CLONE_DIR}' || true
  fi
" 2>&1 | tee -a "${EVIDENCE_FILE}" || true

_info "Removing \$HOME/.yashigani install dir..."
_vm_ssh "
  if [[ -d \"\${HOME}/.yashigani\" ]]; then
    ${RUNTIME} unshare rm -rf \"\${HOME}/.yashigani\" 2>/dev/null || rm -rf \"\${HOME}/.yashigani\" || true
  fi
" 2>&1 | tee -a "${EVIDENCE_FILE}" || true

_info "Pruning stale container state..."
_vm_ssh "
  ${RUNTIME} system prune -f 2>/dev/null || true
  ${RUNTIME} volume prune -f 2>/dev/null || true
" 2>&1 | tee -a "${EVIDENCE_FILE}" || true

_ev_section "Post-wipe state"
_vm_ssh "
  ${RUNTIME} ps -a 2>/dev/null || true
  ${RUNTIME} volume ls 2>/dev/null || true
" 2>&1 | tee -a "${EVIDENCE_FILE}" || true
_ok "VM wiped to clean state"

# ---------------------------------------------------------------------------
# PHASE 3: Clone branch to VM
# ---------------------------------------------------------------------------
_section "Phase 3: Clone ${BRANCH} to VM"

REPO_URL="$(git -C "${REPO_DIR}" remote get-url origin 2>/dev/null || echo 'https://github.com/agnosticsec-com/yashigani.git')"
_ev "Repo URL:  ${REPO_URL}"

_vm_ssh "
  set -euo pipefail
  git clone --depth 1 --branch '${BRANCH}' '${REPO_URL}' '${VM_CLONE_DIR}' 2>&1
  cd '${VM_CLONE_DIR}'
  git log --oneline -1
" 2>&1 | tee -a "${EVIDENCE_FILE}"
_ok "Clone complete: ${VM_CLONE_DIR}"

# PHASE 3b removed: bind-mount dir pre-creation was BIND-MOUNT-001 workaround,
# now fixed in install.sh (#85). install.sh auto-creates docker/data, docker/certs,
# docker/logs with correct ownership (podman unshare chown for rootless Podman).

# ---------------------------------------------------------------------------
# PHASE 4: Run install.sh on VM
# ---------------------------------------------------------------------------
_section "Phase 4: install.sh (non-interactive, ${RUNTIME}, demo, selfsigned)"

_ev_section "install.sh invocation"
_ev "install.sh --non-interactive --deploy demo --domain ${INSTALL_DOMAIN}"
_ev "           --tls-mode selfsigned --admin-email ${INSTALL_ADMIN_EMAIL}"
_ev "           --runtime ${RUNTIME}"
_ev ""

INSTALL_LOG="${EVIDENCE_DIR}/install-${TIMESTAMP}.log"

# Run install.sh on VM, capturing output to both evidence log and stdout.
# HISTFILE=/dev/null — no secret leakage via bash history on VM.
# Strategy: the remote bash writes its exit code to a file on the VM so we can
# read it back after SSH returns. This avoids PIPESTATUS-through-tee-through-SSH.
# We use VM-side `timeout` to guard against hangs (available on Ubuntu 24.04).
_info "Running install.sh (this will take several minutes, timeout: ${TIMEOUT}s)..."

VM_EXITCODE_FILE="${VM_CLONE_DIR}/.install_exit_code"

# SSH ServerAliveInterval: 60s × 20 = 20min host-side detection of dead connection.
ssh -i "${VM_SSH_KEY}" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=20 \
    -o BatchMode=yes \
    "${VM_USER}@${VM_HOST}" \
    "bash -c 'export HISTFILE=/dev/null; export YSG_RUNTIME=${RUNTIME}; \
      cd ${VM_CLONE_DIR} && \
      timeout ${TIMEOUT} bash install.sh \
        --non-interactive \
        --deploy demo \
        --domain ${INSTALL_DOMAIN} \
        --tls-mode selfsigned \
        --admin-email ${INSTALL_ADMIN_EMAIL} \
        --runtime ${RUNTIME} 2>&1; \
      echo \$? > ${VM_EXITCODE_FILE}'" \
  | tee "${INSTALL_LOG}" | tee -a "${EVIDENCE_FILE}" || true

# Read exit code back from VM
INSTALL_EXIT="$(
  ssh -i "${VM_SSH_KEY}" \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=10 \
      -o BatchMode=yes \
      "${VM_USER}@${VM_HOST}" \
      "cat ${VM_EXITCODE_FILE} 2>/dev/null | tr -d '[:space:]'" 2>/dev/null || echo "unknown"
)"

_ev ""
_ev "install.sh exit code: ${INSTALL_EXIT}"

if [[ "${INSTALL_EXIT}" != "0" ]]; then
  _fail "install.sh exited non-zero (${INSTALL_EXIT})"
  _ev "CLEAN SLATE FAIL — install.sh non-zero exit"
  exit 1
fi

_ev ""
_ev "install.sh exit code: 0"
_ok "install.sh completed successfully"

# ---------------------------------------------------------------------------
# PHASE 5: Container state snapshot
# ---------------------------------------------------------------------------
_section "Phase 5: Container state"

_ev_section "Container state (${RUNTIME} ps -a)"
_vm_ssh "${RUNTIME} ps -a 2>&1 || true" 2>&1 | tee -a "${EVIDENCE_FILE}"

_ev_section "Container state (${RUNTIME} ps --format 'table ...')"
_vm_ssh "${RUNTIME} ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 || true" \
  2>&1 | tee -a "${EVIDENCE_FILE}"

# ---------------------------------------------------------------------------
# PHASE 6: Healthchecks — /healthz probes
# ---------------------------------------------------------------------------
_section "Phase 6: /healthz probes"

# Determine HTTPS port — check .env on VM
HTTPS_PORT="443"
ENV_HTTPS_PORT="$(_vm_ssh "
  env_f=\${HOME}/.yashigani/docker/.env
  if [[ -f \"\$env_f\" ]]; then
    grep '^YASHIGANI_HTTPS_PORT=' \"\$env_f\" | cut -d= -f2 | tr -d '\"'
  else
    echo '443'
  fi
" 2>/dev/null || echo '443')"
[[ -n "${ENV_HTTPS_PORT}" ]] && HTTPS_PORT="${ENV_HTTPS_PORT}"
_ev "HTTPS port: ${HTTPS_PORT}"

# Retry helper for transport-level errors only
_probe_http() {
  local label="$1" url="$2"
  local attempt=0 max=6 delay=10
  while [[ $attempt -lt $max ]]; do
    local code exit_code=0
    code=$(_vm_ssh "curl -s -o /dev/null -w '%{http_code}' --insecure --max-time 10 '${url}' 2>/dev/null" 2>/dev/null) || exit_code=$?
    # Transport error (curl exits non-zero on connect failure)
    if [[ $exit_code -ne 0 || -z "$code" ]]; then
      attempt=$((attempt + 1))
      _info "${label}: transport error, retry ${attempt}/${max} in ${delay}s..."
      sleep "${delay}"
      continue
    fi
    # First non-2xx is FAIL (SOP 4 — no retry on 4xx/5xx)
    if [[ "$code" =~ ^2 ]]; then
      _ev "${label}: HTTP ${code}"
      return 0
    else
      _ev "${label}: HTTP ${code} — FAIL"
      return 1
    fi
  done
  _ev "${label}: transport timeout after ${max} retries — FAIL"
  return 1
}

_ev_section "/healthz probes"
GATEWAY_HEALTHZ_OK=true
BACKOFFICE_LOGIN_OK=true

_probe_http "Gateway /healthz" "https://${INSTALL_DOMAIN}:${HTTPS_PORT}/healthz" \
  2>&1 | tee -a "${EVIDENCE_FILE}" || GATEWAY_HEALTHZ_OK=false

# /login returns 200 for GET (proves Caddy → backoffice routing)
_probe_http "Backoffice /login" "https://${INSTALL_DOMAIN}:${HTTPS_PORT}/login" \
  2>&1 | tee -a "${EVIDENCE_FILE}" || BACKOFFICE_LOGIN_OK=false

if [[ "${GATEWAY_HEALTHZ_OK}" != "true" || "${BACKOFFICE_LOGIN_OK}" != "true" ]]; then
  _fail "Healthcheck probe(s) failed"
  _ev "CLEAN SLATE FAIL — healthcheck probes failed"
  exit 1
fi
_ok "All /healthz probes passed"

# ---------------------------------------------------------------------------
# PHASE 7: Admin login probe (SOP 4 — release_gate_probe.sh)
# ---------------------------------------------------------------------------
_section "Phase 7: Admin login probe"

if [[ "${NO_PROBE}" == "true" ]]; then
  _warn "--no-probe set — skipping admin login probe (not a full GREEN)"
  _ev "Admin probe: SKIPPED (--no-probe)"
  _ev "CLEAN SLATE PARTIAL — no-probe mode, cannot emit GREEN"
  exit 0
fi

# Copy release_gate_probe.sh to VM
_info "Copying release_gate_probe.sh to VM..."
scp -i "${VM_SSH_KEY}" \
    -o StrictHostKeyChecking=no \
    -o BatchMode=yes \
    "${SCRIPT_DIR}/release_gate_probe.sh" \
    "${VM_USER}@${VM_HOST}:/home/${VM_USER}/release_gate_probe_${TIMESTAMP}.sh"

# Set permissions on VM copy
_vm_ssh "chmod 755 \"/home/${VM_USER}/release_gate_probe_${TIMESTAMP}.sh\""

# Determine secrets dir on VM — install.sh writes secrets into the clone dir
VM_SECRETS_DIR="${VM_CLONE_DIR}/docker/secrets"

_ev_section "release_gate_probe.sh output"

PROBE_OUTPUT=""
# Capture output regardless of exit code — success/failure is determined by
# whether the output contains "Admin1 login HTTP: 200" etc. (SOP 4 contract).
# Capture probe output regardless of exit code — success/failure is determined
# by whether the output contains "Admin1 login HTTP: 200" (SOP 4 grep contract).
# shellcheck disable=SC2030
# For Podman rootless, admin credential files are chowned to UID 1001 (subuid-mapped)
# by _pki_chown_client_keys/gate-#ROOTLESS-11 so the backoffice container can read them.
# After chown, the host user (su) cannot `cat` them directly — they're 0600 owned by
# the subuid-mapped UID. Use `podman unshare cat` to read within the user namespace.
# Docker installs leave files owned by the installer user — plain `cat` works there.
PROBE_CAT_PREFIX="cat"
if [[ "${RUNTIME}" == "podman" ]]; then
  PROBE_CAT_PREFIX="podman unshare cat"
fi

{ PROBE_OUTPUT="$(
    _vm_ssh "
      HISTFILE=/dev/null bash '/home/${VM_USER}/release_gate_probe_${TIMESTAMP}.sh' \
        --base-url 'https://${INSTALL_DOMAIN}:${HTTPS_PORT}' \
        --secrets-dir '${VM_SECRETS_DIR}' \
        --cat-prefix '${PROBE_CAT_PREFIX}' 2>&1
    " 2>&1
  )"; } || true

_ev "${PROBE_OUTPUT}"

# Cleanup probe script from VM
_vm_ssh "rm -f '/home/${VM_USER}/release_gate_probe_${TIMESTAMP}.sh'" 2>/dev/null || true

# SOP 4 grep contract: evidence must contain both literal lines
ADMIN1_LINE="$(printf '%s' "${PROBE_OUTPUT}" | grep 'Admin1 login HTTP:' || true)"
ADMIN2_LINE="$(printf '%s' "${PROBE_OUTPUT}" | grep 'Admin2 login HTTP:' || true)"

_ev ""
_ev "Admin1 probe: ${ADMIN1_LINE:-MISSING}"
_ev "Admin2 probe: ${ADMIN2_LINE:-MISSING}"

ADMIN1_CODE="$(printf '%s' "${ADMIN1_LINE}" | grep -oE '[0-9]+$' || echo '')"
ADMIN2_CODE="$(printf '%s' "${ADMIN2_LINE}" | grep -oE '[0-9]+$' || echo '')"

# Verify both returned 200
if [[ "$ADMIN1_CODE" != "200" || "$ADMIN2_CODE" != "200" ]]; then
  _fail "Admin probe failed: Admin1=${ADMIN1_CODE:-MISSING}, Admin2=${ADMIN2_CODE:-MISSING}"
  _ev "CLEAN SLATE FAIL — admin login probe failed"
  exit 1
fi

# SOP 4: emit the contract lines literally in evidence (grep contract)
_ev ""
_ev "Admin1 login HTTP: 200"
_ev "Admin2 login HTTP: 200"

# ---------------------------------------------------------------------------
# PHASE 8: Bootstrap evidence — TOTP secret files present
# ---------------------------------------------------------------------------
_section "Phase 8: Bootstrap evidence (TOTP secret files)"

_ev_section "Bootstrap evidence"
TOTP_OK=true

for secret_file in admin1_totp_secret admin2_totp_secret admin1_username admin2_username; do
  FILE_PRESENT="$(_vm_ssh "
    f='${VM_SECRETS_DIR}/${secret_file}'
    if [[ -f \"\$f\" && -s \"\$f\" ]]; then echo present; else echo MISSING; fi
  " 2>/dev/null || echo MISSING)"
  _ev "  ${secret_file}: ${FILE_PRESENT}"
  if [[ "${FILE_PRESENT}" != "present" ]]; then
    TOTP_OK=false
  fi
done

if [[ "${TOTP_OK}" != "true" ]]; then
  _fail "One or more TOTP/bootstrap secret files missing — bootstrap did not complete"
  _ev "CLEAN SLATE FAIL — bootstrap secrets missing"
  exit 1
fi
_ok "Bootstrap evidence confirmed (TOTP secret files present)"

# ---------------------------------------------------------------------------
# PHASE 8b: SSRF guard env var assertion (v2.23.2 fix — TM-V231-004)
# Verify YASHIGANI_AGENT_UPSTREAM_HOSTNAMES is set on the backoffice container
# so canonical agent bundles (langflow/letta/openclaw) can register without
# hitting the RFC1918-private SSRF block. Absence = bundles silently broken.
# ---------------------------------------------------------------------------
_section "Phase 8b: SSRF guard env var (YASHIGANI_AGENT_UPSTREAM_HOSTNAMES)"

_ev_section "SSRF guard env var check"

# Determine backoffice container name — Podman and Docker differ only in prefix.
# docker compose names: docker-backoffice-1 (docker) or <compose-project>_backoffice_1 (podman-compose).
# Use `<runtime> ps --format` to find the running backoffice container name.
BACKOFFICE_CONTAINER="$(_vm_ssh "
  ${RUNTIME} ps --format '{{.Names}}' 2>/dev/null | grep -E 'backoffice' | head -1 || true
" 2>/dev/null | tr -d '[:space:]')"

if [[ -z "${BACKOFFICE_CONTAINER}" ]]; then
  _ev "SSRF guard env var: FAIL — could not determine backoffice container name"
  _fail "Backoffice container not found; cannot verify YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"
  _ev "CLEAN SLATE FAIL — SSRF guard env var assertion failed"
  exit 1
fi

_ev "Backoffice container: ${BACKOFFICE_CONTAINER}"

UPSTREAM_HOSTNAMES_VALUE="$(_vm_ssh "
  ${RUNTIME} exec '${BACKOFFICE_CONTAINER}' env 2>/dev/null \
    | grep '^YASHIGANI_AGENT_UPSTREAM_HOSTNAMES=' \
    | cut -d= -f2- \
    | tr -d '[:space:]' \
    || true
" 2>/dev/null | tr -d '[:space:]')"

_ev "YASHIGANI_AGENT_UPSTREAM_HOSTNAMES=${UPSTREAM_HOSTNAMES_VALUE:-<not set>}"

if [[ -z "${UPSTREAM_HOSTNAMES_VALUE}" ]]; then
  _ev "SSRF guard env var: FAIL — YASHIGANI_AGENT_UPSTREAM_HOSTNAMES is empty or unset"
  _fail "Agent bundles (langflow/letta/openclaw) will be silently broken — var not propagated"
  _ev "CLEAN SLATE FAIL — SSRF guard env var not set on backoffice"
  exit 1
fi

# Verify the three canonical bundle hostnames are present
UPSTREAM_OK=true
for hostname in langflow letta openclaw; do
  if printf '%s' "${UPSTREAM_HOSTNAMES_VALUE}" | tr ',' '\n' | grep -qx "${hostname}"; then
    _ev "  ${hostname}: present"
  else
    _ev "  ${hostname}: MISSING from YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"
    UPSTREAM_OK=false
  fi
done

if [[ "${UPSTREAM_OK}" != "true" ]]; then
  _ev "SSRF guard env var: FAIL — one or more canonical bundle hostnames missing"
  _fail "Agent bundle hostname allowlist incomplete"
  _ev "CLEAN SLATE FAIL — SSRF guard env var incomplete"
  exit 1
fi

_ev "SSRF guard env var: PASS"
_ok "YASHIGANI_AGENT_UPSTREAM_HOSTNAMES set correctly (langflow,letta,openclaw)"

# ---------------------------------------------------------------------------
# PHASE 9: Verdict
# ---------------------------------------------------------------------------
_section "Phase 9: Verdict"

_ev ""
_ev "=============================="
_ev "  CLEAN SLATE GREEN"
_ev "  Branch:  ${BRANCH}"
_ev "  Runtime: ${RUNTIME}"
_ev "  Time:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
_ev "=============================="
_ev ""

_ok "CLEAN SLATE GREEN"
_ok "Evidence: ${EVIDENCE_FILE}"
_ok "Install log: ${INSTALL_LOG}"

exit 0
