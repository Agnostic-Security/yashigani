#!/usr/bin/env bash
# scripts/backup.sh — Yashigani encrypted backup
# Last updated: 2026-05-27T00:00:00+01:00 (fix(backup): B5 — include agent bundle state dirs in tarball)
#
# Produces an age-encrypted tarball at:
#   /var/lib/yashigani/backups/<timestamp>.tar.gz.age
#
# The primary source directory (--source-dir / YASHIGANI_BACKUP_SOURCE_DIR) is
# always included.  Agent bundle state directories (langflow flows, letta
# memories, openclaw policies) live in separate volumes and are included via
# --extra-dirs.  Without --extra-dirs, agent state is silently excluded from
# the backup (B5 data-loss path — closes v2.25.0 P2 B5).
#
# Usage:
#   backup.sh [--output-dir DIR] [--recipient-key FILE] [--dry-run]
#             [--extra-dirs DIR1:DIR2:...]
#
# Environment variables:
#   YASHIGANI_BACKUP_OUTPUT_DIR    Override output directory (default: /var/lib/yashigani/backups)
#   YASHIGANI_BACKUP_RECIPIENT     Override recipient public key file (default: /etc/yashigani/backup-recipient.age.pub)
#   YASHIGANI_BACKUP_SOURCE_DIR    Override source directory (default: /var/lib/yashigani)
#   YASHIGANI_BACKUP_EXTRA_DIRS    Colon-separated list of extra dirs to archive (default: empty)
#                                  Example: /var/lib/yashigani/agents/langflow:/var/lib/yashigani/agents/letta
#
# Operator pre-requisites (see docs/operations/backup.md):
#   1. Generate key pair: age-keygen -o /etc/yashigani/backup-identity.age
#   2. Install recipient key: age-keygen -y /etc/yashigani/backup-identity.age \
#         > /etc/yashigani/backup-recipient.age.pub
#   3. chmod 0400 /etc/yashigani/backup-identity.age
#   4. chmod 0444 /etc/yashigani/backup-recipient.age.pub
#
# Finding: MP.L2-3.8.9 — backup encryption at rest
# CWE: CWE-312 (cleartext storage of sensitive information)
# B5: agent bundle state excluded from backup — silent data loss on restore
# ============================================================================

set -euo pipefail
umask 077

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RECIPIENT_KEY_FILE="${YASHIGANI_BACKUP_RECIPIENT:-/etc/yashigani/backup-recipient.age.pub}"
OUTPUT_DIR="${YASHIGANI_BACKUP_OUTPUT_DIR:-/var/lib/yashigani/backups}"
SOURCE_DIR="${YASHIGANI_BACKUP_SOURCE_DIR:-/var/lib/yashigani}"
# B5: colon-separated list of additional directories to include in the tarball.
# Populated by the K8s CronJob via YASHIGANI_BACKUP_EXTRA_DIRS or --extra-dirs.
# Each directory that exists is added as a separate top-level entry in the archive.
# Missing directories are logged as warnings (not errors) — they may be absent if
# the corresponding agent bundle is not enabled.
EXTRA_DIRS="${YASHIGANI_BACKUP_EXTRA_DIRS:-}"
DRY_RUN=false

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

log_info()    { printf "    --> %s\n" "$*"; }
log_success() { printf "    ${C_GREEN}ok${C_RESET}  %s\n" "$*"; }
log_error()   { printf "    ${C_RED}!!  ERROR: %s${C_RESET}\n" "$*" >&2; }
log_warn()    { printf "    ${C_YELLOW}!!  WARNING: %s${C_RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: backup.sh [OPTIONS]

Produce an age-encrypted tarball of Yashigani backup data.

Options:
  --output-dir DIR        Directory to write <timestamp>.tar.gz.age (default: /var/lib/yashigani/backups)
  --recipient-key FILE    Path to age recipient public key (default: /etc/yashigani/backup-recipient.age.pub)
  --source-dir DIR        Directory to archive (default: /var/lib/yashigani)
  --extra-dirs DIR1:DIR2  Colon-separated list of additional directories to include
                          (B5: use for agent bundle state — langflow, letta, openclaw)
  --dry-run               Validate configuration without writing output
  --help, -h              Print this help and exit

Environment variables:
  YASHIGANI_BACKUP_OUTPUT_DIR    Override --output-dir
  YASHIGANI_BACKUP_RECIPIENT     Override --recipient-key
  YASHIGANI_BACKUP_SOURCE_DIR    Override --source-dir
  YASHIGANI_BACKUP_EXTRA_DIRS    Override --extra-dirs (colon-separated)

The recipient public key file MUST start with 'age1' (native age format).
Armored PEM-wrapped keys are NOT accepted.

See docs/operations/backup.md for key generation and rotation runbook.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)    OUTPUT_DIR="$2";         shift 2 ;;
    --recipient-key) RECIPIENT_KEY_FILE="$2"; shift 2 ;;
    --source-dir)    SOURCE_DIR="$2";         shift 2 ;;
    --extra-dirs)    EXTRA_DIRS="$2";         shift 2 ;;
    --dry-run)       DRY_RUN=true;            shift   ;;
    --help|-h)       usage; exit 0                    ;;
    *) log_error "Unknown option: $1"; usage; exit 1  ;;
  esac
done

# ---------------------------------------------------------------------------
# Gate 1: age binary present
# ---------------------------------------------------------------------------
if ! command -v age >/dev/null 2>&1; then
  log_error "age binary not found in PATH."
  log_error "  On Debian/Ubuntu: apt-get install -y age"
  log_error "  On Alpine:        apk add age"
  log_error "  From upstream:    https://age-encryption.org/  (v1.0.0+)"
  exit 1
fi

AGE_VERSION="$(age --version 2>/dev/null || echo "unknown")"
log_info "age version: ${AGE_VERSION}"

# ---------------------------------------------------------------------------
# Gate 2: recipient key file present and valid shape
# ---------------------------------------------------------------------------
if [[ ! -f "${RECIPIENT_KEY_FILE}" ]]; then
  log_error "Recipient public key file not found: ${RECIPIENT_KEY_FILE}"
  log_error ""
  log_error "Operator action required — this file MUST be provisioned before backups run."
  log_error "To generate an age key pair:"
  log_error "  age-keygen -o /etc/yashigani/backup-identity.age"
  log_error "  age-keygen -y /etc/yashigani/backup-identity.age \\"
  log_error "    > /etc/yashigani/backup-recipient.age.pub"
  log_error "  chmod 0400 /etc/yashigani/backup-identity.age"
  log_error "  chmod 0444 /etc/yashigani/backup-recipient.age.pub"
  log_error ""
  log_error "See docs/operations/backup.md — 'Encryption' section."
  exit 1
fi

# Read and validate key shape — must start with age1 (native age public key)
RECIPIENT_KEY="$(< "${RECIPIENT_KEY_FILE}")"
RECIPIENT_KEY="${RECIPIENT_KEY%%$'\n'*}"   # first line only (ignore comments)
# Strip any trailing whitespace
RECIPIENT_KEY="${RECIPIENT_KEY%"${RECIPIENT_KEY##*[![:space:]]}"}"

if [[ -z "${RECIPIENT_KEY}" ]]; then
  log_error "Recipient key file is empty: ${RECIPIENT_KEY_FILE}"
  exit 1
fi

# age native public keys start with 'age1' (bech32-encoded X25519 or HKDF)
if [[ "${RECIPIENT_KEY}" != age1* ]]; then
  log_error "Recipient key in ${RECIPIENT_KEY_FILE} does not look like an age public key."
  log_error "  Expected format: age1<bech32...>"
  log_error "  Got:             ${RECIPIENT_KEY:0:30}..."
  log_error ""
  log_error "Generate a valid key with: age-keygen | grep '^Public key:' | awk '{print \$3}'"
  exit 1
fi

log_success "Recipient key validated: ${RECIPIENT_KEY:0:16}..."

# ---------------------------------------------------------------------------
# Gate 3: source directory present
# ---------------------------------------------------------------------------
if [[ ! -d "${SOURCE_DIR}" ]]; then
  log_error "Source directory not found: ${SOURCE_DIR}"
  exit 1
fi

# ---------------------------------------------------------------------------
# B5: validate extra dirs (warn-only — absent agent dirs are non-fatal)
# Split EXTRA_DIRS on colon into array; verify each entry is a non-empty string.
# ---------------------------------------------------------------------------
EXTRA_DIRS_ARRAY=()
if [[ -n "${EXTRA_DIRS}" ]]; then
  # Read colon-separated dirs into array (IFS split — no glob expansion risk;
  # each element is a path token, not a glob).
  IFS=':' read -ra _raw_dirs <<< "${EXTRA_DIRS}"
  for _d in "${_raw_dirs[@]}"; do
    # Strip leading/trailing whitespace
    _d="${_d#"${_d%%[![:space:]]*}"}"
    _d="${_d%"${_d##*[![:space:]]}"}"
    [[ -z "${_d}" ]] && continue
    if [[ -d "${_d}" ]]; then
      EXTRA_DIRS_ARRAY+=("${_d}")
      log_info "  Extra dir:  ${_d} (found)"
    else
      # B5: warn rather than fail — if langflow is disabled the PVC mount
      # path won't exist; we should still back up the core source dir.
      log_warn "  Extra dir:  ${_d} (NOT FOUND — skipping; agent bundle may be disabled)"
    fi
  done
fi

# ---------------------------------------------------------------------------
# Dry-run exit
# ---------------------------------------------------------------------------
if [[ "${DRY_RUN}" == "true" ]]; then
  log_success "Dry-run: all gates passed."
  log_info "  Recipient key:  ${RECIPIENT_KEY_FILE}"
  log_info "  Output dir:     ${OUTPUT_DIR}"
  log_info "  Source dir:     ${SOURCE_DIR}"
  if [[ ${#EXTRA_DIRS_ARRAY[@]} -gt 0 ]]; then
    for _d in "${EXTRA_DIRS_ARRAY[@]}"; do
      log_info "  Extra dir:      ${_d}"
    done
  else
    log_info "  Extra dirs:     (none — agent bundle state not included in backup)"
    log_warn "  B5: no extra dirs configured. To include agent bundle state, set"
    log_warn "      YASHIGANI_BACKUP_EXTRA_DIRS or pass --extra-dirs DIR1:DIR2"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Create output directory (0700 — backups must not be world-readable)
# ---------------------------------------------------------------------------
if [[ ! -d "${OUTPUT_DIR}" ]]; then
  if ! mkdir -p "${OUTPUT_DIR}"; then
    log_error "Cannot create output directory: ${OUTPUT_DIR}"
    exit 1
  fi
fi
chmod 0700 "${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Build timestamp + output path
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
OUTPUT_FILE="${OUTPUT_DIR}/${TIMESTAMP}.tar.gz.age"

log_info "Starting encrypted backup..."
log_info "  Source:   ${SOURCE_DIR}"
log_info "  Output:   ${OUTPUT_FILE}"
log_info "  Recipient: ${RECIPIENT_KEY:0:16}..."
if [[ ${#EXTRA_DIRS_ARRAY[@]} -gt 0 ]]; then
  for _d in "${EXTRA_DIRS_ARRAY[@]}"; do
    log_info "  Extra:    ${_d}"
  done
else
  log_warn "  No extra dirs configured — agent bundle state excluded from backup (B5)."
  log_warn "  Set YASHIGANI_BACKUP_EXTRA_DIRS to include langflow/letta/openclaw state."
fi

# ---------------------------------------------------------------------------
# Produce tarball and pipe through age encryption.
#
# Pipeline: tar -cz SOURCE_DIR [extra_dirs...] | age --encrypt --recipient KEY > OUTPUT_FILE
#
# B5: extra dirs are appended as --directory parent basename pairs so each dir
# appears as a top-level entry in the archive (restore unpacks cleanly into the
# original paths without path-collision with the primary SOURCE_DIR tree).
#
# Failure modes:
#   - tar non-zero:   archive creation failed (permissions, I/O) — output deleted
#   - age non-zero:   encryption failed (bad key, I/O)           — output deleted
#
# We use a temp file in the same directory as the final target so the atomic
# rename is guaranteed to be on the same filesystem (no cross-fs mv).
# The temp file is 0600 (umask 077 applied at top of script).
# ---------------------------------------------------------------------------
TMP_OUTPUT="${OUTPUT_DIR}/.tmp-${TIMESTAMP}-$$.tar.gz.age"
# Temp file for capturing tar exit status across the pipeline boundary.
# We cannot rely on PIPESTATUS inside a portable function-call context, so we
# write tar's exit code to a temp status file that survives the subshell.
TAR_STATUS_FILE="${OUTPUT_DIR}/.tmp-tar-status-${TIMESTAMP}-$$"

# Build the tar argument list for extra dirs.
# Each extra dir becomes: --directory <parent> <basename>
# This preserves the canonical path structure inside the archive:
#   SOURCE_DIR=/var/lib/yashigani        → yashigani/ at archive root
#   extra_dir=/var/lib/agents/langflow   → langflow/  at archive root
# On restore, the operator extracts each tree to its original parent.
TAR_EXTRA_ARGS=()
for _extra in "${EXTRA_DIRS_ARRAY[@]}"; do
  TAR_EXTRA_ARGS+=( "--directory" "$(dirname "${_extra}")" "$(basename "${_extra}")" )
done

# Ensure temp files are cleaned up on any exit (including SIGINT/SIGTERM)
# shellcheck disable=SC2064
trap 'rm -f "${TMP_OUTPUT}" "${TAR_STATUS_FILE}" 2>/dev/null; exit 1' INT TERM

# Produce tarball and pipe through age.
# TAR_STATUS is captured via a status file because the { ... }|pipe construct
# runs tar in a subshell where variable assignments are not visible to the
# parent shell (SC2030/SC2031).
(
  tar --create --gzip \
      --directory "$(dirname "${SOURCE_DIR}")" \
      "$(basename "${SOURCE_DIR}")" \
      "${TAR_EXTRA_ARGS[@]}" \
      2>/dev/null
  printf '%d' $? > "${TAR_STATUS_FILE}"
) | age --encrypt --recipient "${RECIPIENT_KEY}" --output "${TMP_OUTPUT}" 2>/dev/null
ENCRYPT_STATUS=$?

TAR_STATUS=0
if [[ -f "${TAR_STATUS_FILE}" ]]; then
  TAR_STATUS=$(cat "${TAR_STATUS_FILE}")
  rm -f "${TAR_STATUS_FILE}"
fi

if [[ "${TAR_STATUS}" -ne 0 ]]; then
  rm -f "${TMP_OUTPUT}" 2>/dev/null || true
  trap - INT TERM
  log_error "tar failed (exit ${TAR_STATUS}) — no backup written to disk."
  log_error "  Check: read access to ${SOURCE_DIR} and extra dirs"
  exit 1
fi

if [[ "${ENCRYPT_STATUS}" -ne 0 ]]; then
  rm -f "${TMP_OUTPUT}" 2>/dev/null || true
  trap - INT TERM
  log_error "age encryption failed (exit ${ENCRYPT_STATUS}) — no backup written to disk."
  log_error "  Check: age binary version, recipient key format."
  exit 1
fi

if [[ ! -f "${TMP_OUTPUT}" ]]; then
  trap - INT TERM
  log_error "Pipeline succeeded but output file not found: ${TMP_OUTPUT}"
  exit 1
fi

# Atomic rename: temp → final
mv "${TMP_OUTPUT}" "${OUTPUT_FILE}"
rm -f "${TAR_STATUS_FILE}" 2>/dev/null || true
trap - INT TERM

chmod 0400 "${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
BACKUP_SIZE="$(du -sh "${OUTPUT_FILE}" 2>/dev/null | awk '{print $1}')"
log_success "Encrypted backup written: ${OUTPUT_FILE} (${BACKUP_SIZE})"
log_info "Retention: manage old backups with 'find ${OUTPUT_DIR} -name \"*.tar.gz.age\" -mtime +30 -delete'"
log_info "Restore:   bash restore.sh --encrypted <path-to-identity.age> ${OUTPUT_FILE}"

printf '\n%sBackup complete.%s\n\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
printf "  File:      %s\n" "${OUTPUT_FILE}"
printf "  Size:      %s\n" "${BACKUP_SIZE}"
printf "  Recipient: %s\n\n" "${RECIPIENT_KEY:0:16}..."
