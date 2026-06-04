#!/usr/bin/env bash
set -euo pipefail
# Last updated: 2026-05-10T00:00:00+01:00 (fix(pki): PR#122 — replace blanket CWE-732 find assertion with per-service pki_key_mode check; eliminates false-positive on prometheus_client.key 0640)
# Last updated: 2026-05-10T00:00:00+01:00 (fix(pki): GATE5-BUG-01 — source shared lib/pki_ownership.sh; restore stops blanket-chmod; per-key ownership on written keys only; maintainer directive 2026-05-10)
# Last updated: 2026-05-09T00:00:00+01:00 (feat: MP.L2-3.8.9 — add --encrypted path for age-encrypted .tar.gz.age backups)
# Last updated: 2026-05-10T18:30:00+01:00 (fix(gate5): global _DECRYPT_EXTRACT_DIR for EXIT trap — local var inaccessible in EXIT trap when set -e triggers early script exit)
# Last updated: 2026-05-08T00:00:00+01:00 (fix: K8s verify path — trigger rollout restart + wait + healthz probe after K8s secret restore; PR #67 followup)
# Last updated: 2026-05-07T09:00:00+01:00 (fix: validate_backup BACKUP_DIR→backup_dir variable mismatch — signed backups failed validation without --force)
# Last updated: 2026-05-03T12:45:00+01:00 (V232-SMOKE-010: exclude .gitkeep from empty-file check; V232-SMOKE-011: podman unshare chown -R before cp restore; V232-SMOKE-012: secrets dir 0751→0755)

# ---------------------------------------------------------------------------
# Shared PKI service-key ownership map (single source of truth).
# lib/pki_ownership.sh must live alongside restore.sh in the repo root.
# GATE5-BUG-01 / maintainer directive 2026-05-10.
# ---------------------------------------------------------------------------
# shellcheck source=lib/pki_ownership.sh
_YSG_RESTORE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_YSG_RESTORE_SCRIPT_DIR}/lib/pki_ownership.sh" ]]; then
  # shellcheck disable=SC1091
  source "${_YSG_RESTORE_SCRIPT_DIR}/lib/pki_ownership.sh"
else
  printf "ERROR: lib/pki_ownership.sh not found alongside restore.sh\n" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# FIPS-aware SHA-256 helpers (integrity-verification paths only).
# lib/yashigani-fips.sh routes through OpenSSL FIPS Provider when FIPS_MODE=1.
# CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2 directive 2026-05-24.
# ---------------------------------------------------------------------------
# shellcheck source=lib/yashigani-fips.sh
if [[ -f "${_YSG_RESTORE_SCRIPT_DIR}/lib/yashigani-fips.sh" ]]; then
  # shellcheck disable=SC1091
  source "${_YSG_RESTORE_SCRIPT_DIR}/lib/yashigani-fips.sh"
else
  printf "ERROR: lib/yashigani-fips.sh not found alongside restore.sh\n" >&2
  exit 1
fi

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
RUN_VALIDATE=false

# ---------------------------------------------------------------------------
# Encrypted restore state (MP.L2-3.8.9)
# Set by --encrypted <identity-file>; also honoured from env.
# ---------------------------------------------------------------------------
ENCRYPTED_MODE=false
IDENTITY_FILE="${YASHIGANI_BACKUP_IDENTITY_FILE:-/etc/yashigani/backup-identity.age}"

# ---------------------------------------------------------------------------
# v2 dual-wrap restore state (YSG-RISK-050/051)
# Flow A: --recovery-password (interactive prompt, default)
# Flow B: --recovery-license <path>  (licensed tier wrap#2)
# Flow C: --recovery-key <hex|env>   (community tier wrap#2)
# ---------------------------------------------------------------------------
V2_RECOVERY_MODE="password"     # "password" | "license" | "key"
V2_RECOVERY_LICENSE=""          # path to .ysg file for flow B
V2_RECOVERY_KEY=""              # hex-encoded key for flow C

# Script-global staging dir for v2 decrypt (must be global for EXIT trap to reach it;
# same pattern as _DECRYPT_EXTRACT_DIR for the age-encrypted restore path).
_V2_STAGING_DIR=""

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
# _validate_v2_backup <backup_dir>
# YSG-RISK-050/051: Structural + HMAC validation for v2 dual-wrap backups.
# Checks that backup-meta.json is well-formed and bundle.enc is present.
# Does NOT decrypt (that requires the credential — done in _v2_decrypt_to_staging).
# HMAC verification requires the DEK which is only available after decryption —
# we do structural + schema checks here; HMAC is verified inside _v2_decrypt_to_staging.
# ---------------------------------------------------------------------------
_validate_v2_backup() {
  local backup_dir="$1"
  local errors=0

  log_info "v2 encrypted backup detected (backup-meta.json present)"

  # Hard fail: bundle.enc must exist alongside the meta.
  if [[ ! -f "${backup_dir}/bundle.enc" ]]; then
    log_error "v2 backup missing bundle.enc — partial backup or corrupt directory"
    errors=$((errors + 1))
  fi

  if [[ "$errors" -gt 0 ]]; then
    log_error "v2 backup validation: ${errors} failure(s)"
    return 1
  fi

  # Schema check: backup-meta.json must be valid JSON with expected top-level keys.
  local _meta_keys_ok=true
  for _key in version ts tier bundle_aead wrap1 wrap2 hmac; do
    if ! python3 -c "import json,sys; m=json.load(open('${backup_dir}/backup-meta.json')); sys.exit(0 if '${_key}' in m else 1)" 2>/dev/null; then
      log_error "v2 backup-meta.json missing required key: ${_key}"
      _meta_keys_ok=false
      errors=$((errors + 1))
    fi
  done

  # Check version field.
  if [[ "$_meta_keys_ok" == "true" ]]; then
    local _version
    _version=$(python3 -c "import json; print(json.load(open('${backup_dir}/backup-meta.json'))['version'])" 2>/dev/null || true)
    if [[ "$_version" != "yashigani-backup-v1" ]]; then
      log_error "v2 backup-meta.json unknown version: '${_version}' (expected 'yashigani-backup-v1')"
      errors=$((errors + 1))
    fi

    # Check wrap2.present is true (wrap#2 is always required — fail-closed).
    local _wrap2_present
    _wrap2_present=$(python3 -c "import json; print(json.load(open('${backup_dir}/backup-meta.json'))['wrap2']['present'])" 2>/dev/null || true)
    if [[ "$_wrap2_present" != "True" && "$_wrap2_present" != "true" ]]; then
      log_error "v2 backup-meta.json wrap2.present is not true — recovery wrap is missing (corrupt backup)"
      errors=$((errors + 1))
    fi

    # Warn if wrap1.present is false.
    local _wrap1_present
    _wrap1_present=$(python3 -c "import json; print(json.load(open('${backup_dir}/backup-meta.json'))['wrap1']['present'])" 2>/dev/null || true)
    if [[ "$_wrap1_present" == "False" || "$_wrap1_present" == "false" ]]; then
      log_warn "v2 backup: wrap1.present=false — admin-password path unavailable; use --recovery-license or --recovery-key"
    fi

    # Warn if bundle.enc is suspiciously small (< 256 bytes would indicate an empty bundle).
    local _bundle_size
    _bundle_size=$(wc -c < "${backup_dir}/bundle.enc" 2>/dev/null | tr -d ' ')
    if [[ -n "$_bundle_size" && "$_bundle_size" -lt 256 ]]; then
      log_error "v2 bundle.enc is suspiciously small (${_bundle_size} bytes) — likely corrupt"
      errors=$((errors + 1))
    fi
  fi

  if [[ "$errors" -gt 0 ]]; then
    log_error "v2 backup validation: ${errors} failure(s)"
    return 1
  fi

  log_success "v2 backup structural validation passed (HMAC will be verified at decrypt time)"
  return 0
}

# ---------------------------------------------------------------------------
# _v2_decrypt_to_staging <backup_dir> <staging_dir>
# YSG-RISK-050/051: Decrypt a v2 backup bundle to a staging directory.
# Reads V2_RECOVERY_MODE / V2_RECOVERY_LICENSE / V2_RECOVERY_KEY globals
# (set from CLI flags). For flow A (password), prompts interactively.
# On success: staging_dir contains the extracted contents (secrets/, .env, etc.)
# On failure: exits non-zero (fail-closed; no partial state).
# ---------------------------------------------------------------------------
_v2_decrypt_to_staging() {
  local backup_dir="$1"
  local staging_dir="$2"

  local meta_file="${backup_dir}/backup-meta.json"
  local bundle_file="${backup_dir}/bundle.enc"

  mkdir -p "$staging_dir"

  log_info "v2 backup: decrypting bundle.enc (flow: ${V2_RECOVERY_MODE})"

  # Build the Python decrypt inline script.
  local _py_decrypt
  _py_decrypt=$(cat << 'PYPEOF'
#!/usr/bin/env python3
"""
YSG-RISK-050/051: v2 backup decrypt + HMAC verify.
LOCKED spec 2026-05-28. Three flows: A=password, B=license, C=key.
All credentials via environment variables.
"""
import hashlib
import hmac as _hmac
import json
import os
import sys
import tarfile
import io
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA384
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
except ImportError as e:
    sys.stderr.write(f"FATAL: cryptography not available: {e}\n"); sys.exit(1)

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
except ImportError as e:
    sys.stderr.write(f"FATAL: argon2-cffi not available: {e}\n"); sys.exit(1)

META_FILE    = os.environ["_YSG_META_FILE"]
BUNDLE_FILE  = os.environ["_YSG_BUNDLE_FILE"]
STAGING_DIR  = os.environ["_YSG_STAGING_DIR"]
FLOW         = os.environ["_YSG_FLOW"]         # "password" | "license" | "key"
CREDENTIAL   = sys.stdin.read()  # plaintext password | hex IKM2 — via stdin (NEW-ISSUE-2, CWE-214: not env, not argv)

meta = json.loads(Path(META_FILE).read_text())
bundle_ct = Path(BUNDLE_FILE).read_bytes()
ts = meta["ts"]

def _hkdf(ikm, salt, info, length):
    return HKDF(
        algorithm=SHA384(), length=length,
        salt=salt if salt else None, info=info,
        backend=default_backend(),
    ).derive(ikm)

def _zero(b):
    if isinstance(b, bytearray):
        for i in range(len(b)): b[i] = 0

# ── Derive DEK ───────────────────────────────────────────────────────────────
# wrap#1 kdf_algo is always "argon2id+hkdf-sha384" (Nico ruling 2026-05-28).
# Under FIPS_MODE=1, wrap1.present=false — the flow cannot reach this branch.
# The PBKDF2 branch is removed: PBKDF2 cannot reproduce an argon2 verifier.
dek = None

if FLOW == "password":
    w1 = meta.get("wrap1", {})
    if not w1.get("present", False):
        sys.stderr.write("FATAL: wrap1.present=false — admin-password path not available.\n")
        sys.stderr.write("  Use --recovery-license or --recovery-key to restore via wrap#2.\n")
        sys.exit(1)
    kdf_algo = w1.get("kdf_algo", "argon2id+hkdf-sha384")
    kek1_hkdf_salt = bytes.fromhex(w1["kek1_hkdf_salt_hex"])
    iv1            = bytes.fromhex(w1["iv_hex"])
    wdek1_ct       = bytes.fromhex(w1["wdek_ct_hex"])
    wdek1_tag      = bytes.fromhex(w1["wdek_tag_hex"])
    aad1 = b"yashigani-backup-v1" + ts.encode() + b"\x01"

    if "argon2id" in kdf_algo:
        # Flow A: recompute V = argon2id_raw(typed_plaintext, argon2_salt_from_meta, params).
        # This matches the V that backup extracted from the stored PHC iff password unchanged.
        salt_b = bytes.fromhex(w1["argon2_salt_hex"])
        ikm1 = bytearray(hash_secret_raw(
            secret=CREDENTIAL.encode(),
            salt=salt_b,
            time_cost=w1["argon2_time_cost"],
            memory_cost=w1["argon2_memory_cost"],
            parallelism=w1["argon2_parallelism"],
            hash_len=w1["argon2_hash_len"],
            type=Argon2Type.ID,
            version=w1["argon2_version"],
        ))
    else:
        sys.stderr.write(f"FATAL: Unsupported wrap#1 kdf_algo: {kdf_algo!r}\n")
        sys.stderr.write("  Only 'argon2id+hkdf-sha384' is supported (Nico ruling 2026-05-28).\n")
        sys.exit(1)

    kek1 = bytearray(_hkdf(bytes(ikm1), kek1_hkdf_salt, b"yashigani-kek1-v1", 32))
    _zero(ikm1)
    try:
        dek = bytearray(AESGCM(bytes(kek1)).decrypt(iv1, wdek1_ct + wdek1_tag, aad1))
    except InvalidTag:
        sys.stderr.write("FATAL: Wrong password — AES-GCM tag verification failed (InvalidTag).\n")
        sys.stderr.write("  The admin password does not match the backup. Try --recovery-license or --recovery-key.\n")
        sys.exit(2)
    finally:
        _zero(kek1)

else:
    # Flow B or C: wrap#2
    w2 = meta.get("wrap2", {})
    if not w2.get("present", False):
        sys.stderr.write("FATAL: wrap2.present=false — recovery path not available.\n")
        sys.exit(1)
    kek2_hkdf_salt = bytes.fromhex(w2["kek2_hkdf_salt_hex"])
    iv2            = bytes.fromhex(w2["iv_hex"])
    wdek2_ct       = bytes.fromhex(w2["wdek_ct_hex"])
    wdek2_tag      = bytes.fromhex(w2["wdek_tag_hex"])
    aad2 = b"yashigani-backup-v1" + ts.encode() + b"\x02"
    ikm2 = bytearray(bytes.fromhex(CREDENTIAL))
    kek2 = bytearray(_hkdf(bytes(ikm2), kek2_hkdf_salt, b"yashigani-kek2-v1", 32))
    _zero(ikm2)
    try:
        dek = bytearray(AESGCM(bytes(kek2)).decrypt(iv2, wdek2_ct + wdek2_tag, aad2))
    except InvalidTag:
        sys.stderr.write("FATAL: Recovery key/license does not match backup wrap#2 — AES-GCM InvalidTag.\n")
        sys.exit(2)
    finally:
        _zero(kek2)

# ── Verify HMAC-SHA384 ────────────────────────────────────────────────────────
mac_key = bytearray(_hkdf(bytes(dek), b"", b"yashigani-backup-meta-mac-v1", 48))

# Re-derive AAD_B: meta with hmac_hex = "" (same canonical form as backup time).
meta_for_aad = json.loads(Path(META_FILE).read_text())
meta_for_aad["hmac"]["hmac_hex"] = ""
aad_b = json.dumps(meta_for_aad, sort_keys=True, separators=(",", ":")).encode()

expected_hmac = _hmac.new(bytes(mac_key), aad_b, digestmod=hashlib.sha384).hexdigest()
_zero(mac_key)

stored_hmac = meta.get("hmac", {}).get("hmac_hex", "")
if not _hmac.compare_digest(expected_hmac, stored_hmac):
    sys.stderr.write("FATAL: HMAC-SHA384 verification failed — backup-meta.json has been tampered.\n")
    sys.stderr.write("  Expected and stored HMACs do not match. Refuse to restore.\n")
    sys.exit(3)

# ── Decrypt bundle.enc → tar.gz ───────────────────────────────────────────────
bundle_iv = bytes.fromhex(meta["bundle_aead"]["iv_hex"])
try:
    pt_bytes = AESGCM(bytes(dek)).decrypt(bundle_iv, bundle_ct, aad_b)
except InvalidTag:
    sys.stderr.write("FATAL: bundle.enc AES-GCM tag verification failed — bundle tampered or corrupt.\n")
    sys.exit(3)
finally:
    _zero(dek)

# ── Extract tar.gz to staging_dir ─────────────────────────────────────────────
# Use filter="data" (Python ≥3.12, confirmed in pyproject.toml) which blocks
# absolute paths, ".." traversal, symlink attacks, and special files.
# (FINDING-4 fix: manual filter with startswith("..") / "//" checks did NOT
# block absolute paths like "/etc/passwd" or "a/../../etc/evil".)
staging = Path(STAGING_DIR)
staging.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(pt_bytes), mode="r:gz") as tar:
    # Strip the leading arcname prefix (backup_staging/) from member names
    # before extraction so the staging dir gets the bare contents.
    members = []
    for member in tar.getmembers():
        if member.name == "backup_staging":
            continue
        if member.name.startswith("backup_staging/"):
            member.name = member.name[len("backup_staging/"):]
        if not member.name:
            continue
        members.append(member)
    tar.extractall(path=str(staging), members=members, filter="data")

sys.stdout.write("OK: bundle decrypted, HMAC verified, extracted to staging\n")
sys.exit(0)
PYPEOF
  )

  # Gather the credential for the chosen flow.
  local _credential=""
  local _flow_env="$V2_RECOVERY_MODE"

  case "$V2_RECOVERY_MODE" in
    password)
      # Flow A: prompt for admin password interactively.
      local _wrap1_present
      _wrap1_present=$(python3 -c \
        "import json; m=json.load(open('${meta_file}')); print(m['wrap1'].get('present', False))" \
        2>/dev/null || true)
      if [[ "$_wrap1_present" == "False" || "$_wrap1_present" == "false" ]]; then
        log_error "v2 backup: wrap1.present=false — admin-password restore unavailable."
        log_error "  Use --recovery-license <path> or --recovery-key <hex> to restore via wrap#2."
        exit 1
      fi
      printf "\n"
      printf "  %s\n" "v2 encrypted backup — enter the Yashigani admin password to decrypt."
      printf "  %s\n" "(This is the password you use to log in to the admin panel.)"
      printf "\n"
      read -rs -p "  Admin password: " _credential
      printf "\n"
      if [[ -z "$_credential" ]]; then
        log_error "v2 backup: empty password entered — aborting."
        exit 1
      fi
      ;;
    license)
      # Flow B: licensed tier — read .ysg file bytes as hex-encoded IKM2.
      if [[ -z "$V2_RECOVERY_LICENSE" ]]; then
        log_error "v2 backup: --recovery-license requires a path to the .ysg license file."
        exit 1
      fi
      if [[ ! -f "$V2_RECOVERY_LICENSE" ]]; then
        log_error "v2 backup: license file not found: ${V2_RECOVERY_LICENSE}"
        exit 1
      fi
      _credential=$(xxd -p -c 9999 "$V2_RECOVERY_LICENSE" 2>/dev/null | tr -d '\n' \
        || od -A n -t x1 "$V2_RECOVERY_LICENSE" 2>/dev/null | tr -d ' \n' || true)
      if [[ -z "$_credential" ]]; then
        log_error "v2 backup: failed to hex-encode .ysg file (xxd/od missing?)"
        exit 1
      fi
      _flow_env="key"  # Python uses "key" for both B and C (wrap#2)
      ;;
    key)
      # Flow C: community tier — DB AES key as hex-encoded IKM2.
      if [[ -z "$V2_RECOVERY_KEY" ]]; then
        log_error "v2 backup: --recovery-key requires a hex value or 'env'."
        exit 1
      fi
      # Encode the key string's UTF-8 bytes as hex for IKM2.
      _credential=$(printf '%s' "$V2_RECOVERY_KEY" | xxd -p -c 9999 2>/dev/null | tr -d '\n' \
        || printf '%s' "$V2_RECOVERY_KEY" | od -A n -t x1 2>/dev/null | tr -d ' \n' || true)
      if [[ -z "$_credential" ]]; then
        log_error "v2 backup: failed to hex-encode recovery key"
        exit 1
      fi
      ;;
    *)
      log_error "v2 backup: unknown recovery mode '${V2_RECOVERY_MODE}'"
      exit 1
      ;;
  esac

  # We use a tempfile for the Python script (no secrets in it).
  local _py_tmp
  _py_tmp=$(mktemp "${staging_dir}/.ysg_decrypt_XXXXXX.py")
  chmod 0700 "$_py_tmp"
  printf '%s' "$_py_decrypt" > "$_py_tmp"

  # NEW-ISSUE-2 (Laura re-gate, CWE-214): the credential (plaintext password or
  # hex IKM2) must NOT be passed via env (visible in /proc/<pid>/environ) — feed
  # it to the Python via stdin instead. Non-secret config stays in env vars.
  if ! _py_out=$(
    printf '%s' "$_credential" | \
    _YSG_META_FILE="$meta_file" \
    _YSG_BUNDLE_FILE="$bundle_file" \
    _YSG_STAGING_DIR="$staging_dir" \
    _YSG_FLOW="$_flow_env" \
    _YSG_FIPS_MODE="${FIPS_MODE:-0}" \
    python3 "$_py_tmp" 2>&1
  ); then
    local _exit_code=$?
    rm -f "$_py_tmp"
    # Zero the credential variable (best-effort).
    _credential=""
    log_error "v2 backup: decryption failed (exit ${_exit_code})"
    log_error "  ${_py_out}"
    rm -rf "$staging_dir"
    exit 1
  fi

  rm -f "$_py_tmp"
  _credential=""  # best-effort clear

  log_success "v2 backup decrypted and HMAC verified: ${_py_out}"
  return 0
}

# ---------------------------------------------------------------------------
# Validate backup integrity
# ---------------------------------------------------------------------------
validate_backup() {
  local backup_dir="$1"
  local errors=0

  # ── v2 backup detection (YSG-RISK-050/051) ───────────────────────────────
  # A v2 backup has backup-meta.json (cleartext) + bundle.enc (AEAD-encrypted).
  # The sensitive content (secrets/, .env, postgres_dump.sql, agent-volumes/) is
  # inside bundle.enc — NOT present as plaintext. Structural checks differ.
  if [[ -f "${backup_dir}/backup-meta.json" ]]; then
    _validate_v2_backup "$backup_dir"
    return $?
  fi

  # ── Legacy (v1) backup path ───────────────────────────────────────────────
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
            # _fips_sha256 routes through OpenSSL FIPS Provider when FIPS_MODE=1
            # (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2).
            _actual_hash=$(_fips_sha256 "$_fpath")
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

  # ── v2 backup: decrypt bundle.enc → staging dir ───────────────────────────
  # If this is a v2 backup (backup-meta.json present), decrypt the bundle to a
  # temp staging dir before the rest of the restore logic runs. After decryption,
  # `backup_dir` is rebound to the staging dir so all subsequent logic (secrets
  # copy, .env restore, pg_dump restore) works on the plaintext staging content.
  #
  # The staging dir is cleaned up on EXIT regardless of success/failure.
  local _v2_staging_dir=""
  if [[ -f "${backup_dir}/backup-meta.json" ]]; then
    _v2_staging_dir="${BACKUPS_DIR}/.v2-staging-$(date +%Y%m%d_%H%M%S)-$$"
    # Register cleanup on exit regardless of success/failure (fail-closed).
    # _V2_STAGING_DIR is a global so the EXIT trap can reach it.
    _V2_STAGING_DIR="$_v2_staging_dir"
    trap 'rm -rf "${_V2_STAGING_DIR:-}" 2>/dev/null' EXIT

    _v2_decrypt_to_staging "$backup_dir" "$_v2_staging_dir"

    # Verify that the decrypted staging contains the expected backup content.
    if [[ ! -d "${_v2_staging_dir}/secrets" && ! -f "${_v2_staging_dir}/.env" ]]; then
      log_error "v2 backup: decrypted staging dir missing secrets/ and .env — extraction may have failed"
      exit 1
    fi

    # Rebind backup_dir to the decrypted staging dir for all subsequent logic.
    backup_dir="$_v2_staging_dir"
    log_info "v2 backup: using decrypted staging dir: ${backup_dir}"
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
    # Enumerate which keys were actually present in the backup before the copy.
    # _pki_chown_client_keys applies ownership ONLY to those keys — keys already
    # on disk that were not in the backup are left untouched.
    # maintainer directive 2026-05-10: "restore of keys should only be done in a
    # scenario where they have been nuked in some way". GATE5-BUG-01.
    local _backup_written_keys=()
    local _bk_svc
    # Service leaf keys from the shared map.
    while IFS= read -r _bk_svc; do
      if [[ -f "${backup_dir}/secrets/${_bk_svc}_client.key" ]]; then
        _backup_written_keys+=("${_bk_svc}_client.key")
      fi
    done < <(pki_services_all)
    # CA private keys — not in the service map but still need ownership tracking.
    for _bk_ca_key in ca_root.key ca_intermediate.key; do
      if [[ -f "${backup_dir}/secrets/${_bk_ca_key}" ]]; then
        _backup_written_keys+=("${_bk_ca_key}")
      fi
    done

    # cp -p preserves source mode/ownership timestamps.
    if ! cp -rp "${backup_dir}/secrets/"* "${WORK_DIR}/docker/secrets/"; then
      log_error "Failed to copy secrets from backup"
      return 1
    fi
    local secret_count
    secret_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f | wc -l | tr -d ' ')
    log_success "Secrets copied from backup (${secret_count} files)"

    # BUG-58B-04a + BUG-58B-04b (v2.23.1): reapply canonical file modes and
    # re-own service private keys ONLY for the keys that were actually written
    # from the backup. Keys already on disk and not in the backup are untouched.
    # GATE5-BUG-01 / maintainer directive 2026-05-10: removed blanket find+chmod sweep.
    _pki_chown_client_keys "${_backup_written_keys[@]+"${_backup_written_keys[@]}"}"
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
# _pki_chown_client_keys — Re-own service private keys to container UIDs.
#
# Accepts a list of key BASENAMES (e.g. "gateway_client.key") that were
# actually written from the backup. Only those keys get ownership re-applied;
# keys already on disk that were NOT in the backup are left untouched.
#
# maintainer directive 2026-05-10 / GATE5-BUG-01:
#   "restore of keys should only be done in a scenario where they have been
#    nuked in some way" — so restore must NOT blanket-chmod every *.key it
#    finds on disk. Only the keys it actually placed get touched.
#
# UID + mode come from lib/pki_ownership.sh (single source of truth).
# Runs after secrets are restored on every supported runtime.
#
# Usage: _pki_chown_client_keys [key_basename ...]
#   e.g.: _pki_chown_client_keys "gateway_client.key" "pgbouncer_client.key"
#   With no args: no keys are touched (no backup keys found).
# ---------------------------------------------------------------------------
_pki_chown_client_keys() {
  # Positional: list of key basenames that were written from the backup.
  local _written_keys=("$@")
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  if [[ "${#_written_keys[@]}" -eq 0 ]]; then
    log_info "_pki_chown_client_keys: no keys were written from backup — nothing to re-own"
    return 0
  fi

  # Determine chown mode: root can chown directly; non-root uses podman unshare
  # (Podman rootless user-namespace). Docker non-root: restore.sh never runs
  # sudo (P0-14) — warn with a copy-pasteable remediation block instead.
  local _chown_mode="direct"
  if [[ "$(id -u)" != "0" ]]; then
    if [[ "${RUNTIME}" == "podman" ]]; then
      _chown_mode="unshare"
    else
      # Docker non-root: warn-only — never sudo (P0-14 / feedback_security_company_no_shortcuts).
      _chown_mode="warn"
    fi
  fi

  log_info "Re-owning ${#_written_keys[@]} restored key(s) to container UIDs (mode: ${_chown_mode})"

  # Helper: apply chown+chmod to a single file using the active strategy.
  # Args: <uid> <keyfile_path> <label> <mode>
  _do_restore_chown() {
    local _uid="$1" _file="$2" _label="$3" _mode="$4"
    case "$_chown_mode" in
      direct)
        if ! chown "${_uid}:${_uid}" "$_file"; then
          log_warn "chown failed on ${_label} — container may fail to start"
          return 0
        fi
        if ! chmod "${_mode}" "$_file"; then
          log_warn "chmod ${_mode} failed on ${_label} (not fatal for direct mode)"
        fi
        ;;
      unshare)
        # RESTORE-1 (v2.23.1 gate): chmod must run INSIDE the podman unshare
        # namespace because after `podman unshare chown`, the file is owned by
        # a subuid-range UID on the host and a subsequent host-side chmod fails
        # with EPERM. This matches install.sh's _do_chown pattern.
        if ! podman unshare sh -c \
              "chown ${_uid}:${_uid} '${_file}' && chmod ${_mode} '${_file}'" 2>/dev/null; then
          log_warn "podman unshare chown/chmod failed on ${_label} — container may fail to start"
        fi
        ;;
      warn)
        log_warn "Non-root Docker: cannot chown ${_label} to UID ${_uid} without sudo."
        log_warn "  Run manually if the service fails to start:"
        log_warn "    sudo chown ${_uid}:${_uid} \"${_file}\" && sudo chmod ${_mode} \"${_file}\""
        ;;
    esac
    return 0
  }

  # Apply ownership to each key that was actually written from backup.
  local _kb _svc _uid _mode _keyfile
  for _kb in "${_written_keys[@]}"; do
    # Derive service name: strip trailing "_client.key".
    _svc="${_kb%_client.key}"
    _keyfile="${_secrets_dir}/${_kb}"

    if [[ ! -f "$_keyfile" ]]; then
      # Key was in backup manifest but file not found after cp — operator error.
      log_error "Key ${_kb} was in backup but not found at ${_keyfile} after restore."
      log_error "  The backup may be corrupt or the copy failed for this file."
      log_error "  Manual recovery: re-run install.sh to regenerate all keys."
      # Non-fatal: continue restoring other keys; surface all errors at once.
      continue
    fi

    # Look up this service in the shared map.
    if ! _uid="$(pki_service_uid "$_svc" 2>/dev/null)"; then
      # Key is not a known service key (e.g. a CA key or custom key).
      # Leave it alone — it was written by cp -rp and inherits backup permissions.
      log_info "  ${_kb}: not in service map — leaving permissions as restored from backup"
      continue
    fi
    _mode="$(pki_key_mode "$_svc")"

    log_info "  ${_kb}: chown ${_uid}:${_uid} chmod ${_mode}"
    _do_restore_chown "${_uid}" "${_keyfile}" "${_kb}" "${_mode}"
  done

  # Cert files (*.crt) that were in the backup: set to 0644 (public material).
  # We find these from the backup dir's crt files — only touch what we wrote.
  # This is safe as a host-side chmod because certs are public; no ownership change.
  log_info "Chmod'ing restored client certs + CA certs to 0644 (public material)"
  find "${_secrets_dir}" -maxdepth 1 -type f \
    \( -name '*_client.crt' -o -name 'ca_*.crt' \) \
    -exec chmod 0644 {} \; 2>/dev/null || true

  # CA private keys: tighten to 0400 ONLY if they were in the backup.
  # (Already handled correctly by pki_service_uid — ca_root.key / ca_intermediate.key
  #  are NOT in the service map, so they are left at backup permissions above.
  #  We apply 0400 explicitly here as the documented CA key posture.)
  for _ca_key in ca_root.key ca_intermediate.key; do
    if [[ -f "${_secrets_dir}/${_ca_key}" ]]; then
      # Check whether this CA key was actually written from backup.
      local _ca_was_restored=0
      local _wk
      for _wk in "${_written_keys[@]+"${_written_keys[@]}"}"; do
        if [[ "$_wk" == "$_ca_key" ]]; then
          _ca_was_restored=1
          break
        fi
      done
      if [[ "$_ca_was_restored" == "1" ]]; then
        chmod 0400 "${_secrets_dir}/${_ca_key}" 2>/dev/null || true
      fi
    fi
  done

  # BUG-58B-04a: reapply 0644 to public password/token files that the backup's
  # per-file chmod may have tightened (pre-fix backups used chmod -R 600).
  # These are not keys — safe to chmod on the host without ownership change.
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
      chmod 0644 "${_secrets_dir}/${_f}" 2>/dev/null || true
    fi
  done
  # bootstrap_token files (glob — one per service registered in manifest)
  find "${_secrets_dir}" -maxdepth 1 -type f -name '*_bootstrap_token' \
    -exec chmod 0644 {} \; 2>/dev/null || true

  log_success "Service key ownership applied to ${#_written_keys[@]} restored key(s)"

  # S1 / CWE-732 assertion — data-driven per-service mode check.
  #
  # Replaces the previous blanket `find -perm -040` which fired a false-positive
  # on prometheus_client.key (legitimately 0640 per EX-231-10).
  #
  # Two sub-checks:
  #   A) Per-service: actual mode must match pki_key_mode() for every written key
  #      that is in the shared map. This catches silent chmod regression on any
  #      service, including future 0640 services.
  #   B) World-readable sweep: any *.key file with the world-read bit (004) is
  #      always wrong — no service requires world-readable private keys.
  #
  # Note: for 'unshare' mode, subuid-range-owned files may not be stat-able by
  # the host caller — stat returns empty. We treat empty-stat as skip (not PASS)
  # to avoid false-positives; the log makes the skip visible.
  #
  # Portable stat: GNU stat -c '%a'; BSD stat -f '%OLp' (macOS).
  _stat_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1" 2>/dev/null || true
  }

  local _cwe732_fail=0

  # Sub-check A: per-service mode parity for written keys in the shared map.
  local _ck _csvc _exp_mode _act_mode _ckfile
  for _ck in "${_written_keys[@]+"${_written_keys[@]}"}"; do
    _csvc="${_ck%_client.key}"
    if ! _exp_mode="$(pki_key_mode "$_csvc" 2>/dev/null)"; then
      # Not a known service key (CA key or custom) — skip mode check for sub-A;
      # sub-B world-read sweep covers it.
      continue
    fi
    _ckfile="${_secrets_dir}/${_ck}"
    if [[ ! -f "$_ckfile" ]]; then
      continue  # already reported as missing above
    fi
    _act_mode="$(_stat_mode "$_ckfile")"
    if [[ -z "$_act_mode" ]]; then
      log_warn "CWE-732 check: cannot stat ${_ck} (unshare namespace?) — mode unverified"
      continue
    fi
    # Normalise: strip leading zeros that BSD stat omits (e.g. "640" vs "0640").
    _exp_mode="${_exp_mode#0}"
    _act_mode="${_act_mode#0}"
    if [[ "$_act_mode" != "$_exp_mode" ]]; then
      log_error "CWE-732: ${_ck} mode is ${_act_mode}, expected ${_exp_mode} (from pki_key_mode)"
      _cwe732_fail=1
    fi
  done

  # Sub-check B: world-readable bit on any *.key is always wrong.
  if find "${_secrets_dir}" -maxdepth 1 -type f -name '*.key' \
        -perm -004 2>/dev/null | grep -q .; then
    log_error "CWE-732: world-readable *.key file(s) under ${_secrets_dir} after restore chown"
    _cwe732_fail=1
  fi

  if [[ "$_cwe732_fail" == "1" ]]; then
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
    log_warn "  After bringing postgres up, exec into the postgres container/pod as the postgres user"
    log_warn "  (K8s: kubectl exec -n <ns> <pod> -- sh; Compose: docker/podman exec <container> sh)"
    log_warn "  then run:"
    log_warn "    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > \${PGDATA}/root.crt"
    log_warn "    chmod 0640 \${PGDATA}/root.crt"
    log_warn "    cp /run/secrets/postgres_client.crt \${PGDATA}/server.crt && chmod 0644 \${PGDATA}/server.crt"
    log_warn "    cp /run/secrets/postgres_client.key \${PGDATA}/server.key && chmod 0600 \${PGDATA}/server.key"
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
  # K8s privilege model: the postgres pod runs as runAsUser: 70 (postgres user on
  # Alpine). kubectl exec inherits that UID — it does NOT arrive as root.
  # Compose/Podman paths: exec -T postgres also runs as the postgres user because
  # the container drops to postgres after entrypoint init.
  #
  # Consequence: `install -o postgres` and `gosu postgres` are unavailable here —
  # both require root (install -o changes file ownership; gosu does setuid).
  # su -s /bin/sh postgres also requires root (setuid to another user).
  #
  # Correct approach: since we are already running as the postgres UID (70), use
  # cp + chmod to install files we own. pg_ctl is called directly without any
  # user-switch wrapper.
  if ! pg_exec "$pg_target" sh -c '
    set -e
    PGDATA="${PGDATA:-/var/lib/postgresql/data/pgdata}"
    : "${PGDATA:?PGDATA env var unset in postgres container}"
    # Trust bundle: root + intermediate concatenated (must match install.sh line that
    # does: cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > ${PGDATA}/root.crt)
    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > "${PGDATA}/root.crt"
    # chown to ourselves is a no-op on Linux; chmod is valid as owner regardless of root.
    # DO NOT use install -o / -g here: that requires root privilege. We are running as
    # the postgres UID (70) and can chmod files we own without root.
    chmod 0640 "${PGDATA}/root.crt"
    # cp preserves the source file; chmod to the required mode after copy.
    # install -m -o is intentionally avoided: it requires CAP_CHOWN / root.
    cp /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
    chmod 0644 "${PGDATA}/server.crt"
    cp /run/secrets/postgres_client.key "${PGDATA}/server.key"
    chmod 0600 "${PGDATA}/server.key"
    # pg_ctl requires the postgres UID — which we already are. Do NOT use gosu or
    # su: gosu is a setuid helper (unavailable to non-root), su requires CAP_SETUID.
    # Direct invocation is correct here for both K8s (runAsUser: 70) and Compose
    # (entrypoint drops to postgres before any exec command).
    pg_ctl -D "${PGDATA}" reload
  '; then
    log_error "PGDATA CA refresh failed. mTLS between pgbouncer and postgres may be broken."
    log_error "  Manual recovery: exec into postgres pod/container as the postgres user, then run:"
    log_error "    cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > \${PGDATA}/root.crt"
    log_error "    chmod 0640 \${PGDATA}/root.crt"
    log_error "    cp /run/secrets/postgres_client.crt \${PGDATA}/server.crt && chmod 0644 \${PGDATA}/server.crt"
    log_error "    cp /run/secrets/postgres_client.key \${PGDATA}/server.key && chmod 0600 \${PGDATA}/server.key"
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
    log_warn "    psql -U yashigani_admin -d postgres"
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
    --recovery-license)
      # Flow B (YSG-RISK-050): licensed tier wrap#2 — decrypt DEK using .ysg file bytes.
      # Usage: --recovery-license /path/to/license.ysg
      V2_RECOVERY_MODE="license"
      shift
      V2_RECOVERY_LICENSE="${1:?--recovery-license requires a path argument}"
      shift
      ;;
    --recovery-key)
      # Flow C (YSG-RISK-050): community tier wrap#2 — decrypt DEK using DB AES key.
      # Usage: --recovery-key <hex>
      #        --recovery-key env (reads from YASHIGANI_DB_AES_KEY env var)
      V2_RECOVERY_MODE="key"
      shift
      V2_RECOVERY_KEY="${1:?--recovery-key requires a hex argument or 'env'}"
      if [[ "$V2_RECOVERY_KEY" == "env" ]]; then
        V2_RECOVERY_KEY="${YASHIGANI_DB_AES_KEY:?YASHIGANI_DB_AES_KEY env var required with --recovery-key env}"
      fi
      shift
      ;;
    --encrypted)
      # --encrypted IDENTITY FILE  — identity key then archive path
      # --encrypted FILE           — identity from env/default, archive is $2
      ENCRYPTED_MODE=true
      shift
      # Check whether next arg looks like an age identity file (ends .age) or
      # is the archive itself (.tar.gz.age). Accept either order:
      #   --encrypted /etc/yashigani/backup-identity.age /path/to/backup.tar.gz.age
      #   --encrypted /path/to/backup.tar.gz.age         (identity from env/default)
      if [[ "${1:-}" == *.age && "${1:-}" != *.tar.gz.age ]]; then
        # First positional arg looks like an identity key
        IDENTITY_FILE="$1"
        shift
        RESTORE_TARGET="${1:-}"
        [[ -n "${RESTORE_TARGET}" ]] && shift
      else
        # No identity arg — use default/env; next arg is the archive
        RESTORE_TARGET="${1:-}"
        [[ -n "${RESTORE_TARGET}" ]] && shift
      fi
      ;;
    --validate)
      # Opt-in: after K8s restore completes, invoke scripts/k8s-restore-validate.sh.
      # Default is off so the restore completes quickly without requiring kubectl
      # port-forward access from the operator's terminal.
      RUN_VALIDATE=true
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Yashigani Restore Script

Usage:
  bash restore.sh                                       List available backups
  bash restore.sh <backup_dir>                          Restore from specific backup
  bash restore.sh --latest                              Restore most recent backup
  bash restore.sh --latest --k8s -n yashigani          Restore into Kubernetes
  bash restore.sh --latest --k8s --validate            Restore + run k8s-restore-validate.sh
  bash restore.sh --encrypted <identity.age> <file.tar.gz.age>  Decrypt + restore encrypted backup

  v2 dual-wrap encrypted backups (YSG-RISK-050/051, install.sh >= v2.25.0):
  bash restore.sh <backup_dir>                          Flow A: interactive admin password prompt
  bash restore.sh --recovery-license /path/to/f.ysg <backup_dir>  Flow B: licensed tier recovery
  bash restore.sh --recovery-key <hex> <backup_dir>    Flow C: community tier DB-key recovery
  bash restore.sh --recovery-key env <backup_dir>      Flow C: reads YASHIGANI_DB_AES_KEY env

Options:
  --k8s, --kubernetes      Restore into a Kubernetes cluster
  -n, --namespace NS       Kubernetes namespace (default: yashigani)
  --latest                 Use most recent backup
  --force                  Skip validation warnings
  --validate               (K8s only) Run k8s-restore-validate.sh after restore (default: off)
  --encrypted IDENTITY FILE  Decrypt FILE using age IDENTITY then restore (MP.L2-3.8.9)
                           IDENTITY defaults to YASHIGANI_BACKUP_IDENTITY_FILE or
                           /etc/yashigani/backup-identity.age when only FILE is given
  --recovery-license FILE  (v2 backup) Use .ysg license bytes for wrap#2 DEK unwrap (Flow B)
  --recovery-key HEX|env   (v2 backup) Use community DB AES key for wrap#2 DEK unwrap (Flow C)
  --help                   Show this help

Supported platforms:
  - Docker Compose (Linux/macOS)
  - Podman Compose (Linux/macOS rootless)
  - Kubernetes (via kubectl)

Encrypted backups (age):
  Produced by scripts/backup.sh. Decrypt + restore in one step:
    bash restore.sh --encrypted /etc/yashigani/backup-identity.age \
      /var/lib/yashigani/backups/20260509_120000.tar.gz.age

  Or set YASHIGANI_BACKUP_IDENTITY_FILE and pass the archive path directly:
    YASHIGANI_BACKUP_IDENTITY_FILE=/etc/yashigani/backup-identity.age \
      bash restore.sh /var/lib/yashigani/backups/20260509_120000.tar.gz.age

  Legacy unencrypted backups (.tar.gz or directory) are still accepted with a warning.
EOF
      exit 0
      ;;
    *)
      RESTORE_TARGET="$1"
      shift
      ;;
  esac
done

# ---------------------------------------------------------------------------
# decrypt_and_restore — MP.L2-3.8.9
#
# Decrypts a .tar.gz.age file produced by scripts/backup.sh using the
# operator's age identity key, extracts the tarball to a temporary directory,
# then delegates to restore_backup() for the standard secrets/env/DB restore
# flow.  Works on Docker, Podman, and K8s (same runtime detection as the
# directory-based path).
#
# Temporary extraction is placed under BACKUPS_DIR (same filesystem as the
# archive for efficient rename) and is cleaned up on exit regardless of
# success/failure.
# ---------------------------------------------------------------------------
decrypt_and_restore() {
  local archive_file="$1"

  # Validate age binary
  if ! command -v age >/dev/null 2>&1; then
    log_error "age binary not found — cannot decrypt backup."
    log_error "  On Debian/Ubuntu: apt-get install -y age"
    log_error "  On Alpine:        apk add age"
    log_error "  From upstream:    https://age-encryption.org/"
    exit 1
  fi

  # Validate identity file
  if [[ ! -f "${IDENTITY_FILE}" ]]; then
    log_error "age identity (private key) file not found: ${IDENTITY_FILE}"
    log_error "  Set YASHIGANI_BACKUP_IDENTITY_FILE or pass: --encrypted <identity.age> <archive.tar.gz.age>"
    log_error "  See docs/operations/backup.md — 'Encryption' section."
    exit 1
  fi
  # Identity file must not be world/group-readable (CWE-732)
  local _id_perm
  _id_perm=$(stat -c '%a' "${IDENTITY_FILE}" 2>/dev/null || stat -f '%OLp' "${IDENTITY_FILE}" 2>/dev/null || echo "")
  if [[ -n "${_id_perm}" && "${_id_perm}" != "400" && "${_id_perm}" != "600" ]]; then
    log_warn "Identity file permissions are ${_id_perm} — should be 400 or 600 (CWE-732)."
    log_warn "  Fix: chmod 0400 ${IDENTITY_FILE}"
  fi

  if [[ ! -f "${archive_file}" ]]; then
    log_error "Encrypted archive not found: ${archive_file}"
    exit 1
  fi

  if [[ "${archive_file}" != *.tar.gz.age ]]; then
    log_warn "Archive does not have .tar.gz.age extension: ${archive_file}"
    log_warn "  Attempting decryption anyway — file may still be age-encrypted."
  fi

  log_info "Decrypting: ${archive_file}"
  log_info "  Identity:  ${IDENTITY_FILE}"

  # Create temp extraction directory under BACKUPS_DIR (same filesystem).
  # umask 077 at script top ensures it is created 0700.
  # NOTE: _DECRYPT_EXTRACT_DIR is intentionally NOT declared local — bash EXIT
  # traps run in the main shell scope, not the function scope, so local variables
  # from decrypt_and_restore() are inaccessible there. Using a script-global
  # variable ensures the cleanup trap can always expand the path even if
  # restore_backup() exits non-zero (triggering set -e and bypassing the
  # explicit trap - INT TERM EXIT at the end of this function).
  local _ts
  _ts="$(date -u +%Y%m%d_%H%M%S)"
  _DECRYPT_EXTRACT_DIR="${BACKUPS_DIR}/.age-extract-${_ts}-$$"
  mkdir -p "${_DECRYPT_EXTRACT_DIR}"
  # local alias for readability within this function
  local _extract_dir="${_DECRYPT_EXTRACT_DIR}"

  # Register cleanup on any exit
  trap 'rm -rf "${_DECRYPT_EXTRACT_DIR}" 2>/dev/null; exit 1' INT TERM
  trap 'rm -rf "${_DECRYPT_EXTRACT_DIR}" 2>/dev/null' EXIT

  log_info "Decrypting and extracting archive..."
  if ! age --decrypt --identity "${IDENTITY_FILE}" "${archive_file}" \
         | tar --extract --gzip --directory "${_extract_dir}" 2>/dev/null; then
    log_error "Decryption or extraction failed."
    log_error "  Verify the identity key matches the recipient key used during backup."
    log_error "  Verify the archive is not truncated: ls -lh ${archive_file}"
    rm -rf "${_extract_dir}" 2>/dev/null || true
    trap - INT TERM EXIT
    exit 1
  fi

  log_success "Archive decrypted and extracted to ${_extract_dir}"

  # Locate the actual backup directory inside the extraction root.
  # backup.sh archives SOURCE_DIR (e.g. /var/lib/yashigani), so extracted
  # root contains a single subdirectory named after the source base.
  # We also support the legacy pattern where the tarball root IS the backup dir
  # (i.e. contains secrets/ and .env directly).
  local _backup_dir=""
  if [[ -d "${_extract_dir}/secrets" || -f "${_extract_dir}/.env" ]]; then
    # Tarball root is the backup dir
    _backup_dir="${_extract_dir}"
  else
    # Look for the first subdirectory
    local _sub
    _sub=$(find "${_extract_dir}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)
    if [[ -n "${_sub}" ]]; then
      _backup_dir="${_sub}"
    fi
  fi

  if [[ -z "${_backup_dir}" || ( ! -d "${_backup_dir}/secrets" && ! -f "${_backup_dir}/.env" ) ]]; then
    log_error "Could not locate backup data (secrets/ or .env) inside extracted archive."
    log_error "  Extraction root: ${_extract_dir}"
    rm -rf "${_extract_dir}" 2>/dev/null || true
    trap - INT TERM EXIT
    exit 1
  fi

  log_info "Backup data located at: ${_backup_dir}"

  # Delegate to standard restore_backup() flow
  restore_backup "${_backup_dir}"

  # Cleanup extraction temp
  rm -rf "${_extract_dir}" 2>/dev/null || true
  trap - INT TERM EXIT
}

detect_runtime

# ---------------------------------------------------------------------------
# Handle encrypted archive (.tar.gz.age) when passed as RESTORE_TARGET
# without --encrypted flag but with YASHIGANI_BACKUP_IDENTITY_FILE set.
# Also handle legacy unencrypted .tar.gz tarballs with a warning.
# ---------------------------------------------------------------------------
if [[ "${ENCRYPTED_MODE}" == "false" && "${RESTORE_TARGET}" == *.tar.gz.age ]]; then
  log_warn "Archive appears to be age-encrypted (.tar.gz.age). Enabling encrypted restore path."
  log_warn "  Using identity: ${IDENTITY_FILE}"
  ENCRYPTED_MODE=true
fi
if [[ "${ENCRYPTED_MODE}" == "false" && "${RESTORE_TARGET}" == *.tar.gz ]]; then
  log_warn "LEGACY: Unencrypted .tar.gz backup detected. Backups created by scripts/backup.sh"
  log_warn "  (v2.23.3+) are encrypted with age (MP.L2-3.8.9). This backup predates encryption."
  log_warn "  Extracting for restore — recommend re-creating this backup with encryption."
  if ! command -v tar >/dev/null 2>&1; then
    log_error "tar not found — cannot extract legacy backup"
    exit 1
  fi
  _ts_legacy="$(date -u +%Y%m%d_%H%M%S)"
  _extract_legacy="${BACKUPS_DIR}/.legacy-extract-${_ts_legacy}-$$"
  mkdir -p "${_extract_legacy}"
  # shellcheck disable=SC2064
  trap 'rm -rf "${_extract_legacy}" 2>/dev/null; exit 1' INT TERM
  if ! tar --extract --gzip --directory "${_extract_legacy}" --file "${RESTORE_TARGET}" 2>/dev/null; then
    log_error "tar extraction failed for legacy archive: ${RESTORE_TARGET}"
    rm -rf "${_extract_legacy}" 2>/dev/null || true
    trap - INT TERM
    exit 1
  fi
  _legacy_dir=$(find "${_extract_legacy}" -mindepth 0 -maxdepth 1 \( -name "secrets" -o -name ".env" \) 2>/dev/null | head -1 | xargs -I{} dirname {} 2>/dev/null || echo "${_extract_legacy}")
  restore_backup "${_legacy_dir:-${_extract_legacy}}"
  rm -rf "${_extract_legacy}" 2>/dev/null || true
  trap - INT TERM
  exit 0
fi

case "${RESTORE_TARGET}" in
  "")
    if [[ "${ENCRYPTED_MODE}" == "true" ]]; then
      log_error "--encrypted specified but no archive path given."
      log_error "  Usage: bash restore.sh --encrypted [identity.age] <archive.tar.gz.age>"
      exit 1
    fi
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
    if [[ "${ENCRYPTED_MODE}" == "true" ]]; then
      decrypt_and_restore "${RESTORE_TARGET}"
    elif [[ -d "$RESTORE_TARGET" ]]; then
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

# ---------------------------------------------------------------------------
# Optional post-restore K8s validation (opt-in via --validate)
# ---------------------------------------------------------------------------
if [[ "$RUN_VALIDATE" == "true" ]]; then
  if [[ "$K8S_MODE" != "true" ]]; then
    log_warn "--validate is only meaningful with --k8s. Skipping."
  else
    VALIDATE_SCRIPT="${WORK_DIR}/scripts/k8s-restore-validate.sh"
    if [[ ! -x "$VALIDATE_SCRIPT" ]]; then
      log_warn "--validate specified but ${VALIDATE_SCRIPT} not found or not executable. Skipping."
    else
      log_info "Running K8s restore validation (scripts/k8s-restore-validate.sh)..."
      KUBECTL_NAMESPACE="${K8S_NAMESPACE}" bash "${VALIDATE_SCRIPT}" || {
        log_error "K8s restore validation reported failures — see output above."
        exit 1
      }
    fi
  fi
fi
