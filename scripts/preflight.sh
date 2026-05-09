#!/usr/bin/env bash
# scripts/preflight.sh — Yashigani v0.9.2
# last-updated: 2026-05-09T00:00:00+01:00 (feat: air-gap mode — G20 air-gap gate #58)
# Pre-install requirement checks. Exits 1 if any REQUIRED check fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
SKIP_DNS=0
SKIP_PORTS=0

for arg in "$@"; do
  case "$arg" in
    --skip-dns)   SKIP_DNS=1   ;;
    --skip-ports) SKIP_PORTS=1 ;;
    --help)
      cat <<'EOF'
Usage: scripts/preflight.sh [OPTIONS]

Pre-install requirement checks for Yashigani.

Options:
  --skip-dns    Skip DNS resolution check for YASHIGANI_TLS_DOMAIN
  --skip-ports  Skip port 80/443 availability checks
  --help        Print this help message

Environment variables read:
  TLS_MODE              If "acme", DNS check is performed unless --skip-dns
  YASHIGANI_TLS_DOMAIN  Domain to verify DNS for (required when TLS_MODE=acme)

Exit codes:
  0  All REQUIRED checks passed
  1  One or more REQUIRED checks failed
EOF
      exit 0
      ;;
    *) ;;
  esac
done

# ---------------------------------------------------------------------------
# Source platform detection
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
REQUIRED_FAILURES=0
declare -a RESULT_LINES=()

_pass() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("PASS|${label}|${detail}")
}

_fail() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("FAIL|${label}|${detail}")
  REQUIRED_FAILURES=$(( REQUIRED_FAILURES + 1 ))
}

_warn_check() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("WARN|${label}|${detail}")
}

# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

# 1. Shell version — checks the USER's login shell, not the script executor
_check_shell_version() {
  # Detect the user's actual login shell
  local user_shell="${SHELL:-/bin/sh}"
  local user_shell_name
  user_shell_name="$(basename "$user_shell")"

  # Get the version of the user's login shell
  local shell_ver=""
  case "$user_shell_name" in
    zsh)
      shell_ver="$("$user_shell" --version 2>/dev/null | awk '{print $2}' || echo "")"
      if [ -n "$shell_ver" ]; then
        local major="${shell_ver%%.*}"
        if [ "$major" -ge 5 ]; then
          _pass "User shell" "zsh ${shell_ver} (${user_shell})"
        else
          _warn_check "User shell" "zsh ${shell_ver} — 5.0+ recommended"
        fi
      else
        _pass "User shell" "zsh (${user_shell})"
      fi
      ;;
    bash)
      shell_ver="$("$user_shell" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")"
      if [ -n "$shell_ver" ]; then
        local major="${shell_ver%%.*}"
        if [ "$major" -ge 4 ]; then
          _pass "User shell" "bash ${shell_ver} (${user_shell})"
        elif [ "$YSG_OS" = "macos" ]; then
          _warn_check "User shell" "bash ${shell_ver} (macOS default — consider: brew install bash)"
        else
          _fail "User shell" "bash ${shell_ver} — need >= 4"
        fi
      else
        _pass "User shell" "bash (${user_shell})"
      fi
      ;;
    *)
      _warn_check "User shell" "${user_shell_name} (${user_shell}) — bash or zsh recommended"
      ;;
  esac

  # Also note what's running this script (informational only, not a pass/fail)
  if [ -n "${BASH_VERSION:-}" ]; then
    local script_major="${BASH_VERSION%%.*}"
    if [ "$script_major" -lt 4 ] && [ "$YSG_OS" = "macos" ]; then
      # macOS /bin/bash is 3.2 — that's fine, the installer handles it
      true
    fi
  fi
}

# 2. curl
_check_curl() {
  if command -v curl >/dev/null 2>&1; then
    _pass "curl" "$(curl --version 2>/dev/null | head -1)"
  else
    _fail "curl" "not found — install curl"
  fi
}

# 3. Container runtime (Docker or Podman)
_check_docker_daemon() {
  case "${YSG_RUNTIME:-none}" in
    docker)
      if docker info >/dev/null 2>&1; then
        _pass "Container runtime" "Docker — running"
      elif [ "$YSG_OS" = "macos" ] && [ -d "/Applications/Docker.app" ]; then
        _warn_check "Container runtime" "Docker Desktop installed but daemon not responding — open Docker Desktop"
      else
        _fail "Container runtime" "Docker found but daemon not reachable — is Docker running?"
      fi
      ;;
    docker_desktop_no_cli)
      _warn_check "Container runtime" "Docker Desktop installed but CLI not in PATH"
      printf "\n"
      printf "      ${YSG_YELLOW}The 'docker' command is not in your PATH but Docker Desktop is installed.${YSG_RESET}\n"
      printf "      ${YSG_YELLOW}We can fix this by creating a symlink (requires sudo).${YSG_RESET}\n"
      printf "\n"
      printf "      Run this command:\n"
      printf "        ${YSG_GREEN}sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker${YSG_RESET}\n"
      printf "\n"
      # Offer to run it automatically if interactive
      if [ -t 0 ]; then
        printf "      Would you like to run this now? [Y/n]: "
        local fix_answer
        read -r fix_answer
        fix_answer="$(echo "${fix_answer:-y}" | tr '[:upper:]' '[:lower:]')"
        if [ "$fix_answer" = "y" ] || [ "$fix_answer" = "yes" ] || [ -z "$fix_answer" ]; then
          if sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker 2>/dev/null; then
            printf "      ${YSG_GREEN}Done! Docker CLI is now available.${YSG_RESET}\n\n"
            # Re-check — update runtime detection
            if docker info >/dev/null 2>&1; then
              YSG_RUNTIME="docker"
              export YSG_RUNTIME
              # Replace the warning with a pass
              REQUIRED_FAILURES=$((REQUIRED_FAILURES > 0 ? REQUIRED_FAILURES - 1 : 0))
              RESULT_LINES=("${RESULT_LINES[@]/${RESULT_LINES[-1]}/}")
              _pass "Container runtime" "Docker — running (CLI symlink created)"
            else
              printf "      ${YSG_YELLOW}Symlink created but Docker daemon not responding — open Docker Desktop first.${YSG_RESET}\n\n"
            fi
          else
            printf "      ${YSG_RED}Could not create symlink. Run manually:${YSG_RESET}\n"
            printf "        sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker\n\n"
          fi
        else
          printf "\n      You can also enable it via: Docker Desktop → Settings → General → \"Install Docker CLI\"\n\n"
        fi
      fi
      ;;
    podman)
      if podman info >/dev/null 2>&1; then
        _pass "Container runtime" "Podman — running"
      elif command -v podman >/dev/null 2>&1; then
        _warn_check "Container runtime" "Podman found but not running — try: podman machine start"
      else
        _fail "Container runtime" "Podman not reachable"
      fi
      ;;
    none)
      if [ "$YSG_OS" = "macos" ]; then
        _fail "Container runtime" "no runtime found — install Docker Desktop from docker.com/products/docker-desktop"
      else
        _fail "Container runtime" "no container runtime found — install Docker or Podman"
      fi
      ;;
  esac
}

# 4. Compose
_check_compose() {
  case "${YSG_RUNTIME:-docker}" in
    podman)
      if command -v podman-compose >/dev/null 2>&1; then
        local ver
        ver="$(podman-compose version 2>/dev/null | head -1 || echo "unknown")"
        _pass "Compose" "podman-compose ${ver}"
      elif command -v docker-compose >/dev/null 2>&1; then
        local ver
        ver="$(docker-compose version --short 2>/dev/null || echo "unknown")"
        _pass "Compose" "docker-compose (standalone) v${ver}"
      else
        _warn_check "Compose" "podman-compose not found — install: pip install podman-compose"
      fi
      ;;
    *)
      case "$YSG_COMPOSE" in
        plugin)
          local ver
          ver="$(docker compose version --short 2>/dev/null || echo "unknown")"
          _pass "Compose" "Docker Compose plugin v${ver}"
          ;;
        standalone)
          local ver
          ver="$(docker-compose version --short 2>/dev/null || echo "unknown")"
          _pass "Compose" "docker-compose (standalone) v${ver}"
          ;;
        none)
          _fail "Compose" "not found — install docker-compose-plugin"
          ;;
      esac
      ;;
  esac
}

# 5. Ports 80 and 443
_check_port() {
  local port="$1"
  local in_use=0

  # Try ss first (most Linux)
  if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      in_use=1
    fi
  # Fall back to netstat
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
      in_use=1
    fi
  # Fall back to lsof
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      in_use=1
    fi
  fi

  if [ "$in_use" -eq 0 ]; then
    _pass "Port ${port}" "free"
  else
    _fail "Port ${port}" "IN USE — stop the process using port ${port} first"
  fi
}

_check_ports() {
  local http_port="${YASHIGANI_HTTP_PORT:-80}"
  local https_port="${YASHIGANI_HTTPS_PORT:-443}"
  if [ "$SKIP_PORTS" -eq 1 ]; then
    _pass "Port ${http_port}"  "skipped (--skip-ports)"
    _pass "Port ${https_port}" "skipped (--skip-ports)"
    return
  fi
  _check_port "$http_port"
  _check_port "$https_port"
}

# 6. Disk space
_check_disk() {
  local mount_point="/"

  # Try to find the container storage mount point — fall back to / if unavailable
  case "${YSG_RUNTIME:-docker}" in
    docker|docker_desktop_no_cli)
      local docker_root=""
      docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
      if [ -n "$docker_root" ] && [ -d "$docker_root" ]; then
        mount_point="$docker_root"
      fi
      ;;
    podman)
      local podman_root="${HOME}/.local/share/containers"
      [ -d "$podman_root" ] && mount_point="$podman_root"
      ;;
  esac

  local avail_gb=0
  if [ "$YSG_OS" = "macos" ]; then
    avail_gb="$(df -g "$mount_point" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")"
  else
    avail_gb="$(df -BG "$mount_point" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || echo "0")"
  fi
  avail_gb="${avail_gb:-0}"

  if [ "$avail_gb" -ge 10 ]; then
    _pass "Disk space" "${avail_gb} GB available on ${mount_point}"
  else
    _fail "Disk space" "${avail_gb} GB available — need >= 10 GB on ${mount_point}"
  fi
}

# 7+8. RAM checks
_check_ram() {
  local ram_mb=0

  if [ "$YSG_OS" = "linux" ] && [ -r /proc/meminfo ]; then
    ram_mb="$(awk '/^MemTotal:/ { printf "%d", $2/1024 }' /proc/meminfo)"
  elif [ "$YSG_OS" = "macos" ]; then
    local ram_bytes
    ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    ram_mb=$(( ram_bytes / 1024 / 1024 ))
  fi

  local ram_gb_display
  ram_gb_display="$(awk "BEGIN { printf \"%.1f\", ${ram_mb}/1024 }") GB"

  if [ "$ram_mb" -lt 512 ]; then
    _fail "RAM" "${ram_gb_display} — 512 MB absolute minimum not met"
  elif [ "$ram_mb" -lt 2048 ]; then
    _warn_check "RAM" "${ram_gb_display} (2 GB recommended)"
  else
    _pass "RAM" "${ram_gb_display}"
  fi

  if [ "$ram_mb" -lt 4096 ]; then
    _warn_check "RAM (Ollama)" "${ram_gb_display} (4 GB recommended for LLM inference)"
  else
    _pass "RAM (Ollama)" "${ram_gb_display} — sufficient for LLM inference"
  fi
}

# 9. Secrets mechanism
_check_secrets() {
  case "${YSG_RUNTIME:-docker}" in
    podman)
      # Podman uses podman secret or environment-based secrets — no /run/secrets needed
      if command -v podman >/dev/null 2>&1; then
        _pass "Secrets" "Podman secrets mechanism available"
      else
        _warn_check "Secrets" "Podman not found — secrets will use environment variables"
      fi
      ;;
    docker|docker_desktop_no_cli)
      if [ -d /run/secrets ] && [ -w /run/secrets ]; then
        _pass "Secrets" "/run/secrets writable"
      elif docker info >/dev/null 2>&1; then
        _pass "Secrets" "Docker secrets mechanism available"
      elif [ "$YSG_OS" = "macos" ]; then
        _pass "Secrets" "Docker Desktop manages secrets internally"
      else
        _fail "Secrets" "/run/secrets not writable and Docker not reachable"
      fi
      ;;
    *)
      _warn_check "Secrets" "unknown runtime — secrets will use environment variables"
      ;;
  esac
}

# G19. Backup encryption — age binary + recipient key (MP.L2-3.8.9 / CMMC L2)
# Warn (not fail) if age is absent: operators may not yet have provisioned keys.
# Hard-fail if the recipient file exists but is unreadable or malformed.
_check_backup_encryption() {
  local recipient_file="${YASHIGANI_BACKUP_RECIPIENT:-/etc/yashigani/backup-recipient.age.pub}"

  # age binary
  if ! command -v age >/dev/null 2>&1; then
    _warn_check "Backup encryption (G19)" "age binary not found — install age before enabling backups (MP.L2-3.8.9)"
  else
    local _age_ver
    _age_ver="$(age --version 2>/dev/null || echo "unknown")"
    _pass "Backup encryption (G19)" "age present (${_age_ver})"
  fi

  # Recipient public key file — hard-fail if it exists but is wrong
  if [[ -f "${recipient_file}" ]]; then
    local _key
    _key="$(head -1 "${recipient_file}" 2>/dev/null | tr -d '[:space:]')"
    if [[ -z "${_key}" ]]; then
      _fail "Backup recipient key (G19)" "${recipient_file} is empty — backup.sh will refuse to run"
    elif [[ "${_key}" != age1* ]]; then
      _fail "Backup recipient key (G19)" "${recipient_file} does not contain a valid age public key (must start with 'age1')"
    else
      _pass "Backup recipient key (G19)" "${recipient_file} — ${_key:0:16}..."
    fi
  else
    _warn_check "Backup recipient key (G19)" "${recipient_file} not found — provision before running backup.sh (see docs/operations/backup.md)"
  fi
}

# 10. DNS check (conditional on TLS_MODE=acme)
_check_dns() {
  local tls_mode="${TLS_MODE:-}"
  local domain="${YASHIGANI_TLS_DOMAIN:-}"

  if [ "$SKIP_DNS" -eq 1 ]; then
    _pass "DNS" "skipped (--skip-dns)"
    return
  fi

  if [ "$tls_mode" != "acme" ]; then
    _pass "DNS" "skipped (TLS_MODE is not 'acme')"
    return
  fi

  if [ -z "$domain" ]; then
    _fail "DNS" "TLS_MODE=acme but YASHIGANI_TLS_DOMAIN is not set"
    return
  fi

  local resolved=0
  if command -v dig >/dev/null 2>&1; then
    dig +short "$domain" 2>/dev/null | grep -qE '^[0-9]+\.' && resolved=1
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$domain" >/dev/null 2>&1 && resolved=1
  elif command -v host >/dev/null 2>&1; then
    host "$domain" >/dev/null 2>&1 && resolved=1
  else
    _warn_check "DNS" "no dig/nslookup/host available — cannot verify ${domain}"
    return
  fi

  if [ "$resolved" -eq 1 ]; then
    _pass "DNS" "${domain} resolves"
  else
    _fail "DNS" "${domain} does not resolve — check your DNS records"
  fi
}

# 10+. GPU check
_check_gpu() {
  case "${YSG_GPU_TYPE:-none}" in
    apple_metal)
      local vram_gb
      vram_gb="$(awk "BEGIN { printf \"%.0f\", ${YSG_GPU_VRAM_MB:-0}/1024 }")"
      _pass "GPU" "${YSG_GPU_NAME:-Apple Silicon} — ${vram_gb} GB unified memory (Metal)"
      if [ "${YSG_GPU_VRAM_MB:-0}" -lt 8192 ]; then
        _warn_check "GPU memory" "${vram_gb} GB — 8 GB+ recommended for local LLM inference"
      fi
      ;;
    nvidia)
      local vram_gb
      vram_gb="$(awk "BEGIN { printf \"%.0f\", ${YSG_GPU_VRAM_MB:-0}/1024 }")"
      _pass "GPU" "${YSG_GPU_NAME:-NVIDIA GPU} — ${vram_gb} GB VRAM (CUDA)"
      if [ "${YSG_GPU_VRAM_MB:-0}" -lt 8192 ]; then
        _warn_check "GPU VRAM" "${vram_gb} GB — 8 GB+ recommended for local LLM inference"
      fi
      ;;
    amd_rocm)
      local vram_gb
      vram_gb="$(awk "BEGIN { printf \"%.0f\", ${YSG_GPU_VRAM_MB:-0}/1024 }")"
      _pass "GPU" "${YSG_GPU_NAME:-AMD GPU} — ${vram_gb} GB VRAM (ROCm)"
      ;;
    nvidia_no_driver)
      _warn_check "GPU" "${YSG_GPU_NAME:-NVIDIA GPU detected} — drivers not installed"
      ;;
    amd_no_driver)
      _warn_check "GPU" "${YSG_GPU_NAME:-AMD GPU detected} — ROCm not installed"
      ;;
    none)
      _warn_check "GPU" "no GPU detected — Ollama will use CPU inference (slower)"
      ;;
  esac
}

# G20. Air-gap mode gate — verify bundle + manifest present + digests parseable
# Only runs when AIR_GAP=true is set in the environment (set by install.sh).
# Hard-fails if --air-gap is set but bundle/manifest is missing or corrupt.
_check_airgap() {
  local air_gap="${AIR_GAP:-false}"
  local bundle_path="${AIR_GAP_BUNDLE:-}"

  if [[ "$air_gap" != "true" ]]; then
    # Not in air-gap mode — skip gate
    return
  fi

  # G20a: bundle file must exist
  if [[ -z "$bundle_path" ]]; then
    _fail "Air-gap (G20a)" "--air-gap set but AIR_GAP_BUNDLE not specified — pass --bundle <path>"
  elif [[ ! -f "$bundle_path" ]]; then
    _fail "Air-gap (G20a)" "Bundle not found: ${bundle_path}"
  else
    local bundle_size_mb
    bundle_size_mb="$(du -sm "${bundle_path}" 2>/dev/null | awk '{print $1}' || echo "?")"
    _pass "Air-gap (G20a)" "Bundle present: $(basename "${bundle_path}") (${bundle_size_mb} MB)"
  fi

  # G20b: airgap/manifest.yml must exist beside install.sh or in WORK_DIR
  local manifest_file=""
  local _script_dir
  _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo ".")"
  local _repo_root
  _repo_root="$(cd "${_script_dir}/.." && pwd 2>/dev/null || echo ".")"

  for _d in "${_repo_root}" "$(pwd)" "${WORK_DIR:-}"; do
    [[ -z "$_d" ]] && continue
    if [[ -f "${_d}/airgap/manifest.yml" ]]; then
      manifest_file="${_d}/airgap/manifest.yml"
      break
    fi
  done

  if [[ -z "$manifest_file" ]]; then
    _fail "Air-gap (G20b)" "airgap/manifest.yml not found — transfer it alongside install.sh"
  else
    _pass "Air-gap (G20b)" "Manifest present: ${manifest_file}"
  fi

  # G20c: manifest must be parseable and contain a version field
  if [[ -n "$manifest_file" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
      _warn_check "Air-gap (G20c)" "python3 not found — manifest parse check skipped"
    else
      local manifest_version
      manifest_version="$(python3 -c "
import re, sys
with open('${manifest_file}') as f:
    for line in f:
        m = re.match(r'^version: \"?([^\"]+)\"?', line)
        if m:
            print(m.group(1)); sys.exit(0)
sys.exit(1)
" 2>/dev/null || echo "")"
      if [[ -z "$manifest_version" ]]; then
        _fail "Air-gap (G20c)" "Manifest parse failed — version field not found in ${manifest_file}"
      else
        _pass "Air-gap (G20c)" "Manifest version: ${manifest_version}"
      fi
    fi
  fi

  # G20d: zstd required to unpack the bundle
  if ! command -v zstd >/dev/null 2>&1; then
    _fail "Air-gap (G20d)" "zstd not installed — required to unpack the air-gap bundle (apt install zstd)"
  else
    _pass "Air-gap (G20d)" "zstd present ($(zstd --version 2>/dev/null | head -1 || echo 'unknown'))"
  fi

  # G20e: sidecar manifest sidecar (warn if absent — not hard-fail)
  local sidecar_path="${bundle_path%.tar.zst}.manifest"
  if [[ -n "$bundle_path" ]]; then
    if [[ -f "$sidecar_path" ]]; then
      _pass "Air-gap (G20e)" "Sidecar manifest present: $(basename "${sidecar_path}")"
    else
      _warn_check "Air-gap (G20e)" "Sidecar .manifest not found — SHA256 integrity check will be skipped during load"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
_check_shell_version
_check_curl
_check_docker_daemon
_check_compose
_check_ports
_check_disk
_check_ram
_check_gpu
_check_secrets
_check_backup_encryption
_check_airgap
_check_dns

# ---------------------------------------------------------------------------
# Print summary table
# ---------------------------------------------------------------------------
printf "\n"
printf "%-4s %-26s %s\n" "   " "Check" "Result"
printf "%s\n" "------------------------------------------------------------"

for line in "${RESULT_LINES[@]}"; do
  IFS='|' read -r status label detail <<< "$line"
  case "$status" in
    PASS)
      icon="${YSG_GREEN}✓${YSG_RESET}"
      color="$YSG_RESET"
      ;;
    FAIL)
      icon="${YSG_RED}✗${YSG_RESET}"
      color="$YSG_RED"
      ;;
    WARN)
      icon="${YSG_YELLOW}⚠${YSG_RESET}"
      color="$YSG_YELLOW"
      ;;
    *)
      icon=" "
      color="$YSG_RESET"
      ;;
  esac
  printf " %b %-26s %b%s%b\n" "$icon" "$label" "$color" "$detail" "$YSG_RESET"
done

printf "\n"

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
if [ "$REQUIRED_FAILURES" -gt 0 ]; then
  printf "${YSG_RED}Preflight failed: %d required check(s) did not pass.${YSG_RESET}\n" \
    "$REQUIRED_FAILURES" >&2
  exit 1
fi

printf "${YSG_GREEN}All required checks passed.${YSG_RESET}\n"
exit 0
