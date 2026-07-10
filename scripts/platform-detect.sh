#!/usr/bin/env bash
# scripts/platform-detect.sh — Yashigani v2.1.0
# Full platform detection. Source this script; exports YSG_* environment variables.
# Last updated: 2026-04-23T00:00:00+00:00

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers (only when stdout is a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  YSG_RED='\033[0;31m'
  YSG_GREEN='\033[0;32m'
  YSG_YELLOW='\033[1;33m'
  YSG_BLUE='\033[0;34m'
  YSG_RESET='\033[0m'
else
  YSG_RED=''
  YSG_GREEN=''
  YSG_YELLOW=''
  YSG_BLUE=''
  YSG_RESET=''
fi
export YSG_RED YSG_GREEN YSG_YELLOW YSG_BLUE YSG_RESET

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage: source scripts/platform-detect.sh [--help]

Detects the current platform and exports the following variables:

  YSG_OS       — "linux" | "macos"
  YSG_DISTRO   — "ubuntu" | "debian" | "rhel" | "fedora" | "amzn" | "alpine" | "arch" | "macos"
  YSG_ARCH     — "amd64" | "arm64"
  YSG_CLOUD    — "aws" | "gcp" | "azure" | "digitalocean" | "hetzner" | "none"
  YSG_VM       — "kvm" | "vmware" | "virtualbox" | "hyperv" | "none"
  YSG_RUNTIME  — "docker" | "podman" | "none"
  YSG_COMPOSE  — "plugin" | "standalone" | "none"
  YSG_K8S      — "true" | "false"

Set YSG_DETECT_VERBOSE=1 before sourcing to print detected values.
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
_detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "linux" ;;
  esac
}

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
_detect_distro() {
  local os="$1"
  if [ "$os" = "macos" ]; then
    echo "macos"
    return
  fi
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    local id
    id="$(. /etc/os-release && echo "${ID:-unknown}")"
    case "$id" in
      ubuntu)  echo "ubuntu"  ;;
      debian)  echo "debian"  ;;
      rhel|centos|rocky|almalinux) echo "rhel" ;;
      fedora)  echo "fedora"  ;;
      amzn)    echo "amzn"    ;;
      alpine)  echo "alpine"  ;;
      arch)    echo "arch"    ;;
      *)       echo "$id"     ;;
    esac
    return
  fi
  if [ -f /etc/debian_version ]; then echo "debian"; return; fi
  if [ -f /etc/redhat-release ]; then echo "rhel";   return; fi
  if [ -f /etc/alpine-release ]; then echo "alpine"; return; fi
  echo "unknown"
}

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------
_detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64"  ;;
    aarch64|arm64) echo "arm64"  ;;
    *)             echo "amd64"  ;;
  esac
}

# ---------------------------------------------------------------------------
# Cloud detection (curl with 1s timeout, no auth required)
# ---------------------------------------------------------------------------
_curl_probe() {
  # $1 = url, remaining args passed to curl
  curl --silent --max-time 1 --connect-timeout 1 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || echo "000"
}

_detect_cloud() {
  local code

  # AWS — try IMDSv2 token first, fall back to plain IMDSv1 probe
  local aws_token
  aws_token="$(curl --silent --max-time 1 --connect-timeout 1 \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 10" 2>/dev/null || true)"
  if [ -n "$aws_token" ]; then
    code="$(_curl_probe "http://169.254.169.254/latest/meta-data/" \
      -H "X-aws-ec2-metadata-token: ${aws_token}")"
    [ "$code" = "200" ] && echo "aws" && return
  fi
  code="$(_curl_probe "http://169.254.169.254/latest/meta-data/")"
  [ "$code" = "200" ] && echo "aws" && return

  # GCP
  code="$(_curl_probe "http://metadata.google.internal/computeMetadata/v1/" \
    -H "Metadata-Flavor: Google")"
  [ "$code" = "200" ] && echo "gcp" && return

  # Azure
  code="$(_curl_probe \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
    -H "Metadata: true")"
  [ "$code" = "200" ] && echo "azure" && return

  # DigitalOcean
  code="$(_curl_probe "http://169.254.169.254/metadata/v1/id")"
  [ "$code" = "200" ] && echo "digitalocean" && return

  # Hetzner — check response headers for "server: hetzner"
  local hetzner_header
  hetzner_header="$(curl --silent --max-time 1 --connect-timeout 1 \
    -D - -o /dev/null "http://169.254.169.254/" 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | grep -i '^server:' || true)"
  if echo "$hetzner_header" | grep -qi 'hetzner'; then
    echo "hetzner" && return
  fi

  echo "none"
}

# ---------------------------------------------------------------------------
# VM detection
# ---------------------------------------------------------------------------
_detect_vm() {
  # Try systemd-detect-virt first
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    local virt
    virt="$(systemd-detect-virt 2>/dev/null || echo "none")"
    case "$virt" in
      kvm|qemu)     echo "kvm"        && return ;;
      vmware)       echo "vmware"     && return ;;
      oracle)       echo "virtualbox" && return ;;
      microsoft)    echo "hyperv"     && return ;;
      none)         echo "none"       && return ;;
      *)            ;;
    esac
  fi

  # Fall back to DMI strings
  local dmi_product=""
  for f in /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor \
            /sys/class/dmi/id/board_vendor; do
    [ -r "$f" ] && dmi_product="$dmi_product $(cat "$f" 2>/dev/null || true)"
  done
  dmi_product="$(echo "$dmi_product" | tr '[:upper:]' '[:lower:]')"

  case "$dmi_product" in
    *kvm*|*qemu*)        echo "kvm"        && return ;;
    *vmware*)            echo "vmware"     && return ;;
    *virtualbox*)        echo "virtualbox" && return ;;
    *"microsoft corporation"*) echo "hyperv" && return ;;
  esac

  # Fall back to /proc/cpuinfo
  if [ -r /proc/cpuinfo ]; then
    local cpuinfo
    cpuinfo="$(tr '[:upper:]' '[:lower:]' < /proc/cpuinfo)"
    echo "$cpuinfo" | grep -qi 'kvm\|qemu'      && echo "kvm"        && return
    echo "$cpuinfo" | grep -qi 'vmware'          && echo "vmware"     && return
    echo "$cpuinfo" | grep -qi 'virtualbox\|vbox' && echo "virtualbox" && return
  fi

  echo "none"
}

# ---------------------------------------------------------------------------
# Container runtime detection
# ---------------------------------------------------------------------------
_detect_runtime() {
  # Detect which container runtime is available and responsive.
  # Priority: whichever runtime is actually running > installed but not running.
  # Both Docker and Podman are first-class citizens.
  #
  # Exports per-runtime detection booleans into the environment so install.sh
  # can present an explicit prompt to the admin (maintainer directive 2026-04-29 —
  # admin always picks the runtime, even when both are detected; podman is the
  # default pre-selection per `feedback_runtime_choice.md`).

  local docker_available=false
  local podman_available=false
  local docker_running=false
  local podman_running=false

  # --- Check Docker ---
  if command -v docker >/dev/null 2>&1; then
    docker_available=true
    docker info >/dev/null 2>&1 && docker_running=true
  elif [ "$YSG_OS" = "macos" ] && [ -d "/Applications/Docker.app" ]; then
    # Docker Desktop installed but CLI not in PATH
    local dd_docker=""
    for p in "$HOME/.docker/bin/docker" "/usr/local/bin/docker" \
             "/usr/local/bin/com.docker.cli" \
             "/Applications/Docker.app/Contents/Resources/bin/docker"; do
      [ -x "$p" ] && dd_docker="$p" && break
    done
    if [ -n "$dd_docker" ]; then
      docker_available=true
      $dd_docker info >/dev/null 2>&1 && docker_running=true
    fi
  fi

  # --- Check Podman ---
  if command -v podman >/dev/null 2>&1; then
    podman_available=true
    podman info >/dev/null 2>&1 && podman_running=true
  fi

  # Export the per-runtime booleans so install.sh can present an explicit
  # admin prompt with full visibility into what's installed AND what's running.
  # The auto-pick below only sets the SUGGESTED default; install.sh's
  # prompt_runtime_choice() always asks the admin to confirm or override.
  export YSG_DOCKER_AVAILABLE="$docker_available"
  export YSG_DOCKER_RUNNING="$docker_running"
  export YSG_PODMAN_AVAILABLE="$podman_available"
  export YSG_PODMAN_RUNNING="$podman_running"

  # --- Decision: prefer Podman (rootless, daemonless, more secure) ---
  if $podman_running; then
    echo "podman" && return
  fi
  if $docker_running; then
    echo "docker" && return
  fi

  # Neither is running — prefer Podman if installed
  if $podman_available; then
    echo "podman" && return
  fi
  if $docker_available; then
    echo "docker" && return
  fi

  # Docker Desktop installed but no CLI in PATH
  if [ "$YSG_OS" = "macos" ] && [ -d "/Applications/Docker.app" ]; then
    echo "docker_desktop_no_cli" && return
  fi

  echo "none"
}

# ---------------------------------------------------------------------------
# Compose detection
# ---------------------------------------------------------------------------
_detect_compose() {
  # Check Docker compose (plugin or standalone)
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "plugin" && return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "standalone" && return
  fi
  # Check Podman compose (built-in subcommand in Podman 4+, or podman-compose)
  if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    echo "podman-plugin" && return
  fi
  if command -v podman-compose >/dev/null 2>&1; then
    echo "podman-standalone" && return
  fi
  echo "none"
}

# ---------------------------------------------------------------------------
# Kubernetes detection
# ---------------------------------------------------------------------------
_detect_k8s() {
  if command -v kubectl >/dev/null 2>&1 && command -v helm >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

# ---------------------------------------------------------------------------
# GPU detection
# ---------------------------------------------------------------------------
_detect_gpu() {
  local os="$1"
  local gpu_type="none"
  local gpu_name=""
  local gpu_vram_mb=0
  local gpu_compute="none"

  # --- Apple Silicon (macOS M-series) ---
  if [ "$os" = "macos" ]; then
    local chip
    chip="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")"
    if echo "$chip" | grep -qi "Apple"; then
      gpu_type="apple_metal"
      gpu_name="$chip"
      local ram_bytes
      ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
      gpu_vram_mb=$(( ram_bytes / 1024 / 1024 ))
      gpu_compute="metal"
      case "$chip" in
        *M1*)     gpu_compute="metal,ane_16core" ;;
        *M2*)     gpu_compute="metal,ane_16core" ;;
        *M3*)     gpu_compute="metal,ane_16core,ray_tracing" ;;
        *M4*)     gpu_compute="metal,ane_16core,ray_tracing" ;;
      esac
    fi
  fi

  # --- NVIDIA ---
  if [ "$gpu_type" = "none" ] && command -v nvidia-smi >/dev/null 2>&1; then
    if nvidia-smi >/dev/null 2>&1; then
      gpu_type="nvidia"
      gpu_name="$(nvidia-smi --query-gpu=gpu_name --format=csv,noheader 2>/dev/null | head -1 || echo "NVIDIA GPU")"
      gpu_vram_mb="$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "0")"
      local driver_ver
      driver_ver="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo "")"
      gpu_compute="cuda"
      [ -n "$driver_ver" ] && gpu_compute="cuda,driver_${driver_ver}"
    fi
  fi

  # --- AMD ROCm (discrete GPU: Radeon RX / Instinct / PRO) ---
  # rocm-smi present and working → full ROCm driver stack installed.
  # AMD APUs (Ryzen AI gfx1150/1151) with partial ROCm may also trigger this;
  # if ROCm inference fails at runtime, set YSG_GPU_TYPE=vulkan in docker/.env
  # to route through the Vulkan overlay (docker-compose.gpu-vulkan.yml) instead.
  if [ "$gpu_type" = "none" ] && command -v rocm-smi >/dev/null 2>&1; then
    if rocm-smi >/dev/null 2>&1; then
      gpu_type="amd_rocm"
      gpu_name="$(rocm-smi --showproductname 2>/dev/null | grep -i "card series" | head -1 | awk -F: '{gsub(/^[ \t]+/,"",$2); print $2}' || echo "AMD GPU")"
      gpu_vram_mb="$(rocm-smi --showmeminfo vram 2>/dev/null | grep -i 'total.*vram' | head -1 | grep -oE '[0-9]+' | head -1 || echo 0)"
      gpu_compute="rocm"
    fi
  fi

  # --- Fallback: lspci (Linux only) ---
  # Covers: NVIDIA without driver, AMD discrete without ROCm, Intel Arc/iGPU,
  # AMD APU without ROCm. Intel and AMD APU are mapped to 'vulkan' since the
  # Vulkan backend is the reliable inference path for these (source: docs.ollama.com/gpu).
  if [ "$gpu_type" = "none" ] && command -v lspci >/dev/null 2>&1; then
    if lspci 2>/dev/null | grep -qi "nvidia"; then
      gpu_type="nvidia_no_driver"
      gpu_name="$(lspci 2>/dev/null | grep -i nvidia | head -1 | sed 's/.*: //')"
      gpu_compute="none (install NVIDIA drivers + nvidia-container-toolkit)"
    elif lspci 2>/dev/null | grep -qiE "amd.*(radeon rx|instinct|pro w)"; then
      # AMD discrete (no ROCm driver) — install ROCm for best performance.
      gpu_type="amd_no_driver"
      gpu_name="$(lspci 2>/dev/null | grep -iE 'amd.*(radeon rx|instinct|pro w)' | head -1 | sed 's/.*: //')"
      gpu_compute="none (install ROCm: rocm.docs.amd.com)"
    elif lspci 2>/dev/null | grep -qiE "intel.*(arc|xe|a[0-9]+ graphics|hd graphics|uhd graphics|iris)"; then
      # Intel Arc discrete + iGPU (HD/UHD/Iris/Xe). No native ollama support —
      # inference via Vulkan backend (docker-compose.gpu-vulkan.yml).
      gpu_type="vulkan"
      gpu_name="$(lspci 2>/dev/null | grep -iE 'intel.*(arc|xe|a[0-9]+ graphics|hd graphics|uhd graphics|iris)' | head -1 | sed 's/.*: //')"
      gpu_compute="vulkan (Intel — requires mesa-vulkan-drivers)"
    elif lspci 2>/dev/null | grep -qiE "amd.*(radeon|ryzen|rx|vega|780m|760m|graphics)"; then
      # AMD APU / Ryzen integrated graphics (no rocm-smi, or gfx1150/1151 APU).
      # Map to Vulkan — ROCm APU support is experimental (source: docs.ollama.com/gpu).
      gpu_type="vulkan"
      gpu_name="$(lspci 2>/dev/null | grep -iE 'amd.*(radeon|ryzen|rx|vega|780m|760m|graphics)' | head -1 | sed 's/.*: //')"
      gpu_compute="vulkan (AMD APU — ROCm experimental; Mesa RADV recommended)"
    fi
  fi

  echo "${gpu_type}|${gpu_name}|${gpu_vram_mb}|${gpu_compute}"
}

# ---------------------------------------------------------------------------
# Run all detections
# ---------------------------------------------------------------------------
YSG_OS="$(_detect_os)"
YSG_DISTRO="$(_detect_distro "$YSG_OS")"
YSG_ARCH="$(_detect_arch)"
YSG_CLOUD="$(_detect_cloud)"
YSG_VM="$(_detect_vm)"
YSG_RUNTIME="${YSG_RUNTIME:-$(_detect_runtime)}"
YSG_COMPOSE="$(_detect_compose)"
YSG_K8S="$(_detect_k8s)"

# GPU detection
_gpu_result="$(_detect_gpu "$YSG_OS")"
YSG_GPU_TYPE="$(echo "$_gpu_result"   | cut -d'|' -f1)"
YSG_GPU_NAME="$(echo "$_gpu_result"   | cut -d'|' -f2)"
YSG_GPU_VRAM_MB="$(echo "$_gpu_result" | cut -d'|' -f3)"
YSG_GPU_COMPUTE="$(echo "$_gpu_result" | cut -d'|' -f4)"
unset _gpu_result

export YSG_OS YSG_DISTRO YSG_ARCH YSG_CLOUD YSG_VM YSG_RUNTIME YSG_COMPOSE YSG_K8S
export YSG_GPU_TYPE YSG_GPU_NAME YSG_GPU_VRAM_MB YSG_GPU_COMPUTE

# ---------------------------------------------------------------------------
# Verbose output
# ---------------------------------------------------------------------------
if [ "${YSG_DETECT_VERBOSE:-0}" = "1" ]; then
  printf "${YSG_BLUE}Platform detection results:${YSG_RESET}\n"
  printf "  %-20s %s\n" "YSG_OS"         "$YSG_OS"
  printf "  %-20s %s\n" "YSG_DISTRO"     "$YSG_DISTRO"
  printf "  %-20s %s\n" "YSG_ARCH"       "$YSG_ARCH"
  printf "  %-20s %s\n" "YSG_CLOUD"      "$YSG_CLOUD"
  printf "  %-20s %s\n" "YSG_VM"         "$YSG_VM"
  printf "  %-20s %s\n" "YSG_RUNTIME"    "$YSG_RUNTIME"
  printf "  %-20s %s\n" "YSG_COMPOSE"    "$YSG_COMPOSE"
  printf "  %-20s %s\n" "YSG_K8S"        "$YSG_K8S"
  printf "  %-20s %s\n" "YSG_GPU_TYPE"   "$YSG_GPU_TYPE"
  printf "  %-20s %s\n" "YSG_GPU_NAME"   "$YSG_GPU_NAME"
  printf "  %-20s %s\n" "YSG_GPU_VRAM_MB" "$YSG_GPU_VRAM_MB"
  printf "  %-20s %s\n" "YSG_GPU_COMPUTE" "$YSG_GPU_COMPUTE"
fi
