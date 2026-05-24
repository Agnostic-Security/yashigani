#!/usr/bin/env bash
# scripts/wizard.sh — Yashigani v0.6.0
# Interactive or non-interactive configuration wizard. Writes .env to project root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
NON_INTERACTIVE=0
CLI_DOMAIN=""
CLI_TLS_MODE=""
CLI_ADMIN_EMAIL=""
CLI_UPSTREAM_URL=""
CLI_KMS_PROVIDER=""
CLI_BACKEND=""
CLI_STREAM=""
CLI_SIEM=""
CLI_LICENSE_KEY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=1 ;;
    --domain)         shift; CLI_DOMAIN="$1" ;;
    --tls-mode)       shift; CLI_TLS_MODE="$1" ;;
    --admin-email)    shift; CLI_ADMIN_EMAIL="$1" ;;
    --upstream-url)   shift; CLI_UPSTREAM_URL="$1" ;;
    --kms-provider)   shift; CLI_KMS_PROVIDER="$1" ;;
    --backend)        shift; CLI_BACKEND="$1" ;;
    --stream)         shift; CLI_STREAM="$1" ;;
    --siem)           shift; CLI_SIEM="$1" ;;
    --license-key)    shift; CLI_LICENSE_KEY="$1" ;;
    --help)
      cat <<'EOF'
Usage: scripts/wizard.sh [OPTIONS]

Interactive or non-interactive Yashigani configuration wizard.
Writes a .env file in the project root.

Interactive mode (default): prompts for each value with defaults shown.
Non-interactive mode:        reads values from flags or environment variables.

Options:
  --non-interactive    Skip all prompts; use flags/env vars
  --domain DOMAIN      YASHIGANI_TLS_DOMAIN (required)
  --tls-mode MODE      acme|ca|selfsigned (default: acme)
  --admin-email EMAIL  YASHIGANI_ADMIN_USERNAME (default: admin@DOMAIN)
  --upstream-url URL   UPSTREAM_MCP_URL (required)
  --kms-provider KMS   docker|aws|azure|gcp|keeper|vault (default: docker)
  --backend BACKEND    ollama|anthropic|gemini (default: ollama)
  --stream STREAM      opensource|corporate|saas (default: opensource)
  --siem MODE          none|splunk|elasticsearch|wazuh (default: none)
  --license-key KEY    Path to license key file (optional)
  --help               Print this message

Environment variables (used in non-interactive mode if flags not set):
  YASHIGANI_TLS_DOMAIN, YASHIGANI_TLS_MODE, YASHIGANI_ADMIN_USERNAME,
  UPSTREAM_MCP_URL, YASHIGANI_KMS_PROVIDER,
  YASHIGANI_INSPECTION_DEFAULT_BACKEND, YASHIGANI_DEPLOYMENT_STREAM,
  YASHIGANI_SIEM_MODE, YASHIGANI_LICENSE_FILE
EOF
      exit 0
      ;;
    *) printf "Unknown option: %s\nRun with --help for usage.\n" "$1" >&2; exit 1 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Source platform detection
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Color/print helpers
# ---------------------------------------------------------------------------
_info()  { printf "${YSG_BLUE}[INFO]${YSG_RESET}  %s\n"   "$*"; }
_ok()    { printf "${YSG_GREEN}[OK]${YSG_RESET}    %s\n"  "$*"; }
_warn()  { printf "${YSG_YELLOW}[WARN]${YSG_RESET}  %s\n" "$*"; }
_error() { printf "${YSG_RED}[ERROR]${YSG_RESET} %s\n"    "$*" >&2; }
_die()   { _error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Prompt helper: _ask VAR_NAME "prompt text" "default"
# In non-interactive mode: uses CLI flag value > env var > default
# ---------------------------------------------------------------------------
_ask() {
  local var_name="$1"
  local prompt="$2"
  local default="${3:-}"

  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    # If already set (from CLI flags), keep it
    local current="${!var_name:-}"
    if [ -z "$current" ]; then
      printf -v "$var_name" '%s' "$default"
    fi
    return
  fi

  local display_default=""
  [ -n "$default" ] && display_default=" [${default}]"

  printf "%s%s: " "$prompt" "$display_default"
  local input=""
  IFS= read -r input || true
  if [ -z "$input" ] && [ -n "$default" ]; then
    printf -v "$var_name" '%s' "$default"
  else
    printf -v "$var_name" '%s' "$input"
  fi
}

# ---------------------------------------------------------------------------
# Cloud auto-populate: suggest KMS and fetch region/project info
# ---------------------------------------------------------------------------
_cloud_suggestions() {
  case "$YSG_CLOUD" in
    aws)
      _info "AWS cloud detected. Fetching region from IMDSv2..."
      local token
      token="$(curl --silent --max-time 2 -X PUT \
        "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 10" 2>/dev/null || true)"
      if [ -n "$token" ]; then
        AWS_REGION="$(curl --silent --max-time 2 \
          "http://169.254.169.254/latest/meta-data/placement/region" \
          -H "X-aws-ec2-metadata-token: ${token}" 2>/dev/null || true)"
        [ -n "${AWS_REGION:-}" ] && _info "Detected AWS region: ${AWS_REGION}"
      fi
      : "${SUGGESTED_KMS:=aws}"
      ;;
    gcp)
      _info "GCP cloud detected. Fetching project-id..."
      GCP_PROJECT="$(curl --silent --max-time 2 \
        "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
        -H "Metadata-Flavor: Google" 2>/dev/null || true)"
      [ -n "${GCP_PROJECT:-}" ] && _info "Detected GCP project: ${GCP_PROJECT}"
      : "${SUGGESTED_KMS:=gcp}"
      ;;
    azure)
      _info "Azure cloud detected. Fetching location..."
      AZURE_LOCATION="$(curl --silent --max-time 2 \
        "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text" \
        -H "Metadata: true" 2>/dev/null || true)"
      [ -n "${AZURE_LOCATION:-}" ] && _info "Detected Azure location: ${AZURE_LOCATION}"
      : "${SUGGESTED_KMS:=azure}"
      ;;
    *)
      : "${SUGGESTED_KMS:=docker}"
      ;;
  esac
}

_cloud_suggestions

# ---------------------------------------------------------------------------
# Gather configuration values
# ---------------------------------------------------------------------------

# 1. TLS domain
YASHIGANI_TLS_DOMAIN="${CLI_DOMAIN:-${YASHIGANI_TLS_DOMAIN:-}}"
_ask YASHIGANI_TLS_DOMAIN "TLS domain (e.g. example.com)" ""
while [ -z "${YASHIGANI_TLS_DOMAIN:-}" ]; do
  _error "TLS domain is required."
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    _die "Provide --domain or set YASHIGANI_TLS_DOMAIN."
  fi
  _ask YASHIGANI_TLS_DOMAIN "TLS domain (e.g. example.com)" ""
done

# 2. TLS mode
YASHIGANI_TLS_MODE="${CLI_TLS_MODE:-${YASHIGANI_TLS_MODE:-acme}}"
_ask YASHIGANI_TLS_MODE "TLS mode [acme/ca/selfsigned]" "${YASHIGANI_TLS_MODE}"
case "${YASHIGANI_TLS_MODE}" in
  acme|ca|selfsigned) ;;
  *) _warn "Unknown TLS mode '${YASHIGANI_TLS_MODE}'. Defaulting to 'acme'."; YASHIGANI_TLS_MODE="acme" ;;
esac

# 3. Admin email
local_default_email="admin@${YASHIGANI_TLS_DOMAIN}"
YASHIGANI_ADMIN_USERNAME="${CLI_ADMIN_EMAIL:-${YASHIGANI_ADMIN_USERNAME:-$local_default_email}}"
_ask YASHIGANI_ADMIN_USERNAME "Admin email" "${YASHIGANI_ADMIN_USERNAME}"

# 4. Upstream MCP URL
UPSTREAM_MCP_URL="${CLI_UPSTREAM_URL:-${UPSTREAM_MCP_URL:-}}"
_ask UPSTREAM_MCP_URL "Upstream MCP URL (e.g. https://mcp.example.com)" ""
while [ -z "${UPSTREAM_MCP_URL:-}" ]; do
  _error "Upstream MCP URL is required."
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    _die "Provide --upstream-url or set UPSTREAM_MCP_URL."
  fi
  _ask UPSTREAM_MCP_URL "Upstream MCP URL" ""
done

# 5. KMS provider
YASHIGANI_KMS_PROVIDER="${CLI_KMS_PROVIDER:-${YASHIGANI_KMS_PROVIDER:-${SUGGESTED_KMS:-docker}}}"
_ask YASHIGANI_KMS_PROVIDER "KMS provider [docker/aws/azure/gcp/keeper/vault]" \
  "${YASHIGANI_KMS_PROVIDER}"
case "${YASHIGANI_KMS_PROVIDER}" in
  docker|aws|azure|gcp|keeper|vault) ;;
  *) _warn "Unknown KMS provider '${YASHIGANI_KMS_PROVIDER}'. Defaulting to 'docker'."; YASHIGANI_KMS_PROVIDER="docker" ;;
esac

# 6. Inspection backend
YASHIGANI_INSPECTION_DEFAULT_BACKEND="${CLI_BACKEND:-${YASHIGANI_INSPECTION_DEFAULT_BACKEND:-ollama}}"
_ask YASHIGANI_INSPECTION_DEFAULT_BACKEND \
  "Inspection backend [ollama/anthropic/gemini]" \
  "${YASHIGANI_INSPECTION_DEFAULT_BACKEND}"
case "${YASHIGANI_INSPECTION_DEFAULT_BACKEND}" in
  ollama|anthropic|gemini) ;;
  *) _warn "Unknown backend. Defaulting to 'ollama'."; YASHIGANI_INSPECTION_DEFAULT_BACKEND="ollama" ;;
esac

# 7. Deployment stream
YASHIGANI_DEPLOYMENT_STREAM="${CLI_STREAM:-${YASHIGANI_DEPLOYMENT_STREAM:-opensource}}"
_ask YASHIGANI_DEPLOYMENT_STREAM \
  "Deployment stream [opensource/corporate/saas]" \
  "${YASHIGANI_DEPLOYMENT_STREAM}"
case "${YASHIGANI_DEPLOYMENT_STREAM}" in
  opensource|corporate|saas) ;;
  *) _warn "Unknown stream. Defaulting to 'opensource'."; YASHIGANI_DEPLOYMENT_STREAM="opensource" ;;
esac

# 8. SIEM integration
YASHIGANI_SIEM_MODE="${CLI_SIEM:-${YASHIGANI_SIEM_MODE:-none}}"
_ask YASHIGANI_SIEM_MODE \
  "SIEM integration [none/splunk/elasticsearch/wazuh]" \
  "${YASHIGANI_SIEM_MODE}"
case "${YASHIGANI_SIEM_MODE}" in
  none|splunk|elasticsearch|wazuh) ;;
  *) _warn "Unknown SIEM mode. Defaulting to 'none'."; YASHIGANI_SIEM_MODE="none" ;;
esac

# 9. License key file
YASHIGANI_LICENSE_FILE="${CLI_LICENSE_KEY:-${YASHIGANI_LICENSE_FILE:-}}"
if [ "$NON_INTERACTIVE" -eq 0 ]; then
  printf "License key file path (press Enter to skip for Community edition): "
  local_license_input=""
  IFS= read -r local_license_input || true
  [ -n "$local_license_input" ] && YASHIGANI_LICENSE_FILE="$local_license_input"
fi

# Validate license file if provided
LICENSE_TIER="Community"
if [ -n "${YASHIGANI_LICENSE_FILE:-}" ]; then
  if [ -f "$YASHIGANI_LICENSE_FILE" ]; then
    _ok "License file found: ${YASHIGANI_LICENSE_FILE}"
    LICENSE_TIER="Licensed"
  else
    _warn "License file not found: ${YASHIGANI_LICENSE_FILE} — proceeding as Community edition"
    YASHIGANI_LICENSE_FILE=""
  fi
fi

# ---------------------------------------------------------------------------
# Write .env file
# ---------------------------------------------------------------------------
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"

_info "Writing configuration to ${ENV_FILE}..."

# Build the .env content
{
  # Preserve existing .env.example comments/structure if available
  if [ -f "$ENV_EXAMPLE" ]; then
    printf "# Generated by wizard.sh on %s\n" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf "# Values from .env.example merged with wizard selections\n\n"
  else
    printf "# Yashigani v0.6.0 — generated by wizard.sh on %s\n\n" \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  fi

  printf "# --- TLS / Domain ---\n"
  printf "YASHIGANI_TLS_DOMAIN=%s\n"                   "$YASHIGANI_TLS_DOMAIN"
  printf "YASHIGANI_TLS_MODE=%s\n"                     "$YASHIGANI_TLS_MODE"
  printf "\n# --- Admin ---\n"
  printf "YASHIGANI_ADMIN_USERNAME=%s\n"               "$YASHIGANI_ADMIN_USERNAME"
  printf "\n# --- MCP ---\n"
  printf "UPSTREAM_MCP_URL=%s\n"                       "$UPSTREAM_MCP_URL"
  printf "\n# --- KMS ---\n"
  printf "YASHIGANI_KMS_PROVIDER=%s\n"                 "$YASHIGANI_KMS_PROVIDER"
  printf "\n# --- Inspection ---\n"
  printf "YASHIGANI_INSPECTION_DEFAULT_BACKEND=%s\n"   "$YASHIGANI_INSPECTION_DEFAULT_BACKEND"
  printf "\n# --- Deployment ---\n"
  printf "YASHIGANI_DEPLOYMENT_STREAM=%s\n"            "$YASHIGANI_DEPLOYMENT_STREAM"
  printf "\n# --- SIEM ---\n"
  printf "YASHIGANI_SIEM_MODE=%s\n"                    "$YASHIGANI_SIEM_MODE"

  if [ -n "${YASHIGANI_LICENSE_FILE:-}" ]; then
    printf "\n# --- License ---\n"
    printf "YASHIGANI_LICENSE_FILE=%s\n"               "$YASHIGANI_LICENSE_FILE"
  fi

  # Cloud-detected extras
  if [ "$YSG_CLOUD" = "aws" ] && [ -n "${AWS_REGION:-}" ]; then
    printf "\n# --- AWS (auto-detected) ---\n"
    printf "AWS_REGION=%s\n" "$AWS_REGION"
  fi
  if [ "$YSG_CLOUD" = "gcp" ] && [ -n "${GCP_PROJECT:-}" ]; then
    printf "\n# --- GCP (auto-detected) ---\n"
    printf "GCP_PROJECT=%s\n" "$GCP_PROJECT"
  fi
  if [ "$YSG_CLOUD" = "azure" ] && [ -n "${AZURE_LOCATION:-}" ]; then
    printf "\n# --- Azure (auto-detected) ---\n"
    printf "AZURE_LOCATION=%s\n" "$AZURE_LOCATION"
  fi

} > "$ENV_FILE"

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
printf "\n${YSG_BLUE}Configuration summary:${YSG_RESET}\n"
printf "  %-40s %s\n" "YASHIGANI_TLS_DOMAIN"                "$YASHIGANI_TLS_DOMAIN"
printf "  %-40s %s\n" "YASHIGANI_TLS_MODE"                  "$YASHIGANI_TLS_MODE"
printf "  %-40s %s\n" "YASHIGANI_ADMIN_USERNAME"            "$YASHIGANI_ADMIN_USERNAME"
printf "  %-40s %s\n" "UPSTREAM_MCP_URL"                    "$UPSTREAM_MCP_URL"
printf "  %-40s %s\n" "YASHIGANI_KMS_PROVIDER"              "$YASHIGANI_KMS_PROVIDER"
printf "  %-40s %s\n" "YASHIGANI_INSPECTION_DEFAULT_BACKEND" "$YASHIGANI_INSPECTION_DEFAULT_BACKEND"
printf "  %-40s %s\n" "YASHIGANI_DEPLOYMENT_STREAM"         "$YASHIGANI_DEPLOYMENT_STREAM"
printf "  %-40s %s\n" "YASHIGANI_SIEM_MODE"                 "$YASHIGANI_SIEM_MODE"
if [ -n "${YASHIGANI_LICENSE_FILE:-}" ]; then
  printf "  %-40s %s\n" "YASHIGANI_LICENSE_FILE" "$YASHIGANI_LICENSE_FILE"
fi
printf "\n"

if [ "$LICENSE_TIER" = "Community" ]; then
  printf "${YSG_YELLOW}Community edition — 10 agents max, no SAML/OIDC/SCIM${YSG_RESET}\n"
else
  printf "${YSG_GREEN}License loaded — ${LICENSE_TIER}${YSG_RESET}\n"
fi

_ok ".env written to ${ENV_FILE}"
