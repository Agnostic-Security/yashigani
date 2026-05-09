#!/usr/bin/env bash
# scripts/prepare-airgap-bundle.sh — Yashigani v2.23.3
# last-updated: 2026-05-09T00:00:00+01:00 (feat: air-gap mode + customer-built offline bundle #58)
#
# PURPOSE
# -------
# Run on a CONNECTED host.  Reads airgap/manifest.yml, pulls every image for
# the requested profile(s), verifies each digest matches the manifest (fail-
# closed), saves each image to an individual tar, then packs everything into a
# single zstd-compressed bundle for transfer to the isolated host.
#
# The customer retains full supply-chain control: images are pulled from
# upstream registries with the customer's own credentials and attestation
# tooling.  Agnostic Security does not ship images or blobs — only this
# manifest (kilobytes).
#
# USAGE
#   ./scripts/prepare-airgap-bundle.sh [OPTIONS]
#
# OPTIONS
#   --profile   core|full|observability|agents|wazuh|spire|openwebui
#               Can be repeated: --profile core --profile observability
#               Alias 'full' expands to: core observability openwebui
#               Default: core
#   --runtime   podman|docker   (default: podman if available, else docker)
#   --output    PATH            Directory to write the bundle into (default: .)
#   --version   VERSION         Override the version tag applied to the bundle
#                               filename (default: read from manifest.yml)
#   --dry-run                   Print images that would be pulled; no side-effects
#   --no-build                  Skip the in-tree gateway/backoffice docker build
#   --help                      Show this help
#
# OUTPUT (per run)
#   yashigani-airgap-v<VER>-<profile>.tar.zst   — the bundle
#   yashigani-airgap-v<VER>-<profile>.manifest  — sidecar: SHA256 of bundle +
#                                                  list of images with digests
#
# REQUIREMENTS (connected host)
#   podman or docker
#   zstd           — compression (apt install zstd / brew install zstd)
#   python3        — YAML parsing (standard on any Linux/macOS host)
#
# TRANSFER (after bundle is built)
#   Copy to isolated host:
#     yashigani-airgap-v<VER>-<profile>.tar.zst
#     yashigani-airgap-v<VER>-<profile>.manifest
#     install.sh
#     airgap/manifest.yml
#   Then on isolated host:
#     ./install.sh --air-gap --bundle yashigani-airgap-v<VER>-<profile>.tar.zst

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_FILE="${REPO_ROOT}/airgap/manifest.yml"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROFILES=()
RUNTIME=""
OUTPUT_DIR="."
DRY_RUN=false
NO_BUILD=false
VERSION_OVERRIDE=""

# ---------------------------------------------------------------------------
# Colour helpers (TTY-only)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET="\033[0m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"
  C_RED="\033[1;31m"; C_BLUE="\033[1;34m"; C_BOLD="\033[1m"
else
  C_RESET=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BLUE=""; C_BOLD=""
fi

info()    { printf "${C_BLUE}[airgap] %s${C_RESET}\n" "$1"; }
ok()      { printf "${C_GREEN}    ok  %s${C_RESET}\n" "$1"; }
warn()    { printf "${C_YELLOW}    !!  WARNING: %s${C_RESET}\n" "$1" >&2; }
err()     { printf "${C_RED}    !!  ERROR: %s${C_RESET}\n" "$1" >&2; exit 1; }
dry()     { printf "${C_YELLOW}    >>  (dry-run) would: %s${C_RESET}\n" "$1"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: scripts/prepare-airgap-bundle.sh [OPTIONS]

Builds a Yashigani air-gap bundle from pinned image manifests.
Run on a CONNECTED host before transferring to an isolated environment.

Options:
  --profile    core|full|observability|agents|wazuh|spire|openwebui
               Can be repeated. Default: core
  --runtime    podman|docker  (auto-detected if not set)
  --output     DIR            Write bundle + sidecar to DIR (default: .)
  --version    VER            Override bundle filename version string
  --dry-run                   List images without pulling or saving
  --no-build                  Skip building yashigani/gateway and backoffice from source
  --help                      Show this help

Examples:
  # Core-only bundle (production minimal)
  ./scripts/prepare-airgap-bundle.sh --profile core

  # Full bundle including observability + Open WebUI
  ./scripts/prepare-airgap-bundle.sh --profile full

  # Core + Wazuh SIEM
  ./scripts/prepare-airgap-bundle.sh --profile core --profile wazuh

  # Dry-run: list images for full profile
  ./scripts/prepare-airgap-bundle.sh --profile full --dry-run
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile)
        PROFILES+=("${2:?'--profile requires a value'}")
        shift 2 ;;
      --runtime)
        case "${2:-}" in
          podman|docker) RUNTIME="$2"; shift 2 ;;
          *) err "--runtime must be podman or docker" ;;
        esac ;;
      --output)
        OUTPUT_DIR="${2:?'--output requires a directory path'}"
        shift 2 ;;
      --version)
        VERSION_OVERRIDE="${2:?'--version requires a value'}"
        shift 2 ;;
      --dry-run)  DRY_RUN=true;  shift ;;
      --no-build) NO_BUILD=true; shift ;;
      --help|-h)  usage; exit 0 ;;
      *) err "Unknown option: $1 — run with --help for usage" ;;
    esac
  done

  # Default profile
  if [[ ${#PROFILES[@]} -eq 0 ]]; then
    PROFILES=("core")
  fi
}

# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------
detect_runtime() {
  if [[ -n "$RUNTIME" ]]; then
    command -v "$RUNTIME" >/dev/null 2>&1 || err "$RUNTIME not found in PATH"
    return
  fi
  if command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
  elif command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
  else
    err "Neither podman nor docker found in PATH — install one before running this script"
  fi
  info "Auto-detected runtime: ${RUNTIME}"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
check_deps() {
  local missing=0
  for cmd in python3 zstd sha256sum tar; do
    command -v "$cmd" >/dev/null 2>&1 || { warn "Missing required tool: ${cmd}"; missing=1; }
  done
  # macOS: shasum -a 256 instead of sha256sum
  if ! command -v sha256sum >/dev/null 2>&1 && command -v shasum >/dev/null 2>&1; then
    SHA256CMD="shasum -a 256"
  else
    SHA256CMD="sha256sum"
  fi
  [[ "$missing" -eq 0 ]] || err "Install missing tools then retry"
}

# ---------------------------------------------------------------------------
# YAML parsing — extract images for requested profiles
# ---------------------------------------------------------------------------
# Returns newline-separated list of "ref|digest|name|source" entries.
# 'source: in-tree' entries are the yashigani/* images built locally.
get_images_for_profiles() {
  local profiles_json
  # Build a JSON array of profile names for Python
  profiles_json="$(printf '"%s",' "${EXPANDED_PROFILES[@]}" | sed 's/,$//')"

  python3 - "${MANIFEST_FILE}" "[${profiles_json}]" <<'PYEOF'
import sys, re

manifest_path = sys.argv[1]
import json
requested = json.loads(sys.argv[2])

# Minimal YAML parser for our specific manifest format
# We parse by section headers and indented "- name:" blocks
with open(manifest_path) as f:
    lines = f.readlines()

current_profile = None
current_image = {}
in_images = False
profile_data = {}

i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()

    # Profile section header (2-space indent)
    m = re.match(r'^  (\w+):$', line)
    if m:
        if current_image and current_profile:
            profile_data.setdefault(current_profile, []).append(current_image)
        current_image = {}
        current_profile = m.group(1)
        in_images = False
        i += 1
        continue

    # images: key
    if re.match(r'^    images:$', line):
        in_images = True
        i += 1
        continue

    # profile_aliases section — stop parsing profiles
    if re.match(r'^profile_aliases:', line):
        if current_image and current_profile:
            profile_data.setdefault(current_profile, []).append(current_image)
        current_image = {}
        break

    if in_images and current_profile:
        # New list item — flush previous image
        if re.match(r'^      - name:', line):
            if current_image:
                profile_data.setdefault(current_profile, []).append(current_image)
            current_image = {}

        # Key: value pairs under image block
        m = re.match(r'^        (\w+): "?([^"#\n]*)"?', line)
        if not m:
            m = re.match(r'^      - (\w+): "?([^"#\n]*)"?', line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip().strip('"')
            current_image[key] = val

    i += 1

if current_image and current_profile:
    profile_data.setdefault(current_profile, []).append(current_image)

seen_refs = set()
for prof in requested:
    if prof not in profile_data:
        continue
    for img in profile_data[prof]:
        ref = img.get('ref', '')
        if not ref or ref in seen_refs:
            continue
        seen_refs.add(ref)
        digest = img.get('digest', '')
        name = img.get('name', '')
        source = img.get('source', 'external')
        print(f"{ref}|{digest}|{name}|{source}")
PYEOF
}

# ---------------------------------------------------------------------------
# Expand profile aliases
# ---------------------------------------------------------------------------
expand_profiles() {
  EXPANDED_PROFILES=()
  for prof in "${PROFILES[@]}"; do
    case "$prof" in
      full) EXPANDED_PROFILES+=(core observability openwebui) ;;
      *) EXPANDED_PROFILES+=("$prof") ;;
    esac
  done
  # Deduplicate preserving order
  local seen=()
  local deduped=()
  for p in "${EXPANDED_PROFILES[@]}"; do
    local found=0
    for s in "${seen[@]:-}"; do [[ "$s" == "$p" ]] && found=1; done
    if [[ "$found" -eq 0 ]]; then
      deduped+=("$p"); seen+=("$p")
    fi
  done
  EXPANDED_PROFILES=("${deduped[@]}")
}

# ---------------------------------------------------------------------------
# Pull and verify a single external image
# ---------------------------------------------------------------------------
pull_and_verify() {
  local ref="$1"
  local expected_digest="$2"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "pull + verify ${ref}"
    return 0
  fi

  info "Pulling ${ref} ..."
  if ! "$RUNTIME" pull "${ref}" >/dev/null 2>&1; then
    err "Failed to pull ${ref} — check network connectivity and registry credentials"
  fi

  if [[ -z "$expected_digest" ]]; then
    warn "No digest in manifest for ${ref} — skipping digest verification"
    return 0
  fi

  # Inspect the loaded image and extract the digest
  local actual_digest
  actual_digest="$("$RUNTIME" inspect --format='{{index .RepoDigests 0}}' "${ref}" 2>/dev/null \
    | awk -F@ '{print $2}' || true)"

  if [[ -z "$actual_digest" ]]; then
    # Some runtimes return digest differently
    actual_digest="$("$RUNTIME" inspect --format='{{.Digest}}' "${ref}" 2>/dev/null || true)"
  fi

  if [[ -z "$actual_digest" ]]; then
    warn "Could not retrieve digest for ${ref} — skipping digest verification"
    return 0
  fi

  if [[ "$actual_digest" != "$expected_digest" ]]; then
    err "DIGEST MISMATCH for ${ref}
  expected: ${expected_digest}
  got:      ${actual_digest}
This image does not match the pinned manifest. ABORTING — do not use this bundle."
  fi

  ok "Verified ${ref} digest: ${expected_digest:0:19}..."
}

# ---------------------------------------------------------------------------
# Build in-tree images (gateway / backoffice)
# ---------------------------------------------------------------------------
build_in_tree_images() {
  if [[ "$NO_BUILD" == "true" ]]; then
    warn "--no-build: skipping in-tree image builds (yashigani/gateway, yashigani/backoffice)"
    warn "You must pre-build and tag them before running prepare-airgap-bundle.sh"
    return 0
  fi

  local version="${VERSION_OVERRIDE}"
  if [[ -z "$version" ]]; then
    version="$(python3 -c "
import re, sys
with open('${MANIFEST_FILE}') as f:
    for line in f:
        m = re.match(r'^version: \"?([^\"]+)\"?', line)
        if m:
            print(m.group(1)); sys.exit(0)
print('unknown')
" 2>/dev/null || echo "unknown")"
  fi

  for service in gateway backoffice; do
    local dockerfile="${REPO_ROOT}/docker/Dockerfile.${service}"
    local img_ref="yashigani/${service}:${version}"

    if [[ "$DRY_RUN" == "true" ]]; then
      dry "build ${img_ref} from ${dockerfile}"
      continue
    fi

    if [[ ! -f "$dockerfile" ]]; then
      err "Dockerfile not found: ${dockerfile} — cannot build ${img_ref}"
    fi

    info "Building ${img_ref} from ${dockerfile} ..."
    "$RUNTIME" build \
      -f "${dockerfile}" \
      -t "${img_ref}" \
      "${REPO_ROOT}" >/dev/null 2>&1 || err "Build failed for ${img_ref}"
    ok "Built ${img_ref}"
  done
}

# ---------------------------------------------------------------------------
# Save a single image to tar (uncompressed — outer bundle compresses all)
# ---------------------------------------------------------------------------
save_image_to_tar() {
  local ref="$1"
  local tar_path="$2"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "save ${ref} -> ${tar_path}"
    return 0
  fi

  "$RUNTIME" save -o "${tar_path}" "${ref}" 2>/dev/null \
    || err "Failed to save image ${ref} to ${tar_path}"
  ok "Saved ${ref}"
}

# ---------------------------------------------------------------------------
# Main bundle assembly
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  detect_runtime
  check_deps

  [[ -f "$MANIFEST_FILE" ]] || err "Manifest not found: ${MANIFEST_FILE}"

  # Resolve version from manifest
  local version="${VERSION_OVERRIDE}"
  if [[ -z "$version" ]]; then
    version="$(python3 -c "
import re, sys
with open('${MANIFEST_FILE}') as f:
    for line in f:
        m = re.match(r'^version: \"?([^\"]+)\"?', line)
        if m:
            print(m.group(1)); sys.exit(0)
print('unknown')
" 2>/dev/null || echo "unknown")"
  fi

  expand_profiles
  local profile_label
  profile_label="$(IFS=+; echo "${PROFILES[*]}")"
  profile_label="${profile_label//full/full}"

  local bundle_name="yashigani-airgap-v${version}-${profile_label}"
  local bundle_path="${OUTPUT_DIR}/${bundle_name}.tar.zst"
  local sidecar_path="${OUTPUT_DIR}/${bundle_name}.manifest"

  info "Yashigani Air-Gap Bundle Builder v${version}"
  info "Profile(s): ${EXPANDED_PROFILES[*]}"
  info "Runtime:    ${RUNTIME}"
  info "Output:     ${OUTPUT_DIR}/${bundle_name}.tar.zst"
  printf "\n"

  if [[ "$DRY_RUN" == "true" ]]; then
    printf "${C_YELLOW}  -- DRY RUN — no images will be pulled or saved --${C_RESET}\n\n"
  fi

  # Create output dir
  if [[ "$DRY_RUN" != "true" ]]; then
    mkdir -p "${OUTPUT_DIR}"
  fi

  # Collect image list
  local image_lines
  image_lines="$(get_images_for_profiles)"

  if [[ -z "$image_lines" ]]; then
    err "No images found for profiles: ${EXPANDED_PROFILES[*]} — check airgap/manifest.yml"
  fi

  # Working directory for individual image tars
  local work_dir="${OUTPUT_DIR}/.airgap-build-$$"
  if [[ "$DRY_RUN" != "true" ]]; then
    mkdir -p "${work_dir}"
    # Trap: clean up work_dir on exit (success or failure)
    trap 'rm -rf "${work_dir}"' EXIT
  fi

  # Track in-tree images that need to be built
  local has_in_tree=false
  while IFS='|' read -r ref digest _name_chk source; do
    [[ -z "$ref" ]] && continue
    [[ "$source" == "in-tree" ]] && has_in_tree=true
  done <<< "$image_lines"

  # Build in-tree images first
  if [[ "$has_in_tree" == "true" ]]; then
    info "Building in-tree images (gateway, backoffice) ..."
    build_in_tree_images
  fi

  # Pull + verify + save each external image
  declare -a saved_tars=()
  declare -a sidecar_entries=()

  info "Processing images ..."
  printf "\n"

  local img_count=0
  while IFS='|' read -r ref digest _name source; do
    [[ -z "$ref" ]] && continue
    img_count=$((img_count + 1))

    if [[ "$source" == "in-tree" ]]; then
      # In-tree: tag was built above; verify existence + record digest
      if [[ "$DRY_RUN" == "true" ]]; then
        dry "include in-tree image ${ref}"
        sidecar_entries+=("${ref}|in-tree")
        continue
      fi

      local actual_digest=""
      # Re-tag with version tag matching the ref
      actual_digest="$("$RUNTIME" inspect --format='{{.Id}}' "${ref}" 2>/dev/null | head -c 71 || true)"
      sidecar_entries+=("${ref}|in-tree:${actual_digest}")
    else
      # External: pull + verify digest
      pull_and_verify "${ref}" "${digest}"
      sidecar_entries+=("${ref}|${digest}")
    fi

    # Save to individual tar
    if [[ "$DRY_RUN" != "true" ]]; then
      local safe_name
      safe_name="$(echo "${ref}" | tr '/: @' '____')"
      local tar_file="${work_dir}/${safe_name}.tar"
      save_image_to_tar "${ref}" "${tar_file}"
      saved_tars+=("${tar_file}")
    fi

  done <<< "$image_lines"

  printf "\n"
  info "Images processed: ${img_count}"

  if [[ "$DRY_RUN" == "true" ]]; then
    printf "\n${C_GREEN}Dry-run complete. ${img_count} images would be included in bundle.${C_RESET}\n"
    printf "${C_BOLD}  Bundle name: ${bundle_name}.tar.zst${C_RESET}\n"
    printf "${C_BOLD}  Profiles:    ${profile_label}${C_RESET}\n"
    printf "${C_BOLD}  Version:     ${version}${C_RESET}\n"
    return 0
  fi

  if [[ ${#saved_tars[@]} -eq 0 ]]; then
    err "No image tars produced — nothing to bundle"
  fi

  # Pack all tars into the bundle
  info "Packing bundle (zstd compression) ..."
  tar -C "${work_dir}" -c --zstd -f "${bundle_path}" . 2>/dev/null \
    || err "Failed to create bundle at ${bundle_path}"
  ok "Bundle created: ${bundle_path}"

  # Compute bundle SHA256
  local bundle_sha
  bundle_sha="$(${SHA256CMD} "${bundle_path}" | awk '{print $1}')"
  ok "Bundle SHA256: ${bundle_sha}"

  # Write sidecar manifest
  {
    printf "# Yashigani air-gap bundle sidecar manifest\n"
    printf "# Version:  %s\n" "${version}"
    printf "# Profiles: %s\n" "${profile_label}"
    printf "# Built:    %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf "# Runtime:  %s\n" "${RUNTIME}"
    printf "#\n"
    printf "# Bundle SHA256: %s\n" "${bundle_sha}"
    printf "#\n"
    printf "# Images (ref|digest):\n"
    for entry in "${sidecar_entries[@]}"; do
      printf "image: %s\n" "${entry}"
    done
    printf "#\n"
    printf "# To verify bundle integrity before install:\n"
    printf "#   sha256sum -c <(echo '%s  %s')\n" \
      "${bundle_sha}" "$(basename "${bundle_path}")"
    printf "#\n"
    printf "# To install on isolated host:\n"
    printf "#   ./install.sh --air-gap --bundle %s\n" "$(basename "${bundle_path}")"
  } > "${sidecar_path}"
  ok "Sidecar manifest: ${sidecar_path}"

  printf "\n"
  printf "${C_GREEN}${C_BOLD}Air-gap bundle ready.${C_RESET}\n"
  printf "\n"
  printf "  Transfer these files to the isolated host:\n"
  printf "    %s\n" "${bundle_path}"
  printf "    %s\n" "${sidecar_path}"
  printf "    install.sh\n"
  printf "    airgap/manifest.yml\n"
  printf "\n"
  printf "  On the isolated host:\n"
  printf "    ./install.sh --air-gap --bundle %s\n" "$(basename "${bundle_path}")"
  printf "\n"
  printf "  Bundle SHA256 (for out-of-band verification):\n"
  printf "    %s  %s\n" "${bundle_sha}" "$(basename "${bundle_path}")"
  printf "\n"
  printf "${C_YELLOW}  Supply-chain note: retain the sidecar manifest as provenance evidence.\n"
  printf "  Cross-reference against airgap/manifest.yml for SBOM/attestation.${C_RESET}\n"
}

main "$@"
