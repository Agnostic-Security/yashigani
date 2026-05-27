#!/usr/bin/env bash
# last-updated: 2026-05-23T00:00:00+00:00 (fix(install): BYOCA-BUG-001/002/003/004 — _fp init + podman unshare BYO staging + EC key gate + podman unshare YAML update)
# last-updated: 2026-05-19T00:00:00+01:00 (fix(install): inject X-SPIFFE-ID on POST /admin/agents — close ISSUE-019)
# last-updated: 2026-05-17T17:00:00+00:00 (feat(install): per-install YASHIGANI_INTERNAL_BEARER token generation — close Captain Bucket-C finding)
# last-updated: 2026-05-17T09:00:00+01:00 (fix(pki): host-side bootstrap_token_sha256 update in _pki_run_issuer_podman_macos — compose-path SHA mismatch fix)
# last-updated: 2026-05-17T14:00:00+00:00 (feat(install): write OLLAMA_MODEL to .env when --with-openwebui; ollama-init gated on openwebui profile)
# last-updated: 2026-05-17T00:00:00+00:00 (feat(install): use-case wizard — [Y/n] Open WebUI question in interactive mode; --with-openwebui unchanged for non-interactive)
# last-updated: 2026-05-15T12:00:00+00:00 (fix(install): detect contaminated volumes + verify healthz on convergence — BUG-INSTALL-ON-CONTAMINATED-VOLUMES)
# last-updated: 2026-05-15T00:00:00+00:00 (fix(install): move linger-enable to pre-flight, drop privileged-linger shortcut from install body — Q2 / lint-sudo-pattern fix)
# last-updated: 2026-05-14T22:00:00+00:00 (docs(saml): document + sanity-check RSA SP key requirement — YSG-RISK-044)
# last-updated: 2026-05-14T21:00:00+00:00 (feat: container auto-start on host reboot — _setup_auto_start + sub-functions; BUG-REBOOT-NO-AUTO-START / YSG-RISK-046)
# last-updated: 2026-05-13T15:00:00+00:00 (fix(podman): scope :U-override-load to macOS Podman only — LINUX-SHARED-MOUNT-UID-CLOBBER)
# last-updated: 2026-05-13T13:00:00+00:00 (fix(podman): always apply :U-bearing override on macOS Podman — MACOS-PODMAN-OVERRIDE-LOAD-GAP)
# last-updated: 2026-05-20T12:00:00+01:00 (fix(install): Step 8e — pre-create docker/letta-runtime/openapi_letta.json before compose up for read_only:true letta container)
# last-updated: 2026-05-13T00:00:00+00:00 (fix(podman): add :U to all secret bind-mounts and ephemeral chown — MACOS-PODMAN-PKI-VIRTIOFS-U)
# last-updated: 2026-05-12T00:00:00+01:00 (fix(install): write agent-bundle token placeholders before PKI chown — INSTALLER-BUG-AGENT-TOKENS)
# last-updated: 2026-05-11T12:00:00+01:00 (refactor(pki): split _pki_run_issuer into per-runtime functions — _pki_run_issuer_docker / _pki_run_issuer_podman_linux / _pki_run_issuer_podman_macos; podman cp pattern for macOS applehv)
# last-updated: 2026-05-11T00:30:00+01:00 (fix: macOS+Docker Colima virtiofs — skip host-UID chown assertions in check_installer_preflight + compose_up; YSG_OS==macos gated)
# last-updated: 2026-05-10T21:30:00+01:00 (fix: _pki_chown_client_keys || return 1 at both call sites — fail-closed on chown failure, not silent continue)
# last-updated: 2026-05-10T13:00:00+01:00 (fix: BUG-AG-001 --pull never for air-gap compose up; BUG-AG-005 bump YASHIGANI_VERSION to 2.23.3)
# last-updated: 2026-05-10T00:00:00+01:00 (fix(pki): GATE5-BUG-01 — source shared lib/pki_ownership.sh; upgrade no-rotation path stops touching keys; maintainer directive 2026-05-10)
# last-updated: 2026-05-09T15:00:00+01:00 (fix: Docker non-root — compose_up data/audit mkdir uses ephemeral container when data_dir owned by UID 1001)
# last-updated: 2026-05-09T00:00:00+01:00 (feat: air-gap mode + customer-built offline bundle #58)
# last-updated: 2026-05-08T12:00:00+01:00 (fix/k8s-postgres-exec-privilege-flow: _backup_existing_data — add K8s pg_dump path via kubectl exec; pod runs as UID 70, no root needed)
# last-updated: 2026-05-07T12:05:00+01:00 (retro #83: add grafana:472 to _pki_chown_client_keys; retro #84: loki:10001+promtail:0 added)
# last-updated: 2026-05-07T10:00:00+01:00 (retro #84: loki+promtail added to _pki_chown_client_keys UID map for mTLS cert issuance)
# last-updated: 2026-05-06T20:00:00+01:00 (P-9 fix: _podman_verify_healthchecks() post-compose-up gate; called on Podman path in compose_up())
# last-updated: 2026-05-06T12:00:00+01:00 (fix #85: bind-mount dirs auto-created for all runtimes incl. rootless Podman; sudo mkdir removed from promtail path; fail-loud on backups/tls mkdir)
# last-updated: 2026-05-04T19:30:00+01:00 (v2.23.2: chown caddy_client.key to UID 0 — cap_drop ALL strips DAC_OVERRIDE; gate V232-SMOKE-019. sudo mkdir promtail dir; gate V232-SMOKE-020)
# last-updated: 2026-05-04T18:00:00+01:00 (v2.23.2: postgres+redis password files set 0644 — readable by root containers under cap_drop ALL; gate V232-SMOKE-018)
# last-updated: 2026-05-04T12:00:00+01:00 (v2.23.2: bump YASHIGANI_VERSION; podman unshare mkdir falls back to plain mkdir when unshare unsupported by remote client)
# last-updated: 2026-05-03T14:00:00+01:00 (V232-NEG04: replace /tmp mktemp sites; V232-P27+F-NEW-03: skip-pull guard; F-NEW-04: bind-mount auto-create for rootful/Docker)
# last-updated: 2026-05-03T12:45:00+01:00 (V232-SMOKE-012: _pki_chown_client_keys enforces secrets dir mode 0755 so OPA inotify watcher can read dir)
# last-updated: 2026-05-03T06:00:00+01:00 (fix: use podman cp for postgres SSL injection when old bind-mount lacks new certs — V232-SMOKE-004b)
# last-updated: 2026-05-03T05:30:00+01:00 (fix: pre-start postgres for SSL injection before full compose up — V232-SMOKE-004)
# last-updated: 2026-05-03T04:30:00+01:00 (fix: add OPA/otel-collector/jaeger UIDs to _pki_chown_client_keys — V232-SMOKE-002)
# last-updated: 2026-05-03T03:45:00+01:00 (fix: parallel Podman pull wait deadlock with exec+tee coprocess)
# last-updated: 2026-05-01T12:00:00+01:00 (fix: --mode argv guard prevents TTY/non-interactive overwrite — P1 #3bg)
# last-updated: 2026-05-03T00:30:00+01:00 (fix: chown password files + bootstrap tokens + HMAC secret to UID 1001 — gate #ROOTLESS-11)
# last-updated: 2026-05-03T00:15:00+01:00 (fix: _pki_runtime_cmd honours YSG_RUNTIME=podman on --skip-pull path — gate #ROOTLESS-10)
# last-updated: 2026-05-03T00:00:00+01:00 (fix: separate mount opts for manifest vs secrets in _pki_run_issuer for Podman rootless — gate #ROOTLESS-9)
# last-updated: 2026-05-02T21:55:00+01:00 (fix: guard podman unshare data/audit mkdir on rootful installs — gate #ROOTFUL-1)
# 2026-05-02: preflight check now accepts subuid-remapped UID for Podman rootless (gate #ROOTLESS-1 blocker)
# 2026-05-02: data/audit subdirectory created via podman unshare for Podman rootless (gate #ROOTLESS-2 blocker)
# 2026-05-02: secrets_dir chown deferred to _prepare_secrets_dir_for_pki() for Podman rootless (gate #ROOTLESS-3 blocker)
# 2026-05-02: stale-partial-install guard in compose_up() must not wipe when ca_root.crt already present (gate #ROOTLESS-5 blocker)
# 2026-05-02: license_key placeholder created at step 7 (before PKI chown) in demo mode; compose_up placeholder write is non-fatal for Podman rootless (gate #ROOTLESS-6 blocker)
# 2026-05-02: _pki_chown_client_keys mode probe replaced with static /etc/subuid check; unshare case falls back to podman_run before aborting (gate #ROOTLESS-7 blocker)
# 2026-05-02: step-7 license_key placeholder write made non-fatal when secrets_dir owned by stale UID (gate #ROOTLESS-8 blocker)
# 2026-05-02: edited for OWUI integrator-framing per Legal audit; cross-ref /Internal/IP/shared/owui_licence_correspondence_2026-05-02.md
set -euo pipefail

# ---------------------------------------------------------------------------
# Shared PKI service-key ownership map (single source of truth).
# lib/pki_ownership.sh must live alongside install.sh in the repo root.
# GATE5-BUG-01 / maintainer directive 2026-05-10.
# ---------------------------------------------------------------------------
# shellcheck source=lib/pki_ownership.sh
_YSG_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_YSG_SCRIPT_DIR}/lib/pki_ownership.sh" ]]; then
  # shellcheck disable=SC1091
  source "${_YSG_SCRIPT_DIR}/lib/pki_ownership.sh"
else
  printf "ERROR: lib/pki_ownership.sh not found alongside install.sh\n" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# FIPS-aware SHA-256 helpers (integrity-verification paths only).
# lib/yashigani-fips.sh routes through OpenSSL FIPS Provider when FIPS_MODE=1.
# CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2 directive 2026-05-24.
# ---------------------------------------------------------------------------
# shellcheck source=lib/yashigani-fips.sh
if [[ -f "${_YSG_SCRIPT_DIR}/lib/yashigani-fips.sh" ]]; then
  # shellcheck disable=SC1091
  source "${_YSG_SCRIPT_DIR}/lib/yashigani-fips.sh"
else
  printf "ERROR: lib/yashigani-fips.sh not found alongside install.sh\n" >&2
  exit 1
fi

# =============================================================================
# Yashigani Installer
# https://yashigani.io
#
# Usage:
#   curl -sSL https://get.yashigani.io | bash
#   curl -sSL https://get.yashigani.io | bash -s -- --non-interactive --domain example.com
#   ./install.sh --mode compose
#   ./install.sh --mode k8s --namespace yashigani
# =============================================================================

YASHIGANI_VERSION="2.24.0"
YASHIGANI_REPO_URL="${YASHIGANI_REPO_URL:-https://github.com/agnosticsec-com/yashigani.git}"
YASHIGANI_TARBALL_URL="${YASHIGANI_TARBALL_URL:-https://github.com/agnosticsec-com/yashigani/archive/refs/tags/v${YASHIGANI_VERSION}.tar.gz}"
YSG_INSTALL_DIR="${YSG_INSTALL_DIR:-$HOME/.yashigani}"

# -----------------------------------------------------------------------------
# Color output — only when stdout is a TTY
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET="\033[0m"
  C_BLUE="\033[1;34m"
  C_GREEN="\033[1;32m"
  C_YELLOW="\033[1;33m"
  C_RED="\033[1;31m"
  C_BOLD="\033[1m"
else
  C_RESET=""
  C_BLUE=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_BOLD=""
fi

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
log_step()    { printf "${C_BLUE}[ %s ] %s${C_RESET}\n" "$1" "$2"; }
log_info()    { printf "${C_BOLD}    --> %s${C_RESET}\n" "$1"; }
log_success() { printf "${C_GREEN}    ok  %s${C_RESET}\n" "$1"; }
log_warn()    { printf "${C_YELLOW}    !!  WARNING: %s${C_RESET}\n" "$1" >&2; }
log_error()   { printf "${C_RED}    !!  ERROR: %s${C_RESET}\n" "$1" >&2; }
dry_print()   { printf "${C_YELLOW}    >>  Would run: %s${C_RESET}\n" "$*"; }

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
MODE="compose"
# Set to 1 by parse_args() when --mode appears on argv. Prevents TTY / non-interactive
# detection from overwriting an explicitly requested runtime mode (P1 #3bg).
MODE_EXPLICIT=0
DEPLOY_MODE=""                # demo|production|enterprise — set interactively or via --deploy
DOMAIN=""
TLS_MODE="acme"
# FIPS_MODE — operator opt-in to FIPS-mode crypto (CMVP #4985 when a FIPS-
# configured base image is in use). Default 0 = standard OpenSSL. Set to 1
# via --fips-mode flag or YSG_FIPS_MODE env var. Captain v2.24.4 B8 closure:
# Captain's commit 7d5b6c0 added the YAML side (FIPS_MODE: ${YSG_FIPS_MODE:-0}
# in x-common-env); this closes the install.sh side per Captain's original
# brief — _env_set writes FIPS_MODE to docker/.env so compose reads it
# runtime-agnostically rather than relying on env-var propagation through
# subshells (which works on Linux Podman but not Mac Podman Desktop).
FIPS_MODE="${YSG_FIPS_MODE:-0}"
# CMVP_CERT — operator-supplied CMVP certificate number for the FIPS-validated
# OpenSSL provider in the chosen base image (e.g. "#4985"). Surfaced by
# /admin/crypto/inventory as runtime FIPS attestation evidence for auditors
# (Nico N-002 / v2.25.0 P2 B9). Default empty = attestation reports null.
# Set via --cmvp-cert flag or YSG_CMVP_CERT env var.
CMVP_CERT="${YSG_CMVP_CERT:-}"
ADMIN_EMAIL=""
UPSTREAM_URL=""
LICENSE_KEY_PATH=""
DB_AES_KEY=""                 # YASHIGANI_DB_AES_KEY — set via prompt or --db-aes-key
NON_INTERACTIVE=false
# Track whether YSG_RUNTIME was set explicitly by the operator (env var or
# --runtime CLI flag). When true, prompt_runtime_choice() skips the
# interactive prompt — the admin has already chosen.
if [[ -n "${YSG_RUNTIME:-}" ]]; then
  YSG_RUNTIME_EXPLICIT=true
  export YSG_RUNTIME_EXPLICIT
fi
SKIP_PREFLIGHT=false
SKIP_PULL=false
UPGRADE=false
DRY_RUN=false
OFFLINE=false
AIR_GAP=false             # --air-gap: load images from local bundle, block all outbound fetches
AIR_GAP_BUNDLE=""         # --bundle <path>: path to the .tar.zst bundle built by prepare-airgap-bundle.sh
NAMESPACE="yashigani"
TOTAL_STEPS=13
WORK_DIR=""
AGENT_BUNDLES=""          # comma-separated: langflow,letta,openclaw
INSTALL_WAZUH=false       # opt-in: --wazuh flag
INSTALL_OPENWEBUI=false   # opt-in: --with-openwebui flag
INSTALL_INTERNAL_CA=false    # opt-in: --with-internal-ca flag
INTERNAL_CA_CERT=""          # --internal-ca-cert path; empty = no BYO CA or deferred
INTERNAL_CA_KEY=""           # --internal-ca-key path
INTERNAL_CA_ROOT=""          # --internal-ca-root path (customer root cert for trust anchor)
INTERNAL_CA_FINGERPRINT=""   # --byo-ca-fingerprint sha256 (REQUIRED in non-interactive when BYO is enabled)
INTERNAL_CA_ACCEPT_EXPIRED=false  # --accept-expired-ca for test environments
INTERNAL_CA_DEFER=false      # true when --with-internal-ca is passed without cert/key paths
TLS_MODE_EXPLICITLY_SET=""   # set to "true" when --tls-mode flag is parsed
COMPOSE_PROFILES=()          # populated by select_agent_bundles()
REUSE_VOLUMES=false        # --reuse-volumes or auto-set on additive re-run: skip contaminated-volume pre-check

# Internal mTLS PKI — two-tier (root → intermediate → leaf).
# Lifetimes are clamped to the bounds in docker/service_identities.yaml
# cert_policy block; values outside bounds are silently clamped by the
# yashigani.pki.issuer module.
YASHIGANI_ROOT_CA_LIFETIME_YEARS="${YASHIGANI_ROOT_CA_LIFETIME_YEARS:-10}"
YASHIGANI_INTERMEDIATE_LIFETIME_DAYS="${YASHIGANI_INTERMEDIATE_LIFETIME_DAYS:-180}"
YASHIGANI_CERT_LIFETIME_DAYS="${YASHIGANI_CERT_LIFETIME_DAYS:-90}"
PKI_ACTION=""             # --pki-action=bootstrap|rotate-leaves|rotate-intermediate|rotate-root|status

# Public-access SAN for demo / system-use deployments (YSG-CERT-SAN-001).
# Tiago directive 2026-05-18: VM-IP / hostname access is a supported customer
# path for demo and system-use; CA / Let's Encrypt is the proper-deployment path.
# These are injected into the Caddy server cert SAN at PKI bootstrap / rotation.
# Empty string = auto-detect at install time (see _detect_public_access_params).
YSG_PUBLIC_HOSTNAME="${YSG_PUBLIC_HOSTNAME:-}"
YSG_PUBLIC_IP="${YSG_PUBLIC_IP:-}"

# If stdin is not a TTY (piped from curl), force non-interactive
if [ ! -t 0 ]; then
  NON_INTERACTIVE=true
fi

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BOLD}Yashigani v${YASHIGANI_VERSION} Installer${C_RESET}

USAGE
  install.sh [OPTIONS]
  curl -sSL https://get.yashigani.io | bash -s -- [OPTIONS]

OPTIONS
  --deploy         demo|production|enterprise  Deployment mode (interactive if omitted)
  --mode           compose|k8s|vm         Legacy deployment mode (prefer --deploy)
  --domain         DOMAIN                 TLS domain, e.g. yashigani.example.com
  --tls-mode       acme|ca|selfsigned     TLS provisioning mode (default: acme)
  --fips-mode      [0|1]                  Enable FIPS-mode crypto routing (default: 0).
                                          Pass --fips-mode 1 OR --fips-mode (no arg → 1)
                                          OR set YSG_FIPS_MODE=1 in the env. Writes
                                          FIPS_MODE to docker/.env so gateway, backoffice,
                                          and caddy containers read it. NOTE: FIPS_MODE=1
                                          activates the CMVP-validated path only if the
                                          container base image contains the FIPS Provider
                                          (default python:3.14.0-slim does NOT — operators
                                          requiring CMVP #4985 must swap to a FIPS-configured
                                          base image. See docs/yashigani_install_config.md §30.)
  --cmvp-cert      CERT                   CMVP certificate number for runtime FIPS
                                          attestation, e.g. "#4985". Surfaced by
                                          /admin/crypto/inventory as evidence for auditors.
                                          OR set YSG_CMVP_CERT in the env. Default empty
                                          = attestation reports cmvp_cert: null.
  --admin-email    EMAIL                  Admin account email / username
  --upstream-url   URL                    Upstream MCP URL
  --license-key    PATH                   Path to .ysg license file
  --db-aes-key     KEY                    Database AES-256 encryption key (64-char hex)
  --namespace      NAMESPACE              Kubernetes namespace (default: yashigani)
  --agent-bundles  BUNDLES               Comma-separated opt-in agents: langflow,letta,openclaw (or "all")
  --with-openwebui                        Install Open WebUI chat surface (non-interactive explicit opt-in).
                                          In interactive mode a wizard question is presented instead
                                          ("Will Yashigani be used by humans with a web UI? [Y/n]").
                                          Pulls image unmodified from ghcr.io/open-webui/open-webui;
                                          Open WebUI is governed by its own licence terms.
  --with-internal-ca                      Enable BYO internal CA for service-to-service mTLS.
                                          Without --internal-ca-cert/--internal-ca-key, activates
                                          deferred mode (install runs with Yashigani-generated PKI;
                                          supply CA files later via install.sh re-run).
  --internal-ca-cert PATH                Path to BYO intermediate CA certificate (PEM, absolute).
                                          Requires --internal-ca-key. Use with --with-internal-ca.
  --internal-ca-key  PATH                Path to BYO intermediate CA private key (PEM, absolute).
                                          Requires --internal-ca-cert. Use with --with-internal-ca.
  --internal-ca-root PATH                Path to BYO root CA certificate (PEM, absolute).
                                          Required when --internal-ca-cert is supplied so services
                                          can verify the full chain.
  --byo-ca-fingerprint SHA256            Expected SHA-256 fingerprint of the BYO CA cert.
                                          REQUIRED in --non-interactive mode when BYO CA is enabled.
                                          The installer computes the actual fingerprint and aborts
                                          if they do not match (anti-substitution guard, MUST-1).
  --accept-expired-ca                    Allow an expired BYO CA cert (test environments only).
                                          Logs a CRITICAL warning when used.
  --wazuh                                 Install Wazuh SIEM (manager + indexer + dashboard)
  --offline                               Legacy offline flag (no ACME, no image pulls). Use
                                          --air-gap --bundle <path> for full air-gap installs.
  --air-gap                               Air-gap install mode. Loads images from a pre-built
                                          bundle (--bundle required). Skips ALL outbound fetches
                                          (registry, HIBP, ACME). Images verified against
                                          airgap/manifest.yml digests. Implies --offline.
                                          Build the bundle first on a connected host:
                                            ./scripts/prepare-airgap-bundle.sh --profile core
  --bundle         PATH                   Path to the .tar.zst bundle produced by
                                          prepare-airgap-bundle.sh. Required with --air-gap.
  --non-interactive                       Skip all interactive prompts
  --runtime <docker|podman|k8s>          Lock the container runtime (admin-must-choose
                                          rule per feedback_runtime_choice.md;
                                          equivalent to YSG_RUNTIME=...). Required in
                                          --non-interactive mode if both Docker and
                                          Podman are installed. Default in interactive
                                          mode: prompt with Podman pre-selected.
  --http-port  <N>                        Host port to bind for HTTP (default: 80; or 8080
                                          on macOS / rootless Podman). Use a higher port if
                                          80 is not externally reachable in your network
                                          config — see install guide §1.3. Range: 1-65535.
  --https-port <N>                        Host port to bind for HTTPS (default: 443; or 8443
                                          on macOS / rootless Podman). Same network note as
                                          --http-port. Range: 1-65535.
  --public-hostname HOSTNAME              Hostname (or IP) to include in the Caddy
                                          server cert SAN for demo / system-use access.
                                          Auto-detected via hostname -f if omitted.
                                          Use this when your demo host is reachable by a
                                          known FQDN (e.g. yashigani.local, myhost.lan).
                                          Proper deployments: use --tls-mode acme or ca.
  --public-ip      IP                     Host IP to include in the Caddy cert SAN.
                                          Auto-detected via hostname -I if omitted.
                                          Useful when demos are accessed directly by IP.
  --skip-preflight                        Skip preflight checks
  --skip-pull                             Skip docker compose pull (use local images)
  --upgrade                               Upgrade an existing installation
  --reuse-volumes                         Skip pre-install contaminated-volume detection.
                                          Use only when deliberately reusing volumes from a
                                          previous install (data-in-place upgrade path).
                                          WARNING: mismatched PKI CA in postgres_data will
                                          cause DB-init failures. Prefer --upgrade instead.
  --dry-run                               Print steps without executing
  --help                                  Show this help and exit

ENVIRONMENT
  YSG_INSTALL_DIR        Install directory when run via curl (default: \$HOME/.yashigani)
  YASHIGANI_LICENSE_FILE Alternative path to license file
  YASHIGANI_HTTP_PORT    Host HTTP port (overridden by --http-port flag if both set)
  YASHIGANI_HTTPS_PORT   Host HTTPS port (overridden by --https-port flag if both set)
  YSG_DEBUG              Set to 1 for verbose output

EXAMPLES
  # Interactive compose install
  curl -sSL https://get.yashigani.io | bash

  # Non-interactive compose install
  curl -sSL https://get.yashigani.io | bash -s -- \\
    --non-interactive --domain example.com --admin-email admin@example.com

  # Kubernetes install
  ./install.sh --mode k8s --namespace yashigani --domain example.com

  # Dry-run to review steps
  ./install.sh --dry-run --domain example.com
EOF
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
  # BUG-WAVE1-P1-001: normalise --flag=value to --flag value before the main
  # parsing loop.  GNU getopt-style equals-form (--runtime=podman) is conventional
  # for long options; without this step bash's case-esac only matches the space
  # form (--runtime podman) and rejects the equals form with "Unknown option".
  # The normalisation reconstructs $@ in-place so the main while loop is unchanged
  # and no future flag additions require a parallel equals-case block.
  local _args=()
  for _a in "$@"; do
    if [[ "$_a" == --*=* ]]; then
      # Split --flag=value → "--flag" "value"
      _args+=("${_a%%=*}" "${_a#*=}")
    else
      _args+=("$_a")
    fi
  done
  set -- "${_args[@]+"${_args[@]}"}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        MODE="${2:?'--mode requires a value: compose|k8s|vm'}"
        MODE_EXPLICIT=1   # guard: _apply_deploy_defaults must not overwrite this
        shift 2
        ;;
      --domain)
        DOMAIN="${2:?'--domain requires a value'}"
        shift 2
        ;;
      --tls-mode)
        TLS_MODE="${2:?'--tls-mode requires a value: acme|ca|selfsigned'}"
        TLS_MODE_EXPLICITLY_SET="true"
        shift 2
        ;;
      --fips-mode)
        # Captain v2.24.4 B8 closure (install.sh side). Flag-or-env-var path.
        # Accepts 0/1 explicitly OR `--fips-mode` alone (= 1).
        case "${2:-}" in
          0|1)
            FIPS_MODE="$2"
            shift 2
            ;;
          *)
            FIPS_MODE="1"
            shift 1
            ;;
        esac
        ;;
      --cmvp-cert)
        CMVP_CERT="${2:?'--cmvp-cert requires a value, e.g. \"#4985\"'}"
        shift 2
        ;;
      --admin-email)
        ADMIN_EMAIL="${2:?'--admin-email requires a value'}"
        shift 2
        ;;
      --upstream-url)
        UPSTREAM_URL="${2:?'--upstream-url requires a value'}"
        shift 2
        ;;
      --license-key)
        LICENSE_KEY_PATH="${2:?'--license-key requires a path'}"
        shift 2
        ;;
      --namespace)
        NAMESPACE="${2:?'--namespace requires a value'}"
        shift 2
        ;;
      --deploy)
        DEPLOY_MODE="${2:?'--deploy requires a value: demo|production|enterprise'}"
        shift 2
        ;;
      --db-aes-key)
        DB_AES_KEY="${2:?'--db-aes-key requires a value (64-char hex or 44-char base64)'}"
        shift 2
        ;;
      --with-openwebui)  INSTALL_OPENWEBUI=true;  shift ;;
      --with-internal-ca) INSTALL_INTERNAL_CA=true; shift ;;
      --internal-ca-cert)
        INTERNAL_CA_CERT="${2:?'--internal-ca-cert requires a path'}"
        shift 2
        ;;
      --internal-ca-key)
        INTERNAL_CA_KEY="${2:?'--internal-ca-key requires a path'}"
        shift 2
        ;;
      --internal-ca-root)
        INTERNAL_CA_ROOT="${2:?'--internal-ca-root requires a path'}"
        shift 2
        ;;
      --byo-ca-fingerprint)
        INTERNAL_CA_FINGERPRINT="${2:?'--byo-ca-fingerprint requires a sha256 value'}"
        shift 2
        ;;
      --accept-expired-ca)
        INTERNAL_CA_ACCEPT_EXPIRED=true
        shift
        ;;
      --wazuh)           INSTALL_WAZUH=true;     shift ;;
      --offline)         OFFLINE=true;           shift ;;
      --air-gap)         AIR_GAP=true;           shift ;;
      --bundle)
        AIR_GAP_BUNDLE="${2:?'--bundle requires a path to the .tar.zst bundle'}"
        shift 2 ;;
      --non-interactive) NON_INTERACTIVE=true;  shift ;;
      --runtime)
        # Explicit runtime selection. Required in --non-interactive mode if
        # auto-detection finds both Docker and Podman (admin-must-choose rule).
        # Setting YSG_RUNTIME_EXPLICIT=true tells prompt_runtime_choice() to
        # skip the prompt — the admin already chose via CLI flag.
        case "${2:-}" in
          docker|podman|k8s)
            YSG_RUNTIME="$2"; export YSG_RUNTIME
            YSG_RUNTIME_EXPLICIT=true; export YSG_RUNTIME_EXPLICIT
            shift 2
            ;;
          *) log_error "--runtime must be one of: docker, podman, k8s"; exit 1 ;;
        esac
        ;;
      --http-port)
        _raw_http_port="${2:?'--http-port requires a port number (1-65535)'}"
        if ! [[ "$_raw_http_port" =~ ^[0-9]+$ ]] || [[ "$_raw_http_port" -lt 1 || "$_raw_http_port" -gt 65535 ]]; then
          log_error "--http-port must be an integer 1-65535, got: ${_raw_http_port}"
          exit 1
        fi
        if [[ -n "${YASHIGANI_HTTP_PORT:-}" && "${YASHIGANI_HTTP_PORT}" != "$_raw_http_port" ]]; then
          log_info "--http-port flag (${_raw_http_port}) overrides env YASHIGANI_HTTP_PORT (${YASHIGANI_HTTP_PORT})"
        fi
        export YASHIGANI_HTTP_PORT="$_raw_http_port"
        shift 2
        ;;
      --https-port)
        _raw_https_port="${2:?'--https-port requires a port number (1-65535)'}"
        if ! [[ "$_raw_https_port" =~ ^[0-9]+$ ]] || [[ "$_raw_https_port" -lt 1 || "$_raw_https_port" -gt 65535 ]]; then
          log_error "--https-port must be an integer 1-65535, got: ${_raw_https_port}"
          exit 1
        fi
        if [[ -n "${YASHIGANI_HTTPS_PORT:-}" && "${YASHIGANI_HTTPS_PORT}" != "$_raw_https_port" ]]; then
          log_info "--https-port flag (${_raw_https_port}) overrides env YASHIGANI_HTTPS_PORT (${YASHIGANI_HTTPS_PORT})"
        fi
        export YASHIGANI_HTTPS_PORT="$_raw_https_port"
        shift 2
        ;;
      --public-hostname)
        YSG_PUBLIC_HOSTNAME="${2:?'--public-hostname requires a value'}"
        export YSG_PUBLIC_HOSTNAME
        shift 2
        ;;
      --public-ip)
        YSG_PUBLIC_IP="${2:?'--public-ip requires a value'}"
        export YSG_PUBLIC_IP
        shift 2
        ;;
      --skip-preflight)  SKIP_PREFLIGHT=true;   shift ;;
      --skip-pull)       SKIP_PULL=true;         shift ;;
      --upgrade)         UPGRADE=true;           shift ;;
      --reuse-volumes)   REUSE_VOLUMES=true;     shift ;;
      --dry-run)         DRY_RUN=true;           shift ;;
      --agent-bundles)
        AGENT_BUNDLES="${2:?'--agent-bundles requires a value, e.g. langflow,letta'}"
        shift 2
        ;;
      --pki-action)
        PKI_ACTION="${2:?'--pki-action requires: bootstrap|rotate-leaves|rotate-intermediate|rotate-root|status'}"
        shift 2
        ;;
      --root-ca-lifetime-years)
        YASHIGANI_ROOT_CA_LIFETIME_YEARS="${2:?}"; shift 2 ;;
      --intermediate-lifetime-days)
        YASHIGANI_INTERMEDIATE_LIFETIME_DAYS="${2:?}"; shift 2 ;;
      --cert-lifetime-days)
        YASHIGANI_CERT_LIFETIME_DAYS="${2:?}"; shift 2 ;;
      --help|-h)         usage; exit 0 ;;
      *)
        log_error "Unknown option: $1"
        printf "Run with --help for usage.\n" >&2
        exit 1
        ;;
    esac
  done

  # Validate mode
  case "$MODE" in
    compose|k8s|vm) ;;
    *)
      log_error "Invalid --mode '$MODE'. Allowed values: compose, k8s, vm"
      exit 1
      ;;
  esac

  # Validate tls-mode
  case "$TLS_MODE" in
    acme|ca|selfsigned) ;;
    *)
      log_error "Invalid --tls-mode '$TLS_MODE'. Allowed values: acme, ca, selfsigned"
      exit 1
      ;;
  esac

  # Kubernetes uses a different step count
  if [[ "$MODE" == "k8s" ]]; then
    TOTAL_STEPS=10
  fi

  # Air-gap validation
  if [[ "$AIR_GAP" == "true" ]]; then
    if [[ -z "$AIR_GAP_BUNDLE" ]]; then
      log_error "--air-gap requires --bundle <path-to-.tar.zst>"
      printf "  Build the bundle first on a connected host:\n" >&2
      printf "    ./scripts/prepare-airgap-bundle.sh --profile core\n" >&2
      printf "  Then transfer the bundle to this host and run:\n" >&2
      printf "    ./install.sh --air-gap --bundle yashigani-airgap-v2.23.4-core.tar.zst\n" >&2
      exit 1
    fi
    if [[ "$DRY_RUN" != "true" && ! -f "$AIR_GAP_BUNDLE" ]]; then
      log_error "--bundle path does not exist: ${AIR_GAP_BUNDLE}"
      printf "  Ensure the bundle file has been transferred to this host.\n" >&2
      exit 1
    fi
    # Air-gap implies offline — set all skip flags
    OFFLINE=true
    SKIP_PULL=true
  fi
}

# -----------------------------------------------------------------------------
# Command execution wrapper — respects --dry-run and YSG_DEBUG
# -----------------------------------------------------------------------------
run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "$*"
    return 0
  fi
  if [[ "${YSG_DEBUG:-0}" == "1" ]]; then
    "$@"
  else
    "$@"
  fi
}

# Run a command, suppressing output unless YSG_DEBUG=1 or it fails
run_cmd_silent() {
  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "$*"
    return 0
  fi
  if [[ "${YSG_DEBUG:-0}" == "1" ]]; then
    "$@"
  else
    "$@" > /dev/null 2>&1
  fi
}

# -----------------------------------------------------------------------------
# Error handler
# -----------------------------------------------------------------------------
CURRENT_STEP="?"
CURRENT_STEP_NAME="initializing"

on_error() {
  local exit_code=$?
  printf "\n" >&2
  log_error "Installation failed at Step ${CURRENT_STEP} (${CURRENT_STEP_NAME})"
  log_error "Exit code: ${exit_code}"

  # Show last 10 log lines from compose if available
  if [[ "$MODE" != "k8s" ]] && [[ -n "$WORK_DIR" ]] && command -v docker &>/dev/null; then
    local compose_file="${WORK_DIR}/docker/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
      if docker compose -f "$compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
        printf "${C_YELLOW}--- Last 10 log lines ---${C_RESET}\n" >&2
        docker compose -f "$compose_file" logs --tail=10 2>/dev/null >&2 || true
        printf "${C_YELLOW}-------------------------${C_RESET}\n" >&2
      fi
    fi
  fi

  printf "\n${C_YELLOW}Tip: Run with YSG_DEBUG=1 for verbose output${C_RESET}\n" >&2
  exit 1
}

trap on_error ERR

set_step() {
  CURRENT_STEP="$1"
  CURRENT_STEP_NAME="$2"
}

# -----------------------------------------------------------------------------
# Interactive prompt helpers — respect --non-interactive and piped stdin
# -----------------------------------------------------------------------------

# Returns 0 (yes) or 1 (no). Uses default when non-interactive.
prompt_yn() {
  local question="$1"
  local default="${2:-y}"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    [[ "$default" == "y" ]] && return 0 || return 1
  fi

  local hint
  [[ "$default" == "y" ]] && hint="[Y/n]" || hint="[y/N]"

  printf "${C_BOLD}%s %s: ${C_RESET}" "$question" "$hint"
  local answer
  read -r answer </dev/tty 2>/dev/null || answer="$default"
  answer="${answer:-$default}"
  answer="$(echo "$answer" | tr '[:upper:]' '[:lower:]')"
  [[ "$answer" == "y" || "$answer" == "yes" ]]
}

# Prints the entered value (or default) to stdout
prompt_input() {
  local question="$1"
  local default="${2:-}"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    printf "%s" "$default"
    return 0
  fi

  if [[ -n "$default" ]]; then
    printf "${C_BOLD}%s [%s]: ${C_RESET}" "$question" "$default"
  else
    printf "${C_BOLD}%s: ${C_RESET}" "$question"
  fi

  local answer
  read -r answer </dev/tty 2>/dev/null || answer="$default"
  printf "%s" "${answer:-$default}"
}

# -----------------------------------------------------------------------------
# Assert that a command exists in PATH
# -----------------------------------------------------------------------------
require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command not found in PATH: $cmd"
    log_error "Please install '$cmd' and re-run the installer."
    exit 1
  fi
}

# Resolve the compose command based on detected runtime
# Sets COMPOSE_CMD as an array (e.g. "docker compose" or "podman compose")
# Sets YSG_PODMAN_RUNTIME=true if using Podman (for auto-applying override file)
YSG_PODMAN_RUNTIME=false
COMPOSE_CMD=()   # global declaration so ${#COMPOSE_CMD[@]} is safe under set -u before first resolve

resolve_compose_cmd() {
  COMPOSE_CMD=()
  YSG_PODMAN_RUNTIME=false   # reset before resolution — prevents stale env/state bleed

  # ── HARD RUNTIME SEPARATION (maintainer directive 2026-04-29 after 3rd cross-runtime
  # bug: Pentest #95 docker-compose-shim against Podman socket "file name too long",
  # plus prior compose-path-prefix bugs at v2.23.1 #58c rounds 4 + 7) ────────────
  #
  # When YSG_RUNTIME is set explicitly, ONLY native tools for that runtime are
  # acceptable. We REFUSE to fall through to the other runtime's tools — even if
  # they're available — because docker-compose against a Podman socket (and
  # vice versa) consistently produces subtle path / serialisation / format
  # incompatibilities that LOOK like generic compose bugs but are actually
  # cross-runtime contract mismatches.
  #
  # Auto-detect (YSG_RUNTIME unset / =auto) still tries Podman first then Docker,
  # but each branch is self-contained: Podman branch never selects docker-compose,
  # Docker branch never selects podman-compose.
  local _prefer="${YSG_RUNTIME:-auto}"

  # ── Docker-only branch ─────────────────────────────────────────────────────
  if [[ "$_prefer" == "docker" ]]; then
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
      log_error "YSG_RUNTIME=docker requested but Docker daemon is not reachable."
      log_error "Install Docker Desktop or start the Docker daemon and retry."
      log_error "If you meant Podman, set YSG_RUNTIME=podman instead."
      exit 1
    fi
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("docker" "compose")
      YSG_PODMAN_RUNTIME=false
      log_info "Compose tool: docker compose (Docker plugin)"
      return 0
    fi
    if command -v docker-compose >/dev/null 2>&1; then
      COMPOSE_CMD=("docker-compose")
      YSG_PODMAN_RUNTIME=false
      log_info "Compose tool: docker-compose (standalone)"
      return 0
    fi
    log_error "YSG_RUNTIME=docker but no compose tool found. Install:"
    log_error "  • docker compose plugin: https://docs.docker.com/compose/install/"
    log_error "  • OR docker-compose: https://docs.docker.com/compose/install/standalone/"
    exit 1
  fi

  # ── Podman-only branch ─────────────────────────────────────────────────────
  if [[ "$_prefer" == "podman" ]]; then
    if ! command -v podman >/dev/null 2>&1 || ! podman info >/dev/null 2>&1; then
      log_error "YSG_RUNTIME=podman requested but Podman is not reachable."
      log_error "Install Podman + start its socket (rootful: systemctl start podman.socket)."
      log_error "If you meant Docker, set YSG_RUNTIME=docker instead."
      exit 1
    fi
    # podman-compose (Python) FIRST: sequential, stable, native to Podman.
    # We do NOT fall through to docker-compose — passing docker-compose a Podman
    # socket via DOCKER_HOST works for simple cases but breaks on seccomp profile
    # paths (Pentest #95 TM-V231-005), security_opt parsing, and a few other places
    # where docker-compose makes Docker-specific assumptions about the socket.
    if command -v podman-compose >/dev/null 2>&1; then
      COMPOSE_CMD=("podman-compose")
      YSG_PODMAN_RUNTIME=true
      log_info "Compose tool: podman-compose (native, sequential)"
      return 0
    fi
    if podman compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("podman" "compose")
      YSG_PODMAN_RUNTIME=true
      log_info "Compose tool: podman compose (Podman 4+ built-in)"
      return 0
    fi
    log_error "YSG_RUNTIME=podman but no native Podman compose tool found. Install:"
    log_error "  • podman-compose:  pip install podman-compose"
    log_error "  • OR Podman 4+ with built-in compose subcommand"
    log_error ""
    log_error "Do NOT install docker-compose against the Podman socket — that path"
    log_error "is explicitly NOT supported (cross-runtime compatibility issues, see"
    log_error "Pentest #95 TM-V231-005 + v2.23.1 retro #3a-fix)."
    exit 1
  fi

  # ── Auto-detect (YSG_RUNTIME unset or =auto) ───────────────────────────────
  # Prefer Podman for rootless-first security posture. Strict-self-contained:
  # the Podman branch only considers podman-compose / podman compose; the
  # Docker branch only considers docker compose / docker-compose. No mixing.

  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    if command -v podman-compose >/dev/null 2>&1; then
      COMPOSE_CMD=("podman-compose")
      YSG_PODMAN_RUNTIME=true
      log_info "Compose tool: podman-compose (auto-detect)"
      return 0
    fi
    if podman compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("podman" "compose")
      YSG_PODMAN_RUNTIME=true
      log_info "Compose tool: podman compose (auto-detect, built-in)"
      return 0
    fi
    # Podman is reachable but neither podman-compose nor `podman compose` is
    # available. We refuse to silently fall through to docker-compose against
    # the Podman socket (cross-runtime bug pattern). Tell the user.
    log_warn "Podman is installed but no Podman-native compose tool found."
    log_warn "Install podman-compose (pip install podman-compose) for the native"
    log_warn "Podman path, OR set YSG_RUNTIME=docker if you intend to use Docker."
    log_warn "Continuing auto-detect to look for Docker..."
  fi

  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("docker" "compose")
      YSG_PODMAN_RUNTIME=false
      log_info "Compose tool: docker compose (auto-detect, plugin)"
      return 0
    fi
    if command -v docker-compose >/dev/null 2>&1; then
      COMPOSE_CMD=("docker-compose")
      YSG_PODMAN_RUNTIME=false
      log_info "Compose tool: docker-compose (auto-detect, standalone)"
      return 0
    fi
  fi

  # Docker Desktop on macOS without CLI in PATH (only triggered when YSG_RUNTIME
  # is explicitly =docker_desktop_no_cli; never auto-selected).
  if [ "${YSG_RUNTIME:-}" = "docker_desktop_no_cli" ]; then
    local dd_docker=""
    for p in "$HOME/.docker/bin/docker" "/usr/local/bin/com.docker.cli" \
             "/Applications/Docker.app/Contents/Resources/bin/docker"; do
      [ -x "$p" ] && dd_docker="$p" && break
    done
    if [ -n "$dd_docker" ] && $dd_docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("$dd_docker" "compose")
      YSG_PODMAN_RUNTIME=false
      log_info "Compose tool: $dd_docker compose (Docker Desktop, CLI not in PATH)"
      return 0
    fi
  fi

  log_error "No compose command found. Install one of:"
  log_error "  • Docker:  Docker Desktop OR docker + docker compose plugin"
  log_error "  • Podman:  podman + podman-compose (pip install podman-compose)"
  log_error ""
  log_error "Then set YSG_RUNTIME=docker or YSG_RUNTIME=podman to lock the runtime."
  exit 1
}

# =============================================================================
# STEP 0: Banner
# =============================================================================
print_banner() {
  printf "\n"
  printf "${C_BLUE}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_BLUE}║    Yashigani v%-8s Installer                 ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_BLUE}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY-RUN mode — no changes will be made to the system"
    printf "\n"
  fi
}

# =============================================================================
# STEP 1: Detect / bootstrap working directory
# =============================================================================
detect_working_directory() {
  set_step "1" "Detect working directory"
  log_step "1/${TOTAL_STEPS}" "Detecting working directory..."

  local script_path="${BASH_SOURCE[0]:-/dev/stdin}"
  local in_repo=false

  # Case 1: running as a file (not piped), try script's own directory
  if [[ "$script_path" != "/dev/stdin" && -n "$script_path" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "$script_path")" 2>/dev/null && pwd)" || script_dir=""
    if [[ -n "$script_dir" && -f "${script_dir}/docker/docker-compose.yml" ]]; then
      in_repo=true
      WORK_DIR="$script_dir"
      log_info "Using script directory as repository: $WORK_DIR"
    fi
  fi

  # Case 2: current working directory is already the repo
  if [[ "$in_repo" == "false" && -f "./docker/docker-compose.yml" ]]; then
    in_repo=true
    WORK_DIR="$(pwd)"
    log_info "Using current directory as repository: $WORK_DIR"
  fi

  # Case 3: need to bootstrap (curl pipe or neither of the above)
  if [[ "$in_repo" == "false" ]]; then
    bootstrap_repo
  fi

  export WORK_DIR
  log_success "Working directory: $WORK_DIR"
}

bootstrap_repo() {
  log_info "Yashigani source tree not found locally — bootstrapping..."

  # Check if a previous install already lives at YSG_INSTALL_DIR
  if [[ -d "$YSG_INSTALL_DIR" && -f "${YSG_INSTALL_DIR}/docker/docker-compose.yml" ]]; then
    log_info "Existing installation found at: $YSG_INSTALL_DIR"

    if [[ "$UPGRADE" == "true" ]]; then
      log_info "Pulling latest changes (--upgrade)..."
      if [[ "$DRY_RUN" == "true" ]]; then
        dry_print "git -C $YSG_INSTALL_DIR pull --ff-only"
      elif command -v git &>/dev/null && [[ -d "${YSG_INSTALL_DIR}/.git" ]]; then
        git -C "$YSG_INSTALL_DIR" pull --ff-only
      fi
    elif [[ "$NON_INTERACTIVE" == "true" ]]; then
      log_warn "Existing installation found. Pass --upgrade to update it."
    else
      if prompt_yn "Existing installation found at $YSG_INSTALL_DIR. Pull latest changes?" "y"; then
        UPGRADE=true
        if command -v git &>/dev/null && [[ -d "${YSG_INSTALL_DIR}/.git" ]]; then
          git -C "$YSG_INSTALL_DIR" pull --ff-only
        fi
      fi
    fi

    WORK_DIR="$YSG_INSTALL_DIR"
    return 0
  fi

  require_cmd "curl"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "git clone --depth 1 --branch v${YASHIGANI_VERSION} $YASHIGANI_REPO_URL $YSG_INSTALL_DIR"
    WORK_DIR="$YSG_INSTALL_DIR"
    return 0
  fi

  mkdir -p "$YSG_INSTALL_DIR"

  if command -v git &>/dev/null; then
    log_info "Cloning repository (v${YASHIGANI_VERSION})..."
    if git clone --depth 1 --branch "v${YASHIGANI_VERSION}" \
        "$YASHIGANI_REPO_URL" "$YSG_INSTALL_DIR" 2>&1; then
      log_success "Repository cloned to $YSG_INSTALL_DIR"
    else
      log_warn "git clone failed — falling back to tarball download"
      download_tarball
    fi
  else
    log_info "git not found — downloading tarball"
    download_tarball
  fi

  WORK_DIR="$YSG_INSTALL_DIR"
}

download_tarball() {
  require_cmd "tar"

  # V232-NEG04: never use /tmp — use the install dir's own work subdir so all
  # temporary files stay within the operator-controlled install tree.
  local _dl_work_dir
  _dl_work_dir="${YSG_INSTALL_DIR}/.ysg_work"
  mkdir -p "$_dl_work_dir"
  trap 'rm -rf "${YSG_INSTALL_DIR}/.ysg_work"' EXIT

  local tmp_tar
  tmp_tar="$(mktemp "${_dl_work_dir}/yashigani-XXXXXX.tar.gz")"
  local tmp_dir
  tmp_dir="$(mktemp -d "${_dl_work_dir}/yashigani-extract-XXXXXX")"

  log_info "Downloading tarball: $YASHIGANI_TARBALL_URL"
  if ! curl -sSL --fail --retry 3 -o "$tmp_tar" "$YASHIGANI_TARBALL_URL"; then
    log_error "Tarball download failed: $YASHIGANI_TARBALL_URL"
    rm -rf "$tmp_tar" "$tmp_dir"
    exit 1
  fi

  log_info "Extracting to $YSG_INSTALL_DIR ..."
  tar -xzf "$tmp_tar" -C "$tmp_dir"
  rm -f "$tmp_tar"

  # Tarball typically contains a single top-level directory
  local extracted_name
  extracted_name="$(ls "$tmp_dir" | head -1)"
  if [[ -n "$extracted_name" && -d "${tmp_dir}/${extracted_name}" ]]; then
    # Move contents into YSG_INSTALL_DIR
    find "${tmp_dir}/${extracted_name}" -maxdepth 1 -mindepth 1 \
      -exec mv {} "$YSG_INSTALL_DIR/" \;
  else
    log_error "Unexpected tarball structure; cannot locate extracted files"
    rm -rf "$tmp_dir"
    exit 1
  fi

  rm -rf "$tmp_dir"
  log_success "Tarball extracted to $YSG_INSTALL_DIR"
}

# =============================================================================
# STEP 2: Source platform-detect.sh
# =============================================================================
source_platform_detect() {
  set_step "2" "Source platform-detect.sh"
  log_step "2/${TOTAL_STEPS}" "Loading platform detection..."

  local detect_script="${WORK_DIR}/scripts/platform-detect.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "source $detect_script"
    # Provide fallback values so later steps do not break
    YSG_OS="${YSG_OS:-linux}"
    YSG_ARCH="${YSG_ARCH:-x86_64}"
    YSG_RUNTIME="${YSG_RUNTIME:-docker}"
    YSG_GPU_TYPE="${YSG_GPU_TYPE:-none}"
    YSG_GPU_NAME="${YSG_GPU_NAME:-}"
    YSG_GPU_VRAM_MB="${YSG_GPU_VRAM_MB:-0}"
    YSG_GPU_COMPUTE="${YSG_GPU_COMPUTE:-none}"
    return 0
  fi

  if [[ ! -f "$detect_script" ]]; then
    log_error "Platform detection script not found: $detect_script"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "$detect_script"
  log_success "Platform detection loaded"
}

# =============================================================================
# STEP 3: Print platform summary
# =============================================================================
print_platform_summary() {
  set_step "3" "Platform summary"
  log_step "3/${TOTAL_STEPS}" "Platform summary"

  # --- Interactive fallback if detection failed ---
  if [[ "$NON_INTERACTIVE" != "true" && -t 0 ]]; then
    _interactive_platform_fallback
  fi

  # --- Admin-must-choose-runtime prompt (maintainer directive 2026-04-29) ---
  # Always runs; the function itself handles non-interactive vs interactive
  # branching and respects YSG_RUNTIME_EXPLICIT (set by --runtime CLI flag
  # or pre-existing env var).
  prompt_runtime_choice

  printf "\n"
  printf "  %-22s %s\n" "OS:"           "${YSG_OS:-unknown} (${YSG_DISTRO:-unknown})"
  printf "  %-22s %s\n" "Architecture:" "${YSG_ARCH:-unknown}"
  printf "  %-22s %s\n" "Runtime:"      "${YSG_RUNTIME:-unknown} (compose: ${YSG_COMPOSE:-unknown})"
  printf "  %-22s %s\n" "Deploy mode:"  "$MODE"
  printf "  %-22s %s\n" "Domain:"       "${DOMAIN:-(not set)}"
  printf "  %-22s %s\n" "TLS mode:"     "$TLS_MODE"
  if [[ "$MODE" == "k8s" ]]; then
    printf "  %-22s %s\n" "Namespace:"  "$NAMESPACE"
  fi
  if [[ "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    printf "  %-22s %s\n" "GPU:"        "${YSG_GPU_NAME:-detected}"
    printf "  %-22s %s\n" "GPU memory:" "$(_format_gpu_vram)"
    printf "  %-22s %s\n" "GPU compute:" "${YSG_GPU_COMPUTE:-unknown}"
  else
    printf "  %-22s %s\n" "GPU:"        "none detected"
  fi
  printf "\n"
  _print_model_recommendations
}

_format_gpu_vram() {
  local vram_mb="${YSG_GPU_VRAM_MB:-0}"
  if [ "$vram_mb" -ge 1024 ]; then
    printf "%.1f GB" "$(awk "BEGIN { printf \"%.1f\", ${vram_mb}/1024 }")"
  else
    printf "%d MB" "$vram_mb"
  fi
}

_print_model_recommendations() {
  local vram="${YSG_GPU_VRAM_MB:-0}"
  if [ "$vram" -eq 0 ]; then return; fi
  printf "  ${C_BOLD}Recommended local models for your hardware:${C_RESET}\n"
  if [ "$vram" -ge 49152 ]; then
    printf "    - qwen3:235b-a22b, llama4:scout, deepseek-v3 (large models)\n"
  elif [ "$vram" -ge 32768 ]; then
    printf "    - qwen3:30b-a3b, llama4:scout, mistral-large\n"
  elif [ "$vram" -ge 16384 ]; then
    printf "    - qwen3:30b-a3b, llama3.1:8b, mistral:7b\n"
  elif [ "$vram" -ge 8192 ]; then
    printf "    - qwen2.5:3b (inspection), llama3.1:8b\n"
  else
    printf "    - qwen2.5:3b (inspection only), CPU inference for others\n"
  fi
  printf "\n"
}

# =============================================================================
# Runtime choice prompt — admin always picks the runtime
# =============================================================================
# Per feedback_runtime_choice.md (maintainer directive): admin ALWAYS picks the
# container runtime, even when only one is detected. Default pre-selection
# is Podman (rootless-first security posture). Non-interactive mode: require
# YSG_RUNTIME explicit (--runtime CLI flag or env var); error out otherwise.
#
# This runs AFTER source_platform_detect.sh has set YSG_DOCKER_AVAILABLE +
# YSG_PODMAN_AVAILABLE booleans and the auto-pick suggestion in YSG_RUNTIME.
prompt_runtime_choice() {
  local detected="${YSG_RUNTIME:-none}"
  local docker_avail="${YSG_DOCKER_AVAILABLE:-false}"
  local podman_avail="${YSG_PODMAN_AVAILABLE:-false}"
  local docker_running="${YSG_DOCKER_RUNNING:-false}"
  local podman_running="${YSG_PODMAN_RUNNING:-false}"

  # If admin set --runtime / YSG_RUNTIME explicitly, that wins. Verify the
  # chosen runtime is actually installed; refuse with clear message if not.
  if [[ "${YSG_RUNTIME_EXPLICIT:-false}" == "true" ]]; then
    log_info "Runtime explicitly set: $detected (skipping prompt)"
    return 0
  fi

  # Non-interactive: require explicit choice. Refuse to auto-pick under the
  # admin-must-choose rule. Helpful message tells the operator how to set it.
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ "$docker_avail" == "true" && "$podman_avail" == "true" ]]; then
      log_error "Both Docker and Podman are installed — admin must choose explicitly."
      log_error "Re-run with --runtime docker  OR  --runtime podman"
      log_error "(or set YSG_RUNTIME=docker / YSG_RUNTIME=podman in the environment)"
      exit 1
    fi
    # Only one detected — auto-pick is acceptable in non-interactive mode.
    log_info "Non-interactive mode: runtime auto-selected = $detected"
    return 0
  fi

  # ── Interactive: ALWAYS prompt the admin ────────────────────────────────
  printf "\n"
  printf "  ┌────────────────────────────────────────────────────────────────┐\n"
  printf "  │  Container runtime — admin must choose                         │\n"
  printf "  └────────────────────────────────────────────────────────────────┘\n"
  printf "\n"
  printf "  Detected on this host:\n"

  local podman_status="not installed"
  if [[ "$podman_avail" == "true" ]]; then
    podman_status="installed"
    [[ "$podman_running" == "true" ]] && podman_status="installed + running"
  fi
  local docker_status="not installed"
  if [[ "$docker_avail" == "true" ]]; then
    docker_status="installed"
    [[ "$docker_running" == "true" ]] && docker_status="installed + running"
  fi

  printf "    Podman: %s\n" "$podman_status"
  printf "    Docker: %s\n" "$docker_status"
  printf "\n"
  printf "  Yashigani supports both — pick the one you want this install to use.\n"
  printf "  Podman is recommended (rootless-first, daemonless, more secure posture).\n"
  printf "\n"

  # Build the menu showing the actual options. Podman first (default).
  local default_choice="1"
  printf "    1) Podman   "
  if [[ "$podman_avail" != "true" ]]; then
    printf "(NOT installed — pick this only if you'll install podman+podman-compose)\n"
  elif [[ "$podman_running" != "true" ]]; then
    printf "(installed but not running — install will start the socket)\n"
  else
    printf "(installed + running — recommended)\n"
  fi

  printf "    2) Docker   "
  if [[ "$docker_avail" != "true" ]]; then
    printf "(NOT installed — pick this only if you'll install docker+compose)\n"
  elif [[ "$docker_running" != "true" ]]; then
    printf "(installed but daemon not running — start it before continuing)\n"
  else
    printf "(installed + running)\n"
  fi

  printf "    3) Kubernetes (Helm chart, advanced — Docker Desktop K8s, kind, k3s, prod cluster)\n"
  printf "\n"
  printf "  Choice [1-3] (default: 1 / Podman): "

  local rt_choice
  if ! read -r rt_choice </dev/tty 2>/dev/null; then
    rt_choice=""
  fi
  rt_choice="${rt_choice:-$default_choice}"

  case "$rt_choice" in
    1) YSG_RUNTIME=podman ;;
    2) YSG_RUNTIME=docker ;;
    3) YSG_RUNTIME=k8s ;;
    *) log_warn "Invalid choice — defaulting to Podman"; YSG_RUNTIME=podman ;;
  esac
  export YSG_RUNTIME

  # Sanity-check the chosen runtime is actually installed. If not, warn loud
  # so the admin knows the install will exit at compose-cmd resolution.
  case "$YSG_RUNTIME" in
    podman)
      [[ "$podman_avail" != "true" ]] && \
        log_warn "Podman is not installed yet. Install it before re-running install.sh,"
      [[ "$podman_avail" != "true" ]] && \
        log_warn "or set YSG_RUNTIME=docker if you intended to use Docker."
      ;;
    docker)
      [[ "$docker_avail" != "true" ]] && \
        log_warn "Docker is not installed yet. Install Docker Desktop or docker engine"
      [[ "$docker_avail" != "true" ]] && \
        log_warn "before re-running install.sh."
      ;;
    k8s)
      log_info "Kubernetes runtime selected — install.sh will use helm install path"
      ;;
  esac

  printf "\n"
  log_success "Runtime selected: $YSG_RUNTIME"
}

_interactive_platform_fallback() {
  local needs_prompt=false
  if [[ "${YSG_OS:-unknown}" == "unknown" || "${YSG_RUNTIME:-none}" == "none" ]]; then
    needs_prompt=true
  fi
  if [[ "$needs_prompt" != "true" && "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    return
  fi
  if [[ "$needs_prompt" == "true" ]]; then
    printf "\n"
    log_warn "Some platform values could not be detected automatically."
    printf "\n"
  fi
  if [[ "${YSG_OS:-unknown}" == "unknown" ]]; then
    printf "  Could not detect your operating system. Please select:\n"
    printf "    1) Linux (Ubuntu / Debian)\n"
    printf "    2) Linux (RHEL / CentOS / Fedora)\n"
    printf "    3) Linux (Alpine)\n"
    printf "    4) Linux (Arch)\n"
    printf "    5) macOS\n"
    printf "  Choice [1-5]: "
    read -r os_choice
    case "$os_choice" in
      1) YSG_OS=linux; YSG_DISTRO=ubuntu ;; 2) YSG_OS=linux; YSG_DISTRO=rhel ;;
      3) YSG_OS=linux; YSG_DISTRO=alpine ;; 4) YSG_OS=linux; YSG_DISTRO=arch ;;
      5) YSG_OS=macos; YSG_DISTRO=macos ;;
      *) log_warn "Invalid — defaulting to Linux"; YSG_OS=linux; YSG_DISTRO=ubuntu ;;
    esac
    printf "\n"
  fi
  if [[ "${YSG_RUNTIME:-none}" == "none" || "${YSG_RUNTIME:-}" == "unknown" ]]; then
    printf "  Could not detect a container runtime. Please select:\n"
    printf "    1) Docker (Docker Engine / Docker Desktop)\n"
    printf "    2) Podman\n"
    printf "  Choice [1-2]: "
    read -r rt_choice
    case "$rt_choice" in
      1) YSG_RUNTIME=docker ;; 2) YSG_RUNTIME=podman ;;
      *) log_warn "Invalid — defaulting to Docker"; YSG_RUNTIME=docker ;;
    esac
    printf "\n"
  fi
  if [[ "${YSG_GPU_TYPE:-none}" == "none" ]]; then
    printf "  No GPU was detected automatically. Do you have a GPU?\n"
    printf "    1) NVIDIA GPU (CUDA)\n"
    printf "    2) Apple Silicon (M1 / M2 / M3 / M4)\n"
    printf "    3) AMD GPU (ROCm)\n"
    printf "    4) No GPU / CPU only\n"
    printf "  Choice [1-4]: "
    read -r gpu_choice
    case "$gpu_choice" in
      1)
        YSG_GPU_TYPE=nvidia; YSG_GPU_COMPUTE=cuda; YSG_GPU_NAME="NVIDIA (user-reported)"
        printf "  Enter GPU VRAM in GB (e.g. 8, 16, 24, 48): "; read -r vram_gb
        [[ "${vram_gb:-0}" =~ ^[0-9]+$ ]] || vram_gb=0
        YSG_GPU_VRAM_MB=$(( ${vram_gb:-0} * 1024 )) ;;
      2)
        YSG_GPU_TYPE=apple_metal; YSG_GPU_COMPUTE=metal
        if command -v sysctl >/dev/null 2>&1; then
          local ram_bytes; ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
          YSG_GPU_VRAM_MB=$(( ram_bytes / 1024 / 1024 ))
          YSG_GPU_NAME="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")"
        else
          YSG_GPU_NAME="Apple Silicon (user-reported)"
          printf "  Enter total system RAM in GB: "; read -r ram_gb
          [[ "${ram_gb:-8}" =~ ^[0-9]+$ ]] || ram_gb=8
          YSG_GPU_VRAM_MB=$(( ${ram_gb:-8} * 1024 ))
        fi ;;
      3)
        YSG_GPU_TYPE=amd_rocm; YSG_GPU_COMPUTE=rocm; YSG_GPU_NAME="AMD GPU (user-reported)"
        printf "  Enter GPU VRAM in GB: "; read -r vram_gb
        [[ "${vram_gb:-0}" =~ ^[0-9]+$ ]] || vram_gb=0
        YSG_GPU_VRAM_MB=$(( ${vram_gb:-0} * 1024 )) ;;
      4|*) YSG_GPU_TYPE=none ;;
    esac
    printf "\n"
  fi
}

# =============================================================================
# STEP 4: Install runtime (vm mode only)
# =============================================================================
install_runtime() {
  set_step "4" "Install runtime"

  if [[ "$MODE" != "vm" ]]; then
    return 0
  fi

  log_step "4/${TOTAL_STEPS}" "Installing container runtime (vm mode)..."

  local runtime_script="${WORK_DIR}/scripts/install-runtime.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $runtime_script"
    return 0
  fi

  if [[ ! -f "$runtime_script" ]]; then
    log_error "Runtime installation script not found: $runtime_script"
    exit 1
  fi

  bash "$runtime_script"
  log_success "Container runtime installed"
}

# =============================================================================
# STEP 4b: Installer pre-flight hard-stop checks (P0-12)
#
# These checks run before the main preflight script and will EXIT with a
# copy-pasteable remediation block if the condition is not met.  The installer
# body runs zero sudo — these gates ensure the operator has done any required
# privileged setup before we start.
# =============================================================================
check_installer_preflight() {
  if [[ "$SKIP_PREFLIGHT" == "true" || "$DRY_RUN" == "true" ]]; then
    return 0
  fi

  # Only applies to compose / docker runtimes — K8s manages its own RBAC.
  if [[ "${MODE:-}" == "k8s" ]]; then
    return 0
  fi

  # --- Check 1: docker group membership (Docker runtime only) ---------------
  # The installer body never runs sudo, so the current user must be able to
  # reach the Docker daemon without elevated privilege.
  if [[ "${YSG_RUNTIME:-}" == "docker" ]]; then
    if ! docker info >/dev/null 2>&1; then
      printf "\nPre-flight failed: your user cannot run docker without sudo.\n\n"
      printf "  sudo groupadd docker          # creates the group if it doesn't exist\n"
      printf "  sudo usermod -aG docker \$USER # adds you to the group\n"
      printf "  newgrp docker                 # activate without logout (or log out and back in)\n\n"
      printf "Then re-run this installer.\n\n"
      exit 1
    fi
  fi

  # --- Check 1b: Podman disk space preflight (#3h-fix) ----------------------
  # Warn if Podman has a large reclaimable corpus (>= 50 GB). A "no space left
  # on device" mid-build is one of the hardest errors to diagnose because the
  # build output is swallowed by the tail-1 pipe. This preflight surfaces the
  # issue before any pull/build begins so the admin can prune first.
  # Only runs for Podman runtime; Docker has its own storage manager and the
  # same `podman system df` format is not guaranteed under Docker.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]]; then
    if command -v podman >/dev/null 2>&1; then
      local _reclaimable_raw
      _reclaimable_raw="$(podman system df --format '{{.Reclaimable}}' 2>/dev/null | \
        grep -oE '[0-9]+(\.[0-9]+)?[[:space:]]*(GB|GiB)' | head -1 || echo "")"
      if [[ -n "$_reclaimable_raw" ]]; then
        # Extract numeric value (drop unit; treat GiB == GB for warning threshold).
        local _reclaimable_gb
        _reclaimable_gb="$(echo "$_reclaimable_raw" | grep -oE '[0-9]+(\.[0-9]+)?' | head -1)"
        # awk comparison: warn if reclaimable >= 50 GB.
        if awk "BEGIN { exit !($_reclaimable_gb >= 50) }"; then
          printf "\n"
          printf "${C_YELLOW}[WARN] Podman has %.0f GB reclaimable storage.${C_RESET}\n" "$_reclaimable_gb"
          printf "       Run 'podman system prune -af' to free space before the image pull/build.\n"
          printf "       A 'no space left on device' mid-build can leave the stack in a broken state.\n\n"
        fi
      fi
    fi
  fi

  # --- Check 1c: rootless Podman linger pre-flight ---------------------------
  # loginctl linger must be enabled for the install user BEFORE install runs;
  # without it the user's systemd instance is killed on logout and the
  # yashigani.service unit cannot start containers at boot.
  # The installer body never runs sudo (feedback_audience_sysadmins), so this
  # is a pure warning — the operator must enable linger manually as a
  # pre-flight step. We pause briefly so the operator can Ctrl-C and act.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]] \
     && [[ "$(id -u)" != "0" ]]; then
    local _linger_val
    _linger_val="$(loginctl show-user "$USER" --property=Linger --value 2>/dev/null || echo "no")"
    if [[ "$_linger_val" != "yes" ]]; then
      printf "\n"
      printf "============================================================\n"
      printf "PRE-FLIGHT WARNING\n"
      printf "============================================================\n"
      printf "Rootless Podman install detected.\n"
      printf "Linger is NOT enabled for user: %s\n" "$USER"
      printf "\n"
      printf "Without linger, containers will not auto-start on boot.\n"
      printf "\n"
      printf "To enable linger BEFORE this install (recommended):\n"
      printf "\n"
      printf "    sudo loginctl enable-linger %s\n" "$USER"
      printf "\n"
      printf "Then re-run install.sh.\n"
      printf "\n"
      printf "Continuing without linger — containers will install but will\n"
      printf "require manual \`loginctl enable-linger\` and restart to gain\n"
      printf "auto-start capability.\n"
      printf "============================================================\n"
      printf "\n"
      sleep 3
    fi
  fi

  # --- Check 1d: stale YASHIGANI_INTERNAL_BEARER env-var -------------------
  # If the env-var is set in the calling shell but the secret file is absent or
  # empty, the operator is running in a stale environment from a prior install.
  # The containers will NOT pick up the generated secret and internal routing
  # will break silently. Exit early with a clear remediation message.
  if [[ -n "${YASHIGANI_INTERNAL_BEARER:-}" ]]; then
    local _bearer_file="${WORK_DIR}/docker/secrets/yashigani_internal_bearer"
    if [[ ! -s "$_bearer_file" ]]; then
      printf "\nPre-flight failed: stale YASHIGANI_INTERNAL_BEARER env-var detected.\n\n"
      printf "  The env-var is set in your shell but docker/secrets/yashigani_internal_bearer\n"
      printf "  is absent or empty. This indicates a stale environment from a prior install.\n\n"
      printf "  Remediation: rerun in a fresh shell or:\n"
      printf "      unset YASHIGANI_INTERNAL_BEARER\n\n"
      printf "  Then re-run this installer.\n\n"
      exit 1
    fi
  fi

  # --- Check 2: bind-mount directory ownership (UID 1001) -------------------
  # PKI issuer and backoffice services run as UID 1001 inside containers and
  # write to the bind-mounted secrets dir.
  #
  # Fix #85 (non-interactive/CI): the installer now creates and chowns all
  # bind-mount dirs automatically for every runtime path, eliminating the
  # manual pre-step that was required in CI and cloud-init environments.
  #
  # Docker / rootful Podman (id -u == 0): mkdir + chown 1001:1001 directly.
  #
  # Podman rootless (id -u != 0): mkdir as the current user (we own WORK_DIR),
  # then `podman unshare chown 1001:1001` to remap container UID 1001 to the
  # correct subuid on the host. If `podman unshare` is unavailable (remote
  # client), fall back with a warning — the dir will be uid-remapped on first
  # container write. Only falls through to the hard-stop error block when the
  # directory still can't be created at all (e.g. WORK_DIR itself is unwritable).
  local _bm_failed=0
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # Compute the expected host UID for container UID 1001.
  # Podman rootless: read /etc/subuid for the current user and add 1000.
  # Docker / rootful: literal 1001.
  local _expected_uid="1001"
  local _is_rootless_podman=false
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]] && [[ "$(id -u)" != "0" ]]; then
    _is_rootless_podman=true
    local _subuid_start
    _subuid_start="$(awk -F: -v u="$(id -un)" '$1==u{print $2; exit}' /etc/subuid 2>/dev/null || echo "")"
    if [[ -n "$_subuid_start" ]]; then
      # container UID 1001 = subuid_start + 1001 - 1
      _expected_uid=$(( _subuid_start + 1001 - 1 ))
    fi
  fi

  # Auto-create bind-mount dirs for all runtime paths (fix #85).
  for _bm_dir in "${WORK_DIR}/docker/data" "${WORK_DIR}/docker/certs" "${WORK_DIR}/docker/logs"; do
    if [[ ! -d "$_bm_dir" ]]; then
      if ! mkdir -p "$_bm_dir" 2>/dev/null; then
        log_error "Cannot create bind-mount directory: $_bm_dir"
        log_error "Check that ${WORK_DIR}/docker/ is writable by the current user."
        _bm_failed=1
        continue
      fi
      log_info "Created bind-mount dir: $_bm_dir"
    fi

    if [[ "$_is_rootless_podman" == "true" ]]; then
      # Podman rootless: remap container UID 1001 to the subuid-mapped host UID
      # via podman unshare. This is idempotent — already-chowned dirs are a no-op.
      # shellcheck disable=SC2012
      local _dir_uid
      _dir_uid="$(ls -nd "$_bm_dir" 2>/dev/null | awk '{print $3}')"
      if [[ "$_dir_uid" != "$_expected_uid" ]]; then
        if podman unshare chown 1001:1001 "$_bm_dir" 2>/dev/null; then
          log_info "podman unshare chown 1001:1001 applied to $_bm_dir"
        else
          log_warn "podman unshare unavailable — $_bm_dir will be uid-mapped on first container write"
          # Not a hard failure: Podman rootless will remap ownership at mount time.
        fi
      fi
    else
      # Docker / rootful Podman: direct chown to container UID 1001.
      # macOS+Docker (Colima virtiofs): host-side chown to arbitrary UIDs is
      # restricted by macOS kernel — only root can chown to non-self UIDs.
      # Colima's virtiofs UID mapping means containers already see bind-mounted
      # dirs as root:root inside the VM; after an ephemeral-container chown the
      # container view reflects UID 1001 even though the macOS host still shows
      # the installer UID. Do not attempt host chown on macOS — it will always
      # fail with EPERM, and the failure is spurious (PKI writes succeed).
      if [[ "${YSG_OS:-}" == "macos" ]]; then
        log_info "macOS+Docker: skipping host chown for $_bm_dir (virtiofs UID mapping — PKI container will see UID 1001)"
      else
        # Non-root Docker caller: delegate to _do_chown (V240-002 refactor).
        # _do_chown handles: direct chown attempt → docker_run ephemeral container
        # fallback. The 5th arg passes $_bm_dir as _mount_base (S5/S7): the helper
        # mounts $_bm_dir to /s and chowns /s/$(basename $_bm_dir) — correct because
        # each $_bm_dir IS the mount root (not a file inside docker/secrets).
        # TM-004 (accepted): docker socket grants effective root inside container;
        # same accepted risk as the pre-V240-002 inline block.
        # Error propagation: _do_chown logs + returns 1 on failure; set flag here.
        local _dir_uid
        # shellcheck disable=SC2012
        _dir_uid="$(ls -nd "$_bm_dir" 2>/dev/null | awk '{print $3}')"
        if [[ "$_dir_uid" != "1001" ]]; then
          # S7: _do_chown uses /s mount convention internally (not legacy /t).
          # S5: pass $_bm_dir as _mount_base (5th arg) — target is the dir itself.
          if ! _do_chown "1001:1001" "$_bm_dir" "$(basename "$_bm_dir")" "" "$_bm_dir"; then
            log_error "Cannot chown $_bm_dir to 1001:1001 (direct chown and container fallback both failed)."
            log_error "Ensure your user is in the docker group, or run the installer as root:"
            log_error "  sudo groupadd docker && sudo usermod -aG docker \$USER && newgrp docker"
            log_error "  # OR: sudo bash install.sh"
            _bm_failed=1
          fi
        fi
      fi
    fi
  done

  # Verify the dirs exist and have the expected owner after the auto-create pass.
  for _bm_dir in "${WORK_DIR}/docker/data" "${WORK_DIR}/docker/certs" "${WORK_DIR}/docker/logs"; do
    if [[ ! -d "$_bm_dir" ]]; then
      _bm_failed=1
      break
    fi
    # macOS+Docker (Colima virtiofs): host UID will never show 1001 because
    # macOS restricts chown to non-self UIDs. virtiofs handles the mapping at
    # mount time — containers see UID 1001. Skip the host-UID assertion.
    if [[ "${YSG_OS:-}" == "macos" ]]; then
      log_info "macOS+Docker: bind-mount UID assertion skipped for $_bm_dir (virtiofs UID mapping)"
      continue
    fi
    # shellcheck disable=SC2012
    local _uid
    _uid="$(ls -nd "$_bm_dir" 2>/dev/null | awk '{print $3}')"
    # For Podman rootless where unshare was unavailable, accept installer UID too —
    # the dir will be re-owned on first container write.
    if [[ "$_is_rootless_podman" == "true" ]]; then
      if [[ "$_uid" != "$_expected_uid" && "$_uid" != "$(id -u)" ]]; then
        _bm_failed=1
        break
      fi
    else
      if [[ "$_uid" != "1001" ]]; then
        _bm_failed=1
        break
      fi
    fi
  done

  if [[ "$_bm_failed" -eq 1 ]]; then
    printf "\nPre-flight failed: bind-mount directories could not be created or chowned.\n\n"
    if [[ "$_is_rootless_podman" == "true" ]]; then
      printf "Manual fix:\n"
      printf "  cd %s/docker\n" "${WORK_DIR}"
      printf "  mkdir -p data certs logs\n"
      printf "  podman unshare chown 1001:1001 data certs logs\n\n"
      printf "(Podman rootless: 'podman unshare chown' maps container UID 1001 to the\n"
      printf " correct host subuid. Do NOT use 'sudo chown' for rootless Podman.)\n\n"
    else
      printf "Manual fix:\n"
      printf "  cd %s/docker\n" "${WORK_DIR}"
      printf "  mkdir -p data certs logs\n"
      printf "  sudo chown -R 1001:1001 data certs logs\n\n"
    fi
    printf "Then re-run this installer.\n\n"
    exit 1
  fi
}

# =============================================================================
# STEP 5: Preflight checks
# =============================================================================
run_preflight() {
  set_step "5" "Preflight checks"

  if [[ "$SKIP_PREFLIGHT" == "true" ]]; then
    log_warn "Skipping preflight checks (--skip-preflight)"
    return 0
  fi

  log_step "5/${TOTAL_STEPS}" "Running preflight checks..."

  local preflight_script="${WORK_DIR}/scripts/preflight.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $preflight_script"
    return 0
  fi

  if [[ ! -f "$preflight_script" ]]; then
    log_error "Preflight script not found: $preflight_script"
    exit 1
  fi

  # BUG-B+-001: on a re-run against an existing running stack, ports 80/443 are
  # bound by the running Caddy container. Passing --skip-ports tells preflight.sh
  # to accept those ports as "already ours" rather than treating them as conflicts.
  # Detection: secrets dir populated + at least one compose container running.
  local _preflight_args=()
  if _is_existing_yashigani_running; then
    log_info "Existing Yashigani install detected — skipping port-in-use checks (BUG-B+-001)"
    _preflight_args+=("--skip-ports")
  fi

  # shellcheck disable=SC2068  # intentional: empty array expands to nothing
  bash "$preflight_script" ${_preflight_args[@]+"${_preflight_args[@]}"}
  log_success "Preflight checks passed"
}

# _is_existing_yashigani_running — BUG-B+-001 helper
# Returns 0 (true) if: secrets dir is populated AND at least one yashigani
# compose container is currently running under either Docker or Podman.
# Used by run_preflight (skip port check) and check_existing_installation
# (skip contaminated-volume check on additive re-run).
_is_existing_yashigani_running() {
  local _secrets_dir="${WORK_DIR}/docker/secrets"
  # Secrets dir must exist and contain the root CA cert (written by PKI bootstrap;
  # indicates a completed prior install, not just a partial one).
  [[ -f "${_secrets_dir}/ca_root.crt" ]] || return 1

  # Check whether any compose containers for this project are running.
  local _compose_file="${WORK_DIR}/docker/docker-compose.yml"
  [[ -f "$_compose_file" ]] || return 1

  # macOS does not ship `timeout` (GNU coreutils) — use docker/podman ps directly.
  # The socket is local so hang risk is low. Use label filter (fastest — no compose
  # parsing) as primary, compose ps as fallback.
  # Label filter: works even without compose CLI installed.
  if docker ps --filter 'label=com.docker.compose.project=docker' \
       --format '{{.Names}}' 2>/dev/null | grep -q .; then
    return 0
  fi
  if podman ps --filter 'label=io.podman.compose.project=docker' \
       --format '{{.Names}}' 2>/dev/null | grep -q .; then
    return 0
  fi
  # Compose ps fallback (slower — requires parsing the compose file)
  if docker compose -f "$_compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
    return 0
  fi
  if podman compose -f "$_compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
    return 0
  fi
  return 1
}

# =============================================================================
# =============================================================================
# STEP 5b: Deployment mode selection
# =============================================================================
select_deploy_mode() {
  # Already set via --deploy flag
  if [[ -n "$DEPLOY_MODE" ]]; then
    case "$DEPLOY_MODE" in
      demo|production|enterprise) ;;
      *)
        log_error "Invalid --deploy value '$DEPLOY_MODE'. Use: demo, production, enterprise"
        exit 1
        ;;
    esac
    log_info "Deployment mode: ${DEPLOY_MODE} (--deploy flag)"
    _apply_deploy_defaults
    return 0
  fi

  # Non-interactive without --deploy defaults to demo
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    DEPLOY_MODE="demo"
    log_info "Deployment mode: demo (non-interactive default)"
    _apply_deploy_defaults
    return 0
  fi

  printf "\n"
  printf "${C_BOLD}How would you like to deploy Yashigani?${C_RESET}\n\n"
  printf "    1) Demo / Open Source — quick evaluation on this machine (localhost, self-signed TLS)\n"
  printf "    2) Production — Docker Compose on a real server (Starter / Professional / Professional Plus)\n"
  printf "    3) Enterprise — Kubernetes with Helm charts (Enterprise licence)\n"
  printf "\n"
  printf "${C_BOLD}  Choice [1]: ${C_RESET}"

  local choice
  read -r choice </dev/tty 2>/dev/null || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    1) DEPLOY_MODE="demo" ;;
    2) DEPLOY_MODE="production" ;;
    3) DEPLOY_MODE="enterprise" ;;
    *) log_warn "Invalid choice — defaulting to Demo"; DEPLOY_MODE="demo" ;;
  esac

  printf "\n"
  log_success "Deployment mode: ${DEPLOY_MODE}"
  _apply_deploy_defaults
}

_apply_deploy_defaults() {
  # When --mode was passed explicitly on argv, never overwrite it here (P1 #3bg).
  case "$DEPLOY_MODE" in
    demo)
      [[ "$MODE_EXPLICIT" -eq 0 ]] && MODE="compose"
      DOMAIN="${DOMAIN:-localhost}"
      TLS_MODE="selfsigned"
      SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-false}"
      ;;
    production)
      [[ "$MODE_EXPLICIT" -eq 0 ]] && MODE="compose"
      ;;
    enterprise)
      [[ "$MODE_EXPLICIT" -eq 0 ]] && MODE="k8s"
      TOTAL_STEPS=10
      ;;
  esac

  # Offline mode forces self-signed and skip-pull
  if [[ "$OFFLINE" == "true" ]]; then
    TLS_MODE="selfsigned"
    SKIP_PULL=true
    if [[ "$AIR_GAP" == "true" ]]; then
      log_info "Air-gap mode: TLS set to self-signed, image pull skipped (bundle load in step 9)"
    else
      log_info "Offline mode: TLS set to self-signed, image pull skipped"
    fi
  fi
}

# =============================================================================
# STEP 5c: AES key provisioning
# =============================================================================
provision_aes_key() {
  # Already provided via --db-aes-key flag
  if [[ -n "$DB_AES_KEY" ]]; then
    _validate_aes_key "$DB_AES_KEY"
    log_info "Database AES key: provided via --db-aes-key"
    return 0
  fi

  # Check if .env already has a key (upgrade path)
  local env_file="${WORK_DIR}/docker/.env"
  if [[ -f "$env_file" ]]; then
    local existing_key
    existing_key="$(grep '^YASHIGANI_DB_AES_KEY=' "$env_file" 2>/dev/null | sed 's/^YASHIGANI_DB_AES_KEY=//' || echo "")"
    if [[ -n "$existing_key" ]]; then
      DB_AES_KEY="$existing_key"
      log_info "Database AES key: preserved from existing .env"
      return 0
    fi
  fi

  # Demo mode: auto-generate without prompting
  if [[ "$DEPLOY_MODE" == "demo" ]]; then
    _generate_aes_key
    log_info "Database AES key: auto-generated (demo mode)"
    return 0
  fi

  # Non-interactive: auto-generate
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    _generate_aes_key
    log_info "Database AES key: auto-generated (non-interactive)"
    return 0
  fi

  # Interactive: prompt
  printf "\n"
  printf "${C_BOLD}  Database encryption key (YASHIGANI_DB_AES_KEY):${C_RESET}\n\n"
  printf "    1) Generate a new 256-bit key automatically (recommended)\n"
  printf "    2) Bring your own key (BYOK) — paste an existing key\n"
  printf "\n"
  printf "${C_BOLD}  Choice [1]: ${C_RESET}"

  local choice
  read -r choice </dev/tty 2>/dev/null || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    1)
      _generate_aes_key
      printf "\n"
      printf "  ${C_YELLOW}SAVE THIS KEY — it will only be shown once:${C_RESET}\n"
      printf "  ${C_BOLD}${DB_AES_KEY}${C_RESET}\n"
      printf "\n"
      log_success "Database AES key: generated"
      ;;
    2)
      printf "\n"
      printf "  Paste your 256-bit AES key (64-char hex or 44-char base64): "
      local user_key
      read -r user_key </dev/tty 2>/dev/null || user_key=""
      if [[ -z "$user_key" ]]; then
        log_error "No key provided. Aborting."
        exit 1
      fi
      _validate_aes_key "$user_key"
      DB_AES_KEY="$user_key"
      printf "\n"
      log_success "Database AES key: BYOK accepted"
      ;;
    *)
      log_warn "Invalid choice — generating automatically"
      _generate_aes_key
      log_success "Database AES key: generated"
      ;;
  esac
}

_generate_aes_key() {
  if command -v openssl >/dev/null 2>&1; then
    DB_AES_KEY="$(openssl rand -hex 32)"
  elif command -v python3 >/dev/null 2>&1; then
    DB_AES_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  else
    log_error "Cannot generate AES key: neither openssl nor python3 found"
    exit 1
  fi
}

_validate_aes_key() {
  local key="$1"
  local len=${#key}
  # Accept 64-char hex (32 bytes) or 44-char base64 (32 bytes)
  if [[ "$len" -eq 64 ]] && echo "$key" | grep -qE '^[0-9a-fA-F]+$'; then
    return 0
  elif [[ "$len" -eq 44 ]] && echo "$key" | grep -qE '^[A-Za-z0-9+/]+=*$'; then
    return 0
  else
    log_error "Invalid AES key: expected 64-char hex or 44-char base64 (got ${len} chars)"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# SAML SP key generation — YSG-RISK-044 mitigation
# ---------------------------------------------------------------------------
# SECURITY-MODEL REQUIREMENT: The SAML Service Provider key MUST be RSA.
#
# CVE-2026-41989 (libgcrypt20 ECDH heap-buffer-overflow, HIGH CVSS 7.5):
#   An attacker who can POST a crafted EncryptedAssertion with ECDH-ES key
#   transport to the SAML ACS endpoint can trigger a heap overflow in
#   gcry_pk_decrypt() inside libgcrypt.  The ECDH path is ONLY exercised
#   when the SP private key is an EC key.  RSA SP keys route to the RSA
#   decryption path in xmlsec1 and never invoke gcry_pk_decrypt at all.
#   The libgcrypt ECDH code path is therefore dead on a standard Yashigani
#   deployment — YSG-RISK-044 is NOT-EXPLOITABLE when the SP key is RSA.
#
# Runtime enforcement: SAMLProvider.__init__ calls _assert_rsa_sp_key()
#   in src/yashigani/sso/saml.py, which loads the key with
#   cryptography.hazmat.primitives.serialization.load_pem_private_key and
#   asserts isinstance(key, RSAPrivateKey).  Any non-RSA key type disables
#   SAML at startup — fail-closed.
#
# This function generates the default SP key+cert during install so
# operators have a ready-to-use RSA key without any manual steps.
# BYOK is documented in docs/yashigani_install_config.md §8.2.
#
# PQR forward note: when ML-KEM/Kyber key-transport is standardised in the
# SAML 2.0 / XML Encryption / xmlsec1 / IdP ecosystem, this requirement can
# be revisited (see YSG-RISK-044 forward-tracking note in risk register).
_generate_saml_sp_key() {
  local secrets_dir="${WORK_DIR}/docker/secrets"
  local sp_key_file="${secrets_dir}/saml_sp.key"
  local sp_cert_file="${secrets_dir}/saml_sp.crt"

  # Idempotent: skip if already present (preserve across re-runs)
  if [[ -f "${sp_key_file}" && -f "${sp_cert_file}" ]]; then
    log_info "SAML SP key already present — skipping generation"
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    log_warn "openssl not found — skipping SAML SP key generation"
    log_warn "Generate manually before enabling SAML: openssl genrsa -out docker/secrets/saml_sp.key 4096"
    return 0
  fi

  local domain_label="${YASHIGANI_TLS_DOMAIN:-yashigani}"
  log_info "Generating SAML SP RSA-4096 key + self-signed certificate..."

  # SECURITY-MODEL REQUIREMENT: SAML SP key MUST be RSA.
  # EC keys would expose us to YSG-RISK-044 (CVE-2026-41989, libgcrypt ECDH
  # heap overflow) via the SAML decryption path.  Runtime enforcement at
  # SAMLProvider init refuses EC keys — see src/yashigani/sso/saml.py.
  # When PQR algorithms ship in SAML+xmlsec+IdP ecosystem, this requirement
  # can be revisited (see YSG-RISK-044 forward note in risk register).
  # Bug fix (7cdbcf9 follow-up): secrets_dir may not yet exist at step 5;
  # mkdir -p is idempotent so safe on both fresh install and re-run.
  mkdir -p "${secrets_dir}"
  # Scope umask 077 to a sub-shell so it does NOT bleed into the parent installer
  # process.  An unscoped `umask 077` here caused all subsequent files written by
  # generate_secrets() and any tarball/git extract to land as 0600/0700, making
  # bind-mounted config files unreadable by container UIDs (pgbouncer=70,
  # prometheus=65534, etc.).  Fix: sub-shell inherits the restrictive umask,
  # generates the key, then the sub-shell exits and the parent umask is restored.
  # The explicit chmod 0400 / 0644 below re-enforce key perms independent of umask.
  # (fix: umask-077-bleed / Ava phase-1 failure 2026-05-20)
  (
    umask 077
    if ! openssl genrsa -out "${sp_key_file}" 4096 2>/dev/null; then
      log_error "Failed to generate SAML SP RSA key (YSG-RISK-044)"
      exit 1
    fi
  )

  # Post-generation RSA invariant: confirm the key we just wrote is actually RSA.
  # Catches the (theoretical) case where openssl behaves unexpectedly OR someone
  # edits the line above to switch to a non-RSA algorithm without reading this
  # comment.  Fail-closed: if the check fails, abort install.
  #
  # Bug fix (7cdbcf9 follow-up): `openssl pkey -text | head -1 | grep 'RSA'`
  # is broken on OpenSSL 3.x (Ubuntu 24.04 / OpenSSL 3.0.13): the first line
  # is "Private-Key: (4096 bit, 2 primes)" — "RSA" does not appear until a
  # later line.  Use `openssl rsa -check` instead: exits 0 only for valid RSA
  # private keys; works identically on OpenSSL 1.x and 3.x.
  if ! openssl rsa -check -in "${sp_key_file}" >/dev/null 2>&1; then
    log_error "FATAL: generated SAML SP key is not RSA. YSG-RISK-044 mitigation requires RSA." >&2
    log_error "Remove ${sp_key_file} and re-run install.sh to regenerate." >&2
    exit 1
  fi

  # Self-signed SP certificate — valid 10 years (IdPs only verify SP cert for
  # assertion encryption; use your own CA-signed cert for production if required)
  if ! openssl req -new -x509 \
      -key "${sp_key_file}" \
      -out "${sp_cert_file}" \
      -days 3650 \
      -subj "/CN=${domain_label}/O=Yashigani/OU=SAML-SP" \
      2>/dev/null; then
    log_error "Failed to generate SAML SP self-signed certificate (YSG-RISK-044)"
    exit 1
  fi

  # Harden permissions: private key owner-read-only (CWE-732 / v2.23.1 S1)
  chmod 0400 "${sp_key_file}"
  chmod 0644 "${sp_cert_file}"

  log_success "SAML SP key + certificate generated (RSA-4096, self-signed)"
  log_info "  Key:  docker/secrets/saml_sp.key (0400)"
  log_info "  Cert: docker/secrets/saml_sp.crt (0644)"
  log_info "  Configure SAML IdPs via YASHIGANI_IDP_<N>_SP_PRIVATE_KEY_FILE and"
  log_info "  YASHIGANI_IDP_<N>_SP_CERT_FILE in docker/.env (see §8.2 in install guide)"
}

# Write all required environment variables to docker/.env
_write_aes_key_to_env() {
  local env_file="${WORK_DIR}/docker/.env"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Write environment variables to ${env_file}"
    return 0
  fi

  # Create .env if it doesn't exist.
  # A4 (Laura BLOCKING / CWE-732 / ASVS V6.4.1): chmod 0600 IMMEDIATELY after
  # touch, before any credentials are written.  Without this, ambient umask 022
  # creates a 0644 file; secrets (YASHIGANI_DB_AES_KEY, POSTGRES_PASSWORD,
  # REDIS_PASSWORD, OWUI_SECRET_KEY, TOTP material) land world-readable until a
  # later chmod corrects it.  This also ensures A2's o+rX sweep cannot widen the
  # file: o+rX on a 0600 file would set 0604 (world-readable), which the explicit
  # 0600 here prevents because the sweep runs after this function.
  # docker/.env is also explicitly pruned from the A2 find sweep in _fix_config_perms.
  touch "$env_file"
  chmod 0600 "$env_file"  # A4: secrets-bearing env file must be owner-only (laura-install-umask-threat-model.md)

  # --- Helper: set a var in .env (update if exists, append if not) ---
  _env_set() {
    local key="$1"
    local value="$2"
    if [[ -z "$value" ]]; then return 0; fi
    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
      local tmp_env
      # V232-NEG04: never use /tmp — keep temp file alongside the .env file
      tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
      sed "s|^${key}=.*|${key}=${value}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "${key}=${value}" >> "$env_file"
    fi
  }

  # --- AES encryption key ---
  _env_set "YASHIGANI_DB_AES_KEY" "${DB_AES_KEY}"

  # --- OWUI secret key ---
  # Required by docker-compose (OWUI_SECRET_KEY has no fallback default
  # after Compliance review finding #4). Generate a fresh 256-bit key on first
  # install; preserve existing value across re-runs so cookies survive.
  local existing_owui_key
  existing_owui_key="$(grep '^OWUI_SECRET_KEY=' "$env_file" 2>/dev/null | sed 's/^OWUI_SECRET_KEY=//' || echo "")"
  if [[ -z "$existing_owui_key" ]]; then
    _env_set "OWUI_SECRET_KEY" "$(openssl rand -hex 32)"
  fi

  # --- Runtime-specific security profile overrides (Compliance review finding #2) ---
  # Seccomp + AppArmor profiles are enabled by default in docker-compose.yml.
  # Podman machine VM on macOS runs SELinux, not AppArmor — loading the
  # AppArmor profile fails. Relax by setting YASHIGANI_APPARMOR_PROFILE=
  # unconfined when we detect Podman.
  #
  # v2.23.2 fix (#31/#4): install.sh now sets YASHIGANI_SECCOMP_PROFILE to an
  # absolute path for both Docker and Podman runtimes.
  #
  # Root cause of the v2.23.1 Podman seccomp failure (TM-V231-005):
  #   podman-compose 1.x passes security_opt strings directly to `podman run
  #   --security-opt` without path resolution — so `./seccomp/yashigani.json`
  #   was resolved relative to the shell CWD ($WORK_DIR), not the compose file
  #   directory ($WORK_DIR/docker), causing "file not found". The prior v2.23.1
  #   fix (YASHIGANI_SECCOMP_PROFILE=unconfined on Podman) disabled seccomp
  #   enforcement on Podman entirely.
  #
  #   Note: the earlier absolute-path attempt (Pentest #95, 2026-04-29) was
  #   reverted because docker-compose v5.x inlines JSON and Podman's compat API
  #   hit ENAMETOOLONG. That applied only to docker-compose-against-Podman-socket,
  #   NOT to native podman-compose. install.sh now enforces native podman-compose
  #   (not docker-compose compat), making the absolute path safe on Podman.
  #
  # Retro note: the prior apparmor override checked ${RUNTIME:-} which is
  # NEVER SET anywhere in this script — the correct variable is
  # ${YSG_PODMAN_RUNTIME:-false} or ${YSG_RUNTIME:-docker}. Both must
  # be checked because different codepaths set one or the other. This
  # silently let apparmor default to the profile name all along; compose
  # tolerated it because Podman on macOS ignores unknown apparmor profile
  # names silently, but fails HARD when the seccomp FILE path is wrong.

  # Seccomp: set absolute path for both runtimes. Admin can still override to
  # "unconfined" via YASHIGANI_SECCOMP_PROFILE env var if a host kernel rejects
  # the profile (e.g. nested virtualisation, non-standard kernels).
  local _seccomp_profile="${WORK_DIR}/docker/seccomp/yashigani.json"
  if [[ ! -f "$_seccomp_profile" ]]; then
    log_warn "Seccomp profile not found at ${_seccomp_profile} — falling back to unconfined"
    _env_set "YASHIGANI_SECCOMP_PROFILE" "unconfined"
  else
    _env_set "YASHIGANI_SECCOMP_PROFILE" "${_seccomp_profile}"
    log_info "Seccomp profile: ${_seccomp_profile}"
  fi

  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]]; then
    # AppArmor stays unconfined on Podman (macOS Podman, rootful Linux Podman
    # both ignore unknown profile names; rather than name-mismatch silently,
    # explicitly disable). Linux + AppArmor users override via env.
    _env_set "YASHIGANI_APPARMOR_PROFILE" "unconfined"
  elif [[ "${YSG_OS:-}" == "linux" && "${YSG_RUNTIME:-}" == "docker" ]]; then
    # Docker on Linux: auto-load our AppArmor profile so containers start without
    # requiring a manual 'apparmor_parser -r' step. If loading fails (no apparmor,
    # locked-down kernel, or VM environment), fall back to 'unconfined' so the
    # install doesn't block. Retro v2.23.1 item #3ae.
    local _aa_profile_src="${WORK_DIR}/docker/apparmor/yashigani-gateway"
    if [[ -f "$_aa_profile_src" ]] && command -v apparmor_parser >/dev/null 2>&1; then
      if apparmor_parser -r "$_aa_profile_src" >/dev/null 2>&1; then
        log_success "AppArmor profile loaded: yashigani-gateway"
        _env_set "YASHIGANI_APPARMOR_PROFILE" "yashigani-gateway"
      else
        log_warn "AppArmor profile load failed — falling back to unconfined"
        _env_set "YASHIGANI_APPARMOR_PROFILE" "unconfined"
      fi
    else
      log_warn "AppArmor profile or parser not available — using unconfined"
      _env_set "YASHIGANI_APPARMOR_PROFILE" "unconfined"
    fi
  fi

  # --- Upstream MCP URL ---
  # Demo mode: use a built-in echo server so compose doesn't fail on missing var
  # Production: set from wizard or --upstream-url flag
  local upstream="${UPSTREAM_URL}"
  if [[ -z "$upstream" && "$DEPLOY_MODE" == "demo" ]]; then
    upstream="http://localhost:8080/echo"
  fi
  _env_set "UPSTREAM_MCP_URL" "${upstream}"

  # --- Domain ---
  _env_set "YASHIGANI_TLS_DOMAIN" "${DOMAIN}"

  # --- TLS mode ---
  _env_set "YASHIGANI_TLS_MODE" "${TLS_MODE}"
  # Captain v2.24.4 B8 closure (install.sh side per Nico N-001):
  # Compose YAML at docker/docker-compose.yml `x-common-env` reads
  # `FIPS_MODE: ${YSG_FIPS_MODE:-0}`. Writing FIPS_MODE here to docker/.env
  # makes the value runtime-agnostic — env-var propagation through subshells
  # is fragile (works on Linux Podman, fails on Mac Podman Desktop because
  # YAML interpolation happens client-side and the Podman socket doesn't
  # propagate process env into the compose CLI invocation reliably). docker/.env
  # is read by compose directly, so the operator's --fips-mode / YSG_FIPS_MODE
  # opt-in reaches gateway/backoffice/caddy regardless of runtime.
  _env_set "FIPS_MODE" "${FIPS_MODE:-0}"
  _env_set "YSG_FIPS_MODE" "${FIPS_MODE:-0}"
  # Nico N-002 (v2.25.0 P2 B9): CMVP certificate number for runtime FIPS
  # attestation. Compose YAML at docker/docker-compose.yml x-common-env reads
  # YASHIGANI_CMVP_CERT: ${YSG_CMVP_CERT:-}. Surfaced by /admin/crypto/inventory
  # as auditor evidence. Empty default = attestation reports cmvp_cert: null.
  _env_set "YSG_CMVP_CERT" "${CMVP_CERT:-}"

  # --- Admin email ---
  if [[ -n "$ADMIN_EMAIL" ]]; then
    _env_set "YASHIGANI_ADMIN_EMAIL" "${ADMIN_EMAIL}"
  fi

  # --- Prometheus basic auth (required by Caddy reverse proxy to Prometheus) ---
  # Generate a bcrypt hash for the Prometheus scrape endpoint.
  # Try methods in order: htpasswd (macOS/Linux), python3 bcrypt module, python3 hashlib fallback.
  local prom_password
  prom_password="$(_gen_password)"
  local prom_hash=""

  # Method 1: htpasswd (available on macOS via Apache, Linux via apache2-utils)
  if [[ -z "$prom_hash" ]] && command -v htpasswd >/dev/null 2>&1; then
    prom_hash="$(htpasswd -nbBC 12 "" "${prom_password}" 2>/dev/null | tr -d ':\n' || echo "")"
  fi

  # Method 2: python3 bcrypt module (installed as yashigani dependency)
  if [[ -z "$prom_hash" ]] && command -v python3 >/dev/null 2>&1; then
    prom_hash="$(YASHIGANI_PROM_PW="$prom_password" python3 -c "
import bcrypt, os
pw = os.environ['YASHIGANI_PROM_PW'].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null || echo "")"
  fi

  # Method 3: python3 stdlib bcrypt via hashlib (no external deps)
  # Caddy requires bcrypt ($2a$/$2b$) — PBKDF2 is incompatible
  if [[ -z "$prom_hash" ]] && command -v python3 >/dev/null 2>&1; then
    prom_hash="$(YASHIGANI_PROM_PW="$prom_password" python3 -c "
import os, hashlib, base64, struct
pw = os.environ['YASHIGANI_PROM_PW'].encode()
# bcrypt via subprocess htpasswd or fail
import subprocess, sys
try:
    r = subprocess.run(['htpasswd', '-nbBC', '12', '', pw.decode()], capture_output=True, text=True)
    if r.returncode == 0:
        print(r.stdout.strip().lstrip(':'))
        sys.exit(0)
except FileNotFoundError:
    pass
# No bcrypt available — cannot generate compatible hash
sys.exit(1)
" 2>/dev/null || echo "")"
  fi

  if [[ -z "$prom_hash" ]]; then
    log_error "Failed to generate Prometheus basic-auth hash. Install htpasswd (brew install httpd) or ensure python3 is available."
    exit 1
  fi
  # Escape $ to $$ for Docker Compose — bcrypt hashes contain $ delimiters
  # that Compose would interpret as variable interpolation.
  local escaped_hash="${prom_hash//\$/\$\$}"
  _env_set "PROMETHEUS_BASICAUTH_HASH" "${escaped_hash}"
  _env_set "PROMETHEUS_BASICAUTH_USER" "prometheus"

  # --- Environment mode ---
  # LIC-001: YASHIGANI_ENV permitted values are "dev", "staging", "production".
  # "development" (long-form) is no longer accepted by kms/factory.py; use "dev".
  if [[ "$DEPLOY_MODE" == "demo" ]]; then
    _env_set "YASHIGANI_ENV" "dev"
  else
    _env_set "YASHIGANI_ENV" "production"
  fi

  # --- SSO IdP configuration ---
  # Add documented SSO section if not already present.
  # Operators configure IdPs by setting YASHIGANI_IDP_<N>_* vars.
  if ! grep -q "YASHIGANI_IDP_1_ID" "$env_file" 2>/dev/null; then
    cat >> "$env_file" << 'SSO_EOF'

# ---------------------------------------------------------------------------
# SSO Identity Provider Configuration (Starter tier and above)
# ---------------------------------------------------------------------------
# Configure up to 2 IdPs (Professional tier supports OIDC + SAML).
# Enterprise tier supports unlimited IdPs — add YASHIGANI_IDP_3_*, etc.
#
# YASHIGANI_IDP_1_ID=my-entra-id
# YASHIGANI_IDP_1_NAME=Entra ID
# YASHIGANI_IDP_1_PROTOCOL=oidc
# YASHIGANI_IDP_1_DISCOVERY_URL=https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration
# YASHIGANI_IDP_1_CLIENT_ID=<client-id>
# YASHIGANI_IDP_1_CLIENT_SECRET=<client-secret>
# YASHIGANI_IDP_1_EMAIL_DOMAINS=example.com,example.org
# YASHIGANI_IDP_1_REDIRECT_URI=https://<domain>/auth/sso/oidc/my-entra-id/callback
#
# SAML v2 IdP example (Professional tier and above):
# YASHIGANI_IDP_2_ID=entra-saml
# YASHIGANI_IDP_2_NAME=Entra ID (SAML)
# YASHIGANI_IDP_2_PROTOCOL=saml
# YASHIGANI_IDP_2_DISCOVERY_URL=https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml
# YASHIGANI_IDP_2_EMAIL_DOMAINS=example.com
#
# SAML SP key + certificate (YSG-RISK-044 — RSA REQUIRED; see §8.2 in install guide).
# install.sh generates docker/secrets/saml_sp.key (RSA-4096) + docker/secrets/saml_sp.crt
# at install time.  Uncomment and set these paths to activate SAML SP cryptography.
# DO NOT replace saml_sp.key with an EC key — runtime enforcement will refuse it.
# YASHIGANI_SAML_SP_PRIVATE_KEY_FILE=/run/secrets/saml_sp.key
# YASHIGANI_SAML_SP_CERT_FILE=/run/secrets/saml_sp.crt
#
# Require Yashigani TOTP after SSO (defense against session hijack/replay):
# YASHIGANI_SSO_2FA_REQUIRED=false
SSO_EOF
  fi

  # --- SAML SP key generation (YSG-RISK-044) ---
  # Generates docker/secrets/saml_sp.key (RSA-4096) + saml_sp.crt on first install.
  # Idempotent: skipped if the files already exist.
  if [[ "$DRY_RUN" != "true" ]]; then
    _generate_saml_sp_key
  else
    dry_print "Generate SAML SP RSA-4096 key + certificate (YSG-RISK-044)"
  fi

  log_info "Environment written to ${env_file}"
}

# =============================================================================
# STEP 6: Configuration wizard
# =============================================================================
run_wizard() {
  set_step "6" "Configuration wizard"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    log_step "6/${TOTAL_STEPS}" "Skipping wizard (--non-interactive)"

    local missing=()
    [[ -z "$DOMAIN" ]]       && missing+=("--domain")
    [[ -z "$ADMIN_EMAIL" ]]  && missing+=("--admin-email")
    [[ -z "$UPSTREAM_URL" ]] && missing+=("--upstream-url")

    if [[ ${#missing[@]} -gt 0 ]]; then
      log_warn "Non-interactive mode: the following flags were not provided: ${missing[*]}"
      log_warn "Defaults or empty values will be used; reconfigure via your .env file."
    fi

    export YASHIGANI_TLS_DOMAIN="$DOMAIN"
    export YASHIGANI_ADMIN_USERNAME="$ADMIN_EMAIL"
    export UPSTREAM_MCP_URL="$UPSTREAM_URL"
    export YASHIGANI_TLS_MODE="$TLS_MODE"
    return 0
  fi

  log_step "6/${TOTAL_STEPS}" "Running configuration wizard..."

  local wizard_script="${WORK_DIR}/scripts/wizard.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "source $wizard_script"
    return 0
  fi

  if [[ -f "$wizard_script" ]]; then
    # Source so the wizard can export variables into this shell
    # shellcheck source=/dev/null
    source "$wizard_script"
  else
    log_warn "Wizard script not found: $wizard_script — running built-in prompts"
    run_inline_wizard
  fi

  log_success "Configuration complete"
}

run_inline_wizard() {
  printf "\n${C_BOLD}=== Yashigani Configuration ===${C_RESET}\n\n"

  if [[ -z "$DOMAIN" ]]; then
    DOMAIN="$(prompt_input "Domain name (e.g. yashigani.example.com)" "")"
  fi

  if [[ -z "$ADMIN_EMAIL" ]]; then
    ADMIN_EMAIL="$(prompt_input "Admin email address" "")"
  fi

  if [[ -z "$UPSTREAM_URL" ]]; then
    UPSTREAM_URL="$(prompt_input "Upstream MCP URL" "")"
  fi

  export YASHIGANI_TLS_DOMAIN="$DOMAIN"
  export YASHIGANI_ADMIN_USERNAME="$ADMIN_EMAIL"
  export UPSTREAM_MCP_URL="$UPSTREAM_URL"
  export YASHIGANI_TLS_MODE="$TLS_MODE"
}

# =============================================================================
_backup_existing_data() {
  local backup_dir="${WORK_DIR}/backups/$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$backup_dir"

  log_info "Backing up existing data to ${backup_dir}..."

  # Backup secrets (passwords, TOTP secrets, tokens)
  if [[ -d "${WORK_DIR}/docker/secrets" ]]; then
    # BUG-3 (v2.23.1): cp -rp preserves ownership + mode + timestamps so the
    # subsequent restore (cp -rp on the backup) lands files with the SAME uids
    # the running containers expect (pgbouncer=70, redis=999, postgres=999,
    # grafana=472, gateway/backoffice=1001). cp -r without -p was losing the
    # uids during backup, then restore preserved root:root and broke services.
    #
    # BUG-B+-003: on Podman rootless the secrets dir files are owned by
    # subuid-remapped UIDs (e.g. 100069, 100998, 101000, 102001). The installer
    # runs as UID 1000 (the host user), which cannot read those files directly.
    # Fix: use `podman unshare tar` to read inside the rootless user namespace,
    # where the remapped UIDs appear as their original values and are accessible.
    local _secrets_src="${WORK_DIR}/docker/secrets"
    local _secrets_dest="${backup_dir}/secrets"
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$(id -u)" != "0" ]]; then
      # Podman rootless path: tar inside the user namespace, extract outside.
      mkdir -p "$_secrets_dest"
      if podman unshare bash -c "tar -cf - -C '${_secrets_src}' ." \
           | tar -xpf - -C "$_secrets_dest" 2>/dev/null; then
        log_info "  secrets/ backed up via podman unshare tar (BUG-B+-003)"
      else
        log_warn "  secrets/ backup via podman unshare failed — skipping secrets backup (BUG-B+-003)"
        log_warn "  Secrets are preserved in live volumes; this is non-fatal for upgrade."
        rm -rf "$_secrets_dest"
      fi
    else
      cp -rp "$_secrets_src" "$_secrets_dest"
      log_info "  secrets/ backed up (ownership/mode preserved)"
    fi
  fi

  # Backup .env (contains passwords as env vars)
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    cp "${WORK_DIR}/docker/.env" "${backup_dir}/.env"
    log_info "  .env backed up"
  fi

  # Backup audit logs (if accessible)
  local _runtime_cmd=""
  [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && _runtime_cmd="podman" || _runtime_cmd="docker"
  local audit_volume
  audit_volume="$($_runtime_cmd volume ls -q 2>/dev/null | grep audit_data || true)"
  if [[ -n "$audit_volume" ]]; then
    log_info "  Audit volume detected: ${audit_volume} (preserved in named volume)"
  fi

  # Backup Postgres data (dump if possible).
  # K8s path: find the running postgres pod and exec pg_dump via kubectl.
  # The postgres pod runs as runAsUser: 70 (postgres on Alpine), so kubectl exec
  # arrives as UID 70 — the postgres superuser for this cluster. No root needed;
  # pg_dump -U yashigani_app connects via the local Unix socket (trust auth).
  # Compose/Podman path: exec into the named container. Container name varies by
  # runtime and install order, so detect via docker/podman ps rather than
  # hardcoding 'docker-postgres-1'.
  if [[ "${MODE:-compose}" == "k8s" ]] || [[ "${YSG_RUNTIME:-}" == "k8s" ]]; then
    local _pg_pod
    _pg_pod=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=postgres \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [[ -n "$_pg_pod" ]]; then
      if kubectl exec -i -n "${NAMESPACE}" "$_pg_pod" -- \
           pg_dump -U yashigani_app yashigani > "${backup_dir}/postgres_dump.sql" 2>/dev/null; then
        log_info "  postgres_dump.sql backed up (K8s: pod ${_pg_pod})"
      else
        log_info "  Postgres K8s dump skipped (pod not ready or auth failed)"
        rm -f "${backup_dir}/postgres_dump.sql"
      fi
    else
      log_info "  Postgres dump skipped (no running postgres pod in namespace ${NAMESPACE})"
    fi
  else
    # Compose / Podman path: locate the running postgres container by name pattern.
    # Avoid hardcoding 'docker-postgres-1' — name varies by compose project name,
    # runtime (podman-compose uses underscores), and container restart count.
    local _pg_container
    _pg_container=$($_runtime_cmd ps --format '{{.Names}}' 2>/dev/null \
      | grep -E 'postgres' | grep -v pgbouncer | head -1 || true)
    if [[ -n "$_pg_container" ]]; then
      if $_runtime_cmd exec "$_pg_container" \
           pg_dump -U yashigani_app yashigani > "${backup_dir}/postgres_dump.sql" 2>/dev/null; then
        log_info "  postgres_dump.sql backed up (${RUNTIME:-compose}: container ${_pg_container})"
      else
        log_info "  Postgres dump failed for container ${_pg_container} — dump skipped"
        rm -f "${backup_dir}/postgres_dump.sql"
      fi
    else
      log_info "  Postgres dump skipped (no running postgres container found)"
    fi
  fi

  # BUG-58B-04a (v2.23.1): do NOT use 'chmod -R 600' on the backup dir.
  # That clobbers intentionally-0644 public secret files (admin passwords,
  # bootstrap tokens, service passwords that non-root containers must read).
  # When restore.sh copies these back, the 0600 mode on files that were 0644
  # causes service containers (pgbouncer=UID70, redis=UID999, etc.) to get
  # EACCES on startup. Fix: tighten private keys to 0400, leave everything
  # else at its source mode (already ≤0644 per install.sh canonical assignment).
  # CA private keys and service private keys are the only secret material that
  # must be inaccessible to processes other than their owner; everything else
  # (passwords, certs, tokens) is intentionally readable by the service UIDs.
  find "${backup_dir}/secrets" -maxdepth 1 -type f \
    \( -name '*.key' \) -exec chmod 0400 {} \; 2>/dev/null || true
  # Lock down the backup dir itself and non-secrets files (e.g. postgres_dump.sql,
  # .env) to owner-read-only; the secrets sub-dir mode is controlled above.
  chmod 0700 "$backup_dir"
  if [[ -f "${backup_dir}/.env" ]]; then
    chmod 0600 "${backup_dir}/.env"
  fi
  if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
    chmod 0600 "${backup_dir}/postgres_dump.sql"
  fi
  # Defensive assertion: no world/group-readable private keys in backup (S1).
  if find "${backup_dir}/secrets" -type f -name '*.key' \( -perm -004 -o -perm -040 \) 2>/dev/null | grep -q .; then
    log_error "CWE-732: group/world-readable key file(s) in backup ${backup_dir}/secrets"
    exit 1
  fi

  # RETRO-R4-3: sign the backup manifest so restore.sh can cryptographically verify
  # integrity before touching any live secrets. Signing key is the CA intermediate
  # private key (already present at install time; 0400 owner-only). The signature
  # covers a SHA-256 manifest of every file under the backup dir. restore.sh
  # validate_backup() verifies the signature with the CA intermediate public cert
  # (extracted from ca_intermediate.crt) — reject-if-invalid, warn-if-absent.
  #
  # Threat model: an attacker who can modify backup files on disk but cannot read
  # the CA intermediate key (0400, requires host root or the issuer container) cannot
  # forge a valid signature. Without the signature check, a tampered backup silently
  # overwrites live secrets and breaks mTLS for all services.
  #
  # Implementation:
  #   1. Build a sorted SHA-256 manifest of all files in the backup dir.
  #   2. Sign the manifest with openssl dgst -sign (ECDSA/RSA depending on key type).
  #   3. Write manifest + .sig into the backup dir (0400).
  #   The intermediate key is used rather than the root to avoid root key exposure;
  #   both are equally trusted for this purpose since we control both.
  local _ca_key="${WORK_DIR}/docker/secrets/ca_intermediate.key"
  local _manifest_file="${backup_dir}/MANIFEST.sha256"
  local _sig_file="${backup_dir}/MANIFEST.sha256.sig"
  if [[ -f "$_ca_key" ]]; then
    # Build sorted deterministic manifest: "sha256hash  relative/path" per line.
    # find with -print0 + sort -z to handle spaces in names; awk strips leading ./
    # _fips_sha256_manifest_stream routes through OpenSSL FIPS Provider when FIPS_MODE=1
    # (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2).
    if (
      cd "$backup_dir" && \
      find . -type f ! -name 'MANIFEST.sha256' ! -name 'MANIFEST.sha256.sig' -print0 | \
        sort -z | \
        _fips_sha256_manifest_stream > MANIFEST.sha256
    ); then
      chmod 0400 "$_manifest_file"
      # Sign: openssl dgst -sign reads the raw key (PEM), outputs binary DER sig.
      if openssl dgst -sha256 -sign "$_ca_key" -out "$_sig_file" "$_manifest_file" 2>/dev/null; then
        chmod 0400 "$_sig_file"
        log_success "Backup manifest signed (RETRO-R4-3): ${_manifest_file##*/} + ${_sig_file##*/}"
      else
        log_warn "Backup manifest signing failed (openssl dgst -sign error) — backup is unsigned"
        rm -f "$_sig_file"
      fi
    else
      log_warn "Backup manifest generation failed — backup is unsigned"
    fi
  else
    log_warn "CA intermediate key not found at ${_ca_key} — backup is unsigned (expected on first-run before PKI bootstrap)"
  fi

  log_success "Backup saved to ${backup_dir}"
}

# Idempotency check — detect and handle an existing running installation
# =============================================================================
check_existing_installation() {
  local secrets_dir="${WORK_DIR}/docker/secrets"

  if [[ ! -d "$secrets_dir" ]]; then
    return 0
  fi

  # Check whether compose containers are running.
  # MUST use $COMPOSE_CMD (or resolve it on demand) — never hardcode 'docker compose'
  # here, because Docker Desktop may not be running when the admin is using Podman.
  # Hardcoding 'docker compose' caused a silent hang on macOS from-scratch Podman
  # install (v2.23.2 gate, 2026-05-01): docker CLI is present but daemon is down.
  # Fix: resolve_compose_cmd if COMPOSE_CMD is still empty, then use the array.
  # Guard with timeout 10 to prevent infinite block if socket is unreachable.
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"
  local running=false

  if [[ -f "$compose_file" ]]; then
    if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
      resolve_compose_cmd 2>/dev/null || true
    fi
    if [[ ${#COMPOSE_CMD[@]} -gt 0 ]]; then
      # macOS does not ship `timeout` (GNU coreutils). Use label filter via
      # docker/podman ps (fastest, no compose parsing, socket is local) and fall
      # back to compose ps without timeout.
      local _runtime_bin="${COMPOSE_CMD[0]%%[[:space:]]*}"
      if "$_runtime_bin" ps --filter 'label=com.docker.compose.project=docker' \
           --format '{{.Names}}' 2>/dev/null | grep -q .; then
        running=true
      elif "${COMPOSE_CMD[@]}" -f "$compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
        running=true
      fi
    fi
  fi

  [[ "$running" == "false" ]] && return 0

  log_warn "Existing Yashigani installation detected (containers are running)"

  if [[ "$UPGRADE" == "true" ]]; then
    log_info "Upgrade mode: backing up data, then pulling latest images"
    _backup_existing_data
    return 0
  fi

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    # BUG-B+-002: additive re-run (--with-openwebui / --agent-bundles on a
    # running stack). The live project volumes are NOT contamination — they belong
    # to the running install and carry the current PKI CA. Mark REUSE_VOLUMES so
    # _check_contaminated_volumes skips the false-positive check on REUSE_VOLUMES=true.
    # The live project volumes belong to the running install (same PKI CA) — not contamination.
    if [[ "$INSTALL_OPENWEBUI" == "true" || -n "$AGENT_BUNDLES" ]]; then
      log_info "Additive re-run detected (--with-openwebui / --agent-bundles on running stack)"
      log_info "Existing PKI CA and volumes preserved — skipping contamination check (BUG-B+-002)"
      REUSE_VOLUMES=true
    fi
    log_warn "Pass --upgrade to update the existing installation."
    log_warn "Continuing with current images..."
    SKIP_PULL=true
    return 0
  fi

  printf "\n${C_BOLD}Existing deployment detected. Choose an option:${C_RESET}\n\n"
  printf "    1) Upgrade — backup data, pull latest images, restart services\n"
  printf "    2) Fresh install — backup data, wipe everything, reinstall\n"
  printf "    3) Abort — exit without changes\n"
  printf "\n${C_BOLD}  Choice [1]: ${C_RESET}"

  local choice
  read -r choice </dev/tty 2>/dev/null || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    1)
      UPGRADE=true
      _backup_existing_data
      log_info "Upgrade mode enabled"
      ;;
    2)
      _backup_existing_data
      log_info "Fresh install: stopping existing containers..."
      local compose_file="${WORK_DIR}/docker/docker-compose.yml"
      "${COMPOSE_CMD[@]}" -f "$compose_file" down -v 2>/dev/null || true
      log_success "Previous deployment stopped and volumes removed"
      ;;
    3|*)
      log_info "Exiting — no changes made"
      exit 0
      ;;
  esac
}

# =============================================================================
# _check_contaminated_volumes — BUG-INSTALL-ON-CONTAMINATED-VOLUMES (2a)
# =============================================================================
# Before compose up, enumerate the canonical named volumes for the project.
# If ANY pre-existing volume is found AND the operator did NOT pass
# --reuse-volumes, fail LOUD with a clear remediation message.
#
# Rationale: a leftover postgres_data volume from a prior install may hold an
# old PKI CA bundle. The new install generates a fresh CA; the postgres init
# scripts (05-enable-ssl.sh) write NEW certs into PGDATA on first boot — but
# postgres only runs those scripts when PGDATA is EMPTY. A pre-populated volume
# skips init → new CA but old PGDATA certs → mTLS cert mismatch → every
# backoffice DB connection fails → gateway /healthz returns 200 (gateway is up)
# but all authenticated requests fail. Install appears to succeed. Classic
# fake-green path.
#
# The canonical volume list mirrors _CANONICAL_VOLUMES in uninstall.sh.
# When adding/removing named volumes in docker-compose.yml, keep both in sync.
#
# Called from the compose/vm install path AFTER check_existing_installation()
# (which confirmed no containers are running) and BEFORE generate_secrets()
# (no point generating secrets for a doomed install).
#
# Skip when:
#   * UPGRADE=true — operator explicitly chose upgrade-in-place
#   * REUSE_VOLUMES=true — operator explicitly acknowledged contamination risk
#   * DRY_RUN=true — no side-effects
# ---------------------------------------------------------------------------
_INSTALL_CANONICAL_VOLUMES=(
    audit_data
    bootstrap_data
    redis_data
    ollama_data
    prometheus_data
    grafana_data
    caddy_data
    caddy_config
    postgres_data
    alertmanager_data
    loki_data
    keycloak_data
    openclaw_data
    langflow_data
    letta_data
    openwebui_data
    budget_redis_data
    step_ca_data
    wazuh_api_configuration
    wazuh_etc
    wazuh_logs
    wazuh_queue
    wazuh_var_multigroups
    wazuh_integrations
    wazuh_active_response
    wazuh_agentless
    wazuh_wodles
    filebeat_etc
    filebeat_var
    wazuh_indexer_data
    wazuh_dashboard_config
    wazuh_dashboard_custom
)

_check_contaminated_volumes() {
  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "_check_contaminated_volumes (skipped in dry-run)"
    return 0
  fi
  if [[ "${UPGRADE:-false}" == "true" ]]; then
    log_info "Upgrade mode — skipping contaminated-volume check (--upgrade implies reuse)"
    return 0
  fi
  if [[ "${REUSE_VOLUMES:-false}" == "true" ]]; then
    log_warn "Contaminated-volume check SKIPPED (--reuse-volumes passed). PKI cert mismatch risk acknowledged."
    return 0
  fi

  # Use the install's own runtime — not auto-detect. On dual-runtime hosts
  # (Docker + Podman both installed), auto-detect can pick the wrong store.
  # RUNTIME is set in the call site from COMPOSE_CMD[0] / YSG_RUNTIME.
  local _runtime="${RUNTIME:-${YSG_RUNTIME:-docker}}"
  local _project_prefix="docker"
  local _found_volumes=()

  for _vol in "${_INSTALL_CANONICAL_VOLUMES[@]}"; do
    local _full_vol="${_project_prefix}_${_vol}"
    if "$_runtime" volume inspect "$_full_vol" >/dev/null 2>&1; then
      _found_volumes+=("$_full_vol")
    fi
  done

  if [[ "${#_found_volumes[@]}" -eq 0 ]]; then
    log_success "Contaminated-volume check: no leftover project volumes found — clean slate confirmed"
    return 0
  fi

  # Found leftover volumes — fail LOUD
  log_error "BUG-INSTALL-ON-CONTAMINATED-VOLUMES: volumes from a prior install detected:"
  for _v in "${_found_volumes[@]}"; do
    log_error "  - ${_v}"
  done
  log_error ""
  log_error "A leftover postgres_data volume holds the OLD PKI CA bundle. The new install"
  log_error "generates a fresh CA; postgres DB-init scripts run only on an EMPTY volume."
  log_error "Proceeding would cause a cert mismatch → DB connections fail → fake-green install."
  log_error ""
  log_error "Remediation — choose ONE:"
  log_error "  (a) Full clean slate (RECOMMENDED):"
  log_error "        cd ~/.yashigani && sudo ./uninstall.sh --remove-volumes --yes"
  log_error "      then re-run this installer."
  log_error ""
  log_error "  (b) Keep existing data (upgrade-in-place):"
  log_error "        ./install.sh --upgrade [other options]"
  log_error "      WARNING: only safe if the existing PKI CA matches the new install."
  log_error ""
  log_error "  (c) Acknowledge contamination risk (advanced — NOT recommended):"
  log_error "        ./install.sh --reuse-volumes [other options]"
  log_error "      This skips the check. Use only if you are certain the CA matches."
  exit 1
}

# =============================================================================
# STEP 7 (compose/vm): Handle license key
# =============================================================================
handle_license() {
  set_step "7" "License key"
  log_step "7/${TOTAL_STEPS}" "Checking license..."

  local secrets_dir="${WORK_DIR}/docker/secrets"
  local license_dest="${secrets_dir}/license_key"

  # Determine the source file
  local src_path=""
  if [[ -n "$LICENSE_KEY_PATH" ]]; then
    src_path="$LICENSE_KEY_PATH"
  elif [[ -n "${YASHIGANI_LICENSE_FILE:-}" ]]; then
    src_path="$YASHIGANI_LICENSE_FILE"
  fi

  if [[ -z "$src_path" ]]; then
    log_info "No license key provided — proceeding as Community Edition"
    log_info "To upgrade later, place your .ysg license file at: ${license_dest}"
    # Write placeholder content — Docker Desktop for Mac does not reliably
    # propagate empty files to the VM via VirtioFS/gRPC-FUSE.
    mkdir -p "$secrets_dir"
    echo "# community — replace with .ysg license content to upgrade" > "$license_dest"
    chmod 600 "$license_dest"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "mkdir -p $secrets_dir"
    dry_print "cp $src_path $license_dest"
    return 0
  fi

  if [[ ! -f "$src_path" ]]; then
    log_error "License key file not found: $src_path"
    exit 1
  fi

  mkdir -p "$secrets_dir"
  cp "$src_path" "$license_dest"

  if [[ ! -r "$license_dest" ]]; then
    log_error "License key was copied but is not readable: $license_dest"
    exit 1
  fi

  log_success "License key installed (source: $src_path)"
}

# =============================================================================
# STEP 8 (compose/vm): Optional agent bundle selection
# =============================================================================
# =============================================================================
# BYO Internal CA wizard helpers
# Scope: Q1 / Q1a interactive flow + validation callable from re-run path.
# Tom's Python scope: src/yashigani/pki/drivers/byo_ca.py (compute_ca_fingerprint,
# validate_byo_ca_files). These shell helpers delegate to that module once
# Tom's work lands on mustui main.
# =============================================================================

# _realpath_portable <path>
# Cross-platform realpath: uses GNU coreutils realpath when available,
# falls back to Python3 os.path.realpath (macOS ships without GNU coreutils
# by default — feedback_local_test_must_work_on_macos_and_linux.md).
_realpath_portable() {
  local _p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath -- "$_p" 2>/dev/null || printf '%s' "$_p"
  else
    python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" -- "$_p" 2>/dev/null || printf '%s' "$_p"
  fi
}

# _validate_byo_ca_path <path> <label>
# Path safety: reject paths containing shell metacharacters, '..' components,
# or non-absolute paths. Also rejects /proc, /sys, /dev prefixes (information
# disclosure via special files — Laura §2.1).
# Returns 0 (safe) or 1 (unsafe).
_validate_byo_ca_path() {
  local _path="$1"
  local _label="$2"

  # Must be an absolute path (no ~ expansion, no relative paths)
  if [[ "$_path" != /* ]]; then
    log_error "BYO CA ${_label}: path must be absolute (no ~ or relative paths): ${_path}"
    return 1
  fi

  # Reject '..' path traversal components
  if [[ "$_path" == *..* ]]; then
    log_error "BYO CA ${_label}: path contains '..' traversal component: ${_path}"
    return 1
  fi

  # Reject paths containing shell metacharacters (Laura M1 — CWE-78)
  # Allowed charset: alphanumeric, /, ., -, _
  if [[ "$_path" =~ [^a-zA-Z0-9./_-] ]]; then
    log_error "BYO CA ${_label}: path contains unsafe characters (only a-z A-Z 0-9 . / _ - allowed): ${_path}"
    return 1
  fi

  # Reject special kernel pseudo-filesystems
  local _canon
  _canon="$(_realpath_portable "$_path")"
  case "$_canon" in
    /proc/*|/sys/*|/dev/*)
      log_error "BYO CA ${_label}: path resolves to a kernel pseudo-filesystem: ${_canon}"
      return 1
      ;;
  esac

  # File must exist and be readable
  if [[ ! -f "$_path" || ! -r "$_path" ]]; then
    log_error "BYO CA ${_label}: file not found or not readable: ${_path}"
    return 1
  fi

  # File size cap: 64 KB maximum (rejects PEM-bomb / multi-MB garbage — Laura C7)
  local _size
  _size="$(wc -c < "$_path" 2>/dev/null || printf '0')"
  if [[ "$_size" -gt 65536 ]]; then
    log_error "BYO CA ${_label}: file exceeds 64 KB size limit (${_size} bytes) — rejecting"
    return 1
  fi

  return 0
}

# _check_byo_ca_key_type <key_path>
# BYOCA-BUG-003 (v2.24.0): Tom's issuer.py:bootstrap() requires EC key for the
# BYO intermediate signing CA. RSA intermediates are not supported in v2.24.0 —
# they cause an opaque failure deep in the PKI bootstrap step.
# This check surfaces the constraint early with an actionable error message.
# v2.24.1 may broaden to RSA — see internal-docs/yashigani/iris-v240-byo-internal-ca-design.md §3.
# Returns 0 (EC key) or 1 (not EC key / undetectable).
_check_byo_ca_key_type() {
  local _key="$1"
  # EC detection strategy (BYOCA-BUG-003 fix, v2.24.0):
  #
  # DO NOT use `openssl ec -in "$_key" -noout`: on OpenSSL 3.0.x (Ubuntu 22.04)
  # this command exits 0 for RSA keys because it only parses the PEM header, not
  # the key type. Confirmed bug: RSA keys silently pass the gate on 3.0.13.
  #
  # DO NOT use `openssl pkey -text | head -1` with an "EC" regex: the first line
  # on OpenSSL 3.x is "Private-Key: (N bit)" for all key types — no type word in
  # head -1. The same pattern fails on LibreSSL 3.x for EC keys.
  #
  # DO NOT use `openssl pkey -algorithm`: flag absent on LibreSSL.
  #
  # CORRECT APPROACH: `openssl pkey -noout -text` on EC keys always emits an
  # "ASN1 OID:" line (e.g. "ASN1 OID: secp384r1") and/or a "NIST CURVE:" line.
  # RSA/DSA/EdDSA keys produce neither. This holds across:
  #   - LibreSSL 3.3.6 (macOS 13/14/15)
  #   - OpenSSL 1.1.1 (Ubuntu 20.04)
  #   - OpenSSL 3.0.x (Ubuntu 22.04)  — this is the platform where the old gate failed
  #   - OpenSSL 3.x   (Ubuntu 24.04, RHEL 9, Alpine 3.19+)
  # Also correctly handles PKCS#8-wrapped EC keys (BEGIN PRIVATE KEY) in addition
  # to the traditional format (BEGIN EC PRIVATE KEY).
  if ! openssl pkey -in "$_key" -noout -text 2>/dev/null | grep -qiE "ASN1 OID:|NIST CURVE:"; then
    # Determine type for a helpful error message (best-effort, not security-critical)
    local _first_line
    _first_line="$(openssl pkey -in "$_key" -noout -text 2>/dev/null | head -1)" || _first_line=""
    local _short_type
    _short_type="$(printf '%s' "$_first_line" | grep -oE "(RSA|DSA|ED25519|ED448|X25519|X448)" || printf 'unknown')"
    log_error "BYO CA intermediate key type '${_short_type}' is not supported in v2.24.0."
    log_error "  v2.24.0 requires an EC key (P-256 / P-384 / P-521)."
    log_error "  Regenerate: openssl ecparam -name secp384r1 -genkey -noout -out intermediate.key"
    log_error "  v2.24.1 may broaden to RSA — see internal-docs/yashigani/iris-v240-byo-internal-ca-design.md §3"
    return 1
  fi
  return 0
}

# _validate_byo_ca_files
# Validates INTERNAL_CA_CERT + INTERNAL_CA_KEY (and optionally INTERNAL_CA_ROOT).
# Invokes Tom's Python validator for crypto checks (Basic Constraints, key match,
# expiry, key strength). Computes and displays SHA-256 fingerprint.
# In interactive mode: prompts operator to confirm fingerprint.
# In non-interactive mode: requires --byo-ca-fingerprint to match (Laura MUST-1).
# Reads globals: INTERNAL_CA_CERT, INTERNAL_CA_KEY, INTERNAL_CA_ROOT,
#                INTERNAL_CA_FINGERPRINT, INTERNAL_CA_ACCEPT_EXPIRED, NON_INTERACTIVE
# Returns 0 on success, 1 on failure.
_validate_byo_ca_files() {
  local _cert="$INTERNAL_CA_CERT"
  local _key="$INTERNAL_CA_KEY"
  local _root="${INTERNAL_CA_ROOT:-}"

  # --- Path safety checks ---
  _validate_byo_ca_path "$_cert" "cert" || return 1
  _validate_byo_ca_path "$_key"  "key"  || return 1
  if [[ -n "$_root" ]]; then
    _validate_byo_ca_path "$_root" "root" || return 1
  fi

  # --- Key-type gate: EC required (BYOCA-BUG-003) ---
  # issuer.py:bootstrap() requires EC for BYO intermediate in v2.24.0.
  # Check here for an early, actionable error rather than a silent PKI bootstrap failure.
  _check_byo_ca_key_type "$_key" || return 1

  # --- Python crypto validation (Tom's scope: byo_ca.py) ---
  # When Tom's module is not yet installed, this block fails with an import error.
  # That is expected — flag parsing and wizard UX are tested independently of
  # Tom's module. The gate here is explicit and documented.
  local _accept_expired_arg=""
  [[ "$INTERNAL_CA_ACCEPT_EXPIRED" == "true" ]] && _accept_expired_arg=", accept_expired=True"

  if python3 -c "from yashigani.pki.drivers.byo_ca import validate_byo_ca_files" 2>/dev/null; then
    local _root_arg=""
    [[ -n "$_root" ]] && _root_arg=", root_cert_path='${_root}'"
    if ! python3 -c "
from yashigani.pki.drivers.byo_ca import validate_byo_ca_files
validate_byo_ca_files('${_cert}', '${_key}'${_root_arg}${_accept_expired_arg})
" 2>&1; then
      log_error "BYO CA crypto validation failed — see error above"
      return 1
    fi
  else
    log_warn "yashigani.pki.drivers.byo_ca not yet importable — skipping Python crypto validation (Tom's module pending)"
    log_warn "Basic path + size checks passed; install may fail at PKI bootstrap if files are invalid"
  fi

  # --- SHA-256 fingerprint (Laura MUST-1 / C4) ---
  # Compute fingerprint of the intermediate CA cert. This is what gets shown to
  # the operator for out-of-band verification. Quoted double-expansion below is
  # safe because _cert passed _validate_byo_ca_path (no metacharacters).
  local _fp=""
  if python3 -c "from yashigani.pki.drivers.byo_ca import compute_ca_fingerprint" 2>/dev/null; then
    _fp="$(python3 -c "from yashigani.pki.drivers.byo_ca import compute_ca_fingerprint; print(compute_ca_fingerprint('${_cert}'))" 2>/dev/null)" || _fp=""
  fi

  # Fallback to openssl if Python module unavailable
  if [[ -z "$_fp" ]]; then
    _fp="$(openssl x509 -in "$_cert" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*Fingerprint=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')" || _fp=""
  fi

  if [[ -z "$_fp" ]]; then
    log_error "Failed to compute BYO CA cert fingerprint — cannot verify"
    return 1
  fi

  printf "\n${C_BOLD}BYO CA cert fingerprint (SHA-256):${C_RESET}\n  %s\n" "$_fp"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    # Non-interactive: --byo-ca-fingerprint MUST be supplied and must match (Laura MUST-1)
    if [[ -z "$INTERNAL_CA_FINGERPRINT" ]]; then
      log_error "Non-interactive BYO CA install requires --byo-ca-fingerprint <sha256>"
      log_error "  This is an anti-substitution guard (Laura MUST-1 / CWE-295)."
      log_error "  Compute the fingerprint on a trusted machine and pass it as a flag."
      return 1
    fi
    # Normalise both sides: strip colons + lowercase
    local _fp_norm _supplied_norm
    _fp_norm="$(printf '%s' "$_fp" | tr -d ':' | tr '[:upper:]' '[:lower:]')"
    _supplied_norm="$(printf '%s' "$INTERNAL_CA_FINGERPRINT" | tr -d ':' | tr '[:upper:]' '[:lower:]')"
    if [[ "$_fp_norm" != "$_supplied_norm" ]]; then
      log_error "Fingerprint mismatch:"
      log_error "  Supplied: ${INTERNAL_CA_FINGERPRINT}"
      log_error "  Actual:   ${_fp}"
      log_error "REFUSING to proceed — possible CA substitution attack"
      return 1
    fi
    log_success "BYO CA fingerprint matches --byo-ca-fingerprint (MUST-1 verified)"
  else
    # Interactive: operator must acknowledge fingerprint out-of-band
    printf "\n  ${C_BOLD}Verify this fingerprint with your CA owner before continuing.${C_RESET}\n"
    printf "  (This is a standard anti-substitution check — same as SSH host key verification.)\n\n"
    if ! prompt_yn "Does this fingerprint match what your CA owner provided?" "n"; then
      log_error "BYO CA rejected by operator — fingerprint mismatch or unverified"
      return 1
    fi
  fi

  log_success "BYO CA accepted — will be staged for PKI bootstrap"
  return 0
}

# _prompt_byo_ca_paths_interactive
# Interactive "provide now" path: prompts for cert + key paths, validates each.
# Loops on unreadable paths. Calls _validate_byo_ca_files after both paths
# are collected. Sets INTERNAL_CA_CERT, INTERNAL_CA_KEY (+ optionally
# INTERNAL_CA_ROOT) globals.
_prompt_byo_ca_paths_interactive() {
  local _cert _key _root _ans

  # Prompt for intermediate CA cert
  while true; do
    printf "  CA intermediate certificate (PEM, absolute path): "
    read -r _cert </dev/tty 2>/dev/null || _cert=""
    _cert="${_cert:-}"
    if [[ -z "$_cert" ]]; then
      log_warn "No path entered — try again, or Ctrl-C to abort"
      continue
    fi
    # Trim any accidental surrounding whitespace
    _cert="$(printf '%s' "$_cert" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -f "$_cert" && -r "$_cert" ]]; then
      break
    fi
    log_warn "File not found or not readable: ${_cert} — try again"
  done
  INTERNAL_CA_CERT="$_cert"

  # Prompt for intermediate CA private key
  while true; do
    printf "  CA private key (PEM, absolute path): "
    read -r _key </dev/tty 2>/dev/null || _key=""
    _key="${_key:-}"
    if [[ -z "$_key" ]]; then
      log_warn "No path entered — try again, or Ctrl-C to abort"
      continue
    fi
    _key="$(printf '%s' "$_key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -f "$_key" && -r "$_key" ]]; then
      break
    fi
    log_warn "File not found or not readable: ${_key} — try again"
  done
  INTERNAL_CA_KEY="$_key"

  # Prompt for root CA cert (optional but recommended for Mode B)
  printf "\n  Root CA certificate (PEM, absolute path; press Enter to skip): "
  read -r _root </dev/tty 2>/dev/null || _root=""
  _root="$(printf '%s' "${_root:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [[ -n "$_root" ]]; then
    if [[ -f "$_root" && -r "$_root" ]]; then
      INTERNAL_CA_ROOT="$_root"
    else
      log_warn "Root CA cert not readable: ${_root} — skipping root cert (chain verification will be limited)"
      INTERNAL_CA_ROOT=""
    fi
  fi

  # Run full validation (includes fingerprint display + operator confirmation)
  _validate_byo_ca_files || return 1
}

select_agent_bundles() {
  set_step "8" "Agent bundle selection"
  log_step "8/${TOTAL_STEPS}" "Optional agent bundles..."

  # -----------------------------------------------------------------------
  # Disclaimer — always printed, cannot be suppressed
  # -----------------------------------------------------------------------
  printf "\n"
  printf "${C_YELLOW}╔═══════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_YELLOW}║  THIRD-PARTY AGENT BUNDLES — COURTESY INTEGRATIONS        ║${C_RESET}\n"
  printf "${C_YELLOW}╠═══════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "${C_YELLOW}║  The following agents are provided AS IS by               ║${C_RESET}\n"
  printf "${C_YELLOW}║  Agnostic Security as a convenience.                      ║${C_RESET}\n"
  printf "${C_YELLOW}║                                                           ║${C_RESET}\n"
  printf "${C_YELLOW}║  • Image digests are pinned to upstream releases and      ║${C_RESET}\n"
  printf "${C_YELLOW}║    updated as part of the Yashigani release cycle.        ║${C_RESET}\n"
  printf "${C_YELLOW}║  • All support, bugs, and feature requests must be        ║${C_RESET}\n"
  printf "${C_YELLOW}║    directed to the upstream maintainers — NOT to          ║${C_RESET}\n"
  printf "${C_YELLOW}║    Agnostic Security support.                             ║${C_RESET}\n"
  printf "${C_YELLOW}║  • OpenClaw uses a Node.js 24 image (~800 MB) which is   ║${C_RESET}\n"
  printf "${C_YELLOW}║    significantly larger than the Python agent images.     ║${C_RESET}\n"
  printf "${C_YELLOW}╚═══════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  # Non-interactive: honour --agent-bundles flag (comma-separated list or empty)
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ -n "$AGENT_BUNDLES" ]]; then
      IFS=',' read -ra _bundles <<< "$AGENT_BUNDLES"
      for _b in "${_bundles[@]}"; do
        _b="${_b// /}"   # trim spaces
        case "$_b" in
          all)
            COMPOSE_PROFILES+=("langflow" "letta" "openclaw")
            log_info "Agent bundle enabled (--agent-bundles): langflow, letta, openclaw"
            ;;
          langflow|letta|openclaw)
            COMPOSE_PROFILES+=("$_b")
            log_info "Agent bundle enabled (--agent-bundles): $_b"
            ;;
          *)
            log_warn "Unknown agent bundle '$_b' in --agent-bundles — skipping"
            ;;
        esac
      done
    else
      log_info "No agent bundles selected (--non-interactive, --agent-bundles not set)"
    fi
    return 0
  fi

  printf "${C_BOLD}Available agent bundles:${C_RESET}\n\n"
  printf "    1) Langflow    — Visual multi-agent workflow builder (MIT)\n"
  printf "    2) Letta       — Stateful agent with persistent memory (Apache 2.0)\n"
  printf "    3) OpenClaw    — Node.js 24 personal AI, 30+ channels (${C_YELLOW}~800 MB${C_RESET}, MIT)\n"
  printf "    4) All of the above\n"
  printf "    0) None — skip agent bundles\n"
  printf "\n"
  printf "${C_BOLD}  Enter your choices (comma-separated, e.g. 1,2 or 4 for all) [0]: ${C_RESET}"

  local choices
  read -r choices </dev/tty 2>/dev/null || choices="0"
  choices="${choices:-0}"

  # Normalize: remove spaces
  choices="$(echo "$choices" | tr -d ' ')"

  # Parse choices
  IFS=',' read -ra selected <<< "$choices"
  for choice in "${selected[@]}"; do
    case "$choice" in
      1)
        COMPOSE_PROFILES+=("langflow")
        log_success "Langflow selected"
        ;;
      2)
        COMPOSE_PROFILES+=("letta")
        log_success "Letta selected"
        ;;
      3)
        COMPOSE_PROFILES+=("openclaw")
        log_warn "OpenClaw uses a Node.js 24 image (~800 MB) — ensure sufficient disk space"
        log_success "OpenClaw selected"
        ;;
      4)
        COMPOSE_PROFILES+=("langflow" "letta" "openclaw")
        log_warn "OpenClaw uses a Node.js 24 image (~800 MB) — ensure sufficient disk space"
        log_success "All agent bundles selected"
        ;;
      0)
        ;;
      *)
        log_warn "Unknown option '$choice' — skipping"
        ;;
    esac
  done

  printf "\n"
  if [[ ${#COMPOSE_PROFILES[@]} -eq 0 ]]; then
    log_info "No agent bundles selected — skipping"
  else
    # Deduplicate in case user entered e.g. 1,5
    local unique_profiles=()
    for p in "${COMPOSE_PROFILES[@]}"; do
      local already=false
      for u in "${unique_profiles[@]+"${unique_profiles[@]}"}"; do
        [[ "$u" == "$p" ]] && already=true
      done
      [[ "$already" == "false" ]] && unique_profiles+=("$p")
    done
    COMPOSE_PROFILES=("${unique_profiles[@]}")
    log_success "Agent bundles selected: ${COMPOSE_PROFILES[*]}"
  fi
}

# =============================================================================
# STEP 9 (compose/vm): docker compose pull
# =============================================================================
compose_pull() {
  set_step "9" "docker compose pull"

  if [[ "$SKIP_PULL" == "true" ]]; then
    log_warn "Skipping docker compose pull (--skip-pull)"

    # V232-P27 / F-NEW-03: Partial-state detector.
    # When --skip-pull is set, the caller assumes images are already present
    # locally.  If remote images are absent, later steps produce confusing errors.
    # Detect early: verify remote images exist OR fail clearly.
    # For gateway/backoffice (in-tree Dockerfiles): build automatically when absent.
    _check_skip_pull_images() {
      local _compose_file="${WORK_DIR}/docker/docker-compose.yml"
      local _missing_external=0

      # Build a list of images for active services only. Profile-only services
      # whose profile is not in COMPOSE_PROFILES are skipped — their images
      # can safely be absent when --skip-pull is used without those profiles.
      local _remote_images
      local _active_profiles_arg="${COMPOSE_PROFILES[*]:-}"
      # Profile-aware extraction using python3+yaml when available
      local _py_script='
import sys, yaml
compose_file, active_profiles_str = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
active_profiles = set(active_profiles_str.split()) if active_profiles_str else set()
try:
    with open(compose_file) as f:
        c = yaml.safe_load(f)
    for svc, data in (c.get("services") or {}).items():
        profiles = data.get("profiles") or []
        img = data.get("image") or ""
        if not img or "yashigani/" in img or img.startswith("${"):
            continue
        if not profiles or any(p in active_profiles for p in profiles):
            print(img)
except Exception:
    pass
'
      if command -v python3 >/dev/null 2>&1 && \
         python3 -c "import yaml" >/dev/null 2>&1; then
        _remote_images=$(python3 -c "$_py_script" "$_compose_file" "$_active_profiles_arg" 2>/dev/null | sort -u)
      fi
      # Fallback to legacy grep (no profile filter) if python3/yaml unavailable
      if [[ -z "${_remote_images:-}" ]]; then
        _remote_images=$(grep '^\s*image:' "$_compose_file" 2>/dev/null \
          | sed 's/.*image:[[:space:]]*//' | sed 's/[[:space:]]*$//' \
          | grep -v 'yashigani/' | grep -v '^\${' | sort -u)
      fi

      for _img in $_remote_images; do
        [[ -z "$_img" ]] && continue
        if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
          # Check by full ref first (name:tag@sha256), then by name:tag only.
          # When images are pre-loaded via save/load (e.g., gate5 rootful harness
          # or air-gap bundle), podman image load does not reconstruct RepoDigests,
          # so 'podman image exists name:tag@sha256' fails even though the image
          # is present by name:tag. Falling back to name:tag check is safe:
          # content integrity is guaranteed by the image ID matching.
          local _name_tag_only="${_img%%@*}"
          if ! podman image exists "$_img" 2>/dev/null && \
             ! podman image exists "$_name_tag_only" 2>/dev/null; then
            log_warn "--skip-pull: remote image '$_img' not found locally"
            _missing_external=1
          fi
        else
          docker image inspect "$_img" >/dev/null 2>&1 || { log_warn "--skip-pull: remote image '$_img' not found locally"; _missing_external=1; }
        fi
      done

      if [[ "$_missing_external" -eq 1 ]]; then
        log_error "--skip-pull set but one or more remote images are missing locally."
        log_error "Remove --skip-pull to pull them, or pre-load: docker pull <image>"
        exit 1
      fi

      # gateway/backoffice: build now if absent on Docker path
      # (Podman builds inline during compose_pull proper)
      if [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
        resolve_compose_cmd
        local _gw_ok _bo_ok
        _gw_ok=$(docker image inspect yashigani/gateway:latest >/dev/null 2>&1 && echo yes || echo no)
        _bo_ok=$(docker image inspect yashigani/backoffice:latest >/dev/null 2>&1 && echo yes || echo no)
        if [[ "$_gw_ok" == "no" || "$_bo_ok" == "no" ]]; then
          log_warn "--skip-pull + Docker: gateway/backoffice absent — building from source"
          "${COMPOSE_CMD[@]}" -f "${WORK_DIR}/docker/docker-compose.yml" build gateway backoffice || {
            log_error "Build failed — cannot continue with --skip-pull and missing images"
            exit 1
          }
          log_success "gateway/backoffice built from source"
        fi
      fi
    }

    if [[ "$DRY_RUN" != "true" ]]; then
      _check_skip_pull_images
    fi
    return 0
  fi

  log_step "9/${TOTAL_STEPS}" "Pulling container images..."

  resolve_compose_cmd

  # --- Docker-only checks (skip entirely when using Podman runtime) ---
  # _ensure_docker_running and _fix_docker_credentials call 'docker info' and
  # docker-credential-osxkeychain which are Docker Desktop-specific. Calling
  # them when YSG_PODMAN_RUNTIME=true hangs because Docker daemon is not running.
  # Podman manages its own machine lifecycle — no equivalent checks needed here.
  if [[ "$YSG_PODMAN_RUNTIME" != "true" ]]; then
    # --- Verify Docker daemon is running before attempting pull ---
    _ensure_docker_running

    # --- Fix Docker credential helper if missing (common macOS issue) ---
    _fix_docker_credentials
  fi

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "${COMPOSE_CMD[*]} -f $compose_file pull"
    return 0
  fi

  # Build local images first (gateway + backoffice have Dockerfiles, not on Docker Hub).
  # v2.23.1: Build ALWAYS runs at step 9, regardless of runtime. Previously
  # Podman skipped here and relied on compose_up (step 10) to build — but
  # that leaves step 9b (PKI bootstrap) with no image to run the issuer
  # from, and stale :latest tags from prior installs silently get used
  # (which lack new modules like yashigani.pki). Per-run rebuild is cheap
  # thanks to container-layer caching; correctness beats a few saved seconds.
  #
  # v2.23.3: Skip build if versioned images are already present in the local
  # store. This supports airgap installs and CI harnesses where images are
  # pre-seeded, and avoids unnecessary registry round-trips for the base image.
  # Check by versioned tag (not :latest) to avoid using stale images.
  _local_images_cached() {
    local _gw _bo
    if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
      _gw="localhost/yashigani/gateway:${YASHIGANI_VERSION}"
      _bo="localhost/yashigani/backoffice:${YASHIGANI_VERSION}"
      podman image inspect "$_gw" >/dev/null 2>&1 && \
        podman image inspect "$_bo" >/dev/null 2>&1
    else
      _gw="yashigani/gateway:${YASHIGANI_VERSION}"
      _bo="yashigani/backoffice:${YASHIGANI_VERSION}"
      docker image inspect "$_gw" >/dev/null 2>&1 && \
        docker image inspect "$_bo" >/dev/null 2>&1
    fi
  }
  if _local_images_cached; then
    log_info "Gateway and backoffice images already present (v${YASHIGANI_VERSION}) — skipping build"
    log_success "Local images ready (cached)"
    # Signal compose_up() to use --pull never so digest-pinned compose image refs
    # don't trigger registry round-trips for pre-seeded images. Only safe when
    # images are pre-seeded by a trusted source (harness tarball cache, airgap
    # bundle); fresh installs build+pull with digest verification as usual.
    YASHIGANI_COMPOSE_PULL_POLICY="never"
  else
    log_info "Building gateway and backoffice images from source..."
    "${COMPOSE_CMD[@]}" -f "$compose_file" build gateway backoffice || {
      log_error "Failed to build gateway/backoffice images. Check Dockerfiles."
      exit 1
    }
    log_success "Local images built"
  fi

  # letta-pgbouncer uses edoburu/pgbouncer:v1.25.1-p0 (same multi-arch image as the
  # existing pgbouncer service — arm64 + amd64, pinned sha256). No local build required.
  # The image is pulled as part of the standard remote image pull step below.

  # Pull all remote images
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    # Podman: pull images in parallel for speed (podman-compose pull is sequential)
    log_info "Pulling remote container images (parallel)..."
    local _images
    _images=$(grep '^\s*image:' "$compose_file" | sed 's/.*image:\s*//' | sed 's/\s*$//' \
      | grep -v 'yashigani/' | grep -v '${' | sort -u)
    # Add profile images if selected
    for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      [[ -z "$_profile" ]] && continue
      case "$_profile" in
        langflow) _images="$_images
docker.io/langflowai/langflow:1.9.0" ;;
        letta) _images="$_images
docker.io/letta/letta:0.16.7" ;;
        openclaw) _images="$_images
ghcr.io/openclaw/openclaw:2026.3.1" ;;
      esac
    done
    # Pull 4 at a time.
    # IMPORTANT: use explicit PID tracking instead of bare `wait` — bare `wait`
    # on Linux bash 5.2 includes the `exec > >(tee ...)` logging coprocess in
    # the wait set, causing a deadlock (install.sh waits for tee; tee waits for
    # install.sh stdout to close; install.sh cannot close stdout until it exits).
    local _count=0
    local _total
    local _batch_pids=()
    _total=$(echo "$_images" | grep -c .)
    for _img in $_images; do
      [[ -z "$_img" ]] && continue
      podman pull "$_img" >/dev/null 2>&1 &
      _batch_pids+=($!)
      _count=$((_count + 1))
      if [[ $((_count % 4)) -eq 0 ]]; then
        wait "${_batch_pids[@]}" 2>/dev/null || true
        _batch_pids=()
        log_info "  pulled $_count/$_total images..."
      fi
    done
    # Wait for any remaining batch
    if [[ ${#_batch_pids[@]} -gt 0 ]]; then
      wait "${_batch_pids[@]}" 2>/dev/null || true
    fi
    log_success "All $_total remote images pulled"
    # v2.23.3: After concurrent Podman pulls, the storage may hold a brief lock.
    # Verify the locally-built images are still visible before proceeding to
    # PKI bootstrap (_pki_run_issuer requires them). Retry once with 2s backoff
    # to accommodate any transient storage lock from the parallel pull.
    local _gw_check=0
    for _retry in 1 2; do
      podman image inspect "localhost/yashigani/gateway:${YASHIGANI_VERSION}" >/dev/null 2>&1 \
        || podman image inspect "yashigani/gateway:${YASHIGANI_VERSION}" >/dev/null 2>&1 \
        && _gw_check=1 && break
      log_warn "Gateway image not immediately visible after parallel pull (retry ${_retry}/2)..."
      sleep 2
    done
    if [[ "$_gw_check" == "0" ]]; then
      log_error "Gateway image not found after parallel pull — rebuilding..."
      "${COMPOSE_CMD[@]}" -f "$compose_file" build gateway || {
        log_error "Gateway rebuild failed — cannot continue"
        exit 1
      }
    fi
  else
    log_info "Pulling remote container images..."
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull --ignore-buildable 2>/dev/null || \
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull --ignore-pull-failures 2>/dev/null || \
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull 2>/dev/null || true
    log_success "Container images ready"
  fi
}

# =============================================================================
# STEP 9a (air-gap): load bundle + verify digests
# =============================================================================
# load_airgap_bundle() is called instead of compose_pull when --air-gap is set.
# Steps:
#   1. Verify bundle file exists (already checked in parse_args, but re-check
#      in case WORK_DIR was detected after parse).
#   2. Verify bundle SHA256 against sidecar manifest (if present).
#   3. Unpack + load each image tar via podman load / docker load.
#   4. Verify each loaded external image digest against airgap/manifest.yml.
# Fail-closed on any mismatch: abort before any service starts.
load_airgap_bundle() {
  set_step "9" "load air-gap bundle"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "load_airgap_bundle: would load ${AIR_GAP_BUNDLE}"
    return 0
  fi

  log_step "9/${TOTAL_STEPS}" "Air-gap: loading bundle ${AIR_GAP_BUNDLE} ..."

  # Locate manifest file — first check WORK_DIR, then same dir as install.sh
  local manifest_file=""
  local _check_dirs=("${WORK_DIR:-}" "$(dirname "${BASH_SOURCE[0]}")" "$(pwd)")
  for _d in "${_check_dirs[@]}"; do
    [[ -z "$_d" ]] && continue
    if [[ -f "${_d}/airgap/manifest.yml" ]]; then
      manifest_file="${_d}/airgap/manifest.yml"
      break
    fi
  done

  if [[ -z "$manifest_file" ]]; then
    log_error "airgap/manifest.yml not found — it must be present alongside install.sh"
    log_error "Transfer airgap/manifest.yml from the connected host along with the bundle."
    exit 1
  fi
  log_info "Air-gap manifest: ${manifest_file}"

  # --- Verify bundle SHA256 against sidecar (if sidecar present) ---
  local sidecar_path
  sidecar_path="${AIR_GAP_BUNDLE%.tar.zst}.manifest"
  if [[ -f "$sidecar_path" ]]; then
    log_info "Verifying bundle integrity against sidecar manifest ..."
    local expected_sha
    expected_sha="$(grep '^# Bundle SHA256:' "$sidecar_path" 2>/dev/null | awk '{print $NF}' || true)"
    if [[ -n "$expected_sha" ]]; then
      # _fips_sha256 routes through OpenSSL FIPS Provider when FIPS_MODE=1
      # (CMMC SC.L2-3.13.11 + FIPS 140-3 §6.4 — N2); falls back to sha256sum
      # or shasum when FIPS_MODE is unset/0.
      local actual_sha
      if [ "${FIPS_MODE:-0}" = "1" ] || openssl version 2>/dev/null | grep -qi 'fips'; then
        actual_sha="$(_fips_sha256 "${AIR_GAP_BUNDLE}")" || {
          log_warn "FIPS SHA-256 computation failed for bundle — skipping integrity check"
          actual_sha="$expected_sha"
        }
      elif command -v sha256sum >/dev/null 2>&1; then
        actual_sha="$(sha256sum "${AIR_GAP_BUNDLE}" | awk '{print $1}')"
      elif command -v shasum >/dev/null 2>&1; then
        actual_sha="$(shasum -a 256 "${AIR_GAP_BUNDLE}" | awk '{print $1}')"
      else
        log_warn "sha256sum / shasum not available — skipping bundle integrity check"
        actual_sha="$expected_sha"
      fi
      if [[ "$actual_sha" != "$expected_sha" ]]; then
        log_error "BUNDLE INTEGRITY FAILURE"
        log_error "  Expected SHA256: ${expected_sha}"
        log_error "  Actual SHA256:   ${actual_sha}"
        log_error "The bundle has been modified or corrupted. ABORTING."
        exit 1
      fi
      log_success "Bundle SHA256 verified: ${actual_sha:0:16}..."
    else
      log_warn "No SHA256 entry in sidecar manifest — integrity check skipped"
    fi
  else
    log_warn "Sidecar manifest not found (${sidecar_path}) — bundle integrity check skipped"
    log_warn "Provide the .manifest sidecar alongside the .tar.zst for defence-in-depth verification"
  fi

  # --- Determine container runtime ---
  local rt
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    rt="podman"
  else
    rt="${YSG_RUNTIME:-docker}"
    command -v podman >/dev/null 2>&1 && rt="podman"
    command -v docker >/dev/null 2>&1 && [[ "$rt" != "podman" ]] && rt="docker"
  fi
  log_info "Loading images with runtime: ${rt}"

  # --- Unpack and load each image tar ---
  local work_dir
  # Temp dir for unpacked image tars — must NOT use /tmp (feedback_no_tmp.md).
  # Use WORK_DIR if available, otherwise HOME.
  local _tmp_base="${WORK_DIR:-${HOME:-$(pwd)}}"
  work_dir="$(mktemp -d "${_tmp_base}/yashigani-airgap-load-XXXXXX")"
  # Trap: clean up on exit
  # shellcheck disable=SC2064
  trap "rm -rf '${work_dir}'" EXIT

  log_info "Unpacking bundle ..."
  tar -C "${work_dir}" -x --zstd -f "${AIR_GAP_BUNDLE}" 2>/dev/null \
    || { log_error "Failed to unpack bundle — is zstd installed? (apt install zstd)"; exit 1; }

  local loaded_count=0
  for tar_file in "${work_dir}"/*.tar; do
    [[ -f "$tar_file" ]] || continue
    log_info "  Loading $(basename "${tar_file}") ..."
    "$rt" load -i "${tar_file}" >/dev/null 2>&1 \
      || { log_error "Failed to load image tar: ${tar_file}"; exit 1; }
    loaded_count=$((loaded_count + 1))
  done

  log_success "Loaded ${loaded_count} image(s) from bundle"

  # --- Verify each external image digest against manifest ---
  log_info "Verifying loaded image digests against airgap/manifest.yml ..."

  local verify_fails=0
  local verify_ok=0

  # Extract all external images with digests (and optional id: field) from manifest.
  # Emits: ref|digest|id  (id may be empty for pre-2B manifests — backwards-compat).
  local manifest_refs
  manifest_refs="$(python3 - "${manifest_file}" <<'PYEOF'
import sys, re

manifest_path = sys.argv[1]
with open(manifest_path) as f:
    lines = f.readlines()

current_profile = None
current_image = {}
in_images = False

def flush(img, profile):
    if img and profile:
        src = img.get('source', 'external')
        ref = img.get('ref', '')
        digest = img.get('digest', '')
        img_id = img.get('id', '')
        if src == 'external' and ref and digest:
            print(f"{ref}|{digest}|{img_id}")

i = 0
while i < len(lines):
    line = lines[i]

    m = re.match(r'^  (\w+):$', line)
    if m:
        flush(current_image, current_profile)
        current_image = {}
        current_profile = m.group(1)
        in_images = False
        i += 1
        continue

    if re.match(r'^    images:', line):
        in_images = True
        i += 1
        continue

    if re.match(r'^profile_aliases:', line):
        flush(current_image, current_profile)
        break

    if in_images and current_profile:
        if re.match(r'^      - name:', line):
            flush(current_image, current_profile)
            current_image = {}
        m2 = re.match(r'^        (\w+): "?([^"#\n]*)"?', line)
        if not m2:
            m2 = re.match(r'^      - (\w+): "?([^"#\n]*)"?', line)
        if m2:
            current_image[m2.group(1).strip()] = m2.group(2).strip().strip('"')

    i += 1
PYEOF
  2>/dev/null || echo "")"

  # Counters: verify_ok = full match; verify_warn_no_id = old bundle, no id field
  local verify_warn_no_id=0

  # Only verify images actually present in the local store (some profiles may not be in bundle)
  while IFS='|' read -r ref expected_digest manifest_id; do
    [[ -z "$ref" || -z "$expected_digest" ]] && continue

    # Check if image was loaded (it may not be in this profile's bundle — skip if absent)
    local img_present=0
    if [[ "$rt" == "podman" ]]; then
      podman image exists "${ref}" 2>/dev/null && img_present=1 || true
    else
      docker image inspect "${ref}" >/dev/null 2>&1 && img_present=1 || true
    fi
    [[ "$img_present" -eq 0 ]] && continue

    # --- Primary path: RepoDigests (populated for registry-pulled images) ---
    local actual_digest=""
    actual_digest="$("$rt" inspect --format='{{index .RepoDigests 0}}' "${ref}" 2>/dev/null \
      | awk -F@ '{print $2}' || true)"

    if [[ -z "$actual_digest" ]]; then
      actual_digest="$("$rt" inspect --format='{{.Digest}}' "${ref}" 2>/dev/null || true)"
    fi

    if [[ -n "$actual_digest" ]]; then
      # Registry-pull path: compare RepoDigest against manifest digest field
      if [[ "$actual_digest" == "$expected_digest" ]]; then
        verify_ok=$((verify_ok + 1))
      else
        log_error "DIGEST MISMATCH: ${ref}"
        log_error "  Manifest: ${expected_digest}"
        log_error "  Loaded:   ${actual_digest}"
        verify_fails=$((verify_fails + 1))
      fi
      continue
    fi

    # --- Fallback path: image config .Id (populated for docker/podman load) ---
    # YSG-RISK-038 / Iris Batch 2 item 2B: docker load does not populate
    # RepoDigests; compare image config SHA-256 (.Id) against manifest id: field.
    local actual_id=""
    actual_id="$("$rt" inspect --format='{{.Id}}' "${ref}" 2>/dev/null || true)"

    if [[ -z "$actual_id" ]]; then
      log_warn "Cannot read digest or id for ${ref} — skipping verification (inspect returned empty)"
      continue
    fi

    if [[ -z "$manifest_id" ]]; then
      # Pre-2B manifest without id: field — warn and skip (backwards-compat).
      # Primary integrity gate is bundle SHA256 (already verified above).
      log_warn "manifest.yml has no id: field for ${ref} — regenerate bundle for full load-path verification"
      verify_warn_no_id=$((verify_warn_no_id + 1))
      continue
    fi

    if [[ "$actual_id" == "$manifest_id" ]]; then
      verify_ok=$((verify_ok + 1))
    else
      log_error "IMAGE ID MISMATCH: ${ref}"
      log_error "  Manifest id: ${manifest_id}"
      log_error "  Loaded   id: ${actual_id}"
      verify_fails=$((verify_fails + 1))
    fi
  done <<< "$manifest_refs"

  if [[ "$verify_fails" -gt 0 ]]; then
    log_error "${verify_fails} image(s) failed digest verification — ABORTING air-gap install"
    log_error "The loaded images do not match airgap/manifest.yml. Do not proceed."
    exit 1
  fi

  log_success "Digest verification complete: ${verify_ok} image(s) verified"
  if [[ "$verify_warn_no_id" -gt 0 ]]; then
    log_warn "${verify_warn_no_id} image(s) skipped load-path id verification (pre-2B manifest — regenerate bundle to enable full verification)"
  fi
  log_info "Air-gap: HIBP check disabled (--air-gap implies --no-hibp)"
  log_info "  If a breach is suspected, rotate all passwords after reinstating network access"
}

# Ensure Docker daemon is running — prompt user to start it if not
_ensure_docker_running() {
  # Skip check for dry-run
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi

  # Check if daemon responds
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  # Daemon not running — try to help
  log_warn "Docker daemon is not running."

  if [[ "$YSG_OS" == "macos" && -d "/Applications/Docker.app" ]]; then
    printf "\n"
    printf "  ${C_BOLD}Docker Desktop needs to be started.${C_RESET}\n\n"

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      log_info "Attempting to start Docker Desktop..."
      open -a Docker 2>/dev/null || true
    else
      printf "    1) Start Docker Desktop automatically\n"
      printf "    2) I'll start it manually — wait for me\n"
      printf "\n"
      printf "  ${C_BOLD}Choice [1]: ${C_RESET}"
      local choice
      read -r choice </dev/tty 2>/dev/null || choice="1"
      choice="${choice:-1}"

      if [[ "$choice" == "1" ]]; then
        log_info "Starting Docker Desktop..."
        open -a Docker 2>/dev/null || true
      fi
    fi

    # Wait for daemon to become available (up to 60 seconds)
    printf "  Waiting for Docker daemon"
    local waited=0
    while ! docker info >/dev/null 2>&1; do
      if [[ $waited -ge 60 ]]; then
        printf "\n"
        log_error "Docker daemon did not start within 60 seconds."
        log_error "Start Docker Desktop manually and re-run the installer."
        exit 1
      fi
      printf "."
      sleep 2
      waited=$((waited + 2))
    done
    printf " ready!\n\n"
    log_success "Docker daemon is running"

  elif command -v podman >/dev/null 2>&1; then
    log_info "Trying: podman machine start..."
    podman machine start 2>/dev/null || true
    sleep 3
    if ! podman info >/dev/null 2>&1; then
      log_error "Podman machine did not start. Run 'podman machine start' manually and re-run."
      exit 1
    fi
    log_success "Podman machine is running"

  else
    log_error "No container runtime is running. Start Docker or Podman and re-run the installer."
    exit 1
  fi
}

# Fix missing Docker credential helper (common on macOS when Docker Desktop
# CLI is symlinked but the credential helpers aren't in PATH)
_fix_docker_credentials() {
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi

  # Only relevant on macOS
  if [[ "$YSG_OS" != "macos" ]]; then return 0; fi

  # Check if the credential helper exists
  if command -v docker-credential-osxkeychain >/dev/null 2>&1; then
    return 0  # Already in PATH
  fi

  # Check Docker Desktop's bundled credential helper
  local cred_helper="/Applications/Docker.app/Contents/Resources/bin/docker-credential-osxkeychain"
  if [[ ! -x "$cred_helper" ]]; then
    # No credential helper at all — configure Docker to not use one
    _docker_config_no_credsStore
    return 0
  fi

  # Credential helper exists but not in PATH — symlink it
  log_info "Docker credential helper not in PATH — fixing..."
  if [[ -t 0 && "$NON_INTERACTIVE" != "true" ]]; then
    printf "  ${C_BOLD}Create symlink for docker-credential-osxkeychain? [Y/n]: ${C_RESET}"
    local choice
    read -r choice </dev/tty 2>/dev/null || choice="y"
    choice="$(echo "${choice:-y}" | tr '[:upper:]' '[:lower:]')"
    if [[ "$choice" != "y" && "$choice" != "yes" && -n "$choice" ]]; then
      _docker_config_no_credsStore
      return 0
    fi
  fi

  if ln -sf "$cred_helper" /usr/local/bin/docker-credential-osxkeychain 2>/dev/null; then
    log_success "docker-credential-osxkeychain symlinked"
  else
    log_warn "Could not create symlink — configuring Docker to pull without credential helper"
    _docker_config_no_credsStore
  fi
}

# Configure Docker to not require a credential helper for pulling public images
_docker_config_no_credsStore() {
  local docker_config="$HOME/.docker/config.json"
  if [[ -f "$docker_config" ]]; then
    # Remove credsStore from config if present (allows anonymous pulls)
    if grep -q '"credsStore"' "$docker_config" 2>/dev/null; then
      log_info "Removing credsStore from Docker config (allows anonymous image pulls)..."
      local tmp_config
      tmp_config="$(mktemp)"
      # Use python3 for safe JSON manipulation
      if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json, sys
with open('${docker_config}') as f:
    cfg = json.load(f)
cfg.pop('credsStore', None)
with open('${tmp_config}', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null && mv "$tmp_config" "$docker_config"
      else
        # Fallback: sed (less safe but works for simple cases)
        sed '/"credsStore"/d' "$docker_config" > "$tmp_config" && mv "$tmp_config" "$docker_config"
      fi
      log_success "Docker config updated — anonymous pulls enabled"
    fi
  fi
}

# =============================================================================
# Pre-compose-up: ensure bind-mounted config files are readable by container UIDs
# =============================================================================
# Config files live in the source tree at their source-tree permissions (0644).
# If the installer runs in a restrictive umask context (e.g. the invoking shell
# set umask 077 before extracting the tarball), extracted files land as 0600 and
# container processes (pgbouncer UID 70, prometheus UID 65534, OPA, caddy, etc.)
# cannot read them.
#
# This function restores readable permissions on all bind-mounted config paths
# immediately before compose_up.  It uses `o+rX` (add read/execute for others,
# preserving existing bits) so:
#   - Regular files: 0600 → 0604 (readable) or 0644 → 0644 (unchanged)
#   - Directories:   0700 → 0705 (traversable)
#
# SECURITY BOUNDARY: this function MUST NOT touch docker/secrets/ — all secret
# files must remain 0600 (or tighter).  Only the specific source-tree paths that
# are bind-mounted as :ro config are widened here.  The secrets dir has its own
# hardened perms enforced by generate_secrets() and _prepare_secrets_dir_for_pki().
#
# Paths enumerated from docker/docker-compose.yml bind-mount audit:
#   config/           — prometheus, alertmanager, grafana, loki, otel, promtail, jaeger
#   policy/           — OPA policy files
#   docker/Caddyfile* — caddy config
#   docker/pgbouncer/ — pgbouncer.ini, pgbouncer-letta.ini
#   docker/postgres/  — init scripts (05-enable-ssl.sh, init-agent-dbs.sh)
#   docker/service_identities.yaml
#   docker/openclaw/  — openclaw.json
#   docker/letta-runtime/ — openapi_letta.json
#   docker/keycloak/  — keycloak realm imports
#
# (fix: umask-077-bleed / Ava phase-1 failure 2026-05-20)
_fix_config_perms() {
  local work_dir="${WORK_DIR}"

  log_info "Ensuring bind-mounted config files are readable by container UIDs..."

  # A2 (Iris SUSTAINABILITY / iris-install-umask-design-review.md §6 Amendment 2):
  # Replace the manually-enumerated _docker_config_paths array with a single
  # find + chmod sweep over the entire work_dir, pruning the four paths that must
  # never be widened:
  #
  #   docker/secrets  — secret material; all perms enforced by generate_secrets()
  #                     and _prepare_secrets_dir_for_pki(); guarded by S1 assertion below
  #   .git            — git repository metadata; not bind-mounted; may contain remote
  #                     URLs with embedded credentials in legacy .git/config formats
  #   .ysg_work       — temp scratch dir used during tarball extraction; cleaned post-install
  #   docker/.env     — secrets-bearing env file; must be 0600 (A4); explicit prune here
  #                     because o+rX on a 0600 file yields 0604 (world-readable).
  #                     A4 (write_env_vars touch+chmod 0600) runs before this sweep,
  #                     so the 0600 bit is already set; this prune is belt-and-suspenders.
  #
  # Rational: manual enumeration drifts when new bind-mounted services land (pgbouncer-letta
  # arc proved this). Single sweep + explicit prune list is the sustainable shape —
  # new compose bind-sources are automatically included without a code change here.
  #
  # NOTE: docker/letta-runtime/openapi_letta.json is :rw (not :ro).
  # WARNING: The letta container WRITES this file at runtime (app.py:162).
  #          Write access requires o+w on the host file because cap_drop:ALL removes
  #          CAP_DAC_OVERRIDE. UID 0 alone is insufficient without DAC_OVERRIDE — the
  #          file must have the other-write bit set (mode 0666). Step 8e sets this
  #          unconditionally on every install/reinstall. Non-secret, non-executable.
  #          (A3 / Iris §2 / iris-letta-openapi-write-design-review.md 2026-05-21
  #           / laura-letta-openapi-0666-threat-model.md 2026-05-21)
  find "${work_dir}" \
    -not \( -path "${work_dir}/docker/secrets" -prune \) \
    -not \( -path "${work_dir}/.git" -prune \) \
    -not \( -path "${work_dir}/.ysg_work" -prune \) \
    -not \( -path "${work_dir}/docker/.env" -prune \) \
    -exec chmod o+rX {} + 2>/dev/null \
    || log_warn "chmod o+rX sweep had partial failures (non-fatal — secrets/ not touched)"

  log_info "  Config sweep applied (work_dir minus secrets/.git/.ysg_work/docker/.env)"

  # Invariant: secrets dir must NOT have been touched — assert no world-readable
  # non-certificate files under docker/secrets/ (CWE-732 / v2.23.1 S1).
  # Note: *.crt files are intentionally 0644 (public material — CA and client certs
  # must be readable by all container UIDs for mTLS peer verification). Only private
  # keys and password/token files are checked here.
  local _secrets_dir="${work_dir}/docker/secrets"
  if [[ -d "$_secrets_dir" ]]; then
    # A1 (Iris BLOCKING / iris-install-umask-design-review.md):
    # Check only WORLD-readable (-perm -004), NOT group-readable (-perm -040).
    # caddy_internal_hmac is intentionally 0640 (group-readable for caddy<->backoffice
    # HMAC handoff); checking -perm -040 caused a false-positive abort on every install.
    # Group-readable is a legitimate design choice for specific files in docker/secrets/;
    # world-readable (o+r) on ANY secret file there is always wrong.
    if find "${_secrets_dir}" -type f ! -name "*.crt" -perm -004 2>/dev/null | grep -q .; then
      log_error "CWE-732: world-readable non-cert file(s) found under ${_secrets_dir} after _fix_config_perms" >&2
      log_error "This is a security regression — check for chmod errors above." >&2
      exit 1
    fi
  fi

  log_success "Bind-mounted config permissions verified"
}

# =============================================================================
# STEP 10 (compose/vm): docker compose up -d
# =============================================================================
compose_up() {
  set_step "10" "compose up"
  log_step "10/${TOTAL_STEPS}" "Starting services..."

  resolve_compose_cmd

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  # Auto-apply Podman rootless override when running on Podman
  local compose_files=("-f" "$compose_file")
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    log_info "Podman detected — configuring rootless deployment"

    # 1. Ensure Podman socket is running and find socket path
    systemctl --user start podman.socket 2>/dev/null || true
    local _podman_sock=""
    # macOS: socket path from podman machine inspect
    if [[ "$(uname)" == "Darwin" ]]; then
      _podman_sock="$(podman machine inspect 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['ConnectionInfo']['PodmanSocket']['Path'])" 2>/dev/null || echo "")"
      # Pool Manager requires rootful Podman Machine for container-per-identity isolation
      if [[ ! -S /var/run/docker.sock ]]; then
        log_warn "Podman Machine socket not found at /var/run/docker.sock"
        log_warn "Pool Manager requires a rootful Podman machine for container-per-identity isolation."
        log_warn "Run the following commands, then re-run this installer:"
        log_warn ""
        log_warn "  podman machine stop 2>/dev/null || true"
        log_warn "  podman machine rm -f 2>/dev/null || true"
        log_warn "  podman machine init --rootful"
        log_warn "  podman machine start"
        log_warn ""
        log_warn "Security note: rootful is required for CIAA-compliant container isolation."
        log_warn "Continuing without Pool Manager — container isolation will be DISABLED."
      fi
    fi
    # Linux: rootful vs rootless socket paths differ.
    #   - Rootful (EUID=0, typical for server installs via sudo): systemd-managed
    #     socket at /run/podman/podman.sock, enabled via `systemctl enable --now podman.socket`.
    #     There is no /run/user/0 unless root has a login systemd user session.
    #   - Rootless (non-root user with `loginctl enable-linger`): XDG runtime at
    #     /run/user/$(id -u)/podman/podman.sock.
    # Retro v2.23.1 Ubuntu podman clean-slate: initial attempt defaulted to the
    # rootless path under sudo, docker-compose plugin then failed to connect.
    if [[ -z "$_podman_sock" ]]; then
      if [[ "$(id -u)" == "0" ]]; then
        _podman_sock="/run/podman/podman.sock"
      else
        _podman_sock="/run/user/$(id -u)/podman/podman.sock"
      fi
    fi
    # Verify socket exists; if rootful and missing, try to bring it up via systemd.
    if [[ ! -S "$_podman_sock" ]]; then
      if [[ "$(id -u)" == "0" && "$_podman_sock" == "/run/podman/podman.sock" ]]; then
        log_info "Enabling rootful podman.socket via systemd"
        systemctl enable --now podman.socket 2>/dev/null || true
      fi
    fi
    if [[ ! -S "$_podman_sock" ]]; then
      log_warn "Podman socket not found at ${_podman_sock} — compose may fail"
    fi
    export DOCKER_HOST="unix://${_podman_sock}"
    # Write socket path for gateway container mount (Pool Manager isolation)
    local env_file="${WORK_DIR}/docker/.env"
    if grep -q "^CONTAINER_SOCKET=" "$env_file" 2>/dev/null; then
      local tmp_env; tmp_env="$(mktemp)"
      sed "s|^CONTAINER_SOCKET=.*|CONTAINER_SOCKET=${_podman_sock}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "CONTAINER_SOCKET=${_podman_sock}" >> "$env_file"
    fi

    # 2. Check port binding — macOS can't bind 80/443 rootless, use high ports
    #    On Linux, also detect if ports are already in use and fall back
    local env_file="${WORK_DIR}/docker/.env"
    local _need_high_ports=0

    if [[ "$(uname)" == "Darwin" ]]; then
      log_info "macOS detected — using high ports (8080/8443) for Caddy"
      _need_high_ports=1
    else
      local port_start
      port_start="$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)"
      if [[ "$port_start" -gt 80 ]]; then
        log_warn "Podman rootless: ports 80/443 require sysctl change"
        log_info "Falling back to high ports (8080/8443)"
        _need_high_ports=1
      fi
    fi

    if [[ "$_need_high_ports" -eq 1 ]]; then
      # CLI flags (--http-port / --https-port) take precedence over the
      # auto-detected high-port defaults. Only apply 8080/8443 defaults if the
      # operator has not already specified a port via flag or pre-existing env var.
      if [[ -z "${YASHIGANI_HTTP_PORT:-}" ]]; then
        grep -q "^YASHIGANI_HTTP_PORT=" "$env_file" 2>/dev/null || echo "YASHIGANI_HTTP_PORT=8080" >> "$env_file"
        export YASHIGANI_HTTP_PORT=8080
      fi
      if [[ -z "${YASHIGANI_HTTPS_PORT:-}" ]]; then
        grep -q "^YASHIGANI_HTTPS_PORT=" "$env_file" 2>/dev/null || echo "YASHIGANI_HTTPS_PORT=8443" >> "$env_file"
        export YASHIGANI_HTTPS_PORT=8443
      fi
    fi

    # Persist CLI-supplied port overrides to .env so compose picks them up.
    # This runs unconditionally (after the high-ports block) — if the operator
    # passed --http-port or --https-port, write those values to .env regardless
    # of platform/rootless detection. update-or-append pattern: sed if key exists,
    # append if not.
    if [[ -n "${YASHIGANI_HTTP_PORT:-}" ]]; then
      if grep -q "^YASHIGANI_HTTP_PORT=" "$env_file" 2>/dev/null; then
        local _tmp_env; _tmp_env="$(mktemp)"
        sed "s|^YASHIGANI_HTTP_PORT=.*|YASHIGANI_HTTP_PORT=${YASHIGANI_HTTP_PORT}|" "$env_file" > "$_tmp_env"
        mv "$_tmp_env" "$env_file"
      else
        echo "YASHIGANI_HTTP_PORT=${YASHIGANI_HTTP_PORT}" >> "$env_file"
      fi
    fi
    if [[ -n "${YASHIGANI_HTTPS_PORT:-}" ]]; then
      if grep -q "^YASHIGANI_HTTPS_PORT=" "$env_file" 2>/dev/null; then
        local _tmp_env; _tmp_env="$(mktemp)"
        sed "s|^YASHIGANI_HTTPS_PORT=.*|YASHIGANI_HTTPS_PORT=${YASHIGANI_HTTPS_PORT}|" "$env_file" > "$_tmp_env"
        mv "$_tmp_env" "$env_file"
      else
        echo "YASHIGANI_HTTPS_PORT=${YASHIGANI_HTTPS_PORT}" >> "$env_file"
      fi
    fi

    # 3. Create Docker-compatible directories for promtail (best-effort).
    # On CI runners (GitHub Actions / Podman) /var/lib/docker does not exist and
    # is owned by root, so a plain mkdir fails with EPERM. The installer body
    # never escalates privilege (feedback_audience_sysadmins.md) — warn and
    # continue; promtail will start with reduced container-log coverage.
    # V232-SMOKE-020 — Podman smoke gate 2026-05-04.
    if [[ ! -d "/var/lib/docker/containers" ]]; then
      if ! mkdir -p /var/lib/docker/containers 2>/dev/null; then
        log_warn "Could not create /var/lib/docker/containers — promtail may not collect container logs"
        log_warn "(run 'sudo mkdir -p /var/lib/docker/containers' before install to suppress this warning)"
      fi
    fi

    # 4. Apply Podman rootless overrides.
    #    COMPOSE_CMD was already resolved by resolve_compose_cmd() above.
    #
    #    Override split (LINUX-SHARED-MOUNT-UID-CLOBBER — #138 regression fix):
    #
    #    docker-compose.podman-override.yml — ALL Podman (Linux + macOS):
    #      security_opt: label=disable (needed where SELinux is active — RHEL/Fedora);
    #      Ollama HOME + OLLAMA_MODELS env; promtail profile disable;
    #      backoffice YASHIGANI_AGENT_UPSTREAM_HOSTNAMES env.
    #      No :U volume entries.
    #
    #    docker-compose.podman-virtiofs-override.yml — macOS Podman ONLY:
    #      :U on all secrets bind-mounts. Required on macOS because podman unshare
    #      is unavailable on the remote client and virtiofs returns EPERM without it.
    #      MUST NOT be loaded on Linux rootless: :U lchowns the ENTIRE host-side
    #      source directory to the last-processed container's subuid-mapped UID,
    #      clobbering the per-file UIDs that `podman unshare chown` set. Consequence:
    #      redis (UID 999) loses ownership of redis_client.key → healthcheck fail →
    #      install hangs at `podman wait`. (Reproduced: Ava Track A v5, 2026-05-13.)
    #
    #    Why :U is safe on macOS but unsafe on Linux:
    #      macOS: no `podman unshare` → per-file UIDs never set → :U sets consistent
    #        subuid ownership so all containers read from the same mapped namespace.
    #      Linux: `podman unshare chown` sets per-file UIDs before containers start.
    #        Adding :U afterward overwrites those per-file UIDs, breaking services
    #        whose UID differs from the last container processed.
    local podman_override="${WORK_DIR}/docker/docker-compose.podman-override.yml"
    if [[ -f "$podman_override" ]]; then
      compose_files+=("-f" "$podman_override")
      log_info "Applying Podman rootless override (security_opt + env overrides)"
    else
      log_warn "Podman rootless override not found at ${podman_override}"
    fi
    # macOS virtiofs :U override — macOS Podman only
    if [[ "$(uname -s)" == "Darwin" ]]; then
      local podman_virtiofs_override="${WORK_DIR}/docker/docker-compose.podman-virtiofs-override.yml"
      if [[ -f "$podman_virtiofs_override" ]]; then
        compose_files+=("-f" "$podman_virtiofs_override")
        log_info "Applying Podman virtiofs :U override (macOS only)"
      else
        log_warn "Podman virtiofs override not found at ${podman_virtiofs_override} — :U mounts will not apply (macOS virtiofs may fail)"
      fi
    fi

    # 5. Build images with podman build (compose build uses Docker buildx)
    #    Skip rebuild on upgrade if images already exist
    local _gw_exists=false _bo_exists=false
    podman image exists yashigani/gateway:latest 2>/dev/null && _gw_exists=true
    podman image exists yashigani/backoffice:latest 2>/dev/null && _bo_exists=true

    if [[ "$UPGRADE" == "true" && "$_gw_exists" == "true" && "$_bo_exists" == "true" ]]; then
      log_info "Images already built — skipping rebuild (upgrade path)"
    else
      log_info "Building images with Podman..."
      # retro #32: do NOT pipe through `tail -1`. The script's outer exec
      # redirect at the top of main() already tees stdout+stderr to
      # install.log. Piping through `tail -1` here truncates build output
      # to a single line BEFORE it reaches the outer tee, so disk-full
      # errors ("no space left on device"), Dockerfile syntax errors, and
      # cache-eviction warnings are silently dropped from the log.
      # Verbose terminal output is the explicit tradeoff for visibility.
      podman build -f "${WORK_DIR}/docker/Dockerfile.gateway" -t yashigani/gateway:latest "${WORK_DIR}"
      podman build -f "${WORK_DIR}/docker/Dockerfile.backoffice" -t yashigani/backoffice:latest "${WORK_DIR}"
      log_success "Images built with Podman"
    fi
  fi

  # Ensure all required directories and secret files exist (handles upgrades,
  # re-runs, and failed previous installs). Docker Desktop for Mac (VirtioFS)
  # does not reliably propagate files to the VM — verify all exist with content.
  local secrets_dir="${WORK_DIR}/docker/secrets"
  local data_dir="${WORK_DIR}/docker/data"
  mkdir -p "$secrets_dir"
  # Podman rootless stale-partial-install guard (gate #ROOTLESS-5):
  # If secrets_dir exists but is owned by a different UID (subuid-mapped 1001, e.g.
  # 363144), a previous partial install got far enough to chown the dir before
  # failing. The installer (e.g. UID 1004) cannot write into it. Since
  # check_existing_installation() already confirmed no containers are running,
  # it's safe to wipe and regenerate — no live data is at risk.
  # Only applies when not explicitly upgrading (UPGRADE=false) and when
  # the dir is NOT owned by the current user AND PKI certs have NOT been generated
  # yet (ca_root.crt absent). If ca_root.crt is present, PKI bootstrap already ran
  # and chowned the dir legitimately — do NOT wipe it.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$(id -u)" != "0" && "${UPGRADE:-false}" != "true" ]]; then
    local _secrets_uid
    # shellcheck disable=SC2012
    _secrets_uid="$(ls -nd "$secrets_dir" 2>/dev/null | awk '{print $3}')"
    if [[ -n "$_secrets_uid" && "$_secrets_uid" != "$(id -u)" && ! -f "${secrets_dir}/ca_root.crt" ]]; then
      log_warn "secrets_dir owned by UID ${_secrets_uid} (not installer UID $(id -u)) — stale partial install detected"
      log_warn "Wiping secrets_dir for clean regeneration (no containers running)"
      # Use podman unshare rm -rf so we can remove files owned by the mapped UID
      # without needing sudo. Falls back to plain rm (which works if we have perms).
      if podman unshare rm -rf "$secrets_dir" 2>/dev/null; then
        log_info "secrets_dir wiped via podman unshare"
      else
        log_warn "Could not wipe via podman unshare — trying direct rm"
        rm -rf "$secrets_dir" 2>/dev/null \
          || { log_error "Cannot wipe stale secrets_dir ${secrets_dir}. Run: sudo rm -rf \"${secrets_dir}\" then re-run."; exit 1; }
      fi
      mkdir -p "$secrets_dir"
      log_info "secrets_dir recreated fresh"
    fi
  fi
  # PKI issuer runs as UID 1001 inside the gateway image and writes cert/key files
  # to the bind-mounted secrets dir. The directory must be writable by UID 1001
  # (or its subuid-mapped equivalent) BEFORE the PKI issuer container runs.
  #
  # For Docker / rootful Podman: chown 1001:1001 now. The installer runs as
  # root (or a user that can chown to 1001), so subsequent writes by the
  # installer process also work because it runs as root.
  #
  # For Podman rootless: the installer runs as a non-root user (e.g. UID 1004).
  # If we chown secrets_dir to UID 363144 (subuid-mapped 1001) NOW, the installer
  # can no longer write to it (1004 is "other", no write bit). DEFER the chown
  # to _prepare_secrets_dir_for_pki(), called just before bootstrap_internal_pki().
  # All installer-side writes happen in this function; by the time PKI bootstrap
  # runs, the chown will have been applied and the container can write its certs.
  #
  # Retro v2.23.1 item #3ad + gate #ROOTLESS-3.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    # Deferred to _prepare_secrets_dir_for_pki() — see comment above.
    log_info "secrets_dir chown deferred to PKI bootstrap (Podman rootless)"
  elif [[ "${YSG_OS:-}" == "macos" ]]; then
    # macOS + Docker (Colima virtiofs): host-side chown to UID 1001 is not
    # possible without root. macOS restricts chown to non-self UIDs regardless
    # of file ownership. This is NOT a problem: Colima's virtiofs maps the
    # host user (e.g. UID 502) → UID 0 inside the VM, and the ephemeral
    # Docker chown in _pki_run_issuer() changed the inode's owner to UID 1001
    # from inside the container. Subsequent containers (PKI issuer, backoffice)
    # running as UID 1001 can write to the directory because virtiofs maintains
    # the UID 1001 mapping persistently in the container namespace.
    # Verified empirically: `docker run --user 1001:1001` can write to a
    # directory chowned via ephemeral container even though `ls -nd` on the
    # macOS host still shows the installer UID. (2026-05-11, M4, Colima 0.x)
    log_info "macOS+Docker: secrets_dir host-UID assertion skipped (Colima virtiofs — container sees UID 1001 from ephemeral chown)"
  else
    # For Docker (non-root caller): _pki_run_issuer() already chowned secrets_dir
    # to UID 1001 via an ephemeral docker container. Attempting chown here again
    # from a non-root installer uid (e.g. 1004) would fail with EPERM because
    # only the owner can re-chown a file they don't own, and UID 1004 no longer
    # owns the dir. So: try chown; if it fails, verify the dir is already owned
    # by UID 1001 (set by _pki_run_issuer). If already correct, this is safe to
    # continue — PKI bootstrap already ran successfully.
    if ! chown 1001:1001 "$secrets_dir" 2>/dev/null; then
      # shellcheck disable=SC2012
      _actual_uid=$(ls -nd "$secrets_dir" 2>/dev/null | awk '{print $3}')
      if [[ "$_actual_uid" == "1001" ]]; then
        log_info "secrets_dir already owned by UID 1001 (set by PKI bootstrap) — chown no-op"
      else
        log_error "Cannot chown ${secrets_dir} to UID 1001:1001."
        log_error "The PKI issuer container (UID 1001) cannot write certs to this directory."
        log_error "Fix (run once as root, then re-run installer as your user):"
        log_error "  sudo chown 1001:1001 \"${secrets_dir}\""
        exit 1
      fi
    else
      log_info "secrets_dir chown 1001:1001 applied"
    fi
    # Defensive assertion: secrets dir must be owned by UID 1001 before proceeding.
    # (Skipped for Podman rootless — subuid remapping means host UID != 1001.)
    # (Skipped for macOS — virtiofs UID mapping; see elif branch above.)
    # shellcheck disable=SC2012
    _actual_uid=$(ls -nd "$secrets_dir" 2>/dev/null | awk '{print $3}')
    if [[ "$_actual_uid" != "1001" ]]; then
      log_error "secrets_dir UID is ${_actual_uid}, expected 1001. Aborting PKI bootstrap."
      exit 1
    fi
  fi
  # For Podman rootless, data_dir is owned by the subuid-remapped UID (e.g. 363144).
  # mkdir as the installer user (e.g. UID 1004) would fail with Permission denied.
  # Use `podman unshare` to create the subdirectory inside the user namespace.
  # Gate #ROOTFUL-1: podman unshare is a rootless-only primitive — calling it as
  # UID 0 (rootful install) prints "please use unshare with rootless" and aborts.
  # Guard on id -u != 0 so rootful installs use the plain mkdir -p path instead.
  # Remote-client fallback: `podman unshare` is unsupported when the local podman
  # binary is configured as a remote client (e.g. macOS Podman tunnels to a VM,
  # or `podman --remote`). On failure, fall back to plain mkdir -p — the dir
  # will be uid-mapped on first container write.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$(id -u)" != "0" ]]; then
    if ! podman unshare mkdir -p "${data_dir}/audit" 2>/dev/null; then
      log_warn "podman unshare unavailable (likely remote client) — falling back to plain mkdir -p"
      mkdir -p "${data_dir}/audit"
    fi
  else
    # Docker / rootful Podman: if data_dir is already owned by UID 1001 (chowned
    # by the bind-mount auto-create step or by a pre-install helper like the test
    # harness), plain mkdir will fail for a non-root installer (EPERM). Use an
    # ephemeral docker container (daemon = root) to create the subdir in that case.
    # Falls back to plain mkdir if docker is not available or if the call fails.
    if ! mkdir -p "${data_dir}/audit" 2>/dev/null; then
      local _alpine_mkdir_digest="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
      # Prefer --pull=never with cached alpine:3; fall back to digest-pinned pull.
      if ! docker run --rm --pull=never \
               --volume "${data_dir}:/d:rw" \
               "alpine:3" mkdir -p /d/audit 2>/dev/null; then
        if ! docker run --rm \
               --volume "${data_dir}:/d:rw" \
               "$_alpine_mkdir_digest" \
               mkdir -p /d/audit 2>/dev/null; then
          log_error "Cannot create ${data_dir}/audit — run: sudo mkdir -p \"${data_dir}/audit\""
          exit 1
        fi
      fi
      log_info "Created ${data_dir}/audit via ephemeral docker container (non-root Docker path)"
    fi
  fi
  # v2.23.2 #47 — Backup directory: must exist before compose up so that
  # Podman rootless bind-mount (-v host:container:ro) does not fail on a
  # missing source path. Docker silently creates missing bind-mount sources;
  # Podman rootless does not, causing backoffice to crash at startup.
  # Fix #85: fail loud on mkdir failure rather than silently continuing.
  if ! mkdir -p "${WORK_DIR}/backups" 2>/dev/null; then
    log_error "Cannot create backups directory: ${WORK_DIR}/backups"
    exit 1
  fi
  if ! mkdir -p "${WORK_DIR}/docker/tls" 2>/dev/null; then
    log_error "Cannot create TLS directory: ${WORK_DIR}/docker/tls"
    exit 1
  fi

  for _secret_file in license_key redis_password postgres_password grafana_admin_password; do
    if [[ ! -s "${secrets_dir}/${_secret_file}" ]]; then
      # gate #ROOTLESS-6: for Podman rootless, secrets_dir may be owned by the PKI
      # container UID (363144) after bootstrap. If the write fails, warn and continue —
      # the service will start without the placeholder (secrets should have been created
      # by generate_secrets() before PKI ran; this path is a safety net for upgrades).
      if ! echo "# placeholder — replace with actual value" > "${secrets_dir}/${_secret_file}" 2>/dev/null; then
        log_warn "Could not create placeholder ${_secret_file} (secrets_dir owned by PKI UID — expected for Podman rootless)"
      else
        chmod 600 "${secrets_dir}/${_secret_file}" 2>/dev/null || true
        log_info "Created secret placeholder: ${_secret_file}"
      fi
    fi
  done

  # Flush filesystem to ensure Docker Desktop Mac (VirtioFS) sees all files
  sync 2>/dev/null || true
  sleep 2

  # Ensure agent bundle token files exist if profiles are selected.
  # Primary write is now in step 8d (main body, before _prepare_secrets_dir_for_pki).
  # This loop is a safety-net for upgrade paths where token files may be missing.
  # BUG-B+-NEW-001: secrets_dir may be subuid-remapped on both Podman rootless
  # re-runs AND the additive re-run (Journey B+) path — use _safe_write_secret
  # which tries direct write, then `podman unshare tee`, then ephemeral container.
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    [[ -z "$_profile" ]] && continue
    local _token_file="${secrets_dir}/${_profile}_token"
    if [[ ! -s "$_token_file" ]]; then
      # BUG-B+-NEW-001: use _safe_write_secret so both the re-run and B+ paths
      # succeed even when secrets_dir is owned by a subuid-remapped UID.
      # BUG-WAVE1-P1-002: 0640 so gateway (GID 1001) can read at runtime.
      if _safe_write_secret "# placeholder — auto-generated at first bootstrap" \
           "$_token_file" "0640"; then
        log_info "Created token placeholder (safety-net): ${_profile}_token"
      else
        log_warn "Could not create token placeholder ${_profile}_token (all write paths failed — step 8d should have written this)"
      fi
    fi
  done

  # Build --profile flags for any selected agent bundles
  local profile_args=()
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    [[ -n "$_profile" ]] && profile_args+=("--profile" "$_profile")
  done

  # BUG-AG-001: air-gap installs must never attempt registry pulls during compose up.
  # SKIP_PULL=true prevents the explicit `compose pull` step (Step 9), but without
  # --pull never, `docker compose up` still issues Pulling calls for any image not
  # locally cached — failing on truly isolated networks.
  #
  # docker compose v2 / docker-compose / podman compose: --pull never
  # podman-compose (Python): does NOT support --pull never; omitting --pull is
  #   correct (no flag = don't pull). We must not pass --pull never to podman-compose
  #   or it will error ("unrecognized arguments").
  local _pull_flag=()
  if [[ "$AIR_GAP" == "true" ]]; then
    if [[ "${COMPOSE_CMD[0]}" != "podman-compose" ]]; then
      _pull_flag=("--pull" "never")
      log_info "Air-gap mode: passing --pull never to compose up (BUG-AG-001)"
    else
      log_info "Air-gap mode: podman-compose selected; omitting --pull (no flag = no pull)"
    fi
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "${COMPOSE_CMD[*]} ${compose_files[*]} ${profile_args[*]+${profile_args[*]}} up ${_pull_flag[*]+${_pull_flag[*]}} -d"
    return 0
  fi

  # Clean up any stale containers/networks from failed previous runs.
  # NEVER use -v (--volumes) — that destroys user data (Postgres, Redis, audit logs).
  log_info "Stopping any existing containers (preserving data volumes)..."
  "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} down 2>/dev/null || true

  if [[ "$UPGRADE" == "true" ]]; then
    # V232-SMOKE-004 (2026-05-03): podman-compose 1.5.x implements depends_on
    # condition: service_healthy by spawning `podman wait --condition=healthy`
    # before starting each dependent service. In the upgrade path from v2.22.x,
    # postgres starts with ssl=off (no ssl keys in PGDATA), so pgbouncer cannot
    # open TLS connections and backoffice's DB connect retries all time out.
    # backoffice therefore never becomes healthy, and `podman wait --condition=healthy
    # backoffice` blocks `compose up` indefinitely — creating a deadlock with
    # _upgrade_postgres_ssl, which cannot run until compose_up returns.
    #
    # Fix: pre-start only postgres (no depends_on blocking) before the full `up -d`,
    # wait for pg_isready, run _upgrade_postgres_ssl inline, then start the rest.
    # This replaces the step-10c call site in install_yashigani() which can no longer
    # be reached when compose_up blocks.
    #
    # docker-compose (Go) does NOT block on depends_on during `up -d` — it starts
    # containers in dependency order but returns immediately. This pre-start block
    # only applies to the Podman path.
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
      log_info "Upgrade + Podman: pre-starting postgres for SSL injection (V232-SMOKE-004)..."
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" up ${_pull_flag[@]+"${_pull_flag[@]}"} -d postgres 2>/dev/null || true
      # Wait up to 60s for postgres to accept connections.
      local _pg_ready=0 _pg_i
      for _pg_i in $(seq 1 30); do
        if "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres pg_isready 2>/dev/null; then
          _pg_ready=1; break
        fi
        sleep 2
      done
      if [[ "$_pg_ready" -eq 0 ]]; then
        log_warn "postgres did not become ready in 60s — SSL injection will be attempted anyway"
      fi

      # podman-compose may restart the OLD postgres container (stopped but not
      # removed) rather than creating a new one. If so, the container's
      # /run/secrets bind-mount points to the OLD work dir, which does not have
      # the v2.23.x mTLS certs. Detect this by checking if postgres_client.crt
      # is accessible inside the container via /run/secrets.
      #
      # If the cert is missing inside the container, use podman cp to copy the
      # cert files from the HOST secrets dir directly into the running container
      # before calling _upgrade_postgres_ssl. _upgrade_postgres_ssl reads the
      # certs from /run/secrets inside the container; this cp makes them available
      # regardless of which bind-mount directory is active.
      local _pg_container_name="docker_postgres_1"
      local _host_secrets="${WORK_DIR}/docker/secrets"
      if ! "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres \
             test -f /run/secrets/postgres_client.crt 2>/dev/null; then
        log_info "  postgres_client.crt not in /run/secrets (old bind-mount) — copying via podman cp"
        # Copy the three files _upgrade_postgres_ssl needs into the container's /run/secrets.
        # This dir exists in the container as a bind-mount (read-only from host), but since
        # the bind-mount source is the old dir (no new certs), we use podman cp to inject
        # the files from the new host secrets dir. podman cp overwrites even into a bind-mounted
        # dir on the container side because Podman copies into the overlay FS layer.
        #
        # NOTE: podman cp into a bind-mounted path works differently: it places the file
        # into the underlying host dir, not an overlay. Since the bind-mount is read-only
        # from compose, we CANNOT write into /run/secrets that way. Instead, inject into
        # /var/lib/postgresql/data (PGDATA) directly — that is the destination used by
        # _upgrade_postgres_ssl anyway. We bypass /run/secrets entirely.
        local _pgdata
        _pgdata=$("${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres \
            bash -c 'echo "${PGDATA:-/var/lib/postgresql/data}"' 2>/dev/null | tr -d '\r\n' || echo "/var/lib/postgresql/data")
        log_info "  PGDATA: ${_pgdata} — injecting certs via podman cp + exec chown"

        # Copy server cert + key into PGDATA
        podman cp "${_host_secrets}/postgres_client.crt" "${_pg_container_name}:${_pgdata}/server.crt" 2>/dev/null || {
          log_error "podman cp postgres_client.crt failed — SSL injection aborted"; return 1
        }
        podman cp "${_host_secrets}/postgres_client.key" "${_pg_container_name}:${_pgdata}/server.key" 2>/dev/null || {
          log_error "podman cp postgres_client.key failed — SSL injection aborted"; return 1
        }
        # CA bundle: root + intermediate (same as _upgrade_postgres_ssl step 1)
        local _tmp_bundle
        # V232-NEG04: use secrets dir for temp bundle — never /tmp
        _tmp_bundle=$(mktemp "${_host_secrets}/.ysg_bundle_XXXXXX.crt" 2>/dev/null || echo "${_host_secrets}/.ysg_bundle.crt")
        cat "${_host_secrets}/ca_root.crt" "${_host_secrets}/ca_intermediate.crt" > "$_tmp_bundle"
        podman cp "$_tmp_bundle" "${_pg_container_name}:${_pgdata}/root.crt" 2>/dev/null || {
          log_error "podman cp ca bundle failed — SSL injection aborted"; rm -f "$_tmp_bundle"; return 1
        }
        rm -f "$_tmp_bundle"

        # chown + chmod the copied files to postgres:postgres (UID 70 in pgvector image)
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata}'
chown postgres:postgres \"\$PGDATA/server.crt\" \"\$PGDATA/server.key\" \"\$PGDATA/root.crt\"
chmod 0644 \"\$PGDATA/server.crt\" \"\$PGDATA/root.crt\"
chmod 0600 \"\$PGDATA/server.key\"
echo '[postgres-ssl-upgrade] certs injected via podman cp + chown'
" 2>&1 || {
          log_error "chown/chmod of injected certs failed — SSL injection aborted"
          return 1
        }

        # Append ssl settings + pg_hba.conf + restart postgres
        # (same steps 2-4 from _upgrade_postgres_ssl, but skipping step 1 since
        # we already placed the certs in PGDATA via podman cp above)
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata}'
if grep -q '^ssl = on' \"\$PGDATA/postgresql.conf\" 2>/dev/null; then
  echo '[postgres-ssl-upgrade] ssl already in postgresql.conf — skipping'
  exit 0
fi
printf \"\n# Yashigani internal mTLS (added by install.sh --upgrade)\nssl = on\nssl_cert_file = 'server.crt'\nssl_key_file  = 'server.key'\nssl_ca_file   = 'root.crt'\nssl_min_protocol_version = 'TLSv1.2'\nlog_connections = on\n\" >> \"\$PGDATA/postgresql.conf\"
echo '[postgres-ssl-upgrade] ssl settings appended to postgresql.conf'
" 2>&1 || { log_error "postgresql.conf update failed"; return 1; }

        "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata}'
cat > \"\$PGDATA/pg_hba.conf\" << 'HBAEOF'
# TYPE  DATABASE  USER  ADDRESS        METHOD
local   all       all                  trust
host    all       all   127.0.0.1/32   trust
host    all       all   ::1/128        trust
hostssl all       all   0.0.0.0/0      scram-sha-256  clientcert=verify-ca
hostssl all       all   ::/0           scram-sha-256  clientcert=verify-ca
hostnossl all     all   0.0.0.0/0      reject
hostnossl all     all   ::/0           reject
HBAEOF
chown postgres:postgres \"\$PGDATA/pg_hba.conf\"
chmod 0600 \"\$PGDATA/pg_hba.conf\"
echo '[postgres-ssl-upgrade] pg_hba.conf updated'
" 2>&1 || { log_error "pg_hba.conf update failed"; return 1; }

        log_info "  Restarting postgres to activate SSL config (cp path)..."
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" restart postgres 2>&1 || true
        # Wait for postgres to come back with SSL on
        local _ssl_ok=0 _ssl_i
        for _ssl_i in $(seq 1 30); do
          local _ssl_check
          _ssl_check=$("${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres \
              psql -U yashigani_app -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")
          if [[ "$_ssl_check" == "on" ]]; then
            log_success "  postgres SSL enabled (cp path, confirmed on retry ${_ssl_i})"
            _ssl_ok=1; break
          fi
          sleep 2
        done
        if [[ "$_ssl_ok" -eq 0 ]]; then
          log_error "postgres SSL upgrade: postgres did not enable ssl=on after restart (cp path)"
          return 1
        fi
        # SCRAM re-hash (same as _upgrade_postgres_ssl step 6)
        local _pg_pass
        _pg_pass=$(cat "${WORK_DIR}/docker/secrets/postgres_password" 2>/dev/null || echo "")
        if [[ -n "$_pg_pass" ]]; then
          "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres \
              psql -U yashigani_app -d yashigani -h 127.0.0.1 \
              -c "ALTER USER yashigani_app WITH PASSWORD '${_pg_pass}';" 2>/dev/null || true
          log_info "  SCRAM re-hash applied (cp path)"
        fi
        log_info "postgres SSL injection complete (cp path) — starting remaining services..."
      else
        # /run/secrets is accessible with the new certs — use the standard path
        log_info "  /run/secrets has new certs — using standard _upgrade_postgres_ssl"
        _upgrade_postgres_ssl || return 1
        log_info "postgres SSL injection complete — starting remaining services..."
      fi
    fi
    log_info "Starting services (upgrade — removing orphaned containers)..."
    # ROOTLESS-9 (v2.23.1): podman-compose up -d returns non-zero when optional
    # services (otel-collector, promtail, grafana) fail to start — even if all
    # core services (gateway, backoffice, pgbouncer, postgres, redis, caddy) are
    # healthy. With set -euo pipefail this caused install to abort before
    # bootstrap_postgres, leaving admin accounts unseeded. Core service health is
    # validated by run_health_check (step 12); this non-zero is non-fatal here.
    # v2.23.3: when images were pre-seeded (YASHIGANI_COMPOSE_PULL_POLICY=never),
    # Docker/Podman's image store has images by name:tag but NOT by digest (the
    # OCI manifest list digest changes when images are saved/loaded via tarballs).
    # docker compose up with digest-pinned image refs (image: foo:tag@sha256:...)
    # fails with "No such image" even with --pull never, because Docker resolves
    # the image by the full spec including digest. Fix: strip @sha256:... from all
    # image: lines in a temporary copy of the compose file, then use that for up.
    # The compose file on disk is NOT modified — the temp file is used only for up.
    # This is equivalent to the --air-gap bundle behaviour.
    local _compose_files_up=("${compose_files[@]}")
    if [[ "${YASHIGANI_COMPOSE_PULL_POLICY:-}" == "never" ]] && \
       [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
      log_info "Pre-seeded mode: stripping image digests in compose file for local cache lookup"
      local _digest_stripped_compose
      _digest_stripped_compose="$(mktemp "${WORK_DIR}/docker/docker-compose.tmp.XXXXXX.yml")"
      sed 's|@sha256:[a-f0-9]\{64\}||g' "${compose_file}" > "$_digest_stripped_compose"
      _compose_files_up=("-f" "$_digest_stripped_compose")
      log_info "  temp compose file: $(basename "$_digest_stripped_compose")"
    fi
    "${COMPOSE_CMD[@]}" "${_compose_files_up[@]}" ${profile_args[@]+"${profile_args[@]}"} up ${_pull_flag[@]+"${_pull_flag[@]}"} -d --remove-orphans || true
    # Clean up temp compose file if it was created
    if [[ "${YASHIGANI_COMPOSE_PULL_POLICY:-}" == "never" ]] && \
       [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
      rm -f "${_digest_stripped_compose:-}" 2>/dev/null || true
    fi
  else
    log_info "Starting services..."
    # ROOTLESS-9: same rationale as upgrade path above.
    # v2.23.3: same digest-strip for pre-seeded images (fresh install path).
    local _compose_files_up2=("${compose_files[@]}")
    if [[ "${YASHIGANI_COMPOSE_PULL_POLICY:-}" == "never" ]] && \
       [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
      log_info "Pre-seeded mode: stripping image digests in compose file for local cache lookup"
      local _digest_stripped_compose2
      _digest_stripped_compose2="$(mktemp "${WORK_DIR}/docker/docker-compose.tmp.XXXXXX.yml")"
      sed 's|@sha256:[a-f0-9]\{64\}||g' "${compose_file}" > "$_digest_stripped_compose2"
      _compose_files_up2=("-f" "$_digest_stripped_compose2")
      log_info "  temp compose file: $(basename "$_digest_stripped_compose2")"
    fi
    "${COMPOSE_CMD[@]}" "${_compose_files_up2[@]}" ${profile_args[@]+"${profile_args[@]}"} up ${_pull_flag[@]+"${_pull_flag[@]}"} -d || true
    if [[ "${YASHIGANI_COMPOSE_PULL_POLICY:-}" == "never" ]] && \
       [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
      rm -f "${_digest_stripped_compose2:-}" 2>/dev/null || true
    fi
  fi

  log_success "Services started"

  # ---------------------------------------------------------------------------
  # Retro #81-c: prometheus config smoke check.
  #
  # Bug f52123c shipped a broken scrape config (http_headers.Host is on the
  # Prom v3 forbidden list) that survived `docker compose up` because the
  # container stays "running" even when /-/ready is 503 from a bad config.
  # The prom healthcheck is /-/healthy (process-up), NOT /-/ready
  # (config-loaded-and-scraping). A clean-slate installer run would therefore
  # report green while /targets was empty.
  #
  # Fix: after compose up, (1) syntactically validate the on-disk config with
  # promtool via a throw-away prometheus:v3.0.1 exec, and (2) poll /-/ready on
  # the running instance. promtool failure is BLOCKING (the config is broken
  # — pretending otherwise is the exact failure mode this retro item fixes).
  # /-/ready failure is a warn (first-boot scrape pool setup can run long on
  # slow hosts; we don't want to fail-close on a timing race).
  # ---------------------------------------------------------------------------
  local prom_cfg="${WORK_DIR}/config/prometheus.yml"
  if [[ -f "$prom_cfg" ]]; then
    log_info "Validating prometheus config with promtool..."
    if "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T prometheus promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1; then
      log_success "promtool check config OK"
    else
      local _promtool_out
      _promtool_out="$("${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T prometheus promtool check config /etc/prometheus/prometheus.yml 2>&1 || true)"
      log_error "promtool rejected ${prom_cfg}:"
      printf '%s
' "$_promtool_out" >&2
      log_error "Prometheus will not scrape. Fix config and re-run. See retro #81-c."
      return 1
    fi

    log_info "Waiting for prometheus /-/ready..."
    local _ready_host="127.0.0.1"
    local _ready_port="9090"
    local _ready_ok=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
      if "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T prometheus wget -qO- "http://localhost:9090/-/ready" 2>/dev/null | grep -q "Ready"; then
        _ready_ok=1; break
      fi
      sleep 2
    done
    if [[ "$_ready_ok" -eq 1 ]]; then
      log_success "prometheus /-/ready OK"
    else
      log_warn "prometheus /-/ready not green after 20s — check 'docker compose logs prometheus' if /targets is empty"
    fi
  fi

  # ---------------------------------------------------------------------------
  # P-9 fix: Podman healthcheck wiring verification.
  #
  # podman-compose and podman compose (Docker backend) both wire compose-file
  # healthcheck: blocks into --healthcheck-command at container create time.
  # However, image-baked OCI HEALTHCHECK directives are silently dropped by
  # podman when compose starts the container (unlike Docker Engine which inherits
  # the image-baked HEALTHCHECK as a fallback when no compose-level override is
  # set). All Yashigani compose services carry explicit healthcheck: blocks to
  # avoid this silent-drop class of bug. This gate verifies wiring after
  # compose up. If any container reports a null healthcheck it means a new
  # service was added without a compose healthcheck block — block-close here.
  # ---------------------------------------------------------------------------
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _podman_verify_healthchecks
  fi

  # ---------------------------------------------------------------------------
  # BUG-INSTALL-ON-CONTAMINATED-VOLUMES (2b): post-compose-up convergence check.
  #
  # install.sh was observed to exit 0 even when the gateway DB-init failed (old
  # PKI CA in postgres_data → mTLS cert mismatch → backoffice DB connects fail).
  # The gateway container itself starts and /healthz returns 200, but any request
  # that touches the DB fails. The step-12 health-check only polls /healthz, not
  # a DB-backed endpoint — so a gateway with a healthy process but broken DB
  # passes the health check.
  #
  # This check adds a BLOCKING gateway convergence probe that also verifies the
  # backoffice /healthz responds via the gateway (Caddy → backoffice routing).
  # If the backoffice is down (DB-init failed), /login returns 502/504, not 200.
  # Failure here exits 1 with a diagnostic dump: last 50 lines of gateway +
  # postgres logs.
  #
  # Called at the END of compose_up() so it runs before bootstrap_postgres.
  # Timeout: 60 seconds (polling every 2s).
  # ---------------------------------------------------------------------------
  _verify_gateway_healthz
}

# =============================================================================
# _verify_gateway_healthz — BUG-INSTALL-ON-CONTAMINATED-VOLUMES (2b)
# =============================================================================
# Post-compose-up convergence gate. Polls:
#   1. Gateway /healthz → must return HTTP 200 (gateway process alive)
#   2. Backoffice /login → must return HTTP 200 via Caddy (proves Caddy→backoffice
#      routing; /login is unauth-200 per health-check.sh retro #3n comment)
#
# If either check times out (60s), dumps gateway + postgres logs and exits 1.
# Exit 0 from compose_up is therefore conditional on both checks passing.
#
# Timeout and poll interval are tunable via env vars for CI:
#   YSG_HEALTHZ_TIMEOUT_S   (default: 60)
#   YSG_HEALTHZ_POLL_S      (default: 2)
_verify_gateway_healthz() {
  local _timeout_s="${YSG_HEALTHZ_TIMEOUT_S:-60}"
  local _poll_s="${YSG_HEALTHZ_POLL_S:-2}"
  local _https_port="${YASHIGANI_HTTPS_PORT:-443}"
  local _domain="${DOMAIN:-localhost}"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "_verify_gateway_healthz (skipped in dry-run)"
    return 0
  fi

  log_info "Convergence gate: polling gateway /healthz (timeout ${_timeout_s}s) — BUG-INSTALL-ON-CONTAMINATED-VOLUMES"

  local _deadline=$(( $(date +%s) + _timeout_s ))
  local _gateway_ok=0

  while [[ "$(date +%s)" -lt "$_deadline" ]]; do
    if curl -sk --max-time 5 \
         --resolve "${_domain}:${_https_port}:127.0.0.1" \
         "https://${_domain}:${_https_port}/healthz" \
         -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "^200$"; then
      _gateway_ok=1
      break
    fi
    sleep "$_poll_s"
  done

  if [[ "$_gateway_ok" -eq 0 ]]; then
    log_error "Convergence gate FAILED: gateway /healthz did not return 200 within ${_timeout_s}s"
    log_error "This typically means:"
    log_error "  - Gateway container crashed (check gateway logs below)"
    log_error "  - PKI cert mismatch (contaminated postgres_data volume — re-run uninstall.sh --remove-volumes)"
    log_error "  - Caddy TLS certificate not yet provisioned"
    log_error ""
    log_error "=== Last 50 lines: gateway logs ==="
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" logs --tail=50 gateway 2>/dev/null || true
    log_error "=== Last 50 lines: postgres logs ==="
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" logs --tail=50 postgres 2>/dev/null || true
    exit 1
  fi

  log_success "Convergence gate: gateway /healthz 200 OK"

  # Now verify backoffice is reachable via Caddy (proves DB layer alive enough
  # for backoffice to start). /login returns 200 when unauth — retro #3n.
  log_info "Convergence gate: polling backoffice /login via Caddy (timeout ${_timeout_s}s)"
  local _deadline2=$(( $(date +%s) + _timeout_s ))
  local _backoffice_ok=0

  while [[ "$(date +%s)" -lt "$_deadline2" ]]; do
    if curl -sk --max-time 5 \
         --resolve "${_domain}:${_https_port}:127.0.0.1" \
         "https://${_domain}:${_https_port}/login" \
         -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "^200$"; then
      _backoffice_ok=1
      break
    fi
    sleep "$_poll_s"
  done

  if [[ "$_backoffice_ok" -eq 0 ]]; then
    log_error "Convergence gate FAILED: backoffice /login did not return 200 within ${_timeout_s}s"
    log_error "Backoffice may have failed to connect to the database."
    log_error "=== Last 50 lines: backoffice logs ==="
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" logs --tail=50 backoffice 2>/dev/null || true
    log_error "=== Last 50 lines: postgres logs ==="
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" logs --tail=50 postgres 2>/dev/null || true
    exit 1
  fi

  log_success "Convergence gate: backoffice /login 200 OK — Caddy→backoffice routing verified"
}

# =============================================================================
# _podman_verify_healthchecks — P-9 post-compose-up healthcheck wiring gate
# =============================================================================
# Iterates running Yashigani containers and asserts each has a non-null
# healthcheck config. Services with intentionally disabled healthchecks
# (OPA scratch image, one-shot init containers) are exempted by name.
# Failure is blocking: a missing healthcheck means depends_on: service_healthy
# will never resolve, causing deadlocks in dependent services.
#
# Exemption list (container name contains substring):
#   policy        — OPA scratch image; no shell for healthcheck (V232-SMOKE-003)
#   ollama-init   — one-shot model-pull job; no persistent healthcheck needed
#   promtail      — disabled in podman-override (no /var/lib/docker mount)
_podman_verify_healthchecks() {
  log_info "P-9: verifying Podman healthcheck wiring for all running containers..."

  # Podman names containers as {project}_{service}_{index} (podman-compose)
  # or {project}-{service}-{index} (podman compose / Docker Compose backend).
  # We check every container whose name contains "yashigani" or matches the
  # compose project prefix.

  local _exempt_patterns=("policy" "ollama-init" "promtail")
  local _missing=()
  local _ok_count=0
  local _skip_count=0

  # List all running containers — capture names into an array.
  # Use while+read loop rather than bash 4+ array-builders so install.sh runs on
  # macOS system bash 3.2 (see scripts/test-installer.sh portability gate).
  local _containers=()
  while IFS= read -r _line; do
    [[ -n "$_line" ]] && _containers+=("$_line")
  done < <(podman ps --format '{{.Names}}' 2>/dev/null || true)

  if [[ "${#_containers[@]}" -eq 0 ]]; then
    log_warn "P-9: no running containers found via 'podman ps' — skipping healthcheck wiring check"
    return 0
  fi

  for _ctr in "${_containers[@]}"; do
    # Skip exempted containers
    local _is_exempt=false
    for _pat in "${_exempt_patterns[@]}"; do
      if [[ "$_ctr" == *"${_pat}"* ]]; then
        _is_exempt=true
        break
      fi
    done
    if [[ "$_is_exempt" == "true" ]]; then
      log_info "  P-9: exempt: $_ctr"
      (( _skip_count++ )) || true
      continue
    fi

    # Inspect healthcheck config
    local _hc
    _hc="$(podman inspect --format '{{json .Config.Healthcheck}}' "$_ctr" 2>/dev/null || echo "null")"
    if [[ "$_hc" == "null" || -z "$_hc" ]]; then
      log_warn "  P-9: MISSING healthcheck: $_ctr (Config.Healthcheck is null)"
      _missing+=("$_ctr")
    else
      log_info "  P-9: OK: $_ctr"
      (( _ok_count++ )) || true
    fi
  done

  if [[ "${#_missing[@]}" -gt 0 ]]; then
    log_error "P-9: ${#_missing[@]} container(s) have no healthcheck wired:"
    for _m in "${_missing[@]}"; do
      log_error "  - $_m (add healthcheck: block to docker-compose.yml for this service)"
    done
    log_error "P-9: Missing healthcheck = depends_on: service_healthy deadlock risk."
    log_error "P-9: Fix: add explicit healthcheck: block to docker/docker-compose.yml."
    return 1
  fi

  log_success "P-9: healthcheck wiring verified — ${_ok_count} containers OK, ${_skip_count} exempt"
}

# =============================================================================
# STEP 10b: Container auto-start on host reboot
# =============================================================================
# Installs OS-level auto-start artifacts so Yashigani containers survive a
# host reboot without operator intervention.
#
# Runtime class dispatch:
#   k8s         → no-op (pod restart is controller-native)
#   macOS       → LaunchAgent plist (login-only; dev-workstation target v2.23.4)
#   Linux Docker → verify/enable docker.service; rely on restart: unless-stopped
#   Linux Podman rootful  → /etc/systemd/system/yashigani.service
#   Linux Podman rootless → loginctl enable-linger + ~/.config/systemd/user/yashigani.service
#
# All sub-functions are idempotent: re-running overwrites existing units safely.
# BUG: BUG-REBOOT-NO-AUTO-START / YSG-RISK-046
# =============================================================================

# Dispatcher — determines runtime class and calls the appropriate sub-function.
_setup_auto_start() {
  # K8s: not our concern. Controllers handle pod restart natively.
  if [[ "${YSG_RUNTIME:-}" == "k8s" || "${MODE:-}" == "k8s" ]]; then
    log_info "Auto-start: K8s runtime — skipping (pod restart managed by controller)"
    return 0
  fi

  # macOS: LaunchAgent path regardless of Podman/Docker
  if [[ "${YSG_OS:-}" == "macos" ]]; then
    _setup_auto_start_macos
    return
  fi

  # Linux Docker
  if [[ "${YSG_RUNTIME:-}" == "docker" ]]; then
    _setup_auto_start_docker_linux
    return
  fi

  # Linux Podman rootful (EUID=0)
  if [[ "${YSG_RUNTIME:-}" == "podman" && "$(id -u)" == "0" ]]; then
    _setup_auto_start_podman_rootful
    return
  fi

  # Linux Podman rootless (EUID != 0)
  if [[ "${YSG_RUNTIME:-}" == "podman" && "$(id -u)" != "0" ]]; then
    _setup_auto_start_podman_rootless
    return
  fi

  log_warn "Auto-start: could not determine runtime class — skipping. Containers will NOT auto-start on reboot."
}

# Linux rootful Podman: writes /etc/systemd/system/yashigani.service
# Rootful installs run as root so no sudo is needed for unit writes.
_setup_auto_start_podman_rootful() {
  log_info "Auto-start: configuring systemd service for rootful Podman (Linux)..."

  if ! command -v systemctl >/dev/null 2>&1; then
    log_warn "Auto-start: systemctl not found — skipping (non-systemd host)."
    log_warn "  Containers will NOT auto-start on reboot. Start manually:"
    log_warn "    cd ${WORK_DIR} && ${COMPOSE_CMD[*]} -f docker/docker-compose.yml up -d"
    return 0
  fi

  local unit_file="/etc/systemd/system/yashigani.service"
  local compose_cmd_str="${COMPOSE_CMD[*]}"

  # Write unit file (rootful install runs as root — no sudo needed)
  cat > "$unit_file" <<EOF
[Unit]
Description=Yashigani MCP Security Gateway
Documentation=https://yashigani.io
After=network-online.target podman.socket
Wants=network-online.target
Requires=podman.socket

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${WORK_DIR}
ExecStart=${compose_cmd_str} -f ${WORK_DIR}/docker/docker-compose.yml up -d
ExecStop=${compose_cmd_str} -f ${WORK_DIR}/docker/docker-compose.yml stop
TimeoutStartSec=300
TimeoutStopSec=120
Restart=no
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$unit_file"

  # Reload daemon so systemd picks up the new unit
  systemctl daemon-reload

  # Enable (creates symlink in wants; survives reboots)
  if systemctl enable yashigani.service; then
    log_success "Auto-start: yashigani.service enabled — containers will start on next boot"
  else
    log_warn "Auto-start: systemctl enable failed — containers may NOT auto-start on reboot"
    log_warn "  Run manually: systemctl enable yashigani.service"
  fi

  # Verify and surface state so operator can see it in the same terminal session
  local _enabled
  _enabled="$(systemctl is-enabled yashigani.service 2>/dev/null || echo 'unknown')"
  if [[ "$_enabled" != "enabled" ]]; then
    log_warn "Auto-start: unit is '${_enabled}' (expected 'enabled') — check: journalctl -xe"
  else
    log_info "Auto-start: systemctl is-enabled yashigani.service → ${_enabled}"
  fi
}

# Linux rootless Podman: loginctl enable-linger + ~/.config/systemd/user/yashigani.service
_setup_auto_start_podman_rootless() {
  log_info "Auto-start: configuring user systemd service for rootless Podman (Linux)..."

  if ! command -v systemctl >/dev/null 2>&1; then
    log_warn "Auto-start: systemctl not found — skipping (non-systemd host)."
    log_warn "  Containers will NOT auto-start on reboot. Start manually:"
    log_warn "    cd ${WORK_DIR} && ${COMPOSE_CMD[*]} -f docker/docker-compose.yml up -d"
    return 0
  fi

  local _runtime_user
  _runtime_user="$(id -un)"

  # Step 1: Enable linger (MUST precede unit enable)
  # loginctl enable-linger requires the user's systemd instance to persist after
  # logout and start before login — without it, containers die on logout and
  # cannot auto-start on boot.
  # The install body never runs sudo (feedback_audience_sysadmins). Linger
  # enablement is a documented pre-flight step (sudo loginctl enable-linger).
  # If the current user already has the capability (e.g. rootful), direct
  # loginctl works; otherwise we warn with a copy-pasteable remediation.
  if loginctl enable-linger "$_runtime_user" 2>/dev/null; then
    log_success "Auto-start: linger enabled for ${_runtime_user}"
  else
    log_warn "Auto-start: linger NOT enabled for ${_runtime_user}."
    log_warn ""
    log_warn "Without linger, containers will die on logout and will NOT auto-start on boot."
    log_warn ""
    log_warn "To enable linger, run BEFORE the next install/restart:"
    log_warn ""
    log_warn "    sudo loginctl enable-linger ${_runtime_user}"
    log_warn ""
    log_warn "Then re-run install.sh to set up the auto-start service unit."
    # Continue — unit install is still useful if linger is added later
  fi

  # Step 2: Create user systemd unit directory if absent
  local unit_dir="${HOME}/.config/systemd/user"
  mkdir -p "$unit_dir"
  chmod 700 "$unit_dir"

  local unit_file="${unit_dir}/yashigani.service"
  local compose_cmd_str="${COMPOSE_CMD[*]}"

  cat > "$unit_file" <<EOF
[Unit]
Description=Yashigani MCP Security Gateway
Documentation=https://yashigani.io
After=default.target podman.socket
Wants=default.target
Requires=podman.socket

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${WORK_DIR}
ExecStart=${compose_cmd_str} -f ${WORK_DIR}/docker/docker-compose.yml up -d
ExecStop=${compose_cmd_str} -f ${WORK_DIR}/docker/docker-compose.yml stop
TimeoutStartSec=300
TimeoutStopSec=120
Restart=no
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

  chmod 600 "$unit_file"

  # Reload and enable in the user systemd instance.
  # Non-fatal: if install is run via `sudo -u <user> bash install.sh` (automated
  # provisioning, CI, multi-user setup) there may be no D-Bus session for that
  # user → "Failed to connect to bus: No medium found".  Mirror the loginctl
  # enable-linger pattern above: warn with remediation, continue.
  if systemctl --user daemon-reload 2>/dev/null; then
    log_success "Auto-start: user systemd daemon reloaded"
  else
    log_warn "Auto-start: systemctl --user daemon-reload failed (no D-Bus session?)."
    log_warn ""
    log_warn "This is expected when install runs without a user login session."
    log_warn "To reload manually after logging in as ${_runtime_user}:"
    log_warn ""
    log_warn "    systemctl --user daemon-reload"
    log_warn ""
    # Continue — the unit file is written; enabling/starting it later still works
  fi

  if systemctl --user enable yashigani.service 2>/dev/null; then
    log_success "Auto-start: user yashigani.service enabled"
  else
    log_warn "Auto-start: systemctl --user enable failed — check: systemctl --user status yashigani.service"
  fi

  # Surface linger state so the operator can verify in the same terminal session
  local _linger
  _linger="$(loginctl show-user "$_runtime_user" --property=Linger --value 2>/dev/null || echo 'unknown')"
  if [[ "$_linger" != "yes" ]]; then
    log_warn "Auto-start: Linger=${_linger} for ${_runtime_user}. Without linger, service will not start on boot."
  else
    log_info "Auto-start: Linger=${_linger} for ${_runtime_user}"
  fi
}

# Linux Docker: verify docker.service is enabled; rely on restart: unless-stopped
# No unit file is written — Docker manages its own daemon lifecycle.
_setup_auto_start_docker_linux() {
  log_info "Auto-start: verifying Docker daemon auto-start (Linux)..."

  if ! command -v systemctl >/dev/null 2>&1; then
    log_warn "Auto-start: systemctl not found. Verify docker.service starts on boot manually."
    return 0
  fi

  local _docker_enabled
  _docker_enabled="$(systemctl is-enabled docker 2>/dev/null || echo 'unknown')"

  if [[ "$_docker_enabled" == "enabled" || "$_docker_enabled" == "static" ]]; then
    log_info "Auto-start: docker.service is ${_docker_enabled} — restart: unless-stopped covers container restart"
    return 0
  fi

  # Not enabled — attempt to enable (Docker installs typically auto-enable; this
  # is a safety net for stripped-down or minimal Docker installations)
  log_warn "Auto-start: docker.service is '${_docker_enabled}' (not enabled). Enabling now..."
  if systemctl enable docker 2>/dev/null; then
    log_success "Auto-start: docker.service enabled — containers will restart on next boot via restart: unless-stopped"
  else
    log_warn "Auto-start: could not enable docker.service. Run: systemctl enable docker"
    log_warn "  Without this, containers will NOT auto-start on host reboot."
  fi
}

# macOS Podman: installs ~/Library/LaunchAgents/io.yashigani.autostart.plist
#
# IMPORTANT — v2.23.4 LIMITATION:
#   This LaunchAgent fires at USER LOGIN, not at system boot. Yashigani on
#   macOS will auto-start when the admin user logs in, but NOT on an unattended
#   reboot before login. This is the correct target for the macOS-Podman
#   dev-workstation persona in v2.23.4. A LaunchDaemon (boot-time, root-owned)
#   is deferred — see BUG-REBOOT-NO-AUTO-START out-of-scope items.
#
# Docker Desktop on macOS manages its own "Start at login" setting via its
# system-tray UI; we do not install a competing LaunchAgent for that path.
_setup_auto_start_macos() {
  log_info "Auto-start: configuring LaunchAgent for macOS Podman..."

  if [[ "${YSG_RUNTIME:-}" != "podman" ]]; then
    log_info "Auto-start: macOS Docker path — Docker Desktop manages its own login-item. Skipping."
    return 0
  fi

  local launch_agents_dir="${HOME}/Library/LaunchAgents"
  mkdir -p "$launch_agents_dir"
  local plist="${launch_agents_dir}/io.yashigani.autostart.plist"
  local compose_cmd_str="${COMPOSE_CMD[*]}"

  # Resolve full path to compose binary — LaunchAgent env may lack PATH entries
  # present in the user's interactive shell (e.g. Homebrew prefix not in PATH)
  local _compose_bin
  _compose_bin="$(command -v podman-compose 2>/dev/null || command -v podman 2>/dev/null || echo 'podman-compose')"

  # Ensure log dir exists before launchctl registers it as a log target
  mkdir -p "${HOME}/.yashigani/logs"

  cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.yashigani.autostart</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>podman machine start 2&gt;/dev/null; ${compose_cmd_str} -f ${WORK_DIR}/docker/docker-compose.yml up -d</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${WORK_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>StandardOutPath</key>
  <string>${HOME}/.yashigani/logs/autostart.log</string>
  <key>StandardErrorPath</key>
  <string>${HOME}/.yashigani/logs/autostart-error.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
    <key>HOME</key>
    <string>${HOME}</string>
  </dict>
</dict>
</plist>
EOF

  chmod 644 "$plist"

  # Load immediately so it is registered for this login session
  launchctl load "$plist" 2>/dev/null || true

  log_success "Auto-start: LaunchAgent installed at ${plist}"
  log_info "  Services will auto-start on next login."
  log_info "  Logs: ${HOME}/.yashigani/logs/autostart.log"
  log_warn "  NOTE (v2.23.4): LaunchAgent fires at USER LOGIN, not at boot."
  log_warn "  On an unattended macOS server, a LaunchDaemon is required (root-owned, deferred to v2.23.5+)."
}

# =============================================================================
# STEP 10c (compose/vm, upgrade only): Postgres SSL upgrade injection
# =============================================================================
# When upgrading FROM a version that lacked internal mTLS (v2.22.x and earlier),
# the Postgres PGDATA volume already exists. The postgres image only runs its
# /docker-entrypoint-initdb.d/*.sh scripts on FIRST init (empty PGDATA), so
# 05-enable-ssl.sh is silently skipped on upgrade. This function detects that
# postgres does not yet have ssl=on and injects the SSL config directly into
# the running (or freshly started) postgres container.
#
# Design choices:
#   * Only runs when UPGRADE=true AND postgres is already running (PGDATA exists).
#   * Starts postgres in a minimal mode (no pgbouncer/app containers) to avoid
#     the chicken-and-egg: apps need pgbouncer, pgbouncer needs ssl postgres.
#   * Resets the yashigani_app password to force SCRAM-SHA-256 re-hash.
#     On upgrade the old SCRAM hash may have been computed with different
#     parameters; a password reset forces postgres to recompute the hash with
#     the current scram_iterations setting (retro N1-HARNESS-003, 2026-05-02).
#   * Fail-closed: if postgres cannot be reached after the restart, returns 1.
#
# Retro N1-HARNESS-002 (2026-05-02): this function was absent and caused
# v2.22.3 → v2.23.1 upgrade to fail with pgbouncer "server down" because
# postgres had ssl=off with pg_hba.conf requiring ssl + clientcert.
_upgrade_postgres_ssl() {
  if [[ "$UPGRADE" != "true" ]]; then
    return 0
  fi

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"
  resolve_compose_cmd

  # Check if postgres is running and whether SSL is already on.
  log_info "Checking postgres SSL state (upgrade path)..."
  local _ssl_state
  _ssl_state=$("${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres \
      psql -U yashigani_app -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")

  if [[ "$_ssl_state" == "on" ]]; then
    log_info "Postgres SSL already enabled — skipping SSL upgrade injection"
    return 0
  fi

  log_info "Postgres SSL is '${_ssl_state}' — injecting SSL config for v2.23.1 upgrade"

  # Inject SSL configuration into PGDATA.
  local _pgdata_path
  _pgdata_path=$("${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres \
      bash -c 'echo "${PGDATA:-/var/lib/postgresql/data}"' 2>/dev/null | tr -d '\r\n' || echo "/var/lib/postgresql/data")

  log_info "  PGDATA: ${_pgdata_path}"

  # Step 1: Install server cert + key into PGDATA.
  "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata_path}'
install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt \"\$PGDATA/server.crt\"
install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key \"\$PGDATA/server.key\"
# Trust bundle: root + intermediate concatenated.
cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > \"\$PGDATA/root.crt\"
chown postgres:postgres \"\$PGDATA/root.crt\"
chmod 0640 \"\$PGDATA/root.crt\"
echo '[postgres-ssl-upgrade] Server cert + trust bundle installed'
" 2>&1 || {
    log_error "postgres SSL upgrade: failed to install server cert — cannot enable SSL"
    return 1
  }

  # Step 2: Append ssl settings to postgresql.conf (only if not already present).
  "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata_path}'
if grep -q '^ssl = on' \"\$PGDATA/postgresql.conf\" 2>/dev/null; then
  echo '[postgres-ssl-upgrade] ssl already in postgresql.conf — skipping'
  exit 0
fi
printf \"\n# Yashigani internal mTLS (added by install.sh --upgrade)\nssl = on\nssl_cert_file = 'server.crt'\nssl_key_file  = 'server.key'\nssl_ca_file   = 'root.crt'\nssl_min_protocol_version = 'TLSv1.2'\nlog_connections = on\n\" >> \"\$PGDATA/postgresql.conf\"
echo '[postgres-ssl-upgrade] ssl settings appended to postgresql.conf'
" 2>&1 || {
    log_error "postgres SSL upgrade: failed to update postgresql.conf"
    return 1
  }

  # Step 3: Overwrite pg_hba.conf to require TLS + clientcert (same as 05-enable-ssl.sh).
  "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres bash -c "
set -euo pipefail
PGDATA='${_pgdata_path}'
cat > \"\$PGDATA/pg_hba.conf\" << 'HBAEOF'
# TYPE  DATABASE  USER  ADDRESS        METHOD
# Local socket — used by the postgres docker-entrypoint itself for init.
local   all       all                  trust
# Loopback — postgres image runs its own bootstrap on 127.0.0.1.
host    all       all   127.0.0.1/32   trust
host    all       all   ::1/128        trust
# Everything else must come in over TLS with a client cert signed by our
# internal CA, AND present a valid scram-sha-256 password. Three factors.
hostssl all       all   0.0.0.0/0      scram-sha-256  clientcert=verify-ca
hostssl all       all   ::/0           scram-sha-256  clientcert=verify-ca
# Defence in depth — explicitly reject any plaintext attempt.
hostnossl all     all   0.0.0.0/0      reject
hostnossl all     all   ::/0           reject
HBAEOF
chown postgres:postgres \"\$PGDATA/pg_hba.conf\"
chmod 0600 \"\$PGDATA/pg_hba.conf\"
echo '[postgres-ssl-upgrade] pg_hba.conf updated'
" 2>&1 || {
    log_error "postgres SSL upgrade: failed to update pg_hba.conf"
    return 1
  }

  # Step 4: Restart postgres to pick up new config.
  log_info "  Restarting postgres to activate SSL config..."
  "${COMPOSE_CMD[@]}" -f "$compose_file" restart postgres 2>&1 || {
    log_error "postgres SSL upgrade: failed to restart postgres"
    return 1
  }

  # Step 5: Wait for postgres to come back.
  local _retries=30 _i
  for _i in $(seq 1 $_retries); do
    local _ssl_check
    _ssl_check=$("${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres \
        psql -U yashigani_app -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")
    if [[ "$_ssl_check" == "on" ]]; then
      log_success "postgres SSL enabled (confirmed on retry ${_i})"
      break
    fi
    if [[ "$_i" -eq "$_retries" ]]; then
      log_error "postgres SSL upgrade: postgres did not enable ssl=on after restart"
      return 1
    fi
    sleep 2
  done

  # Step 6: Reset yashigani_app password to force SCRAM-SHA-256 re-hash.
  # Retro N1-HARNESS-003 (2026-05-02): upgrading from v2.22.x leaves the SCRAM
  # hash with parameters that may not match the server's current
  # scram_iterations. A password reset forces postgres to recompute the hash.
  local _pg_pass
  _pg_pass=$(cat "${WORK_DIR}/docker/secrets/postgres_password" 2>/dev/null || \
             grep -oP '(?<=POSTGRES_PASSWORD=)[^ ]+' "${WORK_DIR}/docker/.env" 2>/dev/null | head -1 || echo "")
  if [[ -z "$_pg_pass" ]]; then
    log_warn "postgres SSL upgrade: could not read postgres_password — skipping SCRAM re-hash"
  else
    "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres \
        psql -U yashigani_app -d yashigani -h 127.0.0.1 \
        -c "ALTER USER yashigani_app WITH PASSWORD '${_pg_pass}';" 2>&1 || {
      log_warn "postgres SSL upgrade: SCRAM re-hash failed — pgbouncer auth may fail"
    }
    log_info "  yashigani_app SCRAM hash refreshed"
  fi

  log_success "Postgres SSL upgrade injection complete"
}

# =============================================================================
# STEP 11 (compose/vm): Bootstrap Postgres
# =============================================================================
bootstrap_postgres() {
  set_step "11" "Bootstrap Postgres"
  log_step "11/${TOTAL_STEPS}" "Bootstrapping database..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "docker compose exec backoffice python scripts/bootstrap_postgres.py"
    return 0
  fi

  # Wait for backoffice to be ready before running bootstrap.
  # v2.23.1: backoffice terminates mTLS on :8443 — the readiness probe must
  # present a client cert, same pattern as the Dockerfile HEALTHCHECK.
  local retries=45
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"
  resolve_compose_cmd
  log_info "Waiting for backoffice to be ready..."
  for i in $(seq 1 $retries); do
    if "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T backoffice python -c "import ssl, urllib.request; c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); c.load_cert_chain('/run/secrets/backoffice_client.crt','/run/secrets/backoffice_client.key'); urllib.request.urlopen('https://localhost:8443/healthz', context=c)" >/dev/null 2>&1; then
      break
    fi
    if [[ "$i" -eq "$retries" ]]; then
      log_warn "Backoffice not ready after ${retries} attempts — skipping DB bootstrap"
      log_info "Run manually later: docker compose exec backoffice python scripts/bootstrap_postgres.py"
      return 0
    fi
    sleep 2
  done

  # Run Alembic migrations + seed data via the backoffice container
  "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T backoffice python -m alembic upgrade head 2>&1 || {
    log_warn "Alembic migrations failed — database may already be bootstrapped"
  }

  log_success "Database bootstrapped"
}

# =============================================================================
# STEP 11b (compose): Register agent bundles via backoffice API
# =============================================================================
register_agent_bundles() {
  if [[ ${#COMPOSE_PROFILES[@]} -eq 0 ]]; then
    return 0
  fi

  log_info "Registering agent bundles with backoffice..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Register agent bundles: ${COMPOSE_PROFILES[*]}"
    return 0
  fi

  # v2.23.1: backoffice terminates mTLS on :8443. Intra-container calls below
  # present the backoffice client cert + CA (same pattern as the Dockerfile
  # HEALTHCHECK). `backoffice_url` dropped — was unused dead code.
  local secrets_dir="${WORK_DIR}/docker/secrets"
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  # Rebuild compose file args (same logic as compose_up — keep in sync)
  local compose_files=("-f" "$compose_file")
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    local podman_override="${WORK_DIR}/docker/docker-compose.podman-override.yml"
    [[ -f "$podman_override" ]] && compose_files+=("-f" "$podman_override")
    # macOS virtiofs :U override — macOS Podman only (see compose_up for full rationale)
    if [[ "$(uname -s)" == "Darwin" ]]; then
      local podman_virtiofs_override="${WORK_DIR}/docker/docker-compose.podman-virtiofs-override.yml"
      [[ -f "$podman_virtiofs_override" ]] && compose_files+=("-f" "$podman_virtiofs_override")
    fi
  fi

  # Run the entire registration flow inside the backoffice container.
  # This avoids shell interpolation issues and timing problems with TOTP.
  # The Python script reads secrets from /run/secrets/, computes TOTP,
  # authenticates, checks the live registry, registers each unregistered agent,
  # and writes tokens to /run/secrets/.
  #
  # YSG-AGENT-REG-001 fix: skip decision moved into Python (registry-aware).
  # The old shell-side guard checked token file existence, which diverges from
  # registry state when the secrets dir is preserved across a re-install that
  # wiped Docker volumes (registry empty, token files stale-real-valued → all
  # agents skipped, registry stays empty). The Python script now calls
  # GET /admin/agents after login to get the live registry state and skips
  # only agents that are ACTUALLY registered — not agents with stale token files.
  local agents_json='['
  local first=true
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    [[ -z "$_profile" ]] && continue
    case "$_profile" in
      langflow)  local _name="langflow"  _url="http://langflow:7860"   _proto="langflow" ;;
      letta)     local _name="letta"     _url="http://letta:8283"     _proto="letta" ;;
      openclaw)  local _name="openclaw"  _url="http://openclaw:18789" _proto="openai" ;;
      *) continue ;;
    esac
    $first || agents_json+=','
    agents_json+="{\"profile\":\"${_profile}\",\"name\":\"${_name}\",\"url\":\"${_url}\",\"protocol\":\"${_proto}\"}"
    first=false
  done
  agents_json+=']'

  if [[ "$agents_json" == "[]" ]]; then
    log_info "No new agents to register"
    return 0
  fi

  local reg_output
  local reg_exit=0
  reg_output="$("${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T -e AGENTS_JSON="${agents_json}" backoffice \
    python3 -c '
import json, os, ssl, sys, time, urllib.request

secrets = "/run/secrets"
def read_secret(name):
    try:
        return open(os.path.join(secrets, name)).read().strip()
    except:
        return ""

# v2.23.1: backoffice serves mTLS on :8443. Present the client cert on every
# call (same chain used by the Dockerfile HEALTHCHECK).
# Pattern A for Python ssl: trust anchor is the PUBLIC ca_root.crt. Python
# 3.12/OpenSSL 3.0/Ubuntu 24.04 strict chain validation rejects intermediate-
# only anchors (gate #58a evidence, 2026-04-28). Private ca_root.key never
# enters a workload container.
_ctx = ssl.create_default_context(cafile=os.path.join(secrets, "ca_root.crt"))
_ctx.load_cert_chain(
    os.path.join(secrets, "backoffice_client.crt"),
    os.path.join(secrets, "backoffice_client.key"),
)

user = read_secret("admin1_username")
pw = read_secret("admin1_password")
totp_secret = read_secret("admin1_totp_secret")
caddy_hmac = read_secret("caddy_internal_hmac")
if not all([user, pw, totp_secret, caddy_hmac]):
    print("ERROR:missing_secrets", file=sys.stderr)
    sys.exit(1)

# Compute TOTP using pyotp with SHA-256 (same as backoffice)
import pyotp, hashlib
totp_code = pyotp.TOTP(totp_secret, digest=hashlib.sha256).now()

# Login — Layer B: X-Caddy-Verified-Secret required on every direct backoffice call
login_data = json.dumps({"username": user, "password": pw, "totp_code": totp_code}).encode()
req = urllib.request.Request("https://localhost:8443/auth/login", data=login_data,
                             headers={"Content-Type": "application/json",
                                      "X-Caddy-Verified-Secret": caddy_hmac})
try:
    resp = urllib.request.urlopen(req, context=_ctx)
except Exception as e:
    print(f"ERROR:login_failed:{e}", file=sys.stderr)
    sys.exit(1)

session = ""
cookie = resp.headers.get("Set-Cookie", "")
for part in cookie.split(";"):
    part = part.strip()
    if part.startswith("__Host-yashigani_admin_session="):
        session = part.split("=", 1)[1]
        break

if not session:
    print("ERROR:no_session_cookie", file=sys.stderr)
    sys.exit(1)

# Step-up — POST /admin/agents requires StepUpAdminSession (assert_fresh_stepup).
# A single stepup covers all agent registrations within the 300 s TTL.
#
# ISSUE-020 (2026-05-19): login and stepup both call pyotp.TOTP(...).now().  If
# both calls land in the same 30 s TOTP window the Postgres-backed replay
# cache already holds that window code (inserted by login) and rejects
# the stepup with invalid_totp_code → session last_totp_verified_at never set
# → POST /admin/agents returns 401 step_up_required on every attempt.
#
# Fix: sleep until the start of the NEXT 30 s TOTP window before computing the
# stepup code.  Worst-case latency: 30 s; best-case: ~1 s (called at window
# boundary).  Acceptable in an already-long install path.
_remaining = 30 - (int(time.time()) % 30)
# Add 1 s margin so the new window is firmly established before we compute.
time.sleep(_remaining + 1)
stepup_code = pyotp.TOTP(totp_secret, digest=hashlib.sha256).now()
stepup_data = json.dumps({"totp_code": stepup_code}).encode()
req = urllib.request.Request("https://localhost:8443/auth/stepup", data=stepup_data,
                             headers={"Content-Type": "application/json",
                                      "X-Caddy-Verified-Secret": caddy_hmac,
                                      "Cookie": f"__Host-yashigani_admin_session={session}"})
# Hard-fail on stepup failure.  A successful stepup is required before any
# POST /admin/agents call.  The server updates last_totp_verified_at in the
# existing session (no new cookie is issued) so the same session cookie is
# valid for the subsequent POSTs.
try:
    stepup_resp = urllib.request.urlopen(req, context=_ctx)
    stepup_body = json.loads(stepup_resp.read())
    if not stepup_body.get("stepup_verified"):
        print(f"ERROR:stepup_not_verified:{stepup_body}", file=sys.stderr)
        sys.exit(1)
except urllib.error.HTTPError as e:
    detail = e.read().decode()[:200]
    print(f"ERROR:stepup_failed:{e.code}:{detail}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR:stepup_failed:{e}", file=sys.stderr)
    sys.exit(1)

# YSG-AGENT-REG-001: query the live registry before registering.
# GET /admin/agents returns all agents currently in Redis. This is the
# authoritative source — token files on disk can diverge from the registry
# when secrets_dir is preserved across a re-install that wiped volumes.
# Agents already in the registry are skipped (idempotent); agents absent
# from the registry are registered even if a stale token file exists.
registered_names = set()
try:
    req = urllib.request.Request("https://localhost:8443/admin/agents",
                                 headers={"X-Caddy-Verified-Secret": caddy_hmac,
                                          "Cookie": f"__Host-yashigani_admin_session={session}"})
    resp = urllib.request.urlopen(req, context=_ctx)
    existing = json.loads(resp.read())
    registered_names = {a.get("name", "") for a in existing}
except Exception as e:
    # Non-fatal: if list fails, attempt registration for all agents.
    # Worst case: duplicate registration attempt → 409 Conflict (handled below).
    print(f"WARNING:list_agents_failed:{e}", file=sys.stderr)

# Register agents
agents = json.loads(os.environ.get("AGENTS_JSON", "[]"))
results = []
for agent in agents:
    profile = agent["profile"]
    aname = agent["name"]
    # Skip if agent is already registered in the live registry (idempotent).
    # This check uses registry state, not token-file existence, so it correctly
    # handles: fresh install (registry empty → register), upgrade (registry has
    # agent → skip), re-install with wiped volumes (registry empty, stale token
    # file → register and overwrite stale token).
    if aname in registered_names:
        results.append("SKIP:" + aname + ":" + profile)
        continue
    reg_data = json.dumps({"name": aname, "upstream_url": agent["url"], "protocol": agent.get("protocol", "openai")}).encode()
    # ISSUE-019 (2026-05-19): POST /admin/agents requires a SPIFFE ID
    # (require_spiffe_id gate, YSG-RISK-012b / ASVS V10.3.5).  install.sh runs
    # inside the backoffice container and calls localhost:8443 directly (not via
    # Caddy), so Caddy cannot inject X-SPIFFE-ID from the TLS peer cert.
    # SpiffePeerCertMiddleware cannot extract the peer cert via the ASGI TLS
    # extension because uvicorn does not expose it (confirmed 0.39.0 / 0.46.0).
    # We inject the backoffice identity explicitly.  Trust anchor: this code
    # runs inside the backoffice container, which is the only entity that holds
    # backoffice_client.crt.  CaddyVerifiedMiddleware Layer B (X-Caddy-Verified-
    # Secret HMAC) prevents an external attacker from reaching this route.
    req = urllib.request.Request("https://localhost:8443/admin/agents", data=reg_data,
                                 headers={"Content-Type": "application/json",
                                          "X-Caddy-Verified-Secret": caddy_hmac,
                                          "X-SPIFFE-ID": "spiffe://yashigani.internal/backoffice",
                                          "Cookie": f"__Host-yashigani_admin_session={session}"})
    try:
        resp = urllib.request.urlopen(req, context=_ctx)
        body = json.loads(resp.read())
        token = body.get("token", "")
        if token:
            token_path = os.path.join(secrets, profile + "_token")
            try:
                with open(token_path, "w") as f:
                    f.write(token)
                try:
                    # BUG-WAVE1-P1-002: 0640 so gateway (GID 1001 group) can read at
                    # runtime when installer wrote the file as a different UID.
                    os.chmod(token_path, 0o640)
                except OSError as _chmod_err:
                    # best-effort; host-side chmod applied below.
                    # Log so the issue is visible in install.log (e.g. owner mismatch
                    # on Podman rootless where file owner is UID 101000 inside the
                    # container but a different UID on the host).
                    print(f"WARNING:chmod_640_failed:{token_path}:{_chmod_err}", file=sys.stderr)
            except PermissionError:
                pass  # token printed below for host-side capture
            results.append("OK:" + aname + ":" + profile + ":" + token)
        else:
            results.append("FAIL:" + aname + ":no_token")
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:100]
        results.append("FAIL:" + aname + ":" + str(e.code) + ":" + detail)
    except Exception as e:
        results.append("FAIL:" + aname + ":" + str(e))

for r in results:
    print(r)
' 2>&1)" || reg_exit=$?

  # Hard-fail on stepup errors (Python sys.exit(1); output contains ERROR:stepup_*).
  # Per ISSUE-020: stepup failure means NO agent can be registered; continuing is
  # misleading and violates [[feedback_test_harness_no_fake_green]] applied to
  # install scripts — an advertised flag that silently fails is a fake-green class.
  if [[ $reg_exit -ne 0 ]] && echo "$reg_output" | grep -qE '^ERROR:stepup'; then
    log_error "Agent registration aborted: stepup failed"
    echo "$reg_output" | grep '^ERROR:stepup' >&2
    return 1
  fi

  # Parse results
  local any_registered=false
  while IFS= read -r line; do
    case "$line" in
      OK:*)
        local _parts="${line#OK:}"
        local _agent_name="${_parts%%:*}"
        # Extract profile:token from OK:name:profile:token
        local _rest="${_parts#*:}"
        local _profile="${_rest%%:*}"
        local _token="${_rest#*:}"
        if [[ -n "$_profile" && -n "$_token" && "$_token" != "$_profile" ]]; then
          # ISSUE-027 (2026-05-19): Docker-rootful fallback — Python inside the
          # container may fail to write the token (EACCES) and fall through to
          # printing it for host-side capture.  On Podman rootless the Python step
          # succeeds and the file is already owned by the container UID (101000);
          # the host-side echo then fails with EACCES.  Make the write non-fatal:
          # attempt it (covers Docker rootful where Python failed), and if it fails
          # verify the file was already populated by Python.  Either path is correct.
          if ! echo "$_token" > "${secrets_dir}/${_profile}_token" 2>/dev/null; then
            if [[ ! -s "${secrets_dir}/${_profile}_token" ]]; then
              log_warn "  ${_agent_name}: token write failed and file not populated — token may be missing from secrets dir"
            else
              # Podman rootless: Python wrote the file as UID 101000; host chmod may
              # fail (owner mismatch) but try anyway — os.chmod() in Python above
              # already ran as the file owner and is the primary hardening mechanism.
              # BUG-WAVE1-P1-002 (part B): use 0640 not 0600 so gateway (GID 1001)
              # can read the token at runtime via group permission.
              chmod 0640 "${secrets_dir}/${_profile}_token" 2>/dev/null || true
            fi
          else
            # BUG-WAVE1-P1-002 (part B): 0640 preserves gateway GID 1001 group-read.
            chmod 0640 "${secrets_dir}/${_profile}_token" 2>/dev/null || true
          fi
        fi
        log_success "  ${_agent_name}: registered"
        any_registered=true
        ;;
      SKIP:*)
        # YSG-AGENT-REG-001: agent already in registry — no re-registration needed.
        local _skip_parts="${line#SKIP:}"
        local _skip_name="${_skip_parts%%:*}"
        log_info "  ${_skip_name}: already registered — skipping"
        ;;
      FAIL:*)
        local _fail_detail="${line#FAIL:}"
        log_warn "  ${_fail_detail}"
        ;;
      ERROR:*)
        log_warn "Agent registration: ${line#ERROR:}"
        ;;
    esac
  done <<< "$reg_output"

  if $any_registered; then
    # Restart agent containers so they pick up the new tokens
    log_info "Restarting agent containers with new tokens..."
    for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      [[ -z "$_profile" ]] && continue
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" --profile "$_profile" restart "$_profile" 2>/dev/null || true
    done
    log_success "Agent bundle registration complete"

    # Pre-populate agents in Open WebUI's database
    log_info "Syncing agents to Open WebUI..."
    local init_script="${WORK_DIR}/scripts/init-openwebui-agents.py"
    if [[ -f "$init_script" ]]; then
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" cp "$init_script" open-webui:/tmp/init-agents.py 2>/dev/null || \
        podman cp "$init_script" docker_open-webui_1:/tmp/init-agents.py 2>/dev/null || true
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T open-webui python3 /tmp/init-agents.py 2>&1 || \
        podman exec docker_open-webui_1 python3 /tmp/init-agents.py 2>&1 || true
    fi
  else
    log_warn "No agents were registered — register manually via /admin/agents"
  fi
}

# =============================================================================
# STEP 12 (compose/vm): Health check
# =============================================================================
run_health_check() {
  set_step "12" "Health check"
  log_step "12/${TOTAL_STEPS}" "Running health checks..."

  local health_script="${WORK_DIR}/scripts/health-check.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $health_script"
    return 0
  fi

  if [[ ! -f "$health_script" ]]; then
    log_error "Health check script not found: $health_script"
    exit 1
  fi

  bash "$health_script"
  log_success "Health checks passed"
}

# =============================================================================
# STEP 8b: Generate all service secrets
# =============================================================================
# Stored as module-level vars so the completion summary can print them once.
GEN_ADMIN1_PASSWORD=""
GEN_ADMIN2_PASSWORD=""
GEN_ADMIN1_TOTP_SECRET=""
GEN_ADMIN2_TOTP_SECRET=""
GEN_ADMIN1_TOTP_URI=""
GEN_ADMIN2_TOTP_URI=""
GEN_POSTGRES_PASSWORD=""
GEN_REDIS_PASSWORD=""
GEN_GRAFANA_PASSWORD=""

_gen_password() {
  # 36-char password with mixed case, digits, and symbols.
  # Symbol set: ! * , - . _ ~
  #   - all RFC 3986 unreserved or sub-delim → safe in Postgres DSN userinfo
  #     without percent-encoding (passwords are interpolated raw into
  #     postgresql://user:PW@host/db by Docker Compose / Helm / bootstrap).
  #   - no $ ` \ " to avoid shell / .env variable expansion.
  #   - no = or # to avoid .env assignment / comment parsing.
  #   - no | & \ to avoid breaking sed "s|key=...|key=PW|" updates to .env.
  # Guarantees ≥1 uppercase, lowercase, digit, and symbol (36 chars × ~10%
  # symbol weight otherwise misses symbols in a non-trivial fraction of runs).
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets, string
symbols = "!*,-._~"
alphabet = string.ascii_letters + string.digits + symbols
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(36))
    if (any(c.isupper() for c in pw)
        and any(c.islower() for c in pw)
        and any(c.isdigit() for c in pw)
        and any(c in symbols for c in pw)):
        print(pw)
        break
PY
  elif command -v openssl >/dev/null 2>&1; then
    # openssl base64 only emits [A-Za-z0-9+/=] → insufficient symbol coverage.
    # Blend with /dev/urandom through tr -dc over the full target alphabet.
    # Retry up to 8× to satisfy category requirements.
    local _pw _i
    for _i in 1 2 3 4 5 6 7 8; do
      _pw="$(LC_ALL=C tr -dc 'A-Za-z0-9!*,._~-' < /dev/urandom 2>/dev/null | head -c 36)"
      if [[ "$_pw" =~ [A-Z] ]] && [[ "$_pw" =~ [a-z] ]] && [[ "$_pw" =~ [0-9] ]] && [[ "$_pw" =~ [\!\*,._~-] ]]; then
        printf "%s" "$_pw"
        return 0
      fi
    done
    printf "%s" "$_pw"
  else
    # Last resort — /dev/urandom only; category guarantee via retry loop.
    local _pw _i
    for _i in 1 2 3 4 5 6 7 8; do
      _pw="$(LC_ALL=C tr -dc 'A-Za-z0-9!*,._~-' < /dev/urandom | head -c 36)"
      if [[ "$_pw" =~ [A-Z] ]] && [[ "$_pw" =~ [a-z] ]] && [[ "$_pw" =~ [0-9] ]] && [[ "$_pw" =~ [\!\*,._~-] ]]; then
        printf "%s" "$_pw"
        return 0
      fi
    done
    printf "%s" "$_pw"
  fi
}

_urlencode_userinfo() {
  # Percent-encode a Postgres URI userinfo (user or password) so it round-trips
  # through psycopg2 / SQLAlchemy / libpq URI parsers regardless of which
  # sub-delims they choke on. psycopg2 truncates at ',' in URI-style DSNs
  # even though RFC 3986 permits it in userinfo — so we encode everything
  # except the RFC 3986 "unreserved" set (A-Z a-z 0-9 - . _ ~).
  local _s="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_s" <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""), end="")
PY
  else
    local _i _c _out=""
    for (( _i=0; _i<${#_s}; _i++ )); do
      _c="${_s:_i:1}"
      case "$_c" in
        [A-Za-z0-9._~-]) _out+="$_c" ;;
        *) _out+=$(printf '%%%02X' "'$_c") ;;
      esac
    done
    printf "%s" "$_out"
  fi
}

_gen_totp_secret() {
  # 20-byte (160-bit) TOTP secret, base32-encoded (RFC 4226 / RFC 6238)
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets,base64; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))'
  elif command -v openssl >/dev/null 2>&1; then
    openssl rand 20 | python3 -c 'import sys,base64; print(base64.b32encode(sys.stdin.buffer.read()).decode().rstrip("="))' 2>/dev/null || \
      openssl rand 20 | base64 | tr -dc 'A-Z2-7' | head -c 32
  else
    LC_ALL=C tr -dc 'A-Z2-7' < /dev/urandom | head -c 32
  fi
}

_gen_totp_uri() {
  # otpauth://totp/Yashigani:username?secret=SECRET&issuer=Yashigani&algorithm=SHA256&digits=6&period=30
  # algorithm=SHA256 is mandatory — pyotp uses digest=hashlib.sha256.
  # Without this parameter, authenticator apps default to SHA-1 → codes never match.
  # P0-10 / SHA-256 minimum policy (maintainer directive 2026-05-01).
  local username="$1"
  local secret="$2"
  local issuer="${DOMAIN:-Yashigani}"
  echo "otpauth://totp/Yashigani:${username}?secret=${secret}&issuer=${issuer}&algorithm=SHA256&digits=6&period=30"
}

# Generate two distinct admin usernames from curated word lists
GEN_ADMIN1_USERNAME=""
GEN_ADMIN2_USERNAME=""

_gen_admin_usernames() {
  # Three themed lists — installer picks one theme at random, then two distinct names
  local -a animals=(falcon eagle phoenix raven wolf panther orca hawk lynx cobra
                    tiger condor viper mantis jaguar osprey heron crane puma ibis)
  local -a flowers=(orchid lotus cedar maple jasmine iris dahlia sage willow ivy
                    azalea holly fern clover hazel violet laurel rowan aspen reed)
  local -a robots=(atlas optimus cortex nexus cipher vector prism zenith echo forge
                   titan onyx flux nova spark pulse helix quark axiom delta)

  # Pick a random theme
  local theme_roll
  if command -v python3 >/dev/null 2>&1; then
    theme_roll="$(python3 -c 'import secrets; print(secrets.randbelow(3))')"
  else
    theme_roll=$(( RANDOM % 3 ))
  fi

  local -a chosen_list
  case "$theme_roll" in
    0) chosen_list=("${animals[@]}") ;;
    1) chosen_list=("${flowers[@]}") ;;
    2) chosen_list=("${robots[@]}") ;;
  esac

  local list_len=${#chosen_list[@]}

  # Pick two distinct indices
  local idx1 idx2
  if command -v python3 >/dev/null 2>&1; then
    idx1="$(python3 -c "import secrets; print(secrets.randbelow(${list_len}))")"
    idx2="$(python3 -c "import secrets; r=${idx1}; exec('while r==${idx1}: r=secrets.randbelow(${list_len})'); print(r)")"
  else
    idx1=$(( RANDOM % list_len ))
    idx2=$(( (idx1 + 1 + RANDOM % (list_len - 1)) % list_len ))
  fi

  GEN_ADMIN1_USERNAME="${chosen_list[$idx1]}"
  GEN_ADMIN2_USERNAME="${chosen_list[$idx2]}"
}

# ---------------------------------------------------------------------------
# _do_chgrp — top-level helper: chgrp a single file to group <gid> using the
# correct runtime dispatch strategy (direct / unshare / podman_run / docker_run).
#
# Hoisted from the nested definition inside _pki_chown_client_keys() so that
# generate_secrets() can call it at step 6/13 BEFORE _pki_chown_client_keys
# is first executed by the PKI bootstrap (which runs after step 6).
# Behaviour is identical to the nested version — only scope changes.
#
# Caller: _pki_chown_client_keys() — retained for future per-consumer-but-shared-
# via-group cases. The pgbouncer_userlist caller was removed (Tiago directive
# 2026-05-21). The shared-secrets GID 2002 loop was replaced in v2.24.0 by
# explicit per-consumer _do_chown calls (YSG-SECRETS-DIST-002 CLOSED, Laura A1).
# No active call site in generate_secrets() as of v2.24.0.
#
# Deps: YSG_RUNTIME / YSG_PODMAN_RUNTIME for mode selection; WORK_DIR for
# _secrets_dir used in container bind-mount paths. All computed locally.
# Alpine image digest pinned identically to _pki_chown_client_keys.
#
# IRIS-DESIGN-002 §8 / LAURA-TM-GID-001 GID-003 / GID-006.
# Introduced: hoist from 8dd4c41 nested scope (Ava blocker install.sh:5786
# "_do_chgrp: command not found" / phase1-verdict.md Step 2 FAIL).
# Pattern reference: Iris BACKLOG-V240-002 (_do_chown top-level refactor).
# ---------------------------------------------------------------------------
_do_chgrp() {
  local _gid="$1" _file="$2" _label="$3"

  # Determine dispatch mode — same logic as _pki_chown_client_keys().
  local _effective_runtime="${YSG_RUNTIME:-}"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  local _chown_mode
  if [[ "$_effective_runtime" == "docker" ]]; then
    _chown_mode="docker_run"
  elif [[ "$_effective_runtime" == "podman" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      _chown_mode="direct"
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      _chown_mode="unshare"
    else
      _chown_mode="podman_run"
    fi
  else
    # Unknown / k8s runtime — fall back to direct; caller logs context.
    _chown_mode="direct"
  fi

  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  case "$_chown_mode" in
    direct)
      if ! chgrp "${_gid}" "$_file"; then
        log_error "chgrp ${_gid} failed on ${_label} — aborting"
        return 1
      fi
      ;;
    unshare)
      # GID-006: MUST use podman unshare — NOT host-side chgrp.
      local _unshare_grp_ok=0
      if podman unshare chgrp "${_gid}" "$_file" 2>/dev/null; then
        _unshare_grp_ok=1
      fi
      if [[ "$_unshare_grp_ok" == "0" ]]; then
        log_warn "podman unshare chgrp ${_gid} failed on ${_label} — falling back to podman_run"
        local _rel_file="${_file#"${_secrets_dir}/"}"
        # Defensive: when _file == _secrets_dir, strip is a no-op; target is /s (mount root).
        [[ "$_rel_file" == "$_file" ]] && _rel_file=""
        local _chgrp_target="/s${_rel_file:+/${_rel_file}}"
        if ! podman run --rm \
               --volume "${_secrets_dir}:/s:rw" \
               "$_alpine_image" \
               sh -c "chgrp ${_gid} ${_chgrp_target}" 2>/dev/null; then
          log_error "podman_run fallback chgrp ${_gid} also failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    docker_run)
      local _rel_file="${_file#"${_secrets_dir}/"}"
      # Defensive: when _file == _secrets_dir, strip is a no-op; target is /s (mount root).
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chgrp_target="/s${_rel_file:+/${_rel_file}}"
      if ! docker run --rm --pull=never \
             --volume "${_secrets_dir}:/s:rw" \
             "alpine:3" \
             sh -c "chgrp ${_gid} ${_chgrp_target}" 2>/dev/null; then
        if ! docker run --rm \
               --volume "${_secrets_dir}:/s:rw" \
               "$_alpine_image" \
               sh -c "chgrp ${_gid} ${_chgrp_target}"; then
          log_error "docker_run chgrp ${_gid} failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    podman_run)
      local _rel_file="${_file#"${_secrets_dir}/"}"
      # Defensive: when _file == _secrets_dir, strip is a no-op; target is /s (mount root).
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chgrp_target="/s${_rel_file:+/${_rel_file}}"
      if ! podman run --rm \
             --network=none \
             --volume "${_secrets_dir}:/s:rw,U" \
             "$_alpine_image" \
             sh -c "chgrp ${_gid} ${_chgrp_target}" 2>/dev/null; then
        log_warn "podman run chgrp ${_gid} failed on ${_label} (macOS TCC Privacy may block virtiofs access)"
        log_warn "  To fix permanently: grant Podman Full Disk Access in System Settings > Privacy"
      fi
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# _do_chown — top-level helper: chown a single file to <uid>:<uid> using the
# correct runtime dispatch strategy (direct / unshare / podman_run / docker_run).
#
# Hoisted from the nested definition inside _pki_chown_client_keys() so that
# check_installer_preflight() can call it for docker/data, docker/certs, and
# docker/logs BEFORE _pki_chown_client_keys first executes (V240-002).
# Behaviour is identical to the nested version — only scope changes.
#
# Signature: _do_chown <uid> <file> <label> [chmod_mode] [mount_base]
#   $1  _uid        — numeric UID[:GID] to chown to (integer guard applied)
#   $2  _file       — absolute path to the file/dir
#   $3  _label      — human-readable label for log messages
#   $4  _extra_chmod — optional octal mode (e.g. "0640") applied after chown
#   $5  _mount_base  — optional mount root for container bind (default: $_secrets_dir)
#                      Use when targeting a dir that is NOT under docker/secrets
#                      (e.g. docker/data, docker/certs, docker/logs).
#                      Uses := assignment-default (S4): empty-string arg is treated
#                      as missing and falls back to $_secrets_dir correctly under
#                      set -u. The /s mount point convention applies in all branches.
#
# All callers passing only 3 or 4 args are backward-compatible — the 5th arg
# defaults to $_secrets_dir identically to the nested version.
#
# Deps: YSG_RUNTIME / YSG_PODMAN_RUNTIME for mode selection; WORK_DIR for
# _secrets_dir used in container bind-mount paths. All computed locally (S1).
# Alpine image digest pinned identically to _pki_chown_client_keys.
#
# V240-002: Iris AMENDED design (iris-v240-002-do-chown-refactor.md)
# Laura threat-model: laura-v240-002-do-chown-threat-model.md (S1-S7 applied)
# Pattern reference: git 79c2f5d (_do_chgrp hoist — established pattern)
# ---------------------------------------------------------------------------
_do_chown() {
  local _uid="$1" _file="$2" _label="$3" _extra_chmod="${4:-}"

  # S6: integer guard — reject any non-numeric uid before shell interpolation.
  # Defends against accidental non-integer args from future callers; all current
  # callers supply integer literals or values from pki_service_uid() (hardcoded
  # integers). Fail-closed under set -euo pipefail.
  if ! [[ "$_uid" =~ ^[0-9]+(:[0-9]+)?$ ]]; then
    log_error "_do_chown: uid '${_uid}' is not a valid integer (or uid:gid pair) — refusing"
    return 1
  fi

  # S1: Determine dispatch mode locally — same logic as _do_chgrp and
  # _pki_chown_client_keys(); does NOT rely on parent-scope closure variables.
  local _effective_runtime="${YSG_RUNTIME:-}"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  local _chown_mode
  if [[ "$_effective_runtime" == "docker" ]]; then
    _chown_mode="docker_run"
  elif [[ "$_effective_runtime" == "podman" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      _chown_mode="direct"
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      _chown_mode="unshare"
    else
      _chown_mode="podman_run"
    fi
  else
    _chown_mode="direct"
  fi

  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # S4: two-step default for _mount_base — bash prohibits := assignment on
  # positional parameters. Use ${5:-} to capture the arg (empty-string-safe
  # under set -u), then apply a conditional fallback to $_secrets_dir if the
  # result is empty. This covers both the unset case (caller passes fewer than
  # 5 args) and the empty-string case (caller passes "" as arg 5).
  local _mount_base="${5:-}"
  [[ -n "$_mount_base" ]] || _mount_base="$_secrets_dir"

  # Handle both "uid" (integer) and "uid:gid" (pair) input formats.
  # When _uid is already a pair, use it verbatim; otherwise synthesise uid:uid.
  local _chown_spec
  if [[ "${_uid}" == *:* ]]; then
    _chown_spec="${_uid}"
  else
    _chown_spec="${_uid}:${_uid}"
  fi

  case "$_chown_mode" in
    direct)
      if ! chown "${_chown_spec}" "$_file"; then
        log_error "chown ${_chown_spec} failed on ${_label} — aborting (fix file ownership manually)"
        return 1
      fi
      if [[ -n "$_extra_chmod" ]]; then
        if ! chmod "$_extra_chmod" "$_file"; then
          log_error "chmod ${_extra_chmod} failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    unshare)
      # gate #ROOTLESS-7 fallback: if podman unshare chown fails, attempt
      # podman_run ephemeral container before aborting.
      local _unshare_ok=0
      if podman unshare chown "${_chown_spec}" "$_file" 2>/dev/null; then
        _unshare_ok=1
        if [[ -n "$_extra_chmod" ]]; then
          if ! podman unshare chmod "$_extra_chmod" "$_file" 2>/dev/null; then
            log_warn "podman unshare chmod ${_extra_chmod} failed on ${_label} — falling back to podman_run"
            _unshare_ok=0
          fi
        fi
      fi
      if [[ "$_unshare_ok" == "0" ]]; then
        log_warn "podman unshare chown/chmod failed on ${_label} — falling back to podman_run"
        # S5: bind _mount_base (not hard-coded _secrets_dir) so callers outside
        # docker/secrets (e.g. check_installer_preflight with $_bm_dir) mount
        # the correct root. Mount point is /s (S7 convention).
        local _rel_file="${_file#"${_mount_base}/"}"
        # Defensive (VEB-Strip): when _file == _mount_base (e.g. install.sh:1396
        # bind-mount-dir chown), strip is a no-op; target is /s (mount root).
        [[ "$_rel_file" == "$_file" ]] && _rel_file=""
        local _chown_target="/s${_rel_file:+/${_rel_file}}"
        local _container_cmd="chown ${_chown_spec} ${_chown_target}"
        if [[ -n "$_extra_chmod" ]]; then
          _container_cmd="${_container_cmd} && chmod ${_extra_chmod} ${_chown_target}"
        fi
        if ! podman run --rm \
               --volume "${_mount_base}:/s:rw" \
               "$_alpine_image" \
               sh -c "$_container_cmd" 2>/dev/null; then
          log_error "podman_run fallback chown/chmod also failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    docker_run)
      # S5: bind _mount_base to /s (S7 convention — matches internal logic).
      local _rel_file="${_file#"${_mount_base}/"}"
      # Defensive (VEB-Strip): when _file == _mount_base (e.g. install.sh:1396
      # bind-mount-dir chown), strip is a no-op; target is /s (mount root).
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chown_target="/s${_rel_file:+/${_rel_file}}"
      local _container_cmd="chown ${_chown_spec} ${_chown_target}"
      if [[ -n "$_extra_chmod" ]]; then
        _container_cmd="${_container_cmd} && chmod ${_extra_chmod} ${_chown_target}"
      fi
      if ! docker run --rm --pull=never \
             --volume "${_mount_base}:/s:rw" \
             "alpine:3" \
             sh -c "$_container_cmd" 2>/dev/null; then
        if ! docker run --rm \
               --volume "${_mount_base}:/s:rw" \
               "$_alpine_image" \
               sh -c "$_container_cmd"; then
          log_error "docker run chown/chmod failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    podman_run)
      # S5: bind _mount_base to /s (S7 convention).
      local _rel_file="${_file#"${_mount_base}/"}"
      # Defensive (VEB-Strip): when _file == _mount_base (e.g. install.sh:1396
      # bind-mount-dir chown), strip is a no-op; target is /s (mount root).
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chown_target="/s${_rel_file:+/${_rel_file}}"
      local _container_cmd="chown ${_chown_spec} ${_chown_target}"
      if [[ -n "$_extra_chmod" ]]; then
        _container_cmd="${_container_cmd} && chmod ${_extra_chmod} ${_chown_target}"
      fi
      if ! podman run --rm \
             --network=none \
             --volume "${_mount_base}:/s:rw,U" \
             "$_alpine_image" \
             sh -c "$_container_cmd" 2>/dev/null; then
        log_warn "podman run chown/chmod failed on ${_label} (macOS TCC Privacy may block virtiofs access)"
        log_warn "  virtiofs UID remapping should compensate — verifying at service start"
        log_warn "  To fix permanently: grant Podman Full Disk Access in System Settings > Privacy"
      fi
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# _do_chmod_dir — top-level helper: chmod a directory using the correct runtime
# dispatch strategy (direct / unshare / podman_run / docker_run).
#
# Hoisted from the nested definition inside _pki_chown_client_keys() (V240-002).
# Behaviour is identical to the nested version — only scope changes.
#
# Signature: _do_chmod_dir <dir> <mode>
# CHM-001 (S3): only mode 755 is permitted. Any other value is rejected
# fail-closed. Prevents accidental 0777 / 4755 (setuid). The allowlist guard
# is the FIRST statement in the body, before dispatch.
#
# S1: dispatch state (_chown_mode, _alpine_image, _secrets_dir) computed locally.
# S2: mode hard-coded in each branch (no caller-supplied mode used in commands —
#     the allowlist guard already enforces 755; the case branches pass $_mode but
#     that value has already been validated against the allowlist).
#
# V240-002: Iris AMENDED design / Laura S1, S3.
# ---------------------------------------------------------------------------
_do_chmod_dir() {
  local _dir="$1" _mode="$2"

  # S3: CHM-001 allowlist guard — carried verbatim from nested definition.
  # Must be first statement before dispatch block.
  case "$_mode" in
    755) ;;
    *)
      log_error "_do_chmod_dir: refusing unsupported mode '${_mode}' — only 755 allowed by design (LAURA-TM-CHMOD-001 CHM-001)"
      return 1
      ;;
  esac

  # S1: compute dispatch state locally.
  local _effective_runtime="${YSG_RUNTIME:-}"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  local _chown_mode
  if [[ "$_effective_runtime" == "docker" ]]; then
    _chown_mode="docker_run"
  elif [[ "$_effective_runtime" == "podman" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      _chown_mode="direct"
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      _chown_mode="unshare"
    else
      _chown_mode="podman_run"
    fi
  else
    _chown_mode="direct"
  fi

  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

  case "$_chown_mode" in
    direct)
      if ! chmod "$_mode" "$_dir"; then
        log_warn "_do_chmod_dir: direct chmod ${_mode} failed on ${_dir}"
      fi
      ;;
    unshare)
      # Try podman unshare first; fall back to podman_run on failure (gate #ROOTLESS-7 pattern).
      if ! podman unshare chmod "$_mode" "$_dir" 2>/dev/null; then
        log_warn "_do_chmod_dir: podman unshare chmod ${_mode} failed — trying podman_run fallback"
        if ! podman run --rm \
               --volume "${_dir}:/d:rw" \
               "$_alpine_image" \
               chmod "$_mode" /d 2>/dev/null; then
          log_warn "_do_chmod_dir: podman_run fallback chmod ${_mode} also failed on ${_dir}"
        fi
      fi
      ;;
    docker_run)
      # Prefer cached alpine:3 tag (--pull=never); fall back to digest-pinned image.
      # CHM-002/CHM-003 (ACCEPTED): container root has CAP_FOWNER; blast radius is
      # the single dir bound at this call site. Ephemeral --rm, no network.
      if ! docker run --rm --pull=never \
             --volume "${_dir}:/d:rw" \
             "alpine:3" \
             chmod "$_mode" /d 2>/dev/null; then
        if ! docker run --rm \
               --volume "${_dir}:/d:rw" \
               "$_alpine_image" \
               chmod "$_mode" /d 2>/dev/null; then
          log_warn "_do_chmod_dir: docker_run chmod ${_mode} failed on ${_dir}"
        fi
      fi
      ;;
    podman_run)
      # Podman remote-client (macOS): podman unshare not supported; use container.
      # WARN-not-ABORT: same rationale as _do_chown podman_run path (macOS TCC / virtiofs).
      if ! podman run --rm \
             --network=none \
             --volume "${_dir}:/d:rw" \
             "$_alpine_image" \
             chmod "$_mode" /d 2>/dev/null; then
        log_warn "_do_chmod_dir: podman_run chmod ${_mode} failed on ${_dir} (macOS TCC Privacy may block virtiofs)"
        log_warn "  To fix permanently: grant Podman Full Disk Access in System Settings > Privacy"
      fi
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# _do_chmod_0640 — top-level helper: chmod 0640 a single file using the correct
# runtime dispatch strategy (direct / unshare / podman_run / docker_run).
#
# Hoisted from the nested definition inside _pki_chown_client_keys() (V240-002).
# Behaviour is identical to the nested version — only scope changes.
#
# Signature: _do_chmod_0640 <file> <label>
# S2: mode 0640 is hard-coded in every branch — no parameterisation.
# The mode is not in the function name by accident; it is the security invariant
# (LAURA-TM-CHMOD-001). Any new mode requires a new function + CHM approval.
#
# S1: dispatch state computed locally.
#
# V240-002: Iris AMENDED design / Laura S1, S2.
# ---------------------------------------------------------------------------
_do_chmod_0640() {
  local _file="$1" _label="$2"

  # S1: compute dispatch state locally.
  local _effective_runtime="${YSG_RUNTIME:-}"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  local _chown_mode
  if [[ "$_effective_runtime" == "docker" ]]; then
    _chown_mode="docker_run"
  elif [[ "$_effective_runtime" == "podman" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      _chown_mode="direct"
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      _chown_mode="unshare"
    else
      _chown_mode="podman_run"
    fi
  else
    _chown_mode="direct"
  fi

  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  case "$_chown_mode" in
    direct)
      # S2: literal 0640 — no parameter.
      if ! chmod 0640 "$_file"; then
        log_error "chmod 0640 failed on ${_label} — aborting"
        return 1
      fi
      ;;
    unshare)
      if ! podman unshare chmod 0640 "$_file" 2>/dev/null; then
        log_warn "podman unshare chmod 0640 failed on ${_label} — falling back to podman_run"
        local _rel_file="${_file#"${_secrets_dir}/"}"
        # Defensive (VEB-Strip): when _file == _secrets_dir, strip is a no-op; target is /s.
        [[ "$_rel_file" == "$_file" ]] && _rel_file=""
        local _chmod_target="/s${_rel_file:+/${_rel_file}}"
        if ! podman run --rm \
               --volume "${_secrets_dir}:/s:rw" \
               "$_alpine_image" \
               sh -c "chmod 0640 ${_chmod_target}" 2>/dev/null; then
          log_error "podman_run fallback chmod 0640 also failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    docker_run)
      local _rel_file="${_file#"${_secrets_dir}/"}"
      # Defensive (VEB-Strip): when _file == _secrets_dir, strip is a no-op; target is /s.
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chmod_target="/s${_rel_file:+/${_rel_file}}"
      if ! docker run --rm --pull=never \
             --volume "${_secrets_dir}:/s:rw" \
             "alpine:3" \
             sh -c "chmod 0640 ${_chmod_target}" 2>/dev/null; then
        if ! docker run --rm \
               --volume "${_secrets_dir}:/s:rw" \
               "$_alpine_image" \
               sh -c "chmod 0640 ${_chmod_target}"; then
          log_error "docker_run chmod 0640 failed on ${_label} — aborting"
          return 1
        fi
      fi
      ;;
    podman_run)
      local _rel_file="${_file#"${_secrets_dir}/"}"
      # Defensive (VEB-Strip): when _file == _secrets_dir, strip is a no-op; target is /s.
      [[ "$_rel_file" == "$_file" ]] && _rel_file=""
      local _chmod_target="/s${_rel_file:+/${_rel_file}}"
      if ! podman run --rm \
             --network=none \
             --volume "${_secrets_dir}:/s:rw,U" \
             "$_alpine_image" \
             sh -c "chmod 0640 ${_chmod_target}" 2>/dev/null; then
        log_warn "podman run chmod 0640 failed on ${_label} (macOS TCC Privacy may block virtiofs access)"
      fi
      ;;
  esac
  return 0
}

# _safe_read_secret — BUG-B+-004: Podman-rootless-aware secret file reader
#
# On Podman rootless, secrets are owned by subuid-remapped UIDs that the host
# installer user (UID 1000) cannot read directly. This helper tries:
#   1. Direct read (works on Docker / Podman rootful / first-install)
#   2. `podman unshare cat` (works on Podman rootless re-run)
#   3. Read from .env (last-resort — value is already there from first install)
#
# Usage: _safe_read_secret <file> <ENV_KEY> <env_file>
# Writes the value to stdout; returns 0 on success, 1 if all attempts fail.
_safe_read_secret() {
  local _sr_file="$1"
  local _sr_env_key="${2:-}"
  local _sr_env_file="${3:-}"
  local _sr_val

  # Attempt 1: direct cat (most common case)
  if _sr_val="$(cat "$_sr_file" 2>/dev/null)" && [[ -n "$_sr_val" ]]; then
    printf '%s' "$_sr_val"
    return 0
  fi

  # Attempt 2: Podman rootless — read inside the user namespace
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && command -v podman >/dev/null 2>&1; then
    if _sr_val="$(podman unshare cat "$_sr_file" 2>/dev/null)" && [[ -n "$_sr_val" ]]; then
      printf '%s' "$_sr_val"
      return 0
    fi
  fi

  # Attempt 3: read from .env (value already present from first install)
  if [[ -n "$_sr_env_key" && -n "$_sr_env_file" && -f "$_sr_env_file" ]]; then
    if _sr_val="$(grep "^${_sr_env_key}=" "$_sr_env_file" 2>/dev/null | cut -d= -f2-)"; then
      if [[ -n "$_sr_val" ]]; then
        printf '%s' "$_sr_val"
        return 0
      fi
    fi
  fi

  return 1
}

# ---------------------------------------------------------------------------
# _safe_write_secret — BUG-B+-NEW-001: Podman-rootless-aware secret file writer
#
# On the additive re-run path (Journey B+), docker/secrets/ is already owned
# by a subuid-remapped UID (e.g. UID 101000 on the host). A plain `echo >` from
# the host installer user (UID 1000) fails with EACCES. This helper tries:
#   1. Direct write (works on Docker / Podman rootful / first-install)
#   2. `podman unshare tee` (works on Podman rootless re-run — runs inside the
#      user namespace where the host installer UID maps to the file owner)
#   3. Ephemeral container write via podman/docker run (last-resort fallback)
#
# After each successful write, chmod is applied via the same namespace/container
# so the effective mode is preserved inside the rootless user namespace.
#
# Usage: _safe_write_secret <content> <file> <mode>
#   $1  _sw_content  — the secret value to write (no trailing newline)
#   $2  _sw_file     — absolute path to the target file
#   $3  _sw_mode     — octal mode string e.g. "0640"
# Returns 0 on success, 1 if all attempts fail.
#
# Security properties:
#   - Content never passed via command-line argument (process-table visible).
#   - `tee` reads from stdin, avoiding any argv exposure of the secret.
#   - Mode applied atomically in the same namespace/container after write.
#   - Fail-closed: returns 1 if the content could not be written and verified.
#
# BUG-B+-NEW-001 / v2.24.1 Phase A wave 1 (Su).
# ---------------------------------------------------------------------------
_safe_write_secret() {
  local _sw_content="$1" _sw_file="$2" _sw_mode="${3:-0640}"

  local _secrets_dir="${WORK_DIR}/docker/secrets"
  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

  # --- Attempt 1: direct write (Docker / Podman rootful / first-install) ----
  if printf '%s' "$_sw_content" > "$_sw_file" 2>/dev/null; then
    chmod "$_sw_mode" "$_sw_file" 2>/dev/null || true
    return 0
  fi

  # --- Attempt 2: Podman rootless — write inside the user namespace ---------
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && command -v podman >/dev/null 2>&1; then
    # `podman unshare tee` maps host UID to the container owner UID, giving
    # us write access to subuid-remapped files. Stdin avoids argv exposure.
    if printf '%s' "$_sw_content" | podman unshare tee "$_sw_file" >/dev/null 2>&1; then
      podman unshare chmod "$_sw_mode" "$_sw_file" 2>/dev/null || true
      return 0
    fi
  fi

  # --- Attempt 3: ephemeral container write ---------------------------------
  # Bind the secrets dir and write from inside a container that runs as root,
  # giving it ownership of the remapped UIDs.  Uses /s mount convention (S7).
  local _rel_file="${_sw_file#"${_secrets_dir}/"}"
  [[ "$_rel_file" == "$_sw_file" ]] && _rel_file=""
  local _target="/s${_rel_file:+/${_rel_file}}"

  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && command -v podman >/dev/null 2>&1; then
    if printf '%s' "$_sw_content" | podman run --rm --network=none \
         --volume "${_secrets_dir}:/s:rw,U" \
         "$_alpine_image" \
         sh -c "tee ${_target} >/dev/null && chmod ${_sw_mode} ${_target}" 2>/dev/null; then
      return 0
    fi
  elif command -v docker >/dev/null 2>&1; then
    if printf '%s' "$_sw_content" | docker run --rm --pull=never \
         --volume "${_secrets_dir}:/s:rw" \
         "alpine:3" \
         sh -c "tee ${_target} >/dev/null && chmod ${_sw_mode} ${_target}" 2>/dev/null; then
      return 0
    fi
    # docker pull fallback
    if printf '%s' "$_sw_content" | docker run --rm \
         --volume "${_secrets_dir}:/s:rw" \
         "$_alpine_image" \
         sh -c "tee ${_target} >/dev/null && chmod ${_sw_mode} ${_target}" 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

generate_secrets() {
  local secrets_dir="${WORK_DIR}/docker/secrets"

  # Skip if secrets already exist (upgrade path)
  if [[ -f "${secrets_dir}/postgres_password" && -f "${secrets_dir}/redis_password" ]]; then
    log_info "Secrets already exist — preserving (upgrade path)"
    GEN_POSTGRES_PASSWORD="$(cat "${secrets_dir}/postgres_password" 2>/dev/null || echo "[preserved]")"
    GEN_REDIS_PASSWORD="$(cat "${secrets_dir}/redis_password" 2>/dev/null || echo "[preserved]")"
    GEN_GRAFANA_PASSWORD="$(cat "${secrets_dir}/grafana_admin_password" 2>/dev/null || echo "[preserved]")"
    GEN_ADMIN1_USERNAME="$(cat "${secrets_dir}/admin1_username" 2>/dev/null || echo "[preserved]")"
    GEN_ADMIN2_USERNAME="$(cat "${secrets_dir}/admin2_username" 2>/dev/null || echo "[preserved]")"
    GEN_ADMIN1_PASSWORD="[preserved — check secrets dir]"
    GEN_ADMIN2_PASSWORD="[preserved — check secrets dir]"
    GEN_ADMIN1_TOTP_SECRET="[preserved]"
    GEN_ADMIN2_TOTP_SECRET="[preserved]"
    GEN_ADMIN1_TOTP_URI=""
    GEN_ADMIN2_TOTP_URI=""
    # Ensure passwords are in .env for Docker Compose interpolation
    local env_file="${WORK_DIR}/docker/.env"
    for _pw_key_val in "POSTGRES_PASSWORD:${GEN_POSTGRES_PASSWORD}" "REDIS_PASSWORD:${GEN_REDIS_PASSWORD}"; do
      local _pw_key="${_pw_key_val%%:*}"
      local _pw_val="${_pw_key_val#*:}"
      if [[ "$_pw_val" != "[preserved]" && -n "$_pw_val" ]]; then
        if grep -q "^${_pw_key}=" "$env_file" 2>/dev/null; then
          local tmp_env; tmp_env="$(mktemp)"
          sed "s|^${_pw_key}=.*|${_pw_key}=${_pw_val}|" "$env_file" > "$tmp_env"
          mv "$tmp_env" "$env_file"
        else
          echo "${_pw_key}=${_pw_val}" >> "$env_file"
        fi
      fi
    done
    # v2.23.1 fix: URL-encoded Postgres password for URI-style DSNs (psycopg2
    # mis-parses unreserved sub-delims like ',' in userinfo). Compose templates
    # must reference POSTGRES_PASSWORD_URLENC for postgresql:// DSNs; raw
    # POSTGRES_PASSWORD remains for non-URI env (pgbouncer auth, libpq kwargs).
    if [[ "$GEN_POSTGRES_PASSWORD" != "[preserved]" && -n "$GEN_POSTGRES_PASSWORD" ]]; then
      local _pgurlenc
      _pgurlenc="$(_urlencode_userinfo "$GEN_POSTGRES_PASSWORD")"
      if grep -q "^POSTGRES_PASSWORD_URLENC=" "$env_file" 2>/dev/null; then
        local tmp_env; tmp_env="$(mktemp)"
        sed "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${_pgurlenc}|" "$env_file" > "$tmp_env"
        mv "$tmp_env" "$env_file"
      else
        echo "POSTGRES_PASSWORD_URLENC=${_pgurlenc}" >> "$env_file"
      fi
    fi
    # Ensure OpenClaw gateway token exists
    if ! grep -q "^OPENCLAW_GATEWAY_TOKEN=" "$env_file" 2>/dev/null; then
      local openclaw_token
      openclaw_token="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
      echo "OPENCLAW_GATEWAY_TOKEN=${openclaw_token}" >> "$env_file"
    fi

    # Generate credentials for NEW services added since last install
    # This handles upgrades where new components (e.g., Wazuh) need passwords
    local _new_creds_generated=false
    for _cred_name in wazuh_indexer_password wazuh_api_password wazuh_dashboard_password; do
      if [[ ! -s "${secrets_dir}/${_cred_name}" ]] || grep -q "placeholder" "${secrets_dir}/${_cred_name}" 2>/dev/null; then
        local _new_pw
        _new_pw="$(_gen_password)"
        printf "%s" "$_new_pw" > "${secrets_dir}/${_cred_name}"
        chmod 600 "${secrets_dir}/${_cred_name}"
        # Map secret file name to env var name
        local _env_key
        _env_key="$(echo "$_cred_name" | tr '[:lower:]' '[:upper:]')"
        if ! grep -q "^${_env_key}=" "$env_file" 2>/dev/null; then
          echo "${_env_key}=${_new_pw}" >> "$env_file"
        fi
        log_info "  New credential generated: ${_cred_name}"
        _new_creds_generated=true
      fi
    done
    if [[ "$_new_creds_generated" == "true" ]]; then
      log_success "New service credentials generated (upgrade path)"
    fi

    # Read Wazuh credentials (may have been generated above or in a previous install)
    GEN_WAZUH_INDEXER_PASSWORD="$(cat "${secrets_dir}/wazuh_indexer_password" 2>/dev/null || echo "")"
    GEN_WAZUH_API_PASSWORD="$(cat "${secrets_dir}/wazuh_api_password" 2>/dev/null || echo "")"
    GEN_WAZUH_DASHBOARD_PASSWORD="$(cat "${secrets_dir}/wazuh_dashboard_password" 2>/dev/null || echo "")"

    # BUG-1 (v2.23.1): caddy_internal_hmac was silently skipped on the upgrade
    # path because this early-return block never reached the generation code below.
    # A partial install (e.g. K8s first, then Docker) leaves postgres_password in
    # .env but omits caddy_internal_hmac, so the gateway cannot start.
    # Fix: check + generate each new secret independently, regardless of whether
    # core secrets (postgres/redis) already exist.
    local hmac_file="${secrets_dir}/caddy_internal_hmac"
    if [[ ! -s "$hmac_file" ]] || [[ "${REINSTALL:-false}" == "true" ]]; then
      local _hmac_secret
      if command -v openssl >/dev/null 2>&1; then
        _hmac_secret="$(openssl rand -hex 32)"
      elif command -v python3 >/dev/null 2>&1; then
        _hmac_secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
      else
        log_error "Cannot generate caddy_internal_hmac: neither openssl nor python3 found"
        return 1
      fi
      printf "%s" "$_hmac_secret" > "$hmac_file"
      chmod 0640 "$hmac_file"
      log_info "Generated caddy_internal_hmac → ${hmac_file} (mode 0640, upgrade path)"
    else
      log_info "caddy_internal_hmac already present — preserving (use REINSTALL=true to rotate)"
    fi
    # Always sync CADDY_INTERNAL_HMAC into .env (may be absent if secret was just created).
    # BUG-B+-004: use _safe_read_secret — direct cat fails on Podman rootless (subuid owner).
    local _hmac_val
    if _hmac_val="$(_safe_read_secret "$hmac_file" "CADDY_INTERNAL_HMAC" "$env_file")"; then
      if grep -q "^CADDY_INTERNAL_HMAC=" "$env_file" 2>/dev/null; then
        local tmp_env; tmp_env="$(mktemp)"
        sed "s|^CADDY_INTERNAL_HMAC=.*|CADDY_INTERNAL_HMAC=${_hmac_val}|" "$env_file" > "$tmp_env"
        mv "$tmp_env" "$env_file"
      else
        echo "CADDY_INTERNAL_HMAC=${_hmac_val}" >> "$env_file"
      fi
    else
      log_warn "Cannot read caddy_internal_hmac — CADDY_INTERNAL_HMAC already in .env, preserving existing value (BUG-B+-004)"
    fi

    # Bucket-C finding (Captain gitleaks baseline 2026-05-17): per-install
    # YASHIGANI_INTERNAL_BEARER — generate if absent on upgrade path.
    local _bearer_file_up="${secrets_dir}/yashigani_internal_bearer"
    if [[ ! -s "$_bearer_file_up" ]]; then
      local _bearer_up
      _bearer_up="$(_gen_password)"
      printf "%s" "$_bearer_up" > "$_bearer_file_up"
      chmod 0600 "$_bearer_file_up"
      log_info "Generated yashigani_internal_bearer → ${_bearer_file_up} (mode 0600, upgrade path)"
    else
      log_info "yashigani_internal_bearer already present — preserving (upgrade path)"
    fi
    # Always sync into .env so Compose can interpolate YASHIGANI_INTERNAL_BEARER.
    # BUG-B+-004: use _safe_read_secret — direct cat fails on Podman rootless (subuid owner).
    local _bearer_val_up
    if _bearer_val_up="$(_safe_read_secret "$_bearer_file_up" "YASHIGANI_INTERNAL_BEARER" "$env_file")"; then
      if grep -q "^YASHIGANI_INTERNAL_BEARER=" "$env_file" 2>/dev/null; then
        local tmp_env; tmp_env="$(mktemp)"
        sed "s|^YASHIGANI_INTERNAL_BEARER=.*|YASHIGANI_INTERNAL_BEARER=${_bearer_val_up}|" "$env_file" > "$tmp_env"
        mv "$tmp_env" "$env_file"
      else
        echo "YASHIGANI_INTERNAL_BEARER=${_bearer_val_up}" >> "$env_file"
      fi
    else
      log_warn "Cannot read yashigani_internal_bearer — YASHIGANI_INTERNAL_BEARER already in .env, preserving existing value (BUG-B+-004)"
    fi

    # #2-fix: sync installer version into .env on upgrade path (same as fresh install).
    if grep -q "^YASHIGANI_VERSION=" "$env_file" 2>/dev/null; then
      local tmp_env; tmp_env="$(mktemp)"
      sed "s|^YASHIGANI_VERSION=.*|YASHIGANI_VERSION=${YASHIGANI_VERSION}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "YASHIGANI_VERSION=${YASHIGANI_VERSION}" >> "$env_file"
    fi

    # pgbouncer_userlist SCRAM verifier generation removed (Tiago directive 2026-05-21).
    # YSG-RISK-049 ACCEPTED-LOW non-KMS-only. YSG-RISK-049 is now CLOSED by the
    # auth_query design (v2.24.0). pgbouncer_authenticator_password replaces this.

    # --- pgbouncer_authenticator_password (YSG-RISK-049 close — v2.24.0) -------
    # KMS-architectural posture (per docs/yashigani_install_config.md §6.1):
    # In production with YASHIGANI_KMS_PROVIDER set, pgbouncer_authenticator_password
    # is fetched at runtime via the KMS provider and bypasses this cleartext
    # path entirely. Non-KMS dev/standalone deployments use this on-disk
    # cleartext at 0640 owned by pgbouncer UID 70 (dedicated mount, not GID 2002).
    #
    # Option C isolation (Iris + Laura 2026-05-21): dedicated Docker secret mount
    # at /run/secrets/pgbouncer_authenticator_password inside the container — NOT
    # GID-2002 bind-mount. YSG-SECRETS-DIST-002 blast radius unchanged.
    #
    # _do_chown now handles uid:gid pairs natively (V240-002 follow-up fix).
    # Correct ownership is 70:999 (pgbouncer uid:postgres gid) — pgbouncer (UID 70)
    # reads as owner; postgres (UID 999) reads as group at init time via
    # 10-pgbouncer-auth.sh. Symmetric with postgres_password 1001:999 0640.
    local _pgba_file="${secrets_dir}/pgbouncer_authenticator_password"
    if [[ ! -s "$_pgba_file" ]]; then
      local _pgba_pw
      _pgba_pw="$(_gen_password)"
      printf "%s" "$_pgba_pw" > "$_pgba_file"
      chmod 0600 "$_pgba_file"
      _do_chown "70:999" "$_pgba_file" "pgbouncer_authenticator_password" "" "${secrets_dir}" || true
      _do_chmod_0640 "$_pgba_file" "pgbouncer_authenticator_password" || true
      log_info "Generated pgbouncer_authenticator_password → ${_pgba_file} (mode 0640 uid 70:999, upgrade path)"
    else
      log_info "pgbouncer_authenticator_password already present — preserving (upgrade path)"
    fi

    return 0
  fi

  # Generate unique admin usernames from themed word lists
  _gen_admin_usernames

  log_info "Generating service passwords and 2FA secrets..."
  log_info "Admin usernames: ${GEN_ADMIN1_USERNAME} (primary), ${GEN_ADMIN2_USERNAME} (backup)"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Generate 36-char passwords for: ${GEN_ADMIN1_USERNAME}, ${GEN_ADMIN2_USERNAME}, postgres, redis, grafana"
    dry_print "Generate TOTP secrets for: ${GEN_ADMIN1_USERNAME}, ${GEN_ADMIN2_USERNAME}"
    dry_print "Write to ${secrets_dir}/"
    GEN_ADMIN1_PASSWORD="[dry-run]"
    GEN_ADMIN2_PASSWORD="[dry-run]"
    GEN_ADMIN1_TOTP_SECRET="[dry-run]"
    GEN_ADMIN2_TOTP_SECRET="[dry-run]"
    GEN_POSTGRES_PASSWORD="[dry-run]"
    GEN_REDIS_PASSWORD="[dry-run]"
    GEN_GRAFANA_PASSWORD="[dry-run]"
    return 0
  fi

  mkdir -p "$secrets_dir"

  # --- Admin 1 (primary) ---
  GEN_ADMIN1_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_ADMIN1_PASSWORD" > "${secrets_dir}/admin1_password"
  chmod 600 "${secrets_dir}/admin1_password"
  # Also write as admin_initial_password — the backoffice bootstrap checks this
  # file to decide whether to generate new credentials or use existing ones
  printf "%s" "$GEN_ADMIN1_PASSWORD" > "${secrets_dir}/admin_initial_password"
  chmod 600 "${secrets_dir}/admin_initial_password"
  printf "%s" "$GEN_ADMIN1_USERNAME" > "${secrets_dir}/admin1_username"
  chmod 600 "${secrets_dir}/admin1_username"
  # Update .env so backoffice creates the account with the generated username
  local env_file="${WORK_DIR}/docker/.env"
  if grep -q "^YASHIGANI_ADMIN_USERNAME=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^YASHIGANI_ADMIN_USERNAME=.*|YASHIGANI_ADMIN_USERNAME=${GEN_ADMIN1_USERNAME}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "YASHIGANI_ADMIN_USERNAME=${GEN_ADMIN1_USERNAME}" >> "$env_file"
  fi

  GEN_ADMIN1_TOTP_SECRET="$(_gen_totp_secret)"
  printf "%s" "$GEN_ADMIN1_TOTP_SECRET" > "${secrets_dir}/admin1_totp_secret"
  chmod 600 "${secrets_dir}/admin1_totp_secret"
  GEN_ADMIN1_TOTP_URI="$(_gen_totp_uri "$GEN_ADMIN1_USERNAME" "$GEN_ADMIN1_TOTP_SECRET")"

  # --- Admin 2 (backup — anti-lockout) ---
  GEN_ADMIN2_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_ADMIN2_PASSWORD" > "${secrets_dir}/admin2_password"
  chmod 600 "${secrets_dir}/admin2_password"
  printf "%s" "$GEN_ADMIN2_USERNAME" > "${secrets_dir}/admin2_username"
  chmod 600 "${secrets_dir}/admin2_username"

  GEN_ADMIN2_TOTP_SECRET="$(_gen_totp_secret)"
  printf "%s" "$GEN_ADMIN2_TOTP_SECRET" > "${secrets_dir}/admin2_totp_secret"
  chmod 600 "${secrets_dir}/admin2_totp_secret"
  GEN_ADMIN2_TOTP_URI="$(_gen_totp_uri "$GEN_ADMIN2_USERNAME" "$GEN_ADMIN2_TOTP_SECRET")"

  # --- PostgreSQL ---
  GEN_POSTGRES_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_POSTGRES_PASSWORD" > "${secrets_dir}/postgres_password"
  chmod 600 "${secrets_dir}/postgres_password"
  # Also write to .env so Docker Compose can interpolate ${POSTGRES_PASSWORD}
  # in service DSN and PgBouncer DATABASE_URL
  local env_file="${WORK_DIR}/docker/.env"
  if grep -q "^POSTGRES_PASSWORD=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}" >> "$env_file"
  fi
  # v2.23.1 fix: URL-encoded variant for URI-style DSNs (see _urlencode_userinfo).
  GEN_POSTGRES_PASSWORD_URLENC="$(_urlencode_userinfo "$GEN_POSTGRES_PASSWORD")"
  if grep -q "^POSTGRES_PASSWORD_URLENC=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${GEN_POSTGRES_PASSWORD_URLENC}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "POSTGRES_PASSWORD_URLENC=${GEN_POSTGRES_PASSWORD_URLENC}" >> "$env_file"
  fi

  # --- Redis ---
  GEN_REDIS_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_REDIS_PASSWORD" > "${secrets_dir}/redis_password"
  chmod 600 "${secrets_dir}/redis_password"
  # Write to .env for Compose interpolation (LangGraph REDIS_URI needs it)
  if grep -q "^REDIS_PASSWORD=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${GEN_REDIS_PASSWORD}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "REDIS_PASSWORD=${GEN_REDIS_PASSWORD}" >> "$env_file"
  fi

  # --- OpenClaw gateway token ---
  local openclaw_token
  openclaw_token="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
  printf "%s" "$openclaw_token" > "${secrets_dir}/openclaw_gateway_token"
  chmod 600 "${secrets_dir}/openclaw_gateway_token"
  if grep -q "^OPENCLAW_GATEWAY_TOKEN=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^OPENCLAW_GATEWAY_TOKEN=.*|OPENCLAW_GATEWAY_TOKEN=${openclaw_token}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "OPENCLAW_GATEWAY_TOKEN=${openclaw_token}" >> "$env_file"
  fi

  # --- Grafana ---
  GEN_GRAFANA_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_GRAFANA_PASSWORD" > "${secrets_dir}/grafana_admin_password"
  chmod 600 "${secrets_dir}/grafana_admin_password"

  # --- Wazuh SIEM (generated even if --wazuh not selected — ready for later) ---
  GEN_WAZUH_INDEXER_PASSWORD="$(_gen_password)"
  GEN_WAZUH_API_PASSWORD="$(_gen_password)"
  GEN_WAZUH_DASHBOARD_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_WAZUH_INDEXER_PASSWORD" > "${secrets_dir}/wazuh_indexer_password"
  printf "%s" "$GEN_WAZUH_API_PASSWORD" > "${secrets_dir}/wazuh_api_password"
  printf "%s" "$GEN_WAZUH_DASHBOARD_PASSWORD" > "${secrets_dir}/wazuh_dashboard_password"
  chmod 600 "${secrets_dir}/wazuh_indexer_password" "${secrets_dir}/wazuh_api_password" "${secrets_dir}/wazuh_dashboard_password"
  # Write to .env for Compose interpolation
  for _wkey in WAZUH_INDEXER_PASSWORD WAZUH_API_PASSWORD WAZUH_DASHBOARD_PASSWORD; do
    local _wval
    case "$_wkey" in
      WAZUH_INDEXER_PASSWORD)   _wval="$GEN_WAZUH_INDEXER_PASSWORD" ;;
      WAZUH_API_PASSWORD)       _wval="$GEN_WAZUH_API_PASSWORD" ;;
      WAZUH_DASHBOARD_PASSWORD) _wval="$GEN_WAZUH_DASHBOARD_PASSWORD" ;;
    esac
    if grep -q "^${_wkey}=" "$env_file" 2>/dev/null; then
      local tmp_env; tmp_env="$(mktemp)"
      sed "s|^${_wkey}=.*|${_wkey}=${_wval}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "${_wkey}=${_wval}" >> "$env_file"
    fi
  done

  # --- EX-231-10 Layer B: per-install Caddy HMAC shared secret ----------------
  # caddy_internal_hmac: 32 bytes (256-bit), hex-encoded.
  # Caddy reads it via CADDY_INTERNAL_HMAC env var and injects it as
  # X-Caddy-Verified-Secret on every upstream proxy to backoffice and gateway.
  # the gateway/backoffice middleware does hmac.compare_digest(header, secret) → 401 if absent.
  # Mode 0440: readable by uid 1001 (yashigani — Caddy/gateway/backoffice);
  # never world-readable.
  # On --upgrade this block regenerates the secret. All three containers must
  # be restarted to pick it up (install.sh --upgrade restarts them).
  local hmac_file="${secrets_dir}/caddy_internal_hmac"
  if [[ ! -s "$hmac_file" ]] || [[ "${REINSTALL:-false}" == "true" ]]; then
    local _hmac_secret
    if command -v openssl >/dev/null 2>&1; then
      _hmac_secret="$(openssl rand -hex 32)"
    elif command -v python3 >/dev/null 2>&1; then
      _hmac_secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    else
      log_error "Cannot generate caddy_internal_hmac: neither openssl nor python3 found"
      return 1
    fi
    printf "%s" "$_hmac_secret" > "$hmac_file"
    chmod 0640 "$hmac_file"
    log_info "Generated caddy_internal_hmac → ${hmac_file} (mode 0640)"
  else
    log_info "caddy_internal_hmac already present — preserving (use REINSTALL=true to rotate)"
  fi
  # Write/update CADDY_INTERNAL_HMAC in .env so Compose can interpolate it
  # into the Caddy, gateway, and backoffice environment blocks.
  # BUG-B+-004 (sweep): safe read — file may be subuid-owned on Podman rootless re-run.
  local _hmac_val
  if _hmac_val="$(_safe_read_secret "$hmac_file" "CADDY_INTERNAL_HMAC" "$env_file")"; then
    if grep -q "^CADDY_INTERNAL_HMAC=" "$env_file" 2>/dev/null; then
      local tmp_env; tmp_env="$(mktemp)"
      sed "s|^CADDY_INTERNAL_HMAC=.*|CADDY_INTERNAL_HMAC=${_hmac_val}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "CADDY_INTERNAL_HMAC=${_hmac_val}" >> "$env_file"
    fi
  else
    log_warn "Cannot read caddy_internal_hmac — CADDY_INTERNAL_HMAC already in .env, preserving (BUG-B+-004)"
  fi

  # --- Bucket-C: per-install YASHIGANI_INTERNAL_BEARER ---------------------
  # Replaces the hardcoded "yashigani-internal" literal that was baked into
  # public source (Captain gitleaks baseline finding 2026-05-17).
  # Token uses _gen_password() — 36 chars, A-Za-z0-9!*,-._~ with category
  # guarantees — per feedback_password_charset.md.
  # Mode 0600: only the install user can read it; Captain wires it into
  # docker-compose.yml as a Docker/Podman secret (Captain's scope).
  # Idempotent: file already exists with non-empty content → preserve.
  local _bearer_file="${secrets_dir}/yashigani_internal_bearer"
  if [[ ! -s "$_bearer_file" ]]; then
    local _bearer_token
    _bearer_token="$(_gen_password)"
    printf "%s" "$_bearer_token" > "$_bearer_file"
    chmod 0600 "$_bearer_file"
    log_info "Generated yashigani_internal_bearer → ${_bearer_file} (mode 0600)"
  else
    log_info "yashigani_internal_bearer already present — preserving (use --remove-volumes to rotate)"
    local _bearer_token
    # BUG-B+-004 (sweep): safe read — may be subuid-owned on Podman rootless re-install.
    _bearer_token="$(_safe_read_secret "$_bearer_file" "YASHIGANI_INTERNAL_BEARER" "$env_file" || true)"
  fi
  # Sync YASHIGANI_INTERNAL_BEARER into .env for Compose interpolation.
  if grep -q "^YASHIGANI_INTERNAL_BEARER=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^YASHIGANI_INTERNAL_BEARER=.*|YASHIGANI_INTERNAL_BEARER=${_bearer_token}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "YASHIGANI_INTERNAL_BEARER=${_bearer_token}" >> "$env_file"
  fi

  # pgbouncer_userlist SCRAM verifier generation removed (Tiago directive 2026-05-21).
  # YSG-RISK-049 is now CLOSED by the auth_query design (v2.24.0).
  # pgbouncer_authenticator_password (below) replaces the cleartext userlist.txt path.

  # --- pgbouncer_authenticator_password (YSG-RISK-049 close — v2.24.0) -----------
  # This credential is used exclusively by pgbouncer for the auth_query connection
  # to postgres (as the pgbouncer_authenticator role). It is never used by any
  # application service and grants only EXECUTE on ysg_pgbouncer_get_auth().
  #
  # KMS-architectural posture (per docs/yashigani_install_config.md §6.1):
  # In production with YASHIGANI_KMS_PROVIDER set, pgbouncer_authenticator_password
  # is fetched at runtime via the KMS provider and bypasses this cleartext
  # path entirely. Non-KMS dev/standalone deployments use this on-disk
  # cleartext at 0640 owned by pgbouncer UID 70 (dedicated mount, not GID 2002).
  #
  # Option C isolation (Iris + Laura 2026-05-21): dedicated Docker secret mount
  # at /run/secrets/pgbouncer_authenticator_password inside the container — NOT
  # GID-2002 bind-mount. YSG-SECRETS-DIST-002 blast radius unchanged.
  #
  # _do_chown now handles uid:gid pairs natively (V240-002 follow-up fix).
  # Correct ownership is 70:999 (pgbouncer uid:postgres gid) — pgbouncer (UID 70)
  # reads as owner; postgres (UID 999) reads as group at init time via
  # 10-pgbouncer-auth.sh. Symmetric with postgres_password 1001:999 0640.
  local _pgba_file="${secrets_dir}/pgbouncer_authenticator_password"
  if [[ ! -s "$_pgba_file" ]]; then
    local _pgba_pw
    _pgba_pw="$(_gen_password)"
    printf "%s" "$_pgba_pw" > "$_pgba_file"
    chmod 0600 "$_pgba_file"
    _do_chown "70:999" "$_pgba_file" "pgbouncer_authenticator_password" "" "${secrets_dir}" || true
    _do_chmod_0640 "$_pgba_file" "pgbouncer_authenticator_password" || true
    log_info "Generated pgbouncer_authenticator_password → ${_pgba_file} (mode 0640, uid 70:999)"
  else
    log_info "pgbouncer_authenticator_password already present — preserving (use --remove-volumes to rotate)"
  fi

  # --- HIBP breach check on generated passwords (defense-in-depth) ---
  _hibp_check_passwords

  # #2-fix: write YASHIGANI_VERSION to .env so `compose build` tags images
  # consistently with the installer version (`:${YASHIGANI_VERSION}`) and the
  # version is visible to Compose for any `${YASHIGANI_VERSION}` interpolation.
  if grep -q "^YASHIGANI_VERSION=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^YASHIGANI_VERSION=.*|YASHIGANI_VERSION=${YASHIGANI_VERSION}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "YASHIGANI_VERSION=${YASHIGANI_VERSION}" >> "$env_file"
  fi

  log_success "All passwords and 2FA secrets generated (${secrets_dir}/)"
}

# =============================================================================
# Have I Been Pwned (HIBP) k-Anonymity password breach check
# =============================================================================
# Uses the HIBP Passwords API v3 (api.pwnedpasswords.com)
# Protocol: SHA-1 hash the password, send first 5 chars, check locally.
# The actual password NEVER leaves the system.
# See: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

_hibp_check_single() {
  local label="$1"
  local password="$2"

  # Skip if no curl or no internet
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi

  # SHA-1 hash the password
  local sha1_hash=""
  if command -v shasum >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | shasum -a 1 | awk '{print toupper($1)}')"
  elif command -v sha1sum >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | sha1sum | awk '{print toupper($1)}')"
  elif command -v openssl >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | openssl dgst -sha1 | awk '{print toupper($NF)}')"
  else
    return 0  # Can't hash — skip silently
  fi

  local prefix="${sha1_hash:0:5}"
  local suffix="${sha1_hash:5}"

  # Query HIBP k-Anonymity API (5-char prefix only — password never sent)
  local response=""
  response="$(curl -sSL --max-time 5 --connect-timeout 3 \
    -H "User-Agent: Yashigani-Installer/${YASHIGANI_VERSION}" \
    "https://api.pwnedpasswords.com/range/${prefix}" 2>/dev/null || echo "")"

  if [[ -z "$response" ]]; then
    return 0  # API unreachable — skip silently (air-gapped, offline, etc.)
  fi

  # Check if our suffix appears in the response
  local match_count=""
  match_count="$(echo "$response" | grep -i "^${suffix}:" | cut -d: -f2 | tr -d '\r' || echo "")"

  if [[ -n "$match_count" && "$match_count" -gt 0 ]]; then
    log_warn "HIBP: ${label} password found in ${match_count} data breach(es) — regenerating..."
    return 1  # Compromised
  fi

  return 0  # Clean
}

_hibp_check_passwords() {
  # Only check if we have internet access (skip in offline/air-gap/demo-localhost mode)
  if [[ "$AIR_GAP" == "true" ]]; then
    log_info "Skipping HIBP breach check (air-gap mode — no outbound access)"
    log_info "  If a breach is suspected, rotate passwords once network access is restored."
    return 0
  fi
  if [[ "$OFFLINE" == "true" ]]; then
    log_info "Skipping HIBP breach check (offline mode)"
    return 0
  fi

  log_info "Checking generated passwords against HIBP breach database..."

  local max_retries=3

  # Check admin1 — regenerate if compromised (extremely unlikely for 36-char random)
  local attempt=0
  while ! _hibp_check_single "Admin 1 (${GEN_ADMIN1_USERNAME})" "$GEN_ADMIN1_PASSWORD"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      log_warn "HIBP: Could not generate a clean password after ${max_retries} attempts — proceeding anyway"
      break
    fi
    GEN_ADMIN1_PASSWORD="$(_gen_password)"
    printf "%s" "$GEN_ADMIN1_PASSWORD" > "${WORK_DIR}/docker/secrets/admin1_password"
  done

  # Check admin2
  attempt=0
  while ! _hibp_check_single "Admin 2 (${GEN_ADMIN2_USERNAME})" "$GEN_ADMIN2_PASSWORD"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      break
    fi
    GEN_ADMIN2_PASSWORD="$(_gen_password)"
    printf "%s" "$GEN_ADMIN2_PASSWORD" > "${WORK_DIR}/docker/secrets/admin2_password"
  done

  # Check service passwords (postgres, redis, grafana)
  _hibp_check_and_regen "postgres" "$GEN_POSTGRES_PASSWORD" "${WORK_DIR}/docker/secrets/postgres_password" $max_retries
  _hibp_check_and_regen "redis" "$GEN_REDIS_PASSWORD" "${WORK_DIR}/docker/secrets/redis_password" $max_retries
  _hibp_check_and_regen "grafana" "$GEN_GRAFANA_PASSWORD" "${WORK_DIR}/docker/secrets/grafana_admin_password" $max_retries

  log_success "HIBP breach check complete — all passwords clean"
}

_hibp_check_and_regen() {
  local label="$1"
  local password="$2"
  local secret_file="$3"
  local max_retries="$4"
  local attempt=0

  while ! _hibp_check_single "$label" "$password"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      break
    fi
    password="$(_gen_password)"
    printf "%s" "$password" > "$secret_file"
  done

  # Update the module-level variable
  local upper_label
  upper_label="$(echo "$label" | tr '[:lower:]' '[:upper:]')"
  printf -v "GEN_${upper_label}_PASSWORD" '%s' "$password"
}

# =============================================================================
# STEP 13 (compose/vm): Completion summary with credentials
# =============================================================================
print_completion_summary() {
  set_step "13" "Completion"
  log_step "13/${TOTAL_STEPS}" "Installation complete"

  local proto="https"
  [[ "$TLS_MODE" == "selfsigned" ]] && proto="https (self-signed)"

  printf "\n"
  printf "${C_GREEN}╔═══════════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_GREEN}║    Yashigani v%-8s is up and running!                     ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_GREEN}╚═══════════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  # --- Access URLs ---
  if [[ -n "$DOMAIN" ]]; then
    printf "  ${C_BOLD}Access:${C_RESET}\n"
    printf "    %-22s %s://%s\n"           "Open WebUI:"   "$proto"  "$DOMAIN"
    printf "    %-22s %s://%s/admin/login\n" "Admin Panel:" "$proto" "$DOMAIN"
    printf "    %-22s %s://%s/v1\n"        "Gateway API:"  "https"   "$DOMAIN"
    if [[ "$DOMAIN" != "localhost" ]]; then
      printf "    %-22s https://%s:3000\n" "Grafana:" "$DOMAIN"
    else
      printf "    %-22s https://localhost:3000\n" "Grafana:"
    fi
    printf "\n"
  fi

  # --- Credentials (shown ONCE — never again) ---
  printf "  ${C_YELLOW}╔══════════════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "  ${C_YELLOW}║  CREDENTIALS — SAVE THESE NOW (shown only once)                 ║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Admin 1 (primary):${C_RESET}                                           ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_USERNAME}"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP secret:  %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_TOTP_SECRET}"
  if [[ -n "$GEN_ADMIN1_TOTP_URI" ]]; then
  printf "  ${C_YELLOW}║${C_RESET}    TOTP URI (paste into authenticator app):                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %s\n" "${GEN_ADMIN1_TOTP_URI}"
  fi
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Admin 2 (backup — anti-lockout):${C_RESET}                              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_USERNAME}"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP secret:  %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_TOTP_SECRET}"
  if [[ -n "$GEN_ADMIN2_TOTP_URI" ]]; then
  printf "  ${C_YELLOW}║${C_RESET}    TOTP URI (paste into authenticator app):                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %s\n" "${GEN_ADMIN2_TOTP_URI}"
  fi
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Encryption Key (AES-256 + HMAC):${C_RESET}                              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %-60s ${C_YELLOW}║${C_RESET}\n" "${DB_AES_KEY:-[not set]}"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}CRITICAL: This key encrypts database columns AND hashes${C_RESET}       ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}email addresses in audit logs. Losing this key means${C_RESET}          ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}permanent data loss. Store in break-glass vault.${C_RESET}              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}PostgreSQL:${C_RESET}                                                  ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    User:         yashigani_app                                  ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_POSTGRES_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Redis:${C_RESET}                                                       ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_REDIS_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Grafana:${C_RESET}                                                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     admin                                          ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_GRAFANA_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  if [[ -n "${GEN_WAZUH_INDEXER_PASSWORD:-}" ]]; then
    printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Wazuh SIEM:${C_RESET}                                                  ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}    Indexer:      admin / %-34s ${C_YELLOW}║${C_RESET}\n" "${GEN_WAZUH_INDEXER_PASSWORD}"
    printf "  ${C_YELLOW}║${C_RESET}    API:          wazuh-wui / %-30s ${C_YELLOW}║${C_RESET}\n" "${GEN_WAZUH_API_PASSWORD}"
    printf "  ${C_YELLOW}║${C_RESET}    Dashboard:    kibanaserver / %-28s ${C_YELLOW}║${C_RESET}\n" "${GEN_WAZUH_DASHBOARD_PASSWORD}"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  fi
  # --- YASHIGANI_INTERNAL_BEARER audit line (masked — operator sanity check) ---
  local _ibearer_file="${WORK_DIR}/docker/secrets/yashigani_internal_bearer"
  if [[ -s "$_ibearer_file" || -f "$_ibearer_file" ]]; then
    local _ibearer_full
    # BUG-B+-004 (sweep): safe read — may be subuid-owned on Podman rootless.
    _ibearer_full="$(_safe_read_secret "$_ibearer_file" "YASHIGANI_INTERNAL_BEARER" \
                     "${WORK_DIR}/docker/.env" 2>/dev/null || true)"
    local _ibearer_len="${#_ibearer_full}"
    local _ibearer_preview="${_ibearer_full:0:4}...${_ibearer_full: -4} (${_ibearer_len} chars)"
    printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Internal Bearer token:${C_RESET}                                        ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}    %-60s ${C_YELLOW}║${C_RESET}\n" "${_ibearer_preview}"
    printf "  ${C_YELLOW}║${C_RESET}    (first 4 + last 4 chars shown — full token in docker/secrets/)   ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  fi
  printf "  ${C_YELLOW}╚══════════════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"
  printf "  ${C_RED}${C_BOLD}WARNING:${C_RESET} These credentials will NOT be shown again.\n"
  printf "  ${C_RED}Store them in a password manager or secure vault immediately.${C_RESET}\n"
  printf "\n"

  # --- Agent bundles ---
  if [[ ${#COMPOSE_PROFILES[@]} -gt 0 ]]; then
    printf "  ${C_BOLD}Agent bundles installed:${C_RESET} %s\n" "${COMPOSE_PROFILES[*]}"
    printf "\n"
  fi

  # --- Deployment mode ---
  printf "  ${C_BOLD}Deployment:${C_RESET}\n"
  printf "    %-22s %s\n" "Mode:"      "${DEPLOY_MODE:-compose}"
  printf "    %-22s %s\n" "Directory:" "$WORK_DIR"
  printf "    %-22s %s\n" "TLS:"       "$TLS_MODE"
  if [[ "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    printf "    %-22s %s\n" "GPU:"     "${YSG_GPU_NAME}"
  fi
  printf "\n"

  # --- Next steps ---
  printf "  ${C_BOLD}Next steps:${C_RESET}\n"
  printf "    1. Save ALL credentials above in a password manager\n"
  printf "    2. Scan the TOTP QR URIs into a SHA-256-compatible authenticator app (Authy, 1Password, Aegis).\n       Note: Google Authenticator may not work on iOS or older Android — Yashigani uses HMAC-SHA-256\n       per the SHA-256 minimum policy. Apps that ignore the algorithm parameter default to SHA-1\n       and will silently produce wrong codes.\n"
  printf "    3. Log in to the backoffice as '%s' and change the default password\n" "${GEN_ADMIN1_USERNAME}"
  printf "    4. Store '%s' credentials in a safe/vault (break-glass backup)\n" "${GEN_ADMIN2_USERNAME}"
  printf "    5. Register your first AI agent\n"
  printf "    6. Configure your OPA RBAC policy\n"
  if [[ "$DEPLOY_MODE" != "demo" ]]; then
    printf "    7. Set up SIEM integration (Splunk / Elastic / Wazuh)\n"
    printf "    8. Import your licence key (if not done during install)\n"
  fi
  printf "\n"

  # --- Useful commands ---
  printf "  ${C_BOLD}Useful commands:${C_RESET}\n"
  printf "    Health check:    bash %s/scripts/health-check.sh\n" "$WORK_DIR"
  printf "    View logs:       ${COMPOSE_CMD[*]:-docker compose} -f %s/docker/docker-compose.yml logs -f\n" "$WORK_DIR"
  printf "    Update:          bash %s/update.sh\n" "$WORK_DIR"
  printf "    Uninstall:       bash %s/uninstall.sh\n" "$WORK_DIR"
  printf "\n"

  # --- DNS / Browser access guidance ---
  if [[ "$TLS_MODE" == "selfsigned" && "$DOMAIN" != "localhost" ]]; then
    local machine_ip
    machine_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || ipconfig getifaddr en0 2>/dev/null || echo "<this-machine-ip>")"

    printf "  ${C_YELLOW}╔══════════════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "  ${C_YELLOW}║  IMPORTANT: DNS / Browser Access                                 ║${C_RESET}\n"
    printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Yashigani uses a self-signed TLS certificate for the domain    ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  '%s'. To access it from your browser or other  ${C_YELLOW}║${C_RESET}\n" "${DOMAIN}"
    printf "  ${C_YELLOW}║${C_RESET}  machines, add this entry to /etc/hosts on each client:         ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Run on your computer (or any client that needs access):        ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}    sudo sh -c 'echo \"%s %s\" >> /etc/hosts'  ${C_YELLOW}║${C_RESET}\n" "$machine_ip" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Then open: https://%s                          ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}  Admin UI:  https://%s/admin/login              ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Your browser will show a certificate warning — this is         ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  expected with self-signed certificates. Accept it to proceed.  ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  For curl: curl -sk https://%s/healthz          ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}╚══════════════════════════════════════════════════════════════════╝${C_RESET}\n"
    printf "\n"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "This was a dry-run — no changes were made to the system"
  fi
}

# =============================================================================
# Kubernetes flow steps
# =============================================================================

# STEP 7 (k8s): helm dependency update
k8s_helm_dep_update() {
  set_step "7" "helm dependency update"
  log_step "7/${TOTAL_STEPS}" "Updating Helm chart dependencies..."

  require_cmd "helm"

  local chart_dir="${WORK_DIR}/helm/yashigani"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "helm dependency update $chart_dir"
    return 0
  fi

  if [[ ! -d "$chart_dir" ]]; then
    log_error "Helm chart directory not found: $chart_dir"
    exit 1
  fi

  helm dependency update "$chart_dir"
  log_success "Helm dependencies updated"
}

# _write_helm_values — render operator-supplied flags into ${WORK_DIR}/.env.helm
# (B2 — GAP 2: this file was never written by any code path; k8s_helm_install
# silently fell through to chart defaults meaning DOMAIN, UPSTREAM_URL, AES key,
# and TLS_MODE never reached Helm regardless of what the operator passed).
#
# Produces a YAML values override file read by k8s_helm_install as `-f .env.helm`.
# Helm merge order: chart defaults < -f .env.helm < --set flags.
# The FIPS_MODE --set injection in k8s_helm_install is intentionally retained
# (--set wins over -f, and the operator-visible log message stays).
#
# DB_AES_KEY handling: the `yashigani-backoffice-secrets` Secret generated by
# helm/yashigani/templates/secrets.yaml uses Helm's lookup() to preserve the
# existing Secret value on upgrade, and generates via randAlphaNum when absent.
# There is no values.yaml key for db_aes_key — it requires a Captain schema change
# to backoffice.dbAesKey. Coordination note: Captain must add
# `backoffice.dbAesKey` to values.yaml and update templates/secrets.yaml to use
# .Values.backoffice.dbAesKey when non-empty. Until that schema change lands,
# DB_AES_KEY is pre-seeded into a K8s Secret before helm install so that Helm's
# lookup() path preserves the operator-generated key on all installs.
#
# Permissions: 0600 — the file may contain the licensing key (paid credential).
_write_helm_values() {
  local helm_values="${WORK_DIR}/.env.helm"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "_write_helm_values → ${helm_values}"
    return 0
  fi

  # Create with 0600 IMMEDIATELY (may contain license key — paid credential).
  # umask 022 would produce 0644 which is world-readable; explicit chmod prevents
  # that race between touch and chmod.
  touch "$helm_values"
  chmod 0600 "$helm_values"

  # Write YAML values override.
  # Each key is only written when the operator supplied a non-empty value —
  # empty writes would silently override chart defaults with empty strings,
  # which is worse than omitting the key entirely.
  {
    printf '# Yashigani helm values override — generated by install.sh\n'
    printf '# B2-fix: operator-supplied flags are now written here so k8s_helm_install\n'
    printf '# does not silently deploy with chart defaults for domain/upstream/tls-mode.\n'
    printf '# DO NOT edit manually — re-run install.sh to regenerate.\n'
    printf '\n'
    printf 'global:\n'

    if [[ -n "${DOMAIN:-}" ]]; then
      # YAML single-quote the domain to prevent glob/special-char interpretation.
      printf "  tlsDomain: '%s'\n" "${DOMAIN}"
    fi

    if [[ -n "${TLS_MODE:-}" ]]; then
      printf "  tlsMode: '%s'\n" "${TLS_MODE}"
    fi

    if [[ -n "${ADMIN_EMAIL:-}" ]]; then
      # acmeEmail used by ACME/Let's Encrypt — also the primary admin contact.
      printf "  acmeEmail: '%s'\n" "${ADMIN_EMAIL}"
    fi

    printf '\n'
    printf 'gateway:\n'
    printf '  env:\n'

    if [[ -n "${UPSTREAM_URL:-}" ]]; then
      printf "    upstreamUrl: '%s'\n" "${UPSTREAM_URL}"
    fi

    printf '\n'
    printf 'fips:\n'
    # Write fips.mode into the file so the value is visible in the values
    # override. The --set fips.mode=true injection in k8s_helm_install is
    # kept (--set wins over -f); this makes the intent explicit in the file.
    if [[ "${FIPS_MODE:-0}" == "1" ]]; then
      printf '  mode: true\n'
    else
      printf '  mode: false\n'
    fi
    # Nico N-002 (v2.25.0 P2 B9): persist cmvpCert too. Operator-supplied;
    # may be empty (omit field if so to preserve chart default).
    # YAML-single-quoted to safely carry "#" (would be a YAML comment unquoted).
    # Replace any single quotes in the value with the YAML-escaped form ''.
    if [[ -n "${CMVP_CERT:-}" ]]; then
      printf "  cmvpCert: '%s'\n" "${CMVP_CERT//\'/\'\'}"
    fi

    # License key: read from file if operator passed --license-key.
    # Written last — it may be multi-line (YAML literal block scalar).
    if [[ -n "${LICENSE_KEY_PATH:-}" ]]; then
      if [[ -f "$LICENSE_KEY_PATH" ]]; then
        local _license_content
        _license_content="$(cat "$LICENSE_KEY_PATH" 2>/dev/null || true)"
        if [[ -n "$_license_content" ]]; then
          printf '\n'
          printf 'licensing:\n'
          # YAML literal block scalar (|) preserves newlines. Indent 4 spaces.
          printf '  licenseKey: |\n'
          printf '%s\n' "$_license_content" | sed 's/^/    /'
          log_info "License key written to helm values (from ${LICENSE_KEY_PATH})"
        else
          log_warn "License key file is empty: ${LICENSE_KEY_PATH} — community tier will be used"
        fi
      else
        log_error "License key file not found: ${LICENSE_KEY_PATH}"
        exit 1
      fi
    fi

  } >> "$helm_values"

  # Pre-seed backoffice Secret with operator-supplied AES key BEFORE helm install.
  # Helm's lookup() in templates/secrets.yaml will find this Secret and preserve
  # db_aes_key rather than generating randAlphaNum. On upgrade, the existing
  # Secret is already present so lookup() preserves it automatically.
  # When DB_AES_KEY is empty provision_aes_key() already generated one — use it.
  if [[ -n "${DB_AES_KEY:-}" && -n "${NAMESPACE:-}" ]] && command -v kubectl >/dev/null 2>&1; then
    local _bo_secret_name="yashigani-backoffice-secrets"
    if ! kubectl get secret "$_bo_secret_name" -n "$NAMESPACE" >/dev/null 2>&1; then
      log_info "Pre-seeding ${_bo_secret_name} with operator AES key..."
      kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml \
        | kubectl apply -f - >/dev/null 2>&1 || true
      kubectl create secret generic "$_bo_secret_name" \
        --namespace "$NAMESPACE" \
        --from-literal=db_aes_key="${DB_AES_KEY}" \
        --dry-run=client -o yaml \
        | kubectl apply -f - >/dev/null
      log_success "AES key pre-seeded into ${_bo_secret_name} (namespace: ${NAMESPACE})"
    else
      log_info "Secret ${_bo_secret_name} already exists — preserving existing AES key (upgrade path)"
    fi
  fi

  log_success "Helm values written: ${helm_values}"
  log_info "  tlsDomain=${DOMAIN:-<unset>}  tlsMode=${TLS_MODE:-<unset>}  upstreamUrl=${UPSTREAM_URL:-<unset>}"
}

# STEP 8 (k8s): helm upgrade --install
# Last updated (k8s_helm_install): 2026-05-08T00:00:00+01:00
k8s_helm_install() {
  set_step "8" "helm upgrade --install"
  log_step "8/${TOTAL_STEPS}" "Deploying via Helm..."

  require_cmd "helm"

  local chart_dir="${WORK_DIR}/helm/yashigani"
  local helm_values="${WORK_DIR}/.env.helm"

  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ -f "$helm_values" ]]; then
      dry_print "helm upgrade --install yashigani $chart_dir -n $NAMESPACE --create-namespace -f $helm_values"
    else
      dry_print "helm upgrade --install yashigani $chart_dir -n $NAMESPACE --create-namespace"
    fi
    return 0
  fi

  # v2.23.3 retro K8s gap — differentiate fresh-install vs upgrade timeout.
  #
  # Fresh install: 10m — pre-flight image pull (scripts/k8s-install.sh or
  #   operator pre-pull step in kubernetes_deployment.md) is expected before
  #   helm install. With images already present in the node's containerd
  #   cache, 10m is sufficient for all hook jobs + pod ready transitions on
  #   Docker Desktop and kind clusters.
  #
  # Upgrade: 5m — pods are already running; only rolling restarts are needed.
  #   New images should be pre-pulled before upgrading. 5m is tight enough to
  #   surface stuck rollouts quickly rather than letting operators wait 20m.
  #
  # Override: set HELM_TIMEOUT env var before calling install.sh to force a
  #   specific value (e.g. HELM_TIMEOUT=20m for air-gap first-installs where
  #   image pull cannot be pre-staged).
  #
  # v2.23.1 task #94 — flag set rationale (unchanged):
  #   --wait              block until all Deployments/StatefulSets Available so
  #                       the next install step (rollout status) doesn't race.
  #   --wait-for-jobs     pre-install hooks (admin-bootstrap, mtls-bootstrap)
  #                       must finish before main resources, otherwise the
  #                       backoffice starts without the bootstrap secret.
  #   --atomic            on failure, helm rolls back; avoids leaving the
  #                       release in pending-install state which then blocks
  #                       a subsequent helm install with "cannot re-use a
  #                       name that is still in use".
  #   --burst-limit 1000  raise client-side throttling above the default 100
  #   --qps 500           so that helm's internal poll loop (which iterates
  #                       all 97 resources every 2s) does not saturate the
  #                       client-go rate limiter and spuriously raise
  #                       "client rate limiter Wait returned an error:
  #                       context deadline exceeded".

  local _helm_timeout
  if [[ -n "${HELM_TIMEOUT:-}" ]]; then
    _helm_timeout="${HELM_TIMEOUT}"
    log_info "Using HELM_TIMEOUT override: ${_helm_timeout}"
  elif helm status yashigani --namespace "$NAMESPACE" >/dev/null 2>&1; then
    # Release already exists — this is an upgrade.
    _helm_timeout="5m"
    log_info "Existing Helm release detected — using upgrade timeout: ${_helm_timeout}"
  else
    # Fresh install.
    _helm_timeout="10m"
    log_info "No existing Helm release — using fresh-install timeout: ${_helm_timeout}"
  fi

  local helm_args=(
    upgrade --install yashigani "$chart_dir"
    --namespace "$NAMESPACE"
    --create-namespace
    --wait
    --wait-for-jobs
    --timeout "${_helm_timeout}"
    --atomic
    --burst-limit 1000
    --qps 500
  )

  # B2-fix: gate on values file existence. _write_helm_values must run before
  # this step (called from main() k8s path). If the file is absent it means the
  # install sequence is broken — fail closed rather than deploy misconfigured.
  if [[ -f "$helm_values" ]]; then
    helm_args+=(-f "$helm_values")
  else
    log_error "Helm values file not found: $helm_values"
    log_error "_write_helm_values must run before k8s_helm_install (sequence bug)"
    log_error "Re-run install.sh from the beginning to regenerate $helm_values"
    exit 1
  fi

  # Iris drift gate finding Q1 (v2.24.4 close): translate --fips-mode to
  # the helm chart's fips.mode value. Captain's chart accepts --set
  # fips.mode=true; without this translation `install.sh --mode k8s
  # --fips-mode 1` silently produces FIPS=off in every k8s container
  # because compose's docker/.env path is irrelevant in k8s mode.
  # Closes the install.sh side of B8 for k8s — parallel to the compose-
  # path _env_set "FIPS_MODE" writes that this branch already added.
  if [[ "${FIPS_MODE:-0}" == "1" ]]; then
    helm_args+=(--set fips.mode=true)
    log_info "FIPS_MODE=1 — passing --set fips.mode=true to helm"
  fi
  # Nico N-002 (v2.25.0 P2 B9): translate --cmvp-cert to fips.cmvpCert helm value.
  # Without this, --mode k8s --cmvp-cert "#4985" silently drops the cert number
  # (k8s path doesn't read docker/.env). Mirrors the FIPS_MODE Q1 pattern above.
  if [[ -n "${CMVP_CERT:-}" ]]; then
    helm_args+=(--set "fips.cmvpCert=${CMVP_CERT}")
    log_info "CMVP_CERT=${CMVP_CERT} — passing --set fips.cmvpCert to helm"
  fi

  helm "${helm_args[@]}"
  log_success "Helm release deployed"

  # Petra P0-1 (v2.24.4): warn if licensing.licenseKey was not supplied.
  # When the key is absent the gateway and backoffice fall back to COMMUNITY
  # tier — every paid-tier K8s install silently regressed to COMMUNITY before
  # this fix. Emit a visible WARNING so the operator knows to re-run with:
  #   helm upgrade yashigani ... --set licensing.licenseKey="$(cat my.ysg)"
  local _lic_secret
  _lic_secret=$(kubectl get secret yashigani-license --namespace "$NAMESPACE" \
    --ignore-not-found 2>/dev/null)
  if [[ -z "$_lic_secret" ]]; then
    log_warn "COMMUNITY TIER ACTIVE: yashigani-license Secret not found."
    log_warn "Gateway and backoffice are running in COMMUNITY tier."
    log_warn "To enroll a paid licence re-run with:"
    log_warn "  helm upgrade yashigani ./helm/yashigani -n ${NAMESPACE} \\"
    log_warn "    --set licensing.licenseKey=\"\$(cat /path/to/your.ysg)\""
  fi
}

# STEP 9 (k8s): kubectl rollout status
k8s_rollout_status() {
  set_step "9" "kubectl rollout status"
  log_step "9/${TOTAL_STEPS}" "Waiting for gateway deployment to become ready..."

  require_cmd "kubectl"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "kubectl rollout status deployment/yashigani-gateway -n $NAMESPACE --timeout=300s"
    return 0
  fi

  kubectl rollout status deployment/yashigani-gateway \
    --namespace "$NAMESPACE" \
    --timeout=300s

  log_success "Gateway deployment is ready"
}

# STEP 10 (k8s): Access instructions
k8s_print_access() {
  set_step "10" "Access instructions"
  log_step "10/${TOTAL_STEPS}" "Deployment complete"

  printf "\n"
  printf "${C_GREEN}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_GREEN}║  Yashigani v%-8s deployed to Kubernetes!     ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_GREEN}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"
  printf "  %-22s %s\n" "Namespace:"    "$NAMESPACE"
  printf "  %-22s %s\n" "Helm release:" "yashigani"
  if [[ -n "$DOMAIN" ]]; then
    printf "  %-22s https://%s\n" "Dashboard:" "$DOMAIN"
  fi
  printf "\n"
  printf "  Check pods:\n"
  printf "    kubectl get pods -n %s\n\n" "$NAMESPACE"
  printf "  View gateway logs:\n"
  printf "    kubectl logs -f deployment/yashigani-gateway -n %s\n\n" "$NAMESPACE"
  printf "  Uninstall:\n"
  printf "    helm uninstall yashigani -n %s\n\n" "$NAMESPACE"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "This was a dry-run — no changes were made to the cluster"
  fi
}

# =============================================================================
# Public-access SAN auto-detection (YSG-CERT-SAN-001)
# =============================================================================
# Detect the host's public-facing hostname and primary IP for inclusion in the
# Caddy server cert SAN. Called once before PKI bootstrap + rotation.
#
# Resolution order (per _detect_public_access_params):
#   1. Operator flag: --public-hostname / --public-ip (already in YSG_PUBLIC_HOSTNAME / YSG_PUBLIC_IP)
#   2. Auto-detect: hostname -f (FQDN) + hostname -I (first non-loopback IP)
#   3. Fall through with empty values — cert has internal SANs only (old behaviour).
#
# Results are exported; _pki_run_issuer passes them to the issuer via
# --caddy-extra-dns and --caddy-extra-ip flags on bootstrap / rotate-leaves.
# =============================================================================

_detect_public_access_params() {
  # Step 1 — if both already set by flags, nothing to do.
  if [[ -n "${YSG_PUBLIC_HOSTNAME:-}" && -n "${YSG_PUBLIC_IP:-}" ]]; then
    log_info "Public access SAN: hostname=${YSG_PUBLIC_HOSTNAME} ip=${YSG_PUBLIC_IP} (from flags)"
    export YSG_PUBLIC_HOSTNAME YSG_PUBLIC_IP
    return 0
  fi

  # Step 2 — auto-detect hostname if not set.
  if [[ -z "${YSG_PUBLIC_HOSTNAME:-}" ]]; then
    local _detected_hostname=""
    # hostname -f (FQDN) preferred — falls back to short hostname if FQDN unavailable.
    # macOS: hostname -f is not supported; use hostname alone.
    if [[ "$(uname -s)" == "Darwin" ]]; then
      _detected_hostname="$(hostname 2>/dev/null || true)"
    else
      _detected_hostname="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
    fi
    # Strip trailing dot (some distros emit "myhost.lan." from hostname -f).
    _detected_hostname="${_detected_hostname%.}"
    # Reject empty, localhost, or .localdomain — these add no demo value.
    if [[ -n "$_detected_hostname" \
          && "$_detected_hostname" != "localhost" \
          && "$_detected_hostname" != "localhost.localdomain" ]]; then
      YSG_PUBLIC_HOSTNAME="$_detected_hostname"
      log_info "Public access SAN: hostname=${YSG_PUBLIC_HOSTNAME} (auto-detected via hostname -f)"
    else
      log_info "Public access SAN: hostname auto-detect returned '${_detected_hostname}' — skipping DNS SAN"
    fi
    export YSG_PUBLIC_HOSTNAME
  fi

  # Step 3 — auto-detect primary external IP if not set.
  if [[ -z "${YSG_PUBLIC_IP:-}" ]]; then
    local _detected_ip=""
    # hostname -I returns space-separated IPs; take the first non-loopback one.
    # macOS: hostname -I is not supported; use ipconfig getifaddr en0 as fallback.
    if [[ "$(uname -s)" == "Darwin" ]]; then
      _detected_ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
      if [[ -z "$_detected_ip" ]]; then
        # en1 fallback (Wi-Fi on some Macs)
        _detected_ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
      fi
    else
      # hostname -I: space-separated; pick first entry, strip leading/trailing space.
      _detected_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    # Reject empty or loopback addresses.
    if [[ -n "$_detected_ip" \
          && "$_detected_ip" != "127.0.0.1" \
          && "$_detected_ip" != "::1" ]]; then
      YSG_PUBLIC_IP="$_detected_ip"
      log_info "Public access SAN: ip=${YSG_PUBLIC_IP} (auto-detected)"
    else
      log_info "Public access SAN: IP auto-detect returned '${_detected_ip}' — skipping IP SAN"
    fi
    export YSG_PUBLIC_IP
  fi

  if [[ -n "${YSG_PUBLIC_HOSTNAME:-}" || -n "${YSG_PUBLIC_IP:-}" ]]; then
    log_info "Caddy cert will cover: ${YSG_PUBLIC_HOSTNAME:-<none>} / ${YSG_PUBLIC_IP:-<none>}"
    log_info "  Proper deployments: use --tls-mode acme or --tls-mode ca for browser-trusted certs"
  else
    log_warn "Public access SAN: no hostname or IP resolved — Caddy cert covers internal names only"
    log_warn "  Access via VM IP will fail TLS. Use --public-hostname / --public-ip to override."
  fi
}

# =============================================================================
# Main
# =============================================================================
# =============================================================================
# Internal mTLS PKI bootstrap (task #29 — v2.23.1)
#
# Two-tier CA (root → intermediate → leaf) generated by Python's cryptography
# library via `python -m yashigani.pki.issuer`. Produces:
#   ./docker/secrets/ca_root.crt           (trust anchor for every service)
#   ./docker/secrets/ca_root.key           (0400 — never leaves the host)
#   ./docker/secrets/ca_intermediate.crt   (signs leaves)
#   ./docker/secrets/ca_intermediate.key
#   ./docker/secrets/<service>_client.crt  (leaf || intermediate PEM bundle)
#   ./docker/secrets/<service>_client.key
#   ./docker/secrets/<service>_bootstrap_token  (tamper-check token, SHA-256
#                                                recorded in the manifest)
#
# The gateway image (built in compose_pull) bundles the yashigani package
# including yashigani.pki.issuer and its cryptography dependency, so we run
# the issuer as a throwaway container with the secrets dir + manifest
# bind-mounted.
# =============================================================================

_pki_runtime_cmd() {
  # Pick docker vs podman. Priority:
  #   1. Explicit request: YSG_PODMAN_RUNTIME=true -> podman (even if docker is
  #      installed, honour the operator's choice).
  #   1b. gate #ROOTLESS-10: also honour YSG_RUNTIME=podman directly. When
  #      --skip-pull is passed, compose_pull() returns before resolve_compose_cmd()
  #      is called, so YSG_PODMAN_RUNTIME stays false even though the operator
  #      chose podman via YSG_RUNTIME=podman. Reading YSG_RUNTIME here as a
  #      fallback ensures _pki_run_issuer uses podman on --skip-pull paths.
  #   2. Docker available -> docker (fastest path on typical dev machines).
  #   3. Podman fallback.
  # Platform Review Finding fix — earlier version had inverted logic that ignored
  # YSG_PODMAN_RUNTIME when docker was also present.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    echo "podman"; return
  fi
  if [[ "${YSG_RUNTIME:-}" == "podman" ]]; then
    echo "podman"; return
  fi
  if command -v docker >/dev/null 2>&1; then
    echo "docker"; return
  fi
  echo "podman"
}

_pki_validate_lifetimes() {
  # Clamp to manifest bounds: root 5-20 yr, intermediate 90-365 d, leaf 30-90 d.
  if ! [[ "$YASHIGANI_ROOT_CA_LIFETIME_YEARS" =~ ^[0-9]+$ ]] \
     || (( YASHIGANI_ROOT_CA_LIFETIME_YEARS < 5 )) \
     || (( YASHIGANI_ROOT_CA_LIFETIME_YEARS > 20 )); then
    log_warn "Root CA lifetime ${YASHIGANI_ROOT_CA_LIFETIME_YEARS} outside 5–20 yr bounds; clamping to 10"
    YASHIGANI_ROOT_CA_LIFETIME_YEARS=10
  fi
  if ! [[ "$YASHIGANI_INTERMEDIATE_LIFETIME_DAYS" =~ ^[0-9]+$ ]] \
     || (( YASHIGANI_INTERMEDIATE_LIFETIME_DAYS < 90 )) \
     || (( YASHIGANI_INTERMEDIATE_LIFETIME_DAYS > 365 )); then
    log_warn "Intermediate lifetime ${YASHIGANI_INTERMEDIATE_LIFETIME_DAYS} outside 90–365 d bounds; clamping to 180"
    YASHIGANI_INTERMEDIATE_LIFETIME_DAYS=180
  fi
  if ! [[ "$YASHIGANI_CERT_LIFETIME_DAYS" =~ ^[0-9]+$ ]] \
     || (( YASHIGANI_CERT_LIFETIME_DAYS < 30 )) \
     || (( YASHIGANI_CERT_LIFETIME_DAYS > 90 )); then
    log_warn "Leaf cert lifetime ${YASHIGANI_CERT_LIFETIME_DAYS} outside 30–90 d bounds; clamping to 90"
    YASHIGANI_CERT_LIFETIME_DAYS=90
  fi
}

_pki_prompt_lifetimes() {
  # Ask the operator during the wizard. Silent in non-interactive / demo mode.
  if [[ "$NON_INTERACTIVE" == "true" || "$DEPLOY_MODE" == "demo" ]]; then
    return 0
  fi
  printf "\n${C_BOLD}Internal mTLS certificate lifetimes${C_RESET}\n"
  printf "  Services inside Yashigani authenticate each other with short-lived\n"
  printf "  client certificates. Defaults follow web-PKI conventions.\n"
  printf "\n"

  local _input
  printf "  Leaf cert lifetime (service client certs, days, 30–90) [${YASHIGANI_CERT_LIFETIME_DAYS}]: "
  read -r _input </dev/tty 2>/dev/null || _input=""
  [[ -n "$_input" ]] && YASHIGANI_CERT_LIFETIME_DAYS="$_input"

  printf "  Intermediate CA lifetime (days, 90–365) [${YASHIGANI_INTERMEDIATE_LIFETIME_DAYS}]: "
  read -r _input </dev/tty 2>/dev/null || _input=""
  [[ -n "$_input" ]] && YASHIGANI_INTERMEDIATE_LIFETIME_DAYS="$_input"

  printf "  Root CA lifetime (years, 5–20) [${YASHIGANI_ROOT_CA_LIFETIME_YEARS}]: "
  read -r _input </dev/tty 2>/dev/null || _input=""
  [[ -n "$_input" ]] && YASHIGANI_ROOT_CA_LIFETIME_YEARS="$_input"

  _pki_validate_lifetimes
}

_pki_persist_env() {
  local env_file="${WORK_DIR}/docker/.env"
  if [[ -z "${WORK_DIR:-}" || ! -d "$WORK_DIR" ]]; then
    log_error "_pki_persist_env: WORK_DIR not set or missing — cannot write .env"
    return 1
  fi
  for kv in \
    "YASHIGANI_ROOT_CA_LIFETIME_YEARS:${YASHIGANI_ROOT_CA_LIFETIME_YEARS}" \
    "YASHIGANI_INTERMEDIATE_LIFETIME_DAYS:${YASHIGANI_INTERMEDIATE_LIFETIME_DAYS}" \
    "YASHIGANI_CERT_LIFETIME_DAYS:${YASHIGANI_CERT_LIFETIME_DAYS}"; do
    local k="${kv%%:*}"; local v="${kv#*:}"
    if grep -q "^${k}=" "$env_file" 2>/dev/null; then
      # Platform Review Finding: mktemp on same filesystem as target so mv is atomic.
      local tmp_env; tmp_env="$(mktemp "${env_file}.XXXXXX")"
      sed "s|^${k}=.*|${k}=${v}|" "$env_file" > "$tmp_env" && mv "$tmp_env" "$env_file"
    else
      echo "${k}=${v}" >> "$env_file"
    fi
  done
}

# =============================================================================
# _pki_run_issuer — per-runtime split (P-10 / v2.23.3 refactor)
#
# Per project_podman_parity_registry.md discipline (Tiago directive 2026-05-10):
# unified if/else runtime branches inside a single function are the failure mode
# the registry exists to prevent. Each runtime gets its own function with its own
# invariants. The dispatcher (_pki_run_issuer) owns shared preamble only.
#
# Call graph:
#   _pki_run_issuer(subcmd, args...)
#     → _pki_run_issuer_docker(subcmd, image, manifest_in, secrets_in, args...)
#     → _pki_run_issuer_podman_linux(subcmd, image, manifest_in, secrets_in, args...)
#     → _pki_run_issuer_podman_macos(subcmd, image, manifest_in, secrets_in, args...)
# =============================================================================

# ---------------------------------------------------------------------------
# _pki_run_issuer_docker — Docker runtime issuer execution
#
# Carries 3174a1e macOS+Docker Colima virtiofs behaviour: that path gates on
# YSG_OS=macos inside compose_up; the chown here runs unconditionally but
# falls through gracefully when host-UID assertion is not required.
#
# Chown strategy: ephemeral `docker run --rm alpine chown` so the daemon's
# root privilege chowns inside the bind mount regardless of host caller UID.
# Plain `chown` is last-resort only (works only if installer is root).
# ---------------------------------------------------------------------------
_pki_run_issuer_docker() {
  local subcmd="$1"; local image="$2"; local manifest_in="$3"; local secrets_in="$4"
  shift 4

  # alpine:3 digest (amd64+arm64 manifest list — 2026-04-29; rotate each release):
  local _alpine_chown_digest="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

  # Docker: no :U support — chown the secrets dir + manifest to UID 1001 so
  # the issuer (USER yashigani = UID 1001) can write certs/keys into /secrets
  # and write back bootstrap_token_sha256 to the manifest.
  #
  # The previous approach — plain `chown 1001:1001 "$secrets_in" 2>/dev/null || true`
  # — silently no-ops when the installer runs as a non-root uid (e.g. 1004) that
  # lacks CAP_CHOWN on the host. The PKI container then starts with secrets_dir
  # still owned by the installer uid, gets EACCES, and aborts with PermissionError.
  #
  # Fix: use an ephemeral Docker container running as root (Docker daemon = root
  # internally, so it can chown inside the container regardless of host caller uid).
  # Same pattern as _pki_chown_client_keys() docker_run mode.
  _docker_chown_dir() {
    local _dir="$1" _target="$2"
    docker run --rm --pull=never \
           --volume "${_dir}:${_target}:rw" \
           "alpine:3" chown 1001:1001 "${_target}" 2>/dev/null && return 0
    docker run --rm \
           --volume "${_dir}:${_target}:rw" \
           "$_alpine_chown_digest" chown 1001:1001 "${_target}" 2>/dev/null && return 0
    chown 1001:1001 "$_dir" 2>/dev/null || true
  }
  _docker_chown_dir "${secrets_in}" /s

  # Retro #3ah (v2.23.1): the issuer also writes back to
  # service_identities.yaml (bootstrap_token_sha256 fields) via the
  # /manifest.yaml bind mount. Without ownership match the write fails
  # with PermissionError and the whole PKI bootstrap aborts.
  local _manifest_dir; _manifest_dir="$(dirname "$manifest_in")"
  local _manifest_base; _manifest_base="$(basename "$manifest_in")"
  _docker_chown_file() {
    local _dir="$1" _file="$2"
    docker run --rm --pull=never \
           --volume "${_dir}:/m:rw" \
           "alpine:3" chown 1001:1001 "/m/${_file}" 2>/dev/null && return 0
    docker run --rm \
           --volume "${_dir}:/m:rw" \
           "$_alpine_chown_digest" chown 1001:1001 "/m/${_file}" 2>/dev/null && return 0
    chown 1001:1001 "${_dir}/${_file}" 2>/dev/null || true
  }
  _docker_chown_file "${_manifest_dir}" "${_manifest_base}"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "docker run --rm --network=none -v ${secrets_in}:/secrets:rw,Z -v ${manifest_in}:/manifest.yaml:rw,Z $image python -m yashigani.pki.issuer --secrets-dir /secrets --manifest /manifest.yaml $subcmd $*"
    return 0
  fi

  # --network=none: issuer does no network I/O, and cutting the network
  # prevents any accidental telemetry exfil.
  docker run --rm --network=none \
    -v "${secrets_in}:/secrets:rw,Z" \
    -v "${manifest_in}:/manifest.yaml:rw,Z" \
    "$image" \
    python -m yashigani.pki.issuer \
      --secrets-dir /secrets \
      --manifest /manifest.yaml \
      "$subcmd" "$@"
}

# ---------------------------------------------------------------------------
# _pki_run_issuer_podman_linux — Linux Podman rootless/rootful issuer execution
#
# gate #ROOTLESS-9: ":U" MUST NOT be applied to the manifest file mount.
# ":U" calls lchown on the mount source. For directories this is recursive;
# for a single file it is still called. On Podman rootless, the lchown
# target UID (subuid-mapped 1001 = e.g. 428680) is outside the host
# user's UID (1005), so the kernel rejects lchown with EPERM even though
# the user owns the file and is namespace-root inside the container.
# The secrets dir is pre-chowned to the remapped UID by
# _prepare_secrets_dir_for_pki(), so it does not need :U; but keeping :U
# on secrets_dir is harmless and helps rootful Podman. The manifest is
# pre-chowned via podman unshare (rootless) or plain chown (rootful) so the
# container can write back bootstrap_token_sha256 fields. ":U" is NOT
# applied to the manifest mount on any path.
# ---------------------------------------------------------------------------
_pki_run_issuer_podman_linux() {
  local subcmd="$1"; local image="$2"; local manifest_in="$3"; local secrets_in="$4"
  shift 4

  # Manifest: pre-chown to container UID so the issuer can write back.
  # Use podman unshare for rootless (non-root caller); direct chown for rootful.
  if [[ "$(id -u)" != "0" ]]; then
    # Rootless: map container UID 1001 → host subuid-remapped UID via unshare.
    podman unshare chown 1001:1001 "$manifest_in" 2>/dev/null \
      || log_warn "Could not chown manifest via podman unshare — PKI may fail to write bootstrap_token_sha256"
  else
    # Rootful Podman: direct chown is safe.
    chown 1001:1001 "$manifest_in" 2>/dev/null || true
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "podman run --rm --network=none -v ${secrets_in}:/secrets:rw,Z,U -v ${manifest_in}:/manifest.yaml:rw,Z $image python -m yashigani.pki.issuer --secrets-dir /secrets --manifest /manifest.yaml $subcmd $*"
    return 0
  fi

  # --network=none: issuer does no network I/O, and cutting the network
  # prevents any accidental telemetry exfil.
  podman run --rm --network=none \
    -v "${secrets_in}:/secrets:rw,Z,U" \
    -v "${manifest_in}:/manifest.yaml:rw,Z" \
    "$image" \
    python -m yashigani.pki.issuer \
      --secrets-dir /secrets \
      --manifest /manifest.yaml \
      "$subcmd" "$@"
}

# ---------------------------------------------------------------------------
# _pki_run_issuer_podman_macos — macOS Podman applehv issuer execution (P-10)
#
# macOS Podman tunnels to an applehv VM. bind-mount semantics differ from
# Linux Podman: ":U" calls lchown through the remote socket into the VM, which
# can silently no-op for the manifest file (EPERM inside the namespace).
# ":Z" SELinux relabelling is also unsupported on the macOS host side.
#
# Strategy: `podman cp` — copy files into/out of a created-but-not-started
# container so the issuer runs in a known-clean filesystem state without
# relying on bind-mount permission propagation across the hypervisor boundary.
#
# Security mitigations (5/5 reviewer consensus, 2026-05-11):
#   Laura: realpath -s prefix check on both input paths before podman cp
#   Laura: container name from openssl rand (CSPRNG, not date-based)
#   Laura+Lu: atomic rename (cp-out to .new + mv -f) for manifest write-back
#   Lu: trap on RETURN for podman rm -f — set BEFORE podman create
#   Su: strict exit-0 gate before any cp-back (never cp back partial state)
#   Su: podman rm -f pre-create for name collision (silent, not fail-loud)
#   Su: DRY_RUN gate honouring existing dry_print pattern
#   Su: podman cp src container:/path (no trailing slash on in-copy)
#   Su: podman cp container:/path/. dest (trailing dot on out-copy)
#
# Discriminator: macOS + no /etc/subuid (per _pki_run_issuer dispatcher logic).
# Documentation: project_podman_parity_registry.md P-10.
# ---------------------------------------------------------------------------
_pki_run_issuer_podman_macos() {
  local subcmd="$1"; local image="$2"; local manifest_in="$3"; local secrets_in="$4"
  shift 4

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "podman cp [macOS applehv] | podman run (created) | podman cp back — $image python -m yashigani.pki.issuer --secrets-dir /secrets --manifest /manifest.yaml $subcmd $*"
    return 0
  fi

  # --- Laura mitigation: realpath prefix check ---
  # BSD realpath on macOS does not support -m (allow non-existent components),
  # but -s (no symlink resolution) is available on macOS 12+. We use -s to get
  # the lexical canonical path and assert it starts under WORK_DIR.
  local _canon_manifest _canon_secrets
  _canon_manifest="$(realpath -s "$manifest_in" 2>/dev/null || printf '%s' "$manifest_in")"
  _canon_secrets="$(realpath -s "$secrets_in" 2>/dev/null || printf '%s' "$secrets_in")"
  if [[ "$_canon_manifest" != "${WORK_DIR}"/* ]]; then
    log_error "_pki_run_issuer_podman_macos: manifest_in '${manifest_in}' resolves outside WORK_DIR '${WORK_DIR}' — aborting"
    return 1
  fi
  if [[ "$_canon_secrets" != "${WORK_DIR}"/* ]]; then
    log_error "_pki_run_issuer_podman_macos: secrets_in '${secrets_in}' resolves outside WORK_DIR '${WORK_DIR}' — aborting"
    return 1
  fi

  # --- Laura mitigation: CSPRNG container name ---
  local _cname
  _cname="ysg-pki-issuer-$(openssl rand -hex 8)"

  # --- Lu mitigation: trap on RETURN — set BEFORE podman create ---
  # Ensures cleanup even if podman create succeeds but a later step exits.
  # Use ${_created:-false} in the trap body to be safe under set -u: RETURN
  # traps fire in the calling scope where the local is gone, so the bare
  # reference would trigger "unbound variable". The :- default avoids that.
  local _created=false
  trap 'if [[ "${_created:-false}" == "true" ]]; then podman rm -f "${_cname:-}" >/dev/null 2>&1 || true; fi' RETURN

  # Pre-remove any stale container with the same name (name collision guard).
  # Silent, not fail-loud: if it doesn't exist, rm -f exits 1 which we ignore.
  podman rm -f "$_cname" >/dev/null 2>&1 || true

  # Create the container (no start) so we can populate it via podman cp.
  podman create \
    --name "$_cname" \
    --network=none \
    "$image" \
    python -m yashigani.pki.issuer \
      --secrets-dir /secrets \
      --manifest /manifest.yaml \
      "$subcmd" "$@" >/dev/null
  _created=true

  # Copy secrets dir into the container (no trailing slash = copy the dir itself,
  # placing it at /secrets inside the container).
  podman cp "${secrets_in}" "${_cname}:/secrets"

  # Copy the manifest file into the container root.
  podman cp "${manifest_in}" "${_cname}:/manifest.yaml"

  # Run the issuer. Strict exit-0 gate: if non-zero, cp-back is skipped and the
  # trap cleans up the container — no partial PKI state written to the host.
  local _rc=0
  podman start -a "$_cname" || _rc=$?

  if [[ "$_rc" -ne 0 ]]; then
    log_error "_pki_run_issuer_podman_macos: issuer exited ${_rc} — PKI state NOT written back"
    return "$_rc"
  fi

  # --- Laura+Lu mitigation: atomic rename for manifest write-back ---
  # Copy manifest to a staging file first; then mv -f for atomicity.
  # Matches _pki_persist_env() precedent at install.sh:5994.
  podman cp "${_cname}:/manifest.yaml" "${manifest_in}.new"
  mv -f "${manifest_in}.new" "${manifest_in}"

  # Copy secrets dir back to the host. Trailing dot (/secrets/.) copies the
  # CONTENTS of /secrets rather than creating a nested /secrets/secrets.
  podman cp "${_cname}:/secrets/." "${secrets_in}"

  # --- Host-side manifest hash update (macOS Podman applehv write-back guard) ---
  #
  # On macOS Podman (remote client to applehv VM) the container's write-back to
  # /manifest.yaml is confirmed by the issuer log but the podman cp above copies
  # the container's manifest to .new; in practice the .new file may carry the
  # original (pre-bootstrap) content if the VM's copy-on-write layer for the
  # manually-managed container fs is not fully flushed before podman cp reads it.
  #
  # Regardless of whether the cp-back carried the updated manifest, we now have
  # all *_bootstrap_token files on the HOST (copied above via podman cp /secrets/.).
  # Re-derive the SHA-256 of each token from the host copies and patch
  # service_identities.yaml directly — this is authoritative and doesn't depend
  # on the container's manifest write-back landing correctly.
  #
  # Logic mirrors _update_manifest_hashes() in src/yashigani/pki/issuer.py:
  #   - Walk each "- name: <svc>" block in service_identities.yaml.
  #   - If <svc>_bootstrap_token exists in secrets_in, compute its SHA-256.
  #   - Replace the bootstrap_token_sha256 line for that service.
  #
  # Uses a Python one-liner (Python 3 is guaranteed on macOS 12+) so we don't
  # need to replicate the YAML-aware line-walk in bash.
  _pki_macos_update_manifest_hashes() {
    local _mf="$1" _sec="$2"
    python3 - "$_mf" "$_sec" <<'PYEOF'
import sys, hashlib, pathlib, os

manifest_path = pathlib.Path(sys.argv[1])
secrets_dir   = pathlib.Path(sys.argv[2])

text  = manifest_path.read_text()
lines = text.splitlines(keepends=True)
out   = []
current_service = None
for line in lines:
    stripped = line.strip()
    if stripped.startswith("- name:"):
        current_service = stripped.split(":", 1)[1].strip().strip("'\"")
    if stripped.startswith("bootstrap_token_sha256:") and current_service:
        tok = secrets_dir / f"{current_service}_bootstrap_token"
        if tok.exists():
            h = hashlib.sha256(tok.read_bytes().strip()).hexdigest()
            prefix = line[: len(line) - len(line.lstrip())]
            line = f'{prefix}bootstrap_token_sha256: "{h}"\n'
    out.append(line)

new_text = "".join(out)
# Atomic write (same pattern as _pki_persist_env)
tmp = manifest_path.with_suffix(".yaml.new_hashes")
tmp.write_text(new_text)
tmp.replace(manifest_path)
print(f"pki-macos-hash-update: manifest patched for {secrets_dir}", file=sys.stderr)
PYEOF
  }

  if ! _pki_macos_update_manifest_hashes "${manifest_in}" "${secrets_in}"; then
    log_warn "_pki_run_issuer_podman_macos: host-side hash update failed — bootstrap_token_sha256 in manifest may be stale"
  fi

  # Trap fires on RETURN and removes the container.
}

# ---------------------------------------------------------------------------
# _pki_run_issuer — dispatcher (shared preamble + per-runtime dispatch)
#
# Shared preamble: image lookup, path validation, mkdir.
# Per-runtime dispatch: docker | podman_linux | podman_macos.
# Discriminator for macOS Podman: uname == Darwin AND no /etc/subuid.
# (macOS hosts running Podman remote client have no subuid allocation;
# Linux Podman rootless hosts always have an /etc/subuid entry.)
# ---------------------------------------------------------------------------
_pki_run_issuer() {
  # Usage: _pki_run_issuer <subcommand> [extra args...]
  local subcmd="$1"; shift
  local runtime; runtime="$(_pki_runtime_cmd)"
  # Pick the first existing local image tag. install.sh --upgrade paths
  # that skip compose build may leave :latest as the only built tag, so
  # falling back to it is safer than forcing a pull of :${VERSION} that
  # doesn't exist on a remote registry (yashigani/gateway isn't public).
  # Use `image inspect` rather than `image exists` — the latter is a
  # Podman-only subcommand (Docker errors with "unknown command").
  # `image inspect IMAGE` is portable across docker/podman and returns 0
  # when the image is present locally.
  local image=""
  for tag in "${YASHIGANI_VERSION}" "latest"; do
    if "$runtime" image inspect "yashigani/gateway:${tag}" >/dev/null 2>&1 \
       || "$runtime" image inspect "localhost/yashigani/gateway:${tag}" >/dev/null 2>&1; then
      image="yashigani/gateway:${tag}"
      break
    fi
  done
  if [[ -z "$image" ]]; then
    log_error "_pki_run_issuer: no local yashigani/gateway image found — compose build must run first"
    return 1
  fi
  # Canonical manifest: docker/service_identities.yaml (git-tracked, schema-only,
  # all bootstrap_token_sha256 fields are empty placeholders).
  local _canonical_manifest="${WORK_DIR}/docker/service_identities.yaml"

  # Runtime manifest: docker/var/runtime/service_identities.yaml (gitignored).
  # The PKI issuer writes per-install bootstrap_token_sha256 hashes here, not
  # into the tracked canonical file. Compose bind-mounts this runtime copy into
  # each Python service at /etc/yashigani/service_identities.yaml.
  local manifest_in="${WORK_DIR}/docker/var/runtime/service_identities.yaml"
  local secrets_in="${WORK_DIR}/docker/secrets"

  mkdir -p "$secrets_in"
  if [[ ! -f "$_canonical_manifest" ]]; then
    log_error "service_identities.yaml missing at ${_canonical_manifest} — re-clone the repo."
    return 1
  fi

  # Create the runtime directory and seed the runtime manifest from the canonical.
  # mkdir -p is idempotent — safe to re-run on upgrade.
  mkdir -p "${WORK_DIR}/docker/var/runtime"
  cp -f "$_canonical_manifest" "$manifest_in" \
    || { log_error "_pki_run_issuer: failed to copy canonical manifest to runtime path ${manifest_in}"; return 1; }
  log_info "_pki_run_issuer: seeded runtime manifest at ${manifest_in} (hash-back will populate bootstrap_token_sha256 values)"

  case "$runtime" in
    docker)
      _pki_run_issuer_docker "$subcmd" "$image" "$manifest_in" "$secrets_in" "$@"
      ;;
    podman)
      # Discriminator: macOS Podman remote client vs Linux Podman local.
      # macOS applehv VM callers have no /etc/subuid on the Mac side;
      # Linux rootless callers always have an /etc/subuid entry.
      if [[ "$(uname -s)" == "Darwin" ]] && [[ ! -f /etc/subuid ]]; then
        _pki_run_issuer_podman_macos "$subcmd" "$image" "$manifest_in" "$secrets_in" "$@"
      else
        _pki_run_issuer_podman_linux "$subcmd" "$image" "$manifest_in" "$secrets_in" "$@"
      fi
      ;;
    *)
      log_error "_pki_run_issuer: unknown runtime '${runtime}'"
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# _pki_chown_client_keys — re-own each service's private key to the UID of
# the consuming container, and chmod all certificate files to 0644.
# Called on both fresh install and skip paths so keys and certs are always
# accessible even when PKI bootstrap is skipped (certs already present).
#
# Retro v2.23.1 root cause: pgbouncer (UID 70) crashed because keys were
# owned by UID 1001 from the issuer image and chown was never called on
# the skip path.
# Retro v2.23.1 RC-6: pgbouncer_client.crt was 0600 owned by UID 1001 —
# pgbouncer runs as UID 70 and could not read it. Fix: chmod 0644 all
# *_client.crt and ca_*.crt files. Certificates are public material
# (distributed to peers for verification) and require no secrecy; 0644 is
# correct. Private keys remain 0600, chowned to the container's UID.
#
# fix #58a-chown (2026-04-29): bifurcate chown strategy by YSG_RUNTIME.
# fix #58a-podman-remote (2026-04-29): detect Podman remote-client mode
#   (macOS Podman tunnels to a VM; `podman unshare` is unsupported on the
#   remote client). Detected via `podman info --format '{{.Host.RemoteSocket.Exists}}'`.
#   Remote callers use podman_run mode (ephemeral `podman run --rm`) rather
#   than `podman unshare`. This simplifies the matrix:
#     docker            → docker_run  (docker run --rm alpine chown)
#     podman remote     → podman_run  (podman run --rm alpine chown)
#     podman local root → direct      (plain chown)
#     podman local non-root → unshare (podman unshare chown)
#
#   Previous bug: _chown_mode was set to "unshare" purely on `id -u != 0`.
#   When YSG_RUNTIME=docker AND Podman is also installed AND the caller is
#   non-root, `podman unshare chown` maps service UIDs (e.g. 70) through
#   Podman's /etc/subuid range (typically 165536+70 = 165605). Docker
#   containers run their service as the bare UID (70), so the host file at
#   165605 is inaccessible → TLS key read fails → pgbouncer/postgres/redis
#   crash at startup → full stack cascades. (Pentest EX-231-10 AUDIT-NEEDED.)
#
#   Correct per-runtime strategy:
#     k8s    → skip entirely; mtls-bootstrap-job.yaml handles ownership.
#     podman + root    → direct chown (root can chown to any UID).
#     podman + non-root → podman unshare chown (correct namespace mapping).
#     docker (root or non-root) → docker run --rm with alpine:3 image;
#       the Docker daemon runs as root and can chown inside the container to
#       any UID. This works for both root and non-root callers.
#       Image pinned to digest to prevent supply-chain substitution.
#       alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
#       (amd64/arm64 manifest list — 2026-04-29; rotate on next release cycle)
#
#   Error discipline (SOP 1 fail-closed): any chown failure is log_error +
#   return 1. The previous log_warn + continue masked a 6-day live bug.
#
# Last updated: 2026-04-29T22:05:15+01:00
# ---------------------------------------------------------------------------
_pki_chown_client_keys() {
  local _effective_runtime="${YSG_RUNTIME:-}"
  # Normalise: YSG_PODMAN_RUNTIME=true overrides YSG_RUNTIME for legacy callers.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  # K8s: ownership is handled by mtls-bootstrap-job.yaml initContainer.
  # Nothing to do here — skip silently.
  if [[ "$_effective_runtime" == "k8s" ]]; then
    log_info "_pki_chown_client_keys: K8s runtime — skipping (mtls-bootstrap-job owns this step)"
    return 0
  fi

  # Only act for docker and podman runtimes.
  if [[ "$_effective_runtime" != "podman" && "$_effective_runtime" != "docker" ]]; then
    log_info "_pki_chown_client_keys: unknown runtime '${_effective_runtime}' — skipping"
    return 0
  fi

  # Service→UID map sourced from lib/pki_ownership.sh (single source of truth).
  # GATE5-BUG-01 / maintainer directive 2026-05-10: adding a new service updates
  # lib/pki_ownership.sh only; install.sh + restore.sh inherit automatically.

  # Determine chown strategy for this runtime.
  # "direct"      — plain chown(1); Podman local root caller.
  # "unshare"     — podman unshare chown; maps UIDs through the user-namespace
  #                 for the rootless Podman LOCAL caller. MUST NOT be used on
  #                 the Docker path or on Podman remote (macOS client).
  # "docker_run"  — ephemeral docker run --rm; mounts the secrets dir, runs
  #                 chown inside the container where Docker daemon provides
  #                 root privs. Works regardless of host caller UID.
  # "podman_run"  — ephemeral podman run --rm; same approach for Podman remote
  #                 (macOS tunnels to VM). `podman unshare` is NOT supported on
  #                 the remote client — this is the correct fallback.
  local _chown_mode
  if [[ "$_effective_runtime" == "docker" ]]; then
    _chown_mode="docker_run"
  elif [[ "$_effective_runtime" == "podman" ]]; then
    # Detect Podman remote-client (macOS Podman tunnels to a VM).
    # `podman unshare` is unsupported on the remote client; use podman_run.
    #
    # Detection strategy (retro N1-HARNESS-001, 2026-05-02):
    # `podman info --format '{{.Host.RemoteSocket.Exists}}'` returns true even
    # when running as the local Podman host user via an SSH session, because a
    # UNIX socket path exists on the host.  This caused Linux-local installs to
    # take the podman_run path, which then failed when the alpine pull image was
    # unavailable (Docker Hub rate limit) and soft-warned instead of chowning.
    #
    # gate #ROOTLESS-7 (2026-05-02): `podman unshare echo "unshare_probe"` was
    # the previous probe but it touches Podman's container storage briefly.
    # When called immediately after _pki_run_issuer releases the storage lock,
    # there is a transient window where the probe returns non-zero, causing
    # the install to fall through to podman_run mode. In podman_run mode the
    # ephemeral alpine container volume mount fails because secrets_dir was
    # chowned to a subuid-range UID (363144) that podman run cannot access from
    # the rootless installer, so chown is silently skipped and pgbouncer (UID 70)
    # cannot read its key → pgbouncer crash-loops → podman-compose waits forever.
    #
    # Fix: replace the live podman probe with a static /etc/subuid check.
    # If the current user has a subuid allocation ≥ 65536 entries, podman unshare
    # is supported and we are the local rootless caller. This is a kernel-level
    # capability check, not a runtime lock check, so it is immune to transient
    # storage contention. macOS remote callers do not have /etc/subuid entries on
    # the Mac side (they run via the Podman VM), so they fall through to podman_run.
    if [[ "$(id -u)" == "0" ]]; then
      _chown_mode="direct"
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      # User has a subuid allocation ≥ 65536 → local rootless Podman; use unshare.
      # Note: /etc/subuid uses username (not numeric UID) in field 1; id -un gets
      # the username. Some distros also accept numeric UIDs in /etc/subuid; we
      # check by username first which covers the common Debian/Ubuntu layout.
      _chown_mode="unshare"
    else
      # No /etc/subuid entry for this user (macOS client, restricted env).
      _chown_mode="podman_run"
    fi
  fi

  log_info "Chown'ing client keys to container UIDs (runtime: ${_effective_runtime}, mode: ${_chown_mode})"

  # Alpine:3 image pinned to digest (manifest list — covers amd64+arm64).
  # digest captured 2026-04-29; rotate on next release cycle via:
  #   docker pull alpine:3 && docker inspect alpine:3 --format='{{index .RepoDigests 0}}'
  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # _do_chmod_dir — hoisted to top-level scope (V240-002).
  # See the top-level _do_chmod_dir() definition (above generate_secrets()) for
  # the full implementation with local dispatch recomputation (S1) and the
  # CHM-001 allowlist guard (S3). The nested definition was removed to close
  # BACKLOG-V240-002 (Iris AMENDED design, iris-v240-002-do-chown-refactor.md).
  # IRIS-DESIGN-004 / LAURA-TM-CHMOD-001 CHM-001 / Laura S1+S3.
  # The top-level _do_chmod_dir() is called directly below.

  # V232-SMOKE-012 fix: ensure the secrets directory is mode 0755 (rwxr-xr-x)
  # so ALL container UIDs (including OPA=1000, otel-collector=10001, etc.) can
  # both traverse AND read-list the directory. OPA's inotify TLS cert watcher
  # requires read on the directory; 0751 (others --x) prevents it → OPA unhealthy.
  # restore.sh previously set 0751; install.sh did not enforce a canonical mode.
  # This call normalises it regardless of what set it previously.
  # IRIS-DESIGN-004: replaced broken inline if/else block (which ignored _chown_mode
  # and fell through to host-direct chmod, causing EPERM for Docker non-root callers).
  _do_chmod_dir "${_secrets_dir}" 755 || return 1

  # _do_chown — hoisted to top-level scope (V240-002).
  # See the top-level _do_chown() definition (above generate_secrets()) for the
  # full implementation with S1 local dispatch recomputation, S4 _mount_base,
  # S5 unshare/docker_run fallback binding, S6 uid integer guard, S7 /s convention.
  # The nested definition was removed to close BACKLOG-V240-002.
  # iris-v240-002-do-chown-refactor.md / laura-v240-002-do-chown-threat-model.md

  # _do_chgrp — hoisted to top-level scope (defined before generate_secrets).
  # See the top-level _do_chgrp() definition above generate_secrets() for the
  # full implementation. That version computes _chown_mode/_alpine_image/_secrets_dir
  # locally using the same logic as this function, so it is fully equivalent here.
  # The nested definition was removed to fix the bash scoping bug: nested functions
  # are only registered when the outer function executes, but generate_secrets()
  # calls _do_chgrp at step 6/13 before _pki_chown_client_keys runs (step 7+).
  # (Ava blocker: install.sh line 5786 "_do_chgrp: command not found" — 8dd4c41.)

  # _do_chmod_0640 — hoisted to top-level scope (V240-002).
  # See the top-level _do_chmod_0640() definition (above generate_secrets()) for
  # the full implementation with S1 local dispatch recomputation and S2 hard-coded
  # 0640 mode invariant. The nested definition was removed to close BACKLOG-V240-002.
  # iris-v240-002-do-chown-refactor.md / laura-v240-002-do-chown-threat-model.md

  # Iterate all services from the shared map (lib/pki_ownership.sh).
  # pki_service_uid + pki_key_mode replace the inline array and the prometheus
  # special-case. Adding a new service updates lib/pki_ownership.sh only.
  # GATE5-BUG-01 / maintainer directive 2026-05-10.
  local _svc _uid _mode _keyfile
  while IFS= read -r _svc; do
    _uid="$(pki_service_uid "$_svc")"
    _mode="$(pki_key_mode "$_svc")"
    _keyfile="${_secrets_dir}/${_svc}_client.key"
    if [[ -f "$_keyfile" ]]; then
      # #3d-fix: mode from shared map (0600 default, 0640 for prometheus).
      # chmod runs inside the container alongside chown so a non-root installer
      # (e.g. uid 1003) doesn't get EPERM trying to chmod a file it no longer owns.
      _do_chown "${_uid}" "$_keyfile" "${_svc}_client.key" "${_mode}" || return 1
    fi
  done < <(pki_services_all)

  # Chmod all certificate files to 0644. Certs are public material and must
  # be readable by every container that verifies peer identity (pgbouncer,
  # gateway, backoffice, postgres, redis, etc.). Keys are owned+chmod'd above.
  # This find+chmod is runtime-agnostic — it runs as the host caller and only
  # changes mode bits (not ownership), so it works for both root and non-root.
  log_info "Chmod'ing client certs + CA certs to 0644 (public material)"
  find "${_secrets_dir}" -maxdepth 1 -type f \
    \( -name '*_client.crt' -o -name 'ca_*.crt' \) \
    -exec chmod 0644 {} \; 2>/dev/null || true

  # gate #ROOTLESS-11: password files, bootstrap tokens, and HMAC secret are
  # written by generate_secrets() as the installer user (e.g. UID 1005 on Podman
  # rootless, UID 0 on Docker root installs). They are mode 0600 (owner-read-only).
  # Containers running as UID 1001 (gateway, backoffice) cannot read their own
  # Redis password, Postgres password, admin credentials, or bootstrap token
  # without an explicit chown to 1001.
  #
  # _pki_chown_client_keys previously only re-owned *_client.key files; all other
  # secrets remained owned by the installer user and were unreadable by UID 1001
  # containers. This caused Redis AuthenticationError (gateway falls back to empty
  # password → connect rejected) and backoffice PermissionError on admin_initial_password.
  #
  # Fix: enumerate all "container-consumed" secret files and chown to 1001:1001.
  # Files NOT listed here (admin1/2_password, admin1/2_totp_secret) are also read
  # by the backoffice (to bootstrap TOTP) — they are included in the list below.
  # This is correct: the admin password files are "installer-display-only" on the
  # host side; ownership by UID 1001 does not weaken them (mode stays 0600).
  # YSG-SECRETS-DIST-002 CLOSED (v2.24.0 — Laura A1 amendment):
  # postgres_password, redis_password, and yashigani_internal_bearer are no longer
  # chowned to UID 1001 then widened to GID 2002. Each file is now set to a single
  # per-consumer owner at 0600/0640 further below. gateway + backoffice receive all
  # three via .env env var — no file read — so removing them from the 1001 list is
  # correct (they were never file-readers for these three secrets).
  log_info "Chown'ing password files + bootstrap tokens + HMAC to UID 1001 (gate #ROOTLESS-11)"
  local _uid1001_secrets=(
    license_key
    admin_initial_password
    admin1_password
    admin1_username
    admin1_totp_secret
    admin2_password
    admin2_username
    admin2_totp_secret
    grafana_admin_password
    caddy_internal_hmac
    openclaw_gateway_token
    # wazuh passwords are read by the wazuh containers (run as root inside docker),
    # not by the UID 1001 services. Chowning them to 1001 is harmless: root (UID 0)
    # inside the wazuh containers can still read them; the mode stays 0600.
    wazuh_indexer_password
    wazuh_api_password
    wazuh_dashboard_password
  )
  for _sf in "${_uid1001_secrets[@]}"; do
    local _sfpath="${_secrets_dir}/${_sf}"
    if [[ -f "$_sfpath" ]]; then
      _do_chown "1001" "$_sfpath" "$_sf" || return 1
    fi
  done

  # Per-consumer secret ownership — YSG-SECRETS-DIST-002 CLOSED (Laura A1 amendment).
  #
  # Each of the three shared secrets is now chowned to a single consumer UID at mode
  # 0600 (or 0640 for the bearer, which has a second consumer via GID 2002). This
  # replaces the old blanket chgrp 2002 + chmod 0640 applied to all three files.
  #
  # Why the old approach was wrong (Laura B1 BLOCKER):
  #   cap_drop:[ALL] removes CAP_DAC_OVERRIDE. Root inside a cap_drop:[ALL] container
  #   cannot read a file it does not own by UID. The old "chown 1001:1001 then chgrp 2002
  #   0640" model gave postgres/redis (UID 999) group-read access but set owner UID to
  #   1001, not 999. Under cap_drop:[ALL], UID 999 cannot read a 1001-owned file without
  #   DAC_OVERRIDE — so the group bit was the only read path, and GID 2002 on all six
  #   consumers meant any compromised container could read all three secrets.
  #   Ref: compose lines 588–590 (budget-redis DAC_OVERRIDE note).
  #
  # Fix — per-consumer GID-based ownership (rework v2 — Ava E2E gate FAIL on 999:999 0600):
  #
  #   postgres_password   → 1001:999 0640
  #     backoffice + gateway (UID 1001): FILE-READ as owner (primary path in entrypoint.py:334
  #     and gateway/entrypoint.py:215). postgres (UID 999, GID 999): reads as group (startup
  #     via POSTGRES_PASSWORD_FILE env). Rotator (UID 1001) writes atomically via
  #     tmp+chmod(0o640)+os.chown(-1,999)+rename — Tom scope, A2 amendment.
  #
  #   redis_password      → 1001:999 0640
  #     backoffice + gateway (UID 1001): FILE-READ as owner (primary path in entrypoint.py:78
  #     and gateway/_redis_url.py:81). redis + budget-redis (UID 999, GID 999): read as group
  #     (startup cmd). Rotator (UID 1001) writes atomically — Tom scope, A2 amendment.
  #
  #   yashigani_internal_bearer → 0:2002 0640  (UNCHANGED)
  #     open-webui (UID 0) + letta (UID 0): read as owner.
  #     langflow (UID 1000): reads via group GID 2002 (group_add:["2002"] — Captain scope).
  #     gateway + backoffice: ENV-ONLY (os.environ — no file DAC needed).
  #
  # The prior 999:999 0600 scheme caused PermissionError on gateway + backoffice at
  # startup (UID 1001, cap_drop:[ALL], no DAC_OVERRIDE): file-read failed; OSError
  # fallback read empty env var; gateway crash-looped on Redis auth failure.
  # Ava gate FAIL recorded at tip a3cf4a3. RCA in iris-v240-ysg-secrets-dist-002-rework-design.md.
  #
  # Cross-secret reachability (GID 999 shared by redis + postgres): non-issue because
  # per-file mounts mean each service sees only its own secret — Laura §5 GO verdict.
  #
  # Upgrade path: _pki_chown_client_keys() is re-run by install.sh upgrade path.
  # Files at old 999:999 0600 (tip a3cf4a3) are rechowned to 1001:999 0640 here.
  #
  # Iris rework design: iris-v240-ysg-secrets-dist-002-rework-design.md
  # Laura GO-with-amendments: laura-v240-ysg-secrets-dist-002-rework-threat-model.md
  local _pp_path="${_secrets_dir}/postgres_password"
  local _rp_path="${_secrets_dir}/redis_password"
  local _ib_path="${_secrets_dir}/yashigani_internal_bearer"
  local _pgba_path="${_secrets_dir}/pgbouncer_authenticator_password"
  if [[ -f "$_pp_path" ]]; then
    _do_chown "1001:999" "$_pp_path" "postgres_password" || return 1
    _do_chmod_0640 "$_pp_path" "postgres_password" || return 1
  fi
  if [[ -f "$_rp_path" ]]; then
    _do_chown "1001:999" "$_rp_path" "redis_password" || return 1
    _do_chmod_0640 "$_rp_path" "redis_password" || return 1
  fi
  if [[ -f "$_ib_path" ]]; then
    _do_chown "0:2002" "$_ib_path" "yashigani_internal_bearer" || return 1
    _do_chmod_0640 "$_ib_path" "yashigani_internal_bearer" || return 1
  fi
  # pgbouncer_authenticator_password — re-chown to 70:999 0640 AFTER the PKI issuer's
  # :U mount-remap clobbers it. The issuer container runs as USER yashigani (UID 1001)
  # with -v secrets:/secrets:rw,Z,U which recursively remaps ownership to 1001. The
  # generate_secrets() call at L5981/L6226 sets 70:999 correctly, but the issuer's
  # :U remap (which runs later, during PKI bootstrapping) overwrites it to 1001:1001.
  # This block is the post-:U recovery point — same role as postgres_password and
  # redis_password re-chowns above.
  #
  # pgbouncer (UID 70) reads as owner; postgres (UID 999, GID 999) reads as group at
  # init time via 10-pgbouncer-auth.sh.
  #
  # NOT added to _uid1001_secrets array — that would chown to 1001 not 70.
  # NOT added to *_bootstrap_token find-glob — name does not match the pattern.
  # Compose mount is :ro (no :U) — runtime does not remap, post-install chown sticks.
  # Cross-ref: install.sh L5981/L6226 (initial ownership, pre-PKI-issuer);
  # feedback_brief_cue_adjacent_abstractions.md (:U mount-remap clobbers pattern).
  if [[ -f "$_pgba_path" ]]; then
    _do_chown "70:999" "$_pgba_path" "pgbouncer_authenticator_password" || return 1
    _do_chmod_0640 "$_pgba_path" "pgbouncer_authenticator_password" || return 1
  fi
  log_info "Per-consumer ownership set: postgres_password+redis_password → 1001:999 0640; yashigani_internal_bearer → 0:2002 0640; pgbouncer_authenticator_password → 70:999 0640 (YSG-SECRETS-DIST-002 REWORK + Bug #8 fix — Iris rework + Laura A1)"

  # Chown all *_bootstrap_token files to UID 1001. Each service reads its own
  # bootstrap token at startup to verify identity; all services run as UID 1001
  # (or, for root-inside-container services like caddy/redis, as UID 0 which
  # can always read the file after the chown).
  log_info "Chown'ing *_bootstrap_token files to UID 1001"
  while IFS= read -r -d '' _btoken; do
    _do_chown "1001" "$_btoken" "$(basename "$_btoken")" || return 1
  done < <(find "${_secrets_dir}" -maxdepth 1 -name '*_bootstrap_token' -print0 2>/dev/null)

  # BUG-WAVE1-P1-002: agent bundle token files — chown to installer-UID:1001 0640.
  #
  # WHY this is needed: the PKI issuer container runs with -v secrets:/secrets:rw,Z,U
  # (Linux Podman rootless) or via docker run --rm alpine chown 1001:1001 (Docker).
  # Both paths remap the ENTIRE secrets dir, clobbering the token placeholder
  # ownership set at step 8d (installer UID, e.g. 1000:1000 0600). After remap,
  # token files land at subuid_base+1001 (Podman) or 1001:1001 (Docker).
  #
  # Ownership goal: host installer (installer_uid) can overwrite the placeholder
  # with the real token during register_agent_bundles(); gateway container (UID 1001)
  # can read the file at runtime.
  #
  # Pattern: installer_uid:1001 0640 — mirrors 1001:999 0640 for postgres_password.
  #   installer_uid = $(id -u) at function call time (same UID that ran install.sh).
  #   GID 1001 = gateway container primary group; gateway reads as group at runtime.
  #
  # Gating: only chown when the file exists (profile not selected → no file).
  # Three agent-bundle token files (langflow, letta, openclaw).
  #
  # Cross-ref: register_agent_bundles() chmod 0640 change (BUG-WAVE1-P1-002 part B)
  # ensures the mode stays 0640 after the host-side write at line 5356.
  local _installer_uid
  _installer_uid="$(id -u)"
  log_info "Chown'ing agent bundle token files to ${_installer_uid}:1001 0640 (BUG-WAVE1-P1-002)"
  local _agent_token_files=(langflow_token letta_token openclaw_token)
  for _atf in "${_agent_token_files[@]}"; do
    local _atpath="${_secrets_dir}/${_atf}"
    if [[ -f "$_atpath" ]]; then
      _do_chown "${_installer_uid}:1001" "$_atpath" "$_atf" || return 1
      _do_chmod_0640 "$_atpath" "$_atf" || return 1
    fi
  done
}

# ---------------------------------------------------------------------------
# _pki_detect_uri_san_drift — compare URI SANs on existing leaf certs against
# docker/service_identities.yaml. Detects certs minted before the manifest's
# spiffe_id for a service existed (or where the spiffe_id was changed since
# mint). A drift triggers a forced leaf rotation regardless of time-based
# renewal status.
#
# Motivation: v2.23.1 retro #82. Pre-EX-231-08 certs (Apr-22) carry no URI
# SAN, so Caddy's X-SPIFFE-ID header is empty and the SPIFFE gate at
# /internal/metrics returns 401 even though the mTLS handshake passes.
# Time-based status check alone does NOT catch this — those certs are still
# within their validity window.
#
# Return: 0 if every leaf's URI SAN matches the manifest's spiffe_id.
#         1 if any leaf is missing, has no URI SAN, or the URI SAN disagrees
#         with the manifest.
# Prints one line per service.
# Last updated: 2026-04-24T13:45:00+01:00
# ---------------------------------------------------------------------------
_pki_detect_uri_san_drift() {
  local manifest="${WORK_DIR}/docker/service_identities.yaml"
  local secrets_dir="${WORK_DIR}/docker/secrets"

  if [[ ! -f "$manifest" ]]; then
    log_warn "service_identities.yaml missing at ${manifest} — skipping URI SAN drift check"
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    log_warn "openssl not on PATH — skipping URI SAN drift check"
    return 0
  fi

  # Parse manifest into "<name>|<spiffe_id>" pairs. awk walks the list-of-maps
  # and emits the spiffe_id encountered within each "- name:" block. Tolerant
  # to comment lines, blank lines, and quoted values.
  local pairs
  pairs=$(awk '
    /^[[:space:]]*-[[:space:]]+name:[[:space:]]+/ {
      if (name != "" && sid != "") print name "|" sid
      sub(/^[[:space:]]*-[[:space:]]+name:[[:space:]]+/, "")
      gsub(/[[:space:]"'\'']/, "")
      name = $0
      sid = ""
      next
    }
    /^[[:space:]]+spiffe_id:[[:space:]]+/ {
      if (name == "") next
      sub(/^[[:space:]]+spiffe_id:[[:space:]]+/, "")
      gsub(/[[:space:]"'\'']/, "")
      sid = $0
    }
    END {
      if (name != "" && sid != "") print name "|" sid
    }
  ' "$manifest")

  if [[ -z "$pairs" ]]; then
    log_warn "No (name, spiffe_id) pairs parsed from manifest — skipping drift check"
    return 0
  fi

  local drift=0
  local svc expected crt san_block got
  while IFS='|' read -r svc expected; do
    [[ -z "$svc" || -z "$expected" ]] && continue
    crt="${secrets_dir}/${svc}_client.crt"
    if [[ ! -f "$crt" ]]; then
      log_warn "  ${svc}: leaf cert missing (${crt}) — treating as drift"
      drift=1
      continue
    fi
    # openssl -text emits SANs on the line immediately following
    # "X509v3 Subject Alternative Name:" — split on commas, keep URI entries.
    san_block=$(openssl x509 -in "$crt" -noout -text 2>/dev/null \
                | awk '/X509v3 Subject Alternative Name/{getline; print; exit}')
    got=$(printf '%s' "$san_block" | tr ',' '\n' \
          | sed -n 's/^[[:space:]]*URI:[[:space:]]*//p' \
          | head -1)
    if [[ -z "$got" ]]; then
      log_warn "  ${svc}: no URI SAN on leaf — expected ${expected}"
      drift=1
    elif [[ "$got" != "$expected" ]]; then
      log_warn "  ${svc}: URI SAN mismatch — got ${got}, expected ${expected}"
      drift=1
    else
      log_info "  ${svc}: URI SAN OK (${got})"
    fi
  done <<< "$pairs"

  return $drift
}

# _prepare_secrets_dir_for_pki() — chown secrets_dir so the PKI issuer container
# can write certs into it. For Podman rootless this is deferred from generate_secrets()
# to here, because the installer needs to write files into secrets_dir during
# generate_secrets() and can only do so while it still owns the directory.
# gate #ROOTLESS-3 fix (v2.23.1).
_prepare_secrets_dir_for_pki() {
  local secrets_dir="${WORK_DIR}/docker/secrets"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    if [[ "$(id -u)" == "0" ]]; then
      # Rootful Podman running as root — plain chown works
      chown 1001:1001 "$secrets_dir" 2>/dev/null || true
      log_info "secrets_dir chown 1001:1001 applied (rootful)"
    else
      # Rootless Podman — use podman unshare to map through the user namespace
      if podman unshare chown 1001:1001 "$secrets_dir" 2>/dev/null; then
        log_info "secrets_dir chown 1001:1001 applied via podman unshare (rootless)"
      else
        log_warn "Could not chown ${secrets_dir} via podman unshare — PKI issuer and all service containers use :U remapping (podman-override.yml); ownership is consistent across the stack"
      fi
    fi
  fi
  # Docker / non-Podman path: chown was already applied in generate_secrets().
}

# ---------------------------------------------------------------------------
# _chown_agent_volumes — set correct ownership on named volumes for Bucket-C
# agent containers BEFORE compose_up starts them.
#
# Problem (BLOCKER-LF-001 / ASVS V14.1.1 / CWE-272):
#   Docker creates named volumes owned by root (0:0) on first reference.
#   langflow runs as uid=1000 (USER langflow in langflowai/langflow Dockerfile)
#   and writes its SQLite DB + config to /app/langflow (langflow_data volume).
#   With root-owned volume, langflow gets EACCES on first write → crash-loop.
#
#   letta runs as uid=0 inside the container and writes to /root/.letta
#   (letta_data volume). Root can always write to a root-owned volume — no fix
#   needed for letta_data.
#
# Fix: chown docker_langflow_data to uid=1000 using an ephemeral container (mirrors
# _pki_chown_client_keys docker_run mode). Idempotent — safe to re-run.
# Called between bootstrap_internal_pki and compose_up (step 9b→10).
#
# K8s: Helm agent-bundles.yaml uses podSecurityContext.fsGroup (set per-bundle
# via values.yaml) — kubelet applies ownership at mount time. Skip here.
#
# Alpine digest reuse: same image as _pki_chown_client_keys — avoid pulling a
# different image tag; digests locked together for supply-chain consistency.
# ---------------------------------------------------------------------------
_chown_agent_volumes() {
  local _effective_runtime="${YSG_RUNTIME:-}"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _effective_runtime="podman"
  fi

  # K8s: Helm agent-bundles.yaml sets podSecurityContext.fsGroup per bundle via
  # values.yaml — the kubelet applies volume ownership at mount time. No host-side
  # chown needed.
  if [[ "$_effective_runtime" == "k8s" ]]; then
    log_info "_chown_agent_volumes: K8s runtime — skipping (Helm podSecurityContext.fsGroup handles volume ownership)"
    return 0
  fi

  # Only act for docker and podman runtimes.
  if [[ "$_effective_runtime" != "podman" && "$_effective_runtime" != "docker" ]]; then
    log_info "_chown_agent_volumes: unknown runtime '${_effective_runtime}' — skipping"
    return 0
  fi

  # Same digest as _pki_chown_client_keys — pinned to prevent supply-chain substitution.
  # alpine:3 (amd64/arm64 manifest list, 2026-04-29). Rotate on next release cycle.
  local _alpine_image="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

  log_info "Chown'ing agent named volumes to container UIDs (runtime: ${_effective_runtime})"

  # Docker Compose prefixes named volumes with the project name derived from the
  # directory containing the compose file. Our compose file lives under docker/,
  # so the project name is "docker" → volumes are docker_langflow_data, etc.
  # This matches the _project_prefix convention in _check_contaminated_volumes.
  local _compose_project_prefix="docker"

  # langflow_data → uid=1000 (langflowai/langflow USER langflow = UID 1000)
  # ASVS V14.1.1: least privilege — volume must not be root-owned when process
  # runs as non-root.
  local _lf_vol="${_compose_project_prefix}_langflow_data"
  log_info "  ${_lf_vol}: chown /vol to 1000:1000"

  local _chown_ok=0
  if [[ "$_effective_runtime" == "docker" ]]; then
    # docker_run mode: daemon provides root inside container; chown any UID.
    # --pull=never uses cached alpine:3 if present; fallback to digest pull.
    if docker run --rm --pull=never \
         --volume "${_lf_vol}:/vol:rw" \
         "alpine:3" \
         chown 1000:1000 /vol 2>/dev/null; then
      _chown_ok=1
    elif docker run --rm \
         --volume "${_lf_vol}:/vol:rw" \
         "$_alpine_image" \
         chown 1000:1000 /vol; then
      _chown_ok=1
    fi
  elif [[ "$_effective_runtime" == "podman" ]]; then
    # Determine Podman sub-mode (same logic as _pki_chown_client_keys).
    if [[ "$(id -u)" == "0" ]]; then
      # Rootful Podman: use podman run (plain chown not available for named volumes).
      if podman run --rm \
           --volume "${_lf_vol}:/vol:rw" \
           "$_alpine_image" \
           chown 1000:1000 /vol 2>/dev/null; then
        _chown_ok=1
      fi
    elif awk -v u="$(id -un)" -F: '$1==u && $3>=65536 {found=1} END{exit !found}' \
           /etc/subuid 2>/dev/null; then
      # Rootless local Podman: inspect volume mountpoint, then podman unshare.
      local _lf_vol_path
      _lf_vol_path="$(podman volume inspect "${_lf_vol}" --format '{{.Mountpoint}}' 2>/dev/null || echo "")"
      if [[ -n "$_lf_vol_path" && -d "$_lf_vol_path" ]]; then
        if podman unshare chown 1000:1000 "$_lf_vol_path" 2>/dev/null; then
          _chown_ok=1
        fi
      fi
      # Fallback: podman run (idempotent if unshare failed or vol not yet created).
      if [[ "$_chown_ok" == "0" ]]; then
        if podman run --rm \
             --volume "${_lf_vol}:/vol:rw" \
             "$_alpine_image" \
             chown 1000:1000 /vol 2>/dev/null; then
          _chown_ok=1
        fi
      fi
    else
      # Podman remote (macOS client tunnelling to VM) — podman run only.
      if podman run --rm \
           --network=none \
           --volume "${_lf_vol}:/vol:rw,U" \
           "$_alpine_image" \
           chown 1000:1000 /vol 2>/dev/null; then
        _chown_ok=1
      fi
    fi
  fi

  if [[ "$_chown_ok" == "0" ]]; then
    log_error "_chown_agent_volumes: failed to chown ${_lf_vol} to 1000:1000 — langflow will EACCES on startup (BLOCKER-LF-001)"
    return 1
  fi
  log_info "  ${_lf_vol}: chown 1000:1000 OK"

  # ${_compose_project_prefix}_letta_data: letta runs as uid=0 inside the container;
  # root-owned volume is correct. No chown needed. Documented here for maintainer clarity.
  log_info "  ${_compose_project_prefix}_letta_data: uid=0 (root) — no chown needed"

  return 0
}

bootstrap_internal_pki() {
  set_step "9b" "internal mTLS PKI"
  log_step "9b/${TOTAL_STEPS}" "Bootstrapping internal mTLS PKI..."
  _pki_validate_lifetimes
  # YSG-CERT-SAN-001: resolve public hostname + IP for Caddy cert SAN.
  _detect_public_access_params
  local ca_root="${WORK_DIR}/docker/secrets/ca_root.crt"
  if [[ -f "$ca_root" ]]; then
    log_info "Root CA already present — checking renewal status"
    local needs_rotation=false
    # Platform Review Finding: no /tmp — keep scratch inside WORK_DIR.
    # Podman rootless: status_file written by container (UID 363144) cannot
    # be removed by host user via plain rm. Use podman unshare rm when runtime
    # is Podman rootless (non-root); fall back to direct rm otherwise.
    local status_file="${WORK_DIR}/docker/secrets/.pki-status"
    if _pki_run_issuer status >"$status_file" 2>&1; then
      if grep -q "'status': 'renew'" "$status_file" 2>/dev/null; then
        log_info "Time-based renewal needed"
        needs_rotation=true
      fi
    fi
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$(id -u)" != "0" ]]; then
      podman unshare rm -f "$status_file" 2>/dev/null || rm -f "$status_file" 2>/dev/null || true
    else
      rm -f "$status_file"
    fi

    # Manifest-aware drift check — v2.23.1 retro #82. Rotates leaves even if
    # they are still time-valid when the URI SAN doesn't match the manifest.
    log_info "Checking leaf URI SANs against docker/service_identities.yaml"
    if ! _pki_detect_uri_san_drift; then
      log_warn "URI SAN drift detected — forcing leaf rotation"
      needs_rotation=true
    fi

    if [[ "$needs_rotation" == "true" ]]; then
      # Build extra-SAN args for Caddy cert on rotation (YSG-CERT-SAN-001).
      local _rotate_san_args=()
      [[ -n "${YSG_PUBLIC_HOSTNAME:-}" ]] && _rotate_san_args+=(--caddy-extra-dns "${YSG_PUBLIC_HOSTNAME}")
      [[ -n "${YSG_PUBLIC_IP:-}" ]]       && _rotate_san_args+=(--caddy-extra-ip  "${YSG_PUBLIC_IP}")
      if ! _pki_run_issuer rotate-leaves \
             --leaf-lifetime-days "$YASHIGANI_CERT_LIFETIME_DAYS" \
             "${_rotate_san_args[@]}"; then
        log_error "Leaf rotation failed — mTLS mesh will not converge"
        return 1
      fi
      log_success "Leaf certs rotated"
      _pki_persist_env
      # New keys generated by rotate-leaves — apply service ownership atomically.
      # maintainer directive 2026-05-10: upgrade path that does NOT rotate keys must
      # NOT sweep-chmod existing keys. Ownership is applied only when new key
      # material has actually been written. GATE5-BUG-01.
      _pki_chown_client_keys || return 1
    else
      log_success "Certs current — no rotation needed"
      _pki_persist_env
      # No new keys generated. Existing keys are already correctly owned from the
      # previous install/rotate step. Do NOT re-apply chown (upgrade no-touch rule).
      # maintainer directive 2026-05-10 / GATE5-BUG-01.
      #
      # Exception — Podman rootless: re-apply unshare chown unconditionally (idempotent).
      # Keys may be host:host owned if docker/secrets/ survived a wipe without
      # namespace remapping (partial-state retry, backup restore, upgrade-over-upgrade).
      # For Docker/rootful host UID == container UID so the no-touch rule is safe there;
      # for Podman rootless it is not. See YSG-INSTALL-PKI-001.
      if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" && "$(id -u)" != "0" ]]; then
        _pki_chown_client_keys || return 1
      fi
      log_info "Existing key ownership preserved (no rotation — upgrade no-touch rule)"
    fi
    return 0
  fi

  log_info "Fresh install — generating root + intermediate + leaves"
  log_info "  Root:         ${YASHIGANI_ROOT_CA_LIFETIME_YEARS} years"
  log_info "  Intermediate: ${YASHIGANI_INTERMEDIATE_LIFETIME_DAYS} days"
  log_info "  Leaves:       ${YASHIGANI_CERT_LIFETIME_DAYS} days"

  # Build extra-SAN args for Caddy cert (YSG-CERT-SAN-001).
  local _san_args=()
  [[ -n "${YSG_PUBLIC_HOSTNAME:-}" ]] && _san_args+=(--caddy-extra-dns "${YSG_PUBLIC_HOSTNAME}")
  [[ -n "${YSG_PUBLIC_IP:-}" ]]       && _san_args+=(--caddy-extra-ip  "${YSG_PUBLIC_IP}")

  if ! _pki_run_issuer bootstrap \
       --root-lifetime-years "$YASHIGANI_ROOT_CA_LIFETIME_YEARS" \
       --intermediate-lifetime-days "$YASHIGANI_INTERMEDIATE_LIFETIME_DAYS" \
       --leaf-lifetime-days "$YASHIGANI_CERT_LIFETIME_DAYS" \
       "${_san_args[@]}"; then
    log_error "PKI bootstrap failed — internal mTLS certs not generated"
    return 1
  fi

  _pki_persist_env

  _pki_chown_client_keys || return 1  # re-own service keys to container UIDs; fail-closed

  log_success "Internal CA + per-service leaf certs generated"
  log_info "  CA root:      docker/secrets/ca_root.crt"
  log_info "  Service certs are bind-mounted into each container via compose"
}

# =============================================================================
# _postgres_byo_ca_trust_sync — post-BYO-CA-activation postgres trust-bundle sync
# =============================================================================
# Called by Su's _activate_byo_ca() AFTER the new ca_root.crt + ca_intermediate.crt
# have been written into docker/secrets/ but BEFORE services are restarted.
#
# Problem: PGDATA/root.crt is written once by 05-enable-ssl.sh at first initdb
# and never auto-updated. When a BYO CA is activated (deferred or rotation path),
# the postgres container must re-read the new trust bundle or it will reject client
# certs signed by the new CA.
#
# This function:
#   1. Detects whether postgres is already running.
#   2. If running: invokes the now-idempotent 05-enable-ssl.sh inside the container.
#      The script detects the trust-bundle change via SHA-256 comparison, writes the
#      new PGDATA/root.crt atomically, and issues pg_ctl reload so postgres picks
#      it up without a full restart.
#   3. If not running: the updated docker/secrets/ca_root.crt + ca_intermediate.crt
#      will be consumed by 05-enable-ssl.sh naturally at next container start
#      (first-init path). No action needed.
#   4. Falls back to a warn (not error) if docker/podman exec cannot reach postgres;
#      in that case the operator must restart postgres manually.
#
# Cross-platform: works on Docker Engine (macOS + Linux) and Podman (rootful +
# rootless) by trying the docker exec path first, then the podman exec path.
# The postgres container name follows the compose project naming convention:
#   Docker Engine: docker-postgres-1 (project prefix "docker")
#   Podman Compose: docker_postgres_1 (project prefix "docker", underscore separator)
# Both patterns are tried.
#
# IMPORTANT: This function is Captain's scope only. It does NOT perform any
# validation of the BYO CA files (Su's scope) or any PKI issuer operations
# (Tom's scope). It is called AFTER those are complete.
# =============================================================================
_postgres_byo_ca_trust_sync() {
  log_info "BYO CA trust-bundle sync: checking postgres container state"

  local _script_path="/docker-entrypoint-initdb.d/05-enable-ssl.sh"
  local _sync_ok=false

  # Enumerate candidate container names in order of likelihood.
  # Docker Compose v2 uses hyphen separator; Podman Compose uses underscore.
  local _pg_names=(
    "docker-postgres-1"
    "docker_postgres_1"
    "yashigani-postgres-1"
    "yashigani_postgres_1"
  )

  # Fall back to trying docker then podman directly.
  local _exec_tools=()
  if command -v docker >/dev/null 2>&1; then
    _exec_tools+=("docker")
  fi
  if command -v podman >/dev/null 2>&1; then
    _exec_tools+=("podman")
  fi

  if [[ ${#_exec_tools[@]} -eq 0 ]]; then
    log_warn "BYO CA trust-bundle sync: no container runtime found (docker/podman) — skipping exec path"
    log_warn "  Manual remediation: restart postgres after BYO CA activation:"
    log_warn "  docker compose restart postgres"
    return 0
  fi

  for _tool in "${_exec_tools[@]}"; do
    for _cname in "${_pg_names[@]}"; do
      # Check if the container exists and is running.
      if "${_tool}" inspect --format '{{.State.Running}}' "${_cname}" 2>/dev/null | grep -q '^true$'; then
        log_info "  Found running postgres container: ${_cname} (via ${_tool})"
        log_info "  Invoking trust-bundle sync inside container..."

        # Run the idempotent 05-enable-ssl.sh inside the container.
        # It will detect the checksum change, update root.crt atomically, and
        # issue pg_ctl reload. Output is forwarded to the installer log.
        if "${_tool}" exec "${_cname}" bash "${_script_path}" 2>&1 | while IFS= read -r _line; do
            log_info "    [postgres] ${_line}"
          done; then
          log_success "BYO CA trust-bundle synced in running postgres container (${_cname})"
          log_info "  Postgres re-reads root.crt via pg_ctl reload — no restart required"
          _sync_ok=true
          break 2
        else
          log_warn "BYO CA trust-bundle sync via ${_tool} exec ${_cname} failed (exit non-zero)"
          log_warn "  Manual remediation: docker compose restart postgres"
          _sync_ok=false
          break 2
        fi
      fi
    done
  done

  if [[ "$_sync_ok" == "false" ]]; then
    # Postgres is not running. Trust bundle will be picked up at next start.
    log_info "BYO CA trust-bundle sync: postgres container not running"
    log_info "  Updated ca_root.crt + ca_intermediate.crt will be consumed by"
    log_info "  05-enable-ssl.sh at next postgres container start — no action needed now."
  fi

  return 0
}

# =============================================================================
# _activate_byo_ca — stage customer CA files and re-issue all leaf certs
# =============================================================================
# Called when BYO CA files are ready:
#   (a) Fresh install with provide-now path (--with-internal-ca + cert/key flags)
#   (b) Deferred activation re-run (--internal-ca-cert + --internal-ca-key only)
#   (c) CA rotation (same flags as b, against an existing BYO install)
#
# Pre-conditions (enforced by caller):
#   - _validate_byo_ca_files() already succeeded
#   - INTERNAL_CA_CERT, INTERNAL_CA_KEY are non-empty absolute paths
#   - INTERNAL_CA_ROOT may be empty (optional)
#   - WORK_DIR is set and is the install root
#
# Steps:
#   1. Backup existing CA files (if any) into docker/backups/
#   2. Stage BYO files into docker/secrets/ atomically
#   3. Write ca_source.* fields into service_identities.yaml
#   4. Run _pki_run_issuer bootstrap (Tom's #a55e0ee branches on byo_intermediate)
#   5. Re-own service keys to container UIDs
#   6. Sync postgres trust bundle (Captain's _postgres_byo_ca_trust_sync)
#   7. Clear sentinel + update .env
#
# The issuer bootstrap in step 4 detects ca_source.mode == byo_intermediate,
# skips root/intermediate generation, and signs leaves against the customer's
# intermediate key — per Tom's a55e0ee implementation.
# =============================================================================
_activate_byo_ca() {
  local _cert="$INTERNAL_CA_CERT"
  local _key="$INTERNAL_CA_KEY"
  local _root="${INTERNAL_CA_ROOT:-}"
  local _secrets_dir="${WORK_DIR}/docker/secrets"
  local _manifest="${WORK_DIR}/docker/service_identities.yaml"
  local _env_file="${WORK_DIR}/docker/.env"
  local _backup_dir
  _backup_dir="${WORK_DIR}/docker/backups/byo_ca_$(date -u +%Y%m%dT%H%M%SZ)"

  log_step "9b-byo" "BYO internal CA activation"
  log_info "Activating BYO internal CA: ${_cert}"

  # ---- Step 1: Backup existing CA files if present ---
  if [[ -f "${_secrets_dir}/ca_root.crt" || -f "${_secrets_dir}/ca_intermediate.crt" ]]; then
    log_info "Backing up existing CA files to ${_backup_dir}/"
    mkdir -p "${_backup_dir}"
    for _f in ca_root.crt ca_intermediate.crt ca_intermediate.key; do
      [[ -f "${_secrets_dir}/${_f}" ]] \
        && install -m 0600 -p "${_secrets_dir}/${_f}" "${_backup_dir}/${_f}" \
        || true
    done
    log_info "  Backup: ${_backup_dir}/"
  fi

  # ---- Step 2: Stage BYO files atomically ---
  # Certs are group-readable (0644) so container processes can read them.
  # Key is owner-only (0600) — only the PKI issuer container reads it.
  log_info "Staging BYO CA files into docker/secrets/"

  # BYOCA-BUG-002: after _prepare_secrets_dir_for_pki() the secrets dir is
  # chowned to UID 1001 via `podman unshare chown` on Podman rootless. The host
  # UID (typically 1000) no longer owns the dir, so plain install(1) fails with
  # EACCES. Fix: run the install(1) calls inside `podman unshare` so they
  # execute within the user-namespace mapping and see the dir as owned by 1001.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && [[ "$(id -u)" != "0" ]] \
       && podman unshare true 2>/dev/null; then
    podman unshare bash -c "install -m 0644 '${_cert}' '${_secrets_dir}/byo_ca_intermediate.crt'" \
      || { log_error "_activate_byo_ca: failed to copy BYO cert (podman unshare)"; return 1; }
    podman unshare bash -c "install -m 0600 '${_key}' '${_secrets_dir}/byo_ca_intermediate.key'" \
      || { log_error "_activate_byo_ca: failed to copy BYO key (podman unshare)"; return 1; }
    if [[ -n "$_root" ]]; then
      podman unshare bash -c "install -m 0644 '${_root}' '${_secrets_dir}/byo_ca_root.crt'" \
        || { log_error "_activate_byo_ca: failed to copy BYO root cert (podman unshare)"; return 1; }
      log_info "  byo_ca_root.crt staged (customer root)"
    fi
  else
    install -m 0644 -p "${_cert}" "${_secrets_dir}/byo_ca_intermediate.crt" \
      || { log_error "_activate_byo_ca: failed to copy BYO cert to secrets dir"; return 1; }
    install -m 0600 -p "${_key}" "${_secrets_dir}/byo_ca_intermediate.key" \
      || { log_error "_activate_byo_ca: failed to copy BYO key to secrets dir"; return 1; }
    if [[ -n "$_root" ]]; then
      install -m 0644 -p "${_root}" "${_secrets_dir}/byo_ca_root.crt" \
        || { log_error "_activate_byo_ca: failed to copy BYO root cert to secrets dir"; return 1; }
      log_info "  byo_ca_root.crt staged (customer root)"
    fi
  fi

  log_info "  byo_ca_intermediate.crt staged"
  log_info "  byo_ca_intermediate.key staged (mode 0600)"

  # S1 assertion: no world/group-readable key under docker/secrets/
  if find "${_secrets_dir}" -name "byo_ca_intermediate.key" \
       \( -perm -004 -o -perm -040 \) | grep -q .; then
    log_error "CWE-732: byo_ca_intermediate.key is group/world-readable — aborting"
    return 1
  fi

  # ---- Step 3: Write ca_source fields into service_identities.yaml ---
  # The issuer container reads these at bootstrap time to determine whether to
  # generate its own CA or use the customer-supplied files. Container-internal
  # path: secrets dir is mounted at /secrets inside the issuer container.
  log_info "Writing ca_source.byo fields into service_identities.yaml"

  local _has_root=0
  [[ -n "$_root" ]] && _has_root=1

  # BYOCA-BUG-004: service_identities.yaml may be owned by the Podman user-namespace
  # UID after _prepare_secrets_dir_for_pki (EACCES for host UID 1000 on rootless).
  # Fix: use `podman unshare python3` when on Podman rootless.
  local _py_cmd="python3"
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && [[ "$(id -u)" != "0" ]] \
       && podman unshare true 2>/dev/null; then
    _py_cmd="podman unshare python3"
  fi

  ${_py_cmd} - "${_manifest}" "${_has_root}" <<'PYEOF' \
    || { log_error "_activate_byo_ca: failed to update service_identities.yaml ca_source fields"; return 1; }
import sys, yaml, pathlib

manifest_path = pathlib.Path(sys.argv[1])
has_root = sys.argv[2] == "1"

with open(manifest_path) as f:
    m = yaml.safe_load(f)

m.setdefault("ca_source", {})
m["ca_source"]["mode"] = "byo_intermediate"
m["ca_source"].setdefault("byo", {})
m["ca_source"]["byo"]["intermediate_cert_path"] = "/secrets/byo_ca_intermediate.crt"
m["ca_source"]["byo"]["intermediate_key_path"]  = "/secrets/byo_ca_intermediate.key"
m["ca_source"]["byo"]["root_cert_path"]         = "/secrets/byo_ca_root.crt" if has_root else None

# Preserve structure: write back with safe_dump (no anchors, block style)
with open(manifest_path, "w") as f:
    yaml.safe_dump(m, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

print("ca_source.mode = byo_intermediate written to manifest")
PYEOF

  log_info "  service_identities.yaml updated: ca_source.mode=byo_intermediate"

  # ---- Step 4: Run PKI issuer bootstrap ---
  # Tom's a55e0ee bootstrap() branches on ca_source.mode == byo_intermediate:
  #   - Skips root + intermediate generation
  #   - Reads /secrets/byo_ca_intermediate.{crt,key} as the signing CA
  #   - Issues all leaf certs under the customer intermediate
  # The _pki_run_issuer dispatcher handles Docker vs Podman vs macOS.
  log_info "Running PKI issuer bootstrap against BYO intermediate CA..."
  _pki_validate_lifetimes
  _detect_public_access_params

  local _san_args=()
  [[ -n "${YSG_PUBLIC_HOSTNAME:-}" ]] && _san_args+=(--caddy-extra-dns "${YSG_PUBLIC_HOSTNAME}")
  [[ -n "${YSG_PUBLIC_IP:-}" ]]       && _san_args+=(--caddy-extra-ip  "${YSG_PUBLIC_IP}")

  if ! _pki_run_issuer bootstrap \
         --root-lifetime-years   "$YASHIGANI_ROOT_CA_LIFETIME_YEARS" \
         --intermediate-lifetime-days "$YASHIGANI_INTERMEDIATE_LIFETIME_DAYS" \
         --leaf-lifetime-days    "$YASHIGANI_CERT_LIFETIME_DAYS" \
         "${_san_args[@]}"; then
    log_error "_activate_byo_ca: PKI issuer bootstrap failed — BYO CA leaves NOT issued"
    return 1
  fi

  _pki_persist_env
  log_success "BYO CA leaf certs issued by customer intermediate"

  # ---- Step 5: Re-own service keys to container UIDs ---
  _pki_chown_client_keys || return 1

  # ---- Step 6: Postgres trust-bundle sync ---
  # _postgres_byo_ca_trust_sync is Captain's implementation (38512fd).
  # It invokes 05-enable-ssl.sh inside the running postgres container
  # (if running) to atomically update PGDATA/root.crt and issue pg_ctl reload.
  # Falls back to a warn if postgres is not running — the updated secrets/ca_root.crt
  # will be consumed at next postgres start.
  _postgres_byo_ca_trust_sync \
    || log_warn "_activate_byo_ca: trust sync did not propagate to running postgres — restart manually: docker compose restart postgres"

  # ---- Step 7: Clear deferred sentinel + update .env ---
  local _sentinel="${_secrets_dir}/.byo_ca_pending"
  if [[ -f "$_sentinel" ]]; then
    rm -f "$_sentinel" \
      || log_warn "_activate_byo_ca: could not remove ${_sentinel} — non-fatal"
    log_info "Cleared deferred sentinel: .byo_ca_pending"
  fi

  # Write/update YASHIGANI_BYO_CA_MODE in .env (sed-update if already present)
  if grep -q "^YASHIGANI_BYO_CA_MODE=" "$_env_file" 2>/dev/null; then
    sed -i.bak "s|^YASHIGANI_BYO_CA_MODE=.*|YASHIGANI_BYO_CA_MODE=byo_intermediate|" "$_env_file" \
      && rm -f "${_env_file}.bak" || true
  else
    echo "YASHIGANI_BYO_CA_MODE=byo_intermediate" >> "$_env_file"
  fi
  log_info "YASHIGANI_BYO_CA_MODE=byo_intermediate written to .env"

  log_success "BYO internal CA activated"
  log_info "  CA root trust anchor:    docker/secrets/byo_ca_root.crt (if supplied)"
  log_info "  Intermediate (signing):  docker/secrets/byo_ca_intermediate.crt"
  log_info "  All service leaf certs re-issued under customer intermediate"
  log_info "  Restart services to pick up new certs:"
  log_info "    docker compose restart gateway backoffice pgbouncer redis budget-redis policy"
}

# =============================================================================
# _activate_byo_ca_rerun — deferred-then-activated re-run short-circuit
# =============================================================================
# Detects if this is a BYO CA activation re-run against an existing install
# (i.e. --internal-ca-cert was supplied, ca_root.crt already exists OR sentinel
# .byo_ca_pending exists). If so: validate files, activate, restart if running,
# and exit. This short-circuits the full install flow.
#
# Returns 0 if this is NOT a re-run path (caller continues full install).
# Exits  0 if this IS a re-run path (activation complete).
# Exits  1 if this IS a re-run path but activation failed.
# =============================================================================
_activate_byo_ca_rerun() {
  local _secrets_dir="${WORK_DIR}/docker/secrets"
  local _sentinel="${_secrets_dir}/.byo_ca_pending"
  local _ca_root="${_secrets_dir}/ca_root.crt"

  # Determine whether this looks like a re-run activation:
  #   - --internal-ca-cert was supplied (INTERNAL_CA_CERT non-empty)
  #   - AND an existing install is present (ca_root.crt exists OR sentinel exists)
  if [[ -z "$INTERNAL_CA_CERT" ]]; then
    return 0  # no cert supplied — not a re-run activation path
  fi

  if [[ ! -f "$_ca_root" && ! -f "$_sentinel" ]]; then
    return 0  # no existing install detected — treat as fresh install with BYO
  fi

  log_info "BYO CA re-run detected: existing install + --internal-ca-cert supplied"
  [[ -f "$_sentinel" ]] && log_info "  Deferred sentinel present: .byo_ca_pending"
  [[ -f "$_ca_root"   ]] && log_info "  Existing CA root present: ca_root.crt"

  # Validate files (Laura's requirements — same path as fresh install)
  if ! _validate_byo_ca_files; then
    log_error "BYO CA validation failed — aborting re-run. Check the flags and retry."
    exit 1
  fi

  # Detect if the stack is running so we can restart it after activation
  local _compose_file="${WORK_DIR}/docker/docker-compose.yml"
  local _stack_running=false
  if [[ -f "$_compose_file" && ${#COMPOSE_CMD[@]} -gt 0 ]]; then
    if timeout 10 "${COMPOSE_CMD[@]}" -f "$_compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
      _stack_running=true
      log_info "  Stack is running — will restart services after BYO CA activation"
    fi
  fi

  # Activate the BYO CA
  _activate_byo_ca || exit 1

  # Restart services if the stack was running (picks up new leaf certs)
  if [[ "$_stack_running" == "true" ]]; then
    log_info "Restarting services to pick up new BYO CA leaf certs..."
    if "${COMPOSE_CMD[@]}" -f "$_compose_file" \
         restart gateway backoffice pgbouncer redis budget-redis policy 2>&1 | \
         while IFS= read -r _line; do log_info "  [compose restart] ${_line}"; done; then
      log_success "Services restarted with new BYO CA leaf certs"
    else
      log_warn "Service restart returned non-zero — check container logs"
      log_warn "  docker compose restart gateway backoffice pgbouncer redis budget-redis policy"
    fi
  else
    log_info "Stack not running. BYO CA files are in place."
    log_info "Start Yashigani with: docker compose -f docker/docker-compose.yml up -d"
  fi

  log_success "BYO CA activation re-run complete"
  exit 0
}

# Subcommand entry — for `install.sh --pki-action=<action>` used in maintenance.
handle_pki_subcommand() {
  case "$PKI_ACTION" in
    bootstrap)
      _prepare_secrets_dir_for_pki
      bootstrap_internal_pki
      ;;
    rotate-leaves)
      log_step "-" "Rotating leaf certs"
      # YSG-CERT-SAN-001: respect public SAN env vars if set (e.g. after re-running
      # with --public-hostname / --public-ip on a previously-installed stack).
      _detect_public_access_params
      local _rl_san_args=()
      [[ -n "${YSG_PUBLIC_HOSTNAME:-}" ]] && _rl_san_args+=(--caddy-extra-dns "${YSG_PUBLIC_HOSTNAME}")
      [[ -n "${YSG_PUBLIC_IP:-}" ]]       && _rl_san_args+=(--caddy-extra-ip  "${YSG_PUBLIC_IP}")
      _pki_run_issuer rotate-leaves \
        --leaf-lifetime-days "$YASHIGANI_CERT_LIFETIME_DAYS" \
        "${_rl_san_args[@]}"
      log_success "Leaf certs rotated — restart services to pick up new certs"
      log_info "  docker compose restart gateway backoffice postgres pgbouncer redis budget-redis policy"
      ;;
    rotate-intermediate)
      log_step "-" "Rotating intermediate + leaf certs"
      _pki_run_issuer rotate-intermediate \
        --intermediate-lifetime-days "$YASHIGANI_INTERMEDIATE_LIFETIME_DAYS" \
        --leaf-lifetime-days "$YASHIGANI_CERT_LIFETIME_DAYS"
      log_success "Intermediate + leaves rotated — restart the stack"
      ;;
    rotate-root)
      log_warn "Root CA rotation is DESTRUCTIVE — every service's trust bundle"
      log_warn "will be replaced. Expect a brief mesh-wide restart window."
      printf "  Proceed? Type YES in caps to confirm: "
      local _ans
      read -r _ans </dev/tty 2>/dev/null || _ans=""
      if [[ "$_ans" != "YES" ]]; then
        log_info "Cancelled"
        return 0
      fi
      _pki_run_issuer rotate-root --confirm \
        --root-lifetime-years "$YASHIGANI_ROOT_CA_LIFETIME_YEARS" \
        --intermediate-lifetime-days "$YASHIGANI_INTERMEDIATE_LIFETIME_DAYS" \
        --leaf-lifetime-days "$YASHIGANI_CERT_LIFETIME_DAYS"
      log_success "Full PKI rotated — restart all services"
      ;;
    status)
      _pki_run_issuer status
      ;;
    *)
      log_error "Unknown --pki-action '${PKI_ACTION}'"
      log_info "Valid: bootstrap | rotate-leaves | rotate-intermediate | rotate-root | status"
      exit 1
      ;;
  esac
}

main() {
  parse_args "$@"

  # Short-circuit path for PKI maintenance commands: no full install, no wizard.
  if [[ -n "$PKI_ACTION" ]]; then
    detect_working_directory
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then cd "$WORK_DIR"; fi
    handle_pki_subcommand
    exit 0
  fi

  # ---- Step 0: Banner ----
  print_banner

  # ---- Step 1: Working directory ----
  detect_working_directory

  # Move into the repo now that we know where it is
  if [[ "$DRY_RUN" != "true" && -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    cd "$WORK_DIR"
  fi

  # #3h-fix: tee all install output to install.log so "no space left on device"
  # and other mid-build errors are always recoverable from disk. Activated once
  # WORK_DIR is resolved so the log lands in the right place. Skipped when:
  #   * DRY_RUN — no side-effects, logging unnecessary.
  #   * PKI subcommands — they exit before this point (handled above).
  #   * YSG_NO_LOG=true — escape hatch for CI runners that capture stdout natively.
  # The re-exec guard (YSG_LOGGING_ACTIVE) prevents a double-log loop.
  # stdout and stderr are merged (2>&1) before tee so the log is interleaved in
  # chronological order, matching what the operator sees in the terminal.
  if [[ "$DRY_RUN" != "true" && "${YSG_NO_LOG:-false}" != "true" && "${YSG_LOGGING_ACTIVE:-false}" != "true" ]]; then
    local _log_dir="${WORK_DIR:-$(pwd)}"
    local _log_file="${_log_dir}/install.log"
    export YSG_LOGGING_ACTIVE=true
    # Re-exec via tee: all subsequent output from this process is duplicated to
    # install.log. exec replaces the shell's stdout/stderr — the tee process
    # inherits both and copies to the log file. ANSI escape codes are preserved
    # in the log (they do not affect file readability and strip cleanly with
    # `cat -v` or `sed 's/\x1b\[[0-9;]*m//g'`).
    exec > >(tee -a "$_log_file") 2>&1
    # Capture the tee coprocess PID immediately after exec.  This is used at
    # the very end of main() to drain buffered output before exit (SF-012:
    # final lines dropped when the outer tee/calling shell closes before the
    # inner tee subprocess flushes).  NOTE: do NOT use bare `wait` — that
    # includes the tee coprocess and causes a deadlock (see L2782 comment).
    _tee_pid=$!
    log_info "Install log: ${_log_file}"
  fi

  # ---- Step 2: Platform detection ----
  source_platform_detect

  # ---- Step 3: Platform summary ----
  print_platform_summary

  # ---- Step 3b: Deployment mode selection (new in v0.9.0) ----
  select_deploy_mode

  # ---- Step 3c: AES key provisioning (new in v0.9.0) ----
  provision_aes_key

  if [[ "$MODE" == "k8s" ]]; then
    # ------------------------------------------------------------------
    # Kubernetes / Enterprise deployment path
    # ------------------------------------------------------------------
    # Step 4: n/a (no runtime install for k8s)
    # Step 5: Preflight
    run_preflight

    # Step 6: Wizard / config
    run_wizard

    # Write AES key to compose .env (no-op for k8s helm path; AES key is
    # pre-seeded into K8s Secret by _write_helm_values below).
    _write_aes_key_to_env

    # Write helm values override file from operator-supplied flags.
    # B2-fix: _write_helm_values must run BEFORE k8s_helm_dep_update so that the
    # AES key pre-seed happens before helm installs the backoffice Secret.
    _write_helm_values

    # Step 7: Helm dependency update
    k8s_helm_dep_update

    # Step 8: Helm install/upgrade
    k8s_helm_install

    # Step 9: Rollout status
    k8s_rollout_status

    # Step 10: Access instructions
    k8s_print_access

    # Step 11: Write install state file (B1 — GAP 1: k8s path never wrote this
    # file, causing uninstall.sh to fall through to auto-detect which tried
    # podman/docker and never reached the k8s teardown path. Operator ran
    # uninstall.sh, got clean exit 0, Helm release + PKI Secrets all survived.)
    #
    # Mode 0644: intentional — uninstall.sh may run as a different OS user
    # (cross-UID clean-slate scenario). Contents are not sensitive (Laura TM-1
    # verdict: runtime name + namespace are not credentials).
    # git-ignored via docker/.yashigani-install-state entry in .gitignore.
    if [[ "$DRY_RUN" != "true" ]]; then
      mkdir -p "${WORK_DIR}/docker"
      {
        printf 'RUNTIME=%s\n'            "k8s"
        printf 'NAMESPACE=%s\n'          "${NAMESPACE}"
        printf 'HELM_RELEASE=%s\n'       "yashigani"
        printf 'INSTALL_UID=%s\n'        "$(id -u)"
        printf 'INSTALL_USER=%s\n'       "$(id -un)"
        printf 'INSTALL_TIMESTAMP=%s\n'  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'YASHIGANI_VERSION=%s\n'  "${YASHIGANI_VERSION:-unknown}"
      } > "${WORK_DIR}/docker/.yashigani-install-state"
      chmod 0644 "${WORK_DIR}/docker/.yashigani-install-state"
      log_info "Install state written: ${WORK_DIR}/docker/.yashigani-install-state"
      log_info "  RUNTIME=k8s  NAMESPACE=${NAMESPACE}  HELM_RELEASE=yashigani"
    fi

  else
    # ------------------------------------------------------------------
    # Docker Compose deployment path (Demo + Production)
    # ------------------------------------------------------------------

    # Step 4: Install runtime (vm mode only — no-op for compose)
    install_runtime

    # Step 4b: Installer pre-flight hard-stop (P0-12: docker group + bind-mount owner)
    check_installer_preflight

    # Step 5: Preflight
    run_preflight

    # Step 6: Wizard / config (skipped in demo mode — defaults applied)
    if [[ "$DEPLOY_MODE" == "demo" ]]; then
      log_step "6/${TOTAL_STEPS}" "Skipping wizard (demo mode — using defaults)"
    else
      run_wizard
    fi

    # Idempotency: check for running installation before making changes
    check_existing_installation

    # Pre-install contaminated-volume check (BUG-INSTALL-ON-CONTAMINATED-VOLUMES)
    # Must run AFTER check_existing_installation (containers stopped) and BEFORE
    # generate_secrets (no point generating secrets for a doomed install).
    #
    # IMPORTANT: use YSG_RUNTIME (the operator-selected runtime) NOT a fresh
    # auto-detect. On hosts where both Docker Engine and Podman are installed,
    # auto-detect can pick the wrong runtime and check volumes in the wrong
    # store. If the stack was installed under Docker, those volumes live in the
    # Docker store; if under Podman, in the Podman store. We must check the
    # same store the new install will use.
    #
    # COMPOSE_CMD was set by resolve_compose_cmd() called from
    # check_existing_installation(). The first element tells us the runtime.
    if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
      resolve_compose_cmd 2>/dev/null || true
    fi

    # BYO CA re-run / deferred-activation short-circuit.
    # If --internal-ca-cert was supplied against an existing install (ca_root.crt
    # or .byo_ca_pending sentinel present), activate the BYO CA and exit.
    # COMPOSE_CMD is now resolved so the stack-running check inside
    # _activate_byo_ca_rerun works correctly.
    # Returns 0 if this is NOT a re-run path (continues full install).
    # Exits 0 or 1 if this IS a re-run path (does not return).
    _activate_byo_ca_rerun
    # Derive RUNTIME from resolved COMPOSE_CMD: "podman-compose" or "podman compose"
    # → podman; "docker compose" or "docker-compose" → docker.
    if [[ -z "${RUNTIME:-}" ]]; then
      case "${COMPOSE_CMD[0]:-}" in
        podman*) RUNTIME="podman" ;;
        docker*) RUNTIME="docker" ;;
        *)       RUNTIME="${YSG_RUNTIME:-docker}" ;;
      esac
    fi
    _check_contaminated_volumes

    # Write AES key to .env
    _write_aes_key_to_env

    # Generate all service passwords (admin, postgres, redis, grafana)
    generate_secrets

    # Step 7: License key (skipped in demo — Community, no key needed)
    if [[ "$DEPLOY_MODE" == "demo" ]]; then
      log_step "7/${TOTAL_STEPS}" "Skipping licence key (demo mode — Community tier)"
      # gate #ROOTLESS-6: create placeholder NOW (before PKI bootstrap chowns secrets_dir)
      # so compose_up() doesn't need to write it after the chown.
      # gate #ROOTLESS-8: if secrets_dir is owned by a foreign UID from a stale
      # install (e.g. rootful PKI ran and chowned to 1001 before disk-full abort),
      # the write will fail with EPERM. The stale-partial-install guard in
      # compose_up() will clean it up later; treat EPERM here as non-fatal so
      # the installer continues to the guard rather than aborting at step 7.
      local _lic="${WORK_DIR}/docker/secrets/license_key"
      if [[ ! -s "$_lic" ]]; then
        if ! echo "# community — no licence key required" > "$_lic" 2>/dev/null; then
          log_warn "Could not create license_key placeholder at step 7 (secrets_dir may be owned by stale UID — stale-install guard will handle this in compose_up)"
        else
          chmod 600 "$_lic" 2>/dev/null || true
        fi
      fi
    else
      handle_license
    fi

    # Step 8: Optional agent bundle selection
    select_agent_bundles

    # Step 8b-0: BYO Internal CA wizard — Q1 + Q1a (Tiago directive 2026-05-23).
    # Q1 (BYO internal CA) and Q2 (edge TLS mode) are INDEPENDENT decisions.
    # A customer can: BYO CA for mTLS + ACME for edge, or BYO CA for both, or
    # no BYO CA + ACME for edge (default), or no BYO CA + self-signed (demo).
    # Rule: these prompts are additive — Journey A and Journey B shapes unchanged.
    # BYO CA for internal mTLS (Q1) — interactive path
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
      printf "\n${C_BOLD}Internal CA for service-to-service mTLS${C_RESET}\n"
      printf "  Yashigani uses mTLS for inter-service traffic. By default it generates\n"
      printf "  its own internal CA. If your organisation has an existing internal CA,\n"
      printf "  you can supply its certificate + key here so Yashigani signs service\n"
      printf "  leaf certs against your CA instead of a Yashigani-generated one.\n\n"
      if prompt_yn "Do you want to provide your own internal CA?" "n"; then
        INSTALL_INTERNAL_CA=true
        printf "\n${C_BOLD}Provide files now or later?${C_RESET}\n"
        printf "  now    — paste paths to cert + key files (validated immediately)\n"
        printf "  later  — install proceeds with Yashigani-generated PKI; supply files\n"
        printf "            post-install via: install.sh --internal-ca-cert /path --internal-ca-key /path\n\n"
        printf "  ${C_BOLD}Provide now or later? [now/later, default=now]: ${C_RESET}"
        local _byo_ca_when
        read -r _byo_ca_when </dev/tty 2>/dev/null || _byo_ca_when="now"
        _byo_ca_when="${_byo_ca_when:-now}"
        case "$_byo_ca_when" in
          now|"")
            if ! _prompt_byo_ca_paths_interactive; then
              log_error "BYO CA setup failed — aborting. Correct the errors above and re-run."
              exit 1
            fi
            ;;
          later|defer)
            INTERNAL_CA_DEFER=true
            log_info "BYO CA deferred. After install, run:"
            log_info "  install.sh --internal-ca-cert /path/to/cert --internal-ca-key /path/to/key"
            ;;
          *)
            log_warn "Unknown answer '${_byo_ca_when}' — treating as 'later' (deferred)"
            INTERNAL_CA_DEFER=true
            log_info "BYO CA deferred. After install, run:"
            log_info "  install.sh --internal-ca-cert /path/to/cert --internal-ca-key /path/to/key"
            ;;
        esac
      fi
    fi

    # Non-interactive: honour explicit BYO CA flags
    if [[ "$NON_INTERACTIVE" == "true" && "$INSTALL_INTERNAL_CA" == "true" ]]; then
      if [[ -n "$INTERNAL_CA_CERT" && -n "$INTERNAL_CA_KEY" ]]; then
        # Provide-now path via explicit flags
        if ! _validate_byo_ca_files; then
          log_error "BYO CA validation failed — aborting. Check the flags and retry."
          exit 1
        fi
      else
        # --with-internal-ca alone (no cert/key paths) = deferred
        INTERNAL_CA_DEFER=true
        log_info "BYO CA deferred (--with-internal-ca without --internal-ca-cert/--internal-ca-key)"
        log_info "After install, run: install.sh --internal-ca-cert /path/to/cert --internal-ca-key /path/to/key"
      fi
    fi

    # Write BYO CA mode to .env for re-run / upgrade path detection
    if [[ "$INSTALL_INTERNAL_CA" == "true" ]]; then
      local _byo_mode_env="${WORK_DIR}/docker/.env"
      if [[ "$INTERNAL_CA_DEFER" == "true" ]]; then
        grep -q "^YASHIGANI_BYO_CA_MODE=" "$_byo_mode_env" 2>/dev/null \
          || echo "YASHIGANI_BYO_CA_MODE=deferred" >> "$_byo_mode_env"
        log_info "YASHIGANI_BYO_CA_MODE=deferred written to .env"
      else
        grep -q "^YASHIGANI_BYO_CA_MODE=" "$_byo_mode_env" 2>/dev/null \
          || echo "YASHIGANI_BYO_CA_MODE=byo_intermediate" >> "$_byo_mode_env"
        log_info "YASHIGANI_BYO_CA_MODE=byo_intermediate written to .env"
      fi
    fi

    # Q2 — Edge TLS mode interactive cascade.
    # Only runs when: (a) interactive mode AND (b) --tls-mode was NOT explicitly
    # passed as a CLI flag AND (c) deploy mode is not demo (demo forces selfsigned
    # via _apply_deploy_defaults, no prompt needed).
    # Non-interactive: --tls-mode flag (or default acme) is honoured as-is.
    if [[ "$NON_INTERACTIVE" != "true" \
       && -z "$TLS_MODE_EXPLICITLY_SET" \
       && "$DEPLOY_MODE" != "demo" ]]; then
      printf "\n${C_BOLD}Edge TLS — how should Caddy present its certificate to clients?${C_RESET}\n"
      printf "  Let's Encrypt ACME issues a trusted public certificate.\n"
      printf "    Requires: public DNS pointing to this host + port 443 reachable.\n"
      printf "  Self-signed is for demo / localhost / offline use only.\n\n"
      if prompt_yn "Use Let's Encrypt ACME for edge TLS?" "y"; then
        TLS_MODE="acme"
        log_info "Edge TLS: Let's Encrypt ACME selected"
      else
        TLS_MODE="selfsigned"
        log_info "Edge TLS: self-signed selected (demo / localhost)"
      fi
    fi

    # Step 8b: Open WebUI — interactive wizard or honour --with-openwebui flag.
    # Non-interactive: INSTALL_OPENWEBUI is false (default) or true (--with-openwebui).
    #   No prompt. Honour the flag as-is.
    # Interactive: ask [Y/n] (default Y). Wizard sets INSTALL_OPENWEBUI=true when Y.
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      if [[ "$INSTALL_OPENWEBUI" == "true" ]]; then
        COMPOSE_PROFILES+=("openwebui")
        log_success "Open WebUI enabled (--with-openwebui flag)"
      else
        log_info "Open WebUI skipped (default non-interactive; pass --with-openwebui to enable)"
      fi
    else
      printf "\n${C_BOLD}Will Yashigani be used by humans with a web UI?${C_RESET}\n"
      printf "  Y (default) — Installs Open WebUI as chat surface for human users.\n"
      printf "                Recommended if any human will log in and chat with MCP-backed LLMs.\n"
      printf "  N           — API/agent-only deployment. Smaller footprint, no chat UI exposed.\n"
      printf "                You can add Open WebUI later by re-running install.sh with --with-openwebui.\n"
      printf "\n"
      if prompt_yn "Install Open WebUI (human chat UI)?" "y"; then
        INSTALL_OPENWEBUI=true
        COMPOSE_PROFILES+=("openwebui")
        log_success "Open WebUI selected"
      else
        log_info "Open WebUI skipped — API/agent-only deployment"
      fi
    fi

    # Step 8b-ii: Write OLLAMA_MODEL to .env when Open WebUI is enabled.
    # ollama-init (compose) and the ollama-init Job (helm) both read OLLAMA_MODEL
    # to decide which model to pull. install.sh sets it here so operators get
    # a working default (qwen2.5:3b, 1.9 GB) without manual .env editing.
    # Value is written only when INSTALL_OPENWEBUI=true; on API-only installs the
    # ollama-init service is gated by profiles: [openwebui] and never starts,
    # so the var is irrelevant there.
    if [[ "$INSTALL_OPENWEBUI" == "true" ]]; then
      local _env_file="${WORK_DIR}/docker/.env"
      local _ollama_model="${OLLAMA_MODEL_OVERRIDE:-qwen2.5:3b}"
      # Preserve any operator-supplied OLLAMA_MODEL — only write if absent.
      if ! grep -q "^OLLAMA_MODEL=" "$_env_file" 2>/dev/null; then
        echo "OLLAMA_MODEL=${_ollama_model}" >> "$_env_file"
        log_info "Ollama default model set: ${_ollama_model} (1.9 GB — will pull on first start)"
      else
        log_info "Ollama model already set in .env — preserving operator value"
      fi
    fi

    # Step 8c: Wazuh SIEM (opt-in)
    if [[ "$INSTALL_WAZUH" == "true" ]]; then
      COMPOSE_PROFILES+=("wazuh")
      log_success "Wazuh SIEM enabled (--wazuh flag)"
    elif [[ "$NON_INTERACTIVE" != "true" ]]; then
      printf "\n${C_BOLD}Install Wazuh SIEM? (open-source security monitoring)${C_RESET}\n"
      printf "    Includes: Wazuh Manager + OpenSearch Indexer + Dashboard\n"
      printf "    ${C_YELLOW}Requires ~2 GB additional disk space${C_RESET}\n"
      printf "\n${C_BOLD}  Install Wazuh? [y/N]: ${C_RESET}"
      local wazuh_choice
      read -r wazuh_choice </dev/tty 2>/dev/null || wazuh_choice="n"
      case "$wazuh_choice" in
        y|Y|yes|YES|Yes)
          COMPOSE_PROFILES+=("wazuh")
          log_success "Wazuh SIEM selected"
          ;;
      esac
    fi

    # Step 8d: Write agent-bundle token placeholders NOW — while the installer
    # still owns docker/secrets/ (before _prepare_secrets_dir_for_pki chowns it
    # to UID 1001 for the PKI issuer container). INSTALLER-BUG-AGENT-TOKENS:
    # previously these writes lived inside compose_up() which runs AFTER the
    # chown; on Podman rootless the host user can no longer write to the
    # subuid-remapped directory and the installer died with EACCES.
    # BUG-B+-NEW-001: on the additive re-run path (Journey B+), secrets_dir is
    # already subuid-remapped from the prior install, so even this step-8d write
    # can fail with EACCES. Use _safe_write_secret which tries direct write first
    # then falls back to `podman unshare tee` (rootless namespace) and finally
    # an ephemeral container write.
    # Covers every profile that may have been added in steps 8/8b/8c
    # (langflow, letta, openclaw, openwebui, wazuh, ...).
    local _tok_secrets_dir="${WORK_DIR}/docker/secrets"
    for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      [[ -z "$_profile" ]] && continue
      local _tok_file="${_tok_secrets_dir}/${_profile}_token"
      if [[ ! -s "$_tok_file" ]]; then
        # BUG-B+-NEW-001: use _safe_write_secret so the re-run path succeeds
        # even when secrets_dir is already owned by a subuid-remapped UID.
        # BUG-WAVE1-P1-002: 0640 so gateway (GID 1001) can read at runtime.
        # _pki_chown_client_keys re-chowns to installer_uid:1001 0640 post-PKI.
        if _safe_write_secret "# placeholder — auto-generated at first bootstrap" \
             "$_tok_file" "0640"; then
          log_info "Created token placeholder: ${_profile}_token"
        else
          log_warn "Could not create token placeholder ${_profile}_token (all write paths failed — see _safe_write_secret)"
        fi
      fi
    done

    # Step 8e: Pre-create letta-runtime bind-mount host files and set mode 0666.
    # docker-compose.yml mounts ./letta-runtime/openapi_letta.json:/app/openapi_letta.json:rw
    # as a single-file bind mount so letta can write openapi_letta.json (app.py:162)
    # while the rootfs remains read_only:true. Docker requires the host-side path to exist
    # as a FILE before bind-mounting (if it doesn't exist, Docker creates a directory at
    # that path, causing letta startup to fail with IsADirectoryError).
    # Mode 0666 is required: cap_drop:ALL removes CAP_DAC_OVERRIDE, so UID 0 inside
    # the container cannot write a file it does not own unless the other-write bit is set.
    # The file contains only an OpenAPI schema (non-secret, non-executable). chmod 0666
    # is applied unconditionally (idempotent on reinstall; survives _fix_config_perms o+rX
    # sweep unchanged). See iris-letta-openapi-write-design-review.md (2026-05-21) and
    # laura-letta-openapi-0666-threat-model.md (2026-05-21) for full rationale.
    # This block only runs when the letta profile is active.
    if printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -q "^letta$"; then
      local _letta_rt_dir="${WORK_DIR}/docker/letta-runtime"
      local _letta_openapi="${_letta_rt_dir}/openapi_letta.json"
      if [[ ! -d "$_letta_rt_dir" ]]; then
        mkdir -p "$_letta_rt_dir" || log_warn "Could not create letta-runtime dir — letta openapi bind-mount may fail"
      fi
      touch "$_letta_openapi" 2>/dev/null || true
      chmod 0666 "$_letta_openapi" \
        || log_warn "Could not chmod 0666 letta-runtime/openapi_letta.json — letta openapi bind-mount may fail"
      log_info "letta-runtime/openapi_letta.json placeholder: mode 0666 (DAC_OVERRIDE-free write)"
    fi

    # Step 9: docker compose pull — OR air-gap bundle load
    if [[ "$AIR_GAP" == "true" ]]; then
      load_airgap_bundle
    else
      compose_pull
    fi

    # Step 9b: Internal mTLS PKI — bootstrap root + intermediate + leaves BEFORE
    # services start, because postgres/redis/opa/gateway/backoffice all now
    # mount certs from docker/secrets/. No certs = no boot.
    # Podman rootless: chown secrets_dir now (deferred from generate_secrets to
    # allow installer-side writes; see _prepare_secrets_dir_for_pki comment).
    _prepare_secrets_dir_for_pki
    _pki_prompt_lifetimes

    # BYO CA — provide-now fresh-install path.
    # When the operator supplied --with-internal-ca + cert/key flags (or the
    # interactive wizard collected them), INSTALL_INTERNAL_CA=true AND
    # INTERNAL_CA_DEFER=false AND INTERNAL_CA_CERT is set.
    # In this case _activate_byo_ca() stages the customer files, writes the
    # manifest ca_source fields, and calls _pki_run_issuer bootstrap — which
    # then branches on ca_source.mode=byo_intermediate (Tom a55e0ee).
    # bootstrap_internal_pki is SKIPPED (it would generate a Yashigani-owned CA).
    # The deferred path (INTERNAL_CA_DEFER=true) still runs bootstrap_internal_pki
    # to generate a Yashigani CA for the initial install; the sentinel
    # .byo_ca_pending is written below after step 9b completes.
    if [[ "$INSTALL_INTERNAL_CA" == "true" \
       && "$INTERNAL_CA_DEFER" != "true" \
       && -n "$INTERNAL_CA_CERT" ]]; then
      _activate_byo_ca || { log_error "BYO CA activation failed — aborting"; exit 1; }
    else
      bootstrap_internal_pki
    fi

    # BYO CA deferred sentinel — written after step 9b so it exists before
    # compose_up starts. Fresh install completed with Yashigani-generated PKI;
    # the sentinel signals that a BYO CA activation is outstanding.
    if [[ "$INSTALL_INTERNAL_CA" == "true" && "$INTERNAL_CA_DEFER" == "true" ]]; then
      local _byo_sentinel="${WORK_DIR}/docker/secrets/.byo_ca_pending"
      touch "$_byo_sentinel" 2>/dev/null \
        || log_warn "Could not write .byo_ca_pending sentinel — non-fatal"
      chmod 0600 "$_byo_sentinel" 2>/dev/null || true
      log_info "BYO CA deferred sentinel written: docker/secrets/.byo_ca_pending"
      log_info "Activate BYO CA later with:"
      log_info "  install.sh --internal-ca-cert /path/to/intermediate.pem \\"
      log_info "             --internal-ca-key  /path/to/intermediate.key  \\"
      log_info "             --internal-ca-root /path/to/root.pem \\"
      log_info "             --byo-ca-fingerprint <sha256>"
    fi

    # Step 9c: chown named volumes for Bucket-C agent containers.
    # Must run AFTER bootstrap_internal_pki (compose pull creates volumes) and
    # BEFORE compose_up (containers must not start with root-owned volumes).
    # BLOCKER-LF-001 / ASVS V14.1.1 / CWE-272.
    _chown_agent_volumes || return 1

    # Step 9d: ensure bind-mounted config files are readable by container UIDs.
    # Fixes umask 077 bleed: if the invoking shell had a restrictive umask at
    # tarball-extract time, config files land as 0600 and container processes
    # (pgbouncer UID 70, prometheus UID 65534, OPA, caddy, etc.) cannot read them.
    # Must run AFTER PKI (which writes certs into docker/secrets/) so the
    # invariant check can assert secrets/ was not accidentally widened.
    # (fix: umask-077-bleed / Ava phase-1 failure 2026-05-20)
    _fix_config_perms

    # YSG-RISK-049 upgrade migration notice (Amendment B — Iris design 2026-05-21).
    # Shown on UPGRADE=true only. The 10-pgbouncer-auth.sh init script creates the
    # pgbouncer_authenticator role and ysg_pgbouncer_get_auth function on FIRST BOOT
    # of a fresh postgres volume. Existing clusters (UPGRADE path) must run this
    # step ONCE BEFORE pgbouncer starts with the new auth_query configuration.
    # The script is idempotent (IF NOT EXISTS guards) — safe to re-run; no-op on
    # fresh installs where postgres init already executed it automatically.
    #
    # YSG-RISK-050 (v2.24.0): pgbouncer authenticator now uses dedicated
    # pgbouncer-auth_client.{crt,key} on the postgres-facing connection
    # (separate from pgbouncer_client.{crt,key} on the client-facing side).
    # Cert issuance happens automatically via PKI iterator reading
    # docker/service_identities.yaml + lib/pki_ownership.sh. No additional
    # install.sh logic required.
    #
    # The updated 10-pgbouncer-auth.sh (v2.24.0) also removes the pg_hba A2
    # carveout (Amendment A2/YSG-RISK-049) when re-run. Re-running the migration
    # step below achieves both: role/function idempotency + carveout removal.
    if [[ "${UPGRADE:-false}" == "true" ]]; then
      log_warn "v2.23.4 → v2.24.0 upgrade detected. The new YSG-RISK-049 auth_query"
      log_warn "design requires running the pgbouncer_authenticator role + function"
      log_warn "migration once. Run this command ONCE after install completes:"
      log_warn ""
      log_warn "  docker exec yashigani-postgres psql -U postgres -d yashigani \\"
      log_warn "    -f /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh"
      log_warn ""
      log_warn "(The script is idempotent — safe to re-run; no-op on fresh installs"
      log_warn "  where the init script already executed.)"
      log_warn "v2.24.x cert-separation upgrade: this also removes the pg_hba A2 carveout"
      log_warn "(YSG-RISK-050) — pgbouncer-auth now uses a dedicated client cert."
    fi

    # Step 10: docker compose up -d
    compose_up

    # Step 10b: Install auto-start units so containers survive a host reboot.
    # Runs after compose_up so WORK_DIR + COMPOSE_CMD are fully resolved.
    # Runs before health-check so unit state is visible in the same terminal session.
    # BUG-REBOOT-NO-AUTO-START / YSG-RISK-046
    _setup_auto_start

    # Step 10c: Inject postgres SSL when upgrading from a version without mTLS.
    # This runs AFTER compose_up (postgres must be running) but BEFORE
    # bootstrap_postgres (which waits for backoffice, which waits for pgbouncer,
    # which needs ssl postgres). Safe no-op on fresh installs.
    _upgrade_postgres_ssl

    # Step 11: Bootstrap Postgres
    bootstrap_postgres

    # Step 11b: Register agent bundles (after backoffice is healthy)
    register_agent_bundles

    # Step 11c: Auto-configure SIEM sink when Wazuh is installed
    if [[ "$INSTALL_WAZUH" == "true" ]] || echo "${COMPOSE_PROFILES[*]+"${COMPOSE_PROFILES[*]}"}" | grep -q "wazuh"; then
      log_info "Configuring audit SIEM sink for Wazuh..."
      # v2.23.1: reach backoffice via Caddy (host port → :443 in container).
      # Caddy uses a self-signed cert in demo; -k tolerates it. Admin auth is
      # the session cookie minted during admin bootstrap.
      local _bo_url="https://localhost:${YASHIGANI_HTTPS_PORT:-443}"
      local _siem_config='{"backend":"wazuh","wazuh_url":"https://wazuh-manager:55000","wazuh_username":"wazuh-wui","wazuh_password":"'"${GEN_WAZUH_API_PASSWORD:-}"'","enabled":true}'
      if curl -skf -X PUT "${_bo_url}/admin/alerts/sinks" -H "Content-Type: application/json" -d "$_siem_config" -b "$(cat "${WORK_DIR}/docker/secrets/admin1_session_cookie" 2>/dev/null || echo '')" >/dev/null 2>&1; then
        log_success "Wazuh SIEM sink auto-configured"
      else
        log_warn "Wazuh SIEM sink auto-configuration failed — configure manually via admin UI"
      fi
    fi

    # Step 12: Health check
    run_health_check

    # Step 12b: Write install state file (Iris IRIS-ARCH-001 / Laura LAURA-TM-CLEANUP-001).
    # Records the effective runtime + installer identity so uninstall.sh can read the
    # correct runtime without heuristic auto-detect (V240-004 + dual-runtime mismatch).
    # Mode 0644: intentional — uninstall.sh may run as a different OS user (cross-UID
    # clean-slate scenario). Contents are not sensitive (see Laura TM-1 verdict).
    # git-ignored via docker/.yashigani-install-state entry in .gitignore.
    {
      printf 'RUNTIME=%s\n'            "${RUNTIME:-${YSG_RUNTIME:-docker}}"
      printf 'INSTALL_UID=%s\n'        "$(id -u)"
      printf 'INSTALL_USER=%s\n'       "$(id -un)"
      printf 'INSTALL_TIMESTAMP=%s\n'  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'YASHIGANI_VERSION=%s\n'  "${YASHIGANI_VERSION:-unknown}"
    } > "${WORK_DIR}/docker/.yashigani-install-state"
    chmod 0644 "${WORK_DIR}/docker/.yashigani-install-state"
    log_info "Install state written: ${WORK_DIR}/docker/.yashigani-install-state"

    # Step 13: Completion summary
    print_completion_summary
  fi

  # SF-012: drain the tee coprocess so the final log lines ([12/13] and [13/13])
  # are flushed to install.log before the process exits.  Wait on the specific
  # PID only — bare `wait` would deadlock (see L2782 comment on coprocess + wait).
  if [[ -n "${_tee_pid:-}" ]]; then
    wait "$_tee_pid" 2>/dev/null || true
  fi
}

main "$@"
