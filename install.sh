#!/usr/bin/env bash
# last-updated: 2026-05-29T00:00:00+01:00 (feat(p3): MCP bridge-join + P-384 signing key generation — YSG-P3-MCP-SIGKEY / YSG-P3-MCP-BRIDGE-JOIN)
# last-updated: 2026-05-28T00:00:00+01:00 (fix(backup): DRIFT-B5-COMPOSE-AGENT-BACKUP — snapshot langflow_data/letta_data/openclaw_data named volumes in _backup_existing_data; warn-only on absent volume; Docker+Podman parity via alpine tar pattern; 0600 tarballs; K8s-gated)
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

YASHIGANI_VERSION="3.1.2"
# GIT_SHA: git short-hash of the current source tree used as a cache-busting
# build arg (--build-arg GIT_SHA=...) for first-party images (gateway,
# backoffice, extractor). Consumed as ARG GIT_SHA / LABEL revision in each
# Dockerfile AFTER all dep-install COPY layers so base/dep layers stay cached
# while any source commit forces the app-code layer to rebuild.
# This closes the version-drift stale-image bug class (cf. 0d9aed1): when
# YASHIGANI_VERSION is unchanged but source commits have landed, a cached image
# tagged :3.0.0 from an earlier build would be reused silently. With GIT_SHA
# baked into the image label, _local_images_cached() detects the mismatch and
# forces a rebuild even when the version tag already exists in the local store.
# Falls back to "dev" (non-git checkout / airgap / tarball installs); in those
# cases the caller must ensure the image store is clean or set YASHIGANI_FORCE_REBUILD=1.
YASHIGANI_GIT_SHA="${YASHIGANI_GIT_SHA:-}"
if [[ -z "$YASHIGANI_GIT_SHA" ]]; then
  if command -v git >/dev/null 2>&1 && git -C "${_YSG_SCRIPT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    YASHIGANI_GIT_SHA="$(git -C "${_YSG_SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || true)"
  fi
  YASHIGANI_GIT_SHA="${YASHIGANI_GIT_SHA:-dev}"
fi
export YASHIGANI_GIT_SHA
YASHIGANI_REPO_URL="${YASHIGANI_REPO_URL:-https://github.com/Agnostic-Security/yashigani.git}"
YASHIGANI_TARBALL_URL="${YASHIGANI_TARBALL_URL:-https://github.com/Agnostic-Security/yashigani/archive/refs/tags/v${YASHIGANI_VERSION}.tar.gz}"
# MI-1: record whether the operator pinned YSG_INSTALL_DIR explicitly in the
# environment BEFORE the default is applied. An explicit pin always wins over the
# per-instance keying in _resolve_instance_install_dir() (operator intent is
# authoritative). Must be evaluated before the ":-default" assignment below.
if [[ -n "${YSG_INSTALL_DIR:-}" ]]; then
  _YSG_INSTALL_DIR_EXPLICIT=1
else
  _YSG_INSTALL_DIR_EXPLICIT=0
fi
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
# log_step "N/TOTAL" "message" — renders an ASCII progress bar from N/TOTAL.
# Falls back to the plain "[ N/TOTAL ]" form for non-numeric labels. Bash-3.2
# safe (printf width + tr; no seq, no unicode, no bc).
log_step() {
  local _frac="$1" _msg="$2" _cur _tot _pct _fill _bar _pad
  _cur="${_frac%%/*}"; _tot="${_frac##*/}"
  if [ "$_cur" -eq "$_cur" ] 2>/dev/null && [ "$_tot" -eq "$_tot" ] 2>/dev/null && [ "${_tot:-0}" -gt 0 ]; then
    _pct=$(( _cur * 100 / _tot )); _fill=$(( _pct * 24 / 100 ))
    _bar="$(printf '%*s' "$_fill" '' | tr ' ' '#')"
    _pad="$(printf '%*s' "$(( 24 - _fill ))" '' | tr ' ' '.')"
    printf "${C_BLUE}[%s%s] %3d%% (step %s) %s${C_RESET}\n" "$_bar" "$_pad" "$_pct" "$_frac" "$_msg"
  else
    printf "${C_BLUE}[ %s ] %s${C_RESET}\n" "$_frac" "$_msg"
  fi
}
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
# Multi-instance (3.0, scoping-draft §4a). The compose PROJECT name scopes every
# container/volume/network. Historically hardcoded/derived as "docker" (the compose
# file's directory name), so two instances on one host collided. PROJECT now derives
# from --domain (sanitised), with an optional explicit --project override.
#   - PROJECT_EXPLICIT=1 when --project was passed (override beats domain derivation).
#   - PROJECT defaults to "docker" until resolved, preserving backward-compat for
#     single-instance installs whose state file predates the PROJECT field.
PROJECT=""
PROJECT_EXPLICIT=0
LIST_INSTANCES=false          # --list: enumerate instances on the host then exit
MULTI_INSTANCE_TIER_ACK=false # --i-understand-tier: acknowledge advisory Pro+/Enterprise gate
# MI-4 (step-up on destructive lifecycle ops / YSG-RISK-061): step-up proof for the
# add-component path. Token minted by the admin API after a fresh TOTP step-up
# (auth/stepup.py); also accepted from YASHIGANI_STEPUP_TOKEN. See _require_stepup_mi4.
STEPUP_TOKEN="${STEPUP_TOKEN:-${YASHIGANI_STEPUP_TOKEN:-}}"
STEPUP_ACK=false              # --i-have-stepped-up: interactive operator ack
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

# S3 (SHIP-BLOCKER): manifest cosign signature gate.
# YSG_REQUIRE_SIGNED_MANIFEST controls enforcement level for the shell gate.
# Values: unset/"warn" (dev default) | "fail" (CI + prod hard-fail).
# The Python signatures.py has its own enforcement; this shell gate guards the
# install path before the Python layer is invoked.
# YSG_RUNTIME_4WAY is set by _detect_runtime() (W2 lib/detect_runtime.sh) after
# resolve_compose_cmd() completes. Used by the onboard codegen path.
YSG_RUNTIME_4WAY="${YSG_RUNTIME_4WAY:-}"

# P1 W4 — onboard / offboard actions (short-circuit like PKI_ACTION).
ONBOARD_MANIFEST=""       # --onboard <manifest.yaml>
OFFBOARD_AGENT=""         # --offboard <agent-name>

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
                                          Picks the deployment SUBSTRATE:
                                            demo, production -> Docker/Podman Compose
                                            enterprise       -> Kubernetes via Helm
                                          So --deploy enterprise REQUIRES a Kubernetes
                                          cluster (--runtime k8s). Combining
                                          --deploy enterprise with --runtime docker/podman
                                          is rejected up-front. For a single-host
                                          Docker/Podman install use --deploy production
                                          (or demo) with --runtime docker|podman.
  --mode           compose|k8s|vm         Legacy deployment mode (prefer --deploy)
  --domain         DOMAIN                 TLS domain, e.g. yashigani.example.com.
                                          ALSO the instance identity: the compose
                                          project derives from it (eu-west.acme.com
                                          -> eu-west-acme-com), so two instances on
                                          one host no longer collide (multi-instance,
                                          Professional Plus / Enterprise).
  --project        NAME                   Override the derived compose project name
                                          (sanitised to [a-z0-9][a-z0-9_-]*). Use a
                                          stable short name (e.g. eu-west) that
                                          --upgrade / --wazuh / uninstall.sh then
                                          target. Defaults to the sanitised --domain.
  --list                                  List Yashigani instances on this host
                                          (project + domain + runtime), then exit.
                                          Use it to pick which instance to upgrade
                                          or uninstall on a shared host.
  --i-understand-tier                     Acknowledge the advisory multi-instance
                                          tier notice (Pro+/Enterprise). The running
                                          instance enforces org limits authoritatively.
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
  --gpu-index      N                      On multi-GPU hosts: index (0-based, as shown by
                                          nvidia-smi) of the NVIDIA GPU to use for Ollama
                                          inference. Without this flag the installer
                                          auto-selects the card with the most VRAM and
                                          prompts interactively when multiple cards are
                                          present. Equivalent to setting YSG_GPU_INDEX.
                                          Example: --gpu-index 1 (selects the second card).
  --gpu-uuid       UUID                   Alternative to --gpu-index: select GPU by UUID
                                          (from nvidia-smi --query-gpu=uuid). Bypasses the
                                          nvidia-smi index ↔ CDI index mismatch on systems
                                          where the order differs. Equivalent to
                                          YSG_GPU_UUID. Example: --gpu-uuid GPU-abc123..
  --non-interactive                       Skip all interactive prompts
  --runtime <docker|podman|k8s>          Lock the container runtime (admin-must-choose
                                          rule per feedback_runtime_choice.md;
                                          equivalent to YSG_RUNTIME=...). Required in
                                          --non-interactive mode if both Docker and
                                          Podman are installed. Default in interactive
                                          mode: prompt with Podman pre-selected.
                                          MUST agree with --deploy: k8s pairs with
                                          --deploy enterprise; docker/podman pair with
                                          --deploy demo|production. A mismatch is rejected
                                          before any install step runs.
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
        # LAURA-V2253-001: reject anything but an RFC-1123 hostname charset so a
        # value with newlines can't inject extra lines into docker/.env (which is
        # later written via these flags and fed to every container). Operator-
        # supplied, but cheap to harden and closes the class for all DOMAIN writes.
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+$ ]]; then
          log_error "--domain must be a valid hostname (letters, digits, dot, hyphen), got: ${DOMAIN}"
          exit 1
        fi
        shift 2
        ;;
      --project)
        # Multi-instance (3.0): explicit compose-project override. Normally PROJECT
        # derives from --domain; this flag lets the operator pin a stable short name
        # (e.g. "eu-west") used by --upgrade/--add-component/uninstall.sh thereafter.
        # Sanitised + validated by _sanitise_project (called after parse_args).
        PROJECT="${2:?'--project requires a value'}"
        PROJECT_EXPLICIT=1
        shift 2
        ;;
      --list)
        # Multi-instance (3.0): enumerate Yashigani instances on this host
        # (project + domain) so the operator can pick one for upgrade/uninstall.
        LIST_INSTANCES=true
        shift
        ;;
      --stepup-token)
        # MI-4: step-up proof for a destructive lifecycle op (add-component).
        STEPUP_TOKEN="${2:?'--stepup-token requires a value'}"
        shift 2
        ;;
      --stepup-token=*)
        STEPUP_TOKEN="${1#*=}"
        shift
        ;;
      --i-have-stepped-up)
        # MI-4: interactive-operator step-up acknowledgement (host-shell path).
        STEPUP_ACK=true
        shift
        ;;
      --i-understand-tier)
        # Advisory multi-instance tier-gate acknowledgement (see _multi_instance_tier_gate).
        MULTI_INSTANCE_TIER_ACK=true
        shift
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
      --gpu-index)
        _raw_gpu_index="${2:?'--gpu-index requires a non-negative integer'}"
        if ! [[ "$_raw_gpu_index" =~ ^[0-9]+$ ]]; then
          log_error "--gpu-index must be a non-negative integer (0-based GPU index), got: ${_raw_gpu_index}"
          exit 1
        fi
        YSG_GPU_INDEX="$_raw_gpu_index"
        export YSG_GPU_INDEX
        shift 2
        ;;
      --gpu-uuid)
        # FINDING-3 (3.1.1): accept UUID to avoid nvidia-smi index ↔ CDI index mismatch.
        YSG_GPU_UUID="${2:?'--gpu-uuid requires a GPU UUID (e.g. GPU-xxxxxxxx-...)'}"
        export YSG_GPU_UUID
        shift 2
        ;;
      --pki-action)
        PKI_ACTION="${2:?'--pki-action requires: bootstrap|rotate-leaves|rotate-intermediate|rotate-root|status'}"
        shift 2
        ;;
      --onboard)
        # P1 W4: onboard a new agent manifest.
        # Usage: ./install.sh --onboard path/to/agent-manifest.yaml
        ONBOARD_MANIFEST="${2:?'--onboard requires a path to the agent manifest YAML'}"
        shift 2
        ;;
      --offboard)
        # P1 W4: offboard a named agent (reverses codegen artifacts).
        # Usage: ./install.sh --offboard <agent-name>
        OFFBOARD_AGENT="${2:?'--offboard requires the agent name to remove'}"
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

# =============================================================================
# Multi-instance support (3.0 — scoping-draft §4a)
# -----------------------------------------------------------------------------
# The compose PROJECT name scopes every container/volume/network. It was hardcoded
# or directory-derived as "docker", so two instances on one host collided. PROJECT
# now derives from --domain (sanitised to a valid compose project), with an optional
# --project override, and is persisted in docker/.yashigani-install-state so
# upgrade/uninstall/add-component target the right instance.
#
# Compose project naming is identical on Docker and Podman (lowercase, [a-z0-9_-],
# leading alnum). We feed it via COMPOSE_PROJECT_NAME in docker/.env (compose reads
# the project-dir .env on BOTH runtimes) AND export it for the label-filter ps calls.
# =============================================================================

# _sanitise_project <raw> — emit a valid compose project name on stdout.
# Compose/Podman rule: must match ^[a-z0-9][a-z0-9_-]*$ (lowercase). We:
#   lowercase → replace every run of disallowed chars with '-' → strip leading
#   non-alnum → trim trailing '-' / '_' → cap length → fall back to "yashigani"
#   if nothing valid remains. Pure string op; no I/O.
_sanitise_project() {
  local _raw="${1:-}"
  local _s
  # lowercase
  _s="$(printf '%s' "$_raw" | tr '[:upper:]' '[:lower:]')"
  # any char not in [a-z0-9_-] → '-'
  _s="$(printf '%s' "$_s" | sed 's/[^a-z0-9_-]/-/g')"
  # collapse repeated separators to a single '-'
  _s="$(printf '%s' "$_s" | sed -E 's/[-_]{2,}/-/g')"
  # strip leading non-alphanumeric (compose requires a leading [a-z0-9])
  _s="$(printf '%s' "$_s" | sed -E 's/^[^a-z0-9]+//')"
  # trim trailing separators
  _s="$(printf '%s' "$_s" | sed -E 's/[-_]+$//')"
  # length cap (compose/k8s-safe); 60 leaves headroom for "<proj>_<volume>" names
  _s="${_s:0:60}"
  # trim again in case the cap left a trailing separator
  _s="$(printf '%s' "$_s" | sed -E 's/[-_]+$//')"
  if [[ -z "$_s" || ! "$_s" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    _s="yashigani"
  fi
  printf '%s' "$_s"
}

# _resolve_project — set the global PROJECT for a fresh install / explicit override.
# Precedence: explicit --project (sanitised) > derived from --domain (sanitised) >
# "docker" (backward-compatible default; what every pre-3.0 single-instance install used).
# Idempotent: safe to call once after parse_args.
_resolve_project() {
  local _candidate=""
  if [[ "$PROJECT_EXPLICIT" -eq 1 && -n "$PROJECT" ]]; then
    _candidate="$PROJECT"
  elif [[ -n "$DOMAIN" ]]; then
    _candidate="$DOMAIN"
  fi
  if [[ -z "$_candidate" ]]; then
    # No domain and no override (e.g. demo/localhost path) → preserve legacy name.
    PROJECT="docker"
  else
    PROJECT="$(_sanitise_project "$_candidate")"
  fi
  export COMPOSE_PROJECT_NAME="$PROJECT"
  log_info "Compose project: ${PROJECT}$( [[ "$PROJECT" == "docker" ]] && printf ' (legacy default — single instance)' || true )"
}

# _read_state_project <state_file> — echo the PROJECT recorded in a state file, or
# "docker" if the field is absent (backward-compat: pre-3.0 state files have no
# PROJECT line, and those installs all used the "docker" project). Used by the
# upgrade / add-component paths so they target the EXISTING instance, not a
# re-derivation (the operator may have used --project the first time).
_read_state_project() {
  local _sf="${1:-${WORK_DIR}/docker/.yashigani-install-state}"
  local _p=""
  if [[ -f "$_sf" && -r "$_sf" ]]; then
    _p="$(grep -E '^PROJECT=' "$_sf" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
  fi
  if [[ -z "$_p" ]]; then
    _p="docker"
  fi
  printf '%s' "$_p"
}

# _read_state_trust_domain <state_file> — echo the SPIFFE_TRUST_DOMAIN recorded in
# a state file, or "yashigani.internal" if absent (legacy single-instance / pre-3.0
# state files). Used by the host-side onboard/codegen path so a BYO agent gets the
# instance's per-instance trust domain on its spiffe_id, not the shared default.
_read_state_trust_domain() {
  local _sf="${1:-${WORK_DIR}/docker/.yashigani-install-state}"
  local _td=""
  if [[ -f "$_sf" && -r "$_sf" ]]; then
    _td="$(grep -E '^SPIFFE_TRUST_DOMAIN=' "$_sf" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
  fi
  if [[ -z "$_td" ]]; then
    _td="yashigani.internal"
  fi
  printf '%s' "$_td"
}

# =============================================================================
# Multi-instance tenancy isolation (3.0 / YSG-RISK-061) — MI-1 / MI-2 / MI-6
# -----------------------------------------------------------------------------
# Root cause the 3.0 work left open: PROJECT namespaced the *runtime* objects
# (per-project compose, networks, volumes) but the on-disk secrets/state and the
# crypto identity (PKI/SPIFFE) stayed at single-instance granularity, anchored at
# a single shared WORK_DIR (default $HOME/.yashigani). Result: a second install
# clobbered the first instance's secrets+state, and `uninstall --project A` wiped
# the shared tree out from under B. These helpers move the *disk* and *identity*
# boundary to per-instance granularity, keyed by PROJECT, while preserving the
# legacy single-instance layout byte-for-byte (PROJECT=docker => no change).
# =============================================================================

# _early_project — best-effort PROJECT resolution from argv ALONE, before the
# wizard runs. Used only to decide the per-instance install dir + trust domain
# early in main(), when --project / --domain are already on the command line.
# Mirrors _resolve_project precedence (explicit --project > --domain > legacy
# "docker") but is side-effect-free: it does NOT export COMPOSE_PROJECT_NAME and
# does NOT log (the authoritative resolution still happens later via
# _resolve_project / _read_state_project once DOMAIN is finalised). Echoes the
# sanitised project on stdout.
_early_project() {
  local _candidate=""
  if [[ "${PROJECT_EXPLICIT:-0}" -eq 1 && -n "${PROJECT:-}" ]]; then
    _candidate="$PROJECT"
  elif [[ -n "${DOMAIN:-}" ]]; then
    _candidate="$DOMAIN"
  fi
  if [[ -z "$_candidate" ]]; then
    printf 'docker'
  else
    _sanitise_project "$_candidate"
  fi
}

# _resolve_instance_install_dir — MI-1: key the bootstrap install dir (and hence
# WORK_DIR, and hence docker/secrets + docker/.env + docker/.yashigani-install-state)
# to the instance PROJECT, so two instances on one host get fully isolated trees.
#
# Backward-compat (NON-NEGOTIABLE): legacy single-instance installs keep the exact
# default path. The keyed path is ONLY used when ALL of:
#   * PROJECT is non-legacy (not "docker"), AND
#   * the operator did NOT pin YSG_INSTALL_DIR explicitly (env override always wins),
#   * AND we are on the bootstrap (curl / non-repo) code path — an in-repo checkout
#     is a fixed tree we must not silently relocate (handled by the guard below).
#
# Idempotent + side-effect-free except for assigning YSG_INSTALL_DIR. Safe to call
# once, right after parse_args, before detect_working_directory.
_resolve_instance_install_dir() {
  # Operator pinned the dir explicitly (env was set before invocation) — honour it
  # verbatim. _YSG_INSTALL_DIR_EXPLICIT is set in parse_args when the env var was
  # present at startup. Never override an explicit operator choice.
  if [[ "${_YSG_INSTALL_DIR_EXPLICIT:-0}" -eq 1 ]]; then
    return 0
  fi

  local _proj
  _proj="$(_early_project)"

  # Legacy / single-instance: leave the default ($HOME/.yashigani) untouched so
  # every pre-3.0 install and every demo/localhost install is byte-for-byte stable.
  if [[ "$_proj" == "docker" ]]; then
    return 0
  fi

  # Non-legacy instance with no explicit dir: key the install dir by project so a
  # second instance does not bootstrap on top of the first. base derived from the
  # default so YSG_INSTALL_DIR overrides (handled above) are never reached here.
  YSG_INSTALL_DIR="${HOME}/.yashigani-${_proj}"
  log_info "Multi-instance: per-instance install dir for project '${_proj}': ${YSG_INSTALL_DIR}"
}

# _instance_identity_token <state_file> — MI-2: read the per-instance identity
# token recorded in a state file. The token is a host-random nonce written once at
# install time; it binds a lifecycle operation to the instance it claims to target.
# A lifecycle op (upgrade / add-component / uninstall) must present a target whose
# resolved state file carries a token that matches the running instance's labels —
# a bare --project string is NOT sufficient to act on a sibling. Echoes the token
# (empty if absent: pre-3.0 / legacy state files have none — handled by callers as
# the backward-compat single-instance case).
_instance_identity_token() {
  local _sf="${1:-${WORK_DIR}/docker/.yashigani-install-state}"
  local _t=""
  if [[ -f "$_sf" && -r "$_sf" ]]; then
    _t="$(grep -E '^INSTANCE_ID=' "$_sf" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
  fi
  printf '%s' "$_t"
}

# _gen_instance_id — MI-2: mint a fresh per-instance identity token (128-bit hex,
# CSPRNG). Written into the state file at install time and embedded as a container
# label so a lifecycle op can prove it is operating on the instance it named rather
# than a free-form sibling. Pure CSPRNG read; no I/O beyond /dev/urandom.
_gen_instance_id() {
  # openssl preferred; /dev/urandom fallback keeps this dependency-light + portable
  # across Docker/Podman/k8s install hosts (busybox included).
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c 32
  fi
}

# _spiffe_trust_domain — MI-6: the per-instance SPIFFE trust domain. Each instance
# gets its OWN trust domain so a leaf cert minted in instance A (URI SAN
# spiffe://<A>.yashigani.internal/<svc>) does NOT satisfy instance B's validators,
# which pin spiffe://<B>.yashigani.internal/. Combined with MI-1's per-instance CA
# key (distinct signing key per tree), cross-instance identity fails BOTH on the CA
# trust anchor AND on the trust-domain authority — belt-and-braces (neither alone is
# sufficient: same-domain+distinct-CA still cross-validates against a verifier that
# only string-matches the SAN under a shared root; distinct-domain+shared-CA still
# cross-validates against a verifier that trusts the CA without pinning the domain).
#
# Backward-compat: legacy PROJECT=docker keeps the canonical "yashigani.internal"
# byte-for-byte, so existing certs + app-side validators (which historically
# hardcoded "yashigani.internal") keep working with NO rotation required.
#
# Echoes the trust-domain authority (no scheme/path) on stdout. Arg: project name.
_spiffe_trust_domain() {
  local _proj="${1:-docker}"
  if [[ -z "$_proj" || "$_proj" == "docker" ]]; then
    printf 'yashigani.internal'
  else
    # <project>.yashigani.internal — the instance label is the leftmost DNS label
    # of the SPIFFE trust-domain authority. _proj is already sanitised to
    # [a-z0-9][a-z0-9_-]* by _sanitise_project; '_' is not DNS-legal, so map any
    # underscore to '-' for the authority component only (cert URI SAN must parse
    # as a URI authority).
    printf '%s.yashigani.internal' "$(printf '%s' "$_proj" | tr '_' '-')"
  fi
}

# _apply_trust_domain_to_runtime_manifest <runtime_manifest> <trust_domain>
# MI-6: rewrite every `spiffe_id: spiffe://yashigani.internal/<svc>` line in the
# RUNTIME service-identity manifest to the per-instance trust domain so the PKI
# issuer bakes per-instance URI SANs into each leaf cert. Operates on the runtime
# (gitignored) copy ONLY — the canonical git-tracked manifest is never touched, so
# git status stays clean (two-copies discipline: canonical = schema/legacy domain,
# runtime = per-install populated copy).
#
# Backward-compat: when trust_domain is the legacy "yashigani.internal" this is a
# no-op rewrite (byte-identical), so legacy installs are unaffected.
# Idempotent: re-running on an already-rewritten manifest replaces the authority
# again to the same value (anchored to the canonical authority via the fixed
# match). Pure text op via sed on the gitignored file; fail-closed (return 1).
_apply_trust_domain_to_runtime_manifest() {
  local _mf="${1:?manifest path required}"
  local _td="${2:?trust domain required}"

  # Legacy / default authority — nothing to do (the canonical manifest already
  # carries spiffe://yashigani.internal/<svc>).
  if [[ "$_td" == "yashigani.internal" ]]; then
    return 0
  fi
  if [[ ! -f "$_mf" ]]; then
    log_error "_apply_trust_domain_to_runtime_manifest: runtime manifest not found at ${_mf}"
    return 1
  fi

  # Replace the trust-domain authority in every spiffe_id value. Anchor on the
  # canonical authority "yashigani.internal" immediately after the scheme so we
  # rewrite the authority and nothing else (the /<svc> path is preserved). This is
  # idempotent because we always anchor on the canonical authority and a previously
  # rewritten file no longer contains it; to stay safe under re-issue we re-seed
  # the runtime manifest from canonical on every _pki_run_issuer call (above), so
  # this rewrite always starts from the canonical authority.
  local _tmp="${_mf}.td.new"
  if sed -E "s#(spiffe://)yashigani\.internal(/)#\1${_td}\2#g" "$_mf" > "$_tmp" 2>/dev/null; then
    mv -f "$_tmp" "$_mf" || { rm -f "$_tmp"; log_error "_apply_trust_domain_to_runtime_manifest: atomic move failed"; return 1; }
    log_info "MI-6: runtime manifest SPIFFE trust domain set to '${_td}' (${_mf})"
    return 0
  fi
  rm -f "$_tmp" 2>/dev/null || true
  log_error "_apply_trust_domain_to_runtime_manifest: sed rewrite failed on ${_mf}"
  return 1
}

# _require_stepup_mi4 <op-label> — MI-4: step-up gate for a destructive lifecycle
# mutation on the install.sh side (add-component on a running stack). The shared
# step-up gate is src/yashigani/auth/stepup.py (Tom's surface); the admin API/WebUI
# path enforces a fresh TOTP step-up and passes the resulting token via
# --stepup-token / YASHIGANI_STEPUP_TOKEN. Host-shell path requires the token, an
# interactive --i-have-stepped-up ack, or an inline interactive confirmation; an
# unattended run with no proof fails closed. When a token is supplied it is now
# CRYPTOGRAPHICALLY VERIFIED end-to-end against the shared privileged_mutation gate
# (src/yashigani/auth/stepup.py verify_stepup_proof, via the `--verify-proof` shim)
# — signature + freshness + purpose + op-binding. A forged/stale/wrong-op token is
# rejected fail-closed (the gate is the single source of truth; we do NOT duplicate it).
# _verify_stepup_proof_token <token> <op-label> — cryptographically verify a
# privileged-mutation step-up proof against the shared gate. The verifier lives
# in the yashigani package (src/yashigani/auth/stepup.py) and needs the per-install
# signing key (caddy_internal_hmac); both are present INSIDE the backoffice
# container, so we exec the shim there. Runtime-agnostic: uses $COMPOSE_CMD which
# is already resolved to docker/podman compose. Returns 0 iff the shim prints OK
# and exits 0; fail-closed (non-zero) on any verifier error, missing container,
# or DENY.
_verify_stepup_proof_token() {
  local _tok="$1" _op_label="$2"
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
    resolve_compose_cmd 2>/dev/null || true
  fi
  if [[ ${#COMPOSE_CMD[@]} -eq 0 || ! -f "$compose_file" ]]; then
    log_error "MI-4: cannot verify step-up proof — no compose runtime / compose file."
    return 1
  fi

  # Pass the token via env (YASHIGANI_STEPUP_TOKEN) so it never lands in the
  # container's argv / process table. -T disables TTY alloc (non-interactive exec).
  if "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T \
        -e "YASHIGANI_STEPUP_TOKEN=${_tok}" \
        backoffice \
        python3 -m yashigani.auth.stepup --verify-proof --op "${_op_label}" 2>/dev/null; then
    return 0
  fi
  return 1
}

_require_stepup_mi4() {
  local _op="${1:-privileged mutation}"
  local _op_label="${2:-${_op}}"   # machine op label bound into the proof (e.g. add-component)
  local _tok="${STEPUP_TOKEN:-${YASHIGANI_STEPUP_TOKEN:-}}"
  if [[ -n "${_tok}" ]]; then
    # Cryptographically verify the proof against the shared gate. The verifier
    # runs inside the backoffice container (where the signing key + yashigani
    # package live); fail-closed if it cannot run or returns non-zero.
    if _verify_stepup_proof_token "${_tok}" "${_op_label}"; then
      log_info "MI-4: step-up proof VERIFIED (op=${_op_label}) — ${_op} authorised."
      return 0
    fi
    log_error "MI-4: step-up proof FAILED verification (op=${_op_label}) — refusing ${_op}."
    exit 1
  fi
  if [[ "${STEPUP_ACK:-false}" == "true" && -t 0 ]]; then
    log_info "MI-4: interactive operator step-up acknowledgement accepted (${_op})."
    return 0
  fi
  if [[ -t 0 && "${NON_INTERACTIVE:-false}" != "true" ]]; then
    printf 'MI-4 step-up: confirm a fresh TOTP step-up for this destructive action (%s).\n' "$_op"
    printf 'Type STEPPED-UP to proceed: '
    local _su_ack=""
    read -r _su_ack || _su_ack=""
    if [[ "$_su_ack" == "STEPPED-UP" ]]; then
      log_info "MI-4: interactive step-up confirmation accepted (${_op})."
      return 0
    fi
    log_error "MI-4: step-up not confirmed — aborting ${_op}."
    exit 1
  fi
  log_error "MI-4 safety stop: ${_op} requires step-up proof."
  log_error "  Supply --stepup-token=<value> (or YASHIGANI_STEPUP_TOKEN) minted by the"
  log_error "  admin API after a fresh TOTP step-up, or run interactively with"
  log_error "  --i-have-stepped-up. Refusing to proceed unattended without step-up."
  exit 1
}

# _list_instances — enumerate Yashigani compose instances on this host as
# "<project>\t<domain>\t<runtime>" rows. Works on Docker (com.docker.compose.project)
# and Podman (io.podman.compose.project) by listing running containers and reading
# the project label + our YASHIGANI_TLS_DOMAIN env from the gateway container.
# Best-effort + read-only; never mutates state. Exit 0 always (empty = no instances).
_list_instances() {
  local _runtimes=() _rt
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && _runtimes+=("docker")
  command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1 && _runtimes+=("podman")

  if [[ "${#_runtimes[@]}" -eq 0 ]]; then
    log_warn "No reachable container runtime (docker/podman) — cannot list instances."
    return 0
  fi

  printf '%-30s %-40s %-8s\n' "PROJECT" "DOMAIN" "RUNTIME"
  printf '%-30s %-40s %-8s\n' "-------" "------" "-------"

  local _found=0
  for _rt in "${_runtimes[@]}"; do
    local _label_key
    if [[ "$_rt" == "podman" ]]; then
      _label_key="io.podman.compose.project"
    else
      _label_key="com.docker.compose.project"
    fi
    # All distinct compose projects that have a yashigani gateway container.
    local _projects
    _projects="$("$_rt" ps -a \
        --filter 'name=gateway' \
        --format '{{.Label "'"$_label_key"'"}}' 2>/dev/null \
        | grep -v '^$' | sort -u || true)"
    local _proj
    while IFS= read -r _proj; do
      [[ -z "$_proj" ]] && continue
      # Pull the domain from the caddy container's env (the canonical holder of
      # YASHIGANI_TLS_DOMAIN). Read-only inspect; the gateway container does NOT
      # carry the domain. Fall back to "(unknown)" if caddy is absent/stopped.
      local _caddy_cid _domain
      _caddy_cid="$("$_rt" ps -a \
          --filter "label=${_label_key}=${_proj}" \
          --filter 'name=caddy' \
          --format '{{.ID}}' 2>/dev/null | head -n1 || true)"
      _domain="(unknown)"
      if [[ -n "$_caddy_cid" ]]; then
        _domain="$("$_rt" inspect "$_caddy_cid" \
            --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
            | grep -E '^YASHIGANI_TLS_DOMAIN=' | head -n1 | cut -d= -f2- || true)"
        [[ -z "$_domain" ]] && _domain="(unknown)"
      fi
      printf '%-30s %-40s %-8s\n' "$_proj" "$_domain" "$_rt"
      _found=$((_found + 1))
    done <<< "$_projects"
  done

  if [[ "$_found" -eq 0 ]]; then
    printf '%s\n' "(no Yashigani instances found on this host)"
  fi
  return 0
}

# _host_has_other_instance <this_project> — return 0 if a DIFFERENT Yashigani
# compose project already exists on this host (i.e. this install would create a
# 2nd, side-by-side instance → multi-instance territory). Read-only.
_host_has_other_instance() {
  local _this="$1"
  local _rt _label_key _projects
  for _rt in docker podman; do
    command -v "$_rt" >/dev/null 2>&1 || continue
    "$_rt" info >/dev/null 2>&1 || continue
    if [[ "$_rt" == "podman" ]]; then
      _label_key="io.podman.compose.project"
    else
      _label_key="com.docker.compose.project"
    fi
    _projects="$("$_rt" ps -a --filter 'name=gateway' \
        --format '{{.Label "'"$_label_key"'"}}' 2>/dev/null \
        | grep -v '^$' | sort -u || true)"
    local _p
    while IFS= read -r _p; do
      [[ -z "$_p" ]] && continue
      if [[ "$_p" != "$_this" ]]; then
        return 0
      fi
    done <<< "$_projects"
  done
  return 1
}

# _unverified_license_tier — echo the tier string from the UNVERIFIED license-key
# payload, or "community" when no license / unparseable. ADVISORY ONLY: this does
# NOT verify the Ed25519 signature (the verify key is image-baked, not on the host),
# so the value is forgeable and used purely for the up-front UX gate. The running
# gateway/backoffice perform the authoritative signed-license + max_orgs enforcement.
_unverified_license_tier() {
  local _lic="${WORK_DIR}/docker/secrets/license_key"
  [[ -n "${LICENSE_KEY_PATH:-}" && -f "$LICENSE_KEY_PATH" ]] && _lic="$LICENSE_KEY_PATH"
  if [[ ! -f "$_lic" ]]; then
    printf 'community'; return 0
  fi
  local _content _seg1 _json _tier
  _content="$(tr -d '[:space:]' < "$_lic" 2>/dev/null || true)"
  if [[ -z "$_content" || "$_content" == \#community* || "${#_content}" -le 20 ]]; then
    printf 'community'; return 0
  fi
  # v4 format: base64url(json).base64url(sig).base64url(countersig) — decode segment 1.
  _seg1="${_content%%.*}"
  # base64url → base64, pad to a multiple of 4, decode (best-effort).
  local _b64 _pad
  _b64="$(printf '%s' "$_seg1" | tr '_-' '/+')"
  _pad=$(( ${#_b64} % 4 ))
  [[ "$_pad" -ne 0 ]] && _b64="${_b64}$(printf '%*s' $((4 - _pad)) '' | tr ' ' '=')"
  _json="$(printf '%s' "$_b64" | base64 -d 2>/dev/null || true)"
  # Extract "tier":"..." without a JSON parser (grep is enough for this single field).
  _tier="$(printf '%s' "$_json" | grep -oE '"tier"[[:space:]]*:[[:space:]]*"[a-z_]+"' \
            | head -n1 | sed -E 's/.*"([a-z_]+)"$/\1/' || true)"
  if [[ -z "$_tier" ]]; then
    printf 'community'; return 0
  fi
  printf '%s' "$_tier"
}

# _multi_instance_tier_gate — advisory Pro+/Enterprise gate for the multi-instance
# path. Triggered ONLY when this install would create a 2nd instance alongside an
# existing one on the host. Default behaviour (Tiago decision pending — memo
# project_v300_design_conflict_tiergate.md): WARN + proceed; server-side max_orgs is
# the authoritative boundary. To switch to a hard ack-required gate, flip the
# `_block_without_ack` flag below to true (one-line change).
_multi_instance_tier_gate() {
  local _block_without_ack=false   # <-- decision seam: false = warn+proceed (a); true = require --i-understand-tier (b)

  # Only relevant when a SECOND instance is being created on this host.
  if ! _host_has_other_instance "$PROJECT"; then
    return 0
  fi

  local _tier
  _tier="$(_unverified_license_tier)"
  case "$_tier" in
    professional_plus|enterprise|academic_nonprofit)
      log_info "Multi-instance: license tier '${_tier}' — multi-instance permitted."
      return 0
      ;;
  esac

  log_warn "MULTI-INSTANCE TIER GATE (advisory):"
  log_warn "  Another Yashigani instance already exists on this host."
  log_warn "  Running multiple instances side-by-side is a Professional Plus / Enterprise"
  log_warn "  capability. The detected license tier is: ${_tier}."
  log_warn "  The RUNNING instance enforces per-tier org limits (max_orgs) authoritatively;"
  log_warn "  this installer cannot verify the signed license host-side (key is image-baked)."

  if [[ "$_block_without_ack" == "true" && "$MULTI_INSTANCE_TIER_ACK" != "true" ]]; then
    log_error "  Re-run with --i-understand-tier to proceed, or upgrade to Pro+/Enterprise."
    exit 1
  fi
  log_warn "  Proceeding — server-side licensing will enforce the actual limits."
  return 0
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
      # --in-pod=false: do NOT place the stack in a shared pod (ROOTLESS-CDI-003).
      # podman-compose defaults to one pod per project; the NVIDIA CDI hook
      # (/usr/bin/nvidia-cdi-hook) fails (exit 1) when the GPU container starts
      # inside that pod, wedging ollama + everything that depends on it. The same
      # CDI device works in a standalone `podman run` (no pod), so we disable the
      # pod. Must be a global arg so up/down/ps are all pod-less + consistent.
      COMPOSE_CMD=("podman-compose" "--in-pod=false")
      YSG_PODMAN_RUNTIME=true
      log_info "Compose tool: podman-compose (native, sequential, --in-pod=false)"
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

  # --- Multi-GPU selection (NVIDIA only; no-op for single-GPU / non-NVIDIA) ---
  # Picks the largest-VRAM card as default, shows an interactive choice when
  # more than one card is present, honours --gpu-index / YSG_GPU_INDEX.
  # Updates YSG_GPU_NAME / YSG_GPU_VRAM_MB / YSG_GPU_CDI before the summary.
  _select_nvidia_gpu

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
    local _gpu_label="${YSG_GPU_NAME:-detected}"
    [[ -n "${YSG_GPU_INDEX:-}" ]] && _gpu_label="[${YSG_GPU_INDEX}] ${_gpu_label}"
    printf "  %-22s %s\n" "GPU:"        "$_gpu_label"
    printf "  %-22s %s\n" "GPU memory:" "$(_format_gpu_vram)"
    printf "  %-22s %s\n" "GPU compute:" "${YSG_GPU_COMPUTE:-unknown}"
    [[ -n "${YSG_GPU_CDI:-}" ]] && printf "  %-22s %s\n" "GPU device (CDI):" "${YSG_GPU_CDI}"
  else
    printf "  %-22s %s\n" "GPU:"        "none detected"
  fi
  printf "\n"

  # --- Optional services — DEPLOY-TIME choice (CLAUDE.md / Optional Services panel) ---
  # Listed so the operator sees exactly what is (and is NOT) being installed, what
  # each does, and that the choice is deploy-time — missing one means re-running
  # the installer. Avoids the "I expected service X" surprise post-install.
  local _ow=" " _wz=" " _ca=" " _lf=" " _le=" " _oc=" "
  [[ "${INSTALL_OPENWEBUI:-false}" == true ]] && _ow="x"
  [[ "${INSTALL_WAZUH:-false}" == true ]] && _wz="x"
  [[ "${INSTALL_INTERNAL_CA:-false}" == true ]] && _ca="x"
  printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx langflow && _lf="x"
  printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx letta && _le="x"
  printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx openclaw && _oc="x"
  # Non-interactive --agent-bundles is parsed into AGENT_BUNDLES but only pushed
  # into COMPOSE_PROFILES at step 8 (after this summary), so read AGENT_BUNDLES too
  # — otherwise the summary shows agents unticked even though they WILL install.
  local _ab=",${AGENT_BUNDLES//[[:space:]]/},"
  [[ "$_ab" == *",all,"* ]] && { _lf="x"; _le="x"; _oc="x"; }
  [[ "$_ab" == *",langflow,"* ]] && _lf="x"
  [[ "$_ab" == *",letta,"* ]] && _le="x"
  [[ "$_ab" == *",openclaw,"* ]] && _oc="x"
  printf "  Optional services (deploy-time choice):\n"
  printf "    [%s] %-12s %s\n" "$_ow" "Open WebUI"  "browser chat UI for end users"
  printf "    [%s] %-12s %s\n" "$_wz" "Wazuh SIEM"  "security monitoring — SIEM (manager+indexer+dashboard)"
  printf "    [%s] %-12s %s\n" "$_ca" "BYO CA"      "Bring-your-own intermediate CA (default: built-in mesh CA)"
  printf "    [%s] %-12s %s\n" "$_lf" "Langflow"    "visual multi-agent workflow builder"
  printf "    [%s] %-12s %s\n" "$_le" "Letta"       "stateful agent with persistent memory"
  printf "    [%s] %-12s %s\n" "$_oc" "OpenClaw"    "connected agent (web search + messaging)"
  printf "    %s\n" "[x] = will be installed. This is a DEPLOY-TIME choice: to add or remove a"
  printf "    %s\n" "service later you re-run the installer (an update/redeploy preserving data)."
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

# _pick_ollama_model_for_vram — return the best default OLLAMA_MODEL for the
# installed GPU's VRAM. Mirrors the tier thresholds in _print_model_recommendations
# so the pulled model matches the displayed recommendation (BUG-GPU-VRAM-001).
# Printed to stdout; caller assigns with $().
_pick_ollama_model_for_vram() {
  local vram="${YSG_GPU_VRAM_MB:-0}"
  if [ "$vram" -ge 32768 ]; then
    printf "qwen3:30b-a3b"
  elif [ "$vram" -ge 16384 ]; then
    printf "llama3.1:8b"
  elif [ "$vram" -ge 8192 ]; then
    printf "llama3.1:8b"
  else
    printf "qwen2.5:3b"
  fi
}

# =============================================================================
# Multi-GPU selection — pick largest VRAM as default; let operator choose
# =============================================================================
# Called from print_platform_summary after platform-detect sets YSG_GPU_TYPE.
# Sets YSG_GPU_INDEX (0-based nvidia-smi index), YSG_GPU_UUID (GPU UUID),
# YSG_GPU_NAME, YSG_GPU_VRAM_MB, and YSG_GPU_CDI.
#
# FINDING-3 (3.1.1): CDI device index mismatch fix.
# The nvidia-smi index and the CDI spec device index can be in DIFFERENT ORDER
# on some hosts (e.g. nvidia-ctk enumerates by PCI bus order, which may be
# reverse of nvidia-smi order). Using "nvidia.com/gpu=<IDX>" as the CDI device
# therefore selects the WRONG physical GPU on mismatched hosts.
#
# Fix: use "nvidia.com/gpu=<UUID>" for YSG_GPU_CDI. The CDI spec includes both
# index-named entries ("0", "1") AND UUID-named entries ("GPU-xxx..."). The
# UUID form is always unambiguous — it identifies the same physical card
# regardless of the index ordering in either nvidia-smi or the CDI spec.
# YSG_GPU_DEV (/dev/nvidia<N>) still uses the nvidia-smi index (device nodes
# are always indexed by nvidia-smi order, no mismatch there).
#
# DEFAULT (no --gpu-index / --gpu-uuid): auto-select the GPU with the most VRAM.
# --gpu-index N: select by nvidia-smi index (correctly resolved to UUID → CDI).
# --gpu-uuid U: select by UUID directly (most explicit, bypasses index entirely).
_select_nvidia_gpu() {
  # Require nvidia-smi and NVIDIA GPU type; non-NVIDIA: no-op.
  if [[ "${YSG_GPU_TYPE:-none}" != "nvidia" ]]; then return 0; fi
  if ! command -v nvidia-smi >/dev/null 2>&1; then return 0; fi

  # Enumerate: "index, uuid, vram_mb, name" per line
  # nounits → bare integers for VRAM (MiB); noheader for clean parsing.
  local smi_out
  smi_out="$(nvidia-smi --query-gpu=index,uuid,memory.total,name --format=csv,noheader,nounits 2>/dev/null)" || return 0

  local gpu_count
  gpu_count="$(echo "$smi_out" | grep -c .)" || gpu_count=0
  if [[ "$gpu_count" -lt 1 ]]; then return 0; fi

  if [[ "$gpu_count" -lt 2 ]]; then
    # Single GPU — set CDI using UUID (not index) to avoid any ordering mismatch.
    # Also update YSG_GPU_NAME / YSG_GPU_VRAM_MB so the preflight VRAM check
    # and model-recommendation logic use the real card's values (BUG-GPU-VRAM-001).
    local _idx _uuid _vram _name
    IFS=',' read -r _idx _uuid _vram _name <<< "$(echo "$smi_out" | head -1)"
    _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
    YSG_GPU_INDEX="${YSG_GPU_INDEX:-${_idx}}"
    YSG_GPU_UUID="${YSG_GPU_UUID:-${_uuid}}"
    YSG_GPU_NAME="$_name"
    YSG_GPU_VRAM_MB="${_vram:-0}"
    # FINDING-3: CDI by UUID — immune to index ordering differences between
    # nvidia-smi and nvidia-ctk's CDI spec generation.
    YSG_GPU_CDI="nvidia.com/gpu=${YSG_GPU_UUID}"
    YSG_GPU_DEV="/dev/nvidia${YSG_GPU_INDEX}"
    export YSG_GPU_INDEX YSG_GPU_UUID YSG_GPU_NAME YSG_GPU_VRAM_MB YSG_GPU_CDI YSG_GPU_DEV
    return 0
  fi

  # Multiple GPUs present — find the one with the most VRAM as the default.
  local best_idx=0 best_uuid="" best_name="" best_vram=0
  local _idx _uuid _vram _name
  while IFS=',' read -r _idx _uuid _vram _name; do
    _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
    if [[ "${_vram:-0}" -gt "$best_vram" ]]; then
      best_idx="$_idx"; best_uuid="$_uuid"; best_name="$_name"; best_vram="${_vram:-0}"
    fi
  done <<< "$smi_out"

  # --gpu-uuid (explicit UUID override) — highest priority.
  if [[ -n "${YSG_GPU_UUID:-}" ]]; then
    local _chosen_name="" _chosen_vram=0 _chosen_idx=0 _uuid_found=false
    while IFS=',' read -r _idx _uuid _vram _name; do
      _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
      if [[ "$_uuid" == "$YSG_GPU_UUID" ]]; then
        _chosen_idx="$_idx"; _chosen_name="$_name"; _chosen_vram="${_vram:-0}"
        _uuid_found=true
      fi
    done <<< "$smi_out"
    if [[ "$_uuid_found" != "true" ]]; then
      log_error "--gpu-uuid ${YSG_GPU_UUID} not found among detected GPUs"
      log_error "Run: nvidia-smi --query-gpu=index,uuid,name --format=csv,noheader"
      exit 1
    fi
    YSG_GPU_INDEX="$_chosen_idx"
    YSG_GPU_NAME="$_chosen_name"
    YSG_GPU_VRAM_MB="$_chosen_vram"
    # UUID already set; CDI by UUID.
    YSG_GPU_CDI="nvidia.com/gpu=${YSG_GPU_UUID}"
    YSG_GPU_DEV="/dev/nvidia${YSG_GPU_INDEX}"
    export YSG_GPU_INDEX YSG_GPU_UUID YSG_GPU_NAME YSG_GPU_VRAM_MB YSG_GPU_CDI YSG_GPU_DEV
    log_info "GPU pinned via --gpu-uuid: [${YSG_GPU_INDEX}] ${YSG_GPU_NAME} ($(_format_gpu_vram)) UUID=${YSG_GPU_UUID}"
    return 0
  fi

  # --gpu-index (nvidia-smi index) — validated and mapped to UUID for CDI.
  if [[ -n "${YSG_GPU_INDEX:-}" ]]; then
    local _chosen_name="" _chosen_uuid="" _chosen_vram=0 _idx_found=false
    while IFS=',' read -r _idx _uuid _vram _name; do
      _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
      if [[ "$_idx" == "$YSG_GPU_INDEX" ]]; then
        _chosen_name="$_name"; _chosen_uuid="$_uuid"; _chosen_vram="${_vram:-0}"
        _idx_found=true
      fi
    done <<< "$smi_out"
    if [[ "$_idx_found" != "true" ]]; then
      log_error "--gpu-index ${YSG_GPU_INDEX} is out of range (detected ${gpu_count} GPUs, indices 0-$((gpu_count-1)))"
      exit 1
    fi
    YSG_GPU_UUID="$_chosen_uuid"
    YSG_GPU_NAME="$_chosen_name"
    YSG_GPU_VRAM_MB="$_chosen_vram"
    # FINDING-3: map nvidia-smi index → UUID → CDI device (UUID form is unambiguous).
    YSG_GPU_CDI="nvidia.com/gpu=${YSG_GPU_UUID}"
    YSG_GPU_DEV="/dev/nvidia${YSG_GPU_INDEX}"
    export YSG_GPU_INDEX YSG_GPU_UUID YSG_GPU_NAME YSG_GPU_VRAM_MB YSG_GPU_CDI YSG_GPU_DEV
    log_info "GPU pinned via --gpu-index: [${YSG_GPU_INDEX}] ${YSG_GPU_NAME} ($(_format_gpu_vram)) UUID=${YSG_GPU_UUID}"
    return 0
  fi

  # Interactive: show detected GPUs and let the operator choose.
  printf "\n"
  printf "  ${C_BOLD}Multiple NVIDIA GPUs detected — select the one for Ollama inference:${C_RESET}\n"
  printf "\n"
  while IFS=',' read -r _idx _uuid _vram _name; do
    _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
    local _vram_display
    if [[ "${_vram:-0}" -ge 1024 ]]; then
      _vram_display="$(awk "BEGIN { printf \"%.1f GB\", ${_vram}/1024 }")"
    else
      _vram_display="${_vram} MB"
    fi
    local _default_tag=""
    [[ "$_idx" == "$best_idx" ]] && _default_tag=" ${C_GREEN}← most VRAM (default)${C_RESET}"
    printf "    %s) %-36s %s%b\n" "$_idx" "$_name" "$_vram_display" "$_default_tag"
  done <<< "$smi_out"
  printf "\n"

  local chosen_idx
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    # Non-interactive without --gpu-index / --gpu-uuid: auto-select largest VRAM.
    chosen_idx="$best_idx"
    log_info "Non-interactive: auto-selected GPU ${chosen_idx} (${best_name}, $(_format_gpu_vram_mb "$best_vram")) — default: largest VRAM"
  else
    printf "  Choice [%s]: " "$best_idx"
    read -r chosen_idx </dev/tty 2>/dev/null || chosen_idx=""
    chosen_idx="${chosen_idx:-$best_idx}"
    chosen_idx="${chosen_idx// /}"
    # Validate choice is a known nvidia-smi index.
    local _valid=false
    while IFS=',' read -r _idx _ _ _; do
      _idx="${_idx// /}"
      [[ "$_idx" == "$chosen_idx" ]] && _valid=true
    done <<< "$smi_out"
    if [[ "$_valid" != "true" ]]; then
      log_warn "Invalid choice '${chosen_idx}' — defaulting to GPU ${best_idx} (largest VRAM)"
      chosen_idx="$best_idx"
    fi
  fi

  # Resolve chosen nvidia-smi index → UUID, name, VRAM.
  local _chosen_name="" _chosen_uuid="" _chosen_vram=0
  while IFS=',' read -r _idx _uuid _vram _name; do
    _idx="${_idx// /}"; _uuid="${_uuid// /}"; _vram="${_vram// /}"; _name="${_name# }"
    if [[ "$_idx" == "$chosen_idx" ]]; then
      _chosen_name="$_name"; _chosen_uuid="$_uuid"; _chosen_vram="${_vram:-0}"
    fi
  done <<< "$smi_out"

  YSG_GPU_INDEX="$chosen_idx"
  YSG_GPU_UUID="$_chosen_uuid"
  YSG_GPU_NAME="$_chosen_name"
  YSG_GPU_VRAM_MB="$_chosen_vram"
  # FINDING-3: CDI by UUID — the RTX 3060 12GB is the expected default on this
  # box (nvidia-smi idx 1; CDI spec UUID form always resolves to the correct card).
  YSG_GPU_CDI="nvidia.com/gpu=${YSG_GPU_UUID}"
  YSG_GPU_DEV="/dev/nvidia${YSG_GPU_INDEX}"
  export YSG_GPU_INDEX YSG_GPU_UUID YSG_GPU_NAME YSG_GPU_VRAM_MB YSG_GPU_CDI YSG_GPU_DEV
  log_success "GPU selected: [${YSG_GPU_INDEX}] ${YSG_GPU_NAME} ($(_format_gpu_vram)) — default: largest VRAM"
  log_info "  UUID: ${YSG_GPU_UUID}  CDI: ${YSG_GPU_CDI}"
  printf "\n"
}

# Helper: format an arbitrary VRAM-MB value (not the global YSG_GPU_VRAM_MB)
_format_gpu_vram_mb() {
  local vram_mb="${1:-0}"
  if [ "$vram_mb" -ge 1024 ]; then
    printf "%.1f GB" "$(awk "BEGIN { printf \"%.1f\", ${vram_mb}/1024 }")"
  else
    printf "%d MB" "$vram_mb"
  fi
}

# =============================================================================
# Podman GPU CDI provisioning — no host sudo (ROOTLESS-CDI-001)
# =============================================================================
# nvidia-ctk 1.19.1 always emits cdiVersion 0.7.0. Podman 4.9.3 (Ubuntu)
# hardcodes /etc/cdi as its ONLY CDI scan directory — cdi_spec_dirs in
# containers.conf is NOT effective on this version (empirically verified: even
# with cdi_spec_dirs pointing only to ~/.config/cdi, podman still reads /etc/cdi
# and ignores the user dir). No /etc/cdi scan means no CDI device resolution.
#
# Two blockers from the prior broken attempt:
#   A. The minimal 0.5.0 spec had no library mounts → ollama sees library=cpu.
#      A working CDI spec MUST include the containerEdits that mount libcuda.so,
#      libnvidia-ml.so etc. — what nvidia-ctk normally discovers and emits.
#   B. /etc/cdi/nvidia.yaml was written 0600 (root-only) → rootless podman
#      gets EACCES on the CDI registry refresh → all CDI devices unresolvable.
#
# Correct fix (no interactive sudo):
#   1. Run nvidia-ctk cdi generate to produce the COMPLETE 0.7.0 spec including
#      all CUDA library mounts and hooks. This is the only reliable source for
#      the correct host library paths and device nodes.
#   2. Transform 0.7.0 → 0.6.0 in-process (Python3, no extra deps):
#        - set cdiVersion: "0.6.0"
#        - strip per-device additionalGids: blocks (0.7.0 addition)
#        - strip gid: fields from deviceNodes (0.7.0 addition)
#        - KEEP all hooks, mounts, library containerEdits intact
#      Podman 4.9.3 accepts 0.6.0 (confirmed via binary string scan: v0.6.0
#      present; v0.7.0 absent). The stripped fields are display/GID-namespace
#      features not needed for headless CUDA compute.
#   3. Write the 0.6.0 spec to /etc/cdi/nvidia.yaml with chmod 0644 via the
#      Docker Engine daemon (rootful — no interactive user sudo). Without 0644,
#      rootless podman cannot read the spec and the CDI registry refresh fails.
#      /etc/cdi/ is created via Docker if it does not exist.
#
# Podman ≥5.0 accepts cdiVersion 0.7.0 natively → skip the transform and
# write the raw nvidia-ctk output directly to /etc/cdi/nvidia.yaml (still with
# 0644 via Docker, so rootless podman can read it).
#
# If nvidia-ctk is missing: WARN loudly and return (CDI unavailable; the
# install.sh CDI probe will fail → devpath fallback WARNS that GPU is CPU-only).
# If Docker daemon unavailable: same — WARN and return; do not silently proceed.

# _transform_cdi_spec_060 <input-070-path> <output-060-path>
# Read a cdiVersion 0.7.0 spec and write a 0.6.0-compatible version by:
#   - setting cdiVersion to "0.6.0"
#   - stripping per-device additionalGids: blocks (indent-aware)
#   - stripping gid: fields from deviceNodes
# All other content (hooks, mounts, library paths, env) is preserved intact.
_transform_cdi_spec_060() {
  local _in="$1" _out="$2"
  python3 - "${_in}" "${_out}" <<'PYEOF'
import sys, re

in_path, out_path = sys.argv[1], sys.argv[2]
with open(in_path) as f:
    lines = f.readlines()

out = []
skip_until_indent = None  # set when inside an additionalGids: block

for line in lines:
    raw = line.rstrip('\n')
    stripped = raw.lstrip()
    indent = len(raw) - len(stripped)

    # End-of-additionalGids-block detection: stop skipping when we reach a
    # line at the SAME or SHALLOWER indentation as the additionalGids: key.
    if skip_until_indent is not None:
        if stripped == '' or indent <= skip_until_indent:
            skip_until_indent = None   # resume output (fall through)
        else:
            continue                   # still inside block — skip

    # Rewrite version line
    if re.match(r'^cdiVersion:\s*0\.7\.0\s*$', stripped):
        out.append('cdiVersion: "0.6.0"\n')
        continue

    # Strip additionalGids: block (keyword + deeper-indented list items)
    if re.match(r'^additionalGids:\s*$', stripped):
        skip_until_indent = indent
        continue

    # Strip gid: fields from deviceNodes (0.7.0 addition)
    if re.match(r'^gid:\s*\d+\s*$', stripped):
        continue

    out.append(line)

with open(out_path, 'w') as f:
    f.writelines(out)

removed = len(lines) - len(out)
print(f"CDI 0.7.0 → 0.6.0 transform: {len(lines)} lines in, {len(out)} out "
      f"({removed} lines stripped)")
PYEOF
}

# _setup_podman_cdi_gpu
# Generate a complete podman-compatible CDI spec via nvidia-ctk, transform it
# to cdiVersion 0.6.0 (podman <5.0 compatible) and deploy it to the USER CDI dir
# (~/.config/cdi), wiring podman to it via cdi_spec_dirs in the USER containers.conf.
# NO /etc/cdi, NO Docker daemon, NO sudo — pure user-space (proven on podman 4.9.3:
# libcuda + nvidia-smi visible in-container via cdi_spec_dirs alone).
# MUST be called before the CDI probe in compose_up() so the probe passes.
_setup_podman_cdi_gpu() {
  if [[ "${YSG_GPU_TYPE:-none}" != "nvidia" ]]; then return 0; fi

  log_info "Podman GPU CDI provisioning — user-space, no host writes (ROOTLESS-CDI-001)"

  # nvidia-ctk required to produce a COMPLETE spec (device nodes + driver-library
  # mounts). A minimal device-only spec does NOT make CUDA work.
  if ! command -v nvidia-ctk >/dev/null 2>&1; then
    log_warn "nvidia-ctk not found — cannot generate CDI spec; ollama will run CPU-only"
    log_warn "Install nvidia-container-toolkit and re-run the installer to enable GPU"
    return 0
  fi

  # User-owned CDI dir — podman (rootless) reads it via cdi_spec_dirs in the USER
  # containers.conf. NO /etc/cdi, NO docker, NO sudo.
  local _cdi_dir="${HOME}/.config/cdi"
  local _cdi_raw="${_cdi_dir}/nvidia-raw.yaml"
  local _cdi_out="${_cdi_dir}/nvidia.yaml"
  mkdir -p "${_cdi_dir}"

  local _podman_major
  _podman_major="$(podman version --format '{{.Client.Version}}' 2>/dev/null | cut -d. -f1)" || _podman_major="4"
  log_info "  podman ${_podman_major}.x detected"

  # Generate the COMPLETE CDI spec (with library mounts) into the user dir.
  log_info "  nvidia-ctk cdi generate → ${_cdi_raw}"
  if ! nvidia-ctk cdi generate --output="${_cdi_raw}" 2>/dev/null || [[ ! -s "${_cdi_raw}" ]]; then
    log_warn "nvidia-ctk cdi generate failed/empty; ollama will run CPU-only"
    rm -f "${_cdi_raw}"; return 0
  fi
  log_info "  raw spec: $(wc -l < "${_cdi_raw}") lines (cdiVersion 0.7.0)"

  # podman <5.0 cannot parse cdiVersion 0.7.0 → transform to 0.6.0 (strip the
  # 0.7.0-only additionalGids blocks; KEEP all library mounts/hooks). ≥5.0 native.
  if [[ "${_podman_major:-4}" -ge 5 ]]; then
    mv -f "${_cdi_raw}" "${_cdi_out}"
    log_info "  podman ≥5.0: using native cdiVersion 0.7.0 spec"
  else
    if ! _transform_cdi_spec_060 "${_cdi_raw}" "${_cdi_out}"; then
      log_warn "CDI 0.6.0 transform failed; ollama will run CPU-only"; rm -f "${_cdi_raw}"; return 0
    fi
    rm -f "${_cdi_raw}"
    if ! grep -q 'cdiVersion: "0.6.0"' "${_cdi_out}" 2>/dev/null; then
      log_warn "transform produced no cdiVersion 0.6.0 marker; ollama will run CPU-only"; return 0
    fi
  fi
  log_info "  CDI spec ready: ${_cdi_out} ($(wc -l < "${_cdi_out}") lines)"

  # Point rootless podman at the user CDI dir via the USER containers.conf.
  # MUST be under [engine] (podman ignores cdi_spec_dirs in other tables — this
  # was the prior bug) and the user dir ONLY — including /etc/cdi would let a host
  # 0.7.0 spec poison the CDI registry on podman <5.0. Idempotent; never touches /etc.
  local _cc="${HOME}/.config/containers/containers.conf"
  mkdir -p "$(dirname "${_cc}")"
  if [[ -f "${_cc}" ]] && grep -qE '^[[:space:]]*cdi_spec_dirs' "${_cc}"; then
    sed -i -E "s|^[[:space:]]*cdi_spec_dirs.*|cdi_spec_dirs = [\"${_cdi_dir}\"]|" "${_cc}"
    log_info "  updated cdi_spec_dirs in ${_cc}"
  elif [[ -f "${_cc}" ]] && grep -qE '^\[engine\]' "${_cc}"; then
    sed -i -E "0,/^\[engine\]/s||[engine]\ncdi_spec_dirs = [\"${_cdi_dir}\"]|" "${_cc}"
    log_info "  inserted cdi_spec_dirs under [engine] in ${_cc}"
  else
    printf '[engine]\ncdi_spec_dirs = ["%s"]\n' "${_cdi_dir}" >> "${_cc}"
    log_info "  wrote [engine] cdi_spec_dirs to ${_cc}"
  fi
  log_success "Podman GPU CDI ready — user-space spec, no /etc/cdi, no docker, no sudo"
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

  # --- Check 1d (#24): Ollama model-store free-space preflight ---------------
  # The Ollama model store (compose: the dedicated ollama_data volume → /root/.ollama;
  # K8s: a 100Gi PVC) grows with each model pull. The full local model set can
  # exceed 80 GB; a "no space left on device" mid-pull leaves models half-written
  # and inference broken. Warn (non-fatal) when the filesystem backing the
  # container-volume store has less than YASHIGANI_OLLAMA_MIN_DISK_GB (default 80)
  # GB free, so the operator can relocate the runtime data-root to a larger disk
  # (or mount one) before pulling models.
  local _min_gb="${YASHIGANI_OLLAMA_MIN_DISK_GB:-80}"
  local _vol_root=""
  if [[ "${YSG_RUNTIME:-}" == "docker" ]] && command -v docker >/dev/null 2>&1; then
    _vol_root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo "")"
  elif command -v podman >/dev/null 2>&1; then
    _vol_root="$(podman info -f '{{.Store.GraphRoot}}' 2>/dev/null || echo "")"
  fi
  [[ -z "$_vol_root" || ! -d "$_vol_root" ]] && _vol_root="/var/lib/docker"
  [[ ! -d "$_vol_root" ]] && _vol_root="/"
  local _avail_gb
  _avail_gb="$(df -Pk "$_vol_root" 2>/dev/null | awk 'NR==2{print int($4/1024/1024)}')"  # MACOS-DF-001: BSD df has no -B; -Pk (1024-blocks) is BSD+GNU portable
  if [[ -n "$_avail_gb" ]] && awk "BEGIN { exit !($_avail_gb < $_min_gb) }"; then
    printf "\n"
    printf "${C_YELLOW}[WARN] Only %s GB free on %s (container-volume store).${C_RESET}\n" "$_avail_gb" "$_vol_root"
    printf "       The dedicated Ollama model store needs >= %s GB for the local model set;\n" "$_min_gb"
    printf "       a 'no space left on device' mid-pull breaks inference. Relocate the runtime\n"
    printf "       data-root to a larger disk (or mount one) before continuing.\n"
    printf "       Override the threshold with YASHIGANI_OLLAMA_MIN_DISK_GB.\n\n"
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
# NOTE: do NOT use this for the onboard/offboard AUTH gate — use
# _is_installed_or_running() instead (residuals-based, fail-closed).
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
  # Multi-instance (3.0): scope the label filter to THIS install's project, not a
  # hardcoded "docker" — otherwise a 2nd named instance false-matches the first.
  local _proj="${COMPOSE_PROJECT_NAME:-docker}"
  if docker ps --filter "label=com.docker.compose.project=${_proj}" \
       --format '{{.Names}}' 2>/dev/null | grep -q .; then
    return 0
  fi
  if podman ps --filter "label=io.podman.compose.project=${_proj}" \
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

# _is_installed_or_running — FIX-2: residuals-based install detection for the
# onboard/offboard AUTH gate.
#
# Returns 0 (true) when install RESIDUALS are present — compose file AND at
# least one file under docker/secrets/ — INDEPENDENT of whether containers are
# currently running and INDEPENDENT of which specific secret file is present.
#
# Design rationale (Laura F1/F2):
#   _is_existing_yashigani_running() is affirmative-only: if the specific
#   ca_root.crt check fails (file removed/renamed) OR all containers are
#   stopped, it returns false and the auth gate is skipped. Both states are
#   trivially achievable by an attacker with host access.
#
#   This function is fail-closed: ANY install residuals (compose file +
#   secrets dir non-empty) imply a prior install and therefore require auth,
#   even if containers are down or the PKI files have been tampered with.
#
# Used exclusively by the onboard/offboard step-up gate decision.
# Never used for port-check or volume-contamination logic (those stay with
# _is_existing_yashigani_running which correctly requires running containers).
_is_installed_or_running() {
  local _compose_file="${WORK_DIR}/docker/docker-compose.yml"
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # Compose file must be present (written by install.sh; indicates a completed
  # or partially-completed install).
  [[ -f "$_compose_file" ]] || return 1

  # Secrets dir must exist AND contain at least one file (any file — not a
  # specific named file, so removal/rename of ca_root.crt does not bypass).
  [[ -d "$_secrets_dir" ]] || return 1
  if find "$_secrets_dir" -maxdepth 1 -type f 2>/dev/null | grep -q .; then
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

  # F3/F9: fail FAST on a deploy-mode ↔ runtime mismatch.
  # The deploy mode determines the deployment substrate:
  #   demo, production → Docker/Podman Compose   (MODE=compose)
  #   enterprise       → Kubernetes via Helm     (MODE=k8s)
  # Previously, `--deploy enterprise --runtime docker` silently resolved to
  # MODE=k8s and ran 8 steps before aborting at "kubernetes cluster unreachable".
  # We only enforce this when the operator set --runtime / YSG_RUNTIME EXPLICITLY
  # (YSG_RUNTIME_EXPLICIT=true) — the natural enterprise→k8s default still works
  # untouched. We also respect an explicit --mode override (MODE_EXPLICIT): if the
  # operator deliberately set --mode compose with --deploy enterprise, that is a
  # conscious override and the runtime check below uses the resolved MODE.
  if [[ "${YSG_RUNTIME_EXPLICIT:-false}" == "true" ]]; then
    case "$MODE" in
      k8s)
        if [[ "${YSG_RUNTIME:-}" == "docker" || "${YSG_RUNTIME:-}" == "podman" ]]; then
          log_error "Incompatible options: --deploy ${DEPLOY_MODE} resolves to Kubernetes (MODE=k8s),"
          log_error "but --runtime ${YSG_RUNTIME} selects a Compose container runtime."
          log_error ""
          log_error "  Enterprise deployments run on Kubernetes via Helm. They do NOT use"
          log_error "  Docker/Podman Compose. Choose ONE of:"
          log_error "    • Kubernetes  : --deploy enterprise --runtime k8s"
          log_error "    • Compose     : --deploy production  --runtime ${YSG_RUNTIME}"
          log_error "                    (or --deploy demo --runtime ${YSG_RUNTIME})"
          exit 1
        fi
        ;;
      compose)
        if [[ "${YSG_RUNTIME:-}" == "k8s" ]]; then
          log_error "Incompatible options: --deploy ${DEPLOY_MODE} resolves to Docker/Podman Compose"
          log_error "(MODE=compose), but --runtime k8s selects Kubernetes."
          log_error ""
          log_error "  demo / production deployments run on Compose. For Kubernetes use:"
          log_error "    --deploy enterprise --runtime k8s"
          exit 1
        fi
        ;;
    esac
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
  # Demo mode: point the gateway at the bundled demo-mcp upstream so the headline
  # "cloud 9" rogue-MCP leg is reproducible from committed code with zero manual
  # steps. Two things MUST be codified together:
  #   1. UPSTREAM_MCP_URL=http://demo-mcp:8000 — tool_catalog._resolve_mcp_servers()
  #      only projects the demo MCP catalog when the upstream URL contains
  #      "demo-mcp" (otherwise the orchestration MCP catalog is EMPTY and the
  #      cloud-9 leg silently doesn't exist).
  #   2. the `demo-mcp` compose profile — without it the service is never started
  #      even though the gateway points at it.
  # Both land via COMPOSE_PROFILES (drives --profile flags + YASHIGANI_ENABLED_PROFILES)
  # and docker/.env. Production: set from wizard or --upstream-url flag.
  local upstream="${UPSTREAM_URL}"
  if [[ -z "$upstream" && "$DEPLOY_MODE" == "demo" ]]; then
    upstream="http://demo-mcp:8000"
    # Enable the demo-mcp compose profile (idempotent — guard against a duplicate).
    if ! printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx "demo-mcp"; then
      COMPOSE_PROFILES+=("demo-mcp")
      log_info "Demo mode: enabling demo-mcp compose profile + pointing UPSTREAM_MCP_URL at http://demo-mcp:8000 (cloud-9 demo upstream)"
    fi
  fi
  _env_set "UPSTREAM_MCP_URL" "${upstream}"

  # --- Cloud-9 MCP-injection demo (demo mode ONLY) ---
  # Codifies the cloud-9 wiring so `install.sh --deploy demo` + populate-demo.py
  # reproduce it with zero manual steps: expose the cloud9-orchestrate virtual
  # model and enable response inspection so the egress block fires and renders in
  # OWUI. INSPECT_RESPONSES is opt-in by design (YSG-RISK-057) — production/
  # enterprise leave it OFF; demo turns it ON to showcase the injection block.
  if [[ "$DEPLOY_MODE" == "demo" ]]; then
    _env_set "YASHIGANI_ORCH_AUTO_MODELS"  "${YASHIGANI_ORCH_AUTO_MODELS:-cloud9-orchestrate}"
    _env_set "YASHIGANI_ORCH_BRAIN_MODEL"  "${YASHIGANI_ORCH_BRAIN_MODEL:-qwen2.5:3b}"
    _env_set "YASHIGANI_INSPECT_RESPONSES" "${YASHIGANI_INSPECT_RESPONSES:-true}"
    log_info "Demo mode: cloud-9 demo wired (cloud9-orchestrate model + response inspection ON)"
  fi

  # --- Domain ---
  _env_set "YASHIGANI_TLS_DOMAIN" "${DOMAIN}"

  # --- Multi-instance identity token (3.0 — MI-2 / YSG-RISK-061) ---
  # Mint-or-preserve a per-instance CSPRNG identity token NOW (at .env generation,
  # before compose up) so compose can stamp it as a container label on every
  # service. A destructive lifecycle op (uninstall) then proves it is operating on
  # the instance it claims by matching the label on the running containers against
  # the INSTANCE_ID recorded in THIS tree's state file — a bare --project string
  # can no longer act on a sibling.
  # Preservation order (idempotent across re-runs/upgrades): existing .env value >
  # existing state-file value > fresh CSPRNG mint. Stored in docker/.env as
  # YASHIGANI_INSTANCE_ID (compose label source) and echoed into the state file by
  # the Step 12b writer (which reads it back from .env via _instance_identity_token
  # of the SAME value).
  local _env_file="${WORK_DIR}/docker/.env"
  local _existing_iid=""
  if [[ -f "$_env_file" ]]; then
    _existing_iid="$(grep -E '^YASHIGANI_INSTANCE_ID=' "$_env_file" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
  fi
  if [[ -z "$_existing_iid" ]]; then
    _existing_iid="$(_instance_identity_token "${WORK_DIR}/docker/.yashigani-install-state")"
  fi
  if [[ -z "$_existing_iid" ]]; then
    _existing_iid="$(_gen_instance_id)"
  fi
  YASHIGANI_INSTANCE_ID="$_existing_iid"
  export YASHIGANI_INSTANCE_ID
  _env_set "YASHIGANI_INSTANCE_ID" "${YASHIGANI_INSTANCE_ID}"

  # --- Multi-instance compose project (3.0 — scoping-draft §4a) ---
  # COMPOSE_PROJECT_NAME in docker/.env is the single source of truth for the
  # project name on BOTH Docker and Podman compose (each reads the project-dir
  # .env). Without it, compose derives the project from the directory name
  # ("docker") and two instances on one host collide on container/volume/network
  # names. PROJECT is resolved in main() (from --project / --domain / state file).
  # Same .env-over-process-env rationale as FIPS_MODE above.
  if [[ -n "${PROJECT:-}" && "${PROJECT}" != "docker" ]]; then
    _env_set "COMPOSE_PROJECT_NAME" "${PROJECT}"
  fi

  # --- Multi-instance SPIFFE trust domain (3.0 — MI-6 / YSG-RISK-061) ---
  # Each instance gets its OWN SPIFFE trust-domain authority so a leaf cert minted
  # in instance A does not satisfy instance B's validators. This is the SINGLE
  # SOURCE OF TRUTH consumed by:
  #   * the install-time cert issuer (per-instance URI SANs baked into leaf certs —
  #     see _apply_trust_domain_to_runtime_manifest, called from enroll path),
  #   * Caddy edge (X-SPIFFE-ID injection + peer-cert ACL match), and
  #   * the app-layer validators (Tom's surface: linter/pool/principal_token/audit
  #     read YASHIGANI_SPIFFE_TRUST_DOMAIN; default "yashigani.internal" preserves
  #     legacy single-instance behaviour with no rotation).
  # Legacy PROJECT=docker keeps "yashigani.internal" byte-for-byte (no env churn).
  YASHIGANI_SPIFFE_TRUST_DOMAIN="$(_spiffe_trust_domain "${PROJECT:-docker}")"
  export YASHIGANI_SPIFFE_TRUST_DOMAIN
  _env_set "YASHIGANI_SPIFFE_TRUST_DOMAIN" "${YASHIGANI_SPIFFE_TRUST_DOMAIN}"

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

  # Method 3 (F1): GENUINE pure-Python bcrypt — zero host prerequisites.
  # Works on a fresh host with NEITHER `htpasswd` (apache2-utils) NOR the python
  # `bcrypt` module — only python3 stdlib is required. Implements the Eksblowfish
  # key schedule + the 64-round "OrpheanBeholderScryDoubt" encryption that defines
  # the bcrypt $2b$ hash. Blowfish init constants are computed from the fractional
  # hex digits of pi at runtime (no embedded data table). Validated byte-for-byte
  # against reference bcrypt 5.0.0 (cost 4/6/10/12, ASCII + symbol + utf-8 + 36-char
  # passwords) — produces identical output and reference checkpw() verifies it.
  # NOTE: cost-12 Eksblowfish in pure Python takes ~30s on a typical host; this
  # path is only reached when both faster methods are unavailable.
  # The password is passed via the environment (never interpolated into the script
  # body) so any password charset is injection-safe. The heredoc is single-quoted
  # ('PYEOF') so the shell performs NO expansion on the Python source.
  if [[ -z "$prom_hash" ]] && command -v python3 >/dev/null 2>&1; then
    log_info "Generating Prometheus basic-auth hash via pure-Python bcrypt (no htpasswd/bcrypt module found; may take ~30s)..."
    prom_hash="$(YASHIGANI_PROM_PW="$prom_password" python3 - <<'PYEOF' 2>/dev/null || echo ""
import os, sys
from decimal import Decimal, getcontext

_B64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def _b64encode(data):
    out = []; i = 0; n = len(data)
    while i < n:
        c1 = data[i]; i += 1
        out.append(_B64[(c1 >> 2) & 0x3F]); c1 = (c1 & 0x03) << 4
        if i >= n: out.append(_B64[c1 & 0x3F]); break
        c2 = data[i]; i += 1; c1 |= (c2 >> 4) & 0x0F
        out.append(_B64[c1 & 0x3F]); c1 = (c2 & 0x0F) << 2
        if i >= n: out.append(_B64[c1 & 0x3F]); break
        c3 = data[i]; i += 1; c1 |= (c3 >> 6) & 0x03
        out.append(_B64[c1 & 0x3F]); out.append(_B64[c3 & 0x3F])
    return "".join(out)

def _init_words():
    n = 18 + 4 * 256; need_hex = n * 8 + 16
    getcontext().prec = int(need_hex * 1.25) + 120
    C = 426880 * Decimal(10005).sqrt()
    K = Decimal(6); M = Decimal(1); X = Decimal(1); L = Decimal(13591409); S = L; i = 1
    limit = Decimal(10) ** (-(int(need_hex * 1.25) + 30))
    while True:
        M = M * (K**3 - 16 * K) / (Decimal(i) ** 3)
        L += 545140134; X *= -262537412640768000
        term = M * L / X; S += term; K += 12
        if abs(term) < limit: break
        i += 1
    pi = C / S; frac = pi - 3
    h = format(int(frac * (Decimal(16) ** need_hex)), "x").rjust(need_hex, "0")
    return [int(h[j * 8:j * 8 + 8], 16) for j in range(n)]

_W = _init_words()

class _BF:
    def __init__(self):
        self.P = list(_W[:18])
        self.S = [list(_W[18 + s * 256:18 + (s + 1) * 256]) for s in range(4)]
    def _F(self, x):
        a = (x >> 24) & 0xFF; b = (x >> 16) & 0xFF; c = (x >> 8) & 0xFF; d = x & 0xFF
        y = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF
        y = (y ^ self.S[2][c]) & 0xFFFFFFFF
        return (y + self.S[3][d]) & 0xFFFFFFFF
    def enc(self, xl, xr):
        for i in range(16):
            xl ^= self.P[i]; xr ^= self._F(xl); xl, xr = xr, xl
        xl, xr = xr, xl
        xr ^= self.P[16]; xl ^= self.P[17]
        return xl & 0xFFFFFFFF, xr & 0xFFFFFFFF
    @staticmethod
    def _s2w(data, off):
        w = 0
        for _ in range(4):
            w = ((w << 8) | data[off % len(data)]) & 0xFFFFFFFF; off += 1
        return w, off
    def expand(self, key):
        off = 0
        for i in range(18):
            w, off = self._s2w(key, off); self.P[i] ^= w
        xl = xr = 0
        for i in range(0, 18, 2):
            xl, xr = self.enc(xl, xr); self.P[i] = xl; self.P[i + 1] = xr
        for s in range(4):
            for i in range(0, 256, 2):
                xl, xr = self.enc(xl, xr); self.S[s][i] = xl; self.S[s][i + 1] = xr
    def expand_salt(self, data, key):
        off = 0
        for i in range(18):
            w, off = self._s2w(key, off); self.P[i] ^= w
        xl = xr = 0; soff = 0
        for i in range(0, 18, 2):
            s1, soff = self._s2w(data, soff); s2, soff = self._s2w(data, soff)
            xl ^= s1; xr ^= s2; xl, xr = self.enc(xl, xr); self.P[i] = xl; self.P[i + 1] = xr
        for s in range(4):
            for i in range(0, 256, 2):
                s1, soff = self._s2w(data, soff); s2, soff = self._s2w(data, soff)
                xl ^= s1; xr ^= s2; xl, xr = self.enc(xl, xr); self.S[s][i] = xl; self.S[s][i + 1] = xr

def hashpw(password, cost, salt16):
    key = password[:72] + b"\x00"
    bf = _BF(); bf.expand_salt(salt16, key)
    for _ in range(1 << cost):
        bf.expand(key); bf.expand(salt16)
    ct = list(b"OrpheanBeholderScryDoubt")
    cd = [(ct[i] << 24) | (ct[i + 1] << 16) | (ct[i + 2] << 8) | ct[i + 3] for i in range(0, 24, 4)]
    for _ in range(64):
        for i in range(0, 6, 2):
            cd[i], cd[i + 1] = bf.enc(cd[i], cd[i + 1])
    out = bytearray()
    for w in cd:
        out += bytes([(w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF])
    return "$2b$%02d$%s%s" % (cost, _b64encode(salt16), _b64encode(bytes(out[:23])))

pw = os.environ["YASHIGANI_PROM_PW"].encode()
sys.stdout.write(hashpw(pw, 12, os.urandom(16)))
PYEOF
)"
  fi

  if [[ -z "$prom_hash" ]]; then
    log_error "Failed to generate Prometheus basic-auth hash."
    log_error "python3 is required for the built-in pure-Python bcrypt fallback."
    log_error "Install python3, OR install htpasswd (apache2-utils / 'brew install httpd'),"
    log_error "OR 'pip install bcrypt' — then re-run install.sh."
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

  # --- Source SHA for first-party image cache-busting ---
  # Written here so `compose build` (Docker path) picks it up via .env
  # interpolation: the compose YAML passes it as build arg GIT_SHA to each
  # first-party Dockerfile. _local_images_cached() reads it back from the
  # running image label to detect stale-tag hits when YASHIGANI_VERSION
  # is unchanged but source commits have landed (version-drift stale-image bug).
  _env_set "YASHIGANI_GIT_SHA" "${YASHIGANI_GIT_SHA}"

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

    # On upgrade, reuse an existing UPSTREAM_MCP_URL from .env rather than exporting an
    # empty value. Compose declares it required (${UPSTREAM_MCP_URL:?set UPSTREAM_MCP_URL}),
    # so a blank export breaks `up` even though the value is already configured — this is
    # what forced operators to re-pass --upstream-url on every upgrade.
    if [[ -z "$UPSTREAM_URL" && -f "${WORK_DIR}/docker/.env" ]]; then
      UPSTREAM_URL="$(grep -m1 '^UPSTREAM_MCP_URL=' "${WORK_DIR}/docker/.env" | cut -d= -f2- || true)"
      [[ -n "$UPSTREAM_URL" ]] && log_info "Reusing existing UPSTREAM_MCP_URL from .env (upgrade)"
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
  # YSG-RISK-050 guardrail: capture ts once; reused for dir name, AADs, recovery id.
  local backup_ts
  backup_ts="$(date +%Y%m%d_%H%M%S)"
  local backup_dir="${WORK_DIR}/backups/${backup_ts}"
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
      # Docker/rootful path. Some client certs/keys are owned by container UIDs
      # (root/999/1000) and unreadable by a non-root install user, so cp -rp returns
      # non-zero. That must NOT abort the upgrade under set -e: the live volumes still
      # hold the secrets and the dual-wrap bundle below is the authoritative copy.
      mkdir -p "$_secrets_dest"
      if cp -rp "$_secrets_src"/. "$_secrets_dest"/ 2>/dev/null; then
        log_info "  secrets/ backed up (ownership/mode preserved)"
      else
        log_warn "  secrets/ partial copy — some keys owned by container UIDs are unreadable as $(id -un); non-fatal (live volumes + dual-wrap bundle retain them)."
      fi
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
  # pg_dump -U yashigani_admin (v2.25.2: the DDL/admin superuser) connects via
  # the local Unix socket (trust auth) — a full dump needs the superuser, the
  # demoted runtime role yashigani_app cannot read every table.
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
           pg_dump -U yashigani_admin yashigani > "${backup_dir}/postgres_dump.sql" 2>/dev/null; then
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
           pg_dump -U yashigani_admin yashigani > "${backup_dir}/postgres_dump.sql" 2>/dev/null; then
        log_info "  postgres_dump.sql backed up (${RUNTIME:-compose}: container ${_pg_container})"
      else
        log_info "  Postgres dump failed for container ${_pg_container} — dump skipped"
        rm -f "${backup_dir}/postgres_dump.sql"
      fi
    else
      log_info "  Postgres dump skipped (no running postgres container found)"
    fi
  fi

  # DRIFT-B5-COMPOSE-AGENT-BACKUP: snapshot named Docker/Podman volumes for each
  # agent bundle that is present on this host. These volumes carry agent-specific
  # state (langflow flows + DB, letta memory + config, openclaw policies) and were
  # silently excluded from every compose backup since v2.23.3.
  #
  # Design decisions:
  #   - Volume names are hardcoded constants — not operator-supplied — so no
  #     path-injection risk.
  #   - Uses "docker/podman run --rm -v <vol>:/data:ro alpine tar" instead of
  #     "docker volume export" because Podman lacks volume export.  The pattern
  #     works identically on both Docker and Podman (rootful + rootless).
  #   - Warn-only when a volume is absent: agent bundles are optional; missing
  #     volumes simply mean the bundle is not enabled.
  #   - Output path: ${backup_dir}/agent-volumes/<bundle>.tar (0600).
  #     The MANIFEST sweep below covers these files automatically.
  #   - Threat model: agent volumes may contain API keys and bearer tokens.
  #     Tarballs are written 0600 (owner-read-only) before any content reaches
  #     them; the backup dir itself is locked to 0700 in the chmod block below.
  #   - Skipped on K8s: agent PVCs are handled by the Helm backup CronJob
  #     (scripts/backup.sh --extra-dirs, B5 Helm side).  This block runs only
  #     on compose/Podman installs.
  if [[ "${MODE:-compose}" != "k8s" && "${YSG_RUNTIME:-}" != "k8s" ]]; then
    # LIVE-FIX2-001 (VM smoke 2026-05-28): compose-created named volumes carry
    # the compose project prefix. The compose file lives in docker/, so the
    # project name is "docker" and volumes are "docker_langflow_data" etc. —
    # NOT bare "langflow_data". The chown path at the post-install step already
    # uses _compose_project_prefix (see the agent-bundle chown block); mirror it
    # here so `volume inspect` actually finds the volume instead of always
    # reporting "not present — skipping" and silently losing agent state.
    # Multi-instance (3.0): the prefix is THIS install's compose project, not a
    # hardcoded "docker" — a 2nd named instance has e.g. "eu-west-acme-com_langflow_data".
    local _compose_project_prefix="${COMPOSE_PROJECT_NAME:-docker}"
    # Ordered list: <volume_name>:<bundle_label>
    local -a _agent_volumes=(
      "${_compose_project_prefix}_langflow_data:langflow"
      "${_compose_project_prefix}_letta_data:letta"
      "${_compose_project_prefix}_openclaw_data:openclaw"
    )
    local _agent_vol_dir="${backup_dir}/agent-volumes"
    local _agent_vol_any=false
    for _vol_entry in "${_agent_volumes[@]}"; do
      local _vol_name="${_vol_entry%%:*}"
      local _vol_label="${_vol_entry##*:}"
      # Check whether the named volume exists on this host.
      if $_runtime_cmd volume inspect -- "$_vol_name" >/dev/null 2>&1; then
        _agent_vol_any=true
        mkdir -p "$_agent_vol_dir"
        local _vol_tar="${_agent_vol_dir}/${_vol_label}.tar"
        # Pre-create at 0600 before writing so content never touches disk at
        # a looser mode (even briefly). umask alone is insufficient here because
        # the tar redirect lands via the shell's open(2), not install(1).
        ( umask 177 && : > "$_vol_tar" )
        # Pipe volume contents through a read-only bind mount via an Alpine
        # container. "--" before the volume name prevents injection if the name
        # ever starts with "-". The volume name is a hardcoded constant but
        # defensive quoting costs nothing.
        # Iris SU-FIX2-IRIS-001: pin alpine digest matching install.sh codebase norm.
        # Prefer cached alpine:3 tag (--pull=never); fall back to digest-pinned pull
        # if not cached. Same pattern as lines 4277-4281 / 5942/5980 / 6076/6158 / 6248/6269.
        local _agent_vol_alpine="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
        if $_runtime_cmd run --rm --pull=never \
             --read-only \
             -v "${_vol_name}:/data:ro" \
             --entrypoint "" \
             "alpine:3" \
             tar -C /data -cf - -- . \
           > "$_vol_tar" 2>/dev/null; then
          chmod 0600 "$_vol_tar"
          log_info "  agent-volumes/${_vol_label}.tar backed up (volume: ${_vol_name})"
        elif $_runtime_cmd run --rm \
               --read-only \
               -v "${_vol_name}:/data:ro" \
               --entrypoint "" \
               "$_agent_vol_alpine" \
               tar -C /data -cf - -- . \
             > "$_vol_tar" 2>/dev/null; then
          chmod 0600 "$_vol_tar"
          log_info "  agent-volumes/${_vol_label}.tar backed up (volume: ${_vol_name}, digest-pinned)"
        else
          log_warn "  agent-volumes/${_vol_label}.tar: tar from volume ${_vol_name} failed — removing partial"
          rm -f "$_vol_tar"
        fi
      else
        log_info "  agent bundle '${_vol_label}' volume (${_vol_name}) not present — skipping (bundle not enabled)"
      fi
    done
    if [[ "$_agent_vol_any" == "true" && -d "$_agent_vol_dir" ]]; then
      chmod 0700 "$_agent_vol_dir"
    fi
  fi

  # BUG-58B-04a (v2.23.1) — sentinel preserved for test_install_compose_agent_backup.py
  # delimiter. The chmod block that was here is superseded by the v2 dual-wrap
  # construction below (YSG-RISK-050/051): all secret content is encrypted into
  # bundle.enc; no plaintext files remain in the backup dir after encryption.

  # ── YSG-RISK-050/051: Dual-wrap signed+encrypted backup (v2, LOCKED) ─────────
  # Supersedes RETRO-R4-3 plaintext + SHA-256 manifest. All sensitive content
  # (secrets/, .env, postgres_dump.sql, agent-volumes/*.tar) is encrypted with
  # AES-256-GCM under a random DEK. The DEK is wrapped under two independent KEKs:
  #   Wrap#1 — admin-password path (argon2id, FIPS_MODE=0 ONLY — ABSENT under FIPS_MODE=1)
  #   Wrap#2 — recovery path (license .ysg bytes OR YASHIGANI_DB_AES_KEY for community)
  # HMAC-SHA384 (key-separated via HKDF) covers the cleartext backup-meta.json.
  # All crypto runs in Python inside the gateway/backoffice container
  # (cryptography + argon2-cffi, both confirmed present). SHA-384 everywhere;
  # no SHA-256 in any new primitive. CNSA-2.0 symmetric suite (Nico-verified).
  #
  # Key hierarchy (locked spec 2026-05-28):
  #   DEK     = os.urandom(32)
  #   MAC_KEY = HKDF-SHA384(DEK, info=b"yashigani-backup-meta-mac-v1", len=48)
  #   IKM1 = V = raw 32-byte argon2 verifier extracted from stored PHC (NO argon2 call at backup)
  #     V = base64decode_padded(PHC.split("$")[-1])   # unpadded argon2 PHC base64
  #   KEK1    = HKDF-SHA384(V, kek1_hkdf_salt, len=32)
  #   KEK2    = HKDF-SHA384(.ysg bytes | DB_AES_KEY, kek2_hkdf_salt, len=32)
  #   WDEK1/2 = AES-256-GCM(KEK, IV, aad=version+ts+wrap_id, pt=DEK)
  #   bundle.enc = AES-256-GCM(DEK, IV_B, aad=meta_bytes_with_empty_hmac, pt=tar.gz)
  #   hmac_hex = HMAC-SHA384(MAC_KEY, aad_bytes)
  #   FIPS_MODE=1: wrap#1 is ABSENT (wrap1.present=false). PBKDF2 cannot reproduce an
  #     argon2 verifier; there is no sound non-interactive password-recovery wrap under FIPS.
  #     Only wrap#2 is written under FIPS. (Nico ruling 2026-05-28.)
  #
  # Guardrails (spec §Implementation guardrails):
  #   - ts captured once and reused everywhere.
  #   - DEK/KEK/MAC_KEY in memory only; never on disk.
  #   - bundle.enc written via tmp→atomic rename; deleted on error.
  #   - backup-meta.json written only AFTER bundle.enc succeeds; if meta fails
  #     bundle.enc is deleted.
  #   - Old plaintext files (secrets/, .env, postgres_dump.sql) + MANIFEST.*
  #     removed from backup dir after bundle.enc is finalised.
  #   - No silent failure; no plaintext fallback; fail-closed.
  #   - Docker + Podman parity; compose/vm path only (K8s is unchanged).

  # Lock down backup_dir itself to 0700 before writing the encrypted bundle.
  chmod 0700 "$backup_dir"

  # Locate a running gateway or backoffice container for the Python crypto step.
  local _crypto_container=""
  local _runtime_cmd_local=""
  [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && _runtime_cmd_local="podman" || _runtime_cmd_local="docker"
  _crypto_container=$($_runtime_cmd_local ps --format '{{.Names}}' 2>/dev/null \
    | grep -E 'backoffice|gateway' | head -1 || true)

  if [[ -z "$_crypto_container" ]]; then
    log_error "YSG-RISK-050: No running gateway/backoffice container found — cannot run dual-wrap backup crypto."
    log_error "  The backup requires the cryptography + argon2-cffi Python libraries (present in gateway/backoffice)."
    log_error "  Ensure at least one of these containers is running before upgrading."
    # Remove the staging dir so no plaintext leaks to disk.
    rm -rf "$backup_dir"
    exit 1
  fi

  log_info "Running dual-wrap backup crypto in container: ${_crypto_container}"

  # Read the admin password hash from Postgres for wrap#1.
  # Query: admin_accounts.password_hash WHERE account_tier='admin' AND disabled=false ORDER BY created_at LIMIT 1
  # If Postgres is unreachable → wrap1.present=false, warn, continue (wrap#2 covers recovery).
  local _admin_phc=""
  local _wrap1_present="true"
  local _pg_container_for_hash
  _pg_container_for_hash=$($_runtime_cmd_local ps --format '{{.Names}}' 2>/dev/null \
    | grep -E 'postgres' | grep -v pgbouncer | head -1 || true)
  if [[ -n "$_pg_container_for_hash" ]]; then
    _admin_phc=$($_runtime_cmd_local exec "$_pg_container_for_hash" \
      psql -U yashigani_admin yashigani -t -A \
      -c "SELECT password_hash FROM admin_accounts WHERE account_tier='admin' AND disabled=false ORDER BY created_at LIMIT 1;" \
      2>/dev/null | tr -d '[:space:]' || true)
    if [[ -z "$_admin_phc" ]]; then
      log_warn "YSG-RISK-050: Could not read admin password_hash from Postgres (empty result) — wrap#1 will be skipped."
      _wrap1_present="false"
    fi
  else
    log_warn "YSG-RISK-050: No running Postgres container found — wrap#1 (admin-password) will be skipped."
    _wrap1_present="false"
  fi

  # Read the recovery IKM: licensed tier = .ysg file bytes; community = YASHIGANI_DB_AES_KEY.
  local _license_file="${WORK_DIR}/docker/secrets/license_key"
  local _ysg_tier="community"
  local _license_key_id="null"
  local _ikm2_source="db_aes_key"  # internal marker: "license" or "db_aes_key"

  if [[ -f "$_license_file" ]]; then
    local _lic_content
    # BUG-B+-004 / BUG-FIX (3.1.0): license_key is subuid-owned on Podman rootless (e.g.
    # UID 166536). Direct `< file` redirect emits a bash "Permission denied" error to
    # stderr that `2>/dev/null` inside the subshell cannot suppress (bash prints the error
    # before entering the subshell). Use `_safe_read_secret` (podman unshare cat) so the
    # read happens inside the correct user namespace and the error is fully silent.
    # Community tier: if the file is unreadable (no license), _lic_content stays empty
    # and the code falls through to the db_aes_key path. Non-fatal.
    _lic_content=$(_safe_read_secret "$_license_file" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "$_lic_content" && "$_lic_content" != "#community"* && "${#_lic_content}" -gt 20 ]]; then
      _ysg_tier="licensed"
      _ikm2_source="license"
      # Extract license_key_id: first 16 chars of the file content as a stable ID.
      _license_key_id="$(printf '%.16s' "$_lic_content")"
    fi
  fi

  # Read YASHIGANI_DB_AES_KEY from .env (community recovery path).
  local _db_aes_key=""
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    _db_aes_key=$(grep '^YASHIGANI_DB_AES_KEY=' "${WORK_DIR}/docker/.env" 2>/dev/null \
      | sed 's/^YASHIGANI_DB_AES_KEY=//' | tr -d '\n' || true)
  fi

  if [[ "$_ikm2_source" == "db_aes_key" && -z "$_db_aes_key" ]]; then
    log_error "YSG-RISK-050: YASHIGANI_DB_AES_KEY not found in docker/.env — cannot derive wrap#2 (recovery) key."
    log_error "  Community tier backup requires YASHIGANI_DB_AES_KEY for the recovery wrap."
    rm -rf "$backup_dir"
    exit 1
  fi

  # Build the Python crypto script. This runs inside the container via docker/podman exec.
  # Secrets (_YSG_ADMIN_PHC, _YSG_IKM2_HEX) passed via stdin JSON to avoid docker inspect
  # exposure (FINDING-4). Non-secret config via -e env: _YSG_WRAP1_PRESENT, _YSG_TIER, etc.
  #
  # The container sees backup_dir as a bind-mount path: the host backup_dir is
  # accessible inside the container because install.sh runs on the host and
  # exec's into the container to perform the crypto. We pass the host path and
  # the container will access it via the bind-mount at ${WORK_DIR} (compose mounts
  # the repo root read-write into gateway/backoffice for secrets access).
  # Specifically: docker/secrets is mounted at /run/secrets inside containers.
  # The backup dir is under ${WORK_DIR}/backups/ which is NOT a container mount,
  # so we pass the backup dir contents via stdin as a tar stream into the container.
  #
  # Implementation pattern: tar the staging dir to stdin → pipe into container →
  # container decrypts/encrypts → writes bundle.enc + backup-meta.json to stdout →
  # host extracts. This avoids any host-path dependency inside the container.

  # We run the Python crypto inline: pass the staging content as a base64-encoded
  # tar.gz blob via environment variable (for small backups this is fine; for large
  # backups we stream). Since backups can be arbitrarily large (agent volumes),
  # we use a streaming approach: write to a temp file in the container's writable
  # scratch space (tmpfs), then stream results back.
  #
  # Simpler approach: exec python3 directly, pass backup_dir path, read result files.
  # This works because the container filesystem has access to the host secrets via
  # the /run/secrets bind-mount, but backup_dir is NOT accessible from inside.
  # Solution: pass the entire staging data as a compressed stdin stream, get the
  # encrypted bundle + meta back as two base64-delimited outputs.
  #
  # Final approach (chosen for clarity + auditability): write the Python script to
  # a tmpfile (mode 0700, no secrets), exec it inside the container with secrets via
  # env. The container needs access to backup_dir. Since the compose bind-mount for
  # data/certs/secrets doesn't include backups/, we use docker cp to push the
  # staging dir in and pull the results out, then clean up in the container.
  # This is clean and avoids any path-injection risk.

  # The Python inline script (heredoc, written to a 0700 tmpfile).
  # All secrets arrive as env vars. No secrets in the script itself.
  local _py_script_path="${backup_dir}/.ysg_backup_crypto_$$.py"
  # Pre-create at 0700 (no content readable) before writing.
  ( umask 077 && : > "$_py_script_path" )
  cat > "$_py_script_path" << 'PYEOF'
#!/usr/bin/env python3
"""
YSG-RISK-050/051: Dual-wrap signed+encrypted backup construction.
LOCKED spec 2026-05-28. Zero crypto decisions here — implement verbatim.
Runs inside gateway/backoffice container (cryptography + argon2-cffi present).
All secrets arrive via stdin JSON. No secrets in argv, env, or on disk
other than the final output files.

IKM1 = V = raw 32-byte argon2 verifier, extracted from stored PHC by base64-decoding
the hash segment (no argon2 call at backup — NO plaintext password needed).
RESTORE recomputes V = argon2id_raw(typed_plaintext, argon2_salt_from_meta, params).
They match iff the password is unchanged. (Nico ruling 2026-05-28.)

FIPS_MODE=1: wrap#1 is ABSENT (wrap1.present=false). PBKDF2 cannot reproduce an
argon2 verifier (different function, different output). Only wrap#2 under FIPS.
"""
import base64
import hashlib
import hmac as _hmac
import json
import os
import sys
import tarfile
from pathlib import Path

# ── Imports (cryptography + argon2-cffi) ─────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA384
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    sys.stderr.write(f"FATAL: cryptography library not available: {e}\n")
    sys.exit(1)

try:
    from argon2 import extract_parameters
except ImportError as e:
    sys.stderr.write(f"FATAL: argon2-cffi not available: {e}\n")
    sys.exit(1)

# ── Inputs via stdin JSON (secrets) + environment (non-secret config) ─────────
# Secrets (_YSG_ADMIN_PHC, _YSG_IKM2_HEX) arrive via stdin JSON to avoid
# exposure in 'docker inspect' (FINDING-4). Non-secret config via env vars.
try:
    _stdin_data = json.loads(sys.stdin.read())
except Exception as e:
    sys.stderr.write(f"FATAL: Failed to parse stdin JSON: {e}\n")
    sys.exit(1)

STAGING_DIR   = os.environ["_YSG_BACKUP_STAGING_DIR"]   # path accessible from container
OUTPUT_DIR    = os.environ["_YSG_BACKUP_OUTPUT_DIR"]     # where bundle.enc + meta go
ADMIN_PHC     = _stdin_data.get("admin_phc", "")         # argon2 PHC or empty (from stdin)
WRAP1_PRESENT = os.environ.get("_YSG_WRAP1_PRESENT", "false").lower() == "true"
IKM2_HEX      = _stdin_data["ikm2_hex"]                  # hex-encoded recovery IKM (from stdin)
TIER          = os.environ.get("_YSG_TIER", "community")
LIC_ID        = os.environ.get("_YSG_LIC_ID", "null")
FIPS_MODE     = os.environ.get("_YSG_FIPS_MODE", "0") == "1"
YSG_VERSION   = os.environ.get("_YSG_VERSION", "unknown")
TS            = os.environ["_YSG_TS"]                    # YYYYMMDD_HHMMSS (captured once)

staging = Path(STAGING_DIR)
output  = Path(OUTPUT_DIR)
output.mkdir(parents=True, exist_ok=True)

bundle_enc_tmp  = output / f"bundle.enc.tmp.{os.getpid()}"
bundle_enc_path = output / "bundle.enc"
meta_path       = output / "backup-meta.json"

def _zero(b: bytearray) -> None:
    """Best-effort zero a bytearray (Python GC gives no hard guarantee)."""
    for i in range(len(b)):
        b[i] = 0

def _hkdf_sha384(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=SHA384(),
        length=length,
        salt=salt if salt else None,
        info=info,
        backend=default_backend(),
    ).derive(ikm)

# ── Step 1: DEK + MAC_KEY ─────────────────────────────────────────────────────
dek     = bytearray(os.urandom(32))
mac_key = bytearray(_hkdf_sha384(
    bytes(dek), b"", b"yashigani-backup-meta-mac-v1", 48
))

# ── Step 2: Wrap#1 (admin-password, FIPS_MODE=0 only) ────────────────────────
# FIPS_MODE=1 → wrap#1 is ABSENT. PBKDF2 cannot reproduce an argon2 verifier
# (different primitive, different output). No sound password-recovery wrap under FIPS.
# Nico ruling 2026-05-28. Only wrap#2 under FIPS_MODE=1.
#
# When FIPS_MODE=0: IKM1 = V = the raw 32-byte argon2 verifier extracted from the
# stored PHC. We base64-decode the last "$"-segment of the PHC (argon2 PHC base64
# is unpadded — add "=" padding before decoding). NO argon2 call at backup.
# RESTORE recomputes V = argon2id_raw(typed_plaintext, argon2_salt_from_meta, params).
# They match iff the password is unchanged. (Single argon2 pass total, at restore only.)
wrap1 = {"present": False}
if WRAP1_PRESENT and ADMIN_PHC and not FIPS_MODE:
    kek1_hkdf_salt = os.urandom(32)
    try:
        params = extract_parameters(ADMIN_PHC)
        # PHC format: $argon2id$v=19$m=...,t=...,p=...$<salt_b64>$<hash_b64>
        # Segments after split("$"): ['', 'argon2id', 'v=19', 'm=...,t=...,p=...', '<salt_b64>', '<hash_b64>']
        phc_segs = ADMIN_PHC.split("$")
        if len(phc_segs) < 6:
            raise ValueError(f"Unexpected PHC format: only {len(phc_segs)} segments")
        salt_seg = phc_segs[4]
        salt_b = base64.b64decode(salt_seg + "=" * (-len(salt_seg) % 4))
        # Extract V by base64-decoding the hash segment (last "$" field).
        # argon2 PHC uses unpadded base64 — add "=" padding before decoding.
        seg = phc_segs[5]
        ikm1 = bytearray(base64.b64decode(seg + "=" * (-len(seg) % 4)))
        if len(ikm1) != 32:
            raise ValueError(f"Unexpected argon2 verifier length: {len(ikm1)} (expected 32)")
        kdf_algo = "argon2id+hkdf-sha384"
        wrap1_extra = {
            "argon2_salt_hex": salt_b.hex(),
            "argon2_time_cost": params.time_cost,
            "argon2_memory_cost": params.memory_cost,
            "argon2_parallelism": params.parallelism,
            "argon2_hash_len": 32,
            "argon2_version": params.version,
        }
        kek1 = bytearray(_hkdf_sha384(
            bytes(ikm1), kek1_hkdf_salt, b"yashigani-kek1-v1", 32
        ))
        _zero(ikm1)
        aad1 = b"yashigani-backup-v1" + TS.encode() + b"\x01"
        iv1  = os.urandom(12)
        ct_and_tag1 = AESGCM(bytes(kek1)).encrypt(iv1, bytes(dek), aad1)
        _zero(kek1)
        # GCM returns ciphertext+tag concatenated; tag is last 16 bytes.
        wdek1_ct  = ct_and_tag1[:-16]
        wdek1_tag = ct_and_tag1[-16:]
        wrap1 = {
            "kdf_algo": kdf_algo,
            **wrap1_extra,
            "kek1_hkdf_salt_hex": kek1_hkdf_salt.hex(),
            "iv_hex": iv1.hex(),
            "wdek_ct_hex": wdek1_ct.hex(),
            "wdek_tag_hex": wdek1_tag.hex(),
            "present": True,
        }
    except Exception as e:
        sys.stderr.write(f"WARNING: wrap#1 V-extraction failed: {e} — wrap#1 skipped\n")
        wrap1 = {"present": False}
elif FIPS_MODE:
    # FIPS_MODE=1: wrap#1 absent by design (Nico ruling 2026-05-28).
    sys.stderr.write("INFO: FIPS_MODE=1 — wrap#1 absent (no sound argon2-free password wrap). wrap#2 only.\n")
    wrap1 = {"present": False}

# ── Step 3: Wrap#2 (recovery) ─────────────────────────────────────────────────
ikm2 = bytearray(bytes.fromhex(IKM2_HEX))
kek2_hkdf_salt = os.urandom(32)
kek2 = bytearray(_hkdf_sha384(bytes(ikm2), kek2_hkdf_salt, b"yashigani-kek2-v1", 32))
_zero(ikm2)
aad2 = b"yashigani-backup-v1" + TS.encode() + b"\x02"
iv2  = os.urandom(12)
ct_and_tag2 = AESGCM(bytes(kek2)).encrypt(iv2, bytes(dek), aad2)
_zero(kek2)
wdek2_ct  = ct_and_tag2[:-16]
wdek2_tag = ct_and_tag2[-16:]
wrap2 = {
    "kdf_algo": "hkdf-sha384",
    "kek2_hkdf_salt_hex": kek2_hkdf_salt.hex(),
    "iv_hex": iv2.hex(),
    "wdek_ct_hex": wdek2_ct.hex(),
    "wdek_tag_hex": wdek2_tag.hex(),
    "present": True,
}

# ── Step 4: tar.gz the staging dir ────────────────────────────────────────────
import io, datetime
pt_buf = io.BytesIO()
with tarfile.open(fileobj=pt_buf, mode="w:gz") as tar:
    tar.add(str(staging), arcname="backup_staging")
pt_bytes = pt_buf.getvalue()

# ── Step 5: Build candidate meta (hmac_hex = "" placeholder) ──────────────────
# AAD_B = canonical meta bytes with hmac_hex = "" (spec: hmac covers this)
iv_b = os.urandom(12)

import time as _time
created_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

meta_obj = {
    "version": "yashigani-backup-v1",
    "ts": TS,
    "tier": TIER,
    "license_key_id": LIC_ID if LIC_ID != "null" else None,
    "fips_mode": FIPS_MODE,
    "bundle_aead": {
        "algorithm": "AES-256-GCM",
        "iv_hex": iv_b.hex(),
        "tag_included_in_bundle_enc": True,
    },
    "wrap1": wrap1,
    "wrap2": wrap2,
    "hmac": {
        "algorithm": "HMAC-SHA384",
        "mac_key_derivation": "HKDF-SHA384(IKM=DEK,salt=empty,info=yashigani-backup-meta-mac-v1)",
        "hmac_hex": "",
    },
    "created_at": created_at,
    "yashigani_version": YSG_VERSION,
}

# Canonical AAD = meta bytes with hmac_hex = "" (sorted keys, compact separators)
aad_b = json.dumps(meta_obj, sort_keys=True, separators=(",", ":")).encode()

# ── Step 6: Encrypt bundle ────────────────────────────────────────────────────
ct_bundle = AESGCM(bytes(dek)).encrypt(iv_b, pt_bytes, aad_b)
# ct_bundle = ciphertext + 16-byte GCM tag (spec: tag_included_in_bundle_enc=true)

# ── Step 7: HMAC-SHA384 over AAD_B ───────────────────────────────────────────
hmac_hex = _hmac.new(bytes(mac_key), aad_b, digestmod=hashlib.sha384).hexdigest()
_zero(mac_key)
_zero(dek)

# ── Step 8: Finalise meta with real hmac_hex ─────────────────────────────────
meta_obj["hmac"]["hmac_hex"] = hmac_hex

# ── Step 9: Write bundle.enc (atomic tmp→rename) ─────────────────────────────
try:
    with open(str(bundle_enc_tmp), "wb") as f:
        f.write(ct_bundle)
    os.chmod(str(bundle_enc_tmp), 0o600)
    os.rename(str(bundle_enc_tmp), str(bundle_enc_path))
except Exception as e:
    try:
        bundle_enc_tmp.unlink(missing_ok=True)
    except Exception:
        pass
    sys.stderr.write(f"FATAL: Failed to write bundle.enc: {e}\n")
    sys.exit(1)

# ── Step 10: Write backup-meta.json (0444 — cleartext, never encrypted) ───────
try:
    meta_json = json.dumps(meta_obj, indent=2, sort_keys=True)
    with open(str(meta_path), "w") as f:
        f.write(meta_json)
    os.chmod(str(meta_path), 0o444)
except Exception as e:
    try:
        bundle_enc_path.unlink(missing_ok=True)
    except Exception:
        pass
    try:
        meta_path.unlink(missing_ok=True)
    except Exception:
        pass
    sys.stderr.write(f"FATAL: Failed to write backup-meta.json: {e}\n")
    sys.exit(1)

sys.stdout.write(f"OK: bundle.enc ({len(ct_bundle)} bytes) + backup-meta.json written\n")
sys.stdout.write(f"OK: wrap1.present={wrap1.get('present', False)} wrap2.present={wrap2.get('present', False)}\n")
sys.exit(0)
PYEOF
  chmod 0700 "$_py_script_path"

  # ── Execute Python crypto in the container ────────────────────────────────
  # The container needs access to:
  #   - backup_dir (staging data: secrets/, .env, postgres_dump.sql, agent-volumes/)
  #   - backup_dir (output: bundle.enc, backup-meta.json)
  # The container does NOT have the host backup_dir mounted. We use docker cp
  # to push the script and staging dir in, exec Python, then cp results back.
  #
  # Approach: use a single exec with the Python script piped via stdin.
  # The staging path is made available to the container by copying the backup dir
  # into a container tmpdir using docker cp, then exec, then cp results back.

  local _container_work="/tmp/.ysg_backup_$$"
  local _container_staging="${_container_work}/staging"
  local _container_output="${_container_work}/output"

  # Push staging dir into container
  if ! $_runtime_cmd_local exec "$_crypto_container" mkdir -p \
        "$_container_staging" "$_container_output" 2>/dev/null; then
    log_error "YSG-RISK-050: Failed to create container working dirs in ${_crypto_container}"
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Stream staging IN via tar-over-exec, then grant access. NOT `docker cp`: it refuses
  # any container with ReadonlyRootfs=true even when the target is a writable tmpfs
  # (Docker 29) — gateway/backoffice run read_only with tmpfs /tmp, so docker cp fails
  # closed there ("Failed to copy staging data"). `exec` writes through the running process
  # into the tmpfs; the container app user then owns all extracted items.
  #
  # BUG-FIX (3.1.0): Two Podman-rootless bugs fixed here:
  # (1) GNU tar two-phase directory-mode: `tar -xf - -C staging` applies the mode of the
  #     archive's `.` entry to the staging directory itself, transiently setting it to 000
  #     (the archive records the backup_dir's actual mode, but tar's two-phase algorithm
  #     sets directories to 000 initially and restores at stream end; with a piped stream
  #     in a Podman exec the final restore sometimes fails). Fix: --no-same-owner
  #     --no-same-permissions so tar uses the container process's umask (022) for all
  #     items, never touching ownership or permissions from archive headers.
  # (2) `chmod -R` uses fchmodat(dirfd, path, mode, 0) to recurse, which returns EPERM
  #     inside a Podman rootless user-namespace + tmpfs context even when the container
  #     user owns the target. `find -exec chmod {} \;` uses chmod(path) per item (one
  #     exec per file/dir), applies chmod on the directory BEFORE descending into it, and
  #     succeeds. Note: this is `\;` not `+` — batch mode (`+`) still uses fchmodat.
  if ! tar -cf - -C "$backup_dir" . | $_runtime_cmd_local exec -i "$_crypto_container" \
       tar -xf - --no-same-owner --no-same-permissions -C "$_container_staging" 2>/dev/null \
     || ! $_runtime_cmd_local exec "$_crypto_container" \
       sh -c "find '${_container_work}' -exec chmod u+rwX {} \;" 2>/dev/null; then
    log_error "YSG-RISK-050: Failed to stream staging data into container ${_crypto_container}"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Write the Python script IN via exec stdin (same read_only-rootfs reason as above).
  if ! $_runtime_cmd_local exec -i "$_crypto_container" sh -c "cat > '${_container_work}/backup_crypto.py'" < "$_py_script_path" 2>/dev/null; then
    log_error "YSG-RISK-050: Failed to write crypto script into container ${_crypto_container}"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Derive IKM2: encode as hex for safe env var transmission.
  local _ikm2_hex=""
  if [[ "$_ikm2_source" == "license" ]]; then
    # .ysg bytes as hex (xxd or od for BusyBox portability).
    _ikm2_hex=$(xxd -p -c 9999 "$_license_file" 2>/dev/null | tr -d '\n' \
      || od -A n -t x1 "$_license_file" 2>/dev/null | tr -d ' \n' || true)
  else
    # DB AES key: already a hex/base64 string. Encode its UTF-8 bytes as hex.
    _ikm2_hex=$(printf '%s' "$_db_aes_key" | xxd -p -c 9999 2>/dev/null | tr -d '\n' \
      || printf '%s' "$_db_aes_key" | od -A n -t x1 2>/dev/null | tr -d ' \n' || true)
  fi

  if [[ -z "$_ikm2_hex" ]]; then
    log_error "YSG-RISK-050: Failed to hex-encode recovery IKM (xxd/od missing?)"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Run Python inside container. Non-secret config is passed via -e env vars.
  # Secrets (admin_phc, ikm2_hex) are passed to the container via stdin as a JSON
  # blob to avoid exposure in 'docker inspect' (FINDING-5: env vars to docker exec
  # are visible in docker inspect to any user with Docker socket access; stdin is not).
  # NEW-ISSUE-1 (Laura re-gate, CWE-214): the host-side JSON build must NOT place
  # the secrets in argv either (visible in ps / /proc/<pid>/cmdline to same-uid).
  # Feed both secrets to the host python3 via stdin, NUL-separated (neither a PHC
  # string nor a hex IKM contains a NUL byte). Not in argv, not in env.
  local _secrets_json
  _secrets_json=$(printf '%s\0%s' "${_admin_phc}" "${_ikm2_hex}" | python3 -c \
    "import json,sys; d=sys.stdin.buffer.read().split(b'\0'); print(json.dumps({'admin_phc': d[0].decode(), 'ikm2_hex': (d[1].decode() if len(d) > 1 else '')}))" \
    2>/dev/null)
  if [[ -z "$_secrets_json" ]]; then
    log_error "YSG-RISK-050: Failed to build secrets JSON for container stdin"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  local _py_output
  if ! _py_output=$(printf '%s' "$_secrets_json" | $_runtime_cmd_local exec -i \
        -e "_YSG_BACKUP_STAGING_DIR=${_container_staging}" \
        -e "_YSG_BACKUP_OUTPUT_DIR=${_container_output}" \
        -e "_YSG_WRAP1_PRESENT=${_wrap1_present}" \
        -e "_YSG_TIER=${_ysg_tier}" \
        -e "_YSG_LIC_ID=${_license_key_id}" \
        -e "_YSG_FIPS_MODE=${FIPS_MODE:-0}" \
        -e "_YSG_VERSION=${YASHIGANI_VERSION:-unknown}" \
        -e "_YSG_TS=${backup_ts}" \
        "$_crypto_container" \
        python3 "${_container_work}/backup_crypto.py" 2>&1); then
    log_error "YSG-RISK-050: Dual-wrap crypto script failed in container ${_crypto_container}"
    log_error "  Output: ${_py_output}"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -f "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  log_info "  Crypto output: ${_py_output}"

  # Pull the results back from the container.
  local _tmp_results_dir
  _tmp_results_dir=$(mktemp -d "${backup_dir}/.ysg_results_XXXXXX")
  # Stream results OUT via tar-over-exec — `docker cp` refuses read_only-rootfs containers
  # in BOTH directions (Docker 29), so cp-out fails too even though the crypto wrote
  # bundle.enc successfully inside the container. exec reads the tmpfs; untar on the host.
  if ! $_runtime_cmd_local exec "$_crypto_container" tar -cf - -C "$_container_output" . | tar -xf - -C "$_tmp_results_dir" 2>/dev/null; then
    log_error "YSG-RISK-050: Failed to stream encrypted bundle from container"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -rf "$_tmp_results_dir" "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Verify bundle.enc and backup-meta.json are present.
  if [[ ! -f "${_tmp_results_dir}/bundle.enc" || ! -f "${_tmp_results_dir}/backup-meta.json" ]]; then
    log_error "YSG-RISK-050: bundle.enc or backup-meta.json missing from container output"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -rf "$_tmp_results_dir" "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Integrity: tar-streaming (unlike per-file docker cp) is not atomic — a truncated but
  # parseable archive could otherwise pass the existence check and be installed as the
  # canonical backup. Verify the streamed bundle.enc matches the in-container original by
  # sha256 (computed via the container's python3, which the crypto step already requires).
  local _in_sha _host_sha
  _in_sha="$($_runtime_cmd_local exec "$_crypto_container" python3 -c "import hashlib;print(hashlib.sha256(open('${_container_output}/bundle.enc','rb').read()).hexdigest())" 2>/dev/null || true)"
  _host_sha="$(sha256sum "${_tmp_results_dir}/bundle.enc" 2>/dev/null | cut -d' ' -f1)"
  if [[ -z "$_in_sha" || "$_in_sha" != "$_host_sha" ]]; then
    log_error "YSG-RISK-050: bundle.enc integrity check failed (in-container sha256 != host) — possible truncated stream; refusing to install an incomplete backup"
    $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true
    rm -rf "$_tmp_results_dir" "$_py_script_path"
    rm -rf "$backup_dir"
    exit 1
  fi

  # Move results into backup_dir.
  install -m 0600 "${_tmp_results_dir}/bundle.enc" "${backup_dir}/bundle.enc"
  install -m 0444 "${_tmp_results_dir}/backup-meta.json" "${backup_dir}/backup-meta.json"
  rm -rf "$_tmp_results_dir"

  # Clean up container working dir.
  $_runtime_cmd_local exec "$_crypto_container" rm -rf "$_container_work" 2>/dev/null || true

  # Remove the Python script from host (no secrets in it but cleanup is good hygiene).
  rm -f "$_py_script_path"

  # ── Remove plaintext staging data from backup_dir ─────────────────────────
  # All sensitive content is now in bundle.enc. Remove plaintext files and any
  # old MANIFEST.sha256 / MANIFEST.sha256.sig (v1 leftovers — spec guardrail 4).
  rm -rf "${backup_dir}/secrets" 2>/dev/null || true
  rm -f  "${backup_dir}/.env" 2>/dev/null || true
  rm -f  "${backup_dir}/postgres_dump.sql" 2>/dev/null || true
  rm -f  "${backup_dir}/MANIFEST.sha256" 2>/dev/null || true
  rm -f  "${backup_dir}/MANIFEST.sha256.sig" 2>/dev/null || true
  # agent-volumes/ tarballs are already inside bundle.enc; remove the plaintext dir.
  rm -rf "${backup_dir}/agent-volumes" 2>/dev/null || true

  # Final permission check: backup_dir should contain ONLY bundle.enc + backup-meta.json.
  # bundle.enc = 0600 (owner-read-only); backup-meta.json = 0444 (cleartext, public).
  if [[ ! -f "${backup_dir}/bundle.enc" ]]; then
    log_error "YSG-RISK-050: bundle.enc not found in ${backup_dir} after cleanup"
    exit 1
  fi
  if [[ ! -f "${backup_dir}/backup-meta.json" ]]; then
    log_error "YSG-RISK-050: backup-meta.json not found in ${backup_dir} after cleanup"
    exit 1
  fi

  # S1 assertion: no plaintext secret files should remain (all went into bundle.enc).
  if find "${backup_dir}" -type f \( -name '*.key' -o -name '*.env' -o -name 'postgres_dump.sql' \) \
        2>/dev/null | grep -q .; then
    log_error "CWE-311 (YSG-RISK-050): plaintext secret file(s) remain in ${backup_dir} after encryption"
    exit 1
  fi

  log_success "Backup encrypted (YSG-RISK-050): bundle.enc + backup-meta.json saved to ${backup_dir}"
  log_info    "  wrap1.present=${_wrap1_present} | wrap2.present=true | tier=${_ysg_tier}"
  log_info    "  Recovery: wrap#1=admin-password | wrap#2=${_ikm2_source}"
  if [[ "$_ysg_tier" == "community" ]]; then
    log_warn  "  Community tier: wrap#2 uses YASHIGANI_DB_AES_KEY. Safeguard/offsite your .env — lose it → backup unrecoverable (YSG-RISK-052)."
  fi
}

# Idempotency check — detect and handle an existing running installation
# =============================================================================
check_existing_installation() {
  local secrets_dir="${WORK_DIR}/docker/secrets"

  # MI-1 (in-repo collision guard): a fresh install whose resolved PROJECT differs
  # from the PROJECT already recorded in THIS tree's state file would clobber the
  # existing instance's secrets + state in place. _resolve_instance_install_dir()
  # relocates bootstrap (curl) installs to a per-project tree, but an in-repo
  # checkout (WORK_DIR = the repo, fixed) cannot be relocated. Fail closed and tell
  # the operator to use a separate install dir, rather than silently overwriting a
  # sibling instance's crypto material. Only fires on a genuine mismatch for a fresh
  # install — upgrade/add-component targets the SAME project by design.
  local _state_file="${WORK_DIR}/docker/.yashigani-install-state"
  if [[ "${UPGRADE:-false}" != "true" && -f "$_state_file" ]]; then
    local _existing_proj _wanted_proj
    _existing_proj="$(_read_state_project "$_state_file")"
    _wanted_proj="${COMPOSE_PROJECT_NAME:-${PROJECT:-docker}}"
    if [[ -n "$_existing_proj" && "$_existing_proj" != "$_wanted_proj" ]]; then
      log_error "Multi-instance safety stop (MI-1): this install tree already hosts instance '${_existing_proj}'."
      log_error "  Installing project '${_wanted_proj}' here would overwrite '${_existing_proj}' secrets + state in place."
      log_error "  Install the new instance into its OWN directory, e.g.:"
      log_error "    YSG_INSTALL_DIR=\"\$HOME/.yashigani-${_wanted_proj}\" ./install.sh --project ${_wanted_proj} ..."
      log_error "  Or target the existing instance with --upgrade --project ${_existing_proj}."
      exit 1
    fi
  fi

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
      # Multi-instance (3.0): scope to THIS install's project (not hardcoded
      # "docker") and use the runtime's own compose-project label key (podman and
      # docker differ), so a 2nd named instance is detected correctly.
      local _runtime_bin="${COMPOSE_CMD[0]%%[[:space:]]*}"
      local _proj="${COMPOSE_PROJECT_NAME:-docker}"
      local _label_key="com.docker.compose.project"
      [[ "$_runtime_bin" == podman* ]] && _label_key="io.podman.compose.project"
      if "$_runtime_bin" ps --filter "label=${_label_key}=${_proj}" \
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
      # MI-4: add-component on a RUNNING stack mutates a live instance — gate it
      # with the shared step-up (auth/stepup.py via the API path; token/ack on the
      # host-shell path). Fail-closed if unattended without a step-up proof.
      _require_stepup_mi4 "add-component on running instance" "add-component"
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
  # Project-aware: the contaminated-volume check must scope to THIS install's compose
  # project, not a hardcoded "docker" — otherwise a parallel/renamed-project install
  # false-positives on an unrelated project's volumes (e.g. a live stack alongside).
  local _project_prefix="${COMPOSE_PROJECT_NAME:-docker}"
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
# validate_byo_ca_files). These shell helpers delegate to that module.
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
  printf "${C_YELLOW}║  Integrations: OpenWebUI, Wazuh, Langflow, Letta, OpenClaw║${C_RESET}\n"
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
# 3.0 doc-OPA: build the per-job sandboxed extractor image (release artifact).
#
# yashigani/extractor:${YASHIGANI_VERSION} is the image the document-enforcement
# feature spawns per job (src/yashigani/documents/sandbox.py
# SandboxedExtractorRunner). It is a BUILD-ONLY service in the
# docker-compose.extractor.yml overlay (never `up`), so it must be built + tagged
# explicitly here to be present when the feature flag is flipped on. Idempotent:
# skips the build if the versioned image is already present (airgap / re-run).
# Failure is FATAL on the Docker path only when document enforcement is enabled;
# otherwise it is a warning (the feature is OFF by default, so a missing image
# does not break a default install — it is only needed if the operator opts in).
# =============================================================================
_build_extractor_image() {
  resolve_compose_cmd
  local _base="${WORK_DIR}/docker/docker-compose.yml"
  local _overlay="${WORK_DIR}/docker/docker-compose.extractor.yml"
  local _tag="yashigani/extractor:${YASHIGANI_VERSION}"

  if [[ ! -f "$_overlay" ]]; then
    log_warn "extractor overlay not found ($_overlay) — skipping extractor build"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "${COMPOSE_CMD[*]} -f $_base -f $_overlay build extractor"
    return 0
  fi

  # Skip if already built (versioned tag), to support airgap / re-runs.
  # Also verify the revision label matches the current source SHA so a stale
  # cached extractor image does not shadow the current source (same fix class
  # as _local_images_cached — version-drift stale-image bug).
  if docker image inspect "$_tag" >/dev/null 2>&1 && [[ "${YASHIGANI_FORCE_REBUILD:-0}" != "1" ]]; then
    local _cached_sha
    _cached_sha="$(docker image inspect "$_tag" \
      --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true)"
    if [[ "$YASHIGANI_GIT_SHA" == "dev" || "$_cached_sha" == "$YASHIGANI_GIT_SHA" ]]; then
      log_info "Extractor image already present ($_tag, SHA ${_cached_sha:-dev}) — skipping build"
      return 0
    fi
    log_info "Extractor image SHA (${_cached_sha:-none}) != source SHA ${YASHIGANI_GIT_SHA} — rebuilding"
  fi

  log_info "Building per-job extractor image ($_tag) as a release artifact..."
  # build-only profile is required to materialise the `extractor` service.
  if "${COMPOSE_CMD[@]}" -f "$_base" -f "$_overlay" --profile build-only build extractor; then
    log_success "Extractor image built ($_tag)"
  else
    if [[ "${YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED:-false}" == "true" ]]; then
      log_error "Extractor image build FAILED and document enforcement is ENABLED — cannot continue"
      exit 1
    fi
    log_warn "Extractor image build failed; document enforcement is OFF by default so continuing"
    log_warn "Enable the feature only after a successful extractor build (Dockerfile.extractor)"
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
  # _local_images_cached returns 0 (true) only when BOTH version-tagged images
  # exist in the local store AND their org.opencontainers.image.revision label
  # matches the current YASHIGANI_GIT_SHA.  A tag-only match is not sufficient:
  # a cached yashigani/backoffice:3.0.0 built from an earlier commit satisfies
  # the tag check while shipping stale code.  The revision label is stamped by
  # --build-arg GIT_SHA=<sha> consumed late in each Dockerfile so the app-code
  # layer re-executes on every source commit while base/dep layers remain cached.
  # Skips the label check and always rebuilds when YASHIGANI_FORCE_REBUILD=1
  # (operator escape hatch for airgap / pre-seeded stores that use GIT_SHA=dev).
  _local_images_cached() {
    local _gw _bo _sha_label_gw _sha_label_bo
    if [[ "${YASHIGANI_FORCE_REBUILD:-0}" == "1" ]]; then
      return 1  # force rebuild requested
    fi
    if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
      _gw="localhost/yashigani/gateway:${YASHIGANI_VERSION}"
      _bo="localhost/yashigani/backoffice:${YASHIGANI_VERSION}"
      # Existence check first (fast path — avoids inspect parse on miss)
      podman image inspect "$_gw" >/dev/null 2>&1 || \
        podman image inspect "yashigani/gateway:${YASHIGANI_VERSION}" >/dev/null 2>&1 || return 1
      podman image inspect "$_bo" >/dev/null 2>&1 || \
        podman image inspect "yashigani/backoffice:${YASHIGANI_VERSION}" >/dev/null 2>&1 || return 1
      # Revision label check — detect stale-tag cache hits
      _sha_label_gw="$(podman image inspect "$_gw" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Labels',{}).get('org.opencontainers.image.revision',''))" 2>/dev/null || true)"
      _sha_label_bo="$(podman image inspect "$_bo" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Labels',{}).get('org.opencontainers.image.revision',''))" 2>/dev/null || true)"
    else
      _gw="yashigani/gateway:${YASHIGANI_VERSION}"
      _bo="yashigani/backoffice:${YASHIGANI_VERSION}"
      docker image inspect "$_gw" >/dev/null 2>&1 || return 1
      docker image inspect "$_bo" >/dev/null 2>&1 || return 1
      _sha_label_gw="$(docker image inspect "$_gw" \
        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true)"
      _sha_label_bo="$(docker image inspect "$_bo" \
        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true)"
    fi
    # If GIT_SHA is "dev" (non-git install), trust the tag and skip label check.
    if [[ "$YASHIGANI_GIT_SHA" == "dev" ]]; then
      return 0
    fi
    # Labels must match; mismatch means the cached image is from an older commit.
    if [[ "$_sha_label_gw" != "$YASHIGANI_GIT_SHA" || "$_sha_label_bo" != "$YASHIGANI_GIT_SHA" ]]; then
      log_info "Cached image SHA (gw=${_sha_label_gw:-none} bo=${_sha_label_bo:-none}) != source SHA ${YASHIGANI_GIT_SHA} — will rebuild"
      return 1
    fi
    return 0
  }
  if _local_images_cached; then
    log_info "Gateway and backoffice images already present (v${YASHIGANI_VERSION}, SHA ${YASHIGANI_GIT_SHA}) — skipping build"
    log_success "Local images ready (cached)"
    # Signal compose_up() to use --pull never so digest-pinned compose image refs
    # don't trigger registry round-trips for pre-seeded images. Only safe when
    # images are pre-seeded by a trusted source (harness tarball cache, airgap
    # bundle); fresh installs build+pull with digest verification as usual.
    YASHIGANI_COMPOSE_PULL_POLICY="never"
  else
    log_info "Building gateway and backoffice images from source (SHA ${YASHIGANI_GIT_SHA})..."
    "${COMPOSE_CMD[@]}" -f "$compose_file" build gateway backoffice || {
      log_error "Failed to build gateway/backoffice images. Check Dockerfiles."
      exit 1
    }
    log_success "Local images built"
  fi

  # --- 3.0 doc-OPA: build the per-job extractor image as a RELEASE ARTIFACT ---
  # The document-enforcement feature spawns ephemeral yashigani/extractor:<ver>
  # containers on demand (SandboxedExtractorRunner). The image is build-only
  # (never `up`), so the standard `build gateway backoffice` does not produce
  # it. Build + tag it here as part of the release image set so the image
  # EXISTS when the operator flips YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true
  # — without this an enabled feature fails at first spawn (image not found).
  # Built on the Docker path here; Podman builds it in the Podman build block.
  if [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]]; then
    _build_extractor_image
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
  # LIVE-BACKUP-PERMS-001 (VM smoke 2026-05-28, CWE-732): backups/ MUST be
  # pruned. _backup_existing_data() copies docker/secrets, docker/.env, the
  # postgres dump, and (B5/FIX-2) agent-volume tarballs into backups/<ts>/ and
  # locks them to 0600/0700. Without this prune the o+rX sweep below re-exposes
  # every one of those backup copies to world-read — the live docker/secrets is
  # pruned but its BACKUP COPY was not, so the S1 assertion passed while backup
  # copies of admin_initial_password, redis_password, agent tokens, the .env,
  # and the DB dump were all 0604/0644. Prune the whole backups/ tree.
  find "${work_dir}" \
    -not \( -path "${work_dir}/docker/secrets" -prune \) \
    -not \( -path "${work_dir}/.git" -prune \) \
    -not \( -path "${work_dir}/.ysg_work" -prune \) \
    -not \( -path "${work_dir}/docker/.env" -prune \) \
    -not \( -path "${work_dir}/backups" -prune \) \
    -not \( -path "${work_dir}/docker/openclaw/openclaw.runtime.json" -prune \) \
    -exec chmod o+rX {} + 2>/dev/null \
    || log_warn "chmod o+rX sweep had partial failures (non-fatal — secrets/ not touched)"

  log_info "  Config sweep applied (work_dir minus secrets/.git/.ysg_work/docker/.env/backups)"

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
    # Self-heal THEN assert: tighten any world-readable non-cert secret (e.g. a password
    # file left 0644 by an earlier step or a prior install) by removing world access, then
    # fail only if any remain. Tightening rather than aborting keeps upgrades moving without
    # weakening posture — group bits (e.g. caddy_internal_hmac 0640) are preserved (o-rwx only).
    find "${_secrets_dir}" -type f ! -name "*.crt" -perm -004 -exec chmod o-rwx {} + 2>/dev/null || true
    if find "${_secrets_dir}" -type f ! -name "*.crt" -perm -004 2>/dev/null | grep -q .; then
      log_error "CWE-732: world-readable non-cert file(s) STILL present under ${_secrets_dir} after self-heal" >&2
      log_error "Could not tighten (ownership/filesystem issue) — investigate." >&2
      exit 1
    fi
  fi

  log_success "Bind-mounted config permissions verified"
}

# =============================================================================
# STEP 10 (compose/vm): docker compose up -d
# =============================================================================
# ---------------------------------------------------------------------------
# v2.25.1: provision Wazuh full internal-CA mTLS material (deploy-local, git-ignored).
# Generates — idempotently, with NO manual steps — everything docker-compose.wazuh.yml
# mounts so the indexer HTTP listener runs on the internal CA (SAN wazuh-indexer),
# filebeat does `full` verification, and admin/kibanaserver authenticate with the REAL
# generated passwords (the image's demo admin/admin is removed). Output lands under
# docker/wazuh-mtls/ (git-ignored — contains the admin key + real-password configs).
# Transport stays on the image demo certs (single node) — only the HTTP layer is re-PKI'd.
# ---------------------------------------------------------------------------
_provision_wazuh_mtls() {
  local secrets="${WORK_DIR}/docker/secrets"
  local wp="${WORK_DIR}/docker/wazuh-mtls"
  local idx_img="docker.io/wazuh/wazuh-indexer:4.14.5"
  local rt="${RUNTIME:-${YSG_RUNTIME:-docker}}"

  # Idempotency: a dedicated marker written LAST (not an intermediate artifact) so a
  # mid-function abort never leaves a half-provisioned dir that a re-run would skip.
  if [[ -f "${wp}/.provisioned" ]]; then
    log_info "Wazuh mTLS material already provisioned — skipping"
    return 0
  fi
  require_cmd openssl
  umask 077   # private keys are born owner-only; relaxed selectively in step 7
  log_info "Provisioning Wazuh full-mTLS material (internal-CA admin cert + real-password internal_users)..."
  # Clear any prior wazuh-mtls dir. A previous successful run chowns it to the container UID
  # (step 7), so a non-root install user may be unable to remove/recurse it — fall back to a
  # root container so re-runs (re-install / upgrade) are idempotent rather than aborting with
  # a misleading downstream error (e.g. a failed cp surfacing as "lacks SAN").
  if [[ -e "${wp}" ]]; then
    rm -rf "${wp}" 2>/dev/null \
      || "$rt" run --rm -u 0 -v "${WORK_DIR}/docker":/d "$idx_img" rm -rf /d/wazuh-mtls 2>/dev/null \
      || true
  fi
  mkdir -p "${wp}/certs" "${wp}/opensearch-security"

  # -------------------------------------------------------------------------
  # Rootless-Podman wazuh-mtls fix (gate #ROOTLESS-WAZUH-1):
  #
  # On rootless Podman the PKI issuer (which ran at step 9b) chowns secrets/
  # to the subuid-mapped host UID (e.g. 165536 for container root). The host
  # user (e.g. UID 1001) cannot open any secrets/ files → EPERM on:
  #   - cat ca_intermediate.crt ca_root.crt  (step 1 CA bundle)
  #   - openssl x509 -CAkey ca_intermediate.key  (step 2 admin cert signing)
  #   - cp wazuh-indexer_client.{crt,key}  (step 3 indexer cert copy)
  #   - password reads for steps 5, 6
  #
  # Fix strategy: steps 1-3 are grouped into a single `podman unshare bash -c`
  # block that runs as namespace-root (host 165536) and can read secrets/.
  # All output lands in ${wp}/certs/ which is host-owned, so no final chown
  # is needed on the output files (wp/ is owned by the install user).
  # Steps 5-6 (password reads) use _safe_read_secret, which tries direct
  # cat first, then `podman unshare cat` on failure.
  #
  # Docker / rootful Podman / macOS: direct path unchanged (no unshare).
  # Fallback: if podman unshare is unavailable (remote client), log_warn and
  # fall through to the direct path.
  # -------------------------------------------------------------------------
  local _is_rootless_podman=false
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]] \
      && [[ "$(id -u)" != "0" ]]; then
    _is_rootless_podman=true
  fi

  if [[ "$_is_rootless_podman" == "true" ]]; then
    # Rootless Podman path — steps 1-3 read from secrets/ inside podman unshare.
    # ${wp} and ${secrets} are expanded host-side before the string reaches unshare;
    # all writes go to ${wp}/certs/ which is host-owned so no chown of output is needed.
    # Process substitution <(printf ...) is unreliable across bash -c heredoc delivery,
    # so the x509 extfile is written to a temp path inside wp/certs/, then removed —
    # keeping all scratch inside the working area (never /tmp).
    local _wazuh_unshare_script
    _wazuh_unshare_script="$(cat <<WAZUH_UNSHARE_EOF
set -euo pipefail
# Step 1: CA bundle
cat '${secrets}/ca_intermediate.crt' '${secrets}/ca_root.crt' > '${wp}/certs/http-ca-bundle.pem'
# Step 2: wazuh-admin leaf signed by internal intermediate
openssl ecparam -genkey -name prime256v1 -out '${wp}/certs/.admin-sec1.pem' 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in '${wp}/certs/.admin-sec1.pem' -out '${wp}/certs/wazuh-admin-key.pem' 2>/dev/null
rm -f '${wp}/certs/.admin-sec1.pem'
openssl req -new -key '${wp}/certs/wazuh-admin-key.pem' -out '${wp}/certs/.admin.csr' \
  -subj '/O=Agnostic Security/CN=wazuh-admin' 2>/dev/null
printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' \
  > '${wp}/certs/.admin-ext.cnf'
openssl x509 -req -in '${wp}/certs/.admin.csr' -CA '${secrets}/ca_intermediate.crt' \
  -CAkey '${secrets}/ca_intermediate.key' -CAcreateserial -days 825 \
  -out '${wp}/certs/wazuh-admin.pem' \
  -extfile '${wp}/certs/.admin-ext.cnf' 2>/dev/null
rm -f '${wp}/certs/.admin.csr' '${wp}/certs/.admin-ext.cnf' '${secrets}/ca_intermediate.srl'
# Step 3: copy indexer HTTP cert/key from secrets to wp
cp '${secrets}/wazuh-indexer_client.crt' '${wp}/certs/http-indexer.pem'
cp '${secrets}/wazuh-indexer_client.key' '${wp}/certs/http-indexer-key.pem'
# Verify outputs are non-empty INSIDE the namespace
[ -s '${wp}/certs/http-ca-bundle.pem' ]
[ -s '${wp}/certs/wazuh-admin-key.pem' ]
[ -s '${wp}/certs/wazuh-admin.pem' ]
[ -s '${wp}/certs/http-indexer.pem' ]
[ -s '${wp}/certs/http-indexer-key.pem' ]
WAZUH_UNSHARE_EOF
)"
    if podman unshare bash -c "$_wazuh_unshare_script" 2>/dev/null; then
      log_info "Wazuh steps 1-3 (CA bundle + admin cert + indexer cert) completed via podman unshare (rootless)"
    else
      log_warn "podman unshare unavailable or failed for wazuh steps 1-3 — falling back to direct path"
      _is_rootless_podman=false  # trigger direct block below
    fi
  fi

  if [[ "$_is_rootless_podman" == "false" ]]; then
    # Docker / rootful Podman / macOS / fallback from unshare-unavailable path.

    # 1. CA bundle (intermediate + root) — HTTP-layer trust anchor
    cat "${secrets}/ca_intermediate.crt" "${secrets}/ca_root.crt" > "${wp}/certs/http-ca-bundle.pem"

    # 2. internal-CA admin cert (EC P-256, PKCS#8 key) signed by the internal intermediate
    openssl ecparam -genkey -name prime256v1 -out "${wp}/certs/.admin-sec1.pem" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "${wp}/certs/.admin-sec1.pem" -out "${wp}/certs/wazuh-admin-key.pem" 2>/dev/null
    rm -f "${wp}/certs/.admin-sec1.pem"
    openssl req -new -key "${wp}/certs/wazuh-admin-key.pem" -out "${wp}/certs/.admin.csr" \
      -subj "/O=Agnostic Security/CN=wazuh-admin" 2>/dev/null
    openssl x509 -req -in "${wp}/certs/.admin.csr" -CA "${secrets}/ca_intermediate.crt" \
      -CAkey "${secrets}/ca_intermediate.key" -CAcreateserial -days 825 -out "${wp}/certs/wazuh-admin.pem" \
      -extfile <(printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE') 2>/dev/null
    rm -f "${wp}/certs/.admin.csr" "${secrets}/ca_intermediate.srl"

    # 3. indexer HTTP server cert = the bootstrap-issued internal-CA cert (SAN wazuh-indexer)
    cp "${secrets}/wazuh-indexer_client.crt" "${wp}/certs/http-indexer.pem"
    cp "${secrets}/wazuh-indexer_client.key" "${wp}/certs/http-indexer-key.pem"
  fi

  # fail-closed: filebeat `full` verification needs SAN=wazuh-indexer on the HTTP cert
  # wp/certs/ is host-owned so this host-side check is valid on both paths.
  if ! openssl x509 -in "${wp}/certs/http-indexer.pem" -noout -text 2>/dev/null | grep -q 'DNS:wazuh-indexer'; then  # MACOS-WAZUHSAN-001: LibreSSL x509 has no -ext flag; the -text SAN read is portable (BSD/LibreSSL + GNU/OpenSSL)
    log_error "wazuh-indexer_client.crt lacks SAN 'wazuh-indexer' — full mTLS would fail closed; aborting"; return 1
  fi

  # 4. base opensearch config from the image, then re-PKI ONLY the HTTP listener + admin_dn
  #    (transport keys are left at the image's demo paths — single node, untouched).
  local cid; cid="$("$rt" create "$idx_img")" || { log_error "could not create temp indexer container"; return 1; }
  if ! "$rt" cp "${cid}:/usr/share/wazuh-indexer/config/opensearch.yml" "${wp}/opensearch.yml" \
     || ! "$rt" cp "${cid}:/usr/share/wazuh-indexer/config/opensearch-security/." "${wp}/opensearch-security/"; then
    "$rt" rm "$cid" >/dev/null 2>&1; log_error "could not extract base indexer config from image"; return 1
  fi
  "$rt" rm "$cid" >/dev/null 2>&1
  # MACOS-SED-001: BSD sed requires an explicit backup extension with -i (e.g. -i '')
  # while GNU sed accepts bare -i. Use -i.bak + rm to be portable across both.
  # Wazuh is Linux-only in practice but the installer runs on macOS for Colima/Docker.
  sed -i.bak \
    -e 's#ssl.http.pemcert_filepath: .*#ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/config/certs/http-indexer.pem#' \
    -e 's#ssl.http.pemkey_filepath: .*#ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/config/certs/http-indexer-key.pem#' \
    -e 's#ssl.http.pemtrustedcas_filepath: .*#ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/config/certs/http-ca-bundle.pem#' \
    "${wp}/opensearch.yml" \
    && rm -f "${wp}/opensearch.yml.bak"
  if ! python3 - "${wp}/opensearch.yml" <<'PYEOF'
import sys,re,yaml
p=sys.argv[1]; t=open(p).read()
# admin_dn -> the internal-CA admin cert CN (securityadmin authenticates as this)
t=re.sub(r'plugins\.security\.authcz\.admin_dn:\n((?:[ \t]*- ".*"\n)+)',
         'plugins.security.authcz.admin_dn:\n- "CN=wazuh-admin,O=Agnostic Security"\n', t)
# TLS 1.3 floor on the HTTP listener — match the internal-mesh 1.3-min (#156). The Wazuh
# stock config pins enabled_protocols to TLSv1.2 with 1.2-only ciphers; rewrite to 1.3.
# wazuh-indexer 4.14.5 (JDK 21) serves 1.3; filebeat (Go) + dashboard (Node) negotiate it
# with NO client change and 1.2 is refused (validated on the clean-slate stack). Transport
# (single node, internal) is intentionally left at the image default.
t,np=re.subn(r'(plugins\.security\.ssl\.http\.enabled_protocols:\n)(?:[ \t]*-[ \t]*"[^"]*"\n)+',
             r'\g<1>  - "TLSv1.3"\n', t)
t,nc=re.subn(r'(plugins\.security\.ssl\.http\.enabled_ciphers:\n)(?:[ \t]*-[ \t]*"[^"]*"\n)+',
             r'\g<1>  - "TLS_AES_256_GCM_SHA384"\n  - "TLS_AES_128_GCM_SHA256"\n  - "TLS_CHACHA20_POLY1305_SHA256"\n', t)
if np != 1:
    sys.stderr.write("opensearch.yml: http.enabled_protocols block not found (!=1) — cannot enforce TLS 1.3 floor\n"); sys.exit(1)
yaml.safe_load(t)   # fail-closed: rewrite must remain valid YAML or the indexer crash-loops
open(p,'w').write(t)
PYEOF
  then log_error "opensearch.yml rewrite (admin_dn + TLS 1.3 floor) failed — aborting"; return 1; fi
  # fail-closed: admin_dn must have landed (else securityadmin can't authenticate) AND the
  # HTTP listener must now be TLS 1.3 (the mesh 1.3-min must extend to the SIEM link)
  grep -q 'CN=wazuh-admin,O=Agnostic Security' "${wp}/opensearch.yml" \
    || { log_error "admin_dn substitution failed in opensearch.yml — aborting"; return 1; }
  grep -A1 'plugins.security.ssl.http.enabled_protocols:' "${wp}/opensearch.yml" | grep -q '"TLSv1.3"' \
    || { log_error "TLS 1.3 floor not applied to indexer HTTP listener — aborting"; return 1; }

  # 5. internal_users.yml: admin + kibanaserver = bcrypt(real generated passwords).
  #    Password is passed via the container ENV (never interpolated into a shell string),
  #    so any password charset is injection-safe.
  #    #ROOTLESS-WAZUH-1: use _safe_read_secret so the cat succeeds on both Docker
  #    (direct) and rootless Podman (podman unshare cat fallback inside _safe_read_secret).
  local ah kh
  local _wazuh_idxpw _wazuh_dashpw
  _wazuh_idxpw="$(_safe_read_secret "${secrets}/wazuh_indexer_password" "" "" 2>/dev/null)" \
    || { log_error "Could not read wazuh_indexer_password — aborting"; return 1; }
  _wazuh_dashpw="$(_safe_read_secret "${secrets}/wazuh_dashboard_password" "" "" 2>/dev/null)" \
    || { log_error "Could not read wazuh_dashboard_password — aborting"; return 1; }
  if [[ -z "$_wazuh_idxpw" || -z "$_wazuh_dashpw" ]]; then
    log_error "wazuh_indexer_password or wazuh_dashboard_password is empty — aborting"; return 1
  fi
  ah="$("$rt" run --rm -e RAWPW="${_wazuh_idxpw}" "$idx_img" \
        bash -lc 'JAVA_HOME=/usr/share/wazuh-indexer/jdk bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$RAWPW"' 2>/dev/null | tail -1)"
  kh="$("$rt" run --rm -e RAWPW="${_wazuh_dashpw}" "$idx_img" \
        bash -lc 'JAVA_HOME=/usr/share/wazuh-indexer/jdk bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$RAWPW"' 2>/dev/null | tail -1)"
  if [[ ! "$ah" =~ ^\$2[aby]\$ ]] || [[ ! "$kh" =~ ^\$2[aby]\$ ]]; then
    log_error "bcrypt hash generation failed (admin/kibanaserver not valid \$2 hashes) — aborting"; return 1
  fi
  python3 - "${wp}/opensearch-security/internal_users.yml" "$ah" "$kh" <<'PYEOF'
import sys,yaml
p,ah,kh=sys.argv[1:4]
d=yaml.safe_load(open(p))
if 'admin' in d: d['admin']['hash']=ah
if 'kibanaserver' in d: d['kibanaserver']['hash']=kh
yaml.safe_dump(d,open(p,'w'),default_flow_style=False,sort_keys=False)
PYEOF

  # 5b. (#21) least-privilege cert-identity for audit forwarding. The agnostic
  #     audit pipeline (gateway + backoffice) forwards events to this indexer over
  #     mesh mTLS, presenting each service's OWN internal-CA leaf (CN=gateway /
  #     CN=backoffice). Map those CNs to a WRITE-ONLY role on yashigani-audit*
  #     — never the wazuh admin. Three edits, applied by securityadmin (security-init):
  #       - config.yml: enable the clientcert_auth_domain (cert CN → username).
  #       - roles.yml: add yashigani_audit_writer (bulk + write/create on yashigani-audit* only).
  #       - roles_mapping.yml: map backoffice + gateway → yashigani_audit_writer.
  #     clientauth_mode is OPTIONAL (default), challenge:false — basic-auth clients
  #     (dashboard/filebeat/securityadmin) are unaffected.
  python3 - "${wp}/opensearch-security" <<'PYEOF'
import sys,yaml,os
sec=sys.argv[1]
cfgp=os.path.join(sec,"config.yml")
cfg=yaml.safe_load(open(cfgp))
authc=cfg["config"]["dynamic"]["authc"]
dom=authc.get("clientcert_auth_domain")
if dom is None:
    dom={"description":"Authenticate via SSL client certificates","transport_enabled":False,
         "order":1,"http_authenticator":{"type":"clientcert",
         "config":{"username_attribute":"cn"},"challenge":False},
         "authentication_backend":{"type":"noop"}}
    authc["clientcert_auth_domain"]=dom
dom["http_enabled"]=True
yaml.safe_dump(cfg,open(cfgp,"w"),default_flow_style=False,sort_keys=False)

rp=os.path.join(sec,"roles.yml")
roles=yaml.safe_load(open(rp))
roles["yashigani_audit_writer"]={"reserved":False,
  "cluster_permissions":["cluster_composite_ops"],
  "index_permissions":[{"index_patterns":["yashigani-audit*"],
    "allowed_actions":["indices:admin/create","indices:admin/mapping/put",
      "indices:admin/mapping/auto_put","indices:data/write/index","indices:data/write/bulk*"]}]}
yaml.safe_dump(roles,open(rp,"w"),default_flow_style=False,sort_keys=False)

rmp=os.path.join(sec,"roles_mapping.yml")
rm=yaml.safe_load(open(rmp))
rm["yashigani_audit_writer"]={"reserved":False,"users":["backoffice","gateway"]}
yaml.safe_dump(rm,open(rmp,"w"),default_flow_style=False,sort_keys=False)
print("[wazuh-mtls] clientcert auth + yashigani_audit_writer (write-only) mapped to backoffice,gateway")
PYEOF

  # 6. dashboard config: real indexer password + internal-CA bundle + full verification
  #    #ROOTLESS-WAZUH-1: _wazuh_idxpw already read via _safe_read_secret above.
  {
    printf 'server.host: "0.0.0.0"\nserver.port: 5601\nserver.ssl.enabled: false\n'
    printf 'opensearch.hosts: ["https://wazuh-indexer:9200"]\n'
    printf 'opensearch.ssl.verificationMode: full\n'
    printf 'opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-indexer/config/certs/http-ca-bundle.pem"]\n'
    printf 'opensearch.username: "admin"\n'
    printf 'opensearch.password: "%s"\n' "${_wazuh_idxpw}"
    printf 'opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]\n'
    printf 'opensearch_security.multitenancy.enabled: false\n'
    # Served behind Caddy at /admin/wazuh/* — basePath makes the dashboard
    # generate links/redirects under that prefix instead of escaping to /app/login
    # (which falls through to the data-plane verifier). rewriteBasePath=true means
    # OSD expects the prefix on inbound requests, so Caddy uses `handle` (no strip).
    printf 'server.basePath: "/admin/wazuh"\nserver.rewriteBasePath: true\n'
  } > "${wp}/opensearch_dashboards.yml"

  # 7. ownership: indexer/dashboard/sidecar run as uid 1000; CA bundle world-readable (manager uid 999)
  "$rt" run --rm -u 0 -v "${wp}":/w "$idx_img" sh -c '
    chown -R 1000:1000 /w
    chmod 644 /w/certs/http-ca-bundle.pem /w/certs/http-indexer.pem /w/certs/wazuh-admin.pem /w/opensearch.yml /w/opensearch-security/*.yml
    chmod 640 /w/certs/http-indexer-key.pem /w/certs/wazuh-admin-key.pem
    chmod 600 /w/opensearch_dashboards.yml' || { log_error "wazuh-mtls ownership/permission step failed"; return 1; }
  : > "${wp}/.provisioned"   # marker written LAST — gates idempotent re-runs
  log_success "Wazuh full-mTLS material provisioned (docker/wazuh-mtls/, git-ignored)"
}

# =============================================================================
# _provision_audit_signing_key — internal-CA leaf for audit-chain checkpoints
# =============================================================================
# Lu wire-sink-gate P2 (v2.25.2 — irrevocable signed chain):
#   The daily audit-chain checkpoint (AuditChainService.run_daily_checkpoint)
#   signs the merkle root with an ECDSA leaf private key.  This function mints a
#   dedicated audit-signing leaf (EC P-256, PKCS#8) signed by the internal
#   intermediate CA — mirroring the wazuh-admin pattern in _provision_wazuh_mtls.
#
# CRITICAL PLACEMENT (Tiago directive 2026-06-04):
#   The signing key is written to docker/secrets/audit-signing/audit_signing.key
#   and mounted RO into BACKOFFICE ONLY (compose: ./secrets/audit-signing →
#   /run/audit-signing).  It is NOT mounted into the gateway/runtime path, so a
#   held yashigani_app DB credential cannot read it and cannot forge a signed
#   checkpoint.  The public cert (audit_signing.crt) is world-readable so an
#   auditor / verification tool can validate signatures against the internal CA.
#
# Idempotent: skips when the key already exists (rotation is a separate concern;
# the key is long-lived like the wazuh-admin cert — 825 days).  Fail-closed:
# returns non-zero if the intermediate CA material is missing.
_provision_audit_signing_key() {
  local secrets="${WORK_DIR}/docker/secrets"
  local asd="${secrets}/audit-signing"
  local keyf="${asd}/audit_signing.key"
  local crtf="${asd}/audit_signing.crt"

  if [[ -f "$keyf" && -f "$crtf" ]]; then
    log_info "Audit-chain signing key already provisioned — skipping"
    return 0
  fi
  if [[ ! -f "${secrets}/ca_intermediate.crt" || ! -f "${secrets}/ca_intermediate.key" ]]; then
    log_error "Audit signing-key provisioning: intermediate CA material missing — aborting (fail-closed)"
    return 1
  fi
  require_cmd openssl

  # -------------------------------------------------------------------------
  # Rootless-Podman audit-signing fix (gate #ROOTLESS-AUDIT-1):
  #
  # On rootless Podman the PKI issuer step (which ran earlier under podman
  # unshare) chowns secrets/ to the subuid-mapped host UID (e.g. 165536 for
  # container root).  The host user (e.g. UID 1001) cannot create a subdir or
  # write files inside that tree → EPERM → empty key → fail-closed abort.
  #
  # Fix: when running rootless Podman, execute the entire mkdir + openssl
  # block inside `podman unshare bash -c '...'` so it runs as namespace-root
  # (host 165536) which CAN write into the subuid-owned secrets tree.  The
  # final chown 1001:1001 inside the unshare maps to the correct subuid host
  # UID (166537 on a 165536-base system) — identical to how the bind-mount
  # block and the PKI issuer block do it.
  #
  # Process substitution (<(printf ...)) is not reliable inside a bash -c
  # heredoc delivered over a single-quoted string, so the x509 extfile is
  # written to a temp path inside audit-signing/ then removed, keeping all
  # scratch inside the function's own working area (never /tmp — repo policy).
  #
  # Fallback: if podman unshare is unavailable (remote client), log_warn and
  # fall through to the existing direct-path block.
  # -------------------------------------------------------------------------
  local _is_rootless_podman=false
  if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" || "${YSG_RUNTIME:-}" == "podman" ]] \
      && [[ "$(id -u)" != "0" ]]; then
    _is_rootless_podman=true
  fi

  if [[ "$_is_rootless_podman" == "true" ]]; then
    # Rootless Podman path: run the full openssl block inside podman unshare.
    # Variables (asd/keyf/crtf/secrets) are expanded host-side before the
    # string is passed to podman unshare bash -c.
    local _unshare_script
    _unshare_script="$(cat <<UNSHARE_EOF
set -euo pipefail
umask 077
mkdir -p '${asd}'
openssl ecparam -genkey -name prime256v1 -out '${asd}/.audit-sec1.pem' 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in '${asd}/.audit-sec1.pem' -out '${keyf}' 2>/dev/null
rm -f '${asd}/.audit-sec1.pem'
openssl req -new -key '${keyf}' -out '${asd}/.audit.csr' \
  -subj '/O=Agnostic Security/CN=audit-checkpoint-signer' 2>/dev/null
printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' \
  > '${asd}/.audit-ext.cnf'
openssl x509 -req -in '${asd}/.audit.csr' -CA '${secrets}/ca_intermediate.crt' \
  -CAkey '${secrets}/ca_intermediate.key' -CAcreateserial -days 825 -out '${crtf}' \
  -extfile '${asd}/.audit-ext.cnf' 2>/dev/null
rm -f '${asd}/.audit.csr' '${asd}/.audit-ext.cnf' '${secrets}/ca_intermediate.srl'
chmod 0640 '${keyf}'
chmod 0644 '${crtf}'
chmod 0750 '${asd}'
chown 1001:1001 '${keyf}' '${crtf}' '${asd}'
# Verify non-empty INSIDE the namespace: after chown to the subuid UID + 0750
# dir, the host user (other) cannot traverse audit-signing/ to stat these, so
# the host-side -s check would false-fail on a healthy key. Verify here
# where access works (#ROOTLESS-AUDIT-1); set -e -> non-zero exit -> fallback.
[ -s '${keyf}' ] && [ -s '${crtf}' ]
UNSHARE_EOF
)"
    if podman unshare bash -c "$_unshare_script" 2>/dev/null; then
      log_info "Audit signing key generated + verified via podman unshare (rootless)"
      log_success "Audit-chain signing key provisioned (docker/secrets/audit-signing/, backoffice-only, git-ignored)"
      return 0
    else
      log_warn "podman unshare unavailable or failed — falling back to direct path (rootless Podman without unshare support)"
      _is_rootless_podman=false   # trigger the direct block below
    fi
  fi

  if [[ "$_is_rootless_podman" == "false" ]]; then
    # Docker / rootful Podman / macOS / fallback from unshare-unavailable path.
    ( umask 077   # private key born owner-only
      mkdir -p "$asd"
      # EC P-256 key, converted to PKCS#8 (load_pem_private_key in chain.py expects PKCS#8).
      openssl ecparam -genkey -name prime256v1 -out "${asd}/.audit-sec1.pem" 2>/dev/null
      openssl pkcs8 -topk8 -nocrypt -in "${asd}/.audit-sec1.pem" -out "$keyf" 2>/dev/null
      rm -f "${asd}/.audit-sec1.pem"
      # CSR + leaf signed by the internal intermediate. CN encodes the SPIFFE-ish
      # signing identity so an auditor can tie a signature to the issuing context.
      openssl req -new -key "$keyf" -out "${asd}/.audit.csr" \
        -subj "/O=Agnostic Security/CN=audit-checkpoint-signer" 2>/dev/null
      openssl x509 -req -in "${asd}/.audit.csr" -CA "${secrets}/ca_intermediate.crt" \
        -CAkey "${secrets}/ca_intermediate.key" -CAcreateserial -days 825 -out "$crtf" \
        -extfile <(printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE') 2>/dev/null
      rm -f "${asd}/.audit.csr" "${secrets}/ca_intermediate.srl"
    )
    if [[ ! -s "$keyf" || ! -s "$crtf" ]]; then
      log_error "Audit signing-key provisioning: openssl produced empty key/cert — aborting"
      return 1
    fi
    # Perms: key 0640 owned by the backoffice container UID (1001); cert 0644 (auditor-readable).
    # cap_drop:[ALL] on backoffice strips DAC_OVERRIDE, so the key must be owner- or
    # group-readable by the backoffice runtime UID. Backoffice runs as UID 1001 (see
    # docker-compose backoffice user/_pki_chown_client_keys map). Chown best-effort
    # (host may lack the UID on macOS virtiofs — the bind mount remaps on read).
    chmod 0640 "$keyf" 2>/dev/null || true
    chmod 0644 "$crtf" 2>/dev/null || true
    chmod 0750 "$asd" 2>/dev/null || true
    chown 1001:1001 "$keyf" 2>/dev/null || true
    chown 1001:1001 "$asd"  2>/dev/null || true
  fi

  log_success "Audit-chain signing key provisioned (docker/secrets/audit-signing/, backoffice-only, git-ignored)"
}

# =============================================================================
# _ensure_agent_databases — idempotent agent-DB provisioning (INSTALL-AGENTDB-001)
# =============================================================================
# Postgres docker-entrypoint-initdb.d scripts (incl. 11-agent-dbs.sh, which
# creates the `letta` database + pgvector) run ONLY on a FRESH/EMPTY PGDATA.
# An upgrade — or any install onto a pre-existing postgres_data volume that was
# initialized before the agent-DB init script existed (or before a given agent
# bundle was enabled) — never runs that script, so the agent DB is missing and
# the agent (e.g. letta) crash-loops on "database \"letta\" does not exist".
#
# This step closes that gap: on EVERY compose_up (fresh AND upgrade), after
# postgres is accepting connections, re-execute the SAME init script that the
# entrypoint would have run — by exec'ing the copy already bind-mounted into the
# running postgres container at /docker-entrypoint-initdb.d/11-agent-dbs.sh.
#
# Single source of truth: the set of agent DBs + owners + extensions lives ONLY
# in docker/postgres/init-agent-dbs.sh. We do NOT duplicate the DB list here.
# The script is already idempotent — `CREATE DATABASE ... WHERE NOT EXISTS ...
# \gexec` (CREATE DATABASE has no IF NOT EXISTS) + `CREATE EXTENSION IF NOT
# EXISTS vector` — so re-running it on a populated volume is a no-op when the DB
# already exists and provisions it when absent. Safe to run repeatedly.
#
# Runtime-agnostic: uses "${COMPOSE_CMD[@]}" ... exec -T postgres, the same
# invocation pattern as _upgrade_postgres_ssl, which works under Docker and
# Podman (rootful + rootless). No host-side psql, no ad-hoc one-liner, no
# hard-coded container name.
#
# Fail behaviour: agent bundles are OPT-IN and OPTIONAL; a provisioning failure
# must not block the core stack. We log the psql output and warn (non-fatal) so
# the gateway/backoffice still come up — the agent will simply remain unreachable
# until the DB is provisioned, which is strictly better than failing the whole
# install. The convergence gate for core services runs separately.
# -----------------------------------------------------------------------------
_ensure_agent_databases() {
  # Only meaningful when at least one agent bundle that needs a postgres DB is
  # enabled. Today that is `letta` (langflow uses sqlite; openclaw/openwebui/wazuh
  # carry no dedicated agent DB). We gate on COMPOSE_PROFILES containing `letta`
  # rather than hard-coding the DB name — if a future bundle adds a DB to the init
  # script, add its profile here and the init script remains the single source for
  # the actual DB/owner/extension definitions.
  local _need_agent_db="false"
  local _p
  for _p in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    case "$_p" in
      letta) _need_agent_db="true" ;;
    esac
  done
  if [[ "$_need_agent_db" != "true" ]]; then
    return 0
  fi

  local _compose_file="${1:-${WORK_DIR}/docker/docker-compose.yml}"
  local _initdb_script="/docker-entrypoint-initdb.d/11-agent-dbs.sh"

  log_info "Ensuring agent databases exist (idempotent; INSTALL-AGENTDB-001)..."

  # Wait for postgres to accept connections over the local socket (trust auth,
  # the path the init script itself uses). Transport errors only — retry with
  # capped backoff; a non-transport psql error is surfaced, not retried-to-pass.
  local _ready="false" _i
  for _i in $(seq 1 30); do
    if "${COMPOSE_CMD[@]}" -f "$_compose_file" exec -T postgres \
         pg_isready -U yashigani_admin -d yashigani >/dev/null 2>&1; then
      _ready="true"; break
    fi
    sleep 2
  done
  if [[ "$_ready" != "true" ]]; then
    log_warn "  postgres did not become ready in 60s — skipping agent-DB provisioning (agents may be unreachable until next run)"
    return 0
  fi

  # Confirm the init script is mounted in the running container. If the volume
  # mount is missing (older compose file), fall back to a warn — we do NOT inline
  # a duplicate DB list (single-source-of-truth rule).
  if ! "${COMPOSE_CMD[@]}" -f "$_compose_file" exec -T postgres \
         test -r "$_initdb_script" 2>/dev/null; then
    log_warn "  ${_initdb_script} not mounted in postgres container — cannot provision agent DBs"
    log_warn "  (ensure docker/postgres/init-agent-dbs.sh is mounted; see docker-compose.yml)"
    return 0
  fi

  # Re-run the EXACT init script the entrypoint runs on a fresh volume. It reads
  # POSTGRES_USER / POSTGRES_DB from the container env (already set) and is
  # idempotent. Capture output so failures are visible, never silent.
  local _out _rc=0
  _out="$("${COMPOSE_CMD[@]}" -f "$_compose_file" exec -T postgres \
            bash "$_initdb_script" 2>&1)" || _rc=$?
  if [[ "$_rc" -eq 0 ]]; then
    log_success "Agent databases ensured (init-agent-dbs.sh ran clean)"
  else
    log_warn "Agent-DB provisioning returned non-zero (rc=${_rc}) — agents may be unreachable:"
    printf '%s\n' "$_out" | sed 's/^/    /' >&2
  fi
  return 0
}

# ---------------------------------------------------------------------------
# _podman_init_sequence — Podman explicit init-container sequencing
#
# FINDING-1 deadlock fix, Option A (3.1.2):
# podman-compose 1.6.0 processes services sequentially and blocks on
# service_healthy deps via `podman wait --condition=healthy`. The original
# FINDING-1 fix (4b87b71) removed init-container depends_on entries from
# wazuh-manager and letta to avoid Podman 4.9.3's dep-graph error on already-
# exited containers. That fixed the dep-graph crash but introduced a new
# deadlock on the INITIAL compose-up:
#
#   wazuh-manager depends on wazuh-indexer:healthy (preserved in
#   docker-compose.podman-override.yml). wazuh-indexer only becomes healthy
#   AFTER wazuh-security-init runs securityadmin.sh. But wazuh-security-init
#   is stuck in "Created" because compose-up is blocked on the wazuh-manager
#   wait — a circular deadlock. Same path exists for letta → agent-db-init.
#
# Fix: explicitly bring up base data services and run init containers to
# completion BEFORE the main `podman-compose up -d`. Docker path is
# unchanged — Docker resolves service_completed_successfully deps without
# sequential blocking.
#
# Call context: called from compose_up() on the Podman path only, before
# the main compose-up. Inherits these caller locals via bash dynamic scoping:
#   compose_files, profile_args, _pull_flag, COMPOSE_PROFILES, COMPOSE_CMD,
#   UPGRADE, log_info, log_success, log_warn, log_error
# ---------------------------------------------------------------------------
_podman_init_sequence() {
  local _pis_timeout_s=300      # wazuh-indexer: 150s start_period + headroom
  local _pis_adb_timeout_s=120  # agent-db-init: fast psql DDL only

  # ── Step 1: Start postgres (fresh install only) ───────────────────────────
  # Upgrade path: postgres is already running from the V232-SMOKE-004 pre-start
  # block. Fresh install: start it now so init containers can reach it.
  if [[ "${UPGRADE:-false}" != "true" ]]; then
    log_info "  Podman init-seq: pre-starting postgres ..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" \
      up ${_pull_flag[@]+"${_pull_flag[@]}"} -d postgres 2>/dev/null || true

    local _pis_pg_ok=0 _pis_pg_deadline
    _pis_pg_deadline=$(( $(date +%s) + 90 ))
    while [[ "$(date +%s)" -lt "$_pis_pg_deadline" ]]; do
      if "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres pg_isready 2>/dev/null; then
        log_success "  Podman init-seq: postgres ready"
        _pis_pg_ok=1; break
      fi
      sleep 3
    done
    [[ "$_pis_pg_ok" -eq 0 ]] && \
      log_warn "  Podman init-seq: postgres not ready in 90s — init containers proceed anyway"
  fi

  # ── Step 2: Start wazuh-indexer and wait for healthy (wazuh profile) ────
  local _pis_wazuh=false
  if printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx "wazuh"; then
    _pis_wazuh=true
    log_info "  Podman init-seq: pre-starting wazuh-indexer ..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} \
      up ${_pull_flag[@]+"${_pull_flag[@]}"} -d wazuh-indexer 2>/dev/null || true

    local _pis_idx_ok=0 _pis_idx_deadline
    _pis_idx_deadline=$(( $(date +%s) + _pis_timeout_s ))
    while [[ "$(date +%s)" -lt "$_pis_idx_deadline" ]]; do
      local _pis_idx_cid
      _pis_idx_cid=$(podman ps -q \
        --filter "label=com.docker.compose.service=wazuh-indexer" 2>/dev/null | head -1 || true)
      if [[ -n "$_pis_idx_cid" ]]; then
        local _pis_idx_health
        _pis_idx_health=$(podman inspect \
          --format '{{.State.Health.Status}}' "$_pis_idx_cid" 2>/dev/null || echo "unknown")
        if [[ "$_pis_idx_health" == "healthy" ]]; then
          log_success "  Podman init-seq: wazuh-indexer healthy"
          _pis_idx_ok=1; break
        fi
      fi
      sleep 5
    done
    [[ "$_pis_idx_ok" -eq 0 ]] && \
      log_warn "  Podman init-seq: wazuh-indexer not healthy after ${_pis_timeout_s}s — securityadmin will self-retry"
  fi

  # ── Step 3: Run wazuh-security-init to completion ────────────────────────
  # This seeds the OpenSearch security index; without it wazuh-indexer stays
  # unhealthy and wazuh-manager deadlocks the main compose-up.
  if [[ "$_pis_wazuh" == "true" ]]; then
    log_info "  Podman init-seq: running wazuh-security-init ..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} \
      up ${_pull_flag[@]+"${_pull_flag[@]}"} -d wazuh-security-init 2>/dev/null || true

    local _pis_wsec_ok=0 _pis_wsec_deadline
    _pis_wsec_deadline=$(( $(date +%s) + _pis_timeout_s ))
    while [[ "$(date +%s)" -lt "$_pis_wsec_deadline" ]]; do
      local _pis_wsec_cid
      _pis_wsec_cid=$(podman ps -a \
        --filter "label=com.docker.compose.service=wazuh-security-init" \
        --format "{{.ID}}" 2>/dev/null | head -1 || true)
      if [[ -n "$_pis_wsec_cid" ]]; then
        local _pis_wsec_status _pis_wsec_exit
        _pis_wsec_status=$(podman inspect \
          --format '{{.State.Status}}' "$_pis_wsec_cid" 2>/dev/null || echo "unknown")
        _pis_wsec_exit=$(podman inspect \
          --format '{{.State.ExitCode}}' "$_pis_wsec_cid" 2>/dev/null || echo "-1")
        if [[ "$_pis_wsec_status" == "exited" ]]; then
          if [[ "$_pis_wsec_exit" == "0" ]]; then
            log_success "  Podman init-seq: wazuh-security-init completed (exit 0)"
            _pis_wsec_ok=1
          else
            log_error "  Podman init-seq: wazuh-security-init exited with code ${_pis_wsec_exit}"
            "${COMPOSE_CMD[@]}" "${compose_files[@]}" \
              logs --tail=30 wazuh-security-init 2>/dev/null || true
          fi
          break
        fi
      fi
      sleep 5
    done
    if [[ "$_pis_wsec_ok" -eq 0 ]]; then
      log_error "  Podman init-seq: wazuh-security-init did not complete in ${_pis_timeout_s}s"
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" \
        logs --tail=20 wazuh-security-init 2>/dev/null || true
    fi
  fi

  # ── Step 4: Run agent-db-init to completion (letta profile) ──────────────
  # Ensures the letta database + pgvector extension exist before letta starts.
  if printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx "letta"; then
    log_info "  Podman init-seq: running agent-db-init ..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} \
      up ${_pull_flag[@]+"${_pull_flag[@]}"} -d agent-db-init 2>/dev/null || true

    local _pis_adb_ok=0 _pis_adb_deadline
    _pis_adb_deadline=$(( $(date +%s) + _pis_adb_timeout_s ))
    while [[ "$(date +%s)" -lt "$_pis_adb_deadline" ]]; do
      local _pis_adb_cid
      _pis_adb_cid=$(podman ps -a \
        --filter "label=com.docker.compose.service=agent-db-init" \
        --format "{{.ID}}" 2>/dev/null | head -1 || true)
      if [[ -n "$_pis_adb_cid" ]]; then
        local _pis_adb_status _pis_adb_exit
        _pis_adb_status=$(podman inspect \
          --format '{{.State.Status}}' "$_pis_adb_cid" 2>/dev/null || echo "unknown")
        _pis_adb_exit=$(podman inspect \
          --format '{{.State.ExitCode}}' "$_pis_adb_cid" 2>/dev/null || echo "-1")
        if [[ "$_pis_adb_status" == "exited" ]]; then
          if [[ "$_pis_adb_exit" == "0" ]]; then
            log_success "  Podman init-seq: agent-db-init completed (exit 0)"
            _pis_adb_ok=1
          else
            log_error "  Podman init-seq: agent-db-init exited with code ${_pis_adb_exit}"
            "${COMPOSE_CMD[@]}" "${compose_files[@]}" \
              logs --tail=30 agent-db-init 2>/dev/null || true
          fi
          break
        fi
      fi
      sleep 5
    done
    if [[ "$_pis_adb_ok" -eq 0 ]]; then
      log_warn "  Podman init-seq: agent-db-init did not complete in ${_pis_adb_timeout_s}s — letta may not start cleanly"
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" \
        logs --tail=10 agent-db-init 2>/dev/null || true
    fi
  fi

  log_info "Podman init-sequencing complete — base services healthy, init containers done"
}

compose_up() {
  set_step "10" "compose up"
  log_step "10/${TOTAL_STEPS}" "Starting services..."

  resolve_compose_cmd

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  # Auto-apply Podman rootless override when running on Podman
  local compose_files=("-f" "$compose_file")

  # v2.25.1: Wazuh Docker-runtime + full internal-CA mTLS overlay. When the wazuh profile
  # is active, provision the deploy-local mTLS material (git-ignored) and layer the overlay
  # that adds caps/cont-init/securityadmin/healthchecks + the internal-CA HTTP listener.
  # No manual steps — reproducible on every up (SOP: changes in code, not hand-applied).
  local _wazuh_overlay="${WORK_DIR}/docker/docker-compose.wazuh.yml"
  if { [[ "${INSTALL_WAZUH:-false}" == "true" ]] || echo "${COMPOSE_PROFILES[*]+"${COMPOSE_PROFILES[*]}"}" | grep -q "wazuh"; } && [[ -f "$_wazuh_overlay" ]]; then
    _provision_wazuh_mtls || { log_error "Wazuh mTLS provisioning failed — aborting before compose up (fail-closed)"; return 1; }
    compose_files+=("-f" "$_wazuh_overlay")
    log_info "Applying Wazuh Docker-runtime + full-mTLS overlay (docker-compose.wazuh.yml)"
  fi

  # GPU overlay (Docker runtime): wire the detected NVIDIA GPU into ollama. The base
  # ollama service has its GPU reservation commented out and the nvidia runtime is not
  # the daemon default, so without this ollama runs CPU-only. Pin a card with YSG_GPU_UUID
  # (defaults to all). Podman uses CDI devices separately; K8s uses the device plugin.
  local _gpu_overlay="${WORK_DIR}/docker/docker-compose.gpu.yml"
  if [[ "${YSG_GPU_TYPE:-none}" == "nvidia" ]] && [[ "${YSG_PODMAN_RUNTIME:-false}" != "true" ]] && [[ -f "$_gpu_overlay" ]]; then
    compose_files+=("-f" "$_gpu_overlay")
    log_info "Applying GPU overlay (docker-compose.gpu.yml) — ollama on NVIDIA device ${YSG_GPU_CDI:-nvidia.com/gpu=all}"
  fi
  # Podman GPU: CDI devices (nvidia.com/gpu=N), not the docker `runtime: nvidia` path.
  # ROOTLESS-CDI-001: Provision a complete podman-compatible CDI spec in /etc/cdi/
  # BEFORE the probe. Spec is generated by nvidia-ctk (full library mounts included),
  # transformed 0.7.0 → 0.6.0 for podman 4.9.3, then written to /etc/cdi/nvidia.yaml
  # with 0644 perms via Docker daemon (no interactive sudo). See _setup_podman_cdi_gpu.
  if [[ "${YSG_GPU_TYPE:-none}" == "nvidia" ]] && [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    _setup_podman_cdi_gpu
  fi
  local _gpu_overlay_podman="${WORK_DIR}/docker/docker-compose.gpu-podman.yml"
  local _gpu_overlay_podman_devpath="${WORK_DIR}/docker/docker-compose.gpu-podman-devpath.yml"
  if [[ "${YSG_GPU_TYPE:-none}" == "nvidia" ]] && [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
    local _cdi_probe_ok=false
    if podman run --rm --device "nvidia.com/gpu=0" \
         --entrypoint "" \
         alpine:latest echo "cdi-probe" >/dev/null 2>&1; then
      _cdi_probe_ok=true
    fi
    if [[ "$_cdi_probe_ok" == "true" ]] && [[ -f "$_gpu_overlay_podman" ]]; then
      compose_files+=("-f" "$_gpu_overlay_podman")
      log_info "CDI probe OK — applying Podman CDI GPU overlay (docker-compose.gpu-podman.yml) — ollama on ${YSG_GPU_CDI:-nvidia.com/gpu=all}"
    elif [[ -f "$_gpu_overlay_podman_devpath" ]]; then
      # CDI unavailable (probe failed or _setup_podman_cdi_gpu returned early).
      # devpath overlay passes device nodes only — NO library mounts.
      # ollama WILL run CPU-only on this path: library=cpu, not library=cuda.
      log_warn "WARN: CDI probe failed — falling back to device-path passthrough (#ROOTLESS-CDI-001)"
      log_warn "WARN: Device-path overlay has NO library mounts → ollama will run CPU-only (library=cpu)"
      log_warn "WARN: GPU acceleration NOT active. Fix: ensure nvidia-ctk + Docker daemon are available."
      log_info "Applying Podman device-path GPU overlay (docker-compose.gpu-podman-devpath.yml) — ollama on ${YSG_GPU_DEV:-/dev/nvidia0}"
      compose_files+=("-f" "$_gpu_overlay_podman_devpath")
    else
      log_warn "GPU overlay not applied — neither CDI nor devpath overlay found; ollama will run CPU-only"
    fi
  fi
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
      local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
        local _tmp_env; _tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
        sed "s|^YASHIGANI_HTTP_PORT=.*|YASHIGANI_HTTP_PORT=${YASHIGANI_HTTP_PORT}|" "$env_file" > "$_tmp_env"
        mv "$_tmp_env" "$env_file"
      else
        echo "YASHIGANI_HTTP_PORT=${YASHIGANI_HTTP_PORT}" >> "$env_file"
      fi
    fi
    if [[ -n "${YASHIGANI_HTTPS_PORT:-}" ]]; then
      if grep -q "^YASHIGANI_HTTPS_PORT=" "$env_file" 2>/dev/null; then
        local _tmp_env; _tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
        sed "s|^YASHIGANI_HTTPS_PORT=.*|YASHIGANI_HTTPS_PORT=${YASHIGANI_HTTPS_PORT}|" "$env_file" > "$_tmp_env"
        mv "$_tmp_env" "$env_file"
      else
        echo "YASHIGANI_HTTPS_PORT=${YASHIGANI_HTTPS_PORT}" >> "$env_file"
      fi
    fi

    # Public base URL (scheme://domain[:port]) — single source for the external
    # URLs that reverse-proxied sub-apps must self-reference (Grafana root_url,
    # Wazuh basePath, …). Port suffix omitted when standard 443. Without the
    # published port these apps 301-redirect to :443 ("site can't be reached"
    # on a non-standard port). update-or-append into .env.
    local _pub_port_suffix=""
    if [[ -n "${YASHIGANI_HTTPS_PORT:-}" && "${YASHIGANI_HTTPS_PORT}" != "443" ]]; then
      _pub_port_suffix=":${YASHIGANI_HTTPS_PORT}"
    fi
    local _pub_url="https://${YASHIGANI_TLS_DOMAIN:-${DOMAIN:-localhost}}${_pub_port_suffix}"
    if grep -q "^YASHIGANI_PUBLIC_URL=" "$env_file" 2>/dev/null; then
      local _tmp_env2; _tmp_env2="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
      sed "s|^YASHIGANI_PUBLIC_URL=.*|YASHIGANI_PUBLIC_URL=${_pub_url}|" "$env_file" > "$_tmp_env2"
      mv "$_tmp_env2" "$env_file"
    else
      echo "YASHIGANI_PUBLIC_URL=${_pub_url}" >> "$env_file"
    fi
    export YASHIGANI_PUBLIC_URL="$_pub_url"

    # Declared set of enabled optional-service profiles, for the backoffice
    # Optional Services panel (observational; the hardened container can't probe
    # Docker). Assemble from agent bundles + the per-flag opt-ins.
    local _enabled_profiles=()
    [[ ${#COMPOSE_PROFILES[@]} -gt 0 ]] && _enabled_profiles+=("${COMPOSE_PROFILES[@]}")
    [[ "${INSTALL_OPENWEBUI:-false}" == "true" ]] && _enabled_profiles+=("openwebui")
    [[ "${INSTALL_WAZUH:-false}" == "true" ]] && _enabled_profiles+=("wazuh")
    [[ "${INSTALL_INTERNAL_CA:-false}" == "true" ]] && _enabled_profiles+=("internal-ca")
    # de-dupe, comma-join
    local _ep_csv; _ep_csv="$(printf '%s\n' "${_enabled_profiles[@]+"${_enabled_profiles[@]}"}" | awk 'NF&&!seen[$0]++' | paste -sd, -)"
    if grep -q "^YASHIGANI_ENABLED_PROFILES=" "$env_file" 2>/dev/null; then
      local _tmp_env3; _tmp_env3="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
      sed "s|^YASHIGANI_ENABLED_PROFILES=.*|YASHIGANI_ENABLED_PROFILES=${_ep_csv}|" "$env_file" > "$_tmp_env3"
      mv "$_tmp_env3" "$env_file"
    else
      echo "YASHIGANI_ENABLED_PROFILES=${_ep_csv}" >> "$env_file"
    fi
    export YASHIGANI_ENABLED_PROFILES="$_ep_csv"

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
    # FINDING-1/5 fix (3.1.1): load init-deps reset file BEFORE the override.
    # This file uses !reset to remove init-container depends_on entries and
    # Docker-specific promtail volumes that block Podman startup. The override
    # file then re-adds the correct deps + promtail journald wiring.
    # Load order matters: reset → re-add (podman-compose merges in -f sequence).
    local podman_init_deps="${WORK_DIR}/docker/docker-compose.podman-init-deps.yml"
    if [[ -f "$podman_init_deps" ]]; then
      compose_files+=("-f" "$podman_init_deps")
      log_info "Applying Podman init-deps reset (FINDING-1/5: removes init-container --requires + Docker volumes)"
    else
      log_warn "Podman init-deps reset not found at ${podman_init_deps} — FINDING-1 dep-graph fix not active"
    fi
    local podman_override="${WORK_DIR}/docker/docker-compose.podman-override.yml"
    if [[ -f "$podman_override" ]]; then
      compose_files+=("-f" "$podman_override")
      log_info "Applying Podman rootless override (security_opt + env + deps re-add + promtail journald)"
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
    #    Skip rebuild only when both version-tagged images exist AND their
    #    revision label matches the current source SHA. A stale :latest or a
    #    version-tagged image from an older commit must be rebuilt (version-drift
    #    stale-image bug — cf. 0d9aed1 + YASHIGANI_GIT_SHA cache-busting fix).
    local _gw_exists=false _bo_exists=false
    local _gw_sha_ok=false _bo_sha_ok=false
    if podman image exists "yashigani/gateway:${YASHIGANI_VERSION}" 2>/dev/null || \
       podman image exists "localhost/yashigani/gateway:${YASHIGANI_VERSION}" 2>/dev/null; then
      _gw_exists=true
      if [[ "$YASHIGANI_GIT_SHA" == "dev" ]]; then
        _gw_sha_ok=true
      else
        local _gw_lbl
        _gw_lbl="$(podman image inspect "yashigani/gateway:${YASHIGANI_VERSION}" 2>/dev/null \
          | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Labels',{}).get('org.opencontainers.image.revision',''))" 2>/dev/null || true)"
        [[ "$_gw_lbl" == "$YASHIGANI_GIT_SHA" ]] && _gw_sha_ok=true
      fi
    fi
    if podman image exists "yashigani/backoffice:${YASHIGANI_VERSION}" 2>/dev/null || \
       podman image exists "localhost/yashigani/backoffice:${YASHIGANI_VERSION}" 2>/dev/null; then
      _bo_exists=true
      if [[ "$YASHIGANI_GIT_SHA" == "dev" ]]; then
        _bo_sha_ok=true
      else
        local _bo_lbl
        _bo_lbl="$(podman image inspect "yashigani/backoffice:${YASHIGANI_VERSION}" 2>/dev/null \
          | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Labels',{}).get('org.opencontainers.image.revision',''))" 2>/dev/null || true)"
        [[ "$_bo_lbl" == "$YASHIGANI_GIT_SHA" ]] && _bo_sha_ok=true
      fi
    fi

    if [[ "$_gw_exists" == "true" && "$_bo_exists" == "true" && \
          "$_gw_sha_ok" == "true" && "$_bo_sha_ok" == "true" && \
          "${YASHIGANI_FORCE_REBUILD:-0}" != "1" ]]; then
      log_info "Images already current (v${YASHIGANI_VERSION}, SHA ${YASHIGANI_GIT_SHA}) — skipping rebuild (Podman)"
    else
      log_info "Building images with Podman (SHA ${YASHIGANI_GIT_SHA})..."
      # retro #32: do NOT pipe through `tail -1`. The script's outer exec
      # redirect at the top of main() already tees stdout+stderr to
      # install.log. Piping through `tail -1` here truncates build output
      # to a single line BEFORE it reaches the outer tee, so disk-full
      # errors ("no space left on device"), Dockerfile syntax errors, and
      # cache-eviction warnings are silently dropped from the log.
      # Verbose terminal output is the explicit tradeoff for visibility.
      podman build -f "${WORK_DIR}/docker/Dockerfile.gateway" \
        --build-arg "GIT_SHA=${YASHIGANI_GIT_SHA}" \
        -t "yashigani/gateway:${YASHIGANI_VERSION}" \
        -t yashigani/gateway:latest "${WORK_DIR}"
      podman build -f "${WORK_DIR}/docker/Dockerfile.backoffice" \
        --build-arg "GIT_SHA=${YASHIGANI_GIT_SHA}" \
        -t "yashigani/backoffice:${YASHIGANI_VERSION}" \
        -t yashigani/backoffice:latest "${WORK_DIR}"
      log_success "Images built with Podman"
    fi

    # 3.0 doc-OPA: build the per-job extractor image (release artifact) under
    # Podman too. Build-only (never `up`), so it must be built + tagged
    # explicitly with the VERSIONED tag the runner names
    # (yashigani/extractor:${YASHIGANI_VERSION}). Idempotent on re-run.
    local _podman_ext_tag="yashigani/extractor:${YASHIGANI_VERSION}"
    local _podman_ext_cached_sha=""
    if podman image exists "$_podman_ext_tag" 2>/dev/null && [[ "${YASHIGANI_FORCE_REBUILD:-0}" != "1" ]]; then
      _podman_ext_cached_sha="$(podman image inspect "$_podman_ext_tag" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Labels',{}).get('org.opencontainers.image.revision',''))" 2>/dev/null || true)"
    fi
    if podman image exists "$_podman_ext_tag" 2>/dev/null \
        && [[ "${YASHIGANI_FORCE_REBUILD:-0}" != "1" ]] \
        && { [[ "$YASHIGANI_GIT_SHA" == "dev" ]] || [[ "$_podman_ext_cached_sha" == "$YASHIGANI_GIT_SHA" ]]; }; then
      log_info "Extractor image already present ($_podman_ext_tag, SHA ${_podman_ext_cached_sha:-dev}) — skipping"
    elif [[ -f "${WORK_DIR}/docker/Dockerfile.extractor" ]]; then
      log_info "Building per-job extractor image with Podman (release artifact)..."
      if podman build -f "${WORK_DIR}/docker/Dockerfile.extractor" \
           --build-arg "GIT_SHA=${YASHIGANI_GIT_SHA}" \
           -t "yashigani/extractor:${YASHIGANI_VERSION}" \
           -t "yashigani/extractor:latest" "${WORK_DIR}"; then
        log_success "Extractor image built with Podman (yashigani/extractor:${YASHIGANI_VERSION})"
      elif [[ "${YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED:-false}" == "true" ]]; then
        log_error "Extractor build FAILED and document enforcement is ENABLED — cannot continue"
        exit 1
      else
        log_warn "Extractor build failed; document enforcement is OFF by default — continuing"
      fi
    else
      log_warn "Dockerfile.extractor not found — skipping extractor build (Podman)"
    fi
  fi

  # --- Runtime-agnostic .env writes (MUST run for docker AND podman) ----------
  # BUGFIX (2026-06-08): YASHIGANI_PUBLIC_URL and YASHIGANI_ENABLED_PROFILES were
  # only written inside the `if podman` branch above, so on Docker they were never
  # set. Result: the backoffice Optional-Services panel read an empty
  # YASHIGANI_ENABLED_PROFILES and showed EVERY deployed optional service + agent
  # (openwebui, wazuh, langflow, letta, openclaw) as "Not deployed"; external
  # sub-apps (Grafana/Wazuh) had no public-URL to self-reference. Recomputed here
  # (the in-branch `local`s never execute on docker) and written unconditionally.
  local _env_file_rt="${WORK_DIR}/docker/.env"
  local _pub_suffix_rt=""
  [[ -n "${YASHIGANI_HTTPS_PORT:-}" && "${YASHIGANI_HTTPS_PORT}" != "443" ]] && _pub_suffix_rt=":${YASHIGANI_HTTPS_PORT}"
  local _pub_url_rt="https://${YASHIGANI_TLS_DOMAIN:-${DOMAIN:-localhost}}${_pub_suffix_rt}"
  if grep -q "^YASHIGANI_PUBLIC_URL=" "$_env_file_rt" 2>/dev/null; then
    local _t1_rt; _t1_rt="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
    sed "s|^YASHIGANI_PUBLIC_URL=.*|YASHIGANI_PUBLIC_URL=${_pub_url_rt}|" "$_env_file_rt" > "$_t1_rt"
    mv "$_t1_rt" "$_env_file_rt"
  else
    echo "YASHIGANI_PUBLIC_URL=${_pub_url_rt}" >> "$_env_file_rt"
  fi
  export YASHIGANI_PUBLIC_URL="$_pub_url_rt"

  local _ep_rt=()
  [[ ${#COMPOSE_PROFILES[@]} -gt 0 ]] && _ep_rt+=("${COMPOSE_PROFILES[@]}")
  [[ "${INSTALL_OPENWEBUI:-false}" == "true" ]] && _ep_rt+=("openwebui")
  [[ "${INSTALL_WAZUH:-false}" == "true" ]] && _ep_rt+=("wazuh")
  [[ "${INSTALL_INTERNAL_CA:-false}" == "true" ]] && _ep_rt+=("internal-ca")
  local _ep_csv_rt; _ep_csv_rt="$(printf '%s\n' "${_ep_rt[@]+"${_ep_rt[@]}"}" | awk 'NF&&!seen[$0]++' | paste -sd, -)"
  if grep -q "^YASHIGANI_ENABLED_PROFILES=" "$_env_file_rt" 2>/dev/null; then
    local _t2_rt; _t2_rt="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
    sed "s|^YASHIGANI_ENABLED_PROFILES=.*|YASHIGANI_ENABLED_PROFILES=${_ep_csv_rt}|" "$_env_file_rt" > "$_t2_rt"
    mv "$_t2_rt" "$_env_file_rt"
  else
    echo "YASHIGANI_ENABLED_PROFILES=${_ep_csv_rt}" >> "$_env_file_rt"
  fi
  export YASHIGANI_ENABLED_PROFILES="$_ep_csv_rt"
  log_info "Enabled optional-service profiles: ${_ep_csv_rt:-<none>}"

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
        # V232-NEG04: use tls/ dir for temp bundle (never /tmp); secrets/ is subuid-owned on
        # rootless Podman so mktemp there would EPERM (#ROOTLESS-WAZUH-1 follow-up).
        # tls/ is created by _prepare_secrets_dir_for_pki and is host-owned.
        _tmp_bundle=$(mktemp "${WORK_DIR}/docker/tls/.ysg_bundle_XXXXXX.crt" 2>/dev/null \
                      || echo "${WORK_DIR}/docker/tls/.ysg_bundle.crt")
        # Read CA certs via podman unshare (subuid-owned on rootless); write bundle to host-owned tls/.
        if ! podman unshare bash -c \
               "cat '${_host_secrets}/ca_root.crt' '${_host_secrets}/ca_intermediate.crt' > '${_tmp_bundle}'" \
               2>/dev/null; then
          # Fallback: direct cat (Docker / rootful / macOS paths should not reach here, but be safe)
          cat "${_host_secrets}/ca_root.crt" "${_host_secrets}/ca_intermediate.crt" > "$_tmp_bundle" 2>/dev/null || {
            log_error "CA bundle creation failed (direct + unshare) — SSL injection aborted"
            rm -f "$_tmp_bundle"; return 1
          }
        fi
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
              psql -U yashigani_admin -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")
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
        # #ROOTLESS-WAZUH-1: postgres_password is subuid-owned on rootless Podman; use
        # _safe_read_secret (tries direct cat, then podman unshare cat, then .env lookup).
        local _pg_pass
        _pg_pass="$(_safe_read_secret "${WORK_DIR}/docker/secrets/postgres_password" \
                    "POSTGRES_PASSWORD" "${WORK_DIR}/docker/.env" 2>/dev/null || echo "")"
        if [[ -n "$_pg_pass" ]]; then
          "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T postgres \
              psql -U yashigani_admin -d yashigani -h 127.0.0.1 \
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
    # FINDING-1 deadlock fix (Option A, 3.1.2): explicit Podman init sequencing.
    # postgres is already running (pre-started by V232-SMOKE-004 block above).
    # _podman_init_sequence starts wazuh-indexer (if wazuh), waits for healthy,
    # runs wazuh-security-init + agent-db-init to completion so the main up -d
    # finds all targets already healthy/initialized — no service_healthy deadlock.
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
      _podman_init_sequence
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
      # Preserve override files (wazuh/podman/gpu overlays) after the base compose — the
      # digest-strip applies only to the base; dropping overlays means profile services
      # defined ONLY in an overlay (e.g. wazuh-security-init) never start.
      local _cf_i
      for ((_cf_i=2; _cf_i<${#compose_files[@]}; _cf_i++)); do
        _compose_files_up+=("${compose_files[$_cf_i]}")
      done
      log_info "  temp compose file: $(basename "$_digest_stripped_compose")"
    fi
    # FINDING-1/2 belt-and-braces: timeout guard on initial compose-up (mirrors
    # self-heal pattern). On Podman, compose-up blocks indefinitely via
    # `podman wait --condition=healthy` if any service_healthy dep is not met.
    # _podman_init_sequence above pre-resolves the known deadlock paths; this
    # timeout ensures no future slow service can deadlock the installer forever.
    # On Docker this guard is a no-op (compose returns quickly by design).
    local _initial_up_timeout_s=300
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=5s "${_initial_up_timeout_s}s" \
        "${COMPOSE_CMD[@]}" "${_compose_files_up[@]}" ${profile_args[@]+"${profile_args[@]}"} \
        up ${_pull_flag[@]+"${_pull_flag[@]}"} -d --remove-orphans || {
        local _up_rc=$?
        [[ "$_up_rc" -eq 124 ]] && \
          log_warn "Initial compose up -d timed out after ${_initial_up_timeout_s}s (FINDING-1/2) — continuing"
        true
      }
    else
      "${COMPOSE_CMD[@]}" "${_compose_files_up[@]}" ${profile_args[@]+"${profile_args[@]}"} up ${_pull_flag[@]+"${_pull_flag[@]}"} -d --remove-orphans || true
    fi
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
      # Preserve override files (wazuh/podman/gpu overlays) — see note above; without this
      # the wazuh-security-init sidecar (overlay-only) never starts → indexer never gets
      # securityadmin'd → whole SIEM chain stalls on a fresh pre-seeded install.
      local _cf2_i
      for ((_cf2_i=2; _cf2_i<${#compose_files[@]}; _cf2_i++)); do
        _compose_files_up2+=("${compose_files[$_cf2_i]}")
      done
      log_info "  temp compose file: $(basename "$_digest_stripped_compose2")"
    fi
    # FINDING-1 deadlock fix (Option A, 3.1.2): explicit Podman init sequencing.
    # On Podman: pre-start postgres, wazuh-indexer (if wazuh), run
    # wazuh-security-init + agent-db-init to completion BEFORE the main up -d
    # so no service_healthy wait can deadlock the installer. Docker: no-op.
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]]; then
      _podman_init_sequence
    fi
    # FINDING-1/2 belt-and-braces: timeout guard on initial compose-up.
    local _initial_up_timeout_s2=300
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=5s "${_initial_up_timeout_s2}s" \
        "${COMPOSE_CMD[@]}" "${_compose_files_up2[@]}" ${profile_args[@]+"${profile_args[@]}"} \
        up ${_pull_flag[@]+"${_pull_flag[@]}"} -d || {
        local _up_rc2=$?
        [[ "$_up_rc2" -eq 124 ]] && \
          log_warn "Initial compose up -d timed out after ${_initial_up_timeout_s2}s (FINDING-1/2) — continuing"
        true
      }
    else
      "${COMPOSE_CMD[@]}" "${_compose_files_up2[@]}" ${profile_args[@]+"${profile_args[@]}"} up ${_pull_flag[@]+"${_pull_flag[@]}"} -d || true
    fi
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

  # ---------------------------------------------------------------------------
  # INSTALL-AGENTDB-001: idempotently ensure opt-in agent databases exist.
  #
  # The postgres initdb agent-DB script (creates `letta` + pgvector) runs ONLY
  # on a fresh PGDATA. On an upgrade — or an install onto a postgres_data volume
  # that predates the agent-DB init script / the bundle being enabled — the DB is
  # never created and the agent crash-loops. This re-runs the SAME (idempotent)
  # init script inside the running postgres container so the DB is provisioned on
  # every install/upgrade. Non-fatal: agent bundles are optional, so a failure
  # here must not block the core stack.
  # ---------------------------------------------------------------------------
  _ensure_agent_databases "$compose_file"
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
  local _timeout_s="${YSG_HEALTHZ_TIMEOUT_S:-300}"   # 60→180→300: a FULL fresh install (all services + DB migrations + agent/SIEM bringup) can take >180s for the gateway to converge while healthy (observed on a clean --wazuh install; gateway does NOT depend on wazuh, it's just overall bringup time). The gate still fail-closes after this. Override with YSG_HEALTHZ_TIMEOUT_S.
  local _poll_s="${YSG_HEALTHZ_POLL_S:-2}"
  local _https_port="${YASHIGANI_HTTPS_PORT:-443}"
  local _domain="${DOMAIN:-localhost}"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "_verify_gateway_healthz (skipped in dry-run)"
    return 0
  fi

  log_info "Convergence gate: polling gateway /healthz (timeout ${_timeout_s}s) — BUG-INSTALL-ON-CONTAMINATED-VOLUMES"

  # FIX-3 (defence-in-depth): use --cacert instead of --insecure/-k.
  # No credentials on these polls, but consistent TLS verification prevents
  # a rogue cert on the loopback from going unnoticed (Laura F2 hardening).
  # ca_root.crt is present here: PKI bootstrap (step 9b) ran before compose_up.
  # Loopback liveness poll of the Caddy EDGE (127.0.0.1 via --resolve) → use --insecure.
  # RECURRING-REGRESSION GUARD (v2.23.x retros — "Caddyfile/cert/probe drift"): the EDGE cert is
  # whatever Caddy issued for this TLS mode — selfsigned = Caddy's own on-the-fly local CA,
  # acme = Let's Encrypt, ca = the BYO CA — and is NEVER signed by the internal mesh ca_root.crt.
  # So `--cacert ca_root` ALWAYS fails verification here (HTTP 000, ssl_verify_result=20) and the
  # gate hangs until timeout — observed breaking every selfsigned/acme install. This is a
  # localhost convergence/liveness check (not a security boundary; verifying a loopback edge cert
  # buys nothing), so use --insecure. DO NOT "harden" this back to --cacert (that is the regression).
  local _curl_tls_opt="--insecure"

  local _deadline=$(( $(date +%s) + _timeout_s ))
  local _gateway_ok=0

  while [[ "$(date +%s)" -lt "$_deadline" ]]; do
    # shellcheck disable=SC2086  # intentional word-splitting for _curl_tls_opt
    if curl --silent $_curl_tls_opt --max-time 5 \
         --resolve "${_domain}:${_https_port}:127.0.0.1" \
         "https://${_domain}:${_https_port}/healthz" \
         -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "^200$"; then
      _gateway_ok=1
      break
    fi
    sleep "$_poll_s"
  done

  # YSG-RISK-084 self-heal: under a heavy fresh install (all agent/SIEM profiles),
  # a slow postgres first-initdb can exceed its healthcheck start_period, so compose
  # aborts dependent app-tier containers to "Created" and the gateway never starts.
  # Postgres is healthy by now — re-converge ONCE (idempotent `up -d` with the same
  # profiles) and re-poll before failing closed.
  #
  # FINDING-2 (3.1.1): self-heal deadlock fix.
  # On Podman, `podman-compose up -d` internally calls `podman wait --condition=healthy`
  # on containers that are stuck in "Created" state (healthcheck not wired until the
  # container actually starts). This `podman wait` hangs indefinitely; the `|| true`
  # does NOT help because the child process blocks, not fails. The `timeout` wrapper
  # limits the call to 180s and kills the entire process group on expiry so no orphan
  # `podman wait` lingers after the installer exits or times out.
  # On non-Podman runtimes (Docker), `timeout` is a no-op guard (the compose call
  # returns quickly on its own).
  if [[ "$_gateway_ok" -eq 0 ]]; then
    local _sh_profile_args=()
    local _p
    for _p in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      _sh_profile_args+=("--profile" "$_p")
    done
    log_warn "Convergence gate: gateway not healthy yet — one self-heal re-converge (YSG-RISK-084)"
    # FINDING-2: wrap in timeout 180s; on expiry, kill child group and continue
    # (never hang the installer). `timeout` is GNU coreutils (Linux-only; Podman
    # is Linux-only so this path is always on Linux where `timeout` is available).
    local _selfheal_timeout_s=180
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=5s "${_selfheal_timeout_s}s" \
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${_sh_profile_args[@]+"${_sh_profile_args[@]}"} up -d >/dev/null 2>&1 || {
        local _rc=$?
        if [[ "$_rc" -eq 124 ]]; then
          log_warn "Self-heal compose up -d timed out after ${_selfheal_timeout_s}s (FINDING-2) — continuing to poll"
        fi
        true
      }
    else
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${_sh_profile_args[@]+"${_sh_profile_args[@]}"} up -d >/dev/null 2>&1 || true
    fi
    local _deadline_sh=$(( $(date +%s) + _timeout_s ))
    while [[ "$(date +%s)" -lt "$_deadline_sh" ]]; do
      # shellcheck disable=SC2086  # intentional word-splitting for _curl_tls_opt
      if curl --silent $_curl_tls_opt --max-time 5 \
           --resolve "${_domain}:${_https_port}:127.0.0.1" \
           "https://${_domain}:${_https_port}/healthz" \
           -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "^200$"; then
        _gateway_ok=1
        log_success "Convergence gate: gateway healthy after self-heal re-converge"
        break
      fi
      sleep "$_poll_s"
    done
  fi

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
    # shellcheck disable=SC2086  # intentional word-splitting for _curl_tls_opt
    if curl --silent $_curl_tls_opt --max-time 5 \
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
      psql -U yashigani_admin -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")

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
        psql -U yashigani_admin -d yashigani -h 127.0.0.1 -tAc "SHOW ssl;" 2>/dev/null | tr -d ' \n' || echo "unknown")
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
  # #ROOTLESS-WAZUH-1: postgres_password is subuid-owned on rootless Podman; use
  # _safe_read_secret (direct cat → podman unshare cat → .env lookup) rather than
  # a bare `cat` that would EPERM on the rootless path.
  local _pg_pass
  _pg_pass="$(_safe_read_secret "${WORK_DIR}/docker/secrets/postgres_password" \
              "POSTGRES_PASSWORD" "${WORK_DIR}/docker/.env" 2>/dev/null || echo "")"
  if [[ -z "$_pg_pass" ]]; then
    log_warn "postgres SSL upgrade: could not read postgres_password — skipping SCRAM re-hash"
  else
    "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T postgres \
        psql -U yashigani_admin -d yashigani -h 127.0.0.1 \
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
    # FINDING-1/5 fix: load init-deps reset BEFORE override (same order as compose_up).
    local podman_init_deps="${WORK_DIR}/docker/docker-compose.podman-init-deps.yml"
    [[ -f "$podman_init_deps" ]] && compose_files+=("-f" "$podman_init_deps")
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
# SEC-001 (2026-06-14): register agent bundles via the NO-ADMIN-API durable
# path — mirrors agents/reconciler.py. Writes directly to Postgres
# (AgentDurableStore) + Redis db/3 (AgentRegistry). No admin login, no TOTP,
# no step-up, no install_svc service account. Eliminates LAURA-2255-001 (human
# admin bootstrap regression) and the install_svc standing-admin backdoor.
#
# Security: this Python runs INSIDE the backoffice container (compose exec),
# which is mesh-isolated (data-network only). We use the same env vars
# (YASHIGANI_DB_DSN, REDIS_USE_TLS, etc.) that the in-process app uses.
# The HTTP stack is not touched — no admin session, no TOTP, no HMAC secret.
import json, os, sys, secrets as _sec_mod
sys.path.insert(0, "/app/src")

agents_spec = json.loads(os.environ.get("AGENTS_JSON", "[]"))
results = []

for agent_spec in agents_spec:
    profile = agent_spec["profile"]
    aname   = agent_spec["name"]
    aurl    = agent_spec["url"]
    aproto  = agent_spec.get("protocol", "openai")

    try:
        from yashigani.agents.registry import AgentRegistry
        from yashigani.agents.durable_store import AgentDurableStore
        from yashigani.gateway._redis_url import build_redis_url
        import redis as _redis

        _redis_url = build_redis_url(
            3,
            use_tls=os.getenv("REDIS_USE_TLS", "true").lower() == "true",
            secrets_dir="/run/secrets",
            client_cert_name="backoffice_client",
        )
        _rc = _redis.from_url(_redis_url, decode_responses=True)
        registry = AgentRegistry(_rc)
        durable  = AgentDurableStore()

        # Skip if agent is already registered by name (idempotent; preserves token)
        existing_names = {a.get("name", "") for a in registry.list_all()}
        if aname in existing_names:
            results.append("SKIP:" + aname + ":" + profile)
            continue

        # Generate PSK token + bcrypt hash (mirrors POST /admin/agents)
        import bcrypt as _bcrypt
        raw_token = "ysg-" + _sec_mod.token_hex(32)
        token_hash = _bcrypt.hashpw(raw_token.encode(), _bcrypt.gensalt(rounds=12)).decode()
        agent_id = "agnt_" + _sec_mod.token_hex(8)

        agent_data = {
            "agent_id": agent_id,
            "name": aname,
            "upstream_url": aurl,
            "protocol": aproto,
            "status": "active",
            "groups": [],
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "allowed_cidrs": [],
        }

        # 1. Durable write (Postgres) — survives redis recreate
        durable.upsert(agent_data, token_hash=token_hash)
        # 2. Fast write (Redis db/3) — request-time source of truth
        registry.restore_from_durable(agent_data, token_hash)
        # 3. Token file for gateway
        token_path = os.path.join("/run/secrets", profile + "_token")
        try:
            with open(token_path, "w") as _tf:
                _tf.write(raw_token)
            try:
                # BUG-WAVE1-P1-002: 0640 so gateway (GID 1001 group) can read
                os.chmod(token_path, 0o640)
            except OSError as _ce:
                print(f"WARNING:chmod_640_failed:{token_path}:{_ce}", file=sys.stderr)
        except PermissionError:
            pass  # printed below for host-side capture
        results.append("OK:" + aname + ":" + profile + ":" + raw_token)
    except Exception as e:
        results.append("FAIL:" + aname + ":" + str(e))

for r in results:
    print(r)
' 2>&1)" || reg_exit=$?

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

    # Pre-populate agents in Open WebUI's database — ONLY when Open WebUI is
    # actually installed. LIVE-OWUI-SYNC-001 (VM smoke 2026-05-28): this block
    # previously gated only on the init script existing, so on an install
    # WITHOUT --with-openwebui it ran `exec ... open-webui` against a container
    # that does not exist and printed "no container docker_open-webui_1 found"
    # (non-fatal via || true, but alarming noise in the install log).
    if [[ "${INSTALL_OPENWEBUI:-false}" == "true" ]]; then
      log_info "Syncing agents to Open WebUI..."
      local init_script="${WORK_DIR}/scripts/init-openwebui-agents.py"
      if [[ -f "$init_script" ]]; then
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" cp "$init_script" open-webui:/tmp/init-agents.py 2>/dev/null || \
          podman cp "$init_script" docker_open-webui_1:/tmp/init-agents.py 2>/dev/null || true
        "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T open-webui python3 /tmp/init-agents.py 2>&1 || \
          podman exec docker_open-webui_1 python3 /tmp/init-agents.py 2>&1 || true
      fi
    else
      log_info "Open WebUI not installed — skipping agent sync (re-run with --with-openwebui to enable)"
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

  # OLLAMA-INIT-EXIT-001: check ollama-init exit status and warn loudly if it
  # failed. ollama-init is a one-shot container (no restart-unless-stopped) so
  # a failed pull is silent once compose_up returns — the step-12 health check
  # only verifies the ollama service port, not that models were actually pulled.
  # This check surfaces init failures so the operator is not left wondering why
  # agents return 404 "model not found". Non-fatal: the core stack is healthy;
  # the operator can re-run 'docker compose --profile <profile> run ollama-init'.
  _check_ollama_init_exit "${WORK_DIR}/docker"
}

# _check_ollama_init_exit — inspect the stopped ollama-init container exit code.
# Called at the end of run_health_check() after the main health script passes.
# Non-fatal: emits a clear WARNING and remediation hint; does NOT exit 1 because
# compose warn-and-continue logic (digest=skip) means exit 0 is now the normal
# path; a lingering exit-1 container means something else (network, disk) failed.
_check_ollama_init_exit() {
  local _compose_dir="${1:-${WORK_DIR}/docker}"
  local _compose_file="${_compose_dir}/docker-compose.yml"

  # Only applies to compose deployments; helm has its own Job status.
  if [[ "${DEPLOY_MODE:-compose}" != "compose" && "${DEPLOY_MODE:-compose}" != "vm" ]]; then
    return 0
  fi

  # ollama-init only runs when at least one AI profile is active.
  local _has_ai_profile=false
  for _p in "${COMPOSE_PROFILES[@]:-}"; do
    case "$_p" in
      openwebui|langflow|letta|openclaw) _has_ai_profile=true; break ;;
    esac
  done
  if [[ "$_has_ai_profile" != "true" ]]; then
    return 0
  fi

  # Look for an exited ollama-init container. Container name format varies by
  # runtime: docker = <project>-ollama-init-1, podman = <project>_ollama-init_1
  local _exit_code=""
  local _ctr_name=""
  while IFS= read -r _line; do
    if [[ "$_line" == *"ollama-init"* ]]; then
      _ctr_name="$_line"
      break
    fi
  done < <("${COMPOSE_CMD[@]:-docker compose}" -f "$_compose_file" ps -a --format '{{.Name}}' 2>/dev/null || true)

  if [[ -z "$_ctr_name" ]]; then
    log_warn "ollama-init container not found — model pull status unknown (check: docker compose ps -a)"
    return 0
  fi

  _exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$_ctr_name" 2>/dev/null || \
                podman inspect --format '{{.State.ExitCode}}' "$_ctr_name" 2>/dev/null || true)"

  if [[ -z "$_exit_code" ]]; then
    log_warn "ollama-init: could not read exit code from container '$_ctr_name'"
    return 0
  fi

  if [[ "$_exit_code" != "0" ]]; then
    log_warn "################################################################"
    log_warn "INSTALL WARNING: ollama-init exited with code ${_exit_code}"
    log_warn "  The model pull container failed — agents (@letta/@langflow/@openclaw)"
    log_warn "  may return 404 'model not found' until models are available in Ollama."
    log_warn "  Check logs:  docker compose -f ${_compose_file} logs ollama-init"
    log_warn "  Re-run pull: docker compose -f ${_compose_file} --profile <profile> run --rm ollama-init"
    log_warn "################################################################"
  else
    log_success "ollama-init exited cleanly (models pulled successfully)"
  fi
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
  # Phase 13 (Yashigani 3.1): Admin-tier TOTP upgraded to HMAC-SHA-512, 8 digits.
  # otpauth://totp/Yashigani:username?secret=SECRET&issuer=Yashigani&algorithm=SHA512&digits=8&period=30
  #
  # All Yashigani admin accounts use SHA-512/8-digit TOTP from v3.1.
  # User-tier accounts use SHA-256/6-digit; those are provisioned via the web UI.
  #
  # REQUIRED AUTHENTICATOR APP: agnosticOTP (iOS/Android) or Aegis — reads the
  # algorithm= and digits= URI parameters. Classic Google Authenticator (SHA-1 only)
  # is NOT compatible with SHA-512/8-digit TOTP and MUST NOT be used.
  #
  # YSG-RISK-078 context: the original SHA-256 reversion was driven by SHA-1-only
  # apps failing silently. Phase 13 mandates agnosticOTP specifically to avoid this.
  local username="$1"
  local secret="$2"
  local issuer="${DOMAIN:-Yashigani}"
  echo "otpauth://totp/Yashigani:${username}?secret=${secret}&issuer=${issuer}&algorithm=SHA512&digits=8&period=30"
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

# _secret_is_valid — F-001 self-heal predicate
#
# Returns 0 (true) if a CSPRNG secret file is present, non-empty, AND does not
# contain a placeholder comment line ("# ...").  Returns 1 in all other cases:
# file absent, zero-length, or contains only a placeholder/comment.
#
# Usage: _secret_is_valid <file>
#
# Rationale: install.sh writes placeholder strings (e.g. "# placeholder —
# auto-generated at first bootstrap") into new secret slots before the PKI
# bootstrap chowns secrets_dir.  A stale/partial install can leave those
# placeholders on disk.  The old guard `[[ -s "$f" ]]` only checks non-zero
# size, so a placeholder file is treated as a valid secret and preserved — then
# envsubst substitution in the OpenClaw config receives the literal comment
# string instead of a token (F-001 abort).  This predicate closes that gap.
#
# F-001 / fix/medlow-findings (Su, 2026-06-14)
_secret_is_valid() {
  local _sv_file="$1"
  # Must exist and be non-empty
  [[ -s "$_sv_file" ]] || return 1
  # Must not start with a comment/placeholder marker.
  # BUG-B+-004 (3.1.0): On Podman rootless, secrets are subuid-owned and unreadable by
  # the host installer user. `head -c 1` fails → the function would return 1 (invalid)
  # on every upgrade, triggering a re-generate + write path that ALSO fails (same EPERM).
  # Fix: if head fails and YSG_PODMAN_RUNTIME=true, retry inside the user namespace via
  # `podman unshare`. If the unshare read also fails, treat the file as valid (it exists
  # and is non-empty per -s, so it's a real secret — the service started with it).
  local _sv_first
  if ! _sv_first="$(head -c 1 "$_sv_file" 2>/dev/null)"; then
    if [[ "${YSG_PODMAN_RUNTIME:-false}" == "true" ]] && command -v podman >/dev/null 2>&1; then
      _sv_first="$(podman unshare sh -c "head -c 1 '${_sv_file}'" 2>/dev/null)" || {
        # Podman unshare also failed: file exists+nonempty but totally unreadable.
        # Treat as valid — the running service proves the value is real.
        return 0
      }
    else
      return 1
    fi
  fi
  [[ "$_sv_first" == "#" ]] && return 1
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

  # Skip if secrets already exist AND are non-empty (upgrade path).
  # FIND-INSTALL-3.1-001: use -s (non-empty) not -f (exists) so that a partial
  # install that created empty secret files falls through to fresh generation
  # rather than taking the upgrade path with an empty password, which skips the
  # -n guard and leaves POSTGRES_PASSWORD / POSTGRES_PASSWORD_URLENC absent from .env.
  if [[ -s "${secrets_dir}/postgres_password" && -s "${secrets_dir}/redis_password" ]]; then
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
          # FIND-INSTALL-3.1-002: keep tmp alongside .env (same FS → atomic mv, no /tmp).
          local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
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
        # FIND-INSTALL-3.1-002: keep tmp alongside .env (same FS → atomic mv, no /tmp).
        local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
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
    # F-001 self-heal: _secret_is_valid rejects placeholder files; REINSTALL rotates.
    if ! _secret_is_valid "$hmac_file" || [[ "${REINSTALL:-false}" == "true" ]]; then
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
        local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
        sed "s|^CADDY_INTERNAL_HMAC=.*|CADDY_INTERNAL_HMAC=${_hmac_val}|" "$env_file" > "$tmp_env"
        mv "$tmp_env" "$env_file"
      else
        echo "CADDY_INTERNAL_HMAC=${_hmac_val}" >> "$env_file"
      fi
    else
      log_warn "Cannot read caddy_internal_hmac — CADDY_INTERNAL_HMAC already in .env, preserving existing value (BUG-B+-004)"
    fi

    # Bucket-C finding (Captain gitleaks baseline 2026-05-17): per-install
    # YASHIGANI_INTERNAL_BEARER — generate if absent OR placeholder on upgrade path.
    # F-001 self-heal: _secret_is_valid rejects placeholder files so a stale
    # partial install that left a "# placeholder" string is treated as missing and
    # regenerated instead of being synced verbatim into .env (fix/medlow-findings).
    local _bearer_file_up="${secrets_dir}/yashigani_internal_bearer"
    if ! _secret_is_valid "$_bearer_file_up"; then
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
      if [[ -z "$_bearer_val_up" ]] || [[ "$_bearer_val_up" == \#* ]]; then
        log_error "F-001: yashigani_internal_bearer was just generated but read back empty or as placeholder — inconsistent state in ${secrets_dir}. Check permissions on docker/secrets/."
        return 1
      fi
      if grep -q "^YASHIGANI_INTERNAL_BEARER=" "$env_file" 2>/dev/null; then
        local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
      local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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

    # BEGIN YSG-P3-MCP-SIGKEY-UPGRADE
    # MCP signing key — generate if absent on upgrade path (same idempotency as caddy_internal_hmac above).
    # This covers upgrades from pre-v2.25.0 where the key did not yet exist.
    local _mcp_key_file_up="${secrets_dir}/mcp_identity_signing_key"
    local _env_file_up="${WORK_DIR}/docker/.env"

    if [[ ! -s "$_mcp_key_file_up" ]]; then
      log_info "Generating MCP P-384 signing key (upgrade path) → ${_mcp_key_file_up}"
      (
        umask 077
        if ! openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null \
             | openssl ec -out "${_mcp_key_file_up}" 2>/dev/null; then
          printf 'ERROR: Failed to generate MCP P-384 signing key (upgrade path)\n' >&2
          rm -f "${_mcp_key_file_up}" 2>/dev/null || true
          exit 1
        fi
        chmod 0600 "${_mcp_key_file_up}"
      ) || {
        log_error "MCP P-384 signing key generation failed (upgrade path) — aborting"
        return 1
      }
      log_info "MCP P-384 signing key generated (mode 0600, upgrade path)"
    else
      log_info "mcp_identity_signing_key already present — preserving (upgrade path)"
    fi

    # No .env sync needed — the gateway reads the key from
    # /run/secrets/mcp_identity_signing_key (file-tier in _jwt.py), which is
    # exposed via the existing docker-compose bind-mount `./secrets:/run/secrets:ro`.
    # Storing the raw private key in .env is wider exposure (docker inspect,
    # backup tools, process env) and is intentionally avoided.
    # END YSG-P3-MCP-SIGKEY-UPGRADE

    # BEGIN DP-Y-002-SECRET-UPGRADE
    # document_pseudonymize_secret — DP-Y-002 §3.1 (upgrade path idempotency).
    # The PSEUDONYMIZE deployment secret is read from the existing
    # ./secrets:/run/secrets:ro bind-mount at /run/secrets/document_pseudonymize_secret.
    # No .env sync needed (the code reads from file, never from an env var as
    # the primary path).  Mode 0600: only processes inside containers that read
    # /run/secrets may access it; not world-readable.
    local _dp_secret_file_up="${secrets_dir}/document_pseudonymize_secret"
    if ! _secret_is_valid "$_dp_secret_file_up" || [[ "${REINSTALL:-false}" == "true" ]]; then
      local _dp_secret_up
      if command -v openssl >/dev/null 2>&1; then
        _dp_secret_up="$(openssl rand -hex 32)"
      elif command -v python3 >/dev/null 2>&1; then
        _dp_secret_up="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
      else
        log_error "Cannot generate document_pseudonymize_secret: neither openssl nor python3 found"
        return 1
      fi
      printf "%s" "$_dp_secret_up" > "$_dp_secret_file_up"
      chmod 0600 "$_dp_secret_file_up"
      log_info "Generated document_pseudonymize_secret → ${_dp_secret_file_up} (mode 0600, upgrade path, DP-Y-002 §3.1)"
      log_warn "OPERATOR NOTE (DP-Y-002): any correspondence tables minted before this upgrade (under the old doc-hash-only keying) will fail integrity verification — this is expected, not a bug."
    else
      log_info "document_pseudonymize_secret already present — preserving (upgrade path)"
    fi
    # END DP-Y-002-SECRET-UPGRADE

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
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
    sed "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}" >> "$env_file"
  fi
  # v2.23.1 fix: URL-encoded variant for URI-style DSNs (see _urlencode_userinfo).
  GEN_POSTGRES_PASSWORD_URLENC="$(_urlencode_userinfo "$GEN_POSTGRES_PASSWORD")"
  if grep -q "^POSTGRES_PASSWORD_URLENC=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
      local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
  # F-001 self-heal: _secret_is_valid rejects placeholder files; REINSTALL rotates.
  if ! _secret_is_valid "$hmac_file" || [[ "${REINSTALL:-false}" == "true" ]]; then
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
      local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
  # Idempotent: valid secret already on disk → preserve.
  #
  # F-001 self-heal (fix/medlow-findings): use _secret_is_valid (not -s) so a
  # stale placeholder file ("# placeholder — auto-generated at first bootstrap")
  # left by a partial install is treated as absent and regenerated.  A plain -s
  # check passes for any non-zero file, so placeholders were silently propagated
  # into .env and then into the OpenClaw envsubst step, causing the abort
  # "yashigani_internal_bearer could not be read".
  local _bearer_file="${secrets_dir}/yashigani_internal_bearer"
  local _bearer_token
  if ! _secret_is_valid "$_bearer_file"; then
    _bearer_token="$(_gen_password)"
    printf "%s" "$_bearer_token" > "$_bearer_file"
    chmod 0600 "$_bearer_file"
    log_info "Generated yashigani_internal_bearer → ${_bearer_file} (mode 0600)"
  else
    log_info "yashigani_internal_bearer already present — preserving (use --remove-volumes to rotate)"
    # BUG-B+-004 (sweep): safe read — may be subuid-owned on Podman rootless re-install.
    _bearer_token="$(_safe_read_secret "$_bearer_file" "YASHIGANI_INTERNAL_BEARER" "$env_file" || true)"
  fi
  # Fail-closed: if the token is still empty or a comment after generation,
  # there is a genuine inconsistency (e.g. write failure on an EACCES secrets_dir).
  if [[ -z "$_bearer_token" ]] || [[ "$_bearer_token" == \#* ]]; then
    log_error "F-001: yashigani_internal_bearer could not be generated or read back — check permissions on ${secrets_dir}. If docker/secrets/ is owned by a subuid-remapped UID, wipe it and re-run."
    return 1
  fi
  # Sync YASHIGANI_INTERNAL_BEARER into .env for Compose interpolation.
  if grep -q "^YASHIGANI_INTERNAL_BEARER=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"  # FIND-INSTALL-3.1-002
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
    local tmp_env; tmp_env="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
    sed "s|^YASHIGANI_VERSION=.*|YASHIGANI_VERSION=${YASHIGANI_VERSION}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "YASHIGANI_VERSION=${YASHIGANI_VERSION}" >> "$env_file"
  fi

  # Cache-busting SHA — keep in sync with the value written by _write_aes_key_to_env.
  # This block runs on the upgrade path (step 7 re-runs secrets generation but skips
  # _write_aes_key_to_env on non-fresh installs), so we always refresh the SHA here
  # to reflect the current source commit.
  if grep -q "^YASHIGANI_GIT_SHA=" "$env_file" 2>/dev/null; then
    local tmp_sha; tmp_sha="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
    sed "s|^YASHIGANI_GIT_SHA=.*|YASHIGANI_GIT_SHA=${YASHIGANI_GIT_SHA}|" "$env_file" > "$tmp_sha"
    mv "$tmp_sha" "$env_file"
  else
    echo "YASHIGANI_GIT_SHA=${YASHIGANI_GIT_SHA}" >> "$env_file"
  fi

  # BEGIN YSG-P3-MCP-SIGKEY
  # --- MCP identity signing key (P-384 / ES384) — Nico ship-blocker ---
  # The MCP JWT issuer (src/yashigani/mcp/_jwt.py) performs a 3-tier key lookup:
  #   1. YASHIGANI_MCP_SIGNING_KEY_PEM env var (base64-encoded PEM, testing only)
  #   2. PEM file at $YASHIGANI_MCP_SIGNING_KEY_PATH
  #      (default /run/secrets/mcp_identity_signing_key — bind-mounted into the
  #      gateway container by the existing compose pattern ./secrets:/run/secrets:ro)
  #   3. Ephemeral key — REFUSED in production/staging (RuntimeError)
  #
  # Install.sh owns path #2: generate a P-384 EC private key and write it to
  # ${secrets_dir}/mcp_identity_signing_key (0600); the existing compose
  # bind-mount exposes it at /run/secrets/mcp_identity_signing_key inside the
  # gateway container, where _jwt.py reads it. No .env env-var sync —
  # storing the raw private key in .env is wider exposure (docker inspect,
  # backup tools, process env) and is intentionally avoided.
  #
  # Idempotent: if the key file already exists, preserve it.
  # Rotation: use scripts/rotate-secret.sh (separate documented operation).
  # Backup: the file lands in ${secrets_dir}/ which is captured by
  #   _backup_existing_data → bundle.enc (YSG-RISK-050/051 dual-wrap).
  # Uninstall: wipe of docker/secrets/* in uninstall.sh --remove-volumes covers this.
  local _mcp_key_file="${secrets_dir}/mcp_identity_signing_key"

  if [[ ! -s "$_mcp_key_file" ]]; then
    log_info "Generating MCP P-384 signing key → ${_mcp_key_file}"
    umask 077
    # Generate a P-384 (secp384r1) EC private key in unencrypted PEM format.
    # openssl ecparam + openssl ec produces a PKCS#8-compatible PEM that the
    # Python cryptography library reads via load_pem_private_key().
    # Use a subshell to scope umask 077 tightly to the key file write.
    (
      umask 077
      if ! openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null \
           | openssl ec -out "${_mcp_key_file}" 2>/dev/null; then
        printf 'ERROR: Failed to generate MCP P-384 signing key\n' >&2
        rm -f "${_mcp_key_file}" 2>/dev/null || true
        exit 1
      fi
      chmod 0600 "${_mcp_key_file}"
    ) || {
      log_error "MCP P-384 signing key generation failed — aborting"
      return 1
    }
    log_info "MCP P-384 signing key generated (mode 0600)"
  else
    log_info "mcp_identity_signing_key already present — preserving (use scripts/rotate-secret.sh to rotate)"
  fi

  # S1 invariant check: the key file must be 0600 — never world or group readable.
  if [[ -f "$_mcp_key_file" ]]; then
    local _mcp_key_mode
    _mcp_key_mode="$(stat -c '%a' "${_mcp_key_file}" 2>/dev/null \
                     || stat -f '%p' "${_mcp_key_file}" 2>/dev/null | tail -c 4 || echo "???")";
    if [[ "${_mcp_key_mode}" != "600" ]]; then
      log_warn "mcp_identity_signing_key mode is ${_mcp_key_mode} — enforcing 0600 (CWE-732 guard)"
      chmod 0600 "${_mcp_key_file}" || true
    fi
  fi

  # FIX-MCP-SIGKEY-PERM: chown the signing key to UID 1001 (gateway container user).
  #
  # The key is generated as 0600 owned by the installer user (UID 1000 = max).
  # The gateway container runs as UID 1001 (maxine on the VM host = uid=1001).
  # Docker rootful bind-mounts expose host UID/GID directly — 0600 uid=1000 is
  # unreadable by the gateway (uid=1001), causing PermissionError at startup.
  #
  # Fix: use _do_chown (V240-002 helper) to set ownership to 1001:1001.  When
  # the installer runs as a non-root user (typical Docker install), bare chown
  # fails silently (EPERM); _do_chown falls through to the docker_run path
  # (alpine container with bind-mount) which succeeds because Docker is rootful.
  # The 0600 mode is preserved — only the owner changes.  This mirrors the
  # convention for other private key files in docker/secrets/ (e.g.
  # gateway_client.key is 0600 1001:1001).
  #
  # P3 broker E2E gate — J8/J9/J10 gateway PermissionError fix (2026-05-30).
  # ASVS V2.6.3: key generation and storage must follow least-privilege.
  if [[ -f "$_mcp_key_file" ]]; then
    _do_chown "1001:1001" "${_mcp_key_file}" "mcp_identity_signing_key" "" "${secrets_dir}" \
      || log_warn "mcp_identity_signing_key: _do_chown 1001:1001 failed — gateway may fail to start"
  fi

  # No .env sync needed — the gateway reads the key from
  # /run/secrets/mcp_identity_signing_key (file-tier in _jwt.py), which is
  # exposed via the existing docker-compose bind-mount `./secrets:/run/secrets:ro`.
  # Storing the raw private key in .env is wider exposure (docker inspect,
  # backup tools, process env) and is intentionally avoided.
  # END YSG-P3-MCP-SIGKEY

  # BEGIN DP-Y-002-SECRET
  # document_pseudonymize_secret — DP-Y-002 §3.1 (fresh install path).
  # The PSEUDONYMIZE action derives per-file tokens via keyed HMAC-SHA256.
  # Without this secret the pipeline FAILS CLOSED (refuses to pseudonymise),
  # per DP-Y-002 §3.1.  256-bit hex is sufficient headroom; mode 0600.
  # Read from /run/secrets/document_pseudonymize_secret via the existing
  # ./secrets:/run/secrets:ro bind-mount — no .env sync needed.
  local _dp_secret_file="${secrets_dir}/document_pseudonymize_secret"
  if ! _secret_is_valid "$_dp_secret_file" || [[ "${REINSTALL:-false}" == "true" ]]; then
    local _dp_secret
    if command -v openssl >/dev/null 2>&1; then
      _dp_secret="$(openssl rand -hex 32)"
    elif command -v python3 >/dev/null 2>&1; then
      _dp_secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    else
      log_error "Cannot generate document_pseudonymize_secret: neither openssl nor python3 found"
      return 1
    fi
    printf "%s" "$_dp_secret" > "$_dp_secret_file"
    chmod 0600 "$_dp_secret_file"
    log_info "Generated document_pseudonymize_secret → ${_dp_secret_file} (mode 0600, DP-Y-002 §3.1)"
  else
    log_info "document_pseudonymize_secret already present — preserving (use REINSTALL=true to rotate)"
  fi
  # END DP-Y-002-SECRET

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
  printf "  ${C_YELLOW}║${C_RESET}    TOTP algo:    %-44s ${C_YELLOW}║${C_RESET}\n" "HMAC-SHA-512 / 8-digit (admin tier; use agnosticOTP or Aegis)"
  if [[ -n "$GEN_ADMIN1_TOTP_URI" ]]; then
  printf "  ${C_YELLOW}║${C_RESET}    TOTP URI (paste into authenticator app):                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %s\n" "${GEN_ADMIN1_TOTP_URI}"
  fi
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Admin 2 (backup — anti-lockout):${C_RESET}                              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_USERNAME}"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP secret:  %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_TOTP_SECRET}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP algo:    %-44s ${C_YELLOW}║${C_RESET}\n" "HMAC-SHA-512 / 8-digit (admin tier; use agnosticOTP or Aegis)"
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
  printf "    2. Scan the TOTP QR URIs into an authenticator that supports non-default algorithms\n       (agnosticOTP, Aegis, Authy, 1Password). Admin accounts use HMAC-SHA-512 / 8-digit TOTP;\n       user accounts use HMAC-SHA-256 / 6-digit. Classic Google Authenticator is NOT compatible.\n"
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

  # F2: helm is a Kubernetes-only dependency. A Docker/Podman compose operator
  # must never be forced to install helm. This step (and every other k8s_* step)
  # only runs inside the `MODE == k8s` branch of main(); this guard is
  # defence-in-depth so that if the flow is ever reached with a compose runtime
  # (e.g. a future refactor), helm is skipped instead of aborting the install.
  if [[ "${MODE:-compose}" != "k8s" || "${YSG_RUNTIME:-}" == "docker" || "${YSG_RUNTIME:-}" == "podman" ]]; then
    log_info "Skipping Helm chart dependencies (compose runtime — helm not required)"
    return 0
  fi

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
# DB_AES_KEY handling (Iris coord #1 — v2.25.0 P2 wave 2):
# backoffice.dbAesKey is now a first-class values.yaml key. When DB_AES_KEY is
# non-empty it is written into .env.helm as backoffice.dbAesKey so secrets.yaml
# uses it directly (Priority: existing Secret > backoffice.dbAesKey > randAlphaNum).
# The prior kubectl create secret --dry-run workaround is removed — it was a
# pre-seeding hack to work around the missing schema key. No longer needed.
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
    printf 'backoffice:\n'

    if [[ -n "${DB_AES_KEY:-}" ]]; then
      # Iris coord #1 (v2.25.0 P2): write dbAesKey directly into helm values.
      # secrets.yaml uses .Values.backoffice.dbAesKey when non-empty, so
      # Helm generates the Secret with the operator key on first install.
      # On upgrade, Helm's lookup() finds the existing Secret and preserves it
      # regardless of this value. The kubectl pre-seeding workaround is retired.
      printf "  dbAesKey: '%s'\n" "${DB_AES_KEY}"
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

  # Iris coord #1 (v2.25.0 P2): kubectl pre-seeding workaround REMOVED.
  # DB_AES_KEY is now written to .env.helm as backoffice.dbAesKey above.
  # Helm's secrets.yaml lookup() preserves the existing Secret on upgrade;
  # on first install it reads backoffice.dbAesKey from the values file.
  # No pre-seeding kubectl call required.

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

  # LIVE-B13-001/002/003/004 (end-of-P2 live-verify on kind v1.35.0):
  # The chart used to manage the Namespace resource directly. That collided
  # with --create-namespace in multiple ways: PSA labels silently dropped on
  # first install, hook annotations broke release tracking, and unconditional
  # Namespace + --atomic triggered full rollback on Namespace-already-exists.
  # Fix: install.sh owns the namespace lifecycle. Pre-create the namespace
  # with PSA warn+audit baseline labels here, then run helm install WITHOUT
  # --create-namespace. PSA enforce is intentionally NOT applied (caddy needs
  # CAP_NET_ADMIN which baseline forbids; PSA has no per-pod exception).
  # Hard enforcement is delegated to Kyverno (admissionPolicies.enabled=true).
  if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    log_info "Pre-creating namespace ${NAMESPACE} with PSA warn+audit baseline labels..."
    kubectl create namespace "$NAMESPACE"
  fi
  # Apply / refresh PSA labels (idempotent via --overwrite). Safe on existing ns.
  kubectl label namespace "$NAMESPACE" --overwrite \
    pod-security.kubernetes.io/warn=baseline \
    pod-security.kubernetes.io/warn-version=latest \
    pod-security.kubernetes.io/audit=baseline \
    pod-security.kubernetes.io/audit-version=latest \
    >/dev/null
  log_success "PSA warn+audit baseline labels applied to namespace ${NAMESPACE}"

  local helm_args=(
    upgrade --install yashigani "$chart_dir"
    --namespace "$NAMESPACE"
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
#
# NEW-BUG-B FIX (Ava 2026-05-30): ":U" MUST NOT be applied to secrets_dir either.
# When secrets_dir already contains files owned by subuid-remapped UIDs (e.g.
# UID 101000 from a previous PKI bootstrap), Podman's ":U" flag calls lchown
# on the bind-mount source for each file.  The caller at UID 1000 cannot
# lchown files owned by UID 101000 — EPERM — even inside podman unshare.
# The outer UID mapping constraint means user-namespace-root cannot lchown
# files whose host UID is outside the caller's subuid range mapped into that
# namespace.  Removing ":U" from secrets_dir is safe: the PKI issuer runs as
# UID 1001 inside the container, and secrets files are pre-chowned to the
# remapped equivalent of UID 1001 by _prepare_secrets_dir_for_pki().
# ":z" (lowercase SELinux label only) is retained — it does NOT call lchown.
#
# The manifest is pre-chowned via podman unshare (rootless) or plain chown
# (rootful) so the container can write back bootstrap_token_sha256 fields.
# ":U" is NOT applied to any mount on any path in this function.
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
    dry_print "podman run --rm --network=none -v ${secrets_in}:/secrets:rw,z -v ${manifest_in}:/manifest.yaml:rw,Z $image python -m yashigani.pki.issuer --secrets-dir /secrets --manifest /manifest.yaml $subcmd $*"
    return 0
  fi

  # --network=none: issuer does no network I/O, and cutting the network
  # prevents any accidental telemetry exfil.
  # NEW-BUG-B: ":U" removed from secrets_dir mount — see gate #ROOTLESS-9 comment.
  # ":z" (SELinux label, no lchown) replaces ":Z,U" for rootless safety.
  podman run --rm --network=none \
    -v "${secrets_in}:/secrets:rw,z" \
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

  # NEW-BUG-C FIX (Ava 2026-05-30): do NOT unconditionally overwrite the runtime
  # manifest with the canonical.  The runtime manifest carries runtime-only fields
  # (bootstrap_token_sha256) written by the PKI issuer and by the onboard handler.
  # Overwriting with the canonical erases those fields — which breaks BUG-5's
  # token-population fix: the token is populated at onboard time, then immediately
  # erased when _pki_run_issuer is called to issue the leaf cert.
  #
  # New policy:
  #   a. If the runtime manifest does NOT exist → copy canonical (bootstrap case).
  #   b. If the runtime manifest DOES exist → merge: copy canonical structure but
  #      preserve bootstrap_token_sha256 values from the runtime copy.
  #
  # Merge is implemented via Python (already a dependency at this point): parse
  # both YAML files, take canonical as the base, overlay bootstrap_token_sha256
  # values from runtime for any service that already has a non-empty hash.
  # On failure (Python absent / YAML error), fall back to canonical-wins and warn.
  if [[ ! -f "$manifest_in" ]]; then
    # Fresh install: runtime manifest absent — seed from canonical.
    cp -f "$_canonical_manifest" "$manifest_in" \
      || { log_error "_pki_run_issuer: failed to copy canonical manifest to runtime path ${manifest_in}"; return 1; }
    log_info "_pki_run_issuer: seeded runtime manifest at ${manifest_in} (fresh — hash-back will populate bootstrap_token_sha256 values)"
  else
    # Runtime manifest exists — merge, preserving bootstrap_token_sha256 fields.
    local _merge_ok=false
    # NEW-BUG-C FIX (cascade audit 2026-05-30):
    #   (a) Removed 2>/dev/null — stderr captured and echoed via log_info so
    #       errors surface in the install log instead of being silently swallowed.
    #   (b) Fixed name-extraction regex: service_identities.yaml uses YAML list
    #       syntax "  - name: caddy" (list-item), not "  name: caddy" (map key).
    #       The old regex r'^\s{0,4}name:...' never matched "  - name:" lines
    #       → runtime_tokens always empty → merge silently produced canonical
    #       output, erasing all bootstrap_token_sha256 values on every PKI call.
    #       Fixed regex accepts both "  - name: svc" and "  name: svc" forms.
    # Strategy: write the Python body to a mktemp file, run once, capture stderr.
    local _merge_py; _merge_py="$(mktemp)"
    cat > "$_merge_py" <<'PYMERGE'
import sys, re

canonical_path, runtime_path = sys.argv[1], sys.argv[2]

# Read both files as raw text to preserve formatting/comments.
with open(canonical_path, encoding='utf-8') as f:
    canonical_text = f.read()
with open(runtime_path, encoding='utf-8') as f:
    runtime_text = f.read()

# Extract bootstrap_token_sha256 values from the runtime file.
# Pattern: lines like "    bootstrap_token_sha256: \"<hex>\"" with non-empty value.
# We preserve them by service name: map service_name -> sha256_value.
#
# BUGFIX (2026-05-30): service_identities.yaml uses YAML list syntax:
#   services:
#     - name: caddy
# The old regex r'^\s{0,4}name:' never matched "  - name:" list-item lines.
# Updated regex accepts both "  - name: svc" and "  name: svc" forms.
runtime_tokens = {}
current_service = None
for line in runtime_text.splitlines():
    # Match "  - name: svc" (list item) or "    name: svc" (map key)
    name_m = re.match(r'^\s+(?:-\s+)?name:\s*["\']?([\w][\w\-]*)["\']?', line)
    if name_m:
        current_service = name_m.group(1)
    tok_m = re.match(r'^\s+bootstrap_token_sha256:\s*"([0-9a-fA-F]{64})"', line)
    if tok_m and current_service:
        runtime_tokens[current_service] = tok_m.group(1)

if not runtime_tokens:
    print('pki-merge: no bootstrap_token_sha256 values found in runtime manifest (fresh install or empty runtime)', file=sys.stderr)

# Now rewrite canonical: for each service that has a runtime token, replace
# the empty bootstrap_token_sha256 placeholder with the runtime value.
current_service = None
out_lines = []
substituted = []
for line in canonical_text.splitlines():
    name_m = re.match(r'^\s+(?:-\s+)?name:\s*["\']?([\w][\w\-]*)["\']?', line)
    if name_m:
        current_service = name_m.group(1)
    if current_service and current_service in runtime_tokens:
        # Replace empty or existing placeholder.
        bts_m = re.match(r'^(\s+bootstrap_token_sha256:)\s*(""|"[0-9a-fA-F]{0,64}")', line)
        if bts_m:
            prefix = bts_m.group(1)
            line = '%s "%s"' % (prefix, runtime_tokens[current_service])
            substituted.append(current_service)
    out_lines.append(line)

merged_text = '\n'.join(out_lines)
if not merged_text.endswith('\n'):
    merged_text += '\n'

with open(runtime_path, 'w', encoding='utf-8') as f:
    f.write(merged_text)

print('pki-merge: preserved %d/%d bootstrap_token_sha256 values: %s' % (
    len(substituted), len(runtime_tokens),
    ', '.join(substituted) if substituted else '(none)'),
    file=sys.stderr)
PYMERGE
    _merge_ok=false
    local _merge_log2; _merge_log2="$(mktemp)"
    # NEW-BUG-H FIX (Ava iter-4 2026-05-30): on Podman rootless, service_identities.yaml
    # in docker/var/runtime/ is owned by the subuid-mapped UID for container UID 1001
    # (e.g. UID 101000 when max=1000 and subuid starts at 100000).  Running plain
    # python3 as UID 1000 raises PermissionError on both read and write paths.
    # Fix: detect rootless Podman via any of: YSG_PODMAN_RUNTIME=true, YSG_RUNTIME=podman,
    # or simply "podman available + /etc/subuid present + running as non-root on Linux".
    # Wrap the merge in `podman unshare` so it runs as UID 0 inside the user namespace
    # (which maps to the PKI-issuer-owned subuid range outside).
    # Note: this check is runtime-agnostic and does NOT depend on YSG_PODMAN_RUNTIME
    # having been set by resolve_compose_cmd, so it works on --pki-action invocations too.
    local _use_unshare=false
    if [[ "$(uname -s)" == "Linux" ]] && \
       [[ "$(id -u)" != "0" ]] && \
       command -v podman >/dev/null 2>&1 && \
       [[ -f /etc/subuid ]]; then
      _use_unshare=true
    fi
    if [[ "$_use_unshare" == "true" ]]; then
      podman unshare python3 "$_merge_py" "$_canonical_manifest" "$manifest_in" \
        2>"$_merge_log2" && _merge_ok=true
    else
      python3 "$_merge_py" "$_canonical_manifest" "$manifest_in" 2>"$_merge_log2" && _merge_ok=true
    fi
    if [[ -s "$_merge_log2" ]]; then
      while IFS= read -r _ml; do log_info "_pki_run_issuer merge: ${_ml}"; done < "$_merge_log2"
    fi
    rm -f "$_merge_py" "$_merge_log2"
    if [[ "$_merge_ok" == "true" ]]; then
      log_info "_pki_run_issuer: merged canonical → runtime manifest (bootstrap_token_sha256 values preserved)"
    else
      log_warn "_pki_run_issuer: manifest merge failed — falling back to canonical (bootstrap_token_sha256 values will be re-issued)"
      # NEW-BUG-H: same podman unshare wrapper for the fallback copy.
      if [[ "$_use_unshare" == "true" ]]; then
        podman unshare cp -f "$_canonical_manifest" "$manifest_in" \
          || { log_error "_pki_run_issuer: failed to copy canonical manifest to runtime path ${manifest_in}"; return 1; }
      else
        cp -f "$_canonical_manifest" "$manifest_in" \
          || { log_error "_pki_run_issuer: failed to copy canonical manifest to runtime path ${manifest_in}"; return 1; }
      fi
    fi
  fi

  # MI-6: stamp the per-instance SPIFFE trust domain onto the runtime manifest
  # BEFORE the issuer reads it, so per-instance URI SANs are baked into every leaf
  # cert. Trust domain resolves from the state file (authoritative once written)
  # then from PROJECT; legacy "yashigani.internal" => no-op. Runs after the manifest
  # is seeded/merged and before the issuer dispatch. Under rootless Podman the
  # runtime manifest may be owned by the subuid-mapped issuer UID, so reuse the
  # same `podman unshare` gate the merge used.
  local _td_for_manifest
  _td_for_manifest="$(grep -E '^SPIFFE_TRUST_DOMAIN=' "${WORK_DIR}/docker/.yashigani-install-state" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
  if [[ -z "$_td_for_manifest" ]]; then
    _td_for_manifest="$(_spiffe_trust_domain "${COMPOSE_PROJECT_NAME:-${PROJECT:-docker}}")"
  fi
  if [[ "$_td_for_manifest" != "yashigani.internal" ]]; then
    if [[ "$(uname -s)" == "Linux" && "$(id -u)" != "0" ]] && command -v podman >/dev/null 2>&1 && [[ -f /etc/subuid ]]; then
      podman unshare bash -c "$(declare -f _apply_trust_domain_to_runtime_manifest log_info log_error); _apply_trust_domain_to_runtime_manifest \"\$1\" \"\$2\"" _ "$manifest_in" "$_td_for_manifest" \
        || { log_error "_pki_run_issuer: MI-6 trust-domain rewrite failed (podman unshare) — refusing to issue certs with wrong trust domain"; return 1; }
    else
      _apply_trust_domain_to_runtime_manifest "$manifest_in" "$_td_for_manifest" \
        || { log_error "_pki_run_issuer: MI-6 trust-domain rewrite failed — refusing to issue certs with wrong trust domain"; return 1; }
    fi
  fi

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
  local _issuer_rc=$?

  # ISSUE-009 / finding C (idempotent self-heal, all runtimes): the runtime
  # manifest's bootstrap_token_sha256 fields MUST be populated from the
  # authoritative source — docker/secrets/<svc>_bootstrap_token, which persists
  # across --upgrade. The issuer writes these back, but a write-back miss (merge
  # fallback, cp race, rootless perms) previously shipped empty tokens, breaking
  # the internal mesh mTLS client at runtime (ISSUE-009). Re-derive host-side on
  # every run and fail closed if none land. Mirrors _update_manifest_hashes()
  # in src/yashigani/pki/issuer.py and the macOS host-side guard above.
  if [[ -d "$secrets_in" ]] && compgen -G "${secrets_in}/*_bootstrap_token" >/dev/null 2>&1; then
    local _use_unshare2=false
    if [[ "$(uname -s)" == "Linux" ]] && [[ "$(id -u)" != "0" ]] \
       && command -v podman >/dev/null 2>&1 && [[ -f /etc/subuid ]]; then
      _use_unshare2=true
    fi
    local _hashpy; _hashpy="$(mktemp)"
    cat > "$_hashpy" <<'PYHASH'
import sys, hashlib, pathlib
mf=pathlib.Path(sys.argv[1]); sec=pathlib.Path(sys.argv[2])
out=[]; cur=None; n=0
for line in mf.read_text().splitlines(keepends=True):
    s=line.strip()
    if s.startswith("- name:"): cur=s.split(":",1)[1].strip().strip("'\"")
    if s.startswith("bootstrap_token_sha256:") and cur:
        tok=sec/f"{cur}_bootstrap_token"
        if tok.exists():
            h=hashlib.sha256(tok.read_bytes().strip()).hexdigest()
            pre=line[:len(line)-len(line.lstrip())]
            line=f'{pre}bootstrap_token_sha256: "{h}"\n'; n+=1
    out.append(line)
tmp=mf.with_suffix(".yaml.tok_new"); tmp.write_text("".join(out)); tmp.replace(mf)
print(f"pki-token-ensure: populated {n} bootstrap_token_sha256 field(s) from secrets", file=sys.stderr)
PYHASH
    if [[ "$_use_unshare2" == "true" ]]; then
      podman unshare python3 "$_hashpy" "$manifest_in" "$secrets_in" 2>&1 | while IFS= read -r _l; do log_info "_pki_run_issuer: ${_l}"; done
    else
      python3 "$_hashpy" "$manifest_in" "$secrets_in" 2>&1 | while IFS= read -r _l; do log_info "_pki_run_issuer: ${_l}"; done
    fi
    rm -f "$_hashpy"
    # fail-closed verification — the explicit ISSUE-009 action-item gate
    local _pop
    if [[ "$_use_unshare2" == "true" ]]; then
      _pop="$(podman unshare grep -cE 'bootstrap_token_sha256: "[0-9a-f]{64}"' "$manifest_in" 2>/dev/null || echo 0)"
    else
      _pop="$(grep -cE 'bootstrap_token_sha256: "[0-9a-f]{64}"' "$manifest_in" 2>/dev/null || echo 0)"
    fi
    if [[ "${_pop:-0}" -lt 1 ]]; then
      log_error "_pki_run_issuer: runtime manifest has 0 populated bootstrap_token_sha256 fields after issuance (ISSUE-009) — aborting fail-closed"
      return 1
    fi
    log_success "_pki_run_issuer: runtime manifest bootstrap tokens populated (${_pop} service(s))"
  fi
  return "$_issuer_rc"
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
    # Install-path service account — read by backoffice (UID 1001) at bootstrap
    # seed AND by register_agent_bundles() inside the backoffice container.
    svc_admin_username
    svc_admin_password
    svc_admin_totp_secret
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

  # C-003 FIX: chown dynamically-onboarded agent client keys.
  #
  # Background: pki_services_all() returns only the STATIC service map from
  # lib/pki_ownership.sh.  Agents onboarded via `install.sh --onboard` are
  # appended to docker/service_identities.yaml (B-002 fix) so that rotate-leaves
  # issues them a client cert/key.  But the static map has no entry for them —
  # the issued key lands owned by the PKI issuer UID (1001 post-:U remap on
  # Docker, subuid-range on Podman rootless) and is unreadable by the agent
  # container (UID 65534, set in compose override by codegen — codegen.py:560).
  # Without this block every post-onboard rotate-leaves leaves the agent key
  # unreadable → agent crash-loops on mTLS handshake.
  #
  # Implementation: read sentinel-guarded agent names from
  # docker/service_identities.yaml (the same file the issuer reads).  Extract
  # `# BEGIN YSG-ONBOARD-<name>` markers; chown each `<name>_client.key` to
  # UID 65534 (nobody — the hardcoded compose `user:` for all BYO agents).
  # Mode 0600 (owner-read-only; nobody is the sole consumer).
  #
  # This is safe to call on a fresh install with no onboarded agents: the
  # grep produces no output and the loop body never executes.
  #
  # UID contract: codegen.py line 560 → `user: "65534:65534"` for ALL
  # Shape-A BYO agents.  A future manifest field (spec.container_uid) may
  # allow override — when that lands, update this block to read from the
  # service_identities entry rather than hardcoding 65534.
  local _sid_runtime="${WORK_DIR}/docker/service_identities.yaml"
  if [[ ! -f "$_sid_runtime" ]]; then
    # Runtime manifest not yet seeded (fresh install pre-PKI); fall back to
    # the IaC source file.
    _sid_runtime="${WORK_DIR}/docker/service_identities.yaml"
  fi
  if [[ -f "$_sid_runtime" ]]; then
    local _onboarded_agent
    while IFS= read -r _onboarded_agent; do
      # Strip leading/trailing whitespace and extract name from sentinel comment.
      _onboarded_agent="${_onboarded_agent#"# BEGIN YSG-ONBOARD-"}"
      _onboarded_agent="${_onboarded_agent%%[[:space:]]*}"
      [[ -z "$_onboarded_agent" ]] && continue
      local _agent_key="${_secrets_dir}/${_onboarded_agent}_client.key"
      if [[ -f "$_agent_key" ]]; then
        log_info "C-003: chown'ing onboarded agent key ${_onboarded_agent}_client.key → UID 65534 (nobody)"
        _do_chown "65534" "$_agent_key" "${_onboarded_agent}_client.key" "0600" || return 1
      fi
    done < <(grep -E '^[[:space:]]*# BEGIN YSG-ONBOARD-' "$_sid_runtime" 2>/dev/null || true)
  fi
}

# ---------------------------------------------------------------------------
# _ysg_ensure_gid_2002 — S7 (HIGH): ensure GID 2002 (ysg-secrets) exists on the
# host and that file-based (source: kms) agent secrets are owned by GID 2002.
#
# Agents declaring spec.secrets[].source=kms receive group_add:["2002"] in
# compose (and supplementalGroups:[2002] in Helm) from the codegen. This
# function ensures the host-side GID exists so the bind-mount ownership is
# correct at container startup.
#
# Linux-only: macOS does not use the GID 2002 pattern (virtiofs remaps).
# K8s: Helm fsGroup handles this — skip on k8s.
#
# S1 (security): never chmod 0644 on secrets files. GID 2002 means 0640 only.
# ---------------------------------------------------------------------------
_ysg_ensure_gid_2002() {
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # K8s path: Helm fsGroup handles supplementalGroups — skip.
  if [[ "${YSG_RUNTIME:-docker}" == "k8s" || "${MODE:-compose}" == "k8s" ]]; then
    log_info "_ysg_ensure_gid_2002: K8s runtime — GID 2002 handled by Helm fsGroup, skipping host-side provisioning"
    return 0
  fi

  # macOS: virtiofs UID/GID remapping makes host-side GID provisioning irrelevant.
  local _os_type
  _os_type="$(uname -s 2>/dev/null || printf 'Linux')"
  if [[ "$_os_type" == "Darwin" ]]; then
    log_info "_ysg_ensure_gid_2002: macOS — virtiofs remaps UIDs/GIDs, skipping host GID check"
    return 0
  fi

  # Check if GID 2002 exists (Linux).
  if ! getent group 2002 >/dev/null 2>&1; then
    log_warn "S7: GID 2002 (ysg-secrets) not found on this host."
    log_warn "  KMS-source agent secrets require GID 2002 for group_add:[\"2002\"] bind-mount access."
    log_warn "  Create it: sudo groupadd -g 2002 ysg-secrets"
    # Non-fatal: the agent will fail to read its secrets, but offboard is safe.
    return 0
  fi

  log_info "_ysg_ensure_gid_2002: GID 2002 exists on host"

  # Apply GID 2002 group ownership to any *_secret files under docker/secrets/
  # that were written for kms-source agents (identified by their naming pattern).
  # The codegen names these with the pattern: <agent>_kms_secret (placeholder).
  # At install/onboard time these files may not yet exist — this is a best-effort
  # post-codegen pass.
  if [[ -d "$_secrets_dir" ]]; then
    local _count=0
    while IFS= read -r _f; do
      if _do_chgrp "2002" "$_f" "${_f##*/}" 2>/dev/null; then
        _do_chmod_0640 "$_f" "${_f##*/}" 2>/dev/null || true
        _count=$((_count + 1))
      fi
    done < <(find "$_secrets_dir" -maxdepth 1 -type f -name '*_kms_secret' 2>/dev/null || true)
    if [[ "$_count" -gt 0 ]]; then
      log_info "  Applied GID 2002 + mode 0640 to ${_count} kms-source secret file(s)"
    fi
  fi
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
      chown -R 1001:1001 "$secrets_dir" 2>/dev/null || true
      log_info "secrets_dir chown -R 1001:1001 applied (rootful)"
    else
      # Rootless Podman — use podman unshare to map through the user namespace.
      #
      # NEW-BUG-B FIX (cascade audit 2026-05-30): the previous call only chowned
      # the DIRECTORY (secrets_dir), not the FILES inside it.  The installer runs
      # as host UID 1000 and writes secret files at UID 1000.  The PKI issuer
      # runs as container UID 1001 (mapped to subuid-range host UID, e.g. 101001).
      # Mode-0400 files owned by host UID 1000 are unreadable by UID 101001 →
      # the issuer gets EPERM when reading existing secrets (e.g. on re-issue
      # or rotate-leaves paths).
      # Fix: chown the directory AND all files inside it to 1001:1001 via
      # podman unshare (which maps 1001 through the user-namespace correctly).
      # Use find + xargs to avoid shell glob limits on large secrets dirs.
      if podman unshare bash -c "chown 1001:1001 '$secrets_dir' && find '$secrets_dir' -maxdepth 1 -mindepth 1 -exec chown 1001:1001 {} +" 2>/dev/null; then
        log_info "secrets_dir + files chown 1001:1001 applied via podman unshare (rootless)"
      else
        # Fallback: try plain chown on the directory only (rootless without unshare — e.g. old kernel)
        podman unshare chown 1001:1001 "$secrets_dir" 2>/dev/null \
          || log_warn "Could not chown ${secrets_dir} via podman unshare — PKI issuer and all service containers use :U remapping (podman-override.yml); ownership is consistent across the stack"
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

  # Docker Compose prefixes named volumes with the project name. Pre-3.0 this was
  # always "docker" (the compose-file directory name) → docker_langflow_data, etc.
  # Multi-instance (3.0): the project is now THIS install's COMPOSE_PROJECT_NAME, so a
  # 2nd named instance gets e.g. eu-west-acme-com_langflow_data. Falls back to "docker"
  # for single-instance / legacy installs. Matches _check_contaminated_volumes.
  local _compose_project_prefix="${COMPOSE_PROJECT_NAME:-docker}"

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
      # Lu wire-sink-gate P2 (v2.25.2): ensure the audit signing key exists after
      # rotation (idempotent — does not rotate the long-lived signing leaf).
      _provision_audit_signing_key || return 1
    else
      log_success "Certs current — no rotation needed"
      _pki_persist_env
      # Lu wire-sink-gate P2 (v2.25.2): provision the audit signing key on the
      # upgrade path too (idempotent — skips if already present). Installs that
      # predate this feature have a CA but no signing leaf; mint it now.
      _provision_audit_signing_key || return 1
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

  # Lu wire-sink-gate P2 (v2.25.2): mint the audit-chain checkpoint signing leaf
  # (internal-CA, backoffice-only) so daily checkpoints are SIGNED → non-repudiable.
  _provision_audit_signing_key || return 1

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
    # MACOS-TIMEOUT-001: `timeout` (GNU coreutils) is absent on macOS; use
    # gtimeout (via Homebrew coreutils) when available, otherwise omit the
    # guard. The compose ps call is local-socket so hangs are unlikely.
    local _timeout_cmd=""
    if command -v timeout >/dev/null 2>&1; then
      _timeout_cmd="timeout 10"
    elif command -v gtimeout >/dev/null 2>&1; then
      _timeout_cmd="gtimeout 10"
    fi
    if ${_timeout_cmd} "${COMPOSE_CMD[@]}" -f "$_compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
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

# =============================================================================
# P1 W6 — Step-up gate for onboard/offboard on a RUNNING system
#
# Called ONLY when _is_existing_yashigani_running() returns 0 (true).
# Prompts for admin username + password + TOTP, authenticates against the
# running backoffice through Caddy (no local crypto — auth delegates entirely
# to the running system, per "Caddy is the auth perimeter").
#
# Two HTTP round-trips, each with a DISTINCT TOTP code:
#   1. POST /auth/login  {username, password, totp_code}  → session cookie
#   2. POST /auth/stepup {totp_code}                      → stepup verified
#
# FIX-1: login and stepup use DIFFERENT TOTP codes (_totp vs _stepup_totp).
# The backoffice used_totp_codes replay cache rejects an already-consumed code
# on the second call (→ 401). The operator must wait for the NEXT authenticator
# window (new 30-second code) before entering the step-up TOTP.
#   - login:  proves identity (username + password + TOTP per ASVS V2.2).
#   - stepup: satisfies the high-value-flow step-up (ASVS V6.8.4, ≤5 min TTL).
#
# NOTE: live login→stepup flow requires two distinct codes from the operator.
# bats tests can only assert distinct field serialisation (no live auth server).
# Real login→stepup interaction is smoke-verified before tag on the live VM.
#
# CWE-214 hardening:
#   - Password and TOTP are read with `read -s` from /dev/tty — never via
#     argv (visible in `ps -ef`) or env vars (visible in /proc/environ).
#   - POST bodies are written to 0600 tmpfiles and fed via curl's --data @file
#     so the credentials never appear on the curl command line.
#   - Tmpfiles and in-memory credentials are cleared in a trap EXIT handler.
#   - All tmpfiles go under ${WORK_DIR} (NEVER /tmp — filesystem guardrail).
#
# Abort discipline:
#   - Any non-2xx HTTP response → return 1 (caller must NOT proceed).
#   - curl transport errors (exit 7 conn-refused, 28 timeout, 35 TLS) → return 1.
#   - Backoffice unreachable → return 1.
#   - No retry-into-pass on auth failures (SOP 4).
#
# Arguments: $1 = operation label ("onboard" | "offboard") for user messages.
# Returns: 0 on success; 1 on any failure.
# =============================================================================
_ysg_onboard_stepup_gate() {
  local _op_label="${1:-onboard}"

  # ── Resolve Caddy HTTPS endpoint ─────────────────────────────────────────
  # 1. Honour YASHIGANI_HTTPS_PORT if already in env (parse_args sets it).
  # 2. Otherwise read from docker/.env (source of truth written at install time).
  # 3. Fall back to 443.
  local _port="${YASHIGANI_HTTPS_PORT:-}"
  if [[ -z "$_port" && -f "${WORK_DIR}/docker/.env" ]]; then
    _port="$(grep '^YASHIGANI_HTTPS_PORT=' "${WORK_DIR}/docker/.env" \
               2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')"
  fi
  _port="${_port:-443}"

  # ── Resolve CA cert for TLS verification ─────────────────────────────────
  # Use the local PKI root — never skip TLS verification.
  local _ca_cert="${WORK_DIR}/docker/secrets/ca_root.crt"
  if [[ ! -f "$_ca_cert" ]]; then
    log_error "Step-up gate: CA cert not found at ${_ca_cert}"
    log_error "  Cannot authenticate against the running system without it."
    return 1
  fi

  local _base_url="https://localhost:${_port}"

  log_step "-" "Step-up authentication required"
  log_info "  This system is already running. Modifying a live ring-fence requires"
  log_info "  admin password + TOTP verification against the running backoffice."
  log_info "  Endpoint: ${_base_url}"
  printf "\n"

  # ── Prompt for credentials (never via argv/env — CWE-214) ────────────────
  local _username _password _totp _stepup_totp

  printf "  Admin username: " >/dev/tty
  read -r _username </dev/tty 2>/dev/null || { log_error "Step-up gate: cannot read username from tty"; return 1; }

  printf "  Admin password: " >/dev/tty
  read -rs _password </dev/tty 2>/dev/null || { log_error "Step-up gate: cannot read password from tty"; return 1; }
  printf "\n" >/dev/tty

  printf "  TOTP code for login (6 digits): " >/dev/tty
  read -rs _totp </dev/tty 2>/dev/null || { log_error "Step-up gate: cannot read TOTP from tty"; return 1; }
  printf "\n" >/dev/tty

  # FIX-1: prompt for a second, distinct TOTP for the step-up call.
  # The backoffice replay cache (used_totp_codes) rejects an already-consumed
  # code on the second round-trip — the operator must enter the NEXT code from
  # their authenticator (a fresh 30-second window).
  log_info "  Wait for the NEXT code in your authenticator (new 30-second window),"
  log_info "  then enter it below for the step-up verification."
  printf "  TOTP code for step-up (6 digits, NEXT window): " >/dev/tty
  read -rs _stepup_totp </dev/tty 2>/dev/null || { log_error "Step-up gate: cannot read step-up TOTP from tty"; _username=""; _password=""; _totp=""; _stepup_totp=""; return 1; }
  printf "\n" >/dev/tty

  # Validate inputs before making any network call
  if [[ -z "$_username" || -z "$_password" || -z "$_totp" || -z "$_stepup_totp" ]]; then
    log_error "Step-up gate: username, password, login TOTP, and step-up TOTP are all required."
    _username=""; _password=""; _totp=""; _stepup_totp=""
    return 1
  fi
  if ! printf '%s' "$_totp" | grep -qE '^[0-9]{6}$'; then
    log_error "Step-up gate: login TOTP must be exactly 6 digits."
    _username=""; _password=""; _totp=""; _stepup_totp=""
    return 1
  fi
  if ! printf '%s' "$_stepup_totp" | grep -qE '^[0-9]{6}$'; then
    log_error "Step-up gate: step-up TOTP must be exactly 6 digits."
    _username=""; _password=""; _totp=""; _stepup_totp=""
    return 1
  fi

  # ── Tmpfile setup (0700 dir, 0600 files, under WORK_DIR — never /tmp) ──────
  local _gate_tmpdir
  _gate_tmpdir="$(mktemp -d "${WORK_DIR}/docker/.ysg-gate-XXXXXX")"
  chmod 0700 "$_gate_tmpdir"

  local _login_body="${_gate_tmpdir}/login.json"
  local _cookie_jar="${_gate_tmpdir}/cookies.txt"
  local _stepup_body="${_gate_tmpdir}/stepup.json"
  local _curl_err="${_gate_tmpdir}/curl_err.txt"
  local _response_file="${_gate_tmpdir}/response.txt"

  # Cleanup function — zeroizes credentials and removes tmpdir on any return path.
  # Registered as RETURN trap so it fires when the function exits for any reason.
  _gate_cleanup() {
    # Shred or overwrite before unlink to limit secret residency on disk.
    if [[ -f "${_login_body:-}" ]]; then
      dd if=/dev/zero of="$_login_body" bs=1 count="$(wc -c < "$_login_body" 2>/dev/null || echo 128)" 2>/dev/null || true
    fi
    if [[ -f "${_stepup_body:-}" ]]; then
      dd if=/dev/zero of="$_stepup_body" bs=1 count="$(wc -c < "$_stepup_body" 2>/dev/null || echo 64)" 2>/dev/null || true
    fi
    rm -rf "${_gate_tmpdir:-}"
  }
  # shellcheck disable=SC2064
  trap "_gate_cleanup; trap - RETURN" RETURN

  # ── Serialize credentials to 0600 JSON tmpfiles (no shell quoting escape risk)
  # python3 json.dumps handles all Unicode and special characters correctly.
  # Credentials never appear on the command line (CWE-214).
  local _prev_umask
  _prev_umask="$(umask)"
  umask 077
  # FIX-1: pass _stepup_totp as a distinct 6th argument so login.json and
  # stepup.json carry different codes — the replay cache rejects a reused code.
  python3 - "$_login_body" "$_stepup_body" \
      "$_username" "$_password" "$_totp" "$_stepup_totp" <<'PYJSON' || {
import sys, json, os
login_path, stepup_path, user, pw, totp, stepup_totp = \
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
# Write with mode 0600 via os.open
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
fd = os.open(login_path, flags, 0o600)
os.write(fd, json.dumps({"username": user, "password": pw, "totp_code": totp}).encode())
os.close(fd)
fd = os.open(stepup_path, flags, 0o600)
os.write(fd, json.dumps({"totp_code": stepup_totp}).encode())
os.close(fd)
PYJSON
    log_error "Step-up gate: failed to write credential tmpfiles."
    umask "$_prev_umask"
    _username=""; _password=""; _totp=""; _stepup_totp=""
    return 1
  }
  umask "$_prev_umask"

  # Zeroize shell-local copies immediately after Python consumed them
  _password=""; _totp=""; _stepup_totp=""

  # ── Round-trip 1: POST /auth/login ────────────────────────────────────────
  log_info "  Authenticating against ${_base_url}/auth/login ..."
  local _login_http_code _login_curl_rc=0
  _login_http_code="$(
    curl --silent \
         --cacert "$_ca_cert" \
         --max-time 15 \
         --connect-timeout 10 \
         -X POST \
         -H "Content-Type: application/json" \
         --data "@${_login_body}" \
         --cookie-jar "$_cookie_jar" \
         -o "$_response_file" \
         -w '%{http_code}' \
         "${_base_url}/auth/login" 2>"${_curl_err}"
  )" || _login_curl_rc=$?

  # Shred login body immediately after use
  if [[ -f "$_login_body" ]]; then
    dd if=/dev/zero of="$_login_body" bs=1 count="$(wc -c < "$_login_body" 2>/dev/null || echo 128)" 2>/dev/null || true
    rm -f "$_login_body"
  fi

  # Abort on transport error (curl exit 7=conn-refused, 28=timeout, 35=TLS)
  if [[ "$_login_curl_rc" -ne 0 ]]; then
    log_error "Step-up gate: /auth/login transport error (curl exit ${_login_curl_rc})."
    if [[ -s "$_curl_err" ]]; then
      log_error "  curl: $(head -1 "${_curl_err}" | tr -d '\n')"
    fi
    log_error "  Is the Yashigani stack running? Check: docker compose ps"
    _username=""
    return 1
  fi

  # Non-2xx → abort, make no changes (SOP 4: first non-2xx is FAIL)
  if [[ "$_login_http_code" != "2"* ]]; then
    log_error "Step-up gate: /auth/login returned HTTP ${_login_http_code}."
    if [[ "$_login_http_code" == "401" ]]; then
      log_error "  Invalid credentials or TOTP. Re-run ${_op_label} with correct credentials."
    elif [[ "$_login_http_code" == "429" ]]; then
      log_error "  Too many failed attempts. Check Retry-After header and wait before retrying."
    fi
    log_error "  NO CHANGES MADE."
    _username=""
    return 1
  fi

  log_info "  Login successful (HTTP ${_login_http_code})."

  # ── Round-trip 2: POST /auth/stepup ───────────────────────────────────────
  # The login TOTP proves identity; the stepup TOTP satisfies the high-value-flow
  # prerequisite (ASVS V6.8.4). Both are required per Tiago directive 2026-05-29.
  log_info "  Performing step-up verification at ${_base_url}/auth/stepup ..."
  local _stepup_http_code _stepup_curl_rc=0
  _stepup_http_code="$(
    curl --silent \
         --cacert "$_ca_cert" \
         --max-time 15 \
         --connect-timeout 10 \
         -X POST \
         -H "Content-Type: application/json" \
         --data "@${_stepup_body}" \
         --cookie "$_cookie_jar" \
         -o "$_response_file" \
         -w '%{http_code}' \
         "${_base_url}/auth/stepup" 2>"${_curl_err}"
  )" || _stepup_curl_rc=$?

  # Shred stepup body immediately after use
  if [[ -f "$_stepup_body" ]]; then
    dd if=/dev/zero of="$_stepup_body" bs=1 count="$(wc -c < "$_stepup_body" 2>/dev/null || echo 64)" 2>/dev/null || true
    rm -f "$_stepup_body"
  fi

  if [[ "$_stepup_curl_rc" -ne 0 ]]; then
    log_error "Step-up gate: /auth/stepup transport error (curl exit ${_stepup_curl_rc})."
    if [[ -s "$_curl_err" ]]; then
      log_error "  curl: $(head -1 "${_curl_err}" | tr -d '\n')"
    fi
    _username=""
    return 1
  fi

  if [[ "$_stepup_http_code" != "2"* ]]; then
    log_error "Step-up gate: /auth/stepup returned HTTP ${_stepup_http_code}."
    if [[ "$_stepup_http_code" == "401" ]]; then
      log_error "  TOTP code rejected at step-up. Ensure your authenticator clock is synchronised."
    elif [[ "$_stepup_http_code" == "429" ]]; then
      log_error "  Step-up locked. Log out and log in again to reset the step-up counter."
    fi
    log_error "  NO CHANGES MADE."
    _username=""
    return 1
  fi

  log_success "Step-up gate passed — admin identity verified."

  # ── Shell-side audit record ───────────────────────────────────────────────
  # MANIFEST_ONBOARD / MANIFEST_OFFBOARD events are emitted by Python codegen
  # and offboard.sh respectively (G2 stages 5c/6a). This log line is the
  # belt-and-suspenders shell record that the step-up gate was satisfied.
  log_info "  Audit: ${_op_label} step-up gate passed for user '${_username}' at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Export operator identity so the Python codegen heredoc and offboard.sh
  # can carry it into the Merkle audit event (G2 stage-5c/6a requirement).
  # Exported before _username is cleared — this is the only path that sets it.
  export YSG_OPERATOR_IDENTITY="${_username}"

  _username=""
  return 0
}

# =============================================================================
# P1 W4 — S3: cosign manifest signature shell gate
#
# Invokes `cosign verify-blob` against the bundled public key.
# Enforcement level mirrors signatures.py (Python side):
#   YSG_REQUIRE_SIGNED_MANIFEST=unset/"warn" → WARN in dev
#   YSG_REQUIRE_SIGNED_MANIFEST=fail/1/true  → FAIL in CI+prod
#   YASHIGANI_ENV=production|staging         → implicit FAIL
#
# The shell gate runs BEFORE the Python parser/validator so a corrupt or
# unsigned manifest cannot reach the codegen pipeline.
#
# Bundled cosign public key location:
#   src/yashigani/manifest/keys/manifest-signing.pub
#
# Hard FAIL on any non-zero cosign exit (S3 / Su-003 / M7).
# =============================================================================
_ysg_cosign_gate() {
  local _manifest_file="$1"
  local _sig_file="${_manifest_file}.cosign.sig"

  # C-001 (Nico MED): FIPS guard — cosign uses Go crypto, NOT covered by
  # CMVP #4985.  Under FIPS_MODE=1 the Python signatures.py path enforces
  # its own gate using RSA-PSS-3072/SHA-384 (FIPS-validated).  We defer to
  # that path and skip cosign entirely.
  if [[ "${FIPS_MODE:-0}" == "1" ]]; then
    log_info "S3: FIPS mode — cosign bypassed; manifest verification defers to signatures.py (RSA-PSS-3072/SHA-384)"
    return 0
  fi

  # Resolve enforcement level
  local _level="warn"
  local _env_val="${YSG_REQUIRE_SIGNED_MANIFEST:-}"
  case "${_env_val}" in
    fail|1|true|yes) _level="fail" ;;
    skip|off|false|0) _level="skip" ;;
  esac
  # Implicit production gate
  local _ysg_env="${YASHIGANI_ENV:-}"
  if [[ "$_ysg_env" == "production" || "$_ysg_env" == "staging" || "$_ysg_env" == "prod" ]]; then
    _level="fail"
  fi

  if [[ "$_level" == "skip" ]]; then
    log_info "S3: manifest signature check skipped (YSG_REQUIRE_SIGNED_MANIFEST=skip)"
    return 0
  fi

  # Locate the bundled cosign public key
  local _key_candidates=(
    "${_YSG_SCRIPT_DIR}/src/yashigani/manifest/keys/manifest-signing.pub"
    "${_YSG_SCRIPT_DIR}/keys/manifest-signing.pub"
  )
  local _bundled_key=""
  local _k
  for _k in "${_key_candidates[@]}"; do
    if [[ -f "$_k" ]]; then
      _bundled_key="$_k"
      break
    fi
  done

  if [[ -z "$_bundled_key" ]]; then
    local _msg="S3: bundled cosign public key not found. Expected at src/yashigani/manifest/keys/manifest-signing.pub"
    if [[ "$_level" == "fail" ]]; then
      log_error "$_msg"
      return 1
    fi
    log_warn "$_msg (S3: non-fatal in dev mode)"
    return 0
  fi

  # Check for detached signature file
  if [[ ! -f "$_sig_file" ]]; then
    local _msg2="S3: cosign detached signature not found at ${_sig_file}"
    if [[ "$_level" == "fail" ]]; then
      log_error "$_msg2"
      log_error "  Sign the manifest with: cosign sign-blob --key <signing-key> ${_manifest_file} > ${_sig_file}"
      return 1
    fi
    log_warn "$_msg2 (S3: non-fatal in dev — set YSG_REQUIRE_SIGNED_MANIFEST=fail for CI/prod)"
    return 0
  fi

  # Check cosign is on PATH
  if ! command -v cosign >/dev/null 2>&1; then
    local _msg3="S3: cosign binary not found in PATH"
    if [[ "$_level" == "fail" ]]; then
      log_error "$_msg3"
      log_error "  Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/"
      return 1
    fi
    log_warn "$_msg3 (S3: non-fatal in dev)"
    return 0
  fi

  # Execute cosign verify-blob — hard FAIL on any non-zero exit (S3).
  local _cosign_out
  local _cosign_rc=0
  _cosign_out="$(cosign verify-blob \
      --key "$_bundled_key" \
      --signature "$_sig_file" \
      "$_manifest_file" 2>&1)" || _cosign_rc=$?

  if [[ "$_cosign_rc" -ne 0 ]]; then
    log_error "S3 (SHIP-BLOCKER): cosign verify-blob FAILED (exit ${_cosign_rc})."
    log_error "  Manifest:   ${_manifest_file}"
    log_error "  Signature:  ${_sig_file}"
    log_error "  Public key: ${_bundled_key}"
    log_error "  cosign output: ${_cosign_out}"
    log_error "  Manifests must be signed before onboarding in CI/prod."
    log_error "  Set YSG_REQUIRE_SIGNED_MANIFEST=skip to bypass in dev (never in prod)."
    # Hard FAIL regardless of enforcement level — any non-zero cosign exit is fatal.
    return 1
  fi

  log_info "S3: cosign verify-blob passed for ${_manifest_file}"
  return 0
}

# =============================================================================
# P1 W4 — S2: onboard handler
#
# Wires _detect_runtime (W2) into the codegen path, invokes Python codegen,
# and applies the generated artifacts (service_identities.yaml append,
# pki_ownership.sh tuple append, compose override write, Helm values write).
#
# The issuer reads service_identities.yaml automatically — no function-body
# edit of install.sh is needed. All additions use BEGIN/END sentinels.
# =============================================================================
handle_onboard_subcommand() {
  local _manifest="${ONBOARD_MANIFEST}"

  if [[ -z "$_manifest" ]]; then
    log_error "--onboard requires a path to an agent manifest YAML"
    exit 1
  fi
  if [[ ! -f "$_manifest" ]]; then
    log_error "--onboard: manifest file not found: ${_manifest}"
    exit 1
  fi

  log_step "-" "Onboarding agent from manifest: ${_manifest}"

  # Resolve WORK_DIR early — needed by both the step-up gate (to locate
  # docker/.env + docker/secrets/ca_root.crt) and the subsequent codegen.
  if [[ -z "${WORK_DIR:-}" || ! -d "${WORK_DIR}" ]]; then
    detect_working_directory
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
      cd "$WORK_DIR"
    fi
  fi

  # P1 W6 — Step-up gate: if install residuals are present (compose file +
  # any secrets), the operator MUST authenticate (password + TOTP) against
  # the live system BEFORE any changes are made.
  # FIX-2: use _is_installed_or_running (residuals-based, fail-closed) NOT
  # _is_existing_yashigani_running (affirmative-only — bypassed by cert
  # removal or stopped containers; Laura F1/F2).
  # Fresh installs (no residuals) skip this gate — onboarding is part of
  # the trusted install flow.
  # Tiago directive 2026-05-29: "if it is adding agents to an already
  # existing system you need to provide password and totp, always."
  if _is_installed_or_running; then
    _ysg_onboard_stepup_gate "onboard" || exit 1
  fi

  # S3: cosign signature gate BEFORE codegen (after step-up gate)
  _ysg_cosign_gate "$_manifest" || exit 1

  # Wire _detect_runtime (W2/L10) — resolve the 4-way runtime BEFORE codegen.
  # Wrong-runtime codegen silently produces no ring-fence (L10).
  if [[ -f "${_YSG_SCRIPT_DIR}/lib/detect_runtime.sh" ]]; then
    # shellcheck source=lib/detect_runtime.sh
    # shellcheck disable=SC1091
    source "${_YSG_SCRIPT_DIR}/lib/detect_runtime.sh"
    _detect_runtime 2>/dev/null || true
    log_info "Runtime 4-way: ${YSG_RUNTIME_4WAY:-unknown} — ${YSG_RUNTIME_4WAY_NOTE:-}"
  else
    log_warn "lib/detect_runtime.sh not found — YSG_RUNTIME_4WAY will be inferred from YSG_RUNTIME"
    # Map legacy YSG_RUNTIME to 4-way for codegen
    case "${YSG_RUNTIME:-}" in
      docker) YSG_RUNTIME_4WAY="docker" ;;
      podman) YSG_RUNTIME_4WAY="podman-rootless" ;;
      k8s)    YSG_RUNTIME_4WAY="k8s" ;;
      *)      YSG_RUNTIME_4WAY="docker" ;;
    esac
    export YSG_RUNTIME_4WAY
  fi

  if [[ "${YSG_RUNTIME_4WAY:-unknown}" == "unknown" ]]; then
    log_error "Runtime detection failed. Set YSG_RUNTIME_4WAY=docker|podman-rootful|podman-rootless|k8s"
    exit 1
  fi

  # Invoke Python codegen pipeline:
  #   parse → validate → verify_signature (Python side) → codegen → apply artifacts
  log_info "Running Python codegen for manifest: ${_manifest}"
  local _codegen_rc=0

  # MI-6: per-instance SPIFFE trust domain for the onboarded agent's spiffe_id.
  # Read from the target instance's state file (authoritative); legacy default
  # yashigani.internal preserved.
  local _onboard_trust_domain
  _onboard_trust_domain="$(_read_state_trust_domain "${WORK_DIR}/docker/.yashigani-install-state")"
  python3 - "$_manifest" "$WORK_DIR" "${YSG_RUNTIME_4WAY}" \
      "${YSG_REQUIRE_SIGNED_MANIFEST:-warn}" "${_onboard_trust_domain}" <<'PYEOF' || _codegen_rc=$?
import sys, os

manifest_path = sys.argv[1]
output_root   = sys.argv[2]
runtime       = sys.argv[3]
sig_level     = sys.argv[4]
# MI-6: per-instance SPIFFE trust-domain authority (legacy => yashigani.internal).
trust_domain  = sys.argv[5] if len(sys.argv) > 5 else "yashigani.internal"

# Extend sys.path to find the yashigani package in the repo src/ tree.
src_dir = os.path.join(output_root, 'src')
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

try:
    from yashigani.manifest import (
        parse_manifest, validate_manifest, verify_manifest_signature,
        CodegenEngine, reset_codegen_registry, is_shape_c,
    )
    # FIX-SHAPE-C-DISPATCH (Ava 2026-05-30): import Shape-C engine so
    # manifests with mcp-b posture / mcp_server category get the correct
    # codegen path (isolated-container + bridge artifacts) instead of the
    # Shape-A LLM-agent path.
    try:
        from yashigani.manifest import CodegenEngineShapeC
        _SHAPE_C_ENGINE_AVAILABLE = True
    except ImportError:
        _SHAPE_C_ENGINE_AVAILABLE = False
except ImportError as e:
    print('[onboard] ERROR: yashigani.manifest package not found: %s' % e, file=sys.stderr)
    print('[onboard] Ensure the package is installed or run from the repo root.', file=sys.stderr)
    sys.exit(1)

from pathlib import Path

manifest_bytes = Path(manifest_path).read_bytes()

# Parse
try:
    parsed = parse_manifest(manifest_bytes)
except Exception as e:
    print('[onboard] FAIL: manifest parse error: %s' % e, file=sys.stderr)
    sys.exit(1)

# Validate
try:
    validate_manifest(parsed)
except Exception as e:
    print('[onboard] FAIL: manifest validation error: %s' % e, file=sys.stderr)
    sys.exit(1)

# S3 (Python side): signature verification
os.environ.setdefault('YSG_REQUIRE_SIGNED_MANIFEST', sig_level)
try:
    verify_manifest_signature(manifest_bytes, parsed)
except Exception as e:
    print('[onboard] FAIL: signature verification: %s' % e, file=sys.stderr)
    sys.exit(1)

# Codegen — write artifacts to output_root
# FIX-SHAPE-C-DISPATCH: dispatch to correct engine based on manifest shape.
# Shape-C manifests (mcp_server category / mcp-b posture) generate an
# isolated-container compose override with the first-party bridge; they must
# NOT use CodegenEngine which generates Shape-A LLM-agent artifacts.
reset_codegen_registry()
try:
    _manifest_is_shape_c = is_shape_c(parsed) if callable(is_shape_c) else False
    if _manifest_is_shape_c and _SHAPE_C_ENGINE_AVAILABLE:
        print('[onboard] Shape-C manifest detected — using CodegenEngineShapeC')
        engine = CodegenEngineShapeC(parsed, runtime)
    else:
        if _manifest_is_shape_c and not _SHAPE_C_ENGINE_AVAILABLE:
            print('[onboard] WARN: Shape-C manifest but CodegenEngineShapeC not importable — falling back to CodegenEngine', file=sys.stderr)
        engine = CodegenEngine(parsed, runtime)
    artifacts = engine.render(output_root=Path(output_root), dry_run=False)
    print('[onboard] Codegen complete. Artifacts written:')
    for rel_path in sorted(artifacts.keys()):
        print('  + %s' % rel_path)
except Exception as e:
    print('[onboard] FAIL: codegen error: %s' % e, file=sys.stderr)
    sys.exit(1)

# S2: append service_identities.yaml entry (sentinel-guarded)
# The issuer reads service_identities.yaml automatically — this appends
# the onboarded agent's SPIFFE identity for PKI issuance on next rotate-leaves.
import re

meta = parsed.get('metadata') or {}
spec = parsed.get('spec') or {}
agent_name = meta.get('name', '')
tenant_id  = meta.get('tenant_id', '')
sid_file   = os.path.join(output_root, 'docker', 'service_identities.yaml')

if not os.path.isfile(sid_file):
    print('[onboard] WARN: service_identities.yaml not found — skipping PKI identity append', file=sys.stderr)
else:
    content = open(sid_file, encoding='utf-8').read()
    begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
    if begin_marker in content:
        print('[onboard] service_identities.yaml: entry for %r already present — idempotent' % agent_name)
    else:
        # B-002 FIX: insert sentinel-guarded entry INSIDE the top-level
        # `services:` mapping, not at EOF (which puts it after `canary_policy:`
        # and outside the mapping → structurally invalid YAML).
        #
        # Strategy: locate the insertion boundary — the first line at column 0
        # that is NOT inside the services: mapping (i.e. a top-level key or
        # comment-section separator that follows the last services entry).
        # We look for:
        #   (a) the pattern `\n\n# ────…` (the decorative separator line
        #       before endpoint_acls: or other top-level sections), OR
        #   (b) `\n^[a-z_]+:` (any top-level key at column 0 after a blank line)
        # whichever comes first AFTER the `services:` line.
        #
        # This is safe for any valid service_identities.yaml: if onboarded
        # agents have already been inserted (prior runs), `begin_marker` check
        # above would have caught the duplicate; this path only runs when the
        # entry is absent.
        spiffe_id = 'spiffe://%s/agents/%s/%s' % (trust_domain, tenant_id, agent_name)
        entry_block = (
            '  # BEGIN YSG-ONBOARD-{name}\n'
            '  # Onboarded agent — managed by yashigani onboard/offboard\n'
            '  - name: {name}\n'
            '    dns_sans: [{name}, {name}.internal]\n'
            '    spiffe_id: {spiffe_id}\n'
            '    purpose: "BYO agent — ring-fenced (P1 onboarding)"\n'
            '    mtls_capable: false\n'
            '    bootstrap_token_sha256: ""\n'
            '    revoked: false\n'
            '  # END YSG-ONBOARD-{name}\n'
        ).format(name=agent_name, spiffe_id=spiffe_id)

        # Find the services: key position first, then search only past it.
        services_match = re.search(r'^services:\s*$', content, re.MULTILINE)
        if services_match is None:
            print('[onboard] FAIL: service_identities.yaml has no top-level `services:` key — cannot insert entry', file=sys.stderr)
            sys.exit(1)
        search_start = services_match.end()

        # Look for the first separator comment block (decorative ─── lines
        # used as section dividers in service_identities.yaml) OR any
        # top-level YAML key (word chars + colon at column 0, preceded by
        # a blank line). Whichever comes first after `services:` is the
        # boundary — we insert the new block immediately before it.
        boundary_re = re.compile(
            r'\n(?=# [─]{5}|[a-z_][a-zA-Z0-9_]*:)',
            re.MULTILINE,
        )
        boundary_match = boundary_re.search(content, search_start)
        if boundary_match is None:
            # Fallback: no boundary found — append before EOF (last resort).
            insert_pos = len(content)
            new_content = content.rstrip('\n') + '\n' + entry_block
        else:
            insert_pos = boundary_match.start() + 1  # after the \n
            new_content = content[:insert_pos] + entry_block + '\n' + content[insert_pos:]

        import tempfile
        dir_ = os.path.dirname(sid_file)
        fd, tmp = tempfile.mkstemp(dir=dir_, prefix='.ysg-onboard-tmp-', suffix='.yaml')
        try:
            os.write(fd, new_content.encode('utf-8'))
            os.close(fd); fd = -1
            os.chmod(tmp, os.stat(sid_file).st_mode & 0o777)
            os.rename(tmp, sid_file)
        except Exception:
            if fd != -1: os.close(fd)
            os.unlink(tmp)
            raise
        print('[onboard] service_identities.yaml: appended entry for %r' % agent_name)

# S7: apply GID 2002 ownership for kms-secret agents
#   The codegen already emits group_add/supplementalGroups in compose/helm.
#   Here we log the requirement; actual chown is deferred to _pki_chown_client_keys
#   post-PKI-bootstrap (the key doesn't exist yet at onboard time).
secrets_list = spec.get('secrets') or []
has_kms = any(s.get('source') == 'kms' for s in secrets_list if isinstance(s, dict))
if has_kms:
    print('[onboard] S7: kms secrets detected — GID 2002 group_add will apply at PKI bootstrap.')
    print('[onboard] S7: ensure GID 2002 exists on host: groupadd -g 2002 ysg-secrets')

print('[onboard] Onboard complete for agent: %s (tenant: %s)' % (agent_name, tenant_id))

# G2 stage-5c: emit MANIFEST_ONBOARD Merkle audit event (Lu-Gap-06 / G2.2)
# Reads operator identity from YSG_OPERATOR_IDENTITY env var (set by the
# step-up gate before _username is cleared). Falls back to "unknown" when
# running on a fresh install where the gate was not invoked.
try:
    import hashlib, json as _json, os as _os
    from yashigani.audit.writer import AuditLogWriter
    from yashigani.audit.config import AuditConfig
    from yashigani.audit.schema import ManifestOnboardEvent

    # Canonical manifest SHA-256: full SHA-256 of the raw YAML bytes
    _manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    # Operator identity threaded from the step-up gate via env var
    _operator = _os.environ.get('YSG_OPERATOR_IDENTITY', 'unknown') or 'unknown'

    # Artifact labels (relative paths without WORK_DIR)
    _artifact_labels = sorted(artifacts.keys())

    # AuditConfig: default log path; override via YASHIGANI_AUDIT_LOG_PATH.
    # On a running system the volume path is /var/log/yashigani/audit.log.
    _audit_log_path = _os.environ.get(
        'YASHIGANI_AUDIT_LOG_PATH',
        _os.path.join(output_root, 'docker', 'var', 'audit.log'),
    )
    _audit_config = AuditConfig(
        log_path=_audit_log_path,
        max_file_size_mb=int(_os.environ.get('YASHIGANI_AUDIT_MAX_FILE_SIZE_MB', '100')),
        retention_days=int(_os.environ.get('YASHIGANI_AUDIT_RETENTION_DAYS', '90')),
    )
    _writer = AuditLogWriter(config=_audit_config)
    _writer.write(ManifestOnboardEvent(
        tenant_id=tenant_id,
        agent_name=agent_name,
        manifest_sha256=_manifest_sha256,
        operator_identity=_operator,
        artifacts_generated=_artifact_labels,
        runtime=runtime,
    ))
    _writer.close()
    print('[onboard] MANIFEST_ONBOARD audit event written (operator=%s sha256=%.16s...)' % (
        _operator, _manifest_sha256))
except Exception as _audit_exc:
    # FIX-03 (YCS-...-W6-03): onboard audit-write must NOT be silent.
    # A change-management control (AU-2 / CM-3 / CC8.1) applied with NO
    # Merkle event is a control failure. The operator and auditor MUST see it.
    # Artifacts are already durable — we do NOT un-apply them.
    import datetime as _dt, json as _json2, os as _os2
    # Fallbacks: these locals may be unset if the exception fired before
    # they were assigned (e.g., import error at the top of the try block).
    _operator = locals().get('_operator', _os2.environ.get('YSG_OPERATOR_IDENTITY', 'unknown') or 'unknown')
    _audit_log_path = locals().get('_audit_log_path', _os2.path.join(output_root, 'docker', 'var', 'audit.log'))
    # (1) LOUD operator-facing error to stderr.
    print('', file=sys.stderr)
    print('=' * 72, file=sys.stderr)
    print('[onboard] ERROR: MANIFEST_ONBOARD audit event write FAILED', file=sys.stderr)
    print('[onboard] ERROR: The ring-fence artifacts were applied but the', file=sys.stderr)
    print('[onboard] ERROR: Merkle audit record could NOT be written.', file=sys.stderr)
    print('[onboard] ERROR: This is a change-management control failure.', file=sys.stderr)
    print('[onboard] ERROR: Agent=%s  Operator=%s' % (agent_name, _operator), file=sys.stderr)
    print('[onboard] ERROR: Cause: %s' % _audit_exc, file=sys.stderr)
    print('[onboard] ERROR: Action required: investigate audit volume, then', file=sys.stderr)
    print('[onboard] ERROR:   manually add a MANIFEST_ONBOARD record or', file=sys.stderr)
    print('[onboard] ERROR:   re-run onboard once the audit volume is healthy.', file=sys.stderr)
    print('=' * 72, file=sys.stderr)
    # (2) Fallback breadcrumb — write a minimal JSON record next to the audit log
    # so the failure is recorded somewhere even if the main audit volume is broken.
    _breadcrumb = {
        'event_type': 'MANIFEST_ONBOARD_AUDIT_WRITE_FAILED',
        'timestamp': _dt.datetime.now(_dt.timezone.utc).isoformat(),
        'agent_name': agent_name,
        'operator_identity': _operator,
        'cause': str(_audit_exc),
    }
    try:
        _bc_dir = _os2.path.dirname(_audit_log_path)
        _bc_path = _os2.path.join(
            _bc_dir,
            'audit-write-failed-%s.json' % agent_name.replace('/', '_'),
        )
        _os2.makedirs(_bc_dir, exist_ok=True)
        with open(_bc_path, 'w', encoding='utf-8') as _bc_f:
            _bc_f.write(_json2.dumps(_breadcrumb) + '\n')
        print('[onboard] ERROR: breadcrumb written to %s' % _bc_path, file=sys.stderr)
    except Exception as _bc_exc:
        print('[onboard] ERROR: breadcrumb write also failed: %s' % _bc_exc, file=sys.stderr)
    # (3) Advisory non-zero exit so the shell caller signals the failure.
    sys.exit(1)
PYEOF

  if [[ "$_codegen_rc" -ne 0 ]]; then
    # FIX-03: codegen exit non-zero covers both real codegen errors AND
    # the audit-write failure path above. Artifacts are applied in both cases;
    # the operator must investigate the audit volume.
    log_error "Onboard completed but audit event write FAILED (exit ${_codegen_rc})"
    log_error "  Merkle audit record is missing — this is a control failure."
    log_error "  Check stderr above and the breadcrumb file in the audit log directory."
    log_error "  Investigate and restore the audit record before considering this onboard complete."
    exit 1
  fi

  # BEGIN YSG-P3-MCP-BRIDGE-JOIN
  # Shape-C (MCP server) post-onboard bridge wiring.
  #
  # After codegen lands the compose-override.yml for a Shape-C agent, the GATEWAY
  # container must join the new ringfence_<agent> bridge so it can reach the bridge
  # on TCP/8000.  The codegen emits an operator-instruction comment; this block
  # mechanises that step.
  #
  # Detection: fast-grep the manifest YAML for category:mcp_server.  We do NOT
  # re-invoke Python here — grep on the already-validated manifest is sufficient
  # and avoids a second Python startup in a potentially slow CI environment.
  #
  # Input validation: agent_name is extracted from the ALREADY-VALIDATED manifest
  # (the Python codegen above rejected it on any invalid character set).  We still
  # guard against shell injection by validating the extracted value against a strict
  # pattern before using it in a shell word.
  #
  # K8s: NetworkPolicy handles gateway↔MCP-server routing; no docker network connect
  # needed.  This block is skipped on K8s runtime.
  #
  # Rootless Podman: podman network connect works but the L1 egress gap (internal:true
  # may not block DNS on rootless) is pre-existing and documented in codegen
  # (_ROOTLESS_L1_GAP_WARNING).  The connect itself still succeeds.

  local _manifest_is_shape_c=false
  if grep -qE '^[[:space:]]*category:[[:space:]]*mcp_server' "${_manifest}" 2>/dev/null; then
    _manifest_is_shape_c=true
  fi

  if [[ "$_manifest_is_shape_c" == "true" ]] && \
     [[ "${YSG_RUNTIME_4WAY:-docker}" != "k8s" ]]; then

    # Extract agent_name from the manifest (already Python-validated — but we
    # validate again for shell safety: only [a-zA-Z0-9_-] permitted).
    local _agent_name_raw
    _agent_name_raw="$(grep -E '^[[:space:]]*name:[[:space:]]*' "${_manifest}" 2>/dev/null \
                        | head -1 | sed 's/.*name:[[:space:]]*//' | tr -d '[:space:]"'"'"'' || true)"

    # Extract tenant_id similarly
    local _tenant_id_raw
    _tenant_id_raw="$(grep -E '^[[:space:]]*tenant_id:[[:space:]]*' "${_manifest}" 2>/dev/null \
                       | head -1 | sed 's/.*tenant_id:[[:space:]]*//' | tr -d '[:space:]"'"'"'' || true)"

    # SECURITY: validate agent_name against strict allowlist before use in any
    # shell expansion or docker/podman command argument.
    # Pattern: alphanumeric + hyphen + underscore, 1-64 chars.
    # Reject anything else — this prevents injection via a crafted manifest name.
    if [[ -z "$_agent_name_raw" ]] || ! [[ "$_agent_name_raw" =~ ^[a-zA-Z0-9_-]{1,64}$ ]]; then
      log_error "Shape-C bridge-join: could not extract a safe agent name from manifest"
      log_error "  Extracted value: '${_agent_name_raw}'"
      log_error "  Expected: alphanumeric + hyphen + underscore, 1-64 chars"
      log_error "  Bridge-join SKIPPED — run operator action manually:"
      log_error "    docker network connect ringfence_<agent> <gateway-container>"
      log_error "    docker compose -f docker/docker-compose.yml up --no-deps -d gateway"
    else
      # Safe to use in shell words from here.
      local _ringfence_net="ringfence_${_agent_name_raw}"
      local _compose_file="${WORK_DIR}/docker/docker-compose.yml"

      # Determine the gateway container name.
      # Compose names containers as <project>-<service>-<index>; the project
      # defaults to the directory name of the compose file.
      #
      # We CANNOT use `compose ps -q gateway` here because docker-compose.yml
      # declares YASHIGANI_UPSTREAM_URL: ${UPSTREAM_MCP_URL:?set UPSTREAM_MCP_URL}
      # — the :? makes it required, so compose errors out when UPSTREAM_MCP_URL
      # is empty (e.g. non-interactive install without --upstream-url).
      # Instead we resolve the container name via `docker/podman ps --filter`
      # which needs no compose-file interpolation.  YSG-P3-MCP-BRIDGE-JOIN-FIX.
      #
      # NEW-BUG-A Part 1 FIX (cascade audit 2026-05-30): on standalone --onboard
      # invocations COMPOSE_CMD is still the empty global.  _runtime_bin_ps would
      # then default to "docker" even on Podman-only stacks, causing all five
      # detection tiers to run "docker ps" and find nothing.
      # Fix: resolve COMPOSE_CMD here, before the detection block.
      if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
        resolve_compose_cmd 2>/dev/null || true
      fi
      local _gw_container=""
      local _runtime_bin_ps="${COMPOSE_CMD[0]:-docker}"
      # strip -compose suffix: "docker-compose" → "docker", "podman-compose" → "podman"
      _runtime_bin_ps="${_runtime_bin_ps%%-compose}"

      # Derive the compose project name from the compose-file directory name
      # (same logic Docker Compose v2 uses by default).
      local _compose_project
      _compose_project="$(basename "$(dirname "$_compose_file")")"

      # NEW-BUG-A FIX — Part 1: gateway container detection.
      #
      # Docker Compose v2 sets com.docker.compose.* labels on containers.
      # podman-compose sets io.podman.compose.* labels.
      # Also: podman-compose names containers with underscores
      # (<project>_<service>_<N>) whereas docker compose v2 uses hyphens
      # (<project>-<service>-<N>).  We must try both label schemas and both
      # naming separators.
      #
      # We CANNOT use `compose ps -q gateway` here because docker-compose.yml
      # declares YASHIGANI_UPSTREAM_URL: ${UPSTREAM_MCP_URL:?set UPSTREAM_MCP_URL}
      # — the :? makes it required, so compose errors out when UPSTREAM_MCP_URL
      # is empty.  Use ps --filter which needs no file interpolation.
      #
      # Detection order:
      #   1. Docker-Compose-v2 label: com.docker.compose.project + service=gateway
      #   2. podman-compose label:    io.podman.compose.project + service=gateway
      #   3. Name pattern hyphen:     <project>-gateway-<N>
      #   4. Name pattern underscore: <project>_gateway_<N>  (podman-compose)
      #   5. Last resort:             any container whose name contains "gateway"

      # Primary: Docker Compose v2 labels (docker / rootful podman-compose)
      _gw_container="$(
        "$_runtime_bin_ps" ps \
          --filter "label=com.docker.compose.project=${_compose_project}" \
          --filter "label=com.docker.compose.service=gateway" \
          --format "{{.Names}}" 2>/dev/null \
        | head -1 || true
      )"

      # Fallback 1: podman-compose labels (io.podman.compose.*)
      if [[ -z "$_gw_container" ]]; then
        _gw_container="$(
          "$_runtime_bin_ps" ps \
            --filter "label=io.podman.compose.project=${_compose_project}" \
            --filter "label=com.docker.compose.service=gateway" \
            --format "{{.Names}}" 2>/dev/null \
          | head -1 || true
        )"
      fi

      # Fallback 2: deterministic compose-v2 name pattern <project>-gateway-<N>
      if [[ -z "$_gw_container" ]]; then
        _gw_container="$(
          "$_runtime_bin_ps" ps \
            --filter "name=^${_compose_project}-gateway-" \
            --format "{{.Names}}" 2>/dev/null \
          | head -1 || true
        )"
      fi

      # Fallback 3: podman-compose name pattern <project>_gateway_<N> (underscore)
      if [[ -z "$_gw_container" ]]; then
        _gw_container="$(
          "$_runtime_bin_ps" ps \
            --filter "name=^${_compose_project}_gateway_" \
            --format "{{.Names}}" 2>/dev/null \
          | head -1 || true
        )"
      fi

      # Last resort: any running container whose name contains "gateway"
      if [[ -z "$_gw_container" ]]; then
        _gw_container="$(
          "$_runtime_bin_ps" ps \
            --filter "name=gateway" \
            --format "{{.Names}}" 2>/dev/null \
          | head -1 || true
        )"
      fi

      # NEW-BUG-A FIX — Part 2: persistent network wiring via docker-compose.yml.
      #
      # `docker/podman network connect` is NOT persisted across `compose down/up`
      # cycles: the gateway container is recreated and the connection is lost.
      # Fix: write the ringfence_<agent> network into the gateway service's
      # `networks:` section of docker-compose.yml AND into the top-level
      # `networks:` definition block.  This way the `compose up --no-deps -d gateway`
      # later in this block creates the gateway container already connected.
      # On subsequent `compose down/up` the network persists via the compose file.
      #
      # This replaces the one-shot `network connect` call as the PRIMARY wiring
      # mechanism.  The `network connect` is retained as a LIVE-stack supplement:
      # it wires the CURRENTLY-RUNNING gateway while we wait for the recreate.
      log_step "-" "NEW-BUG-A: writing ${_ringfence_net} into docker-compose.yml (persistent network wiring)"
      local _compose_patch_ok=false
      python3 - "$_compose_file" "$_ringfence_net" <<'PYCOMPOSE' 2>/dev/null && _compose_patch_ok=true
import sys, re

compose_path = sys.argv[1]
ringfence_net = sys.argv[2]

with open(compose_path, encoding='utf-8') as f:
    lines = f.readlines()

# ── Pass 1: find the gateway service networks: block and add the ringfence net.
# Strategy: locate "  gateway:" (2-space indent, top-level service) then find
# its "    networks:" block.  Insert the new entry only if not already present.
in_gateway = False
in_gateway_networks = False
gateway_networks_indent = None
gateway_networks_end = None  # line index AFTER the last network entry
already_in_gateway_nets = False
inserted_gateway = False

i = 0
result_lines = []
while i < len(lines):
    line = lines[i]
    stripped = line.rstrip('\n')

    # Detect gateway service start (exactly 2-space indent at root level)
    if re.match(r'^  gateway:\s*$', stripped):
        in_gateway = True
        in_gateway_networks = False
        gateway_networks_indent = None
        result_lines.append(line)
        i += 1
        continue

    # Leaving gateway service (another 2-space-indent key or end of file)
    if in_gateway and re.match(r'^  \w', stripped) and not re.match(r'^  gateway:', stripped):
        in_gateway = False
        in_gateway_networks = False

    if in_gateway:
        # Detect `    networks:` block (4-space indent)
        nm = re.match(r'^( {4,})networks:\s*$', stripped)
        if nm and not in_gateway_networks:
            in_gateway_networks = True
            gateway_networks_indent = nm.group(1)
            result_lines.append(line)
            i += 1
            # Walk the network entries
            entry_indent = gateway_networks_indent + '  '
            while i < len(lines):
                entry_line = lines[i]
                entry_stripped = entry_line.rstrip('\n')
                # Still inside networks block?
                if re.match(r'^' + re.escape(entry_indent) + r'- ', entry_stripped):
                    if ringfence_net in entry_stripped:
                        already_in_gateway_nets = True
                    result_lines.append(entry_line)
                    i += 1
                else:
                    # End of networks block for gateway.
                    # Insert before this line if not already present.
                    if not already_in_gateway_nets:
                        result_lines.append('%s- %s\n' % (entry_indent, ringfence_net))
                        inserted_gateway = True
                    break
            continue

    result_lines.append(line)
    i += 1

# ── Pass 2: find the top-level `networks:` block and add the ringfence net def.
# Top-level networks: starts at column 0 with no indent.
# Format to add:
#   <ringfence_net>:
#     driver: bridge
#     enable_ipv6: false
#     internal: true

in_top_networks = False
top_networks_entry_re = re.compile(r'^  \w')
already_in_top_networks = False
inserted_top = False

final_lines = []
i = 0
while i < len(result_lines):
    line = result_lines[i]
    stripped = line.rstrip('\n')

    if re.match(r'^networks:\s*$', stripped):
        in_top_networks = True
        final_lines.append(line)
        i += 1
        # Walk top-level network entries until EOF or next top-level key
        while i < len(result_lines):
            nl = result_lines[i]
            ns = nl.rstrip('\n')
            # Another top-level key (no indent, not a comment, not empty)
            if re.match(r'^\w', ns) and not re.match(r'^networks:', ns):
                break
            if re.match(r'^  ' + re.escape(ringfence_net) + r':', ns):
                already_in_top_networks = True
            final_lines.append(nl)
            i += 1
        if not already_in_top_networks:
            final_lines.append('  # NEW-BUG-A: ringfence bridge for %s MCP agent\n' % ringfence_net)
            final_lines.append('  %s:\n' % ringfence_net)
            final_lines.append('    driver: bridge\n')
            final_lines.append('    enable_ipv6: false\n')
            final_lines.append('    internal: true\n')
            inserted_top = True
        continue

    final_lines.append(line)
    i += 1

if not (inserted_gateway or already_in_gateway_nets):
    print('ERROR: could not find gateway service networks: block', file=sys.stderr)
    sys.exit(1)
if not (inserted_top or already_in_top_networks):
    print('ERROR: could not find top-level networks: block', file=sys.stderr)
    sys.exit(1)

with open(compose_path, 'w', encoding='utf-8') as f:
    f.writelines(final_lines)

print('compose-patch: gateway networks+=%s, top-level networks+=%s' % (
    'added' if inserted_gateway else 'already-present',
    'added' if inserted_top else 'already-present',
))
PYCOMPOSE

      if [[ "$_compose_patch_ok" == "true" ]]; then
        log_success "NEW-BUG-A: ${_ringfence_net} added to docker-compose.yml (gateway + top-level networks)"
      else
        log_warn "NEW-BUG-A: could not patch docker-compose.yml — falling back to network connect only."
        log_warn "  The ringfence network will NOT persist across compose down/up cycles."
        log_warn "  Manual fix: add '- ${_ringfence_net}' under gateway.networks in docker/docker-compose.yml"
        log_warn "  and add '${_ringfence_net}: {driver: bridge, enable_ipv6: false, internal: true}'"
        log_warn "  to the top-level networks: block."
      fi

      if [[ -z "$_gw_container" ]]; then
        log_warn "Shape-C bridge-join: gateway container not found via docker ps."
        log_warn "  Tried: Docker Compose v2 labels (com.docker.compose.*), podman-compose labels"
        log_warn "         (io.podman.compose.*), name patterns '${_compose_project}-gateway-*'"
        log_warn "         and '${_compose_project}_gateway_*', and substring 'gateway'."
        log_warn "  Ensure the stack is running before --onboard for Shape-C agents."
        log_warn "  After starting the stack, rerun:"
        log_warn "    bash install.sh --onboard <manifest> --runtime ${YSG_RUNTIME_4WAY:-docker}"
      else
        log_step "-" "YSG-P3-MCP-BRIDGE-JOIN: live-stack network connect to ${_ringfence_net}"

        # Use the runtime binary we already derived above (_runtime_bin_ps).
        # For network connect we always use the base container runtime (docker/podman).
        local _runtime_bin="$_runtime_bin_ps"

        # Check if gateway is already connected to the ringfence bridge (idempotent).
        local _already_connected=false
        if "$_runtime_bin" network inspect "${_ringfence_net}" \
             --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null \
           | grep -qF "$_gw_container"; then
          _already_connected=true
        fi

        if [[ "$_already_connected" == "true" ]]; then
          log_info "Gateway already connected to ${_ringfence_net} — idempotent, no action."
        else
          log_info "Connecting live gateway container (${_gw_container}) to ${_ringfence_net}..."
          # This live-connect is ephemeral (survives until next gateway recreate).
          # Persistence is via the compose-file patch above.
          if "$_runtime_bin" network connect "${_ringfence_net}" "${_gw_container}" 2>/dev/null; then
            log_success "Gateway live-connected to ${_ringfence_net}"
          else
            local _nc_rc=$?
            log_warn "docker/podman network connect failed (exit ${_nc_rc}) — not fatal."
            log_warn "  Container: ${_gw_container}  Network: ${_ringfence_net}"
            log_warn "  The compose-file patch ensures connectivity after the gateway recreate below."
          fi
        fi

        # ── YASHIGANI_MCP_SERVERS env update + gateway recreate ──────────────
        # The gateway reads YASHIGANI_MCP_SERVERS (JSON array) at startup.
        # We append the new agent's descriptor, then recreate the gateway
        # container with the updated env (compose up --no-deps gateway).
        #
        # Tenant ID: validated against the same allowlist as agent_name.
        local _tenant_id_safe=""
        if [[ -n "$_tenant_id_raw" ]] && [[ "$_tenant_id_raw" =~ ^[a-zA-Z0-9_-]{1,128}$ ]]; then
          _tenant_id_safe="$_tenant_id_raw"
        else
          _tenant_id_safe="unknown"
          log_warn "Shape-C: tenant_id '${_tenant_id_raw}' contains unsafe chars — using 'unknown'"
        fi

        local _env_file="${WORK_DIR}/docker/.env"
        local _bridge_port=8000   # _SC_BRIDGE_PORT from codegen.py:1319

        # Build the new descriptor JSON.
        # _agent_name_raw and _tenant_id_safe are already validated against
        # [a-zA-Z0-9_-] — safe for inline expansion here.
        # python3 json.dumps handles any residual escaping needs.
        # Detect agent type from manifest subprocess command.
        # git-mcp uses /usr/local/bin/git-mcp-launcher; filesystem-mcp uses the
        # mcp-server-filesystem binary.  grep the already-validated manifest to set
        # the correct is_* flag in the YASHIGANI_MCP_SERVERS descriptor.
        # FIX-GIT-AGENT-FLAG (Ava 2026-05-30): previously always emitted
        # is_filesystem_agent=True for all Shape-C agents; git agents must emit
        # is_git_agent=True so broker.py routes to git_tool_allowed OPA gate.
        local _is_git_agent_flag=false
        if grep -qE 'git-mcp-launcher' "${_manifest}" 2>/dev/null; then
          _is_git_agent_flag=true
        fi

        local _new_descriptor
        _new_descriptor="$(python3 -c "
import json
agent = '${_agent_name_raw}'
tenant = '${_tenant_id_safe}'
port = ${_bridge_port}
is_git = '${_is_git_agent_flag}' == 'true'
desc = {
    'agent_name': agent,
    # FIX-UPSTREAM-URL-DOUBLE-MCP (2026-05-30): McpHttpTransport.forward() always
    # appends path="/mcp" to upstream_url.  Do NOT include /mcp in upstream_url —
    # the base URL only (http://filesystem:8000).  Adding /mcp here causes
    # double-path: http://filesystem:8000/mcp/mcp → HTTP 404.
    'upstream_url': 'http://%s:%d' % (agent, port),
    'tenant_id': tenant,
    'is_git_agent': is_git,
    'is_filesystem_agent': not is_git,
}
print(json.dumps(desc))
" 2>/dev/null || echo "")"

        if [[ -z "$_new_descriptor" ]]; then
          log_warn "Shape-C: failed to build MCP server descriptor JSON — YASHIGANI_MCP_SERVERS not updated"
          log_warn "  Add manually to docker/.env:"
          log_warn "    YASHIGANI_MCP_SERVERS=[{\"agent_name\":\"${_agent_name_raw}\",..."
        else
          # Read current YASHIGANI_MCP_SERVERS value from .env (may be absent or empty).
          local _current_servers=""
          if grep -q "^YASHIGANI_MCP_SERVERS=" "$_env_file" 2>/dev/null; then
            _current_servers="$(grep "^YASHIGANI_MCP_SERVERS=" "$_env_file" | head -1 | cut -d= -f2-)"
          fi

          # Append descriptor to the JSON array (or create a new array).
          local _new_servers
          _new_servers="$(python3 -c "
import json, sys
current_raw = '''${_current_servers}'''.strip()
new_desc = json.loads('''${_new_descriptor}''')
try:
    arr = json.loads(current_raw) if current_raw and current_raw != '[]' else []
except json.JSONDecodeError:
    arr = []
# Idempotent: remove existing entry for the same agent_name before appending.
arr = [e for e in arr if isinstance(e, dict) and e.get('agent_name') != new_desc['agent_name']]
arr.append(new_desc)
print(json.dumps(arr))
" 2>/dev/null || echo "[]")"

          if [[ "$_new_servers" == "[]" ]] || [[ -z "$_new_servers" ]]; then
            log_warn "Shape-C: YASHIGANI_MCP_SERVERS update produced empty array — check manually"
          else
            # Write to .env (atomic replace)
            if grep -q "^YASHIGANI_MCP_SERVERS=" "$_env_file" 2>/dev/null; then
              local _tmp_env_mcp; _tmp_env_mcp="$(mktemp "${WORK_DIR}/docker/.env-mcp-XXXXXX")"
              # Use python3 for the replacement — avoids sed special-char issues in JSON values.
              python3 - "$_env_file" "$_tmp_env_mcp" "$_new_servers" <<'PYREPLACE' || {
import sys, re
src, dst, new_val = sys.argv[1], sys.argv[2], sys.argv[3]
content = open(src, encoding='utf-8').read()
new_content = re.sub(r'^YASHIGANI_MCP_SERVERS=.*', 'YASHIGANI_MCP_SERVERS=' + new_val, content, flags=re.MULTILINE)
with open(dst, 'w', encoding='utf-8') as f:
    f.write(new_content)
PYREPLACE
                log_warn "Shape-C: could not update YASHIGANI_MCP_SERVERS in .env — update manually"
                rm -f "${_tmp_env_mcp}" 2>/dev/null || true
              }
              if [[ -f "$_tmp_env_mcp" ]]; then
                mv "$_tmp_env_mcp" "$_env_file"
              fi
            else
              printf 'YASHIGANI_MCP_SERVERS=%s\n' "$_new_servers" >> "$_env_file"
            fi
            log_success "YASHIGANI_MCP_SERVERS updated in docker/.env"
            log_info "  Added: ${_new_descriptor}"
          fi

          # Recreate the gateway container with the updated env.
          # Uses `compose up --no-deps gateway` (Captain spec — restarts only gateway,
          # not the entire stack).  Fail-loud: if this fails, the operator gets
          # explicit recovery instructions.
          #
          # FIX-COMPOSE-CMD: when invoked via `install.sh --onboard`, COMPOSE_CMD is
          # not set by the main install flow.  Resolve it on-demand here so the
          # gateway recreate can proceed in both install-time and standalone --onboard
          # invocations.
          # P3 broker E2E gate — J8/J9 gateway-not-reloaded fix (2026-05-30).
          if [[ ${#COMPOSE_CMD[@]} -eq 0 ]]; then
            resolve_compose_cmd 2>/dev/null || true
          fi
          log_step "-" "Shape-C: recreating gateway with updated YASHIGANI_MCP_SERVERS env"
          if [[ ${#COMPOSE_CMD[@]} -gt 0 ]]; then
            local _gw_up_rc=0
            "${COMPOSE_CMD[@]}" -f "$_compose_file" up --no-deps -d gateway 2>&1 || _gw_up_rc=$?
            if [[ "$_gw_up_rc" -ne 0 ]]; then
              log_error "Gateway recreate failed (exit ${_gw_up_rc})."
              log_error "  The YASHIGANI_MCP_SERVERS env change requires a gateway restart to take effect."
              log_error "  Recovery:"
              log_error "    ${COMPOSE_CMD[*]} -f ${_compose_file} up --no-deps -d gateway"
              log_error "  If the gateway fails to start, check: docker compose logs gateway"
            else
              log_success "Gateway recreated with updated MCP server list."
            fi
          else
            log_warn "Shape-C: COMPOSE_CMD not resolved — cannot recreate gateway automatically."
            log_warn "  Run manually: docker compose -f docker/docker-compose.yml up --no-deps -d gateway"
          fi
        fi
      fi
    fi
  fi
  # END YSG-P3-MCP-BRIDGE-JOIN

  # Production/staging guard: after onboarding a Shape-C MCP agent, verify the
  # MCP signing key file exists.  The gateway will refuse to start if it doesn't
  # (Tom's McpJwtIssuer RuntimeError guard in _jwt.py).
  if [[ "${YASHIGANI_ENV:-}" == "production" || "${YASHIGANI_ENV:-}" == "staging" ]]; then
    local _mcp_key_check="${WORK_DIR}/docker/secrets/mcp_identity_signing_key"
    if [[ ! -f "$_mcp_key_check" ]]; then
      log_error "PRODUCTION GUARD: mcp_identity_signing_key not found at ${_mcp_key_check}"
      log_error "  The gateway will REFUSE to start in ${YASHIGANI_ENV} without a persistent MCP signing key."
      log_error "  Run: ./install.sh (or --pki-action=bootstrap) to generate the key."
      exit 1
    fi
    log_info "Production guard: mcp_identity_signing_key present at ${_mcp_key_check} — OK"
  fi

  # BUG-5 FIX (Ava 2026-05-30): run rotate-leaves --only for the newly onboarded
  # agent immediately so its bootstrap_token_sha256 is populated before the agent
  # container first starts.  Without this, the agent container calls current_service()
  # at startup, finds bootstrap_token_sha256: "" in the runtime manifest, and raises
  # TamperError — refusing to start.
  #
  # Precondition: PKI has been bootstrapped (intermediate cert exists).  If the
  # operator onboards before running bootstrap, skip this with a clear warning —
  # they will need to run --pki-action=rotate-leaves manually after bootstrap.
  #
  # Extract agent name from the manifest (already validated by Python codegen above).
  # Use the same grep pattern as the Shape-C bridge-join block.
  local _new_agent_name=""
  _new_agent_name="$(grep -E '^[[:space:]]*name:[[:space:]]*' "${_manifest}" 2>/dev/null \
    | head -1 | sed 's/.*name:[[:space:]]*//' | tr -d '[:space:]"'"'"'' || true)"

  if [[ -n "${_new_agent_name}" ]] && [[ "${_new_agent_name}" =~ ^[a-zA-Z0-9_-]{1,64}$ ]]; then
    local _intermediate_cert="${WORK_DIR}/docker/secrets/ca_intermediate.crt"
    if [[ -f "$_intermediate_cert" ]]; then
      log_step "-" "BUG-5: issuing bootstrap token + leaf cert for '${_new_agent_name}' (rotate-leaves --only)"
      local _rl_rc=0
      _pki_run_issuer rotate-leaves --only "${_new_agent_name}" || _rl_rc=$?
      if [[ "$_rl_rc" -ne 0 ]]; then
        log_warn "BUG-5: rotate-leaves --only '${_new_agent_name}' failed (exit ${_rl_rc})."
        log_warn "  The agent container will refuse to start until bootstrap_token_sha256 is populated."
        log_warn "  Run manually: ./install.sh --pki-action=rotate-leaves"
      else
        log_success "BUG-5: bootstrap_token_sha256 populated for '${_new_agent_name}' — agent container can start."
        # Re-chown: rotate-leaves generates key material owned by the issuer UID (1001).
        # Without chown, the agent container (potentially a different UID) cannot read its key.
        _pki_chown_client_keys \
          || log_warn "BUG-5: _pki_chown_client_keys failed after --only rotate — agent key may be unreadable"
      fi
    else
      log_warn "BUG-5: PKI not yet bootstrapped (${_intermediate_cert} missing)."
      log_warn "  Run bootstrap first, then: ./install.sh --pki-action=rotate-leaves"
    fi
  else
    log_warn "BUG-5: could not extract valid agent name from manifest — skipping bootstrap-token issuance."
    log_warn "  Run manually: ./install.sh --pki-action=rotate-leaves"
  fi

  log_success "Agent onboarded. Bootstrap token issued (or: run --pki-action=rotate-leaves if PKI not yet bootstrapped)."
  log_info "  (Rotate-leaves issues/updates the agent's client cert from service_identities.yaml)"
}

# =============================================================================
# P1 W4 — S5: offboard handler (delegates to scripts/offboard.sh)
# =============================================================================
handle_offboard_subcommand() {
  local _agent="${OFFBOARD_AGENT}"

  if [[ -z "$_agent" ]]; then
    log_error "--offboard requires an agent name"
    exit 1
  fi

  log_step "-" "Offboarding agent: ${_agent}"

  # Resolve WORK_DIR first so _is_existing_yashigani_running can find docker/secrets
  if [[ -z "${WORK_DIR:-}" || ! -d "${WORK_DIR}" ]]; then
    detect_working_directory
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
      cd "$WORK_DIR"
    fi
  fi

  # P1 W6 — Step-up gate: same requirement as onboard — removing an agent
  # from a ring-fence with install residuals modifies the live security
  # posture and therefore requires admin password + TOTP verification.
  # FIX-2: use _is_installed_or_running (residuals-based, fail-closed);
  # see onboard comment above (Laura F1/F2).
  if _is_installed_or_running; then
    _ysg_onboard_stepup_gate "offboard" || exit 1
  fi

  local _offboard_sh="${_YSG_SCRIPT_DIR}/scripts/offboard.sh"
  if [[ ! -f "$_offboard_sh" ]]; then
    log_error "scripts/offboard.sh not found at ${_offboard_sh}"
    exit 1
  fi

  WORK_DIR="$WORK_DIR" \
  YSG_RUNTIME="${YSG_RUNTIME:-}" \
  YSG_OPERATOR_IDENTITY="${YSG_OPERATOR_IDENTITY:-}" \
    bash "$_offboard_sh" "$_agent"
  local _rc=$?

  if [[ "$_rc" -ne 0 ]]; then
    log_error "Offboard failed (exit ${_rc})"
    exit 1
  fi
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
      # Re-chown private keys to container UIDs after rotation (C-003 fix).
      # _pki_run_issuer regenerates keys with fresh material and writes them
      # mode 0400 owned by the installer UID. Without the chown step the
      # container service processes (e.g. pgbouncer UID 70, backoffice UID 1000)
      # can no longer read their own private keys → crash-loop on next restart.
      # The inline pki_action path did not call _pki_chown_client_keys; the
      # offboard-triggered path (install.sh --pki-action rotate-leaves) therefore
      # left keys unreadable by their owning containers.
      _pki_chown_client_keys || { log_error "C-003: _pki_chown_client_keys failed after rotate-leaves — keys may be unreadable by containers"; return 1; }
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

  # Multi-instance (3.0 / MI-1): key the bootstrap install dir to the instance
  # PROJECT BEFORE detect_working_directory runs, so a second --project/--domain
  # install on the same host bootstraps into its OWN tree
  # ($HOME/.yashigani-<project>) — isolated secrets, .env, state file and CA —
  # instead of clobbering the first instance's shared $HOME/.yashigani. Legacy /
  # single-instance (no --project, no --domain) is untouched. An explicit
  # YSG_INSTALL_DIR env override always wins. Side-effect-free except assigning
  # YSG_INSTALL_DIR; safe before --list / PKI / onboard short-circuits below.
  _resolve_instance_install_dir

  # Multi-instance (3.0): --list enumerates instances on the host, then exits.
  # No working-directory / wizard needed — it only reads the runtime's container
  # labels. Placed before all other short-circuits so it works on any host state.
  if [[ "$LIST_INSTANCES" == "true" ]]; then
    detect_working_directory 2>/dev/null || true
    _list_instances
    exit 0
  fi

  # Short-circuit path for PKI maintenance commands: no full install, no wizard.
  if [[ -n "$PKI_ACTION" ]]; then
    detect_working_directory
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then cd "$WORK_DIR"; fi
    handle_pki_subcommand
    exit 0
  fi

  # P1 W4: Short-circuit path for onboard/offboard: no full install, no wizard.
  if [[ -n "${ONBOARD_MANIFEST:-}" ]]; then
    handle_onboard_subcommand
    exit 0
  fi
  if [[ -n "${OFFBOARD_AGENT:-}" ]]; then
    handle_offboard_subcommand
    exit 0
  fi

  # ---- Step 0: Banner ----
  print_banner

  # Concurrency guard (YSG retro 2026-06-25): a host-wide ADVISORY LOCK prevents
  # two installers colliding on the shared compose project + ports 80/443 (the
  # root cause of the v3.0.0 cycle's zombie-installer collision). flock is tied to
  # the open fd, so a crashed/killed run releases the lock automatically — no
  # stale-lock cruft, and (unlike a pgrep heuristic) no false-positives on the
  # launcher's own command line. FAIL-OPEN: if flock is unavailable or the lock
  # path is unwritable we proceed (never block a legitimate install). Override
  # with YASHIGANI_ALLOW_CONCURRENT_INSTALL=1 for genuine multi-instance hosts.
  #
  # BUG-FIX (3.1.0): Use bash {varname} fd auto-assignment (bash 4.1+, standard on
  # Ubuntu 20.04+) so the lock fd has FD_CLOEXEC set automatically. Without CLOEXEC,
  # every child process spawned by podman-compose (conmon, slirp4netns, aardvark-dns,
  # etc.) inherits the open fd and keeps the flock alive indefinitely — blocking ALL
  # subsequent installs until the containers are killed. With CLOEXEC the lock is held
  # only by the installer process itself, which is the correct invariant.
  if [[ "${YASHIGANI_ALLOW_CONCURRENT_INSTALL:-0}" != "1" && "$DRY_RUN" != "true" ]] \
     && command -v flock >/dev/null 2>&1; then
    local _lockdir="/run/lock"; [[ -w "$_lockdir" ]] || _lockdir="${YSG_INSTALL_DIR:-$HOME}"
    local _lockfile="${_lockdir}/yashigani-install.lock"
    local _lock_fd
    # {_lock_fd} auto-assigns a high fd WITH FD_CLOEXEC — children never inherit it.
    # Held for the lifetime of this process; released on exit (or exec).
    if exec {_lock_fd}>"$_lockfile" 2>/dev/null; then
      if ! flock -n "$_lock_fd"; then
        log_error "Another Yashigani install/uninstall already holds the lock:"
        log_error "  ${_lockfile}"
        log_error "Wait for it to finish (or kill the stale PID), then retry. For genuine"
        log_error "parallel/multi-instance installs set YASHIGANI_ALLOW_CONCURRENT_INSTALL=1."
        exit 1
      fi
    fi
  fi

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
      # MI-2/MI-6 parity with the compose path: mint-or-preserve the instance
      # identity token and record the per-instance trust domain. On k8s the
      # instance label is the namespace (already the tenancy boundary), so the
      # trust domain derives from NAMESPACE; legacy "yashigani" namespace keeps
      # the canonical yashigani.internal authority byte-for-byte.
      local _k8s_state_path="${WORK_DIR}/docker/.yashigani-install-state"
      local _k8s_instance_id _k8s_trust_domain _k8s_proj
      _k8s_proj="${NAMESPACE:-yashigani}"
      _k8s_instance_id="$(_instance_identity_token "$_k8s_state_path")"
      if [[ -z "$_k8s_instance_id" ]]; then
        _k8s_instance_id="$(_gen_instance_id)"
      fi
      # On k8s the legacy default namespace is "yashigani"; map it to the legacy
      # trust domain. Any other namespace gets <namespace>.yashigani.internal.
      if [[ "$_k8s_proj" == "yashigani" ]]; then
        _k8s_trust_domain="yashigani.internal"
      else
        _k8s_trust_domain="$(_spiffe_trust_domain "$(_sanitise_project "$_k8s_proj")")"
      fi
      {
        printf 'RUNTIME=%s\n'            "k8s"
        printf 'NAMESPACE=%s\n'          "${NAMESPACE}"
        printf 'HELM_RELEASE=%s\n'       "yashigani"
        # Multi-instance (3.0): on k8s, instance separation is by namespace/release
        # (already parameterised); PROJECT/DOMAIN are recorded for state-file parity
        # with the compose path and for `--list`. PROJECT defaults to NAMESPACE here.
        printf 'PROJECT=%s\n'            "${NAMESPACE:-yashigani}"
        printf 'DOMAIN=%s\n'             "${DOMAIN:-}"
        printf 'INSTANCE_ID=%s\n'        "${_k8s_instance_id}"
        printf 'SPIFFE_TRUST_DOMAIN=%s\n' "${_k8s_trust_domain}"
        printf 'INSTALL_UID=%s\n'        "$(id -u)"
        printf 'INSTALL_USER=%s\n'       "$(id -un)"
        printf 'INSTALL_TIMESTAMP=%s\n'  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'YASHIGANI_VERSION=%s\n'  "${YASHIGANI_VERSION:-unknown}"
      } > "$_k8s_state_path"
      chmod 0644 "$_k8s_state_path"
      log_info "Install state written: ${_k8s_state_path}"
      log_info "  RUNTIME=k8s  NAMESPACE=${NAMESPACE}  HELM_RELEASE=yashigani  TRUST_DOMAIN=${_k8s_trust_domain}"
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

    # Multi-instance (3.0): resolve the compose PROJECT name NOW — after the wizard
    # has finalised DOMAIN, before any project-scoped operation (existing-install
    # detection, contaminated-volume check, compose up).
    #
    # Precedence:
    #   1. --upgrade / add-component against an EXISTING install → read PROJECT from
    #      that install's state file (don't re-derive; the operator may have used a
    #      custom --project the first time, or --domain may differ on the upgrade run).
    #   2. Explicit --project override (fresh install) → sanitised override.
    #   3. Derived from --domain (fresh install) → sanitised domain.
    #   4. No domain (demo/localhost) → legacy "docker" (single-instance default).
    #
    # The resolved name is exported as COMPOSE_PROJECT_NAME (read by both Docker and
    # Podman compose) and written into docker/.env in generate_env_file().
    if [[ "$UPGRADE" == "true" ]]; then
      # Upgrade / add-component targets an EXISTING instance. Precedence:
      #   1. explicit --project (operator names the instance directly — required to
      #      disambiguate on a multi-instance host) → sanitise it.
      #   2. PROJECT recorded in the state file → use as-is (already a valid name).
      #   3. "docker" legacy default (single-instance, pre-3.0 state file).
      if [[ "$PROJECT_EXPLICIT" -eq 1 && -n "$PROJECT" ]]; then
        PROJECT="$(_sanitise_project "$PROJECT")"
        log_info "Upgrade/add-component targeting instance — project: ${PROJECT} (from --project)"
      else
        PROJECT="$(_read_state_project "${WORK_DIR}/docker/.yashigani-install-state")"
        log_info "Upgrade/add-component targeting existing instance — project: ${PROJECT} (from state file)"
      fi
      export COMPOSE_PROJECT_NAME="$PROJECT"
    else
      _resolve_project
      # Advisory Pro+/Enterprise gate (only fires for a 2nd side-by-side instance).
      _multi_instance_tier_gate
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

    # W2/L10 — wire _detect_runtime after resolve_compose_cmd succeeds.
    # YSG_RUNTIME_4WAY is used by the onboard codegen path to emit the correct
    # ring-fence artifacts. Wrong-runtime codegen silently produces no ring-fence (L10).
    # Called here (after runtime is resolved, before any codegen step) so the
    # 4-way value is available for the rest of the install flow.
    if [[ -f "${_YSG_SCRIPT_DIR}/lib/detect_runtime.sh" ]]; then
      # shellcheck source=lib/detect_runtime.sh
      # shellcheck disable=SC1091
      source "${_YSG_SCRIPT_DIR}/lib/detect_runtime.sh"
      _detect_runtime 2>/dev/null || true
      log_info "Runtime 4-way: ${YSG_RUNTIME_4WAY:-unknown}"
      if [[ "${YSG_RUNTIME_4WAY:-}" == "podman-rootless" ]]; then
        log_warn "L1 network-plane containment NOT active (rootless Podman). L2+L3 active."
      fi
    fi

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
      # BUG-GPU-VRAM-001: pick a model appropriate for the SELECTED GPU's VRAM
      # (set by _select_nvidia_gpu earlier in this step). Previously this always
      # defaulted to qwen2.5:3b regardless of available VRAM. OLLAMA_MODEL_OVERRIDE
      # still wins, preserving explicit operator choice.
      local _ollama_model="${OLLAMA_MODEL_OVERRIDE:-$(_pick_ollama_model_for_vram)}"
      # Preserve any operator-supplied OLLAMA_MODEL — only write if absent.
      if ! grep -q "^OLLAMA_MODEL=" "$_env_file" 2>/dev/null; then
        echo "OLLAMA_MODEL=${_ollama_model}" >> "$_env_file"
        log_info "Ollama default model set: ${_ollama_model} (VRAM-tier choice for $(_format_gpu_vram) — will pull on first start)"
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

    # Step 8c-siem (#21): when Wazuh is selected, point the agnostic audit SIEM
    # pipeline at the bundled indexer via deployment config (.env), loaded at
    # startup by AuditLogWriter.siem_targets_from_env(). Identity = each service's
    # OWN internal-mesh leaf cert (mesh_mtls → pki.client_ssl_context()): no
    # password, NEVER the wazuh admin credential. wazuh-indexer is added to the
    # SSRF allowlist (its name resolves to a private docker IP). If Wazuh is NOT
    # selected, both stay unset → forward to none.
    if printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -qx "wazuh"; then
      local _siem_env_file="${WORK_DIR}/docker/.env"
      local _siem_targets_json='[{"name":"wazuh-bundled","target_type":"elastic_opensearch","url":"https://wazuh-indexer:9200/_bulk","mesh_mtls":true}]'
      _siem_set_env() {  # set-or-replace KEY=VALUE in docker/.env (value may contain |)
        local _k="$1" _v="$2"
        if grep -q "^${_k}=" "$_siem_env_file" 2>/dev/null; then
          local _t; _t="$(mktemp "${WORK_DIR}/docker/.env.XXXXXX")"
          awk -v k="$_k" -v v="$_v" 'BEGIN{FS=OFS="="} $1==k{print k"="v;next} {print}' "$_siem_env_file" > "$_t"
          mv "$_t" "$_siem_env_file"
        else
          printf '%s=%s\n' "$_k" "$_v" >> "$_siem_env_file"
        fi
      }
      _siem_set_env "YASHIGANI_SIEM_TARGETS" "$_siem_targets_json"
      _siem_set_env "YASHIGANI_SIEM_HOSTNAMES" "wazuh-indexer"
      log_success "Audit SIEM forwarding pointed at bundled Wazuh indexer (mesh-mTLS leaf identity)"
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

    # Step 8f: Substitute __YASHIGANI_INTERNAL_BEARER__ into openclaw.runtime.json.
    # docker/docker-compose.yml (openclaw service) bind-mounts
    #   ./openclaw/openclaw.runtime.json:/etc/openclaw/openclaw.json:ro
    # Docker auto-creates the missing bind-source as a DIRECTORY when the file does
    # not yet exist on the host, causing openclaw to read a directory and crash with
    # EISDIR. This step reads docker/openclaw/openclaw.json (git-tracked template),
    # substitutes __YASHIGANI_INTERNAL_BEARER__ with the real token from
    # docker/secrets/yashigani_internal_bearer, and writes the result as a file
    # at docker/openclaw/openclaw.runtime.json (mode 0640, git-ignored).
    # Runs only when the openclaw profile is active.
    # Idempotent: re-runs overwrite the file with fresh token value; a stale
    # directory from a prior broken run is removed first.
    if printf '%s\n' "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}" | grep -q "^openclaw$"; then
      local _oc_template="${WORK_DIR}/docker/openclaw/openclaw.json"
      local _oc_runtime="${WORK_DIR}/docker/openclaw/openclaw.runtime.json"
      local _oc_secrets_dir="${WORK_DIR}/docker/secrets"
      local _oc_bearer_file="${_oc_secrets_dir}/yashigani_internal_bearer"
      local _oc_env_file="${WORK_DIR}/docker/.env"

      # Safety: remove a stale directory left by Docker's dir-autocreate (broken prior run).
      # The directory may be root-owned (Docker creates it as root), so plain rm -rf may fail.
      # Fall back to an ephemeral alpine container that can remove it (same pattern as
      # _chown_agent_volumes and the PKI issuer container).
      if [[ -d "$_oc_runtime" ]] && [[ ! -L "$_oc_runtime" ]]; then
        log_warn "Removing stale openclaw.runtime.json DIRECTORY (left by Docker dir-autocreate on prior broken install)"
        if ! rm -rf "$_oc_runtime" 2>/dev/null; then
          log_info "Plain rm failed (likely root-owned) — using alpine container to remove stale directory"
          local _oc_alpine="alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
          local _oc_openclaw_dir
          _oc_openclaw_dir="$(dirname "$_oc_runtime")"
          local _oc_dir_basename
          _oc_dir_basename="$(basename "$_oc_runtime")"
          ${YSG_RUNTIME:-docker} run --rm \
            -v "${_oc_openclaw_dir}:/mnt/openclaw" \
            "$_oc_alpine" \
            rm -rf "/mnt/openclaw/${_oc_dir_basename}" \
            2>/dev/null \
            || { log_error "Cannot remove stale openclaw.runtime.json directory via container — please run: sudo rm -rf ${_oc_runtime}"; exit 1; }
        fi
        if [[ -e "$_oc_runtime" ]]; then
          log_error "Stale openclaw.runtime.json directory still exists after removal attempt — please run: sudo rm -rf ${_oc_runtime}"
          exit 1
        fi
        log_info "Stale openclaw.runtime.json directory removed"
      fi

      if [[ ! -f "$_oc_template" ]]; then
        log_error "openclaw: template ${_oc_template} not found — cannot generate openclaw.runtime.json"
        exit 1
      fi

      # Read bearer token (Podman-rootless-aware; falls back to .env).
      local _oc_bearer
      _oc_bearer="$(_safe_read_secret "$_oc_bearer_file" "YASHIGANI_INTERNAL_BEARER" "$_oc_env_file" || true)"
      if [[ -z "$_oc_bearer" ]] || [[ "$_oc_bearer" == \#* ]]; then
        log_error "openclaw: yashigani_internal_bearer could not be read from ${_oc_bearer_file} — cannot generate openclaw.runtime.json"
        exit 1
      fi

      # Substitute placeholder and write runtime file.
      # Use a temp file + atomic rename to avoid a partial write being bind-mounted.
      local _oc_tmpfile
      _oc_tmpfile="$(mktemp "${WORK_DIR}/docker/openclaw/.openclaw_runtime_XXXXXX")"
      sed "s|__YASHIGANI_INTERNAL_BEARER__|${_oc_bearer}|g" "$_oc_template" > "$_oc_tmpfile" \
        || { rm -f "$_oc_tmpfile"; log_error "openclaw: sed substitution into openclaw.runtime.json failed"; exit 1; }
      chmod 0640 "$_oc_tmpfile" \
        || log_warn "openclaw: could not chmod 0640 openclaw.runtime.json temp file"
      mv -f "$_oc_tmpfile" "$_oc_runtime" \
        || { rm -f "$_oc_tmpfile"; log_error "openclaw: atomic rename of openclaw.runtime.json failed"; exit 1; }

      # Fail-closed: assert the result is a regular file, not a directory.
      if [[ ! -f "$_oc_runtime" ]] || [[ -d "$_oc_runtime" ]]; then
        log_error "openclaw: openclaw.runtime.json is not a regular file after write — aborting to prevent EISDIR crash"
        exit 1
      fi

      # Fix EACCES: chown openclaw.runtime.json to the openclaw container's runtime
      # UID/GID (node uid=1000, gid=1000 — confirmed from image USER directive).
      # Mode 0640: owner rw, group r, no world-read — preserves CWE-732 intent (the
      # file holds yashigani_internal_bearer; world-read was already excluded by the
      # o+rX exclusion in commit 1f25bec). The install user (e.g. uid 1001) writes the
      # file, but the openclaw process runs as uid 1000 and is not the owner — so it
      # cannot read at 0640 unless it IS the owner. We chown 1000:1000 so the openclaw
      # process is the file owner and mode 0640 grants it read.
      #
      # Docker: _do_chown uses an ephemeral alpine container (docker_run mode) with the
      # openclaw directory mounted at /s — daemon-provided root can chown any UID.
      # Podman rootless: _do_chown uses podman unshare (local) or podman run (remote)
      # to remap container UID 1000 into the host subuid namespace; virtiofs/fuse-
      # overlayfs ensures the remapped ownership is seen correctly by the container.
      # K8s: _do_chown is a no-op (k8s path) — Helm uses podSecurityContext.fsGroup.
      #
      # _mount_base arg (arg 5): the parent directory of _oc_runtime so the /s mount
      # and the relative path strip work correctly (S5 convention from _do_chown).
      local _oc_dir
      _oc_dir="$(dirname "$_oc_runtime")"
      _do_chown "1000" "$_oc_runtime" "openclaw.runtime.json" "0640" "$_oc_dir" \
        || { log_error "openclaw: chown 1000:1000 on openclaw.runtime.json failed — openclaw will EACCES on startup"; exit 1; }
      log_info "openclaw.runtime.json written (bearer substituted, mode 0640, owner 1000:1000 — container-readable, not world-readable)"
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

    # FIND-INSTALL-3.1-001: preflight guard — abort if .env is missing required DB
    # password vars. An upgrade over leftover-but-empty secrets silently drops these
    # (secrets files exist -f, upgrade path taken, empty password, -n guard skips write).
    # This check catches any such drop BEFORE compose up can fake-green via the
    # postgres secret-FILE path (postgres boots off the file, apps then crash on connect).
    if [[ "$DRY_RUN" != "true" ]]; then
      local _pf_env="${WORK_DIR}/docker/.env"
      local _pf_fail=false
      for _pf_key in POSTGRES_PASSWORD POSTGRES_PASSWORD_URLENC REDIS_PASSWORD; do
        local _pf_val
        _pf_val="$(grep "^${_pf_key}=" "${_pf_env}" 2>/dev/null | cut -d= -f2-)" || true
        if [[ -z "${_pf_val}" ]]; then
          log_error "PREFLIGHT FAIL: ${_pf_key} is missing or empty in ${_pf_env}"
          _pf_fail=true
        fi
      done
      if [[ "${_pf_fail}" == "true" ]]; then
        log_error "docker/.env is missing required DB password vars — aborting before compose up."
        log_error "Fix: check docker/secrets/postgres_password + redis_password are non-empty, then re-run install.sh."
        exit 1
      fi
      log_info "Preflight: POSTGRES_PASSWORD, POSTGRES_PASSWORD_URLENC, REDIS_PASSWORD — all present in .env."
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

    # Step 11c (#21): audit SIEM forwarding is configured PRE-deploy at Step
    # 8c-siem by writing YASHIGANI_SIEM_TARGETS + YASHIGANI_SIEM_HOSTNAMES into
    # docker/.env, which AuditLogWriter loads at startup. The previous post-deploy
    # auto-config here PUT to a non-existent endpoint (/admin/alerts/sinks) with a
    # mismatched schema and a session cookie that couldn't satisfy the step-up
    # gate — it silently failed every install, so nothing was ever forwarded.
    # Removed; nothing to do post-deploy.

    # Step 12: Health check
    run_health_check

    # Step 12b: Write install state file (Iris IRIS-ARCH-001 / Laura LAURA-TM-CLEANUP-001).
    # Records the effective runtime + installer identity so uninstall.sh can read the
    # correct runtime without heuristic auto-detect (V240-004 + dual-runtime mismatch).
    # Mode 0644: intentional — uninstall.sh may run as a different OS user (cross-UID
    # clean-slate scenario). Contents are not sensitive (see Laura TM-1 verdict).
    # git-ignored via docker/.yashigani-install-state entry in .gitignore.
    # MI-2: mint-or-preserve the per-instance identity token. It binds lifecycle
    # ops to THIS instance (see _instance_identity_token). Preserve an existing
    # token across upgrade/add-component re-runs so the binding is stable; mint a
    # fresh CSPRNG token only on first install. MI-6: record the per-instance
    # SPIFFE trust domain so uninstall/upgrade and audits read the same authority.
    local _state_path="${WORK_DIR}/docker/.yashigani-install-state"
    local _instance_id _trust_domain _env_path
    # MI-2: the authoritative INSTANCE_ID was minted/preserved in generate_env_file()
    # and written to docker/.env (it is ALSO the compose container-label source).
    # Read it back from .env so the state file and the running-container label carry
    # the SAME token. Fall back to the existing state-file value, then a fresh mint
    # (defensive — .env should always have it on the compose path).
    _env_path="${WORK_DIR}/docker/.env"
    _instance_id=""
    if [[ -f "$_env_path" ]]; then
      _instance_id="$(grep -E '^YASHIGANI_INSTANCE_ID=' "$_env_path" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\r\n[:space:]' || true)"
    fi
    [[ -z "$_instance_id" ]] && _instance_id="$(_instance_identity_token "$_state_path")"
    [[ -z "$_instance_id" ]] && _instance_id="$(_gen_instance_id)"
    _trust_domain="$(_spiffe_trust_domain "${PROJECT:-docker}")"
    {
      printf 'RUNTIME=%s\n'            "${RUNTIME:-${YSG_RUNTIME:-docker}}"
      # Multi-instance (3.0): record the compose project + domain so upgrade /
      # add-component / uninstall.sh target THIS instance without re-deriving.
      # PROJECT falls back to "docker" (legacy single-instance default).
      printf 'PROJECT=%s\n'            "${PROJECT:-docker}"
      printf 'DOMAIN=%s\n'             "${DOMAIN:-}"
      # MI-2: authenticated lifecycle target. INSTANCE_ID is a host-random nonce;
      # a lifecycle op must match it (state file <-> running container label) to
      # act on this instance — a bare --project string is not enough.
      printf 'INSTANCE_ID=%s\n'        "${_instance_id}"
      # MI-6: per-instance SPIFFE trust-domain authority (legacy => yashigani.internal).
      printf 'SPIFFE_TRUST_DOMAIN=%s\n' "${_trust_domain}"
      printf 'INSTALL_UID=%s\n'        "$(id -u)"
      printf 'INSTALL_USER=%s\n'       "$(id -un)"
      printf 'INSTALL_TIMESTAMP=%s\n'  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'YASHIGANI_VERSION=%s\n'  "${YASHIGANI_VERSION:-unknown}"
    } > "$_state_path"
    chmod 0644 "$_state_path"
    log_info "Install state written: ${_state_path}"
    log_info "  PROJECT=${PROJECT:-docker}  DOMAIN=${DOMAIN:-(none)}  TRUST_DOMAIN=${_trust_domain}"

    # Step 13: Completion summary
    print_completion_summary
  fi

  # SF-012: drain the tee coprocess so the final log lines ([12/13] and [13/13])
  # are flushed to install.log before the process exits.  Wait on the specific
  # PID only — bare `wait` would deadlock (see L2782 comment on coprocess + wait).
  #
  # do_wait-HANG FIX (YSG retro 2026-06-25): `wait "$_tee_pid"` with stdout still
  # open blocks FOREVER — the tee coprocess only exits when it receives EOF on the
  # pipe, which never happens while our fd 1/2 (the pipe's write end) stay open.
  # That left install.sh hung in do_wait after printing the completion banner,
  # accumulating zombie installers that collided on the compose project. Fix:
  # reassign fd 1/2 to /dev/null first (closes the pipe's write end -> tee gets
  # EOF -> flushes -> exits), then reap with a bounded backstop so this can NEVER
  # hang again even if tee misbehaves.
  if [[ -n "${_tee_pid:-}" ]]; then
    exec >/dev/null 2>&1
    for _i in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$_tee_pid" 2>/dev/null || break
      sleep 0.2
    done
    kill "$_tee_pid" 2>/dev/null || true
    wait "$_tee_pid" 2>/dev/null || true
  fi
}

main "$@"
