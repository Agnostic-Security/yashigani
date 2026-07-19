#!/usr/bin/env bash
# scripts/k3s-bootstrap.sh — reproducible k3s + Cilium stand-up.
#
# Used for the gate cluster (release-gate CI legs) and documented as a
# reference for customers standing up a new k8s cluster for Yashigani.
# Cilium is the ratified CNI standard (2026-07-19 design). Bootstraps, in
# order:
#   1. k3s server with the built-in CNI + NetworkPolicy controller DISABLED
#      (--flannel-backend=none --disable-network-policy) — flannel/kindnet
#      silently no-op NetworkPolicy (FINDING-V412-UNIVERSAL-004); we do not
#      want either the default CNI or a second NetworkPolicy controller
#      fighting Cilium.
#   2. Cilium, pinned chart version, Phase-1 profile: NO kube-proxy
#      replacement (k3s's built-in kube-proxy stays; Cilium only replaces
#      the CNI/NetworkPolicy layer), Hubble in flow-log mode only (agent-local
#      `hubble observe`; relay/UI are OFF — smaller footprint for Phase-1).
#   3. Wait-gates: Cilium agent DaemonSet + operator Deployment Ready, node
#      Ready (only meaningful once CNI is up), CoreDNS Ready.
#   4. CoreDNS DNSSEC/DoT hardening via scripts/coredns-hardening-apply.sh
#      (single source of truth — do not duplicate the Corefile content here).
#
# Idempotent: safe to re-run against an already-bootstrapped cluster (skips
# k3s install if already active, `helm upgrade --install` for Cilium, and
# coredns-hardening-apply.sh is itself idempotent).
#
# Fail-loud throughout — no step masks a real failure with `|| true` except
# where explicitly documented as a known-harmless no-op (e.g. `helm repo add`
# against an already-added repo).
#
# Usage:
#   sudo scripts/k3s-bootstrap.sh [--upstream-provider cloudflare|quad9]
#                                  [--skip-coredns-hardening] [--help]
#
# Env overrides:
#   K3S_VERSION               pinned k3s release, e.g. v1.30.6+k3s1
#                              (default set below — bump via change-managed PR)
#   CILIUM_CHART_VERSION       pinned Cilium helm chart version
#                              (default set below — bump via change-managed PR)
#   COREDNS_UPSTREAM_PROVIDER  cloudflare (default) | quad9 — forwarded to
#                              scripts/coredns-hardening-apply.sh
#
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Pinned versions — bump these two via a change-managed PR, never silently.
# ---------------------------------------------------------------------------
K3S_VERSION="${K3S_VERSION:-v1.30.6+k3s1}"
CILIUM_CHART_VERSION="${CILIUM_CHART_VERSION:-1.16.5}"

UPSTREAM_PROVIDER="${COREDNS_UPSTREAM_PROVIDER:-cloudflare}"
SKIP_COREDNS_HARDENING=false

_usage() {
  cat <<EOF
Usage: sudo scripts/k3s-bootstrap.sh [OPTIONS]

Bootstraps a k3s cluster with Cilium as CNI (Phase-1 profile: no kube-proxy
replacement, Hubble flow-log mode only) and applies the CoreDNS DNSSEC/DoT
hardening. Idempotent — safe to re-run.

Options:
  --upstream-provider PROVIDER   cloudflare (default) | quad9 — forwarded to
                                  scripts/coredns-hardening-apply.sh
  --skip-coredns-hardening        Skip the CoreDNS DoT/DNSSEC patch step
                                  (install.sh's DNS-01/DNS-02 preflight will
                                  then fail closed until it is applied later)
  --help                          Print this help message

Pinned versions (override via env, bump via change-managed PR):
  K3S_VERSION=${K3S_VERSION}
  CILIUM_CHART_VERSION=${CILIUM_CHART_VERSION}
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream-provider)       UPSTREAM_PROVIDER="${2:?--upstream-provider requires a value}"; shift 2 ;;
    --skip-coredns-hardening)  SKIP_COREDNS_HARDENING=true; shift ;;
    --help|-h)                 _usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; _usage >&2; exit 1 ;;
  esac
done

_log_info() { printf '    --> %s\n' "$1"; }
_log_ok()   { printf '    ok  %s\n' "$1"; }
_log_warn() { printf '    !!  WARNING: %s\n' "$1" >&2; }
_log_err()  { printf '    !!  ERROR: %s\n' "$1" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { _log_err "Required command not found in PATH: $1"; exit 1; }
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  _log_err "This script installs a system service (k3s) and must run as root (sudo)."
  exit 1
fi

require_cmd curl
require_cmd helm
require_cmd sha256sum
require_cmd systemctl

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

_log_info "Pinned K3S_VERSION=${K3S_VERSION}  CILIUM_CHART_VERSION=${CILIUM_CHART_VERSION}"

# ---------------------------------------------------------------------------
# Step 1: k3s server (idempotent — skip install if already active)
# ---------------------------------------------------------------------------
if systemctl is-active --quiet k3s 2>/dev/null; then
  _log_ok "k3s service already active — skipping install."
else
  _log_info "Installing k3s ${K3S_VERSION} (flannel disabled, network-policy controller disabled)..."
  # Supply-chain note (S6): get.k3s.io's own wrapper script has no separately
  # published checksum to pre-verify. Pin the exact release via
  # INSTALL_K3S_VERSION, then VERIFY the installed k3s binary's sha256
  # against the upstream-published checksum for that exact pinned release
  # (below) before trusting this cluster with anything.
  curl -fsSL https://get.k3s.io | \
    INSTALL_K3S_VERSION="$K3S_VERSION" \
    INSTALL_K3S_EXEC="server --flannel-backend=none --disable-network-policy --write-kubeconfig-mode=0600" \
    sh -

  if ! command -v k3s >/dev/null 2>&1; then
    _log_err "k3s install reported success but the 'k3s' binary is not on PATH — aborting."
    exit 1
  fi

  # Verify the installed binary against the upstream-published checksum for
  # this exact pinned version (mitigates a compromised/MITM'd install.sh
  # fetch even though the wrapper script itself isn't pre-verified).
  _log_info "Verifying k3s binary checksum against the pinned release's published sha256sum..."
  _k3s_bin="$(command -v k3s)"
  _checksum_url="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/sha256sum-amd64.txt"
  _checksum_file_content=""
  if ! _checksum_file_content="$(curl -fsSL "$_checksum_url" 2>/dev/null)"; then
    _log_err "Could not fetch the published checksum file for ${K3S_VERSION} (${_checksum_url})."
    _log_err "Refusing to trust an un-verified k3s binary. Investigate connectivity/pin, or run:"
    _log_err "  k3s-uninstall.sh"
    exit 1
  fi
  _expected_sha="$(printf '%s\n' "$_checksum_file_content" | awk '$2=="k3s"{print $1; exit}')"
  if [[ -z "$_expected_sha" ]]; then
    _log_err "Published checksum file for ${K3S_VERSION} did not contain a 'k3s' entry — cannot verify."
    exit 1
  fi
  _actual_sha="$(sha256sum "$_k3s_bin" | awk '{print $1}')"
  if [[ "$_actual_sha" != "$_expected_sha" ]]; then
    _log_err "=============================================================="
    _log_err "k3s binary checksum MISMATCH for pinned version ${K3S_VERSION}."
    _log_err "  expected: ${_expected_sha}"
    _log_err "  actual:   ${_actual_sha}"
    _log_err "Do NOT trust this cluster. Investigate before proceeding — this could indicate"
    _log_err "a compromised mirror or a MITM'd download. Remove with: k3s-uninstall.sh"
    _log_err "=============================================================="
    exit 1
  fi
  _log_ok "k3s binary checksum verified against the pinned release (${K3S_VERSION})."
fi

# ---------------------------------------------------------------------------
# Step 2: wait for the API server + node object to exist. Do NOT wait for
# node Ready yet — the "Ready" condition depends on a working CNI, which
# isn't installed until Step 3. Waiting for it here would hang.
# ---------------------------------------------------------------------------
_log_info "Waiting for the k3s API server to become reachable..."
_api_wait=0
until kubectl get nodes >/dev/null 2>&1; do
  _api_wait=$((_api_wait + 1))
  if [[ "$_api_wait" -ge 30 ]]; then
    _log_err "k3s API server did not become reachable within 60s (kubectl get nodes kept failing)."
    exit 1
  fi
  sleep 2
done
_log_ok "k3s API server reachable."

# ---------------------------------------------------------------------------
# Step 3: Cilium via Helm — idempotent (upgrade --install)
# ---------------------------------------------------------------------------
_log_info "Installing/upgrading Cilium ${CILIUM_CHART_VERSION} (Phase-1: no kube-proxy replacement, Hubble flow-log mode only)..."
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true  # no-op if already added w/ same URL
helm repo update cilium >/dev/null

if ! helm upgrade --install cilium cilium/cilium \
      --version "$CILIUM_CHART_VERSION" \
      --namespace kube-system \
      --set kubeProxyReplacement=false \
      --set hubble.enabled=true \
      --set hubble.relay.enabled=false \
      --set hubble.ui.enabled=false \
      --wait --timeout 5m; then
  _log_err "Cilium helm install/upgrade failed — see output above."
  exit 1
fi
_log_ok "Cilium helm release applied."

# ---------------------------------------------------------------------------
# Step 4: wait-gates — Cilium agent + operator, THEN node Ready (only
# meaningful now that a CNI is present), THEN CoreDNS.
# ---------------------------------------------------------------------------
_log_info "Waiting for Cilium agent DaemonSet Ready..."
if ! kubectl -n kube-system rollout status daemonset/cilium --timeout=180s; then
  _log_err "Cilium agent DaemonSet did not reach Ready within 180s."
  _log_err "Investigate: kubectl -n kube-system get pods -l k8s-app=cilium"
  exit 1
fi

_log_info "Waiting for Cilium operator Deployment Ready..."
if ! kubectl -n kube-system rollout status deployment/cilium-operator --timeout=180s; then
  _log_err "Cilium operator Deployment did not reach Ready within 180s."
  _log_err "Investigate: kubectl -n kube-system get pods -l name=cilium-operator"
  exit 1
fi

_log_info "Waiting for all nodes to report Ready (CNI now present)..."
if ! kubectl wait --for=condition=Ready node --all --timeout=180s; then
  _log_err "Not all nodes reached Ready within 180s of Cilium coming up."
  _log_err "Investigate: kubectl get nodes -o wide ; kubectl -n kube-system get pods"
  exit 1
fi
_log_ok "Cilium is Ready and all nodes report Ready."

_log_info "Waiting for CoreDNS to become Ready..."
if kubectl -n kube-system get deployment coredns >/dev/null 2>&1; then
  if ! kubectl -n kube-system rollout status deployment/coredns --timeout=120s; then
    _log_err "CoreDNS deployment did not reach Ready within 120s."
    exit 1
  fi
elif kubectl -n kube-system get daemonset coredns >/dev/null 2>&1; then
  if ! kubectl -n kube-system rollout status daemonset/coredns --timeout=120s; then
    _log_err "CoreDNS daemonset did not reach Ready within 120s."
    exit 1
  fi
else
  _log_err "No coredns Deployment or DaemonSet found in kube-system — unexpected topology."
  exit 1
fi
_log_ok "CoreDNS Ready."

# ---------------------------------------------------------------------------
# Step 5: CoreDNS DNSSEC/DoT hardening — single source of truth in
# scripts/coredns-hardening-apply.sh; do NOT duplicate the Corefile content
# here (SOP 0).
# ---------------------------------------------------------------------------
if [[ "$SKIP_COREDNS_HARDENING" == "true" ]]; then
  _log_warn "Skipping CoreDNS DNSSEC/DoT hardening (--skip-coredns-hardening)."
  _log_warn "install.sh's DNS-01/DNS-02 preflight will fail closed until this is applied:"
  _log_warn "  scripts/coredns-hardening-apply.sh"
else
  _log_info "Applying CoreDNS DNSSEC/DoT hardening (upstream: ${UPSTREAM_PROVIDER})..."
  if ! COREDNS_UPSTREAM_PROVIDER="$UPSTREAM_PROVIDER" bash "${SCRIPT_DIR}/coredns-hardening-apply.sh"; then
    _log_err "CoreDNS hardening patch failed — see output above."
    exit 1
  fi
fi

_log_ok "=============================================================="
_log_ok "k3s + Cilium bootstrap complete."
_log_ok "  KUBECONFIG=${KUBECONFIG}"
_log_ok "  Cilium profile: Phase-1 (no kube-proxy replacement, Hubble flow-log mode only)"
_log_ok "  Next: run install.sh --deploy enterprise --runtime k8s"
_log_ok "  (kernel eBPF + Cilium CRD + CoreDNS DNSSEC/DoT preflight gates run automatically)"
_log_ok "=============================================================="
