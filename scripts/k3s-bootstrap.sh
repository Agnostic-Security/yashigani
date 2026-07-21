#!/usr/bin/env bash
# scripts/k3s-bootstrap.sh — reproducible k3s + Cilium stand-up.
#
# Used for the gate cluster (release-gate CI legs) and documented as a
# reference for customers standing up a new k8s cluster for Yashigani.
# Cilium is the ratified CNI standard (2026-07-19 design). Bootstraps, in
# order:
#   1. k3s server with the built-in CNI + kube-proxy + NetworkPolicy
#      controller DISABLED (--flannel-backend=none --disable-network-policy
#      --disable-kube-proxy) — flannel/kindnet silently no-op NetworkPolicy
#      (FINDING-V412-UNIVERSAL-004); we do not want the default CNI, a second
#      NetworkPolicy controller, OR a second kube-proxy fighting Cilium.
#      NOTE (2026-07-20, F-K8S-BOOT-3): an earlier "Phase-1: no kube-proxy
#      replacement" profile (kube-proxy left running, Cilium only doing
#      CNI/NetworkPolicy) is NON-VIABLE on k3s — k3s's built-in kube-proxy and
#      Cilium's own eBPF service handling both try to own ClusterIP
#      translation and conflict. The only viable profile on k3s is FULL
#      kube-proxy replacement: `--disable-kube-proxy` at the k3s layer +
#      `kubeProxyReplacement=true` in the Cilium chart.
#   2. Cilium, pinned chart version, full kube-proxy-replacement profile
#      (kubeProxyReplacement=true, k8sServiceHost/k8sServicePort pointed at
#      the node's own API server since kube-proxy is gone),
#      operator.replicas=1 (F-K8S-BOOT-2: the chart defaults to 2 replicas
#      for HA leader-election; on a single-node cluster the 2nd replica can
#      never schedule and only adds noise), Hubble in flow-log mode only
#      (agent-local `hubble observe`; relay/UI are OFF — smaller footprint).
#   3. Host firewall: if ufw is active, open inbound from the Cilium pod CIDR
#      to the host (2026-07-20 finding: ufw's default `deny (incoming)`
#      policy silently drops ALL pod->host traffic, including pod ->
#      ClusterIP-DNAT'd-to-hostNetwork-apiserver on :6443 — this is NOT a
#      Cilium bug, it is the host firewall dropping the SYN before Cilium
#      ever sees a reply-path problem. Without this rule coredns can never
#      reach "kubernetes.default", node never goes fully healthy, and NO
#      workload can run, no matter how correct the Cilium config is).
#   4. Stale-chain hygiene (fresh installs only, 2026-07-20 finding): if this
#      is a genuinely first-time k3s install on this host, purge any
#      leftover CILIUM_*/OLD_CILIUM_* iptables chains (nat/filter/mangle/raw)
#      and their cilium-feeder jump rules before Cilium ever starts. Cilium's
#      periodic iptables-full-reconciliation controller does an atomic
#      rename-old/install-new/delete-stale-entries dance; if a PRIOR Cilium
#      install on this host (e.g. an earlier failed bootstrap attempt that
#      was `helm uninstall`'d) left orphaned chains behind, the very first
#      reconciliation cycle can get stuck trying to delete specific rule text
#      from the orphan chain that doesn't match (`iptables: Bad rule`),
#      failing forever and leaving the LIVE masquerade/SNAT chains
#      permanently empty — pod egress to any hostNetwork/non-cluster
#      destination silently breaks while the Cilium pod itself stays
#      1/1 Running (this class of bug is invisible to a DaemonSet-Ready
#      check, which is why step 6 below adds a black-box connectivity test).
#      We do NOT do this cleanup on top of an already-active k3s (that would
#      rip chains out from under a healthy, already-running Cilium).
#   5. Wait-gates: Cilium agent DaemonSet + operator Deployment Ready, node
#      Ready (only meaningful once CNI is up), CoreDNS Ready.
#   6. Black-box connectivity smoke test (2026-07-20 finding): DaemonSet/
#      Deployment "Ready" only proves the container's own liveness/readiness
#      probe passed — it does NOT prove pod-to-ClusterIP or pod-to-DNS
#      actually works (that is exactly the failure mode this hardening
#      round fixes: Cilium agent was 1/1 Running the entire time its
#      reconciliation loop was stuck). Run a disposable pod that must reach
#      https://<cluster-ip>:443/healthz (TCP+TLS must complete — 401 is a
#      PASS, timeout is a FAIL) and resolve+reach kube-dns. Fail loud, with
#      remediation hints, if either check fails.
#   7. CoreDNS DNSSEC/DoT hardening via scripts/coredns-hardening-apply.sh
#      (single source of truth — do not duplicate the Corefile content here).
#
# Idempotent: safe to re-run against an already-bootstrapped cluster (skips
# k3s install if already active, `helm upgrade --install` for Cilium — never
# `--reuse-values`, see F-K8S-BOOT-4 below — and coredns-hardening-apply.sh
# is itself idempotent).
#
# F-K8S-BOOT-1 (helm PATH discovery): helm may be installed at
# /usr/local/bin/helm rather than a system PATH dir depending on how it was
# installed; PATH is explicitly set below to include it before `require_cmd
# helm` runs.
#
# F-K8S-BOOT-4 (avoid `helm upgrade --reuse-values`): --reuse-values merges
# the OLD release's values with new --set flags at the Go-template layer: if
# a value key that a NEW --set flag depends on was absent from the old
# release (e.g. adding kubeProxyReplacement-dependent keys to a release that
# predates them), the merge can nil-pointer-deref inside the chart templates.
# This script always passes the FULL, explicit set of --set flags on every
# run instead — safe, and every run's config is fully reproducible from this
# file alone (no drift from a previous run's implicit state).
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
#   CILIUM_POD_CIDR            pod CIDR handed to Cilium's cluster-pool IPAM
#                              AND used to scope the ufw allow rule (default
#                              10.0.0.0/8 — matches the Cilium chart's own
#                              ipam.operator.clusterPoolIPv4PodCIDRList
#                              default, pinned explicitly here rather than
#                              left implicit so the firewall rule can never
#                              silently drift out of sync with the CNI config)
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
CILIUM_POD_CIDR="${CILIUM_POD_CIDR:-10.0.0.0/8}"
CILIUM_POD_CIDR_MASK_SIZE="${CILIUM_POD_CIDR_MASK_SIZE:-24}"

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
_FRESH_K3S_INSTALL=false
if systemctl is-active --quiet k3s 2>/dev/null; then
  _log_ok "k3s service already active — skipping install."
else
  _FRESH_K3S_INSTALL=true
  _log_info "Installing k3s ${K3S_VERSION} (flannel disabled, network-policy controller disabled, kube-proxy disabled — Cilium owns all three)..."
  # Supply-chain note (S6): get.k3s.io's own wrapper script has no separately
  # published checksum to pre-verify. Pin the exact release via
  # INSTALL_K3S_VERSION, then VERIFY the installed k3s binary's sha256
  # against the upstream-published checksum for that exact pinned release
  # (below) before trusting this cluster with anything.
  #
  # --disable-kube-proxy (F-K8S-BOOT-3): required — Cilium runs in full
  # kube-proxy-replacement mode below, and k3s's built-in kube-proxy must not
  # also be installing iptables/ipvs rules for the same Services.
  curl -fsSL https://get.k3s.io | \
    INSTALL_K3S_VERSION="$K3S_VERSION" \
    INSTALL_K3S_EXEC="server --flannel-backend=none --disable-network-policy --disable-kube-proxy --write-kubeconfig-mode=0600" \
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
# Step 2b: derive this node's InternalIP — required for Cilium's
# k8sServiceHost/k8sServicePort when kube-proxy is disabled (Cilium can no
# longer rely on kube-proxy's iptables DNAT to find the apiserver; it must be
# told directly where to reach it). Read from the node object itself rather
# than guessing from `hostname -I` / a hardcoded interface name — the node
# object already exists at this point (Step 2 waited for it) even though the
# node isn't Ready yet.
# ---------------------------------------------------------------------------
_log_info "Deriving node InternalIP for Cilium k8sServiceHost..."
NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
if [[ -z "$NODE_IP" ]]; then
  _log_err "Could not determine this node's InternalIP from 'kubectl get nodes' — cannot configure Cilium's k8sServiceHost."
  exit 1
fi
_log_ok "Node InternalIP: ${NODE_IP}"

# ---------------------------------------------------------------------------
# Step 2c: host firewall — allow pod CIDR -> host (2026-07-20 finding).
# ufw's default `deny (incoming)` policy drops ALL pod-originated traffic to
# the host, including pod -> ClusterIP-DNAT'd-to-hostNetwork-apiserver on
# :6443 (k3s's apiserver is NOT a pod — it's a hostNetwork process — so any
# pod reaching it via the kubernetes.default ClusterIP is, from the host
# firewall's point of view, ordinary inbound traffic to a local port, not
# "routed" traffic). Cilium's own CILIUM_INPUT iptables chain does not add a
# broad allow for this (it only matches proxy-marked packets), so without an
# explicit host-firewall rule, coredns can NEVER reach "kubernetes.default",
# the node can never go fully healthy, and no workload can run — regardless
# of how correctly Cilium itself is configured. Only touch ufw if it is
# actually installed and active; skip silently (not an error) otherwise.
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  if ufw status 2>/dev/null | grep -qF "$CILIUM_POD_CIDR"; then
    _log_ok "ufw already allows inbound from pod CIDR ${CILIUM_POD_CIDR} — skipping."
  else
    _log_info "ufw is active — adding allow rule for pod CIDR ${CILIUM_POD_CIDR} -> host..."
    ufw allow from "$CILIUM_POD_CIDR" comment 'k3s/cilium pod CIDR to host (apiserver/hostNetwork/NodePort)' >/dev/null
    _log_ok "ufw allow rule added for ${CILIUM_POD_CIDR}."
  fi
else
  _log_info "ufw not installed/active — skipping host-firewall step (nothing to do)."
fi

# ---------------------------------------------------------------------------
# Step 2d: stale iptables-chain hygiene — FRESH INSTALLS ONLY (2026-07-20
# finding). If a PRIOR Cilium install on this host was torn down (e.g. an
# earlier failed bootstrap attempt, `helm uninstall`) without its own
# cleanup tooling, it can leave orphaned CILIUM_*/OLD_CILIUM_* iptables
# chains behind — `helm uninstall` deletes the DaemonSet but does NOT run
# Cilium's iptables/BPF cleanup by design (avoids a connectivity gap during
# normal upgrades). A brand-new Cilium agent's first-ever iptables full
# reconciliation does an atomic rename-old/install-new/delete-stale-entries
# dance; if it finds a pre-existing orphan chain whose content doesn't match
# what it expects to selectively delete, the atomic delete fails
# ("iptables: Bad rule") and the WHOLE reconciliation aborts forever, every
# ~10s, leaving the live masquerade/SNAT chains permanently EMPTY — while
# the cilium-agent container itself stays 1/1 Running the entire time (its
# liveness/readiness probe doesn't check this). We only do this purge when
# we know Cilium hasn't started yet on this host (i.e. a genuinely fresh k3s
# install, per $_FRESH_K3S_INSTALL from Step 1) — never on top of an
# already-active k3s, which would rip chains out from under a healthy,
# already-running Cilium agent.
# ---------------------------------------------------------------------------
if [[ "$_FRESH_K3S_INSTALL" == "true" ]]; then
  _log_info "Fresh k3s install — purging any orphaned Cilium iptables chains from prior attempts..."
  for _t in filter mangle raw nat; do
    # Remove cilium-feeder jump rules from built-in chains first (a chain
    # can't be deleted with -X while still referenced).
    while IFS= read -r _feeder_rule; do
      [[ -z "$_feeder_rule" ]] && continue
      _chain="${_feeder_rule%% *}"
      _spec="${_feeder_rule#* }"
      # word-splitting of $_spec is intentional here (building an iptables argv)
      # shellcheck disable=SC2086
      iptables -t "$_t" -D "$_chain" $_spec 2>/dev/null || true
    done < <(iptables -t "$_t" -S 2>/dev/null | grep -E "^-A (INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) .*cilium-feeder" | sed 's/^-A //')
    # Then flush + delete every CILIUM_*/OLD_CILIUM_* custom chain.
    for _c in $(iptables -t "$_t" -S 2>/dev/null | grep "^-N" | awk '{print $2}' | grep -i cilium); do
      iptables -t "$_t" -F "$_c" 2>/dev/null || true
    done
    for _c in $(iptables -t "$_t" -S 2>/dev/null | grep "^-N" | awk '{print $2}' | grep -i cilium); do
      iptables -t "$_t" -X "$_c" 2>/dev/null || true
    done
  done
  _log_ok "Orphaned Cilium iptables chains purged (Cilium will build fresh ones with nothing stale to conflict with)."
else
  _log_info "k3s was already active — leaving existing iptables chains alone (Cilium already owns them)."
fi

# ---------------------------------------------------------------------------
# Step 3: Cilium via Helm — idempotent (upgrade --install, never
# --reuse-values, see F-K8S-BOOT-4 in the header comment). Full kube-proxy
# replacement profile (F-K8S-BOOT-3), operator.replicas=1 for single-node
# (F-K8S-BOOT-2), rate-limited + atomic client per the container-runtime
# verification SOP (avoids the default kubectl 50qps/100burst limiter
# tripping under this many concurrently-created resources).
# ---------------------------------------------------------------------------
_log_info "Installing/upgrading Cilium ${CILIUM_CHART_VERSION} (full kube-proxy replacement, operator.replicas=1, Hubble flow-log mode only)..."
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true  # no-op if already added w/ same URL
helm repo update cilium >/dev/null

if ! helm upgrade --install cilium cilium/cilium \
      --version "$CILIUM_CHART_VERSION" \
      --namespace kube-system \
      --set kubeProxyReplacement=true \
      --set k8sServiceHost="$NODE_IP" \
      --set k8sServicePort=6443 \
      --set operator.replicas=1 \
      --set ipam.operator.clusterPoolIPv4PodCIDRList[0]="$CILIUM_POD_CIDR" \
      --set ipam.operator.clusterPoolIPv4MaskSize="$CILIUM_POD_CIDR_MASK_SIZE" \
      --set hubble.enabled=true \
      --set hubble.relay.enabled=false \
      --set hubble.ui.enabled=false \
      --burst-limit 1000 --qps 500 \
      --atomic --wait --wait-for-jobs --timeout 20m; then
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
# Step 4b: black-box connectivity smoke test (2026-07-20 finding). All the
# wait-gates above only prove each Deployment/DaemonSet's OWN
# liveness/readiness probe passed — they do NOT prove pod-to-ClusterIP or
# pod-to-DNS actually works end to end. That is precisely the failure mode
# this hardening round fixes: the Cilium agent was 1/1 Running the entire
# time its iptables reconciliation loop was stuck, and CoreDNS's rollout
# would have hung on this exact class of bug (which is why this check exists
# as an explicit, fail-loud gate rather than being "implied" by the rollout
# waits above). Run a disposable pod that must (a) complete a TCP+TLS
# handshake against the apiserver ClusterIP — a 401 is a PASS (proves the
# path works, just no token), a timeout is a FAIL — and (b) resolve AND
# reach kube-dns for the same Service.
# ---------------------------------------------------------------------------
_log_info "Running black-box connectivity smoke test (pod -> apiserver ClusterIP, pod -> kube-dns)..."
_smoke_pod="k3s-bootstrap-smoke-test"
kubectl delete pod "$_smoke_pod" --ignore-not-found=true --now >/dev/null 2>&1 || true
_cleanup_smoke_pod() { kubectl delete pod "$_smoke_pod" --ignore-not-found=true --now >/dev/null 2>&1 || true; }
trap _cleanup_smoke_pod EXIT

_apiserver_cluster_ip="$(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}')"
_kubedns_cluster_ip="$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"

if [[ -z "$_apiserver_cluster_ip" ]]; then
  _log_err "Could not determine the 'kubernetes' Service ClusterIP — cannot run the connectivity smoke test."
  exit 1
fi

kubectl run "$_smoke_pod" --image=busybox:1.37 --restart=Never --command -- sh -c "
  wget -T5 -O- --no-check-certificate https://${_apiserver_cluster_ip}:443/healthz >/dev/null 2>/tmp/wget.err
  echo \"APISERVER_RC=\$?\"
  cat /tmp/wget.err
  if [[ -n '${_kubedns_cluster_ip}' ]]; then
    nslookup kubernetes.default.svc.cluster.local ${_kubedns_cluster_ip} >/tmp/nslookup.out 2>&1
    echo \"DNS_RC=\$?\"
    cat /tmp/nslookup.out
  fi
" >/dev/null 2>&1 || true

_smoke_wait=0
until [[ "$(kubectl get pod "$_smoke_pod" -o jsonpath='{.status.phase}' 2>/dev/null)" =~ ^(Succeeded|Failed)$ ]]; do
  _smoke_wait=$((_smoke_wait + 1))
  if [[ "$_smoke_wait" -ge 30 ]]; then
    _log_err "Connectivity smoke-test pod did not complete within 60s."
    kubectl describe pod "$_smoke_pod" >&2 || true
    exit 1
  fi
  sleep 2
done

_smoke_log="$(kubectl logs "$_smoke_pod" 2>&1 || true)"
_api_rc="$(printf '%s\n' "$_smoke_log" | sed -n 's/^APISERVER_RC=//p' | head -1)"
_dns_rc="$(printf '%s\n' "$_smoke_log" | sed -n 's/^DNS_RC=//p' | head -1)"

# wget exit 1 for "server returned error" (e.g. 401 Unauthorized) IS a pass —
# it means TCP+TLS completed and the apiserver answered. Only a hard failure
# to connect (timeout, connection refused at a lower layer produces a
# different wget message) is treated as FAIL by grepping the captured
# stderr for a definitive success signal instead of relying on the exit code
# alone.
if printf '%s\n' "$_smoke_log" | grep -qE 'HTTP/1\.1 [0-9]{3}|WWW-Authenticate'; then
  _log_ok "Pod -> apiserver ClusterIP (https://${_apiserver_cluster_ip}:443/healthz): TCP+TLS handshake completed."
else
  _log_err "=============================================================="
  _log_err "FAIL: pod could not complete a TCP+TLS handshake against the apiserver ClusterIP."
  _log_err "This means pod-to-ClusterIP (and therefore pod-to-hostNetwork-service) traffic is BROKEN."
  _log_err "Smoke-test pod output:"
  printf '%s\n' "$_smoke_log" >&2
  _log_err "--------------------------------------------------------------"
  _log_err "Known causes (2026-07-20 incident) and how to check each:"
  _log_err "  1. Host firewall (ufw) dropping pod-CIDR -> host traffic:"
  _log_err "       ufw status verbose ; journalctl -k --since '5 min ago' | grep 'UFW BLOCK'"
  _log_err "     Fix: ufw allow from ${CILIUM_POD_CIDR}"
  _log_err "  2. Cilium's iptables full-reconciliation loop stuck (orphaned chains"
  _log_err "     from a prior install left over from before this run — should not"
  _log_err "     happen on a fresh install since Step 2d purges them, but check):"
  _log_err "       kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose | grep -A2 iptables-reconciliation"
  _log_err "       iptables -t nat -S | grep -i cilium"
  _log_err "  3. Stale conntrack / already-broken pods retrying against the OLD (broken)"
  _log_err "     path: if you just applied a network fix to an ALREADY-RUNNING cluster"
  _log_err "     (repair, not a fresh bootstrap), existing pods (esp. coredns) may keep"
  _log_err "     getting blocked by stale conntrack state even after the fix. Recreate them:"
  _log_err "       kubectl delete pod -n kube-system -l k8s-app=kube-dns"
  _log_err "=============================================================="
  exit 1
fi

if [[ -n "$_kubedns_cluster_ip" ]]; then
  if [[ "$_dns_rc" == "0" ]]; then
    _log_ok "Pod -> kube-dns (${_kubedns_cluster_ip}): resolve+reach succeeded."
  else
    _log_err "FAIL: pod could not resolve+reach kube-dns at ${_kubedns_cluster_ip}."
    _log_err "Smoke-test pod output:"
    printf '%s\n' "$_smoke_log" >&2
    _log_err "See remediation hints above (same class of bug — DNS depends on the same pod->ClusterIP path)."
    exit 1
  fi
fi

trap - EXIT
_cleanup_smoke_pod
_log_ok "Black-box connectivity smoke test passed."

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
_log_ok "  Cilium profile: full kube-proxy replacement, operator.replicas=1, Hubble flow-log mode only"
_log_ok "  Next: run install.sh --deploy enterprise --runtime k8s"
_log_ok "  (kernel eBPF + Cilium CRD + CoreDNS DNSSEC/DoT preflight gates run automatically)"
_log_ok "=============================================================="
