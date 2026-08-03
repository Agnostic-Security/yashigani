#!/usr/bin/env bats
# Regression tests for the CoreDNS hardening pass-through (FIND-YTF412-011).
#
# Defect being locked down: install.sh::_apply_coredns_hardening invoked
# scripts/coredns-hardening-apply.sh with NO arguments, so --upstream-provider
# and --backup-dir (both supported by the script) were unreachable from the
# installer. A non-root operator therefore hit "Permission denied" writing the
# pre-patch backup into the root-owned default dir, the k8s install aborted,
# and the error text steered them to --skip-coredns-dnssec-probe, which
# disables the DNS-01 check entirely.
#
# Design invariant these tests must NOT relax (yashigani-k8s-dns-hardening-design
# -20260719.md §1, Nico, ratified): the forward hop MUST be tls:// with a pinned
# tls_servername. 'custom' changes WHO the trusted validating upstream is
# (internal rather than public) -- never WHETHER the hop is authenticated.

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  SCRIPT="${REPO_ROOT}/scripts/coredns-hardening-apply.sh"
}

# --- argument surface ------------------------------------------------------

@test "install.sh exposes the four coredns pass-through flags" {
  for f in --coredns-upstream-provider --coredns-upstream-addr \
           --coredns-tls-servername --coredns-backup-dir; do
    grep -q -- "$f)" "${REPO_ROOT}/install.sh"
  done
}

@test "install.sh no longer calls the hardening script with zero arguments" {
  # the original defect line
  ! grep -qE 'if ! bash "\$_script"; then' "${REPO_ROOT}/install.sh"
  grep -q '_hardening_args' "${REPO_ROOT}/install.sh"
}

@test "install.sh defaults the backup dir to a user-writable path when non-root" {
  grep -q 'XDG_STATE_HOME' "${REPO_ROOT}/install.sh"
}

# --- provider resolution ---------------------------------------------------

@test "custom provider requires both addr and servername" {
  run bash "$SCRIPT" --upstream-provider custom --upstream-addr 10.1.2.3 --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires BOTH --upstream-addr and --tls-servername"* ]]
}

@test "custom provider rejects a bare servername with no address" {
  run bash "$SCRIPT" --upstream-provider custom --tls-servername dns.internal.example --dry-run
  [ "$status" -ne 0 ]
}

@test "unknown provider is rejected and lists custom" {
  run bash "$SCRIPT" --upstream-provider nope --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"cloudflare|quad9|custom"* ]]
}

# --- Corefile rendering (requires a cluster with CoreDNS; skipped otherwise) --

_cluster_available() {
  command -v kubectl >/dev/null 2>&1 &&
    kubectl -n kube-system get configmap coredns >/dev/null 2>&1
}

@test "custom single upstream renders exactly one tls:// entry" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  run bash "$SCRIPT" --upstream-provider custom --upstream-addr 10.1.2.3 \
        --tls-servername dns.internal.example --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"forward . tls://10.1.2.3 {"* ]]
  # regression: an empty second upstream must never render a bare "tls://"
  [[ "$output" != *"tls:// {"* ]]
}

@test "custom dual upstream renders both tls:// entries" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  run bash "$SCRIPT" --upstream-provider custom --upstream-addr 10.1.2.3,10.1.2.4 \
        --tls-servername dns.internal.example --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"forward . tls://10.1.2.3 tls://10.1.2.4 {"* ]]
}

@test "custom still pins tls_servername (design invariant)" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  run bash "$SCRIPT" --upstream-provider custom --upstream-addr 10.1.2.3 \
        --tls-servername dns.internal.example --dry-run
  [[ "$output" == *"tls_servername dns.internal.example"* ]]
}

@test "cloudflare default is unchanged (no regression)" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  run bash "$SCRIPT" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"forward . tls://1.1.1.1 tls://1.0.0.1 {"* ]]
  [[ "$output" == *"tls_servername cloudflare-dns.com"* ]]
}

@test "no plaintext fallback forward is ever emitted (design doc §1)" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  run bash "$SCRIPT" --upstream-provider custom --upstream-addr 10.1.2.3 \
        --tls-servername dns.internal.example --dry-run
  # every external forward must be tls://; a bare "forward . <ip>" is the
  # spoofable path the design explicitly forbids adding "for resilience"
  ! [[ "$output" =~ forward\ \.\ [0-9] ]]
}

# --- backup dir ------------------------------------------------------------

@test "backup dir is honoured and writable under a normal user" {
  _cluster_available || skip "no CoreDNS configmap reachable"
  tmp="$(mktemp -d)"
  run bash "$SCRIPT" --backup-dir "$tmp" --dry-run
  [ "$status" -eq 0 ]
  rm -rf "$tmp"
}

# --- DNS resolver mode (host vs internet) ----------------------------------
# Tiago 2026-08-02: "just ask if the system is going to be set in a system with
# host resolver or internet resolver". install.sh cannot infer it — a plaintext
# Corefile forward is either a misconfiguration (internet) or entirely correct
# (host, where the node resolver does the encrypted upstream).

@test "install.sh exposes --dns-resolver-mode" {
  grep -q -- "--dns-resolver-mode)" "${REPO_ROOT}/install.sh"
}

@test "the wizard asks the topology instead of assuming" {
  grep -q "_prompt_dns_resolver_mode()" "${REPO_ROOT}/install.sh"
  grep -q "host resolver" "${REPO_ROOT}/install.sh"
  grep -q "internet resolver" "${REPO_ROOT}/install.sh"
}

@test "the prompt is invoked before the DNS gate, not after" {
  prompt_line=$(grep -n "^  _prompt_dns_resolver_mode$" "${REPO_ROOT}/install.sh" | cut -d: -f1)
  gate_line=$(grep -n "if ! _preflight_coredns_dnssec_dot; then" "${REPO_ROOT}/install.sh" | cut -d: -f1)
  [ -n "$prompt_line" ] && [ -n "$gate_line" ]
  [ "$prompt_line" -lt "$gate_line" ]
}

@test "host mode bypasses the Corefile tls:// string check" {
  grep -q 'DNS_RESOLVER_MODE:-internet}" == "host"' "${REPO_ROOT}/install.sh"
}

@test "internet mode remains the default (no silent weakening)" {
  grep -q 'DNS_RESOLVER_MODE:-internet' "${REPO_ROOT}/install.sh"
}

@test "interactive wizard default (bare Enter / no tty / bad input) is internet, not host" {
  # Regression lock for the 4.1.2 stitch CRITICAL: the interactive branch of
  # _prompt_dns_resolver_mode() used to default to 'host' on empty input AND
  # on unrecognised input, silently bypassing the DNS-01 tls:// gate that
  # only 'internet' mode verifies. Assert against the LIVE function body,
  # not a dead fallback expression elsewhere in the file.
  local fn
  fn="$(awk '/^_prompt_dns_resolver_mode\(\)/,/^}/' "${REPO_ROOT}/install.sh")"
  [ -n "$fn" ]
  # empty input must expand to the internet menu option
  echo "$fn" | grep -q 'case "\${_choice:-2}"'
  # the advertised default in the prompt must match
  echo "$fn" | grep -q 'Choice \[2\]'
  # the unrecognised-input arm must land on internet, never host
  echo "$fn" | awk '/\*\)/{f=1} f&&/DNS_RESOLVER_MODE=/{print; exit}' | grep -q '"internet"'
  # host must be reachable ONLY via the explicit menu arm
  [ "$(echo "$fn" | grep -c 'DNS_RESOLVER_MODE="host"')" -eq 1 ]
}

@test "host mode still records an operator attestation" {
  grep -q "OPERATOR ATTESTATION" "${REPO_ROOT}/install.sh"
}

@test "resolver mode is persisted to the install state file" {
  grep -q "DNS_RESOLVER_MODE=%s" "${REPO_ROOT}/install.sh"
}

@test "DNS-02 live resolution is NOT skipped in host mode" {
  # host mode must only bypass the DNS-01 string check; the live probe stands
  block=$(sed -n '/host-resolver topology/,/elif ! grep -qE/p' "${REPO_ROOT}/install.sh")
  [[ "$block" != *"return 0"* ]]
}

@test "non-interactive without the flag defaults to internet, not host" {
  block=$(sed -n '/_prompt_dns_resolver_mode()/,/^}/p' "${REPO_ROOT}/install.sh")
  [[ "$block" == *'NON_INTERACTIVE:-false}" == "true"'* ]]
  [[ "$block" == *'DNS_RESOLVER_MODE="internet"'* ]]
}
