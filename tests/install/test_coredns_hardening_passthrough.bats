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
  # host mode must only bypass the DNS-01 shape checks; the live probe stands.
  # Behavioral (was a sed-window text grep, which Su's 2026-08-03 review
  # flagged as fake-green): run the REAL function in host mode with the
  # cluster boundary stubbed dead — it must attempt DNS-02 and FAIL, never
  # return 0 on attestation alone.
  local corefile='.:53 {
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      fallthrough in-addr.arpa ip6.arpa
    }
    forward . 127.0.0.1:5353
    cache 30
}'
  local fn
  fn="$(awk '/^_preflight_coredns_dnssec_dot\(\)/{f=1} f{print} f&&/^}$/{exit}' "${REPO_ROOT}/install.sh")"
  run env FN_BODY="$fn" SYNTH_COREFILE="$corefile" DNS_MODE=host bash -c '
    log_info(){ echo "INFO: $*"; }; log_warn(){ echo "WARN: $*"; }
    log_error(){ echo "ERROR: $*"; }; log_success(){ echo "OK: $*"; }
    dry_print(){ :; }; require_cmd(){ :; }
    kubectl() {
      if [ "${1:-}" = "-n" ] && [ "${3:-}" = "get" ]; then printf "%s" "$SYNTH_COREFILE"; else return 1; fi
    }
    DNS_RESOLVER_MODE="$DNS_MODE"
    eval "$FN_BODY"
    _preflight_coredns_dnssec_dot
  '
  [ "$status" -ne 0 ]
  [[ "$output" == *"(DNS-02) FAILED"* ]]
}

@test "non-interactive without the flag defaults to internet, not host" {
  block=$(sed -n '/_prompt_dns_resolver_mode()/,/^}/p' "${REPO_ROOT}/install.sh")
  [[ "$block" == *'NON_INTERACTIVE:-false}" == "true"'* ]]
  [[ "$block" == *'DNS_RESOLVER_MODE="internet"'* ]]
}

# --- behavioral DNS-01 tests (stitch review 2026-08-03) --------------------
# Su's review flagged every resolver-mode test above as a static grep (a
# presence-of-string check can pass while the live function fails). These
# tests execute the REAL _preflight_coredns_dnssec_dot body with kubectl
# stubbed at its only boundary, and assert the actual DNS-01 verdict.

_run_dns01() {
  # $1 = DNS_RESOLVER_MODE, $2 = synthetic Corefile
  local fn
  fn="$(awk '/^_preflight_coredns_dnssec_dot\(\)/{f=1} f{print} f&&/^}$/{exit}' "${REPO_ROOT}/install.sh")"
  [ -n "$fn" ]
  SYNTH_COREFILE="$2" DNS_MODE="$1" bash -c '
    log_info(){ echo "INFO: $*"; }
    log_warn(){ echo "WARN: $*"; }
    log_error(){ echo "ERROR: $*"; }
    log_success(){ echo "OK: $*"; }
    dry_print(){ :; }
    require_cmd(){ :; }
    kubectl() {
      if [ "${1:-}" = "-n" ] && [ "${3:-}" = "get" ]; then
        printf "%s" "$SYNTH_COREFILE"
      else
        # any other kubectl call is DNS-02 territory — fail loudly so the
        # test can distinguish "passed DNS-01, reached DNS-02" from a
        # DNS-01 rejection
        echo "DNS02-BOUNDARY-REACHED" >&2
        return 1
      fi
    }
    DNS_RESOLVER_MODE="$DNS_MODE"
    eval "$FN_BODY"
    _preflight_coredns_dnssec_dot
  ' 2>&1 || true
}

@test "behavioral: host-mode Corefile (plain node-resolver forward, no tls://) PASSES DNS-01" {
  local corefile='.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      pods insecure
      fallthrough in-addr.arpa ip6.arpa
    }
    forward . 127.0.0.1:5353
    cache 30
    loop
    reload
}'
  local fn
  fn="$(awk '/^_preflight_coredns_dnssec_dot\(\)/{f=1} f{print} f&&/^}$/{exit}' "${REPO_ROOT}/install.sh")"
  run env FN_BODY="$fn" SYNTH_COREFILE="$corefile" DNS_MODE=host bash -c '
    log_info(){ echo "INFO: $*"; }; log_warn(){ echo "WARN: $*"; }
    log_error(){ echo "ERROR: $*"; }; log_success(){ echo "OK: $*"; }
    dry_print(){ :; }; require_cmd(){ :; }
    kubectl() {
      if [ "${1:-}" = "-n" ] && [ "${3:-}" = "get" ]; then printf "%s" "$SYNTH_COREFILE"; else echo "DNS02-BOUNDARY-REACHED" >&2; return 1; fi
    }
    DNS_RESOLVER_MODE="$DNS_MODE"
    eval "$FN_BODY"
    _preflight_coredns_dnssec_dot
  '
  # DNS-01 must PASS in host mode (the whole point of the mode); the run then
  # proceeds to DNS-02 and fails only at the stubbed cluster boundary.
  [[ "$output" == *"DNS-01 PASS (host mode)"* ]]
  [[ "$output" != *"FINDING (DNS-01)"* ]]
  # proof the run got PAST DNS-01: it must fail at the stubbed DNS-02
  # cluster boundary (namespace create), not at a DNS-01 rejection
  [[ "$output" == *"(DNS-02) FAILED"* ]]
}

@test "behavioral: internet-mode hardened Corefile (tls:// + tls_servername) PASSES DNS-01" {
  local corefile='.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      fallthrough in-addr.arpa ip6.arpa
    }
    forward . tls://1.1.1.1 tls://1.0.0.1 {
      tls_servername cloudflare-dns.com
      health_check 5s
    }
    cache 30
}'
  local fn
  fn="$(awk '/^_preflight_coredns_dnssec_dot\(\)/{f=1} f{print} f&&/^}$/{exit}' "${REPO_ROOT}/install.sh")"
  run env FN_BODY="$fn" SYNTH_COREFILE="$corefile" DNS_MODE=internet bash -c '
    log_info(){ echo "INFO: $*"; }; log_warn(){ echo "WARN: $*"; }
    log_error(){ echo "ERROR: $*"; }; log_success(){ echo "OK: $*"; }
    dry_print(){ :; }; require_cmd(){ :; }
    kubectl() {
      if [ "${1:-}" = "-n" ] && [ "${3:-}" = "get" ]; then printf "%s" "$SYNTH_COREFILE"; else echo "DNS02-BOUNDARY-REACHED" >&2; return 1; fi
    }
    DNS_RESOLVER_MODE="$DNS_MODE"
    eval "$FN_BODY"
    _preflight_coredns_dnssec_dot
  '
  [[ "$output" == *"DNS-01 PASS: CoreDNS external-zone forward uses tls://"* ]]
  [[ "$output" == *"(DNS-02) FAILED"* ]]
}

@test "behavioral: internet-mode PLAINTEXT Corefile is REJECTED at DNS-01 (never reaches DNS-02)" {
  local corefile='.:53 {
    errors
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      fallthrough in-addr.arpa ip6.arpa
    }
    forward . /etc/resolv.conf
    cache 30
}'
  local fn
  fn="$(awk '/^_preflight_coredns_dnssec_dot\(\)/{f=1} f{print} f&&/^}$/{exit}' "${REPO_ROOT}/install.sh")"
  run env FN_BODY="$fn" SYNTH_COREFILE="$corefile" DNS_MODE=internet bash -c '
    log_info(){ echo "INFO: $*"; }; log_warn(){ echo "WARN: $*"; }
    log_error(){ echo "ERROR: $*"; }; log_success(){ echo "OK: $*"; }
    dry_print(){ :; }; require_cmd(){ :; }
    kubectl() {
      if [ "${1:-}" = "-n" ] && [ "${3:-}" = "get" ]; then printf "%s" "$SYNTH_COREFILE"; else echo "DNS02-BOUNDARY-REACHED" >&2; return 1; fi
    }
    DNS_RESOLVER_MODE="$DNS_MODE"
    eval "$FN_BODY"
    _preflight_coredns_dnssec_dot
  '
  [ "$status" -ne 0 ]
  [[ "$output" == *"FINDING (DNS-01)"* ]]
  [[ "$output" != *"(DNS-02) FAILED"* ]]
}
