#!/bin/sh
# Yashigani — Caddy egress restriction entrypoint
# YSG-RISK-061 (2026-05-25): iptables OUTPUT allowlist
# BUG-V243-CADDY-IPV6-IPTABLES (2026-05-26): IPv6 BLOCKED (not allowlisted)
#
# PURPOSE
#   Enforce a network egress allowlist for the Caddy container before starting
#   the Caddy process. Blocks all outbound TCP/UDP except to explicitly
#   permitted destinations.
#
# ADDRESS FAMILY POSTURE — Tiago directives 2026-05-26
#   Yashigani's internal mesh is IPv4-only by design ("anything else internally
#   is ipv4"). However, Caddy at the EDGE accepts IPv6 inbound from internet
#   clients ("allow ipv6 in the front to connect to the internet if the client
#   wants to"). Rationale: IPv6 never gained meaningful deployment traction
#   in the ecosystems Yashigani targets (industry moving toward IPv7); but
#   refusing IPv6 inbound from clients would needlessly drop legitimate
#   connections from dual-stack ISPs that may have routed the client's
#   request over v6.
#
#   What this means for the OUTPUT chain:
#     - iptables (IPv4): full allowlist (loopback, ESTABLISHED, DNS, bridge
#       subnets, ACME, operator extras) — Caddy's IPv4 operational path.
#     - ip6tables (IPv6): MINIMAL — only loopback + ESTABLISHED,RELATED.
#       Loopback is defensive (intra-container). ESTABLISHED,RELATED is the
#       essential allow: when an IPv6 client connects INBOUND to Caddy,
#       response packets must be able to go OUT — without this, the TCP
#       handshake completes but SYN-ACK is dropped and the connection hangs.
#       NO new IPv6 outbound allowed (no DNS, no ACME, no bridge subnets,
#       no operator extras) — Caddy does not initiate IPv6 connections.
#     - LOG rule on CADDY_EGRESS_BLOCKED_V6 catches any NEW IPv6 outbound
#       attempt (canary: in a healthy install this never fires; if it does,
#       investigate as a possible bypass attempt or upstream misconfiguration).
#
#   Internal mesh networks have `enable_ipv6: false` in docker-compose.yml —
#   that's the kernel-level guarantee that in-mesh IPv6 routing is impossible.
#   The `edge` network keeps IPv6 enabled (or default) so Caddy can receive
#   IPv6 inbound from internet clients.
#
# LEGITIMATE CADDY EGRESS DESTINATIONS
#   1. Loopback (lo) — admin unix socket healthchecks
#   2. In-mesh Docker bridge networks (caddy_internal, obs, edge) — resolved at
#      runtime from `ip route` kernel routes; no DNS lookup required
#   3. Docker embedded DNS — 127.0.0.11:53/udp (always localhost)
#   4. ACME providers — resolved at startup (acme mode only; controlled by
#      YASHIGANI_TLS_MODE=acme). Default allowlist:
#      acme-v02.api.letsencrypt.org:443
#      acme-staging-v02.api.letsencrypt.org:443
#   5. OCSP stapling — http://r11.o.lencr.org:80 + r10.o.lencr.org:80 (Let's
#      Encrypt OCSP; only in acme mode). Caddy auto-staples OCSP.
#   6. ESTABLISHED/RELATED — return traffic for inbound client connections on
#      :80/:443 (these are response packets, not new connections)
#   Operators may extend the ACME list via YASHIGANI_CADDY_EGRESS_ALLOWLIST env.
#
# DESIGN NOTES
#   - NET_ADMIN capability is required for iptables OUTPUT manipulation.
#   - If iptables fails (e.g. Podman rootless without --privileged), we log a
#     warning and start Caddy WITHOUT restrictions (graceful degradation).
#   - Docker bridge subnets vary per deployment; we enumerate them at startup
#     from the kernel routing table to avoid hardcoding CIDRs.
#   - The ESTABLISHED/RELATED rule handles response packets for Caddy's own
#     inbound listeners (:80/:443/:8444/:8445) — without it, Caddy cannot send
#     replies back to clients even if OUTPUT is DROP.
#   - LOG target before final DROP: aids debugging when a new upstream is added
#     to Caddyfile without updating this allowlist.
#   - Rootless Podman: the process runs in a user network namespace. iptables
#     may require /proc/net/ip_tables_names or nft backend. If iptables -P OUTPUT
#     DROP fails, we fall through gracefully (logged as WARN).
#
# TRADE-OFF (NET_ADMIN)
#   NET_ADMIN was previously absent (cap_add: [NET_BIND_SERVICE] only).
#   NET_ADMIN allows iptables manipulation within the container's network
#   namespace — it does NOT grant access to the host network stack.
#   Docker/Podman enforce this via Linux network namespaces. Accepted per
#   YSG-RISK-061 (Tiago 2026-05-25).
#
# OPERATOR OVERRIDE
#   YASHIGANI_CADDY_EGRESS_ALLOWLIST — comma-separated list of host:port pairs
#   to add to the ACME allowlist. Example:
#     YASHIGANI_CADDY_EGRESS_ALLOWLIST=acme-v02.api.letsencrypt.org:443,operator-ca.example:443
#   Default: acme-v02.api.letsencrypt.org:443,acme-staging-v02.api.letsencrypt.org:443

set -eu

log() {
    printf '[caddy-entrypoint] %s\n' "$*" >&2
}

warn() {
    printf '[caddy-entrypoint] WARN: %s\n' "$*" >&2
}

apply_egress_rules() {
    # ── Step 1: probe NET_ADMIN availability (IPv4) ──────────────────────────
    # Try to set OUTPUT default policy. If this fails, we have no NET_ADMIN and
    # must skip all iptables setup. Caddy still starts — just without egress
    # restrictions (documented limitation for rootless Podman).
    if ! iptables -P OUTPUT DROP 2>/dev/null; then
        warn "iptables OUTPUT policy modification failed — container lacks NET_ADMIN."
        warn "Egress restrictions NOT applied. Caddy starts without OUTPUT allowlist."
        warn "Rootless Podman limitation: re-run with --cap-add NET_ADMIN or use K8s NetworkPolicy."
        return 0
    fi
    log "NET_ADMIN available — applying iptables OUTPUT allowlist (IPv4)."

    # LAURA-V243-004 (MED): canary observability check.
    # The ip6tables LOG target (CADDY_EGRESS_BLOCKED_V6) uses kernel printk,
    # which is per-network-namespace by default on modern kernels. Container-
    # namespace printk messages do NOT reach the host's journald unless the
    # host sysctl `net.netfilter.nf_log_all_netns=1`. If it's 0 (default on
    # Ubuntu 24.04 + most distros), the LOG canary fires inside the container
    # but is invisible to the operator running `journalctl -k` on the host.
    # DROP enforcement is unaffected (this is observability, not enforcement).
    #
    # We can READ /proc/sys/net/netfilter/nf_log_all_netns from inside the
    # container (read-only host sysctl exposure) without any extra privileges.
    # If 0, surface a clear WARN with the exact remediation command the
    # operator needs to run on the host.
    _nf_log_all_netns_path="/proc/sys/net/netfilter/nf_log_all_netns"
    if [ -r "$_nf_log_all_netns_path" ]; then
        _nf_log_val="$(cat "$_nf_log_all_netns_path" 2>/dev/null || echo "?")"
        if [ "$_nf_log_val" = "0" ]; then
            warn "Host sysctl nf_log_all_netns=0 — ip6tables LOG (CADDY_EGRESS_BLOCKED_V6)"
            warn "  will fire inside this container but will NOT reach host journald."
            warn "  Enforcement (DROP) is unaffected; only the canary observability is lost."
            warn "  Operator remediation on the HOST (one-shot + persistent):"
            warn "    sudo sysctl -w net.netfilter.nf_log_all_netns=1"
            warn "    echo 'net.netfilter.nf_log_all_netns=1' | sudo tee /etc/sysctl.d/90-yashigani-nflog.conf"
        elif [ "$_nf_log_val" = "1" ]; then
            log "nf_log_all_netns=1 — ip6tables LOG canary WILL reach host journald."
        fi
    fi

    # ── Step 1b: IPv6 OUTPUT — DROP all NEW outbound; allow only ESTABLISHED ─
    # Tiago directives 2026-05-26:
    #   "do not implement ipv inside of the yashigani network ... block it"
    #   "allow ipv6 in the front to connect to the internet if the client wants to"
    #
    # Combined posture: ip6tables OUTPUT policy = DROP (so no NEW outbound
    # IPv6 connection from Caddy can succeed — no ACME-over-AAAA, no operator
    # outbound, no internal mesh routing). BUT we MUST allow loopback and
    # ESTABLISHED,RELATED so that when an internet client connects INBOUND
    # to Caddy over IPv6 (legitimate, per directive), Caddy can send response
    # packets back. Without ESTABLISHED ACCEPT on ip6tables OUTPUT, the
    # SYN-ACK and data packets to the v6 client are dropped — the inbound
    # connection appears to hang from the client's perspective.
    #
    # If ip6tables itself is unavailable in this namespace (kernel
    # CONFIG_IP6_NF_IPTABLES absent, IPv6 disabled via sysctl, NET_ADMIN
    # missing for v6) that's the SAFER state because IPv6 has no functional
    # stack — log as INFO, not WARN.
    IPV6_TABLE=0
    if ip6tables -P OUTPUT DROP 2>/dev/null; then
        IPV6_TABLE=1
        # Flush any rules that might have been inherited from another run
        # (defensive — the OUTPUT chain is the one we control).
        ip6tables -F OUTPUT 2>/dev/null || true
        # Loopback — defensive intra-container (::1 → ::1).
        ip6tables -A OUTPUT -o lo -j ACCEPT
        # ESTABLISHED,RELATED — response packets for IPv6 inbound clients.
        # This is the ONLY non-loopback ACCEPT; new outbound IPv6 is DROPped.
        ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        log "ip6tables OUTPUT: DROP policy + loopback + ESTABLISHED only."
        log "  (Internet IPv6 inbound clients receive response packets;"
        log "   Caddy cannot initiate NEW IPv6 outbound — no ACME/DNS/mesh over v6.)"
    else
        log "ip6tables not applicable — kernel/namespace has no usable IPv6 stack (intended state)."
    fi

    # ── Step 2: Allow loopback (IPv4 only) ─────────────────────────────────
    # All Caddy admin socket interactions (healthcheck, reload) go via loopback.
    # IPv6 loopback (::1) is deliberately NOT allowed — Caddy and its callers
    # use 127.0.0.1.
    iptables -A OUTPUT -o lo -j ACCEPT
    log "egress allow: loopback (IPv4 only — IPv6 blocked by policy)"

    # ── Step 3: Allow ESTABLISHED/RELATED (IPv4 only) ────────────────────────
    # Required for Caddy's inbound IPv4 listeners (:80/:443/:8444/:8445) to send
    # response packets. Without this, SYN-ACK and data packets to clients are
    # dropped by the OUTPUT chain. IPv6 ESTABLISHED is NOT allowed — Caddy's
    # listeners should not accept IPv6 (Caddyfile binds IPv4); any IPv6 inbound
    # is a misconfiguration and we will not silently support response traffic
    # for it.
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log "egress allow: ESTABLISHED,RELATED (IPv4 only — response packets for inbound listeners)"

    # ── Step 4: Allow Docker embedded DNS (IPv4 only) ──────────────────────
    # Docker's embedded resolver is 127.0.0.11 (IPv4-only by Docker design).
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    log "egress allow: DNS → 127.0.0.11:53 (Docker embedded resolver, IPv4 only)"

    # ── Step 5: Allow Docker bridge subnets (IPv4 only) ────────────────────
    # Caddy proxies to in-mesh services (gateway, backoffice, open-webui,
    # grafana, prometheus) on Docker bridge networks. We enumerate IPv4
    # subnets from the kernel routing table. IPv6 routes (if any — `ip -6
    # route show`) are deliberately ignored; compose networks are configured
    # with enable_ipv6: false to prevent IPv6 mesh routing entirely.
    bridge_subnets_v4=$(ip route show 2>/dev/null | awk '/proto kernel/ {print $1}')
    if [ -n "$bridge_subnets_v4" ]; then
        for subnet in $bridge_subnets_v4; do
            iptables -A OUTPUT -d "$subnet" -j ACCEPT
            log "egress allow: Docker bridge subnet $subnet (IPv4)"
        done
    else
        warn "No IPv4 bridge subnets found via ip route — in-mesh egress may be blocked."
    fi

    # ── Step 6: Allow ACME providers + operator allowlist (IPv4 only) ────
    # Default ACME list: Let's Encrypt prod + staging + OCSP responders.
    # Operator overrides via YASHIGANI_CADDY_EGRESS_ALLOWLIST (comma-separated
    # host:port pairs) are appended.
    #
    # IPv6 BLOCK posture: `getent ahosts` returns both A and AAAA records.
    # The case-statement below SKIPS AAAA results silently — IPv6 destinations
    # are blocked at the ip6tables policy level (Step 1b), not allowlisted.
    # This is the BUG-V243-CADDY-IPV6-IPTABLES fix: before the fix, the loop
    # fed AAAA records to iptables (IPv4-only) which crashed under set -e.

    # LAURA-V243-002 (2026-05-26): ACME destinations gated on TLS_MODE=acme.
    # Previously DEFAULT_ACME_HOSTS was added to the allowlist unconditionally,
    # making Cloudflare IPs (172.65.32.248:443, 172.65.46.172:443) reachable from
    # the Caddy container even in selfsigned/ca modes that never use ACME. That
    # widens post-RCE exfil surface beyond the documented intent. Operator-
    # supplied YASHIGANI_CADDY_EGRESS_ALLOWLIST is still honoured in any mode
    # (explicit operator opt-in is the boundary).
    DEFAULT_ACME_HOSTS="acme-v02.api.letsencrypt.org:443 acme-staging-v02.api.letsencrypt.org:443 r10.o.lencr.org:80 r11.o.lencr.org:80 r12.o.lencr.org:80 e5.o.lencr.org:80 e6.o.lencr.org:80"
    OPERATOR_EXTRA="${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}"
    _tls_mode="${YASHIGANI_TLS_MODE:-acme}"
    if [ "$_tls_mode" = "acme" ]; then
        full_allowlist="${DEFAULT_ACME_HOSTS}"
        log "TLS mode: acme — ACME/OCSP hosts WILL be added to egress allowlist."
    else
        full_allowlist=""
        log "TLS mode: ${_tls_mode} (non-acme) — ACME/OCSP hosts SKIPPED from egress allowlist (LAURA-V243-002)."
    fi
    if [ -n "$OPERATOR_EXTRA" ]; then
        extra_space=$(printf '%s' "$OPERATOR_EXTRA" | tr ',' ' ')
        # Trim leading space if full_allowlist is empty
        if [ -z "$full_allowlist" ]; then
            full_allowlist="${extra_space}"
        else
            full_allowlist="${full_allowlist} ${extra_space}"
        fi
    fi
    # If nothing to allowlist (non-acme + no operator extras), skip the loop —
    # iptables policy DROP is already in effect (LOG + DROP appended below).
    if [ -z "$full_allowlist" ]; then
        log "No upstream destinations to allowlist (TLS mode is non-acme, no operator extras)."
    fi

    # LAURA-V243-005 (MED): defensive iptables ADD wrapper.
    # Under `set -eu`, a bare `iptables -A OUTPUT ... -j ACCEPT` that fails
    # mid-loop (e.g. crafted operator EGRESS_ALLOWLIST with invalid port,
    # ephemeral kernel/netfilter glitch) aborts the entrypoint before the
    # LOG/DROP sentinel is appended. Caddy then never starts — restart loop
    # with NO clear error message in container logs. Fail-closed (no bypass)
    # per Laura's live test, but operationally opaque.
    # Fix: catch ADD failures, warn loudly with the offending rule, count
    # the failure, and continue. Policy DROP is already in effect — partial
    # allowlist is fail-safe (more drops, not fewer). Final exit code is
    # non-zero IF any ADD failed, so operator sees the rule count + failures.
    _iptables_add_or_warn() {
        # $@ = arguments to iptables (e.g. -A OUTPUT -p tcp -d 1.2.3.4 ...)
        if iptables "$@" 2>&1; then
            return 0
        fi
        warn "iptables ADD failed: iptables $*"
        warn "  (allowlist now partial; OUTPUT policy DROP still applies — fail-safe)"
        _add_failures=$(( _add_failures + 1 ))
        return 1
    }

    resolved_v4=0
    skipped_v6=0
    _add_failures=0
    for host_port in $full_allowlist; do
        host="${host_port%:*}"
        port="${host_port##*:}"
        # Resolve to ALL families (A + AAAA), then SKIP IPv6 results.
        # IPv6 destinations are blocked at the ip6tables policy level.
        all_ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        if [ -z "$all_ips" ]; then
            warn "Could not resolve $host — skipping egress rule for $host:$port"
            continue
        fi
        for ip in $all_ips; do
            case "$ip" in
                *:*)
                    # IPv6 — BLOCKED by ip6tables policy DROP. Skip silently
                    # in the iptables loop. Do NOT add to ip6tables either —
                    # IPv6 is not a supported address family in Yashigani.
                    skipped_v6=$((skipped_v6 + 1))
                    ;;
                *.*)
                    if _iptables_add_or_warn -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT; then
                        log "egress allow: $host ($ip) :$port (IPv4)"
                        resolved_v4=$((resolved_v4 + 1))
                    fi
                    ;;
                *)
                    warn "Unrecognised address family for $host: $ip — skipping."
                    ;;
            esac
        done
    done
    if [ "$_add_failures" -gt 0 ]; then
        warn "iptables ADD failures: $_add_failures (allowlist partial — see warnings above)."
    fi
    log "ACME/OCSP/operator egress: $resolved_v4 IPv4 rules added; $skipped_v6 IPv6 destinations BLOCKED by policy."

    # ── Step 7: LOG then DROP (both tables) ──────────────────────────────
    # IPv4 LOG: any blocked IPv4 egress appears in the host kernel log under
    # CADDY_EGRESS_BLOCKED_V4 prefix.
    iptables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V4: " --log-level 4 2>/dev/null \
        && log "egress LOG rule installed (IPv4, CADDY_EGRESS_BLOCKED_V4 prefix)" \
        || warn "iptables LOG target unavailable — blocked IPv4 egress will not be logged (DROP still applies)"
    iptables -A OUTPUT -j DROP
    log "egress OUTPUT DROP applied (IPv4) — allowlist active."

    # IPv6 LOG: any IPv6 egress attempt (which there shouldn't be in a healthy
    # Yashigani install) logs under CADDY_EGRESS_BLOCKED_V6. This is the
    # canary for IPv6-bypass attempts — if it fires, an attacker or
    # misconfigured service is trying IPv6 egress.
    if [ "$IPV6_TABLE" = "1" ]; then
        ip6tables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V6: " --log-level 4 2>/dev/null \
            && log "egress LOG rule installed (IPv6, CADDY_EGRESS_BLOCKED_V6 prefix — fires on bypass attempts)" \
            || warn "ip6tables LOG target unavailable — IPv6 bypass attempts will not be logged (policy DROP still applies)"
        # No need to -A OUTPUT -j DROP — policy is already DROP and there are
        # zero ACCEPT rules. Adding an explicit -j DROP would shadow the LOG.
    fi

    log "Effective iptables OUTPUT chain (IPv4):"
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done
    if [ "$IPV6_TABLE" = "1" ]; then
        log "Effective ip6tables OUTPUT chain (IPv6, all-DROP):"
        ip6tables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
            log "  $line"
        done
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Caddy egress entrypoint starting (YSG-RISK-061)"
log "TLS mode: ${YASHIGANI_TLS_MODE:-acme} (informational)"
if [ -n "${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}" ]; then
    log "Operator EGRESS_ALLOWLIST: ${YASHIGANI_CADDY_EGRESS_ALLOWLIST}"
fi

apply_egress_rules

log "Starting Caddy..."
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
