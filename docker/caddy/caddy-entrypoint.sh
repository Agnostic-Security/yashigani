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
#   7. openclaw egress-gateway upstreams (v4.1 Phase 1c + FP-06 Phase 2) —
#      slack.com:443, hooks.slack.com:443, api.telegram.org:443 — ONLY when
#      YASHIGANI_OPENCLAW_EGRESS=1 (install.sh sets it iff the openclaw
#      profile is enabled). These mirror the fixed reverse_proxy upstreams in
#      Caddyfile.openclaw-egress (the PRIMARY control; this iptables layer is
#      defence in depth). Unlike the ACME hosts, these use iptables hashlimit
#      (60/min burst 20 per dstip, tunable via YASHIGANI_OPENCLAW_EGRESS_RATE_LIMIT
#      + YASHIGANI_OPENCLAW_EGRESS_RATE_BURST) — coarse NEW-connection rate
#      brake, not per-request HTTP. Falls back to plain ACCEPT if the hashlimit
#      kernel module is unavailable. Known CDN limitation: IPs resolved once at
#      container start; rotate → restart to refresh.
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
    # Caddy proxies to in-mesh services (gateway, backoffice,
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

    # ── Step 6b: openclaw egress-gateway upstreams (v4.1 Phase 1c) ─────────
    # LAURA-I1-03: the :18790 fixed-upstream egress gateway
    # (Caddyfile.openclaw-egress) reverse_proxies to exactly these three FQDNs.
    # These hosts are handled separately from the ACME/operator allowlist (Step 6c
    # below) so they can carry a hashlimit rate-brake (FP-06 Phase 2). Gated on
    # the flag install.sh writes iff the openclaw profile is enabled; any value
    # other than the literal "1" keeps these hosts BLOCKED (fail-closed default).
    OPENCLAW_EGRESS_HOSTS="slack.com:443 hooks.slack.com:443 api.telegram.org:443"
    _openclaw_egress_active=0
    if [ "${YASHIGANI_OPENCLAW_EGRESS:-0}" = "1" ]; then
        _openclaw_egress_active=1
        log "openclaw egress gateway enabled — will allowlist with hashlimit rate-brake: ${OPENCLAW_EGRESS_HOSTS}"
    else
        log "openclaw egress gateway disabled (YASHIGANI_OPENCLAW_EGRESS != 1) — Slack/Telegram hosts NOT allowlisted."
    fi
    # If nothing to allowlist (non-acme + no operator extras + openclaw off), skip.
    if [ -z "$full_allowlist" ] && [ "$_openclaw_egress_active" = "0" ]; then
        log "No upstream destinations to allowlist (TLS mode is non-acme, no operator extras, openclaw disabled)."
    elif [ -z "$full_allowlist" ]; then
        log "No ACME/operator destinations to allowlist (TLS mode is non-acme, no operator extras)."
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

    # ── Step 6c: openclaw egress hashlimit rate-brake (FP-06 Phase 2) ───────
    # DESIGN: openclaw egress hosts are NOT in the plain full_allowlist above.
    # Instead, each resolved IPv4 gets a hashlimit ACCEPT (within rate) and an
    # explicit NEW DROP (over rate) pair — inserted BEFORE the final LOG+DROP.
    # Coarse control: connection-rate (NEW TCP SYN), not per-request HTTP.
    # ESTABLISHED packets for accepted connections are already handled by Step 3.
    #
    # CDN limitation: Slack.com, hooks.slack.com, and api.telegram.org resolve
    # to CDN-rotated IPs. Rules are built once at container start; if IPs rotate,
    # the old rules cover the stale set and new IPs are BLOCKED until restart.
    # This matches the existing ACME allowlist behaviour and is documented as a
    # known class (retro #57-c). A container restart refreshes all rules.
    #
    # Fail-soft: if hashlimit is unavailable (kernel module not loaded or
    # NET_ADMIN absent), the fallback is plain ACCEPT — egress remains functional
    # without the rate brake. Logged as WARN so the operator knows the brake is off.
    #
    # Tunable via env vars (set by install.sh / operator override):
    #   YASHIGANI_OPENCLAW_EGRESS_RATE_LIMIT  — hashlimit rate  (default: 60/min)
    #   YASHIGANI_OPENCLAW_EGRESS_RATE_BURST  — hashlimit burst (default: 20)
    if [ "$_openclaw_egress_active" = "1" ]; then
        _rl_rate="${YASHIGANI_OPENCLAW_EGRESS_RATE_LIMIT:-60/min}"
        _rl_burst="${YASHIGANI_OPENCLAW_EGRESS_RATE_BURST:-20}"
        _rl_applied=0
        _rl_fallback=0
        log "openclaw egress hashlimit rate-brake: ${_rl_rate} burst ${_rl_burst} NEW conn per dstip"
        for host_port in $OPENCLAW_EGRESS_HOSTS; do
            host="${host_port%:*}"
            port="${host_port##*:}"
            all_ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
            if [ -z "$all_ips" ]; then
                warn "hashlimit: could not resolve $host — $host:$port BLOCKED (fail-safe)"
                continue
            fi
            for ip in $all_ips; do
                case "$ip" in
                    *:*)
                        # IPv6 — blocked by ip6tables policy, skip.
                        ;;
                    *.*)
                        # Try hashlimit ACCEPT first. On success, add the per-IP NEW
                        # DROP rule (connections over the limit fall through to DROP here
                        # rather than the final DROP, keeping the LOG rule readable).
                        if iptables -A OUTPUT -p tcp -d "$ip" --dport "$port" \
                            -m state --state NEW \
                            -m hashlimit \
                            --hashlimit-upto "${_rl_rate}" \
                            --hashlimit-burst "${_rl_burst}" \
                            --hashlimit-mode dstip \
                            --hashlimit-name "ysg-oc-egress" \
                            -j ACCEPT 2>/dev/null; then
                            # Explicit DROP for NEW connections that exceeded the rate.
                            # ESTABLISHED packets (return traffic) are accepted by Step 3.
                            if ! iptables -A OUTPUT -p tcp -d "$ip" --dport "$port" \
                                -m state --state NEW -j DROP 2>/dev/null; then
                                warn "hashlimit: NEW-DROP rule failed for $host ($ip):$port — rate exceeded traffic will hit final DROP"
                            fi
                            log "egress hashlimit allow: $host ($ip):$port NEW <=${_rl_rate} burst ${_rl_burst}"
                            _rl_applied=$((_rl_applied + 1))
                        else
                            # hashlimit module unavailable — fall back to plain ACCEPT
                            # so openclaw egress remains operational.
                            warn "hashlimit unavailable for $host ($ip):$port — falling back to plain ACCEPT (rate-brake OFF)"
                            _iptables_add_or_warn -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
                            _rl_fallback=$((_rl_fallback + 1))
                        fi
                        ;;
                    *)
                        warn "hashlimit: unrecognised address family for $host: $ip — skipping"
                        ;;
                esac
            done
        done
        if [ "$_rl_applied" -gt 0 ]; then
            log "openclaw egress hashlimit: $_rl_applied rules applied (${_rl_rate} burst ${_rl_burst} per dstip)."
        fi
        if [ "$_rl_fallback" -gt 0 ]; then
            warn "openclaw egress hashlimit: $_rl_fallback host(s) fell back to plain ACCEPT (rate-brake NOT active for those hosts)."
        fi
        if [ "$_rl_applied" -eq 0 ] && [ "$_rl_fallback" -eq 0 ]; then
            warn "openclaw egress hashlimit: no rules applied — all hosts unresolvable. Slack/Telegram egress is BLOCKED."
        fi
    fi

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


# ── FP-06 Phase 2: Slack operator-config secrets → Caddy parse-time env ───
# Secret files (0600, created by install.sh from operator-supplied values):
#   /run/secrets/openclaw_slack_webhook_path  (CHANNEL 1: incoming-webhook path pin)
#   /run/secrets/openclaw_slack_bot_token     (CHANNEL 2: Web API bot-token pin)
# These are NOT declared in compose environment: — the secret file is the single
# source of truth; this avoids the value appearing in `docker inspect` env dumps.
# caddy-entrypoint.sh reads the files HERE (before exec caddy) and exports them
# so Caddy inherits the vars at parse time ({$YASHIGANI_OPENCLAW_SLACK_*:} in
# the Caddyfile substitutes to the actual value).
# Empty/absent file → var stays unset → Caddy default "" → enforcement expression
# short-circuits false (inert-until-set; default install unbroken).
if [ -s /run/secrets/openclaw_slack_webhook_path ]; then
    YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH="$(cat /run/secrets/openclaw_slack_webhook_path)"
    export YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH
    log "Slack webhook-path pin loaded (YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH set)."
else
    log "Slack webhook-path pin: secret file absent or empty — CHANNEL 1 enforcement OFF (inert)."
fi
if [ -s /run/secrets/openclaw_slack_bot_token ]; then
    YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN="$(cat /run/secrets/openclaw_slack_bot_token)"
    export YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN
    log "Slack bot-token pin loaded (YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN set; value redacted from log)."
else
    log "Slack bot-token pin: secret file absent or empty — CHANNEL 2 enforcement OFF (inert)."
fi

# ── FINDING-V412-CADDYADMIN-002 (Ava/Maxine root-cause, 2026-07-21): stale
#    dynamic-MCP-route boot crash-loop resilience ───────────────────────────
# Caddy's config load is all-or-nothing: `import /etc/caddy/agents-dynamic/
# *.caddy` (docker/Caddyfile.<selfsigned|acme|ca>) glob-imports every file the
# caddy-config-broker has ever written into the broker-owned agents-dynamic
# volume. ONE bad file in there (references a cert the broker's own atomicity
# fix didn't manage to clean up, or any other adapt/provision-time failure)
# fails the WHOLE merged config -> `caddy run` never starts -> compose/K8s
# restarts the container -> the SAME bad file is still on disk -> permanent
# crash-loop with no operator recovery path except a manual `rm` + restart
# (Ava hit exactly this live).
#
# FIX: before handing off to the real `caddy run`, validate every file
# CURRENTLY present in agents-dynamic INDIVIDUALLY (each is a self-contained
# `:port { ... }` site block — see the "import agents-dynamic" comment in
# docker/Caddyfile.selfsigned — so it can be tested standalone) against the
# REAL monolith scaffolding (global options block, every other static
# import, this container's REAL environment) via `caddy validate`, which
# provisions TLS file loaders too (proven above: a `tls <missing-cert>`
# directive fails validate with a clear "no such file or directory", not
# just a syntax parse). Any file that fails on its own is logged LOUDLY
# (exact path + adapt/provision error) and EXCLUDED from the config Caddy
# actually boots from; every other file boots byte-identical, same order.
#
# WHY NOT A LITERAL "mv to a quarantine dir" (the finding's suggested
# wording): `caddy_broker_agents` is mounted `:ro` in THIS container by
# design — FINDING-V412-CADDYADMIN-002's own R2 fix made it read-only
# specifically so Caddy (and everything upstream of it) can never write back
# into the broker-owned volume (see config_broker.py module docstring "WHY
# R2 IS FULLY CLOSED"). This container's root filesystem is also
# `read_only: true` (compose + Helm) with only /tmp (tmpfs) writable.
# Re-opening a write path here to literally `mv` the bad file would undo a
# real security fix for no functional gain. Instead: build a WRITABLE,
# tmpfs-backed COPY of the monolith with the bad file(s) excluded from the
# effective import set, and boot from that copy. The bad file is NEVER
# deleted (only the broker can do that, via DELETE /route or operator
# cleanup) but it is deterministically excluded on EVERY boot until it is —
# same operator-visible "quarantine" signal (loud log line, every restart),
# without weakening R2. Flagged in this comment, not a silent deviation —
# see the fix commit body for the full writeup.
#
# Known interaction (not a new crash-loop): once a bad file is quarantined
# this way, a LATER broker reload for a *different* new route still forwards
# the ORIGINAL (unfiltered) monolith text to Caddy's admin socket (see
# config_broker.py `_trigger_reload`/`_read_raw_monolith` — it always reads
# `/etc/caddy/Caddyfile` verbatim, not our synthesized copy). Caddy's admin
# `POST /load` rejects an invalid candidate WITHOUT dropping the currently
# running (good) config — so the edge keeps serving, but new-route reloads
# will keep failing until the stale file is actually removed from the
# broker's volume. Out of scope for this boot-time fix (that reload path
# already fails closed, never crashes); tracked as a follow-up below.

_CADDY_CONFIG_SRC="/etc/caddy/Caddyfile"
_AGENTS_DYNAMIC_DIR="/etc/caddy/agents-dynamic"
_AGENTS_DYNAMIC_IMPORT_LINE="import /etc/caddy/agents-dynamic/*.caddy"
_RUNTIME_SCRATCH=""
_EFFECTIVE_CONFIG_PATH="$_CADDY_CONFIG_SRC"

_cleanup_runtime_scratch() {
    if [ -n "$_RUNTIME_SCRATCH" ] && [ -d "$_RUNTIME_SCRATCH" ]; then
        rm -rf "$_RUNTIME_SCRATCH"
    fi
}
trap _cleanup_runtime_scratch EXIT

# Splice a replacement for the agents-dynamic import LINE (exact literal
# text match via `grep -F` — no sed/regex metachar escaping needed, since the
# literal itself contains a `*`) into a copy of $_CADDY_CONFIG_SRC, written to
# $2. $1 may be empty (drop the import entirely) or one-or-more "import ..."
# lines. Returns 1 (and copies the source untouched) if the sentinel line
# isn't found — a caddyfile-format drift we must not guess around.
_splice_agents_dynamic_import() {
    replacement="$1"
    out="$2"
    line_no=$(grep -nF "$_AGENTS_DYNAMIC_IMPORT_LINE" "$_CADDY_CONFIG_SRC" 2>/dev/null | head -n1 | cut -d: -f1)
    if [ -z "$line_no" ]; then
        warn "agents-dynamic import sentinel ('$_AGENTS_DYNAMIC_IMPORT_LINE') not found in $_CADDY_CONFIG_SRC"
        warn "  — cannot isolate dynamic routes; leaving config untouched (Caddyfile-format drift?)."
        cp "$_CADDY_CONFIG_SRC" "$out"
        return 1
    fi
    {
        head -n $((line_no - 1)) "$_CADDY_CONFIG_SRC"
        [ -n "$replacement" ] && printf '%s\n' "$replacement"
        tail -n +$((line_no + 1)) "$_CADDY_CONFIG_SRC"
    } > "$out"
}

# Standalone validity test for ONE dynamic route file: same real global
# options + every other static import + real container env, only THIS one
# file glob-... (well, single-path-) imported in place of the full glob.
# stderr of the failing `caddy validate` is written to $2 for the log.
_validate_one_dynamic_file() {
    file="$1"
    errfile="$2"
    test_cfg="$_RUNTIME_SCRATCH/test-$(basename "$file").caddyfile"
    if ! _splice_agents_dynamic_import "import $file" "$test_cfg"; then
        return 1
    fi
    caddy validate --config "$test_cfg" --adapter caddyfile >"$errfile" 2>&1
}

# Sets $_EFFECTIVE_CONFIG_PATH and returns 0 on success, 1 if no valid config
# could be assembled (fail loud — never guess past this point). Runs in the
# CURRENT shell (not a subshell) so the trap + scratch dir persist for the
# `exec caddy run` that follows.
resolve_effective_caddy_config() {
    log "Validating assembled Caddy config (monolith + static + dynamic agent routes)..."
    # NOTE: the assignment is the if-CONDITION itself (not split across two
    # statements with a later `$?` check) — under `set -eu`, `ash`/`dash`
    # abort immediately on a failing command substitution used as a bare
    # assignment statement; putting it directly in the if-condition is the
    # POSIX-exempt form (verified: dash + busybox-class shells do NOT abort
    # here, they take the else branch as expected).
    if first_pass_err="$(caddy validate --config "$_CADDY_CONFIG_SRC" --adapter caddyfile 2>&1)"; then
        log "Caddy config validated OK — no dynamic-route quarantine action needed."
        _EFFECTIVE_CONFIG_PATH="$_CADDY_CONFIG_SRC"
        return 0
    fi

    warn "Caddy config validation FAILED on the first pass — inspecting agents-dynamic"
    warn "  route files individually before giving up (FINDING-V412-CADDYADMIN-002):"
    printf '%s\n' "$first_pass_err" | while IFS= read -r eline; do warn "    $eline"; done

    _RUNTIME_SCRATCH="$(mktemp -d /tmp/yashigani-caddy-runtime.XXXXXX)"

    dynamic_files=""
    if [ -d "$_AGENTS_DYNAMIC_DIR" ]; then
        for f in "$_AGENTS_DYNAMIC_DIR"/*.caddy; do
            [ -e "$f" ] || continue
            dynamic_files="${dynamic_files}${f}
"
        done
    fi

    if [ -z "$dynamic_files" ]; then
        warn "FATAL: Caddy config is invalid and agents-dynamic has NO files to quarantine —"
        warn "  this is not a stale-dynamic-route problem; refusing to guess further."
        return 1
    fi

    good_files=""
    bad_count=0
    old_ifs="$IFS"
    IFS='
'
    for f in $dynamic_files; do
        IFS="$old_ifs"
        [ -n "$f" ] || continue
        errfile="$_RUNTIME_SCRATCH/err-$(basename "$f").log"
        if _validate_one_dynamic_file "$f" "$errfile"; then
            good_files="${good_files}${f}
"
        else
            bad_count=$((bad_count + 1))
            warn "QUARANTINED dynamic route file (excluded from this boot): $f"
            warn "  REASON:"
            while IFS= read -r eline; do warn "    $eline"; done < "$errfile"
        fi
        IFS='
'
    done
    IFS="$old_ifs"

    if [ "$bad_count" -eq 0 ]; then
        # Every single dynamic file validated fine on its own, yet the FULL
        # config is still invalid — NOT the single-bad-file class this fix
        # targets (e.g. two otherwise-valid files collide on the same
        # mesh_port, or the static monolith itself regressed). Quarantining
        # nothing here would be guessing; fail loud instead of masking an
        # unrelated bug.
        warn "FATAL: no single agents-dynamic file failed standalone validation —"
        warn "  this is NOT a stale-dynamic-route problem (cross-file collision or a"
        warn "  static monolith regression). Refusing to drop any file. Original error above."
        return 1
    fi

    replacement=""
    old_ifs="$IFS"
    IFS='
'
    for f in $good_files; do
        IFS="$old_ifs"
        [ -n "$f" ] || continue
        replacement="${replacement}import ${f}
"
        IFS='
'
    done
    IFS="$old_ifs"

    effective_cfg="$_RUNTIME_SCRATCH/Caddyfile.effective"
    _splice_agents_dynamic_import "$replacement" "$effective_cfg" || true

    log "Re-validating effective config with $bad_count bad dynamic-route file(s) excluded..."
    if second_pass_err="$(caddy validate --config "$effective_cfg" --adapter caddyfile 2>&1)"; then
        log "Effective config (bad dynamic routes excluded) validated OK — Caddy WILL start."
        _EFFECTIVE_CONFIG_PATH="$effective_cfg"
        return 0
    fi

    warn "FATAL: config is still invalid even after excluding every individually-bad"
    warn "  dynamic route file — refusing to guess further:"
    printf '%s\n' "$second_pass_err" | while IFS= read -r eline; do warn "    $eline"; done
    return 1
}

if resolve_effective_caddy_config; then
    log "Starting Caddy (config: $_EFFECTIVE_CONFIG_PATH)..."
    exec caddy run --config "$_EFFECTIVE_CONFIG_PATH" --adapter caddyfile
else
    warn "FATAL: could not assemble a valid Caddy config even after dynamic-route"
    warn "  quarantine — refusing to start with an unvalidated config. Exiting non-zero"
    warn "  (compose/K8s will restart; this WILL crash-loop again until the underlying"
    warn "  cause — not a single stale dynamic route — is fixed by an operator)."
    exit 1
fi
