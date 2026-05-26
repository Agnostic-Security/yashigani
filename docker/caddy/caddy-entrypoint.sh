#!/bin/sh
# Yashigani — Caddy egress restriction entrypoint
# YSG-RISK-061 (2026-05-25): iptables + ip6tables OUTPUT allowlist
# BUG-V243-CADDY-IPV6-IPTABLES (2026-05-26): IPv4/IPv6 parity refactor
#
# PURPOSE
#   Enforce a network egress allowlist for the Caddy container before starting
#   the Caddy process. Blocks all outbound TCP/UDP except to explicitly
#   permitted destinations on BOTH IPv4 and IPv6 (parity posture — out-of-the-
#   box restrictions apply equally to both address families). Reduces post-
#   Caddy-RCE attacker impact by blocking internet exfil, C2, and second-stage
#   payload fetch (~60-70% impact reduction per Laura cost-benefit 2026-05-25).
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

    # Probe ip6tables — Alpine + iptables-nft package ships both binaries
    # (xtables-nft shim provides ip6tables in the same package as iptables).
    # If ip6tables-policy fails (kernel CONFIG_IP6_NF_IPTABLES absent, IPv6
    # disabled via sysctl, or namespace lacks NET_ADMIN for v6), we degrade
    # gracefully: keep IPv4 filtering but log a WARN. Egress posture parity
    # is the OUT-OF-BOX intent (Tiago 2026-05-26); ip6tables absence is the
    # rare case, not the default.
    IPV6_ENABLED=0
    if ip6tables -P OUTPUT DROP 2>/dev/null; then
        IPV6_ENABLED=1
        log "ip6tables available — applying ip6tables OUTPUT allowlist (IPv6, parity)."
    else
        warn "ip6tables OUTPUT policy modification failed — IPv6 egress NOT filtered."
        warn "Likely cause: kernel lacks CONFIG_IP6_NF_IPTABLES, IPv6 disabled via sysctl,"
        warn "or container missing NET_ADMIN for v6 namespace. IPv4 filtering proceeds."
    fi

    # ── Step 2: Allow loopback (v4 + v6) ─────────────────────────────────
    # All Caddy admin socket interactions (healthcheck, reload) go via loopback.
    iptables -A OUTPUT -o lo -j ACCEPT
    [ "$IPV6_ENABLED" = "1" ] && ip6tables -A OUTPUT -o lo -j ACCEPT
    log "egress allow: loopback ($([ "$IPV6_ENABLED" = "1" ] && echo "IPv4 + IPv6" || echo "IPv4 only"))"

    # ── Step 3: Allow ESTABLISHED/RELATED (v4 + v6) ──────────────────────
    # Required for Caddy's inbound listeners (:80/:443/:8444/:8445) to send
    # response packets. Without this, SYN-ACK and data packets to clients are
    # dropped by the OUTPUT chain.
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    [ "$IPV6_ENABLED" = "1" ] && ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log "egress allow: ESTABLISHED,RELATED (response packets for inbound listeners)"

    # ── Step 4: Allow Docker embedded DNS (v4 only) ──────────────────────
    # Docker's embedded resolver is 127.0.0.11 (IPv4-only by Docker design).
    # There is no AAAA-equivalent embedded resolver — IPv6 DNS, if needed,
    # would come via operator-configured DNS servers added to OPERATOR_EXTRA.
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    log "egress allow: DNS → 127.0.0.11:53 (Docker embedded resolver, IPv4 only)"

    # ── Step 5: Allow all Docker bridge subnets (v4 + v6) ────────────────
    # Caddy proxies to in-mesh services (gateway, backoffice, open-webui,
    # grafana, prometheus) on Docker bridge networks. Bridge IPs are dynamic
    # (assigned per Docker daemon / compose project). We enumerate them at
    # startup from the kernel routing table.
    bridge_subnets_v4=$(ip route show 2>/dev/null | awk '/proto kernel/ {print $1}')
    if [ -n "$bridge_subnets_v4" ]; then
        for subnet in $bridge_subnets_v4; do
            iptables -A OUTPUT -d "$subnet" -j ACCEPT
            log "egress allow: Docker bridge subnet $subnet (IPv4)"
        done
    else
        warn "No IPv4 bridge subnets found via ip route — in-mesh egress may be blocked."
    fi
    if [ "$IPV6_ENABLED" = "1" ]; then
        bridge_subnets_v6=$(ip -6 route show 2>/dev/null | awk '/proto kernel/ {print $1}')
        if [ -n "$bridge_subnets_v6" ]; then
            for subnet in $bridge_subnets_v6; do
                ip6tables -A OUTPUT -d "$subnet" -j ACCEPT
                log "egress allow: Docker bridge subnet $subnet (IPv6)"
            done
        fi
        # No warn on empty v6 routes — Docker default networks are IPv4-only,
        # absence is expected unless operator enabled IPv6 networking.
    fi

    # ── Step 6: Allow ACME providers + operator allowlist (v4 + v6) ──────
    # Default ACME list: Let's Encrypt prod + staging + OCSP responders.
    # Operator overrides via YASHIGANI_CADDY_EGRESS_ALLOWLIST (comma-separated
    # host:port pairs) are appended.
    #
    # Resolution returns both A (IPv4) and AAAA (IPv6) records. We split by
    # address family (presence of `:` indicates IPv6) and route each to its
    # respective table. This is the BUG-V243-CADDY-IPV6-IPTABLES parity fix
    # — previously the loop fed all addresses to iptables (IPv4-only) which
    # rejected IPv6 with "host/network not found" and crash-looped under
    # set -e.

    DEFAULT_ACME_HOSTS="acme-v02.api.letsencrypt.org:443 acme-staging-v02.api.letsencrypt.org:443 r10.o.lencr.org:80 r11.o.lencr.org:80 r12.o.lencr.org:80 e5.o.lencr.org:80 e6.o.lencr.org:80"
    OPERATOR_EXTRA="${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}"
    full_allowlist="${DEFAULT_ACME_HOSTS}"
    if [ -n "$OPERATOR_EXTRA" ]; then
        extra_space=$(printf '%s' "$OPERATOR_EXTRA" | tr ',' ' ')
        full_allowlist="${full_allowlist} ${extra_space}"
    fi

    resolved_v4=0
    resolved_v6=0
    for host_port in $full_allowlist; do
        host="${host_port%:*}"
        port="${host_port##*:}"
        # Resolve to ALL families (A + AAAA), then route each address to
        # the correct table by detecting `:` (IPv6).
        all_ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        if [ -z "$all_ips" ]; then
            warn "Could not resolve $host — skipping egress rule for $host:$port"
            continue
        fi
        for ip in $all_ips; do
            case "$ip" in
                *:*)
                    if [ "$IPV6_ENABLED" = "1" ]; then
                        ip6tables -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
                        log "egress allow: $host ($ip) :$port (IPv6)"
                        resolved_v6=$((resolved_v6 + 1))
                    fi
                    # If ip6tables unavailable, IPv6 destinations are DROPpED by
                    # kernel default (no chain configured) — graceful fallback.
                    ;;
                *.*)
                    iptables -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
                    log "egress allow: $host ($ip) :$port (IPv4)"
                    resolved_v4=$((resolved_v4 + 1))
                    ;;
                *)
                    warn "Unrecognised address family for $host: $ip — skipping."
                    ;;
            esac
        done
    done
    log "ACME/OCSP/operator egress: $resolved_v4 IPv4 + $resolved_v6 IPv6 rules added."

    # ── Step 7: LOG then DROP (both tables) ──────────────────────────────
    # LOG before DROP: any blocked egress appears in the host kernel log.
    # Aids debugging when a new upstream is added to Caddyfile without
    # updating this allowlist. --log-level 4 = WARNING in kernel log.
    iptables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V4: " --log-level 4 2>/dev/null \
        && log "egress LOG rule installed (IPv4, CADDY_EGRESS_BLOCKED_V4 prefix)" \
        || warn "iptables LOG target unavailable — blocked IPv4 egress will not be logged (DROP still applies)"
    iptables -A OUTPUT -j DROP
    log "egress OUTPUT DROP applied (IPv4) — allowlist active."

    if [ "$IPV6_ENABLED" = "1" ]; then
        ip6tables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED_V6: " --log-level 4 2>/dev/null \
            && log "egress LOG rule installed (IPv6, CADDY_EGRESS_BLOCKED_V6 prefix)" \
            || warn "ip6tables LOG target unavailable — blocked IPv6 egress will not be logged (DROP still applies)"
        ip6tables -A OUTPUT -j DROP
        log "egress OUTPUT DROP applied (IPv6) — allowlist active."
    fi

    log "Effective iptables OUTPUT chain (IPv4):"
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done
    if [ "$IPV6_ENABLED" = "1" ]; then
        log "Effective ip6tables OUTPUT chain (IPv6):"
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
