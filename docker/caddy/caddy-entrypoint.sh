#!/bin/sh
# Yashigani — Caddy egress restriction entrypoint
# YSG-RISK-061 (2026-05-25): iptables OUTPUT allowlist
#
# PURPOSE
#   Enforce a network egress allowlist for the Caddy container before starting
#   the Caddy process. Blocks all outbound TCP/UDP except to explicitly
#   permitted destinations. Reduces post-Caddy-RCE attacker impact by blocking
#   internet exfil, C2, and second-stage payload fetch (~60-70% impact reduction
#   per Laura cost-benefit 2026-05-25).
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
    # ── Step 1: probe NET_ADMIN availability ─────────────────────────────────
    # Try to set OUTPUT default policy. If this fails, we have no NET_ADMIN and
    # must skip all iptables setup. Caddy still starts — just without egress
    # restrictions (documented limitation for rootless Podman).
    if ! iptables -P OUTPUT DROP 2>/dev/null; then
        warn "iptables OUTPUT policy modification failed — container lacks NET_ADMIN."
        warn "Egress restrictions NOT applied. Caddy starts without OUTPUT allowlist."
        warn "Rootless Podman limitation: re-run with --cap-add NET_ADMIN or use K8s NetworkPolicy."
        return 0
    fi

    log "NET_ADMIN available — applying egress OUTPUT allowlist."

    # ── Step 2: Allow loopback ─────────────────────────────────────────────
    # All Caddy admin socket interactions (healthcheck, reload) go via loopback.
    iptables -A OUTPUT -o lo -j ACCEPT
    log "egress allow: loopback"

    # ── Step 3: Allow ESTABLISHED/RELATED ────────────────────────────────────
    # Required for Caddy's inbound listeners (:80/:443/:8444/:8445) to send
    # response packets. Without this, SYN-ACK and data packets to clients are
    # dropped by the OUTPUT chain.
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log "egress allow: ESTABLISHED,RELATED (response packets for inbound listeners)"

    # ── Step 4: Allow Docker embedded DNS ─────────────────────────────────
    # Docker's embedded resolver lives at 127.0.0.11:53. This is the only
    # DNS server Caddy uses for upstream name resolution.
    # TCP port 53 also allowed for large DNS responses.
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    log "egress allow: DNS → 127.0.0.11:53 (Docker embedded resolver)"

    # ── Step 5: Allow all Docker bridge subnets ───────────────────────────
    # Caddy proxies to in-mesh services (gateway, backoffice, open-webui,
    # grafana, prometheus) all on Docker bridge networks. Bridge IPs are
    # dynamic (assigned per Docker daemon / compose project). We enumerate
    # them at startup from the kernel routing table.
    #
    # `ip route show` output format (per runtime verification):
    #   default via <gw> dev eth0
    #   <subnet>/<prefix> dev eth0 proto kernel scope link src <ip>
    # We extract the kernel-link subnets (scope link) which are the bridge
    # subnets Caddy is directly connected to.
    bridge_subnets=$(ip route show 2>/dev/null | awk '/proto kernel/ {print $1}')
    if [ -n "$bridge_subnets" ]; then
        for subnet in $bridge_subnets; do
            iptables -A OUTPUT -d "$subnet" -j ACCEPT
            log "egress allow: Docker bridge subnet $subnet"
        done
    else
        warn "No bridge subnets found via ip route — in-mesh egress may be blocked."
    fi

    # ── Step 6: Allow ACME providers + operator allowlist ────────────────
    # Default ACME list:
    #   acme-v02.api.letsencrypt.org:443    (Let's Encrypt production)
    #   acme-staging-v02.api.letsencrypt.org:443  (Let's Encrypt staging)
    # Let's Encrypt OCSP responders (for OCSP stapling, port 80):
    #   r10.o.lencr.org:80
    #   r11.o.lencr.org:80
    #   r12.o.lencr.org:80   (new R4 responder pool — pre-allow)
    #   e5.o.lencr.org:80    (E5 intermediary pool)
    #   e6.o.lencr.org:80
    # These are only needed in acme TLS mode, but we allow them in all modes —
    # they are non-sensitive and simplify the entrypoint logic.
    # Operator overrides via YASHIGANI_CADDY_EGRESS_ALLOWLIST (comma-separated
    # host:port pairs) are appended to the default list.

    DEFAULT_ACME_HOSTS="acme-v02.api.letsencrypt.org:443 acme-staging-v02.api.letsencrypt.org:443 r10.o.lencr.org:80 r11.o.lencr.org:80 r12.o.lencr.org:80 e5.o.lencr.org:80 e6.o.lencr.org:80"
    OPERATOR_EXTRA="${YASHIGANI_CADDY_EGRESS_ALLOWLIST:-}"

    # Build full allowlist (space-separated host:port)
    full_allowlist="${DEFAULT_ACME_HOSTS}"
    if [ -n "$OPERATOR_EXTRA" ]; then
        # Convert comma-separated operator list to space-separated
        extra_space=$(printf '%s' "$OPERATOR_EXTRA" | tr ',' ' ')
        full_allowlist="${full_allowlist} ${extra_space}"
    fi

    resolved_count=0
    for host_port in $full_allowlist; do
        host="${host_port%:*}"
        port="${host_port##*:}"
        # Resolve via Docker DNS (already allowed above via subnet rule).
        # IPv4 only — this allowlist uses `iptables` (IPv4); AAAA records
        # (containing ':') would fail with "host/network <addr> not found"
        # under `set -e` and crash-loop the container. BUG-V243-CADDY-IPV6-
        # IPTABLES verified on fresh VM/Podman install 2026-05-26 (Caddy
        # restart count 393 in 3 min before fix). IPv6 egress is currently
        # not filtered separately — tracked for follow-up via ip6tables.
        ips=$(getent ahosts "$host" 2>/dev/null | awk '$1 !~ /:/ {print $1}' | sort -u)
        if [ -z "$ips" ]; then
            warn "Could not resolve $host — skipping iptables rule for $host:$port"
            continue
        fi
        for ip in $ips; do
            iptables -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
            log "egress allow: $host ($ip) :$port"
            resolved_count=$((resolved_count + 1))
        done
    done
    log "ACME/OCSP/operator egress: $resolved_count IP-port rules added."

    # ── Step 7: LOG then DROP ─────────────────────────────────────────────
    # LOG before DROP: any blocked egress appears in the host kernel log.
    # Aids debugging when a new upstream is added to Caddyfile without
    # updating this allowlist. --log-level 4 = WARNING in kernel log.
    # The LOG rule may fail silently in some kernel configurations — that is
    # acceptable (DROP still applies).
    iptables -A OUTPUT -j LOG --log-prefix "CADDY_EGRESS_BLOCKED: " --log-level 4 2>/dev/null \
        && log "egress LOG rule installed (CADDY_EGRESS_BLOCKED prefix)" \
        || warn "LOG target unavailable — blocked egress will not be logged (DROP still applies)"

    iptables -A OUTPUT -j DROP
    log "egress OUTPUT DROP applied — allowlist active."
    log "Effective iptables OUTPUT chain:"
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
        log "  $line"
    done
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
