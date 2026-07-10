#!/bin/sh
# Yashigani ringfence-init — L1 network-plane containment script
# plan §2.D L1-L8; CRIT-01, CRIT-02, CRIT-03, HIGH-01, HIGH-05
#
# PURPOSE
#   Apply a default-deny OUTPUT iptables policy in the agent's shared network
#   namespace. The ONLY permitted outbound TCP is to the resolved Caddy
#   ClusterIP/container-IP on port 443. All other egress — including RFC1918
#   addresses, loopback (except lo), and any non-443 port — is DROPped.
#
#   Runs as an init sidecar (network_mode: service:<agent> on Compose;
#   initContainer on K8s). Exits 0 on success. Non-zero exit prevents the
#   agent container from starting (depends_on: service_completed_successfully
#   on Compose; initContainer failure on K8s).
#
# ENVIRONMENT VARIABLES
#   RINGFENCE_CADDY_HOST   Hostname or IP of the Caddy service.
#                          Defaults to "caddy" (Docker compose DNS).
#                          K8s: set to the stable ClusterIP of the Caddy
#                          Service from Helm values (not a hostname — avoids
#                          DNS dependency when CoreDNS is the only nameserver
#                          and the DROP rule is applied first).
#   RINGFENCE_CADDY_PORT   TCP port for the ACCEPT rule. Default: 443.
#   RINGFENCE_DNS_SERVER   DNS server IP for resolver ACCEPT rule.
#                          Default: 127.0.0.11 (Docker embedded DNS).
#                          Set to kube-dns ClusterIP on K8s.
#   RINGFENCE_RUNTIME      Runtime hint for diagnostics. One of:
#                          docker | podman-rootful | podman-rootless | k8s
#                          Injected by codegen from YSG_RUNTIME at onboard time.
#   RINGFENCE_AGENT_NAME   Agent name for log prefix (informational only).
#
# DESIGN NOTES — CADDY IP RESOLUTION (CRIT-02)
#   getent hosts is called BEFORE the DROP policy is set so DNS resolution
#   works normally. Once OUTPUT=DROP is applied, no new DNS queries can
#   leave the namespace. The resolved IP is cached in a shell variable and
#   used for the iptables ACCEPT rule.
#
#   On K8s: RINGFENCE_CADDY_HOST should be set to the stable Caddy ClusterIP
#   (a literal dotted-decimal IPv4 address) so no DNS lookup is required.
#   The ClusterIP never changes for the lifetime of the Service object and is
#   safe to bake into the generated values overlay at onboard time.
#
# DESIGN NOTES — IPv6 (CRIT-03)
#   IPv6 is disabled at the compose level via:
#     sysctls:
#       net.ipv6.conf.all.disable_ipv6: "1"
#       net.ipv6.conf.default.disable_ipv6: "1"
#   ip6tables rules are applied as defence-in-depth in case the kernel
#   enables IPv6 despite the sysctl (e.g. some K8s dual-stack configurations).
#   If ip6tables is not available (IPv6 stack absent), we log and continue.
#
# DESIGN NOTES — ROOTLESS PODMAN GAP (HIGH-01 / L4)
#   Rootless Podman runs init containers in a user network namespace where
#   iptables manipulation requires SYS_ADMIN or full rootful context.
#   This script detects the failure and exits non-zero with a clear message.
#   The compose codegen annotates the generated stanza with a ROOTLESS-PODMAN-
#   L1-GAP comment so operators understand L1 is not active; L2+L3 (Caddy
#   egress enforcement + OPA) remain active.
#
# READINESS FILE (plan L12 — PM / init-sidecar sequencing)
#   After successfully applying rules, writes a readiness marker to the
#   shared tmpfs at /run/ringfence/ready. Pool Manager waits for this file
#   (with a 30-second timeout) before creating the agent container on its
#   network. Compose path: the service_completed_successfully condition is
#   the sequencing gate — the readiness file is informational for the PM.
#   K8s path: initContainer exit code is the sequencing gate.

set -eu

# ── Configuration ─────────────────────────────────────────────────────────────
CADDY_HOST="${RINGFENCE_CADDY_HOST:-caddy}"
CADDY_PORT="${RINGFENCE_CADDY_PORT:-443}"
DNS_SERVER="${RINGFENCE_DNS_SERVER:-127.0.0.11}"
RUNTIME="${RINGFENCE_RUNTIME:-unknown}"
AGENT_NAME="${RINGFENCE_AGENT_NAME:-agent}"
READINESS_DIR="/run/ringfence"
READINESS_FILE="${READINESS_DIR}/ready"

# ── Logging ───────────────────────────────────────────────────────────────────
_log() {
    printf '[ringfence-init][%s] %s\n' "${AGENT_NAME}" "$*" >&2
}

_warn() {
    printf '[ringfence-init][%s] WARN: %s\n' "${AGENT_NAME}" "$*" >&2
}

_fatal() {
    printf '[ringfence-init][%s] FATAL: %s\n' "${AGENT_NAME}" "$*" >&2
    exit 1
}

# ── Runtime gap check (rootless Podman) ───────────────────────────────────────
_check_rootless_gap() {
    if [ "${RUNTIME}" = "podman-rootless" ]; then
        _warn "Runtime is podman-rootless — iptables init is EXPECTED to fail."
        _warn "L1 network-plane containment is NOT available for rootless Podman."
        _warn "L2 (Caddy egress enforcement) + L3 (OPA) remain active."
        _warn "Upgrade to rootful Podman or K8s for L1 containment."
        # Exit 0 deliberately: the compose/K8s stanza codegen has already
        # annotated this deployment with the L1-GAP warning. Failing here
        # would block the agent from starting entirely on rootless Podman,
        # which is a worse UX than documenting the gap and continuing with L2+L3.
        # This matches plan HIGH-01: "rootless gets L2+L3 only with an explicit
        # WARNING in the generated artifact."
        _write_gap_marker "podman-rootless"
        exit 0
    fi
}

# ── Caddy IP resolution (CRIT-02) ─────────────────────────────────────────────
# Must happen BEFORE any DROP policy is applied.
_resolve_caddy_ip() {
    _log "Resolving Caddy host: ${CADDY_HOST}"

    # If CADDY_HOST is already a dotted-decimal IP (K8s ClusterIP case), skip DNS.
    case "${CADDY_HOST}" in
        *.*.*.*) CADDY_IP="${CADDY_HOST}"; _log "Caddy IP (literal): ${CADDY_IP}"; return 0 ;;
        *) ;;   # not a literal IP — fall through to DNS resolution
    esac

    # DNS resolution via getent hosts. Returns "ip  fqdn" lines.
    # We take the first IPv4 result; skip IPv6 (AAAA) results.
    CADDY_IP=""
    while IFS= read -r line; do
        _ip="$(printf '%s' "${line}" | awk '{print $1}')"
        case "${_ip}" in
            *:*) continue ;;   # IPv6 — skip
            *.*)                # IPv4
                CADDY_IP="${_ip}"
                break
                ;;
            *) continue ;;     # unrecognised format — skip
        esac
    done << EOF
$(getent hosts "${CADDY_HOST}" 2>/dev/null || true)
EOF

    if [ -z "${CADDY_IP}" ]; then
        _fatal "Cannot resolve Caddy host '${CADDY_HOST}' to an IPv4 address. " \
               "Verify RINGFENCE_CADDY_HOST and that DNS is reachable BEFORE init runs."
    fi

    _log "Caddy IP resolved: ${CADDY_HOST} -> ${CADDY_IP}"
}

# ── iptables (IPv4) default-deny with Caddy ACCEPT ────────────────────────────
_apply_ipv4_rules() {
    _log "Applying iptables IPv4 OUTPUT rules (runtime: ${RUNTIME})"

    # Probe NET_ADMIN availability. If this fails, we cannot enforce L1.
    if ! iptables -P OUTPUT DROP 2>/dev/null; then
        _warn "iptables OUTPUT policy modification failed — NET_ADMIN unavailable."
        _warn "This indicates a rootless or unprivileged context."
        if [ "${RUNTIME}" = "podman-rootless" ]; then
            # Already handled by _check_rootless_gap — should not reach here,
            # but guard defensively.
            _write_gap_marker "net-admin-unavailable"
            exit 0
        fi
        # For any other runtime: this is a hard failure. The operator must
        # ensure NET_ADMIN is granted (cap_add: [NET_ADMIN] in compose/K8s).
        _fatal "NET_ADMIN required for L1 containment on runtime '${RUNTIME}'. " \
               "Add cap_add: [NET_ADMIN] to the ringfence-init container spec."
    fi

    # Flush any pre-existing OUTPUT rules (defensive; init containers are
    # expected to run against a clean namespace, but be explicit).
    iptables -F OUTPUT 2>/dev/null || true

    # Rule 1: Loopback OUTPUT — allow intra-container communication.
    iptables -A OUTPUT -o lo -j ACCEPT
    _log "ipv4 allow: loopback (lo)"

    # Rule 2: ESTABLISHED,RELATED — allow response packets for inbound connections.
    # Agents accept MCP connections FROM Caddy (inbound). Without this rule,
    # SYN-ACKs and data packets back to Caddy are dropped.
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    _log "ipv4 allow: ESTABLISHED,RELATED (response packets for inbound MCP from Caddy)"

    # Rule 3: DNS to the Docker embedded resolver / kube-dns.
    # Required for the agent to resolve service names (e.g. letta-pgbouncer).
    # UDP + TCP both covered (TCP fallback for large responses).
    iptables -A OUTPUT -p udp --dport 53 -d "${DNS_SERVER}" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "${DNS_SERVER}" -j ACCEPT
    _log "ipv4 allow: DNS -> ${DNS_SERVER}:53"

    # Rule 4: ACCEPT to Caddy IP:port (the ONLY permitted outbound destination).
    # This is the sole egress: Agent -> Caddy -> OPA -> external.
    iptables -A OUTPUT -p tcp --dport "${CADDY_PORT}" -d "${CADDY_IP}" -j ACCEPT
    _log "ipv4 allow: Caddy ${CADDY_IP}:${CADDY_PORT} (sole permitted egress)"

    # Rule 5: LOG then DROP all other OUTPUT.
    # LOG target uses kernel printk. On hosts with nf_log_all_netns=0, log
    # messages stay in the container namespace and do not reach host journald.
    # DROP enforcement is unaffected by LOG availability.
    if iptables -A OUTPUT -j LOG --log-prefix "YSG_RINGFENCE_BLOCKED_V4: " --log-level 4 2>/dev/null; then
        _log "ipv4 LOG sentinel installed (YSG_RINGFENCE_BLOCKED_V4 prefix)"
    else
        _warn "ipv4 LOG target unavailable — blocked egress will not be logged (DROP still applies)"
    fi
    iptables -A OUTPUT -j DROP

    _log "iptables IPv4 OUTPUT: DROP policy active. Effective chain:"
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | while IFS= read -r line; do
        _log "  ipv4: ${line}"
    done

    _log "IPv4 L1 containment: ACTIVE (agent can only reach Caddy ${CADDY_IP}:${CADDY_PORT})"
}

# ── ip6tables (IPv6) default-deny (CRIT-03) ───────────────────────────────────
# IPv6 is disabled at compose level via sysctls. ip6tables rules are
# defence-in-depth for dual-stack K8s environments.
_apply_ipv6_rules() {
    if ! ip6tables -P OUTPUT DROP 2>/dev/null; then
        _log "ip6tables not applicable — IPv6 stack absent or disabled (expected state)"
        return 0
    fi

    ip6tables -F OUTPUT 2>/dev/null || true
    # Loopback only. No ESTABLISHED,RELATED: agents do not accept IPv6 inbound.
    ip6tables -A OUTPUT -o lo -j ACCEPT
    if ip6tables -A OUTPUT -j LOG --log-prefix "YSG_RINGFENCE_BLOCKED_V6: " --log-level 4 2>/dev/null; then
        _log "ipv6 LOG sentinel installed (YSG_RINGFENCE_BLOCKED_V6 prefix)"
    else
        _warn "ip6tables LOG target unavailable — IPv6 bypass attempts will not be logged (DROP still applies)"
    fi
    # Policy DROP already set above; no explicit -j DROP rule needed.

    _log "ip6tables IPv6 OUTPUT: DROP policy active (defence-in-depth)"
}

# ── Readiness marker (plan L12) ───────────────────────────────────────────────
_write_ready_marker() {
    # Write to shared tmpfs (mounted at /run/ringfence in both init and agent
    # containers — compose: tmpfs volume; K8s: emptyDir). Pool Manager polls
    # this path. The file contains the ISO-8601 timestamp + resolved Caddy IP
    # for diagnostic purposes.
    mkdir -p "${READINESS_DIR}" 2>/dev/null || true
    # SC2312: capture date separately to avoid masking exit code
    _ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'unknown')"
    if printf '%s caddy_ip=%s caddy_port=%s runtime=%s\n' \
        "${_ts}" \
        "${CADDY_IP:-unknown}" \
        "${CADDY_PORT}" \
        "${RUNTIME}" \
        > "${READINESS_FILE}" 2>/dev/null; then
        _log "Readiness marker written: ${READINESS_FILE}"
    else
        _warn "Could not write readiness marker to ${READINESS_FILE} (non-fatal; compose sequencing via exit code)"
    fi
}

_write_gap_marker() {
    _reason="${1:-unknown}"
    mkdir -p "${READINESS_DIR}" 2>/dev/null || true
    # SC2312: capture date separately
    _gap_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'unknown')"
    printf '%s l1_gap=true reason=%s runtime=%s\n' \
        "${_gap_ts}" \
        "${_reason}" \
        "${RUNTIME}" \
        > "${READINESS_DIR}/l1-gap" 2>/dev/null || true
    _warn "L1-gap marker written (${_reason}): ${READINESS_DIR}/l1-gap"
}

# ── Main ──────────────────────────────────────────────────────────────────────
_log "ringfence-init starting (YSG-RISK-URF-L1) agent=${AGENT_NAME} runtime=${RUNTIME}"

# Step 1: Check for rootless Podman gap before attempting iptables.
_check_rootless_gap

# Step 2: Resolve Caddy IP (before any DROP rule is active — CRIT-02).
_resolve_caddy_ip

# Step 3: Apply IPv4 default-deny + Caddy ACCEPT.
_apply_ipv4_rules

# Step 4: Apply IPv6 default-deny (defence-in-depth — CRIT-03).
_apply_ipv6_rules

# Step 5: Write readiness marker for Pool Manager sequencing (L12).
_write_ready_marker

_log "ringfence-init complete. Agent network namespace: default-deny OUTPUT, Caddy ACCEPT only."
_log "L1 containment ACTIVE. Agent cannot initiate direct outbound connections."
exit 0
