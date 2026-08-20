#!/bin/sh
# lib/detect_runtime.sh — Yashigani runtime 4-way detection (P1 W2)
# plan §2.D L4 / HIGH-01 / L10
#
# PURPOSE
#   Detect the container runtime environment and emit a normalised
#   YSG_RUNTIME_4WAY value for use by the onboarding codegen, ringfence-init
#   spawner, and any generated artifact comment.
#
# FOUR-WAY VALUES
#   docker             Docker Engine / Docker Desktop (rootful daemon)
#   podman-rootful     Podman, current UID is root (uid=0) or rootful socket
#   podman-rootless    Podman, current UID is non-root (user-namespace remapping)
#   k8s                Kubernetes in-cluster (KUBERNETES_SERVICE_HOST + SA token)
#
# OUTPUTS (shell variables, exported)
#   YSG_RUNTIME_4WAY   One of the four values above, or "unknown" on failure.
#   YSG_RUNTIME_4WAY_NOTE  Human-readable explanation of the decision + any
#                       caveats (e.g. rootless L1 gap).
#
# USAGE — source into install.sh or the onboarding codegen:
#   . "$(dirname "$0")/../lib/detect_runtime.sh"
#   _detect_runtime
#   # YSG_RUNTIME_4WAY is now set
#
# COORDINATION WITH install.sh
#   install.sh already resolves YSG_RUNTIME (docker | podman | k8s) and
#   YSG_PODMAN_RUNTIME (true/false) via _resolve_compose_cmd(). The
#   _detect_runtime function in this file extends that to the 4-way split
#   (distinguishing rootful vs rootless Podman) and is the SINGLE authoritative
#   source for the rootless/rootful distinction.
#   Insertion point in install.sh: call _detect_runtime() after
#   _resolve_compose_cmd() succeeds and before any codegen step.
#   Coordinate with Su when wiring the call site.
#
# BASH-3.2 COMPATIBILITY
#   This file uses only POSIX sh constructs (no declare -A, no ${var,,},
#   no mapfile, no process substitution). It must pass:
#     bash -n lib/detect_runtime.sh
#     SC gate: shellcheck (shell=sh, enable=all) lib/detect_runtime.sh
#   Su owns the bash-3.2 portability gate (plan S6).
#
# ROOTLESS PODMAN L1 GAP (plan HIGH-01 / L4)
#   When YSG_RUNTIME_4WAY=podman-rootless, the ringfence-init iptables sidecar
#   cannot apply L1 containment (iptables inside a user-namespace requires
#   SYS_ADMIN / CAP_NET_ADMIN at the host level, not available rootless).
#   The codegen MUST emit a ROOTLESS-PODMAN-L1-GAP annotation in every
#   generated artifact. The detection here is the trigger for that branch.
#   L2 (Caddy egress enforcement) + L3 (OPA) remain active.
#
# TRUTH TABLE
#   See _detect_runtime_truth_table() below for the full decision matrix.
#   Unit tests at tests/install/test_detect_runtime.bats cover all 7 cases.

# Guard against double-source
[ -n "${_YSG_DETECT_RUNTIME_LOADED:-}" ] && return 0
_YSG_DETECT_RUNTIME_LOADED=1

# ── Internal helpers ──────────────────────────────────────────────────────────

# _dr_log: print to stderr (consistent with install.sh log pattern).
_dr_log() {
    printf '[detect_runtime] %s\n' "$*" >&2
}

# _dr_warn: print a WARNING line to stderr.
_dr_warn() {
    printf '[detect_runtime] WARN: %s\n' "$*" >&2
}

# _dr_is_k8s_incluster: return 0 if running inside a K8s pod.
# Detects: KUBERNETES_SERVICE_HOST env var + SA token file both present.
_dr_is_k8s_incluster() {
    _sa_token="/var/run/secrets/kubernetes.io/serviceaccount/token"
    [ -n "${KUBERNETES_SERVICE_HOST:-}" ] && [ -f "${_sa_token}" ]
}

# _dr_podman_reachable: return 0 if the Podman socket/daemon is reachable.
_dr_podman_reachable() {
    command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1
}

# _dr_docker_reachable: return 0 if the Docker daemon is reachable.
_dr_docker_reachable() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# _dr_is_rootless_podman: return 0 if Podman is running rootless (uid != 0
# AND /etc/subuid entry exists for the current user — the standard indicator
# of rootless container namespacing on Linux).
# On macOS (Docker Desktop, Podman Machine): uid check is sufficient.
_dr_is_rootless_podman() {
    # Primary: current UID is non-root (SC2312: capture id output separately)
    _current_uid="$(id -u 2>/dev/null)" || _current_uid="0"
    [ "${_current_uid}" -ne 0 ] || return 1
    # Secondary: /etc/subuid has an entry for this user (Linux rootless indicator)
    # On macOS this file typically doesn't exist — presence of podman at uid!=0 is enough.
    if [ -f "/etc/subuid" ]; then
        _current_user="$(id -un 2>/dev/null || true)"
        grep -qE "^${_current_user}:" /etc/subuid 2>/dev/null && return 0
        # Some systems use UID directly in subuid instead of username
        grep -qE "^${_current_uid}:" /etc/subuid 2>/dev/null && return 0
        # If /etc/subuid exists but has no entry for this user, this is rootful
        # Podman in a context where uid!=0 is not standard rootless
        # (e.g. a service account running rootful Podman as a non-root user).
        # Fall back to uid check only.
    fi
    # No /etc/subuid (macOS, some minimal Linux) — uid!=0 with reachable Podman
    # is our best indicator. Rootful Podman typically requires uid=0 on Linux.
    return 0
}

# ── Truth table (documentation + test anchor) ─────────────────────────────────
#
# _detect_runtime_truth_table: emit the truth table as a human-readable string.
# Used by tests and operator --runtime-info CLI flag.
#
# TRUTH TABLE (7 cases):
#
#   Case | K8s in-cluster | Podman reachable | Docker reachable | uid=0 | /etc/subuid | Result
#   -----|----------------|-----------------|-----------------|-------|-------------|--------
#    1   | YES            | —               | —               | —     | —           | k8s
#    2   | NO             | YES             | —               | NO    | YES         | podman-rootless
#    3   | NO             | YES             | —               | NO    | NO/absent   | podman-rootless (macOS/uid)
#    4   | NO             | YES             | —               | YES   | —           | podman-rootful
#    5   | NO             | NO              | YES             | —     | —           | docker
#    6   | NO             | YES             | YES             | —     | —           | podman-rootless|rootful (Podman preferred; Docker ignored)
#    7   | NO             | NO              | NO              | —     | —           | unknown
#
# Notes:
#   Case 6: when both Podman and Docker are reachable, Podman wins (rootless-first
#           security posture per install.sh). Docker is ignored for 4-way detection.
#           install.sh's YSG_RUNTIME explicit-choice wins over this default if set.
#   Case 4: rootful Podman (uid=0) — L1 iptables containment is available.
#   Cases 2+3: rootless Podman — L1 gap; codegen annotates artifact with gap warning.
#   Case 7: unknown — codegen emits an error and refuses to generate artifacts.
#
_detect_runtime_truth_table() {
    cat <<'EOF'
Yashigani _detect_runtime() 4-way truth table (plan §2.D L4 / HIGH-01)

Case | K8s in-cluster | Podman | Docker | uid=0 | subuid | YSG_RUNTIME_4WAY
-----|----------------|--------|--------|-------|--------|------------------
  1  | YES            | any    | any    | any   | any    | k8s
  2  | NO             | YES    | any    | NO    | YES    | podman-rootless
  3  | NO             | YES    | any    | NO    | absent | podman-rootless
  4  | NO             | YES    | any    | YES   | any    | podman-rootful
  5  | NO             | NO     | YES    | any   | any    | docker
  6  | NO             | YES    | YES    | NO    | any    | podman-rootless  (Podman preferred)
  7  | NO             | NO     | NO     | any   | any    | unknown

L1-gap indicator: YSG_RUNTIME_4WAY = podman-rootless
  Consequence: ringfence-init iptables will fail; codegen emits ROOTLESS-PODMAN-L1-GAP.
  L2 (Caddy egress) + L3 (OPA) remain active.
EOF
}

# ── Main detection function ───────────────────────────────────────────────────
#
# _detect_runtime: perform 4-way detection and set YSG_RUNTIME_4WAY.
#
# Respects YSG_RUNTIME if explicitly set to one of the four canonical values
# (docker|podman-rootful|podman-rootless|k8s). In that case, the function
# validates the claim and warns if the environment contradicts it.
#
# Sets:
#   YSG_RUNTIME_4WAY         — canonical 4-way value
#   YSG_RUNTIME_4WAY_NOTE    — human-readable explanation
#
# Returns: 0 on success (value set), 1 on unknown (value = "unknown").
_detect_runtime() {
    # If explicitly forced by caller, validate + accept.
    case "${YSG_RUNTIME_4WAY:-}" in
        docker|podman-rootful|podman-rootless|k8s)
            _dr_log "YSG_RUNTIME_4WAY already set explicitly: ${YSG_RUNTIME_4WAY}"
            export YSG_RUNTIME_4WAY
            YSG_RUNTIME_4WAY_NOTE="Explicitly set by caller — not auto-detected."
            export YSG_RUNTIME_4WAY_NOTE
            return 0
            ;;
        *)
            # Empty or unrecognised — fall through to auto-detection below.
            ;;
    esac

    # Honour legacy YSG_RUNTIME (from install.sh _resolve_compose_cmd) as a hint,
    # but extend it to 4-way (k8s and podman rootless/rootful split).
    # YSG_RUNTIME=podman → distinguish rootful vs rootless here.
    # YSG_RUNTIME=k8s    → map to k8s.
    # YSG_RUNTIME=docker → map to docker directly (FIND-INSTALL-3.1-004: skip Podman
    #                       reachability check so a box with both runtimes installed
    #                       reports docker-rootful, not podman-rootless, when the
    #                       operator passed --runtime docker).
    _legacy_hint="${YSG_RUNTIME:-}"

    # ── Case 1: K8s in-cluster ─────────────────────────────────────────────
    if _dr_is_k8s_incluster; then
        YSG_RUNTIME_4WAY="k8s"
        YSG_RUNTIME_4WAY_NOTE="K8s in-cluster: KUBERNETES_SERVICE_HOST set + SA token present. L1 enforced via NetworkPolicy + Kyverno PolicyException."
        export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
        _dr_log "Detected: k8s (in-cluster)"
        return 0
    fi

    # ── Case k8s from hint ─────────────────────────────────────────────────
    if [ "${_legacy_hint}" = "k8s" ]; then
        YSG_RUNTIME_4WAY="k8s"
        YSG_RUNTIME_4WAY_NOTE="K8s: YSG_RUNTIME=k8s explicit (not in-cluster context — Helm/kubectl install path)."
        export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
        _dr_log "Detected: k8s (from YSG_RUNTIME hint)"
        return 0
    fi

    # ── Case docker from hint (FIND-INSTALL-3.1-004) ──────────────────────
    # When the operator passed --runtime docker (YSG_RUNTIME=docker), honour
    # that decision and skip the Podman reachability check. On a box where both
    # Docker Engine and rootless Podman are installed, Podman is reachable, so
    # the auto-detection falls into the podman-rootless branch and mislabels
    # the runtime — causing a false L1-gap warning and wrong ring-fence codegen.
    if [ "${_legacy_hint}" = "docker" ]; then
        if _dr_docker_reachable; then
            YSG_RUNTIME_4WAY="docker"
            YSG_RUNTIME_4WAY_NOTE="Docker Engine (YSG_RUNTIME=docker explicit). Full L1 containment available (iptables + ip6tables). NET_ADMIN required on ringfence-init container."
            export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
            _dr_log "Detected: docker (from YSG_RUNTIME=docker hint)"
            return 0
        fi
        _dr_warn "YSG_RUNTIME=docker but Docker daemon unreachable — falling through to auto-detection."
    fi

    # ── Cases 2-4: Podman ────────────────────────────────────────────────
    # Podman preferred over Docker when both are reachable.
    if _dr_podman_reachable; then
        # SC2312: capture id output separately
        _uid_for_note="$(id -u 2>/dev/null || printf '?')"
        if _dr_is_rootless_podman; then
            YSG_RUNTIME_4WAY="podman-rootless"
            YSG_RUNTIME_4WAY_NOTE="Podman rootless (uid=${_uid_for_note}, user-namespace remapping). L1-GAP: iptables init-sidecar cannot apply L1 containment. L2+L3 active. Upgrade to rootful Podman or K8s for full L1."
            export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
            _dr_warn "podman-rootless detected — L1 network-plane containment NOT available (ROOTLESS-PODMAN-L1-GAP)"
            _dr_warn "L2 (Caddy egress) + L3 (OPA) remain active. Codegen will annotate artifacts with gap warning."
        else
            YSG_RUNTIME_4WAY="podman-rootful"
            YSG_RUNTIME_4WAY_NOTE="Podman rootful (uid=${_uid_for_note}). Full L1 containment available (iptables + ip6tables). NET_ADMIN required on ringfence-init container."
            export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
            _dr_log "Detected: podman-rootful"
        fi
        return 0
    fi

    # ── Case 5: Docker ────────────────────────────────────────────────────
    if _dr_docker_reachable; then
        YSG_RUNTIME_4WAY="docker"
        YSG_RUNTIME_4WAY_NOTE="Docker Engine / Docker Desktop. Full L1 containment available (iptables + ip6tables). NET_ADMIN required on ringfence-init container."
        export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
        _dr_log "Detected: docker"
        return 0
    fi

    # ── Case 7: Unknown ───────────────────────────────────────────────────
    YSG_RUNTIME_4WAY="unknown"
    YSG_RUNTIME_4WAY_NOTE="No K8s SA token, no reachable Podman socket, no reachable Docker daemon. Codegen cannot produce ring-fence artifacts — set YSG_RUNTIME_4WAY explicitly."
    export YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE
    _dr_warn "Runtime detection failed — no K8s, Podman, or Docker reachable."
    _dr_warn "Set YSG_RUNTIME_4WAY=docker|podman-rootful|podman-rootless|k8s explicitly."
    return 1
}

# ── L1-gap annotation helper (for use by codegen) ────────────────────────────
#
# _detect_runtime_l1_gap_annotation: emit the ROOTLESS-PODMAN-L1-GAP comment
# block that codegen inserts into generated docker-compose.override.yml stanzas
# when YSG_RUNTIME_4WAY=podman-rootless.
#
# Usage (codegen):
#   if [ "${YSG_RUNTIME_4WAY}" = "podman-rootless" ]; then
#     _detect_runtime_l1_gap_annotation
#   fi
_detect_runtime_l1_gap_annotation() {
    cat <<'GAPEOF'
# ─────────────────────────────────────────────────────────────────────────────
# ROOTLESS-PODMAN-L1-GAP: ringfence-init iptables will NOT apply.
# L1 network-plane containment is NOT active for this deployment.
#   Runtime: podman-rootless (uid != 0 / user-namespace remapping)
#   Reason:  iptables in a user-namespace requires SYS_ADMIN / CAP_NET_ADMIN
#            at the host level. Rootless Podman grants neither.
# Active controls:
#   L2: Caddy egress enforcement (Caddyfile route + hardcoded upstreams)
#   L3: OPA per-call policy (fail-closed, 500ms timeout)
# Upgrade path for L1 containment:
#   - Switch to rootful Podman: YSG_RUNTIME=podman (run as root or via sudo)
#   - OR deploy to Kubernetes (NetworkPolicy enforces L1 at CNI level)
# ─────────────────────────────────────────────────────────────────────────────
GAPEOF
}

# ── YSG_RUNTIME embedding (for generated artifact comments) ──────────────────
#
# _detect_runtime_artifact_comment: emit a one-line comment string embedding
# YSG_RUNTIME_4WAY for insertion into generated compose/helm/shell artifacts.
# Example output: "# Generated by yashigani onboard. YSG_RUNTIME=podman-rootless"
_detect_runtime_artifact_comment() {
    printf '# Generated by yashigani onboard. YSG_RUNTIME_4WAY=%s\n' \
        "${YSG_RUNTIME_4WAY:-unknown}"
}
