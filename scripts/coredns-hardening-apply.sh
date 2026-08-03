#!/usr/bin/env bash
# scripts/coredns-hardening-apply.sh — patch a cluster's kube-system CoreDNS
# Corefile with the DNSSEC-delegated-validation + DoT forward block.
#
# SINGLE SOURCE OF TRUTH for the hardened forward/cache configuration. Both
# scripts/k3s-bootstrap.sh and install.sh (--apply-coredns-hardening) call
# THIS script rather than embedding the Corefile content themselves — do not
# duplicate it anywhere else in the repo (SOP 0: two copies of any
# file/config fragment is a bug).
#
# Authority: AgnosticSecurity/Products/Yashigani/
#   yashigani-k8s-dns-hardening-design-20260719.md §1.
#
# IMPLEMENTATION NOTE (deviates from the design doc's illustration, same
# substance): the design doc illustrates the TARGET as two separate
# top-level server blocks (a pure "." forward block + a dedicated
# "cluster.local:53" block for the `kubernetes` plugin). The Corefile every
# real cluster actually ships (stock k3s, kubeadm, EKS, GKE) is a SINGLE
# combined "." block containing `kubernetes ... fallthrough` AND `forward`
# together. Restructuring that into two blocks on every customer cluster is
# unnecessary and riskier (more of the operator's existing config touched)
# than achieving the identical security property in place: this script
# finds the "." block's `forward` and `cache` directives (brace-aware, so
# it never mis-parses nested plugin blocks) and replaces ONLY those two
# directives with the hardened DoT forward + tuned cache. Every other
# directive in the block — `kubernetes` (+ options), `errors`, `health`,
# `ready`, `prometheus`, `loop`, `reload`, `loadbalance`, and anything else
# an operator has already added — is preserved byte-for-byte, in place.
# Blocks other than "." (e.g. an already-split "cluster.local:53" block, or
# any custom zone) are never touched. If no "." block exists at all, a
# fresh one (design doc's canonical form, no `kubernetes` plugin) is
# prepended — this only fires on a topology with no catch-all zone, which
# would otherwise have no DNS resolution path out of the cluster at all.
#
# Fail-closed, idempotent (no-op if the Corefile already matches), no
# plaintext fallback stanza is ever added — see design doc §1 anti-pattern
# note: a well-meaning "forward . 8.8.8.8" reliability fallback silently
# defeats the whole control.
#
# Usage:
#   scripts/coredns-hardening-apply.sh [--upstream-provider cloudflare|quad9]
#                                       [--backup-dir DIR] [--dry-run] [--help]
#
# Env overrides (same names the flags set):
#   COREDNS_UPSTREAM_PROVIDER   cloudflare (default) | quad9
#   COREDNS_BACKUP_DIR          default: /var/lib/yashigani/coredns-backups
#
set -euo pipefail

# Hardened PATH — never trust an inherited PATH for a script that mutates a
# shared cluster resource.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# ---------------------------------------------------------------------------
# Defaults / flags
# ---------------------------------------------------------------------------
UPSTREAM_PROVIDER="${COREDNS_UPSTREAM_PROVIDER:-cloudflare}"
# --upstream-provider custom: name an INTERNALLY-CONTROLLED validating resolver
# instead of a public one. The ratified design (yashigani-k8s-dns-hardening-design
# §1) requires "(a) the upstream is a validating resolver we trust, and (b) the
# forward hop is authenticated+encrypted with a pinned server name" -- it does NOT
# require the upstream be public. An internal DoT resolver satisfies both, and
# keeps query metadata (incl. agent/MCP egress targets) inside the estate.
# The tls:// + pinned tls_servername requirement is UNCHANGED and non-negotiable.
UPSTREAM_ADDR="${COREDNS_UPSTREAM_ADDR:-}"
TLS_SERVERNAME_ARG="${COREDNS_TLS_SERVERNAME:-}"
BACKUP_DIR="${COREDNS_BACKUP_DIR:-/var/lib/yashigani/coredns-backups}"
DRY_RUN=false
NAMESPACE="kube-system"
CONFIGMAP_NAME="coredns"

_usage() {
  cat <<'EOF'
Usage: scripts/coredns-hardening-apply.sh [OPTIONS]

Patches kube-system/coredns's "." (external) forward+cache configuration with
DNSSEC-delegated-validation over DoT. cluster.local resolution (the
`kubernetes` plugin) and any other existing zones/directives are preserved
unchanged, in place.

Options:
  --upstream-provider PROVIDER   cloudflare (default) | quad9 | custom
  --upstream-addr ADDR            (custom) resolver IP, or "ip1,ip2" for failover
  --tls-servername NAME           (custom) pinned TLS server name for the hop
  --backup-dir DIR                Where to write the pre-patch Corefile backup
                                   (default: /var/lib/yashigani/coredns-backups)
  --dry-run                       Print the resulting Corefile, apply nothing
  --help                          Print this help message

Exit codes:
  0  Applied (or already up to date)
  1  Failed — see stderr
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream-provider) UPSTREAM_PROVIDER="${2:?--upstream-provider requires a value}"; shift 2 ;;
    --upstream-addr)     UPSTREAM_ADDR="${2:?--upstream-addr requires a value}"; shift 2 ;;
    --tls-servername)    TLS_SERVERNAME_ARG="${2:?--tls-servername requires a value}"; shift 2 ;;
    --backup-dir)        BACKUP_DIR="${2:?--backup-dir requires a value}"; shift 2 ;;
    --dry-run)            DRY_RUN=true; shift ;;
    --help|-h)             _usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; _usage >&2; exit 1 ;;
  esac
done

_log_info()    { printf '    --> %s\n' "$1"; }
_log_ok()      { printf '    ok  %s\n' "$1"; }
_log_warn()    { printf '    !!  WARNING: %s\n' "$1" >&2; }
_log_err()     { printf '    !!  ERROR: %s\n' "$1" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { _log_err "Required command not found in PATH: $1"; exit 1; }
}

require_cmd kubectl
require_cmd python3

case "$UPSTREAM_PROVIDER" in
  cloudflare)
    UPSTREAM_1="1.1.1.1"
    UPSTREAM_2="1.0.0.1"
    TLS_SERVERNAME="cloudflare-dns.com"
    ;;
  quad9)
    UPSTREAM_1="9.9.9.9"
    UPSTREAM_2="149.112.112.112"
    TLS_SERVERNAME="dns.quad9.net"
    ;;
  custom)
    if [[ -z "$UPSTREAM_ADDR" || -z "$TLS_SERVERNAME_ARG" ]]; then
      _log_err "--upstream-provider custom requires BOTH --upstream-addr and --tls-servername"
      _log_err "  e.g. --upstream-provider custom --upstream-addr 10.1.2.3 \\"
      _log_err "       --tls-servername dns.internal.example"
      _log_err "  (the pinned servername is what authenticates the hop -- design doc §1)"
      exit 1
    fi
    # Accept "ip" or "ip1,ip2" for forward's built-in failover.
    UPSTREAM_1="${UPSTREAM_ADDR%%,*}"
    if [[ "$UPSTREAM_ADDR" == *,* ]]; then UPSTREAM_2="${UPSTREAM_ADDR##*,}"; else UPSTREAM_2=""; fi
    TLS_SERVERNAME="$TLS_SERVERNAME_ARG"
    ;;
  *)
    _log_err "Unknown --upstream-provider '${UPSTREAM_PROVIDER}' (use: cloudflare|quad9|custom)"
    exit 1
    ;;
esac

_log_info "Target: configmap/${CONFIGMAP_NAME} -n ${NAMESPACE}"
_log_info "Upstream: ${UPSTREAM_PROVIDER} (tls://${UPSTREAM_1}${UPSTREAM_2:+ tls://${UPSTREAM_2}}, tls_servername=${TLS_SERVERNAME})"

# ---------------------------------------------------------------------------
# Read the existing Corefile
# ---------------------------------------------------------------------------
if ! kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP_NAME" >/dev/null 2>&1; then
  _log_err "configmap/${CONFIGMAP_NAME} not found in namespace ${NAMESPACE}."
  _log_err "This does not look like a cluster with a standard CoreDNS install — aborting."
  exit 1
fi

OLD_COREFILE="$(kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP_NAME" -o jsonpath='{.data.Corefile}')"
if [[ -z "$OLD_COREFILE" ]]; then
  _log_err "configmap/${CONFIGMAP_NAME} has no 'Corefile' data key — aborting (unexpected shape)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Brace-aware, minimal-diff patch — see IMPLEMENTATION NOTE at the top of
# this file. Done in python3 (not sed/awk) because CoreDNS directives nest
# braces (e.g. `forward . ... { ... }`) — a naive line-regex replace risks
# corrupting an operator's existing config. Values passed via environment,
# never interpolated into the python source, to avoid any injection surface
# from Corefile content or upstream values.
# ---------------------------------------------------------------------------
NEW_COREFILE="$(
  OLD_COREFILE="$OLD_COREFILE" \
  UPSTREAM_1="$UPSTREAM_1" UPSTREAM_2="$UPSTREAM_2" TLS_SERVERNAME="$TLS_SERVERNAME" \
  python3 <<'PYEOF'
import os
import re
import sys

old = os.environ["OLD_COREFILE"]
u1 = os.environ["UPSTREAM_1"]
u2 = os.environ["UPSTREAM_2"]
servername = os.environ["TLS_SERVERNAME"]

ROOT_HEADERS = {".:53", ".", ":53"}


def split_blocks(text):
    """Split a Corefile into (header, full_block_text) tuples, brace-depth
    aware so nested plugin blocks don't terminate a split early. Trailing
    non-block text (comments/whitespace) is preserved as (None, text)."""
    blocks = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        brace_idx = text.find("{", i)
        if brace_idx == -1:
            tail = text[i:].strip()
            if tail:
                blocks.append((None, text[i:]))
            break
        header = text[i:brace_idx].strip()
        depth = 1
        j = brace_idx + 1
        while j < n and depth > 0:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        blocks.append((header, text[i:j]))
        i = j
    return blocks


def is_root_header(header):
    if header is None:
        return False
    tokens = header.split()
    return header in ROOT_HEADERS or any(tok in ROOT_HEADERS for tok in tokens)


def find_directive(body, name):
    """Find the first top-level directive `name` in a block's body text
    (already stripped of the outer braces). Brace-aware for a directive that
    opens its own `{ ... }`. Returns (ws_start, name_start, end, indent) or
    None — ws_start/name_start are split so a caller can preserve the
    original leading indentation when substituting in a replacement."""
    pattern = re.compile(r"(?m)^([ \t]*)" + re.escape(name) + r"(?=[ \t{]|$)")
    m = pattern.search(body)
    if not m:
        return None
    ws_start = m.start()
    indent = m.group(1)
    name_start = ws_start + len(indent)
    header_end = body.find("\n", m.end())
    if header_end == -1:
        header_end = len(body)
    brace_on_line = body.find("{", m.end(), header_end)
    if brace_on_line != -1:
        depth = 1
        j = brace_on_line + 1
        n = len(body)
        while j < n and depth > 0:
            if body[j] == "{":
                depth += 1
            elif body[j] == "}":
                depth -= 1
            j += 1
        end = j
    else:
        end = header_end
    return ws_start, name_start, end, indent


# u2 is optional: --upstream-provider custom may name a single internal
# resolver. Emitting a bare "tls://" for an empty u2 would render an invalid
# Corefile, so build the upstream list from the non-empty entries only.
_upstreams = " ".join("tls://%s" % _u for _u in (u1, u2) if _u)

NEW_FORWARD = (
    "forward . %s {\n"
    "        tls_servername %s\n"
    "        health_check 5s\n"
    "        max_fails 2\n"
    "        expire 10s\n"
    "    }"
) % (_upstreams, servername)

NEW_CACHE = "cache 30 {\n        success 9984\n        denial 9984\n    }"

NEW_ROOT_BLOCK_FRESH = (
    ".:53 {\n"
    "    errors\n"
    "    health\n"
    "    ready\n"
    "    prometheus :9153\n"
    "    %s\n"
    "    %s\n"
    "    loop\n"
    "    reload\n"
    "    loadbalance\n"
    "}"
) % (NEW_FORWARD, NEW_CACHE)


def patch_root_block(block_text):
    """Replace ONLY the forward + cache directives inside a "." block,
    leaving every other directive (kubernetes/fallthrough, errors, health,
    ready, prometheus, loop, reload, loadbalance, anything custom) untouched
    and in its original position."""
    first_brace = block_text.find("{")
    header = block_text[:first_brace].rstrip()
    # body excludes the outer braces
    body = block_text[first_brace + 1 : block_text.rfind("}")]

    forward_match = find_directive(body, "forward")
    if forward_match:
        ws, _ns, fe, indent = forward_match
        replacement = indent + NEW_FORWARD
        body = body[:ws] + replacement + body[fe:]
        insert_after = ws + len(replacement)
    else:
        # No forward directive present — append just before the closing
        # brace rather than guessing a position; everything else untouched.
        body = body.rstrip("\n") + "\n    " + NEW_FORWARD
        insert_after = len(body)

    cache_match = find_directive(body, "cache")
    if cache_match:
        ws, _ns, ce, indent = cache_match
        body = body[:ws] + indent + NEW_CACHE + body[ce:]
    else:
        body = body[:insert_after] + "\n    " + NEW_CACHE + body[insert_after:]

    return header + " {" + body.rstrip("\n") + "\n}"


blocks = split_blocks(old)
root_idx = None
for idx, (header, _text) in enumerate(blocks):
    if is_root_header(header):
        root_idx = idx
        break

if root_idx is not None:
    out_blocks = []
    for idx, (header, text) in enumerate(blocks):
        if idx == root_idx:
            out_blocks.append(patch_root_block(text).strip())
        else:
            out_blocks.append(text.strip())
elif blocks:
    # No "." (catch-all) block anywhere, but other blocks exist (e.g. an
    # already-split cluster.local-only topology missing its root block).
    # Prepend a fresh canonical root block; leave every existing block
    # untouched. Never delete anything.
    out_blocks = [NEW_ROOT_BLOCK_FRESH] + [t.strip() for _h, t in blocks]
else:
    print(
        "ERROR: the existing Corefile has no parseable server blocks at all — "
        "refusing to guess. Inspect and apply the design doc §1 change by hand: "
        "AgnosticSecurity/Products/Yashigani/"
        "yashigani-k8s-dns-hardening-design-20260719.md",
        file=sys.stderr,
    )
    sys.exit(1)

print("\n\n".join(out_blocks) + "\n")
PYEOF
)"

if [[ -z "$NEW_COREFILE" ]]; then
  _log_err "Corefile transform produced no output — refusing to apply. No changes made."
  exit 1
fi

# ---------------------------------------------------------------------------
# Idempotency: no-op if nothing changed
# ---------------------------------------------------------------------------
if [[ "$NEW_COREFILE" == "$OLD_COREFILE" ]]; then
  _log_ok "CoreDNS Corefile already matches the hardened DoT/DNSSEC configuration — no-op."
  exit 0
fi

if [[ "$DRY_RUN" == "true" ]]; then
  _log_info "--dry-run: would apply the following Corefile (not applied):"
  printf '%s\n' "$NEW_COREFILE"
  exit 0
fi

# ---------------------------------------------------------------------------
# Backup the pre-patch Corefile
# ---------------------------------------------------------------------------
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="${BACKUP_DIR}/Corefile.$(date -u +%Y%m%dT%H%M%SZ).bak"
printf '%s' "$OLD_COREFILE" > "$BACKUP_FILE"
chmod 0644 "$BACKUP_FILE"
_log_ok "Pre-patch Corefile backed up: ${BACKUP_FILE}"

# ---------------------------------------------------------------------------
# Apply atomically via generate-then-apply (never a string-merge patch —
# avoids any risk of a partial/garbled Corefile mid-mutation).
# ---------------------------------------------------------------------------
if ! kubectl -n "$NAMESPACE" create configmap "$CONFIGMAP_NAME" \
      --from-literal="Corefile=${NEW_COREFILE}" \
      --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null; then
  _log_err "kubectl apply of the patched Corefile failed — cluster CoreDNS ConfigMap unchanged"
  _log_err "(backup at ${BACKUP_FILE} for reference; this run made no changes)."
  exit 1
fi
_log_ok "configmap/${CONFIGMAP_NAME} updated with DoT/DNSSEC forward block (upstream: ${UPSTREAM_PROVIDER})."

# ---------------------------------------------------------------------------
# Roll CoreDNS to pick up the new ConfigMap (kubelet's configmap sync lag can
# be up to ~60s otherwise). Handle both Deployment (k3s/kubeadm default) and
# DaemonSet (some distros) shapes.
# ---------------------------------------------------------------------------
if kubectl -n "$NAMESPACE" get deployment coredns >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" rollout restart deployment/coredns >/dev/null
  if ! kubectl -n "$NAMESPACE" rollout status deployment/coredns --timeout=120s >/dev/null; then
    _log_err "CoreDNS deployment did not roll out within 120s after the Corefile patch."
    _log_err "Investigate: kubectl -n ${NAMESPACE} get pods -l k8s-app=kube-dns"
    exit 1
  fi
elif kubectl -n "$NAMESPACE" get daemonset coredns >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" rollout restart daemonset/coredns >/dev/null
  if ! kubectl -n "$NAMESPACE" rollout status daemonset/coredns --timeout=120s >/dev/null; then
    _log_err "CoreDNS daemonset did not roll out within 120s after the Corefile patch."
    _log_err "Investigate: kubectl -n ${NAMESPACE} get pods -l k8s-app=kube-dns"
    exit 1
  fi
else
  _log_warn "No coredns Deployment or DaemonSet found in ${NAMESPACE} to restart."
  _log_warn "ConfigMap was patched, but CoreDNS pods may take up to ~60s to pick it up on their own."
fi

_log_ok "CoreDNS rolled out with the hardened Corefile."
_log_ok "No plaintext fallback stanza was added — a forward failure now fails closed (SERVFAIL),"
_log_ok "per design doc §1. Verify with: install.sh's DNS-01/DNS-02 preflight, or"
_log_ok "'kubectl -n ${NAMESPACE} get configmap ${CONFIGMAP_NAME} -o jsonpath={.data.Corefile}'"
exit 0
