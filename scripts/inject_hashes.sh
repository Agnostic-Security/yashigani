#!/usr/bin/env bash
# inject_hashes.sh — Build-pipeline v2: inject root->leaf chain-of-trust
# constants into _integrity.py (supersedes the v1 counter-key/HASH_BUNDLE_SIG/
# EXPECTED_TOKEN_HMAC scheme — KDF token step DROPPED entirely in v2, per
# Tom's _integrity.py rewrite for licence-hardening-v2).
#
# Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
#      §2.2 (anchor-SET) + §3.1 (leaf_cert) + §3.3 (hash bundle) plus the
#      LAURA-V2-001/002 fix (2026-07-15): INTEGRITY_HASH is now a REAL, wired
#      self-hash (blank-then-hash convention) folded into the signed bundle —
#      closing both "self-checks live inside the file they protect"
#      (LAURA-V2-001) and "kill-list/anchor-set/leaf-cert are unsigned"
#      (LAURA-V2-002). This SUPERSEDES the old "INTEGRITY_HASH excluded from
#      the signed bundle — unresolvable circularity" deviation: the
#      blank-then-hash convention (both INTEGRITY_HASH's and BUNDLE_SIG's own
#      line-values are replaced with a fixed placeholder before hashing)
#      resolves that circularity, so order of embedding INTEGRITY_HASH vs
#      BUNDLE_SIG no longer matters. This script's algorithm for computing
#      INTEGRITY_HASH MUST stay byte-identical to
#      verifier._compute_integrity_self_hash() — see Step 4 below.
#
#      2026-07-16 follow-up (LAURA-V2-001, "replacing require_feature()'s
#      whole body still yields the feature"): the bundle now ALSO covers 5
#      point-of-use (POU) files — sso/oidc.py, sso/saml.py,
#      backoffice/routes/sso.py, backoffice/routes/scim.py, and
#      licensing/gate_middleware.py — the files that do the ACTUAL privileged
#      work of a licence-gated capability and each carry their own local
#      `_licence_hard_gate()`. The bundle is now ELEVEN lines (was six).
#
#      2026-07-17 fix (LAURA-V2-005 — root-of-trust substitution via
#      _integrity.py alone, zero mesh files touched): the root-of-trust
#      constants (MASTER_ANCHOR_SET_JSON/CODE_LEAF_CERT_JSON/
#      CODE_LEAF_CERT_SIG/KILL_LIST_JSON/CLIENT_DOMAIN_REGISTRY_JSON) are now
#      embedded FIRST (Step 0a/0b, was Steps 2/3), and a derived pin
#      (_EXPECTED_INTEGRITY_ROOT_HASH — Step 0c) is stamped into ALL 7 mesh
#      files' own bytes BEFORE their SHA-256 (Step 1) is taken, so editing
#      ONLY _integrity.py's root-of-trust fields is now caught by every one
#      of the 7 mesh files independently (see licensing/verifier.py's
#      module-level comment above _check_integrity_root_pin()). verifier.py
#      separately hardcodes the real master pubkey(s)
#      (_PINNED_MASTER_ANCHOR_PEMS) and rejects any anchor set that doesn't
#      chain to one — this is NOT build-injected, it is a source-level pin
#      that changes only via a reviewed code release.
#
# Steps (ORDER MATTERS — Step 0c's pin must be stamped into the 7 mesh files
# BEFORE Step 1 hashes them, and INTEGRITY_HASH in Step 4 must be computed
# AFTER every OTHER constant is finalised, so it actually covers them):
#   Step 0a: Embed the chain-of-trust root constants — MASTER_ANCHOR_SET_JSON,
#            CODE_LEAF_CERT_JSON, CODE_LEAF_CERT_SIG — from files produced by
#            `licgen release` / `keygen.py leaf new` + `licgen anchor-set emit`.
#   Step 0b: Optionally embed KILL_LIST_JSON / CLIENT_DOMAIN_REGISTRY_JSON if
#            provided (both have SAFE defaults "[]"/"{}" already in source —
#            unlike Step 0a, an unset Step 0b is not a placeholder failure).
#   Step 0c: Derive _EXPECTED_INTEGRITY_ROOT_HASH from the Step 0a/0b values
#            and stamp it into all 7 mesh files (LAURA-V2-005).
#   Step 1: Compute SHA-256 of 10 licensing/agent/identity/sso/routes/
#           middleware modules (now including the Step 0c stamp) → write
#           into VERIFIER_HASH/ENFORCER_HASH/LOADER_HASH/AGENTS_REGISTRY_
#           HASH/IDENTITY_REGISTRY_HASH (T1-T4 bundle — unchanged v1
#           mechanism) plus OIDC_MODULE_HASH/SAML_MODULE_HASH/SSO_ROUTES_
#           HASH/SCIM_ROUTES_HASH/GATE_MIDDLEWARE_HASH (POU bundle, added
#           2026-07-16).
#   Step 3c: Mesh full topology (member-order polymorphism, unchanged).
#   Step 4: Compute INTEGRITY_HASH — the blank-then-hash self-referential
#           digest of _integrity.py's CURRENT bytes (Steps 0-3 already
#           embedded; the INTEGRITY_HASH and BUNDLE_SIG line-values are
#           blanked to a fixed placeholder before hashing, regardless of
#           their current contents) → write it.
#   Step 5: Build the canonical ELEVEN-line bundle string (5 T1-T4 hashes +
#           5 POU hashes + INTEGRITY_HASH, sorted KEY=hex lines, \n-joined,
#           no trailing newline — SAME construction as
#           verifier._compute_live_hash_bundle_str()) → sign with the CODE
#           leaf's private key via sign_bundle_v2.py (P-384/SHA-384, chain
#           digest §3.3) → BUNDLE_SIG. Embedding BUNDLE_SIG does NOT
#           invalidate the Step 4 INTEGRITY_HASH (its own line is blanked
#           out of that computation).
#
# Usage:
#   CODE_LEAF_KEY_PATH=/run/secrets/code_leaf_private_key \\
#   CODE_LEAF_CERT_PATH=keys/code-4.1.1_leaf_cert.json \\
#   CODE_LEAF_CERT_SIG_PATH=keys/code-4.1.1_leaf_cert.sig.b64 \\
#   MASTER_ANCHOR_SET_PATH=keys/anchor_set.json \\
#   SRC_ROOT=/build/src \\
#   bash scripts/inject_hashes.sh
#
# Required environment:
#   CODE_LEAF_KEY_PATH        Path to the CODE leaf's PRIVATE key PEM (never
#                              baked into the image — Docker BuildKit secret).
#   CODE_LEAF_CERT_PATH       Path to this release's master-signed leaf_cert
#                              JSON (public — safe to bake in).
#   CODE_LEAF_CERT_SIG_PATH   Path to the base64 master signature over that
#                              leaf_cert (public).
#   MASTER_ANCHOR_SET_PATH    Path to the current trust-anchor SET JSON
#                              (public) — from `licgen anchor-set emit`.
#   SRC_ROOT                  Root of the Python source tree (default: src/).
#
# Optional:
#   KILL_LIST_PATH             Path to a kill-list JSON file (public). Unset
#                               leaves the safe "[]" default untouched.
#   CLIENT_DOMAIN_REGISTRY_PATH Path to {client_id:org_domain} JSON (public).
#                               Unset leaves the safe "{}" default untouched.
#   RELEASE_VERSION             This release's version string, folded into the
#                               mesh full-topology seed derivation (Step 3c).
#                               Defaults to a placeholder if unset (dev/test
#                               convenience) — set it for real releases.
#   MESH_SEED                   Per-release mesh-topology seed (Step 3c,
#                               LAURA-V2-003 Phase D hardening). Auto-generated
#                               (openssl rand -hex 16) and PRINTED if unset —
#                               record it to reproduce the exact topology.
#   FIPS_MODE=1                 Use lib/yashigani-fips.sh:_fips_sha256 for T1-T4.
#   SCRIPT_DIR                  Directory containing sign_bundle_v2.py
#                               (default: same directory as this script).
#   INTEGRITY_PY                 Explicit path to _integrity.py (override).
#   CODE_LEAF_KEY_PASSPHRASE /
#   YASHIGANI_KEY_PASSPHRASE     Passphrase for CODE_LEAF_KEY_PATH (MC-01,
#                                 resolved by sign_bundle_v2.py — see its
#                                 own docstring for precedence).
#
# Aborts (non-zero exit) on any failure — never falls back to placeholder
# values. Every private-key path is read-only from this script's point of
# view; only PUBLIC artefacts (certs/sigs/anchor-set/kill-list) are ever
# written into _integrity.py.

set -euo pipefail
IFS=$'\n\t'

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# ---------------------------------------------------------------------------
# Locate script dir and source root
# ---------------------------------------------------------------------------

SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SRC_ROOT="${SRC_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)/src}"

INTEGRITY_PY="${INTEGRITY_PY:-${SRC_ROOT}/yashigani/licensing/_integrity.py}"
VERIFIER_PY="${SRC_ROOT}/yashigani/licensing/verifier.py"
ENFORCER_PY="${SRC_ROOT}/yashigani/licensing/enforcer.py"
LOADER_PY="${SRC_ROOT}/yashigani/licensing/loader.py"
AGENTS_REGISTRY_PY="${SRC_ROOT}/yashigani/agents/registry.py"
IDENTITY_REGISTRY_PY="${SRC_ROOT}/yashigani/identity/registry.py"

# Point-of-use (POU) protected files — added 2026-07-16 (LAURA-V2-001
# follow-up: "replacing require_feature()'s whole body still yields the
# feature"). These are the files that do the ACTUAL privileged work of a
# licence-gated capability, covered by the same live-hash + BUNDLE_SIG
# mechanism as the T1-T4 files above. See _integrity.py's module docstring.
OIDC_MODULE_PY="${SRC_ROOT}/yashigani/sso/oidc.py"
SAML_MODULE_PY="${SRC_ROOT}/yashigani/sso/saml.py"
SSO_ROUTES_PY="${SRC_ROOT}/yashigani/backoffice/routes/sso.py"
SCIM_ROUTES_PY="${SRC_ROOT}/yashigani/backoffice/routes/scim.py"
GATE_MIDDLEWARE_PY="${SRC_ROOT}/yashigani/licensing/gate_middleware.py"

SIGN_BUNDLE_PY="${SCRIPT_DIR}/sign_bundle_v2.py"

# ---------------------------------------------------------------------------
# Validate required env vars and paths
# ---------------------------------------------------------------------------

: "${CODE_LEAF_KEY_PATH:?CODE_LEAF_KEY_PATH must be set (path to code leaf private key PEM)}"
: "${CODE_LEAF_CERT_PATH:?CODE_LEAF_CERT_PATH must be set (path to the release leaf_cert JSON)}"
: "${CODE_LEAF_CERT_SIG_PATH:?CODE_LEAF_CERT_SIG_PATH must be set (path to base64 leaf_cert_sig)}"
: "${MASTER_ANCHOR_SET_PATH:?MASTER_ANCHOR_SET_PATH must be set (path to the trust-anchor SET JSON)}"

for _f in \
    "$INTEGRITY_PY" "$VERIFIER_PY" "$ENFORCER_PY" "$LOADER_PY" \
    "$AGENTS_REGISTRY_PY" "$IDENTITY_REGISTRY_PY" \
    "$OIDC_MODULE_PY" "$SAML_MODULE_PY" "$SSO_ROUTES_PY" "$SCIM_ROUTES_PY" "$GATE_MIDDLEWARE_PY" \
    "$SIGN_BUNDLE_PY" \
    "$CODE_LEAF_KEY_PATH" "$CODE_LEAF_CERT_PATH" "$CODE_LEAF_CERT_SIG_PATH" "$MASTER_ANCHOR_SET_PATH"; do
    if [ ! -f "$_f" ]; then
        printf 'ERROR: required file not found: %s\n' "$_f" >&2
        exit 1
    fi
done

if [ -n "${KILL_LIST_PATH:-}" ] && [ ! -f "${KILL_LIST_PATH}" ]; then
    printf 'ERROR: KILL_LIST_PATH=%s does not exist\n' "${KILL_LIST_PATH}" >&2
    exit 1
fi
if [ -n "${CLIENT_DOMAIN_REGISTRY_PATH:-}" ] && [ ! -f "${CLIENT_DOMAIN_REGISTRY_PATH}" ]; then
    printf 'ERROR: CLIENT_DOMAIN_REGISTRY_PATH=%s does not exist\n' "${CLIENT_DOMAIN_REGISTRY_PATH}" >&2
    exit 1
fi

# Private key permissions — refuse to use world- or group-readable private key (CWE-732)
_key_mode="$(stat -c '%a' "${CODE_LEAF_KEY_PATH}" 2>/dev/null || stat -f '%A' "${CODE_LEAF_KEY_PATH}" 2>/dev/null || echo 'unknown')"
case "${_key_mode}" in
    400|600|"unknown") ;;  # acceptable; unknown = non-Linux stat (macOS variation above covers it)
    *)
        printf 'ERROR: code leaf private key %s has permissions %s — expected 400 or 600 (CWE-732)\n' \
            "${CODE_LEAF_KEY_PATH}" "${_key_mode}" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# SHA-256 helper — FIPS-aware (T1-T4 mechanism, unchanged from v1)
# ---------------------------------------------------------------------------

if [ "${FIPS_MODE:-0}" = "1" ]; then
    # shellcheck source=../lib/yashigani-fips.sh
    . "${SCRIPT_DIR}/../lib/yashigani-fips.sh"
    _sha256_file() { _fips_sha256 "$1"; }
else
    _sha256_file() {
        sha256sum "$1" | cut -d' ' -f1
    }
fi

# ---------------------------------------------------------------------------
# Placeholder replacement helper (single-line string constants)
# ---------------------------------------------------------------------------

_replace_constant() {
    local _file="$1"
    local _name="$2"
    local _value="$3"

    python3 - "$_file" "$_name" "$_value" <<'PYEOF'
import sys, re, pathlib

file_path = pathlib.Path(sys.argv[1])
const_name = sys.argv[2]
new_value = sys.argv[3]

content = file_path.read_text(encoding="utf-8")

pattern = re.compile(
    r'^(' + re.escape(const_name) + r'\s*:\s*str\s*=\s*).*$',
    re.MULTILINE,
)
if not pattern.search(content):
    print(f"ERROR: constant {const_name!r} not found in {file_path}", file=sys.stderr)
    sys.exit(1)

escaped_value = new_value.replace('\\', '\\\\').replace('"', '\\"')

# BUG FIX (found via Su's own end-to-end inject-then-verify test, v2):
# re.sub()'s STRING replacement argument undergoes its OWN backslash-escape
# processing (\g<1>, \1, \\ -> \, etc.) -- so a naive `pattern.sub(r'...' +
# escaped_value + ...)` silently HALVES every backslash a second time,
# corrupting any value that itself contains an escaped backslash (e.g. the
# \n inside a JSON-escaped PEM newline: MASTER_ANCHOR_SET_JSON/
# CODE_LEAF_CERT_JSON). v1's _replace_constant never hit this because it
# only ever injected backslash-free hex/base64 values. Using a FUNCTION as
# the repl argument disables re's replacement-string escape processing
# entirely (documented re.sub behaviour) -- the value is spliced in
# byte-for-byte, exactly once-escaped, exactly as intended.
def _do_replace(m: "re.Match") -> str:
    return m.group(1) + '"' + escaped_value + '"'

new_content = pattern.sub(_do_replace, content)
file_path.write_text(new_content, encoding="utf-8")
PYEOF
}

# ---------------------------------------------------------------------------
# Compact a JSON file to single-line canonical form (sort_keys, no
# whitespace) — safe input for _replace_constant (which requires a
# newline-free value). PEM content embedded inside a JSON string is already
# \n-escaped BY json.dumps, so compacting never loses information — it only
# removes the pretty-printer's own structural whitespace/newlines.
# ---------------------------------------------------------------------------

_compact_json_file() {
    local _file="$1"
    python3 -c "
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)
print(json.dumps(data, sort_keys=True, separators=(',', ':')))
" "$_file"
}

# ---------------------------------------------------------------------------
# Verify no placeholder constants remain
# ---------------------------------------------------------------------------

_assert_no_placeholders() {
    local _file="$1"
    # Second arg (optional): space-separated constant names to check instead
    # of the default _integrity.py list — used for the 7 mesh files' own
    # `_EXPECTED_INTEGRITY_ROOT_HASH` pin (LAURA-V2-005, 2026-07-17).
    local _consts="${2:-}"
    python3 - "$_file" "$_consts" <<'PYEOF'
import sys, re, pathlib

path = pathlib.Path(sys.argv[1])
override = sys.argv[2].split() if len(sys.argv) > 2 and sys.argv[2] else None
content = path.read_text(encoding="utf-8")

INJECTED_CONSTS = override or [
    "VERIFIER_HASH", "ENFORCER_HASH", "LOADER_HASH",
    "AGENTS_REGISTRY_HASH", "IDENTITY_REGISTRY_HASH",
    "OIDC_MODULE_HASH", "SAML_MODULE_HASH", "SSO_ROUTES_HASH",
    "SCIM_ROUTES_HASH", "GATE_MIDDLEWARE_HASH",
    "MESH_TOPOLOGY_JSON",
    "INTEGRITY_HASH",
    "MASTER_ANCHOR_SET_JSON", "CODE_LEAF_CERT_JSON", "CODE_LEAF_CERT_SIG",
    "BUNDLE_SIG",
]
SENTINEL = "PLACEHOLDER_YASHIGANI_INTEGRITY"

errors = []
for const in INJECTED_CONSTS:
    pattern = re.compile(
        r'^' + re.escape(const) + r'\s*:\s*str\s*=\s*(.*)$',
        re.MULTILINE,
    )
    m = pattern.search(content)
    if not m:
        errors.append(f"  {const}: NOT FOUND in file")
    elif SENTINEL in m.group(1):
        errors.append(f"  {const}: still has placeholder sentinel in value: {m.group(1)[:80]}")

if errors:
    print(f"ERROR: {path} still has placeholder constant(s) after injection:", file=sys.stderr)
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ---------------------------------------------------------------------------
# STEP 0: Embed the chain-of-trust root-of-trust constants into _integrity.py
#         (MASTER_ANCHOR_SET_JSON, CODE_LEAF_CERT_JSON, CODE_LEAF_CERT_SIG,
#         optionally KILL_LIST_JSON/CLIENT_DOMAIN_REGISTRY_JSON) — MOVED
#         AHEAD of Step 1 (LAURA-V2-005, 2026-07-17): the new root-of-trust
#         pin (Step 0c below) must be computed from these FINAL values and
#         stamped into the 7 mesh files BEFORE their own SHA-256 is taken in
#         Step 1 — otherwise stamping them afterward would silently
#         invalidate the module hashes Step 1 already wrote. Order MATTERS:
#         0a/0b (embed root data) -> 0c (derive + stamp the pin into the 7
#         mesh files) -> 1 (hash the NOW-stamped mesh files, among others).
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 0a: embedding master anchor-SET + code leaf_cert + leaf_cert_sig\n'

MASTER_ANCHOR_SET_JSON="$(_compact_json_file "${MASTER_ANCHOR_SET_PATH}")"
CODE_LEAF_CERT_JSON="$(_compact_json_file "${CODE_LEAF_CERT_PATH}")"
CODE_LEAF_CERT_SIG="$(tr -d '\n' < "${CODE_LEAF_CERT_SIG_PATH}")"

[ -n "${MASTER_ANCHOR_SET_JSON}" ] || { printf 'ERROR: MASTER_ANCHOR_SET_PATH produced empty JSON\n' >&2; exit 1; }
[ -n "${CODE_LEAF_CERT_JSON}" ] || { printf 'ERROR: CODE_LEAF_CERT_PATH produced empty JSON\n' >&2; exit 1; }
[ -n "${CODE_LEAF_CERT_SIG}" ] || { printf 'ERROR: CODE_LEAF_CERT_SIG_PATH is empty\n' >&2; exit 1; }

_replace_constant "${INTEGRITY_PY}" "MASTER_ANCHOR_SET_JSON" "${MASTER_ANCHOR_SET_JSON}"
_replace_constant "${INTEGRITY_PY}" "CODE_LEAF_CERT_JSON" "${CODE_LEAF_CERT_JSON}"
_replace_constant "${INTEGRITY_PY}" "CODE_LEAF_CERT_SIG" "${CODE_LEAF_CERT_SIG}"

printf '[inject_hashes v2] MASTER_ANCHOR_SET_JSON = %s...\n' "${MASTER_ANCHOR_SET_JSON:0:64}"
printf '[inject_hashes v2] CODE_LEAF_CERT_JSON    = %s...\n' "${CODE_LEAF_CERT_JSON:0:64}"
printf '[inject_hashes v2] CODE_LEAF_CERT_SIG     = %s...\n' "${CODE_LEAF_CERT_SIG:0:32}"
printf '[inject_hashes v2] Step 0a complete\n'

if [ -n "${KILL_LIST_PATH:-}" ]; then
    printf '[inject_hashes v2] Step 0b: embedding KILL_LIST_JSON from %s\n' "${KILL_LIST_PATH}"
    KILL_LIST_JSON="$(_compact_json_file "${KILL_LIST_PATH}")"
    _replace_constant "${INTEGRITY_PY}" "KILL_LIST_JSON" "${KILL_LIST_JSON}"
    printf '[inject_hashes v2] KILL_LIST_JSON = %s...\n' "${KILL_LIST_JSON:0:64}"
else
    printf '[inject_hashes v2] Step 0b: KILL_LIST_PATH unset — leaving safe default "[]"\n'
    KILL_LIST_JSON="[]"
fi

if [ -n "${CLIENT_DOMAIN_REGISTRY_PATH:-}" ]; then
    printf '[inject_hashes v2] Step 0b: embedding CLIENT_DOMAIN_REGISTRY_JSON from %s\n' "${CLIENT_DOMAIN_REGISTRY_PATH}"
    CLIENT_DOMAIN_REGISTRY_JSON="$(_compact_json_file "${CLIENT_DOMAIN_REGISTRY_PATH}")"
    _replace_constant "${INTEGRITY_PY}" "CLIENT_DOMAIN_REGISTRY_JSON" "${CLIENT_DOMAIN_REGISTRY_JSON}"
    printf '[inject_hashes v2] CLIENT_DOMAIN_REGISTRY_JSON = %s...\n' "${CLIENT_DOMAIN_REGISTRY_JSON:0:64}"
else
    printf '[inject_hashes v2] Step 0b: CLIENT_DOMAIN_REGISTRY_PATH unset — leaving safe default "{}"\n'
    CLIENT_DOMAIN_REGISTRY_JSON="{}"
fi

# ---------------------------------------------------------------------------
# STEP 0c: Derive _EXPECTED_INTEGRITY_ROOT_HASH (LAURA-V2-005, 2026-07-17)
#          from the root-of-trust fields JUST embedded above, and stamp the
#          SAME value into each of the 7 mesh files' own local
#          `_EXPECTED_INTEGRITY_ROOT_HASH` constant — see
#          licensing/verifier.py's module-level comment block above
#          `_check_integrity_root_pin()` for the full self-reference
#          rationale (this MUST happen before Step 1 computes the mesh
#          files' own module hashes, or stamping them here would silently
#          invalidate those hashes).
#
#          MUST stay byte-identical to verifier._live_integrity_root_hash()
#          (and its sibling copy in each of the other 6 mesh files) — same
#          5-field canonical "KEY=value" \n-joined string, SHA-256 hex.
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 0c: computing + stamping root-of-trust pin (LAURA-V2-005)\n'

# BUG FIX (LAURA-V2-006 sweep finding, 2026-07-17): the previous version of
# this block spliced ${MASTER_ANCHOR_SET_JSON} et al. directly into an
# UNQUOTED heredoc (`<<PYEOF`), which shell-expands the variables BEFORE
# Python ever sees the script, landing their content inside a Python
# triple-quoted string LITERAL (`"""${VAR}"""`). Since MASTER_ANCHOR_SET_JSON/
# CODE_LEAF_CERT_JSON always embed PEM public keys (JSON-escaped, containing
# literal 2-character `\n` sequences), Python's own string-literal parser
# interpreted those `\n` sequences as REAL newline characters at parse time —
# producing a digest that could never match verifier._live_integrity_root_hash()
# (and each mesh file's own copy), which read the injected constant as a
# runtime string (the literal 2-char `\n` preserved, exactly as
# _replace_constant() wrote it via sys.argv, never re-parsed as Python
# source). Result: Step 0c's stamped pin failed EVERY real build, genuine or
# forged — an availability bug that would have silently degraded every
# customer's OIDC/SAML/SCIM (and, pre-LAURA-V2-006, everything else) to
# COMMUNITY on day one.
#
# Fix: mirror _replace_constant()'s own safe-interpolation pattern — pass the
# values as `sys.argv` (a quoted heredoc marker, `<<'PYEOF'`, so the shell
# performs ZERO expansion inside the script; argv delivers the bytes to
# Python unparsed, exactly like _replace_constant() already does for these
# same values).
INTEGRITY_ROOT_HASH="$(python3 - \
    "${MASTER_ANCHOR_SET_JSON}" \
    "${CODE_LEAF_CERT_JSON}" \
    "${CODE_LEAF_CERT_SIG}" \
    "${KILL_LIST_JSON}" \
    "${CLIENT_DOMAIN_REGISTRY_JSON}" \
    <<'PYEOF'
import hashlib, sys

(
    master_anchor_set_json,
    code_leaf_cert_json,
    code_leaf_cert_sig,
    kill_list_json,
    client_domain_registry_json,
) = sys.argv[1:6]

canonical = "\n".join([
    "MASTER_ANCHOR_SET_JSON=" + master_anchor_set_json,
    "CODE_LEAF_CERT_JSON=" + code_leaf_cert_json,
    "CODE_LEAF_CERT_SIG=" + code_leaf_cert_sig,
    "KILL_LIST_JSON=" + kill_list_json,
    "CLIENT_DOMAIN_REGISTRY_JSON=" + client_domain_registry_json,
])
print(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
PYEOF
)"
[ -n "${INTEGRITY_ROOT_HASH}" ] || { printf 'ERROR: INTEGRITY_ROOT_HASH computation produced empty output\n' >&2; exit 1; }

for _mesh_file in "$VERIFIER_PY" "$ENFORCER_PY" "$GATE_MIDDLEWARE_PY" "$OIDC_MODULE_PY" "$SAML_MODULE_PY" "$SSO_ROUTES_PY" "$SCIM_ROUTES_PY"; do
    _replace_constant "${_mesh_file}" "_EXPECTED_INTEGRITY_ROOT_HASH" "${INTEGRITY_ROOT_HASH}"
done

printf '[inject_hashes v2] _EXPECTED_INTEGRITY_ROOT_HASH = %s (stamped into all 7 mesh files)\n' "${INTEGRITY_ROOT_HASH}"
printf '[inject_hashes v2] Step 0c complete\n'

# ---------------------------------------------------------------------------
# STEP 1: Compute 5 module hashes (T1-T4 bundle — unchanged v1 mechanism)
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 1: computing module hashes\n'

VERIFIER_HASH="$(_sha256_file "${VERIFIER_PY}")"
ENFORCER_HASH="$(_sha256_file "${ENFORCER_PY}")"
LOADER_HASH="$(_sha256_file "${LOADER_PY}")"
AGENTS_REGISTRY_HASH="$(_sha256_file "${AGENTS_REGISTRY_PY}")"
IDENTITY_REGISTRY_HASH="$(_sha256_file "${IDENTITY_REGISTRY_PY}")"
OIDC_MODULE_HASH="$(_sha256_file "${OIDC_MODULE_PY}")"
SAML_MODULE_HASH="$(_sha256_file "${SAML_MODULE_PY}")"
SSO_ROUTES_HASH="$(_sha256_file "${SSO_ROUTES_PY}")"
SCIM_ROUTES_HASH="$(_sha256_file "${SCIM_ROUTES_PY}")"
GATE_MIDDLEWARE_HASH="$(_sha256_file "${GATE_MIDDLEWARE_PY}")"

printf '[inject_hashes v2] VERIFIER_HASH          = %s\n' "$VERIFIER_HASH"
printf '[inject_hashes v2] ENFORCER_HASH          = %s\n' "$ENFORCER_HASH"
printf '[inject_hashes v2] LOADER_HASH            = %s\n' "$LOADER_HASH"
printf '[inject_hashes v2] AGENTS_REGISTRY_HASH   = %s\n' "$AGENTS_REGISTRY_HASH"
printf '[inject_hashes v2] IDENTITY_REGISTRY_HASH = %s\n' "$IDENTITY_REGISTRY_HASH"
printf '[inject_hashes v2] OIDC_MODULE_HASH       = %s\n' "$OIDC_MODULE_HASH"
printf '[inject_hashes v2] SAML_MODULE_HASH       = %s\n' "$SAML_MODULE_HASH"
printf '[inject_hashes v2] SSO_ROUTES_HASH        = %s\n' "$SSO_ROUTES_HASH"
printf '[inject_hashes v2] SCIM_ROUTES_HASH       = %s\n' "$SCIM_ROUTES_HASH"
printf '[inject_hashes v2] GATE_MIDDLEWARE_HASH   = %s\n' "$GATE_MIDDLEWARE_HASH"

_replace_constant "${INTEGRITY_PY}" "VERIFIER_HASH" "${VERIFIER_HASH}"
_replace_constant "${INTEGRITY_PY}" "ENFORCER_HASH" "${ENFORCER_HASH}"
_replace_constant "${INTEGRITY_PY}" "LOADER_HASH" "${LOADER_HASH}"
_replace_constant "${INTEGRITY_PY}" "AGENTS_REGISTRY_HASH" "${AGENTS_REGISTRY_HASH}"
_replace_constant "${INTEGRITY_PY}" "IDENTITY_REGISTRY_HASH" "${IDENTITY_REGISTRY_HASH}"
_replace_constant "${INTEGRITY_PY}" "OIDC_MODULE_HASH" "${OIDC_MODULE_HASH}"
_replace_constant "${INTEGRITY_PY}" "SAML_MODULE_HASH" "${SAML_MODULE_HASH}"
_replace_constant "${INTEGRITY_PY}" "SSO_ROUTES_HASH" "${SSO_ROUTES_HASH}"
_replace_constant "${INTEGRITY_PY}" "SCIM_ROUTES_HASH" "${SCIM_ROUTES_HASH}"
_replace_constant "${INTEGRITY_PY}" "GATE_MIDDLEWARE_HASH" "${GATE_MIDDLEWARE_HASH}"

printf '[inject_hashes v2] Step 1 complete\n'

# ---------------------------------------------------------------------------
# STEPS 2/3 (Steps 2 "embed chain-of-trust constants" and 3a/3b "embed
# KILL_LIST_JSON/CLIENT_DOMAIN_REGISTRY_JSON") — MOVED to Step 0a/0b above
# (LAURA-V2-005, 2026-07-17): the root-of-trust pin computed there
# (Step 0c) must be derived from these FINAL values and stamped into the 7
# mesh files BEFORE Step 1's module hashes are taken, so embedding them here
# (after Step 1) would be too late. See the Step 0 block comment above.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# STEP 3c: Mesh FULL topology (licence-hardening-v2 Phase D, LAURA-V2-003
#          RE-VERIFY hardening, 2026-07-17) — deterministically derive this
#          release's randomized 7-file member order from (RELEASE_VERSION,
#          MESH_SEED) via licensing/chain/mesh_topology.py:compute_mesh_order()
#          (BUILD-TIME ONLY — never imported by any of the 7 runtime
#          enforcement files; they only ever read the resulting, already-
#          signed MESH_TOPOLOGY_JSON). UNLIKE Steps 3a/3b, this step is
#          MANDATORY — it always embeds a real value, never leaves the
#          placeholder default, because every mesh-check file fail-closes
#          on a placeholder/malformed topology in non-dev environments.
#          Phase D: every mesh member checks EVERY OTHER member (a complete
#          graph, not a ring) — the member order no longer selects who
#          checks whom (that's now unconditional/complete), only each
#          file's own peer-iteration order.
#
#          MESH_SEED: if unset, a fresh random seed is generated
#          (openssl rand -hex 16) and PRINTED — the operator MUST record it
#          (e.g. release notes / build manifest) to reproduce this exact
#          topology later for audit/debug. The SAME (RELEASE_VERSION,
#          MESH_SEED) pair always reproduces the SAME member order
#          (deterministic — see mesh_topology.py's docstring). Randomizing
#          the topology per release is per-build polymorphism/obscurity —
#          it raises the cost of a coordinated-edit strip-script written
#          against one release being reusable against the next; it does NOT
#          change the underlying detection guarantee (see mesh_topology.py).
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 3c: computing mesh full topology\n'

RELEASE_VERSION="${RELEASE_VERSION:-0.0.0-unset}"
if [ "${RELEASE_VERSION}" = "0.0.0-unset" ]; then
    printf '[inject_hashes v2] WARNING: RELEASE_VERSION not set — using placeholder version for topology derivation (fine for dev/test builds; set RELEASE_VERSION for real releases so the seed record is meaningful)\n' >&2
fi

if [ -z "${MESH_SEED:-}" ]; then
    MESH_SEED="$(openssl rand -hex 16)"
    printf '[inject_hashes v2] MESH_SEED not provided — generated fresh: %s\n' "${MESH_SEED}"
    printf '[inject_hashes v2] RECORD THIS SEED (with RELEASE_VERSION=%s) to reproduce this exact mesh topology later.\n' "${RELEASE_VERSION}"
else
    printf '[inject_hashes v2] MESH_SEED (provided) = %s\n' "${MESH_SEED}"
fi

MESH_TOPOLOGY_JSON="$(PYTHONPATH="${SRC_ROOT}" python3 -c "
import json, sys
from yashigani.licensing.chain.mesh_topology import compute_mesh_order

version = sys.argv[1]
seed = sys.argv[2]
member_order = compute_mesh_order(version, seed)
print(json.dumps({'version': version, 'seed': seed, 'member_order': member_order}, sort_keys=True, separators=(',', ':')))
" "${RELEASE_VERSION}" "${MESH_SEED}")"

[ -n "${MESH_TOPOLOGY_JSON}" ] || { printf 'ERROR: mesh topology computation produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "MESH_TOPOLOGY_JSON" "${MESH_TOPOLOGY_JSON}"
printf '[inject_hashes v2] MESH_TOPOLOGY_JSON = %s\n' "${MESH_TOPOLOGY_JSON}"
printf '[inject_hashes v2] Step 3c complete\n'

# ---------------------------------------------------------------------------
# STEP 4: Compute INTEGRITY_HASH — the blank-then-hash self-referential
#         digest of _integrity.py's CURRENT bytes (Steps 1-3 already
#         embedded above). MUST stay byte-identical to
#         verifier._compute_integrity_self_hash() (LAURA-V2-002 fix):
#         both the INTEGRITY_HASH line's value and the BUNDLE_SIG line's
#         value are replaced with a fixed placeholder ("0"*64) before
#         hashing, regardless of whatever currently sits in those two
#         lines — this resolves the chicken-and-egg self-reference problem
#         and makes the digest reproducible independent of injection order.
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 4: computing INTEGRITY_HASH (blank-then-hash)\n'

INTEGRITY_HASH="$(python3 - "${INTEGRITY_PY}" <<'PYEOF'
import hashlib, re, sys, pathlib

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

BLANK = "0" * 64
# Match to end of line, NOT just a `"..."` quoted-literal shape — the
# PRISTINE placeholder state of these two constants is a Python EXPRESSION
# (`_PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"`), not a bare string literal.
# A `"[^"]*"`-only pattern silently fails to match (and therefore fails to
# blank) that pristine form on a FIRST build, producing a different digest
# than a later re-verify (where the line has since become a quoted literal)
# — a false-positive tamper report on every freshly-built package. Mirrors
# _replace_constant()'s own `.*$` pattern above and MUST stay byte-identical
# to verifier._compute_integrity_self_hash()'s regexes.
integrity_re = re.compile(r'^(INTEGRITY_HASH\s*:\s*str\s*=\s*).*$', re.MULTILINE)
bundle_re = re.compile(r'^(BUNDLE_SIG\s*:\s*str\s*=\s*).*$', re.MULTILINE)

blanked = integrity_re.sub(lambda m: m.group(1) + '"' + BLANK + '"', text, count=1)
blanked = bundle_re.sub(lambda m: m.group(1) + '"' + BLANK + '"', blanked, count=1)

print(hashlib.sha256(blanked.encode("utf-8")).hexdigest())
PYEOF
)"
[ -n "${INTEGRITY_HASH}" ] || { printf 'ERROR: INTEGRITY_HASH computation produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "INTEGRITY_HASH" "${INTEGRITY_HASH}"

printf '[inject_hashes v2] INTEGRITY_HASH = %s\n' "$INTEGRITY_HASH"
printf '[inject_hashes v2] Step 4 complete\n'

# ---------------------------------------------------------------------------
# STEP 5: Build canonical ELEVEN-line bundle string (10 module hashes +
#         INTEGRITY_HASH, sorted by key — SAME construction as
#         verifier._compute_live_hash_bundle_str()) → sign with the CODE
#         leaf → write BUNDLE_SIG. Embedding BUNDLE_SIG does NOT invalidate
#         the Step 4 INTEGRITY_HASH (its own line is blanked out of that
#         computation, per the blank-then-hash convention above).
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 5: building canonical 11-line bundle string and signing with code leaf\n'

BUNDLE_STR="AGENTS_REGISTRY_HASH=${AGENTS_REGISTRY_HASH}
ENFORCER_HASH=${ENFORCER_HASH}
GATE_MIDDLEWARE_HASH=${GATE_MIDDLEWARE_HASH}
IDENTITY_REGISTRY_HASH=${IDENTITY_REGISTRY_HASH}
INTEGRITY_HASH=${INTEGRITY_HASH}
LOADER_HASH=${LOADER_HASH}
OIDC_MODULE_HASH=${OIDC_MODULE_HASH}
SAML_MODULE_HASH=${SAML_MODULE_HASH}
SCIM_ROUTES_HASH=${SCIM_ROUTES_HASH}
SSO_ROUTES_HASH=${SSO_ROUTES_HASH}
VERIFIER_HASH=${VERIFIER_HASH}"

BUNDLE_SIG="$(PYTHONPATH="${SRC_ROOT}" python3 "${SIGN_BUNDLE_PY}" \
    --key "${CODE_LEAF_KEY_PATH}" \
    --bundle-str "${BUNDLE_STR}")"
[ -n "${BUNDLE_SIG}" ] || { printf 'ERROR: sign_bundle_v2.py produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "BUNDLE_SIG" "${BUNDLE_SIG}"
printf '[inject_hashes v2] BUNDLE_SIG = %s...\n' "${BUNDLE_SIG:0:32}"
printf '[inject_hashes v2] Step 5 complete\n'

# ---------------------------------------------------------------------------
# Post-injection assertion: no placeholders remain
# ---------------------------------------------------------------------------

_assert_no_placeholders "${INTEGRITY_PY}"

# LAURA-V2-005: also assert the 7 mesh files' own root-of-trust pin was
# actually stamped (Step 0c) — a build that skipped that step must fail
# closed the same way a missing VERIFIER_HASH etc. does.
for _mesh_file in "$VERIFIER_PY" "$ENFORCER_PY" "$GATE_MIDDLEWARE_PY" "$OIDC_MODULE_PY" "$SAML_MODULE_PY" "$SSO_ROUTES_PY" "$SCIM_ROUTES_PY"; do
    _assert_no_placeholders "${_mesh_file}" "_EXPECTED_INTEGRITY_ROOT_HASH"
done

printf '[inject_hashes v2] All steps complete. _integrity.py is fully injected (chain-of-trust).\n'
printf '[inject_hashes v2] Final INTEGRITY_HASH: %s\n' "${INTEGRITY_HASH}"
printf '[inject_hashes v2] Final _EXPECTED_INTEGRITY_ROOT_HASH (all 7 mesh files): %s\n' "${INTEGRITY_ROOT_HASH}"
