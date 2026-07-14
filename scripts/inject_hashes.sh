#!/usr/bin/env bash
# inject_hashes.sh — Build-pipeline v2: inject root->leaf chain-of-trust
# constants into _integrity.py (supersedes the v1 counter-key/HASH_BUNDLE_SIG/
# EXPECTED_TOKEN_HMAC scheme — KDF token step DROPPED entirely in v2, per
# Tom's _integrity.py rewrite for licence-hardening-v2).
#
# Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
#      §2.2 (anchor-SET) + §3.1 (leaf_cert) + §3.3 (six-file bundle — v1's
#      5-module-hash mechanics retained; INTEGRITY_HASH excluded from the
#      signed bundle, same circularity-avoidance deviation carried forward
#      unchanged, documented in verifier._build_hash_bundle_str()).
#
# Steps:
#   Step 1: Compute SHA-256 of 5 licensing/agent/identity modules → write
#           into VERIFIER_HASH/ENFORCER_HASH/LOADER_HASH/AGENTS_REGISTRY_HASH/
#           IDENTITY_REGISTRY_HASH (T1-T4 bundle — unchanged v1 mechanism).
#   Step 2: Compute SHA-256(_integrity.py) after Step 1 → write pre-sig
#           INTEGRITY_HASH (unchanged v1 mechanism).
#   Step 3: Embed the chain-of-trust constants — MASTER_ANCHOR_SET_JSON,
#           CODE_LEAF_CERT_JSON, CODE_LEAF_CERT_SIG — from files produced by
#           `licgen release` / `keygen.py leaf new` + `licgen anchor-set emit`.
#   Step 4: Build the canonical 5-hash bundle string (SAME construction as
#           verifier._build_hash_bundle_str() — sorted KEY=hex lines,
#           \n-joined, no trailing newline) → sign with the CODE leaf's
#           private key via sign_bundle_v2.py (P-384/SHA-384, chain digest
#           §3.3) → BUNDLE_SIG.
#   Step 5: Optionally embed KILL_LIST_JSON / CLIENT_DOMAIN_REGISTRY_JSON if
#           provided (both have SAFE defaults "[]"/"{}" already in source —
#           unlike Steps 1-4, an unset Step 5 is not a placeholder failure).
#   Step 6: Re-compute FINAL SHA-256(_integrity.py) → overwrite INTEGRITY_HASH
#           (now covers every chain constant — same tamper-evidence property
#           as v1's final INTEGRITY_HASH).
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
    python3 - "$_file" <<'PYEOF'
import sys, re, pathlib

path = pathlib.Path(sys.argv[1])
content = path.read_text(encoding="utf-8")

INJECTED_CONSTS = [
    "VERIFIER_HASH", "ENFORCER_HASH", "LOADER_HASH",
    "AGENTS_REGISTRY_HASH", "IDENTITY_REGISTRY_HASH",
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
# STEP 1: Compute 5 module hashes (T1-T4 bundle — unchanged v1 mechanism)
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 1: computing module hashes\n'

VERIFIER_HASH="$(_sha256_file "${VERIFIER_PY}")"
ENFORCER_HASH="$(_sha256_file "${ENFORCER_PY}")"
LOADER_HASH="$(_sha256_file "${LOADER_PY}")"
AGENTS_REGISTRY_HASH="$(_sha256_file "${AGENTS_REGISTRY_PY}")"
IDENTITY_REGISTRY_HASH="$(_sha256_file "${IDENTITY_REGISTRY_PY}")"

printf '[inject_hashes v2] VERIFIER_HASH          = %s\n' "$VERIFIER_HASH"
printf '[inject_hashes v2] ENFORCER_HASH          = %s\n' "$ENFORCER_HASH"
printf '[inject_hashes v2] LOADER_HASH            = %s\n' "$LOADER_HASH"
printf '[inject_hashes v2] AGENTS_REGISTRY_HASH   = %s\n' "$AGENTS_REGISTRY_HASH"
printf '[inject_hashes v2] IDENTITY_REGISTRY_HASH = %s\n' "$IDENTITY_REGISTRY_HASH"

_replace_constant "${INTEGRITY_PY}" "VERIFIER_HASH" "${VERIFIER_HASH}"
_replace_constant "${INTEGRITY_PY}" "ENFORCER_HASH" "${ENFORCER_HASH}"
_replace_constant "${INTEGRITY_PY}" "LOADER_HASH" "${LOADER_HASH}"
_replace_constant "${INTEGRITY_PY}" "AGENTS_REGISTRY_HASH" "${AGENTS_REGISTRY_HASH}"
_replace_constant "${INTEGRITY_PY}" "IDENTITY_REGISTRY_HASH" "${IDENTITY_REGISTRY_HASH}"

printf '[inject_hashes v2] Step 1 complete\n'

# ---------------------------------------------------------------------------
# STEP 2: Compute SHA-256(_integrity.py) after Step 1 → write pre-sig
#         INTEGRITY_HASH (unchanged v1 mechanism/deviation — see module
#         docstring + verifier._build_hash_bundle_str()'s own DESIGN-NOTE).
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 2: computing pre-sig INTEGRITY_HASH\n'

INTEGRITY_HASH_STEP2="$(_sha256_file "${INTEGRITY_PY}")"
_replace_constant "${INTEGRITY_PY}" "INTEGRITY_HASH" "${INTEGRITY_HASH_STEP2}"

printf '[inject_hashes v2] INTEGRITY_HASH (step 2) = %s\n' "$INTEGRITY_HASH_STEP2"

# ---------------------------------------------------------------------------
# STEP 3: Embed the chain-of-trust constants (§2.2/§3.1).
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 3: embedding master anchor-SET + code leaf_cert + leaf_cert_sig\n'

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
printf '[inject_hashes v2] Step 3 complete\n'

# ---------------------------------------------------------------------------
# STEP 4: Build canonical bundle string (5 module hashes, NO INTEGRITY_HASH
#         — SAME construction as verifier._build_hash_bundle_str())
#         → sign with the CODE leaf → write BUNDLE_SIG.
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 4: building canonical bundle string and signing with code leaf\n'

BUNDLE_STR="AGENTS_REGISTRY_HASH=${AGENTS_REGISTRY_HASH}
ENFORCER_HASH=${ENFORCER_HASH}
IDENTITY_REGISTRY_HASH=${IDENTITY_REGISTRY_HASH}
LOADER_HASH=${LOADER_HASH}
VERIFIER_HASH=${VERIFIER_HASH}"

BUNDLE_SIG="$(PYTHONPATH="${SRC_ROOT}" python3 "${SIGN_BUNDLE_PY}" \
    --key "${CODE_LEAF_KEY_PATH}" \
    --bundle-str "${BUNDLE_STR}")"
[ -n "${BUNDLE_SIG}" ] || { printf 'ERROR: sign_bundle_v2.py produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "BUNDLE_SIG" "${BUNDLE_SIG}"
printf '[inject_hashes v2] BUNDLE_SIG = %s...\n' "${BUNDLE_SIG:0:32}"
printf '[inject_hashes v2] Step 4 complete\n'

# ---------------------------------------------------------------------------
# STEP 5: Optional — embed KILL_LIST_JSON / CLIENT_DOMAIN_REGISTRY_JSON if
#         provided. Both have SAFE defaults ("[]"/"{}") already in source —
#         unset is a legitimate, non-placeholder state (unlike Steps 1-4).
# ---------------------------------------------------------------------------

if [ -n "${KILL_LIST_PATH:-}" ]; then
    printf '[inject_hashes v2] Step 5a: embedding KILL_LIST_JSON from %s\n' "${KILL_LIST_PATH}"
    KILL_LIST_JSON="$(_compact_json_file "${KILL_LIST_PATH}")"
    _replace_constant "${INTEGRITY_PY}" "KILL_LIST_JSON" "${KILL_LIST_JSON}"
    printf '[inject_hashes v2] KILL_LIST_JSON = %s...\n' "${KILL_LIST_JSON:0:64}"
else
    printf '[inject_hashes v2] Step 5a: KILL_LIST_PATH unset — leaving safe default "[]"\n'
fi

if [ -n "${CLIENT_DOMAIN_REGISTRY_PATH:-}" ]; then
    printf '[inject_hashes v2] Step 5b: embedding CLIENT_DOMAIN_REGISTRY_JSON from %s\n' "${CLIENT_DOMAIN_REGISTRY_PATH}"
    CLIENT_DOMAIN_REGISTRY_JSON="$(_compact_json_file "${CLIENT_DOMAIN_REGISTRY_PATH}")"
    _replace_constant "${INTEGRITY_PY}" "CLIENT_DOMAIN_REGISTRY_JSON" "${CLIENT_DOMAIN_REGISTRY_JSON}"
    printf '[inject_hashes v2] CLIENT_DOMAIN_REGISTRY_JSON = %s...\n' "${CLIENT_DOMAIN_REGISTRY_JSON:0:64}"
else
    printf '[inject_hashes v2] Step 5b: CLIENT_DOMAIN_REGISTRY_PATH unset — leaving safe default "{}"\n'
fi

# ---------------------------------------------------------------------------
# STEP 6: Re-compute final INTEGRITY_HASH (Steps 3+4+5 changed _integrity.py).
#         The signed bundle (Step 4) does NOT need to be recomputed — it
#         covers the 5 module hashes only, which haven't changed since
#         Step 1. Same circularity-avoidance rationale as v1.
# ---------------------------------------------------------------------------

printf '[inject_hashes v2] Step 6: computing final INTEGRITY_HASH\n'

INTEGRITY_HASH_FINAL="$(_sha256_file "${INTEGRITY_PY}")"
_replace_constant "${INTEGRITY_PY}" "INTEGRITY_HASH" "${INTEGRITY_HASH_FINAL}"

printf '[inject_hashes v2] INTEGRITY_HASH (final) = %s\n' "$INTEGRITY_HASH_FINAL"
printf '[inject_hashes v2] Step 6 complete\n'

# ---------------------------------------------------------------------------
# Post-injection assertion: no placeholders remain
# ---------------------------------------------------------------------------

_assert_no_placeholders "${INTEGRITY_PY}"

printf '[inject_hashes v2] All steps complete. _integrity.py is fully injected (chain-of-trust).\n'
printf '[inject_hashes v2] Final INTEGRITY_HASH: %s\n' "${INTEGRITY_HASH_FINAL}"
