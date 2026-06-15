#!/usr/bin/env bash
# inject_hashes.sh — Build-pipeline: inject integrity constants into _integrity.py
#
# Implements the 5-step injection order from Nico's design §2.4:
#   Step 1: Compute SHA-256 of 5 licensing/agent/identity modules + write counter
#           public key → replace placeholders in _integrity.py.
#   Step 2: Compute SHA-256(_integrity.py) after Step 1 → write as INTEGRITY_HASH.
#   Step 3: Build canonical bundle string → ECDSA P-256 sign → write HASH_BUNDLE_SIG.
#   Step 4: Compute HKDF-KDF token HMAC → write EXPECTED_TOKEN_HMAC.
#   Step 5: Re-compute SHA-256(_integrity.py) → overwrite INTEGRITY_HASH (final).
#
# Usage:
#   COUNTER_KEY_PATH=/run/secrets/counter_private_key \\
#   COUNTER_PUB_KEY_PATH=keys/yashigani_counter_public.pem \\
#   SRC_ROOT=/build/src \\
#   bash scripts/inject_hashes.sh
#
# Required environment:
#   COUNTER_KEY_PATH        Path to the counter PRIVATE key PEM (never baked in image).
#   COUNTER_PUB_KEY_PATH    Path to the counter PUBLIC key PEM (embedded in image).
#   SRC_ROOT                Root of the Python source tree (default: src/).
#
# Optional:
#   FIPS_MODE=1             Use lib/yashigani-fips.sh:_fips_sha256 for all hashes.
#   COMMUNITY_LICENCE_ID    Licence ID for KDF (default: "" for Community).
#   COMMUNITY_SEAT_POLICY   Seat policy for KDF (default: "20,5,2" — DG-03).
#   SCRIPT_DIR              Directory containing sign_bundle.py and compute_kdf_token.py
#                           (default: same directory as this script).
#   INTEGRITY_PY            Explicit path to _integrity.py (optional override).
#
# Aborts (non-zero exit) on any failure — never falls back to placeholder values.
# Docker BuildKit secret: counter private key is read from /run/secrets/counter_private_key
# and is NEVER written to any image layer.

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

SIGN_BUNDLE_PY="${SCRIPT_DIR}/sign_bundle.py"
COMPUTE_KDF_PY="${SCRIPT_DIR}/compute_kdf_token.py"

# KDF inputs (DG-01: no CA fingerprint; DG-03: Community seat policy)
COMMUNITY_LICENCE_ID="${COMMUNITY_LICENCE_ID:-}"
COMMUNITY_SEAT_POLICY="${COMMUNITY_SEAT_POLICY:-20,5,2}"

# ---------------------------------------------------------------------------
# Validate required env vars and paths
# ---------------------------------------------------------------------------

: "${COUNTER_KEY_PATH:?COUNTER_KEY_PATH must be set (path to counter private key PEM)}"
: "${COUNTER_PUB_KEY_PATH:?COUNTER_PUB_KEY_PATH must be set (path to counter public key PEM)}"

for _f in \
    "$INTEGRITY_PY" "$VERIFIER_PY" "$ENFORCER_PY" "$LOADER_PY" \
    "$AGENTS_REGISTRY_PY" "$IDENTITY_REGISTRY_PY" \
    "$SIGN_BUNDLE_PY" "$COMPUTE_KDF_PY" \
    "$COUNTER_KEY_PATH" "$COUNTER_PUB_KEY_PATH"; do
    if [ ! -f "$_f" ]; then
        printf 'ERROR: required file not found: %s\n' "$_f" >&2
        exit 1
    fi
done

# Private key permissions — refuse to use world- or group-readable private key (CWE-732)
_key_mode="$(stat -c '%a' "${COUNTER_KEY_PATH}" 2>/dev/null || stat -f '%A' "${COUNTER_KEY_PATH}" 2>/dev/null || echo 'unknown')"
case "${_key_mode}" in
    400|600|"unknown") ;;  # acceptable; unknown = non-Linux stat (macOS variation above covers it)
    *)
        printf 'ERROR: counter private key %s has permissions %s — expected 400 or 600 (CWE-732)\n' \
            "${COUNTER_KEY_PATH}" "${_key_mode}" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# SHA-256 helper — FIPS-aware
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
# Placeholder replacement helper
#
# Replaces a Python string assignment of the form:
#   CONSTANT_NAME: str = "...anything..."
# or:
#   CONSTANT_NAME: str = <anything not containing a newline>
# with:
#   CONSTANT_NAME: str = "NEW_VALUE"
#
# Uses Python (available in builder stage) for reliable in-place substitution
# without relying on GNU sed -i behaviour (macOS/BSD vs Linux portability).
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

# Match the full right-hand side of the assignment — ANY of these forms:
#   CONST: str = "..."                   (plain quoted literal)
#   CONST: str = '...'                   (single-quoted)
#   CONST: str = _PLACEHOLDER_X + "_Y"  (concatenation expression, as in source ctrl)
# Replacement always produces:  CONST: str = "NEW_VALUE"
pattern = re.compile(
    r'^(' + re.escape(const_name) + r'\s*:\s*str\s*=\s*).*$',
    re.MULTILINE,
)
if not pattern.search(content):
    print(f"ERROR: constant {const_name!r} not found in {file_path}", file=sys.stderr)
    sys.exit(1)

escaped_value = new_value.replace('\\', '\\\\').replace('"', '\\"')
new_content = pattern.sub(r'\g<1>"' + escaped_value + '"', content)
file_path.write_text(new_content, encoding="utf-8")
PYEOF
}

# PEM values contain newlines — handled separately via Python heredoc injection.
_replace_pem_constant() {
    local _file="$1"
    local _name="$2"
    local _pem_file="$3"

    python3 - "$_file" "$_name" "$_pem_file" <<'PYEOF'
import sys, re, pathlib

file_path = pathlib.Path(sys.argv[1])
const_name = sys.argv[2]
pem_path = pathlib.Path(sys.argv[3])

pem_value = pem_path.read_text(encoding="utf-8").strip()

content = file_path.read_text(encoding="utf-8")

# Match: CONST_NAME: str = <anything to end of line>
# Handles placeholder expressions and any prior quoted form.
# Replacement uses a triple-quoted block for the PEM (contains newlines).
pattern = re.compile(
    r'^(' + re.escape(const_name) + r'\s*:\s*str\s*=\s*).*$',
    re.MULTILINE,
)
if not pattern.search(content):
    print(f"ERROR: PEM constant {const_name!r} not found in {file_path}", file=sys.stderr)
    sys.exit(1)

escaped = pem_value.replace('\\', '\\\\')
new_content = pattern.sub(r'\g<1>"""\\\n' + escaped + '\n"""', content)
file_path.write_text(new_content, encoding="utf-8")
PYEOF
}

# ---------------------------------------------------------------------------
# Verify no placeholder constants remain
# ---------------------------------------------------------------------------

_assert_no_placeholders() {
    local _file="$1"
    # Check the injected constant VALUES for placeholder strings.
    # The sentinel definition line (_PLACEHOLDER_INTEGRITY = "PLACEHOLDER_YASHIGANI_INTEGRITY")
    # and helper-function bodies (which contain "in VERIFIER_HASH" etc.) are allowed to
    # reference the sentinel by name.  Only the nine injected constants must have real values.
    python3 - "$_file" <<'PYEOF'
import sys, re, pathlib

path = pathlib.Path(sys.argv[1])
content = path.read_text(encoding="utf-8")

INJECTED_CONSTS = [
    "VERIFIER_HASH", "ENFORCER_HASH", "LOADER_HASH",
    "AGENTS_REGISTRY_HASH", "IDENTITY_REGISTRY_HASH",
    "INTEGRITY_HASH", "COUNTER_PUBLIC_KEY_PEM",
    "HASH_BUNDLE_SIG", "EXPECTED_TOKEN_HMAC",
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
# STEP 1: Compute 5 module hashes + embed counter public key
# ---------------------------------------------------------------------------

printf '[inject_hashes] Step 1: computing module hashes and embedding counter public key\n'

VERIFIER_HASH="$(_sha256_file "${VERIFIER_PY}")"
ENFORCER_HASH="$(_sha256_file "${ENFORCER_PY}")"
LOADER_HASH="$(_sha256_file "${LOADER_PY}")"
AGENTS_REGISTRY_HASH="$(_sha256_file "${AGENTS_REGISTRY_PY}")"
IDENTITY_REGISTRY_HASH="$(_sha256_file "${IDENTITY_REGISTRY_PY}")"

printf '[inject_hashes] VERIFIER_HASH          = %s\n' "$VERIFIER_HASH"
printf '[inject_hashes] ENFORCER_HASH          = %s\n' "$ENFORCER_HASH"
printf '[inject_hashes] LOADER_HASH            = %s\n' "$LOADER_HASH"
printf '[inject_hashes] AGENTS_REGISTRY_HASH   = %s\n' "$AGENTS_REGISTRY_HASH"
printf '[inject_hashes] IDENTITY_REGISTRY_HASH = %s\n' "$IDENTITY_REGISTRY_HASH"

_replace_constant "${INTEGRITY_PY}" "VERIFIER_HASH" "${VERIFIER_HASH}"
_replace_constant "${INTEGRITY_PY}" "ENFORCER_HASH" "${ENFORCER_HASH}"
_replace_constant "${INTEGRITY_PY}" "LOADER_HASH" "${LOADER_HASH}"
_replace_constant "${INTEGRITY_PY}" "AGENTS_REGISTRY_HASH" "${AGENTS_REGISTRY_HASH}"
_replace_constant "${INTEGRITY_PY}" "IDENTITY_REGISTRY_HASH" "${IDENTITY_REGISTRY_HASH}"

_replace_pem_constant "${INTEGRITY_PY}" "COUNTER_PUBLIC_KEY_PEM" "${COUNTER_PUB_KEY_PATH}"

printf '[inject_hashes] Step 1 complete\n'

# ---------------------------------------------------------------------------
# STEP 2: Compute SHA-256(_integrity.py) after Step 1 → write INTEGRITY_HASH.
#
# DESIGN-NOTE (Su 2026-06-15): The canonical bundle string (steps 3+4) covers
# the five module hashes only — INTEGRITY_HASH is intentionally excluded.
# Including INTEGRITY_HASH in the signed bundle creates an unresolvable injection
# circularity (sig depends on hash, hash depends on sig).  INTEGRITY_HASH
# receives independent tamper-evidence via the enforcer cross-check path.
# Deviation from Nico §2.4 step order recorded in commit body.
# ---------------------------------------------------------------------------

printf '[inject_hashes] Step 2: computing pre-sig INTEGRITY_HASH\n'

INTEGRITY_HASH_STEP2="$(_sha256_file "${INTEGRITY_PY}")"
_replace_constant "${INTEGRITY_PY}" "INTEGRITY_HASH" "${INTEGRITY_HASH_STEP2}"

printf '[inject_hashes] INTEGRITY_HASH (step 2) = %s\n' "$INTEGRITY_HASH_STEP2"

# ---------------------------------------------------------------------------
# STEP 3: Build canonical bundle string (5 module hashes, NO INTEGRITY_HASH)
#         → sign → write HASH_BUNDLE_SIG.
# ---------------------------------------------------------------------------

printf '[inject_hashes] Step 3: building canonical bundle string and signing\n'

# Canonical bundle: 5 module hashes sorted by key, \n-separated, NO trailing newline.
# Must match verifier._check_hash_bundle_attestation() bundle construction exactly.
BUNDLE_STR="AGENTS_REGISTRY_HASH=${AGENTS_REGISTRY_HASH}
ENFORCER_HASH=${ENFORCER_HASH}
IDENTITY_REGISTRY_HASH=${IDENTITY_REGISTRY_HASH}
LOADER_HASH=${LOADER_HASH}
VERIFIER_HASH=${VERIFIER_HASH}"

HASH_BUNDLE_SIG="$(python3 "${SIGN_BUNDLE_PY}" \
    --key "${COUNTER_KEY_PATH}" \
    --bundle-str "${BUNDLE_STR}")"
[ -n "${HASH_BUNDLE_SIG}" ] || { printf 'ERROR: sign_bundle.py produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "HASH_BUNDLE_SIG" "${HASH_BUNDLE_SIG}"
printf '[inject_hashes] HASH_BUNDLE_SIG = %s...\n' "${HASH_BUNDLE_SIG:0:32}"
printf '[inject_hashes] Step 3 complete\n'

# ---------------------------------------------------------------------------
# STEP 4: Compute KDF token HMAC → write EXPECTED_TOKEN_HMAC.
#
# KDF input bundle matches the signed bundle (5 module hashes, same order).
# DG-01: no CA fingerprint. DG-03: seat_policy="20,5,2".
# ---------------------------------------------------------------------------

printf '[inject_hashes] Step 4: computing EXPECTED_TOKEN_HMAC (DG-01: no CA fingerprint)\n'

EXPECTED_TOKEN_HMAC="$(python3 "${COMPUTE_KDF_PY}" \
    --bundle-str "${BUNDLE_STR}" \
    --licence-id "${COMMUNITY_LICENCE_ID}" \
    --seat-policy "${COMMUNITY_SEAT_POLICY}")"
[ -n "${EXPECTED_TOKEN_HMAC}" ] || { printf 'ERROR: compute_kdf_token.py produced empty output\n' >&2; exit 1; }
_replace_constant "${INTEGRITY_PY}" "EXPECTED_TOKEN_HMAC" "${EXPECTED_TOKEN_HMAC}"
printf '[inject_hashes] EXPECTED_TOKEN_HMAC = %s...\n' "${EXPECTED_TOKEN_HMAC:0:32}"
printf '[inject_hashes] Step 4 complete\n'

# ---------------------------------------------------------------------------
# STEP 5: Re-compute final INTEGRITY_HASH (Steps 3+4 changed _integrity.py).
#         This final hash covers HASH_BUNDLE_SIG and EXPECTED_TOKEN_HMAC,
#         providing tamper evidence for _integrity.py itself via the enforcer
#         cross-check.  The signed bundle does NOT need to be recomputed —
#         it covers the 5 module hashes only, which haven't changed.
# ---------------------------------------------------------------------------

printf '[inject_hashes] Step 5: computing final INTEGRITY_HASH\n'

INTEGRITY_HASH_FINAL="$(_sha256_file "${INTEGRITY_PY}")"
_replace_constant "${INTEGRITY_PY}" "INTEGRITY_HASH" "${INTEGRITY_HASH_FINAL}"

printf '[inject_hashes] INTEGRITY_HASH (final) = %s\n' "$INTEGRITY_HASH_FINAL"
printf '[inject_hashes] Step 5 complete\n'

# ---------------------------------------------------------------------------
# Post-injection assertion: no placeholders remain
# ---------------------------------------------------------------------------

_assert_no_placeholders "${INTEGRITY_PY}"

printf '[inject_hashes] All 5 steps complete. _integrity.py is fully injected.\n'
printf '[inject_hashes] Final INTEGRITY_HASH: %s\n' "${INTEGRITY_HASH_FINAL}"
