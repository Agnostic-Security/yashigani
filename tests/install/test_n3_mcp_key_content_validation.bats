#!/usr/bin/env bats
# tests/install/test_n3_mcp_key_content_validation.bats
#
# FINDING-V412-MCP-SIGNING-KEY-VALIDATION / N3 (Su, 2026-07-21) regression tests.
#
# Root cause (measured live by Maxine, gateway RestartCount 143): install.sh
# gated (re)generation of mcp_identity_signing_key on a NON-EMPTY check only
# (`[[ ! -s "$_mcp_key_file" ]]`). A prior interrupted/killed install can leave
# a corrupt-but-nonempty key file — this suite proves that class of corruption
# with a HAND-CRAFTED fixture (a P-384 SEC1 key whose private-key OCTET STRING
# scalar is 40 bytes instead of the required 48, otherwise well-formed DER) and
# proves the fix rejects it, using BOTH validation tiers:
#   1. python3 + `cryptography` (the exact gateway/backoffice loader)
#   2. the openssl-only fallback (asn1parse scalar-length + curve check) — the
#      path taken on any host without the `cryptography` package importable.
#
# A bare `openssl ec -noout -text` parse ACCEPTS the corrupted fixture (this
# is exactly what shipped the incident — LibreSSL/OpenSSL report a plausible
# "NIST CURVE: P-384" for a truncated scalar). This suite fails loudly if a
# future edit reverts the validator to a bare curve-name check.
#
# Requirements: bats-core >= 1.10.0, bash, openssl, python3 (cryptography
# optional — tier 2 below is exercised explicitly with python3 hidden so CI
# without the `cryptography` package still gets full coverage).
#
# Run:
#   bats tests/install/test_n3_mcp_key_content_validation.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# Test scratch space — under repo, never /tmp.
FIXTURE_DIR="${REPO_ROOT}/tests/install/.fixtures_n3"
FUNCS_SH="${FIXTURE_DIR}/extracted_funcs.sh"

setup() {
  rm -rf "${FIXTURE_DIR}"
  mkdir -p "${FIXTURE_DIR}"

  # ---- Extract the real functions under test verbatim from install.sh -----
  # (same technique test_offboard_idempotency.bats uses for pki_ownership.sh
  # helpers) so this suite tests the SHIPPED code, not a re-implementation.
  {
    printf '#!/usr/bin/env bash\n'
    printf 'YSG_PODMAN_RUNTIME=false\n'
    printf 'log_info() { :; }\n'
    printf 'log_warn() { :; }\n'
    printf 'log_error() { :; }\n'
  } > "${FUNCS_SH}"
  awk '/^_ec_signing_key_is_valid\(\) \{/,/^\}$/' "${INSTALL_SH}" >> "${FUNCS_SH}"
  printf '\n' >> "${FUNCS_SH}"
  awk '/^_mcp_signing_key_is_valid\(\) \{/,/^\}$/' "${INSTALL_SH}" >> "${FUNCS_SH}"
  printf '\n' >> "${FUNCS_SH}"
  awk '/^_audit_signing_key_is_valid\(\) \{/,/^\}$/' "${INSTALL_SH}" >> "${FUNCS_SH}"
  printf '\n' >> "${FUNCS_SH}"
  awk '/^_safe_read_secret\(\) \{/,/^\}$/' "${INSTALL_SH}" >> "${FUNCS_SH}"

  # ---- Fixture: good P-384 SEC1 key (mcp_identity_signing_key format) ------
  openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null \
    | openssl ec -out "${FIXTURE_DIR}/good_mcp.key" 2>/dev/null

  # ---- Fixture: good P-256 PKCS#8 key (audit_signing.key format) ----------
  openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt -out "${FIXTURE_DIR}/good_audit.key" 2>/dev/null

  # ---- Fixture: empty file -------------------------------------------------
  : > "${FIXTURE_DIR}/empty.key"

  # ---- Fixture: wrong-curve SEC1 key (P-256, presented as an MCP key) -----
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
    | openssl ec -out "${FIXTURE_DIR}/wrong_curve.key" 2>/dev/null

  # ---- Fixture: corrupt P-384 SEC1 key — 40-byte scalar (needs 48) --------
  # Reproduces the EXACT corruption class from the incident: well-formed DER,
  # short private-key OCTET STRING. Built by byte-surgery on the good fixture
  # (drop the last 8 bytes of the 48-byte scalar and fix up ASN.1 lengths).
  python3 - "${FIXTURE_DIR}/good_mcp.key" "${FIXTURE_DIR}/corrupt_mcp.key" <<'PYEOF'
import sys, base64

def pem_to_der(path):
    b64 = "".join(l for l in open(path).read().splitlines() if l and not l.startswith("-----"))
    return base64.b64decode(b64)

def der_to_pem(der, label):
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n" % label + "\n".join(lines) + "\n-----END %s-----\n" % label

data = bytearray(pem_to_der(sys.argv[1]))
# SEC1 ECPrivateKey: 30 <len> 02 01 01 04 30 <48-byte scalar> a0 07 ... a1 64 ...
hdr_len = 3 if data[1] == 0x81 else 2
off = hdr_len
assert data[off:off + 3] == bytes.fromhex("020101")
assert data[off + 3] == 0x04 and data[off + 4] == 48
scalar_off = off + 5
scalar = data[scalar_off:scalar_off + 48]
new_scalar = scalar[:40]  # drop 8 bytes -> 40-byte scalar (too short for P-384)
rest = data[scalar_off + 48:]
new_body = bytes.fromhex("020101") + bytes([0x04, len(new_scalar)]) + new_scalar + rest
seq_len = len(new_body)
seq_header = bytes([0x30, 0x81, seq_len]) if seq_len >= 128 else bytes([0x30, seq_len])
open(sys.argv[2], "w").write(der_to_pem(seq_header + new_body, "EC PRIVATE KEY"))
PYEOF

  # ---- Fixture: corrupt P-256 PKCS#8 key — 24-byte scalar (needs 32) ------
  python3 - "${FIXTURE_DIR}/good_audit.key" "${FIXTURE_DIR}/corrupt_audit.key" <<'PYEOF'
import sys, base64

def pem_to_der(path):
    b64 = "".join(l for l in open(path).read().splitlines() if l and not l.startswith("-----"))
    return base64.b64decode(b64)

def der_to_pem(der, label):
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n" % label + "\n".join(lines) + "\n-----END %s-----\n" % label

data = bytearray(pem_to_der(sys.argv[1]))
# PKCS8: 30 <len> 02 01 00 30 <alg-id seq> 04 <len> <inner SEC1: 30 <len> 02 01 01 04 20 <32-byte scalar> ...>
outer_hdr_len = 3 if data[1] == 0x81 else 2
off = outer_hdr_len
assert data[off:off + 3] == bytes.fromhex("020100")
alg_id_tag_off = off + 3
assert data[alg_id_tag_off] == 0x30
alg_id_len = data[alg_id_tag_off + 1]
octet_hdr_off = alg_id_tag_off + 2 + alg_id_len
assert data[octet_hdr_off] == 0x04
outer_octet_len = data[octet_hdr_off + 1]
inner = data[octet_hdr_off + 2: octet_hdr_off + 2 + outer_octet_len]
assert inner[0] == 0x30
assert inner[2:5] == bytes.fromhex("020101")
assert inner[5] == 0x04 and inner[6] == 32
scalar = inner[7:7 + 32]
new_scalar = scalar[:24]  # drop 8 bytes -> 24-byte scalar (too short for P-256)
rest = inner[7 + 32:]
new_inner_body = bytes.fromhex("020101") + bytes([0x04, len(new_scalar)]) + new_scalar + rest
new_inner = bytes([0x30, len(new_inner_body)]) + new_inner_body
prefix = bytes(data[:octet_hdr_off])
new_outer_octet = bytes([0x04, len(new_inner)]) + new_inner
new_body = prefix[outer_hdr_len:] + new_outer_octet
outer_seq_len = len(new_body)
outer_header = bytes([0x30, 0x81, outer_seq_len]) if outer_seq_len >= 128 else bytes([0x30, outer_seq_len])
open(sys.argv[2], "w").write(der_to_pem(outer_header + new_body, "PRIVATE KEY"))
PYEOF
}

teardown() {
  rm -rf "${FIXTURE_DIR}"
}

# ── Sanity: fixtures actually reproduce the incident's false-positive ───────

@test "N3-sanity: bare 'openssl ec -noout -text' ACCEPTS the corrupt MCP fixture (proves the old check was insufficient)" {
  run openssl ec -in "${FIXTURE_DIR}/corrupt_mcp.key" -noout -text
  [ "$status" -eq 0 ]
  [[ "$output" == *"P-384"* ]]
}

@test "N3-sanity: python3 cryptography REJECTS the corrupt MCP fixture with the exact incident error" {
  run python3 -c "
from cryptography.hazmat.primitives.serialization import load_pem_private_key
try:
    load_pem_private_key(open('${FIXTURE_DIR}/corrupt_mcp.key','rb').read(), password=None)
    raise SystemExit(1)
except Exception as e:
    assert 'too short' in str(e), str(e)
    raise SystemExit(0)
"
  [ "$status" -eq 0 ]
}

# ── Tier 1: python3 + cryptography (exact production loader) ───────────────

@test "N3: _mcp_signing_key_is_valid ACCEPTS a good P-384 key" {
  run bash -c "source '${FUNCS_SH}'; _mcp_signing_key_is_valid '${FIXTURE_DIR}/good_mcp.key'"
  [ "$status" -eq 0 ]
}

@test "N3: _mcp_signing_key_is_valid REJECTS the corrupt (short-scalar) P-384 fixture" {
  run bash -c "source '${FUNCS_SH}'; _mcp_signing_key_is_valid '${FIXTURE_DIR}/corrupt_mcp.key'"
  [ "$status" -eq 1 ]
}

@test "N3: _mcp_signing_key_is_valid REJECTS an empty file" {
  run bash -c "source '${FUNCS_SH}'; _mcp_signing_key_is_valid '${FIXTURE_DIR}/empty.key'"
  [ "$status" -eq 1 ]
}

@test "N3: _mcp_signing_key_is_valid REJECTS an absent file" {
  run bash -c "source '${FUNCS_SH}'; _mcp_signing_key_is_valid '${FIXTURE_DIR}/does-not-exist.key'"
  [ "$status" -eq 1 ]
}

@test "N3: _mcp_signing_key_is_valid REJECTS a wrong-curve (P-256) key" {
  run bash -c "source '${FUNCS_SH}'; _mcp_signing_key_is_valid '${FIXTURE_DIR}/wrong_curve.key'"
  [ "$status" -eq 1 ]
}

@test "N3: _audit_signing_key_is_valid ACCEPTS a good PKCS#8 P-256 key" {
  run bash -c "source '${FUNCS_SH}'; _audit_signing_key_is_valid '${FIXTURE_DIR}/good_audit.key'"
  [ "$status" -eq 0 ]
}

@test "N3: _audit_signing_key_is_valid REJECTS the corrupt (short-scalar) PKCS#8 fixture" {
  run bash -c "source '${FUNCS_SH}'; _audit_signing_key_is_valid '${FIXTURE_DIR}/corrupt_audit.key'"
  [ "$status" -eq 1 ]
}

# ── Tier 2: openssl-only fallback (no python3/cryptography on the host) ────
# This is the tier that MUST catch the incident's corruption class without any
# python dependency — proven here by hiding python3 from `command -v`.

@test "N3-fallback: _mcp_signing_key_is_valid ACCEPTS a good P-384 key with no python3" {
  run bash -c "
    command() { [[ \"\$1\" == -v && \"\$2\" == python3 ]] && return 1; builtin command \"\$@\"; }
    source '${FUNCS_SH}'
    _mcp_signing_key_is_valid '${FIXTURE_DIR}/good_mcp.key'
  "
  [ "$status" -eq 0 ]
}

@test "N3-fallback: _mcp_signing_key_is_valid REJECTS the corrupt P-384 fixture with no python3 (the exact incident bug class, openssl-only)" {
  run bash -c "
    command() { [[ \"\$1\" == -v && \"\$2\" == python3 ]] && return 1; builtin command \"\$@\"; }
    source '${FUNCS_SH}'
    _mcp_signing_key_is_valid '${FIXTURE_DIR}/corrupt_mcp.key'
  "
  [ "$status" -eq 1 ]
}

@test "N3-fallback: _audit_signing_key_is_valid ACCEPTS a good PKCS#8 key with no python3" {
  run bash -c "
    command() { [[ \"\$1\" == -v && \"\$2\" == python3 ]] && return 1; builtin command \"\$@\"; }
    source '${FUNCS_SH}'
    _audit_signing_key_is_valid '${FIXTURE_DIR}/good_audit.key'
  "
  [ "$status" -eq 0 ]
}

@test "N3-fallback: _audit_signing_key_is_valid REJECTS the corrupt PKCS#8 fixture with no python3" {
  run bash -c "
    command() { [[ \"\$1\" == -v && \"\$2\" == python3 ]] && return 1; builtin command \"\$@\"; }
    source '${FUNCS_SH}'
    _audit_signing_key_is_valid '${FIXTURE_DIR}/corrupt_audit.key'
  "
  [ "$status" -eq 1 ]
}

# ── Wiring: call sites use content validation, not bare non-emptiness ──────

@test "N3-wiring: fresh-install MCP keygen site calls _mcp_signing_key_is_valid (not bare [[ -s ]])" {
  run grep -c 'if ! _mcp_signing_key_is_valid "\$_mcp_key_file"; then' "${INSTALL_SH}"
  [ "$output" != "0" ]
}

@test "N3-wiring: fresh-install MCP keygen site is atomic (mktemp + mv -f into place)" {
  run grep -c '_mcp_key_tmp="\$(mktemp "\${_mcp_key_file}.XXXXXX")"' "${INSTALL_SH}"
  [ "$output" != "0" ]
  run grep -c 'mv -f "\${_mcp_key_tmp}" "\${_mcp_key_file}"' "${INSTALL_SH}"
  [ "$output" != "0" ]
}

@test "N3-wiring: upgrade-path MCP keygen site FAILS LOUD (does not silently regenerate) on an invalid existing key" {
  run grep -c 'refuses to clobber a file that might be a real, deliberately-rotated key' "${INSTALL_SH}"
  [ "$output" != "0" ]
  run grep -c 'elif ! _mcp_signing_key_is_valid "\$_mcp_key_file_up"; then' "${INSTALL_SH}"
  [ "$output" != "0" ]
}

@test "N3-wiring: upgrade-path MCP keygen (absent-file branch) is also atomic" {
  run grep -c '_mcp_key_tmp_up="\$(mktemp "\${_mcp_key_file_up}.XXXXXX")"' "${INSTALL_SH}"
  [ "$output" != "0" ]
  run grep -c 'mv -f "\${_mcp_key_tmp_up}" "\${_mcp_key_file_up}"' "${INSTALL_SH}"
  [ "$output" != "0" ]
}

@test "N3-wiring: audit-signing-key entry gate calls _audit_signing_key_is_valid (pattern-sweep, PKI keys)" {
  run grep -c '\[\[ -f "\$keyf" && -f "\$crtf" \]\] && _audit_signing_key_is_valid "\$keyf"' "${INSTALL_SH}"
  [ "$output" != "0" ]
}

# ── Static hygiene on the edited regions ────────────────────────────────────

@test "N3: install.sh passes bash -n syntax check" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "N3: extracted functions are shellcheck -x clean" {
  run shellcheck -x "${FUNCS_SH}"
  [ "$status" -eq 0 ]
}
