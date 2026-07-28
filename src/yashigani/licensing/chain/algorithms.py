"""
Yashigani licence-hardening v2 — crypto-agile algorithm dispatch.

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     "NIST PQC alignment" section + ROUND-3/ROUND-4 red-gate fixes.

`Alg` is a CLOSED enum of fixed strings. It lives INSIDE the signed/canonicalised
digest of every leaf_cert and every licence payload — never as an unsigned
wrapper — so an attacker cannot relabel a signature under a different (weaker)
algorithm without invalidating the signature (Nico, ROUND-3 fix 2).

Supported set (design doc, NIST PQC alignment section):
    ecdsa-p384-sha384                      interim, CNSA 2.0 classical — LIVE today
    ml-dsa-87                              FIPS 204, NIST L5 — PQC target (CNSA 2.0 top)
    hybrid(ecdsa-p384+ml-dsa-87)           both-must-verify, ONE atomic non-strippable field
    slh-dsa-sha2-256s                      FIPS 205, L5 — optional conservative hash-based option

Honest-claims discipline: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and SHA-384/512
(FIPS 180-4) are NIST-*approved algorithms*. We do NOT claim a CMVP-*validated
module* for any of them — that is a separate, per-deployment attestation that
must be live-checked against the CMVP database at cutover, never assumed
(see design doc §"NIST PQC alignment" honest-claims bullet, and Nico's role
generally — never claim FIPS 140-3 module validation from an algorithm name).

Interim reality: cryptography>=48 (this repo pins >=48.0.1) does not yet expose
ml_dsa / slh_dsa primitives (verified against the installed 49.0.0 wheel at the
time this module was authored — no `cryptography.hazmat.primitives.asymmetric.ml_dsa`
or `.slh_dsa` module exists). ML_DSA_87, SLH_DSA_SHA2_256S and HYBRID therefore
raise AlgorithmUnavailableError on sign/verify: a deliberate fail-closed stub,
NOT a silent downgrade to the classical component. When the cryptography library
ships FIPS-204/205 support, only the `_ALGORITHM_BACKENDS` table in this file
needs to grow a real implementation — the enum, the wire format, and every
caller (Signer, leaf_cert, verifier) stay unchanged. This is the "no v6, no
format break" property the design calls for.
"""
from __future__ import annotations

import struct
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# ---------------------------------------------------------------------------
# Hashing tier (design doc: "SHA-512 at the top tier, SHA-384 hard floor,
# everywhere ... SHA-256 retired from this design"). Phase A wires the floor;
# per-context digest helpers live in canonical.py.
# ---------------------------------------------------------------------------
HASH_FLOOR = hashes.SHA384
HASH_TOP_TIER = hashes.SHA512


class Alg(str, Enum):
    """Closed enum of fixed algorithm-identifier strings.

    Any string that does not exactly match one of these members is UNKNOWN
    and must be rejected — never coerced, never treated as a lesser-known
    equivalent (no downgrade path). Use `Alg.from_wire()` to parse untrusted
    input; it raises UnknownAlgorithmError rather than returning a default.
    """

    ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
    ML_DSA_87 = "ml-dsa-87"
    HYBRID_ECDSA_P384_ML_DSA_87 = "hybrid(ecdsa-p384+ml-dsa-87)"
    SLH_DSA_SHA2_256S = "slh-dsa-sha2-256s"

    @classmethod
    def from_wire(cls, value: str) -> "Alg":
        """Parse an untrusted `alg` string. Raises UnknownAlgorithmError — never
        silently substitutes a default (that would BE the downgrade attack)."""
        try:
            return cls(value)
        except ValueError as exc:
            raise UnknownAlgorithmError(
                f"alg {value!r} is not in the closed algorithm enum — rejected, no downgrade"
            ) from exc


# Algorithms whose sign/verify path is implemented and safe to use today.
IMPLEMENTED_ALGORITHMS: frozenset[Alg] = frozenset({Alg.ECDSA_P384_SHA384})


class UnknownAlgorithmError(ValueError):
    """Raised when an `alg` string is not a member of the closed Alg enum.

    This is the "reject (no downgrade)" path from the design doc — it must
    never be caught and silently mapped to a default/weaker algorithm.
    """


class AlgorithmUnavailableError(NotImplementedError):
    """Raised when a *known, enum-valid* algorithm has no working backend yet
    (ml-dsa-87, the hybrid combination, slh-dsa-sha2-256s — pending cryptography
    library / hardware support). Distinct from UnknownAlgorithmError: the
    algorithm is legitimate and future-supported, it is just not live in this
    build. Callers must treat this as a hard failure (fail-closed), never as
    "fall back to the classical component."
    """


class RoleMismatchError(RuntimeError):
    """Raised when a Signer is asked to sign for a role it is not provisioned for."""


# ---------------------------------------------------------------------------
# DER <-> raw r||s reconciliation (ROUND-3 fix 3 + KMS-abstraction §, Nico).
#
# Software signing via `cryptography`'s EllipticCurvePrivateKey.sign() already
# emits DER (ASN.1 SEQUENCE{r, s}) — no reconciliation needed for PemSigner.
# PKCS#11 devices (YubiKey PIV C_Sign) and some cloud KMS backends (Azure Key
# Vault) return the RAW concatenation r||s instead. Every hardware/KMS signer
# path MUST run its output through raw_rs_to_der() before returning — this is
# a "live TODAY" fix per the design (not deferred to a future KMS milestone).
# ---------------------------------------------------------------------------

def raw_rs_to_der(raw_signature: bytes, curve_size_bytes: int = 48) -> bytes:
    """Convert a PKCS#11/KMS raw r||s ECDSA signature to DER.

    curve_size_bytes defaults to 48 (P-384's field size in bytes — 384 bits).
    Use 32 for P-256 hardware that has not yet migrated.
    """
    if len(raw_signature) != 2 * curve_size_bytes:
        raise ValueError(
            f"raw ECDSA signature is {len(raw_signature)} bytes; "
            f"expected {2 * curve_size_bytes} for a {curve_size_bytes * 8}-bit curve"
        )
    r = int.from_bytes(raw_signature[:curve_size_bytes], "big")
    s = int.from_bytes(raw_signature[curve_size_bytes:], "big")
    return utils.encode_dss_signature(r, s)


def der_to_raw_rs(der_signature: bytes, curve_size_bytes: int = 48) -> bytes:
    """Convert a DER ECDSA signature to raw r||s (inverse of raw_rs_to_der).

    Provided for symmetry / KMS backends that require raw r||s as *input*
    (e.g. some HSM verify APIs) even though this codebase's canonical wire
    format is always DER.
    """
    r, s = utils.decode_dss_signature(der_signature)
    return r.to_bytes(curve_size_bytes, "big") + s.to_bytes(curve_size_bytes, "big")


# ---------------------------------------------------------------------------
# ECDSA P-384 / SHA-384 backend — the interim, live-today algorithm.
# ---------------------------------------------------------------------------

def _ecdsa_p384_sign(private_key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    """Sign a pre-computed SHA-384 digest (Prehashed) — returns DER.

    `digest` must already be the domain-separated SHA-384 digest produced by
    canonical.py's *_signing_digest() helpers — this function never hashes
    raw message bytes itself, so the caller's domain-separation context tag
    is always inside what gets signed.
    """
    if not isinstance(private_key.curve, ec.SECP384R1):
        raise RuntimeError(
            f"ecdsa-p384-sha384 signer requires a P-384 key; got {private_key.curve.name}"
        )
    if len(digest) != 48:
        raise ValueError(f"ecdsa-p384-sha384 expects a 48-byte SHA-384 digest, got {len(digest)} bytes")
    return private_key.sign(digest, ec.ECDSA(utils.Prehashed(HASH_FLOOR())))


def _ecdsa_p384_verify(public_key_pem: str, digest: bytes, signature: bytes) -> bool:
    """Verify a DER ECDSA P-384/SHA-384 signature over a pre-computed digest.

    Returns False on InvalidSignature. Raises RuntimeError on key-type/curve
    confusion (ASVS-style explicit allowlist — never silently accept a
    different key type at the same slot; see verifier.py's existing
    `_verify_primary_signature` for the established pattern this mirrors).
    """
    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise RuntimeError(
            f"ecdsa-p384-sha384 verify: expected EllipticCurvePublicKey, got {type(public_key).__name__}"
        )
    if not isinstance(public_key.curve, ec.SECP384R1):
        raise RuntimeError(
            f"ecdsa-p384-sha384 verify: expected secp384r1, got {public_key.curve.name}"
        )
    if len(digest) != 48:
        raise ValueError(f"ecdsa-p384-sha384 expects a 48-byte SHA-384 digest, got {len(digest)} bytes")
    try:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(HASH_FLOOR())))
        return True
    except InvalidSignature:
        return False


def verify_signature(alg: Alg, public_key_pem: str, digest: bytes, signature: bytes) -> bool:
    """Dispatch verification by `alg`.

    Raises UnknownAlgorithmError for anything outside the closed enum (call
    Alg.from_wire() first on untrusted input — this function assumes `alg`
    is already a valid Alg member and only handles the "known but not yet
    implemented" case itself).

    Raises AlgorithmUnavailableError for ml-dsa-87 / hybrid / slh-dsa-sha2-256s
    until their backends land — this is fail-closed, NOT a downgrade: the
    hybrid path in particular exposes NO isolated sub-signature verify path,
    so it cannot silently pass on the classical component alone.
    """
    if not isinstance(alg, Alg):
        alg = Alg.from_wire(alg)  # type: ignore[arg-type]

    if alg == Alg.ECDSA_P384_SHA384:
        return _ecdsa_p384_verify(public_key_pem, digest, signature)

    if alg in (Alg.ML_DSA_87, Alg.SLH_DSA_SHA2_256S, Alg.HYBRID_ECDSA_P384_ML_DSA_87):
        raise AlgorithmUnavailableError(
            f"{alg.value} has no live backend in this build (cryptography library / "
            f"hardware support pending) — fail-closed, not a downgrade"
        )

    # Unreachable given the closed enum, but keeps the function total.
    raise UnknownAlgorithmError(f"alg {alg!r} has no dispatch entry")


def sign_message(alg: Alg, private_key: object, digest: bytes) -> bytes:
    """Dispatch signing by `alg`. Mirrors verify_signature()'s fail-closed shape."""
    if not isinstance(alg, Alg):
        alg = Alg.from_wire(alg)  # type: ignore[arg-type]

    if alg == Alg.ECDSA_P384_SHA384:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise RuntimeError(f"ecdsa-p384-sha384 sign requires an EC private key, got {type(private_key).__name__}")
        return _ecdsa_p384_sign(private_key, digest)

    if alg in (Alg.ML_DSA_87, Alg.SLH_DSA_SHA2_256S, Alg.HYBRID_ECDSA_P384_ML_DSA_87):
        raise AlgorithmUnavailableError(
            f"{alg.value} has no live backend in this build — fail-closed, not a downgrade"
        )

    raise UnknownAlgorithmError(f"alg {alg!r} has no dispatch entry")


# ---------------------------------------------------------------------------
# Hybrid wire format — atomic, non-strippable, both-must-verify.
#
# The design is explicit: "Hybrid = one atomic field, both components
# mandatory, verifier exposes NO isolated sub-signature verify path (no
# hybrid->classical downgrade by relabeling)." We enforce that at TWO layers:
#   1. Wire format: encode_hybrid_signature() always writes exactly two
#      length-prefixed components; decode_hybrid_signature() rejects anything
#      that doesn't parse as exactly two components (a stripped/truncated
#      blob fails to decode at all — it is not silently treated as
#      "classical-only").
#   2. API surface: there is no public function that verifies only the
#      ECDSA component of a hybrid signature. verify_signature(HYBRID, ...)
#      is the only entry point, and it currently raises
#      AlgorithmUnavailableError (ML-DSA-87 backend not live) rather than
#      ever returning a pass based on the classical half alone.
# ---------------------------------------------------------------------------

_HYBRID_LEN_STRUCT = struct.Struct(">I")  # 4-byte big-endian length prefix


def encode_hybrid_signature(classical_sig: bytes, pqc_sig: bytes) -> bytes:
    """Wire-encode a hybrid signature as two length-prefixed components.

    Format: u32(len(classical_sig)) || classical_sig || u32(len(pqc_sig)) || pqc_sig
    """
    return (
        _HYBRID_LEN_STRUCT.pack(len(classical_sig))
        + classical_sig
        + _HYBRID_LEN_STRUCT.pack(len(pqc_sig))
        + pqc_sig
    )


def decode_hybrid_signature(blob: bytes) -> tuple[bytes, bytes]:
    """Decode a hybrid signature blob into (classical_sig, pqc_sig).

    Raises ValueError if the blob does not contain EXACTLY two well-formed
    length-prefixed components with no trailing bytes — this is the
    non-strippability enforcement at the wire-format layer. A signature
    with the PQC component chopped off (to try to pass it as classical-only
    elsewhere) fails to decode as a hybrid signature at all.
    """
    if len(blob) < _HYBRID_LEN_STRUCT.size:
        raise ValueError("hybrid signature blob too short to contain a length prefix")
    (classical_len,) = _HYBRID_LEN_STRUCT.unpack_from(blob, 0)
    offset = _HYBRID_LEN_STRUCT.size
    if len(blob) < offset + classical_len + _HYBRID_LEN_STRUCT.size:
        raise ValueError("hybrid signature blob truncated — missing PQC component")
    classical_sig = blob[offset : offset + classical_len]
    offset += classical_len
    (pqc_len,) = _HYBRID_LEN_STRUCT.unpack_from(blob, offset)
    offset += _HYBRID_LEN_STRUCT.size
    if len(blob) < offset + pqc_len:
        raise ValueError("hybrid signature blob truncated — PQC component shorter than declared")
    pqc_sig = blob[offset : offset + pqc_len]
    offset += pqc_len
    if offset != len(blob):
        raise ValueError("hybrid signature blob has trailing bytes after both components — reject")
    if not classical_sig or not pqc_sig:
        raise ValueError("hybrid signature blob has an empty component — both are mandatory")
    return classical_sig, pqc_sig


def hybrid_both_must_verify(classical_ok: bool, pqc_ok: bool) -> bool:
    """Pure AND-logic combinator for hybrid verification.

    Extracted as a standalone pure function (rather than inlined) so the
    both-must-verify property is independently unit-testable without needing
    a live ML-DSA-87 backend: tests can drive this function directly with
    every combination of (True/False, True/False) and assert only
    (True, True) -> True. The real verify_signature(HYBRID, ...) path will
    call this once both component verifiers are live.
    """
    return bool(classical_ok and pqc_ok)
