#!/usr/bin/env python3
"""
compute_kdf_token.py — Build-pipeline helper: compute EXPECTED_TOKEN_HMAC.

Implements DG-01 (no CA fingerprint in KDF inputs) and DG-03 (Community
seat_policy = "20,5,2").

Usage:
    python scripts/compute_kdf_token.py \\
        --bundle-str  "AGENTS_REGISTRY_HASH=<hex>\\n..." \\
        [--licence-id ""]          # default: empty string (Community)
        [--seat-policy "20,5,2"]  # default: Community

    Or pass --bundle-str via stdin with "-":
        echo "$BUNDLE_STR" | python scripts/compute_kdf_token.py --bundle-str -

Output:
    A single hex string (64 chars) printed to stdout — the EXPECTED_TOKEN_HMAC
    constant to embed in _integrity.py.

Construction (must match verifier._check_kdf_token() byte-for-byte):
    IKM   = SHA-256(hash_bundle_str.encode("utf-8"))
    salt  = SHA-256(licence_id.encode("utf-8") + seat_policy.encode("utf-8"))
    token = HKDF-SHA-256(IKM, salt, info=b"yashigani-integrity-v1", L=32)
    EXPECTED_TOKEN_HMAC = SHA-256(token + b"yashigani-kdf-gate-v1").hexdigest()

Security notes:
    - No CA fingerprint (DG-01: dropped from KDF inputs).
    - Community licence_id is "" and seat_policy is "20,5,2" (DG-03).
    - Output is hex, compared with .strip() in the runtime check.
    - This script never reads or touches any private key.
"""
from __future__ import annotations

import argparse
import hashlib
import sys


def _derive_integrity_token(
    hash_bundle_str: str,
    licence_id: str,
    seat_policy: str,
) -> bytes:
    """
    HKDF-SHA-256 over (hash_bundle_str, licence_id, seat_policy).

    Must stay byte-for-byte identical to verifier._derive_integrity_token().
    DG-01: no CA fingerprint in inputs.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256 as CryptoSHA256
    from cryptography.hazmat.backends import default_backend

    ikm = hashlib.sha256(hash_bundle_str.encode("utf-8")).digest()
    salt = hashlib.sha256(
        licence_id.encode("utf-8") + seat_policy.encode("utf-8")
    ).digest()
    hkdf = HKDF(
        algorithm=CryptoSHA256(),
        length=32,
        salt=salt,
        info=b"yashigani-integrity-v1",
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def compute_expected_token_hmac(
    hash_bundle_str: str,
    licence_id: str = "",
    seat_policy: str = "20,5,2",
) -> str:
    """
    Return the hex EXPECTED_TOKEN_HMAC to embed in _integrity.py.

    SHA-256(token || b"yashigani-kdf-gate-v1") as a hex string.
    Matches verifier._check_kdf_token() comparison exactly.
    """
    token = _derive_integrity_token(hash_bundle_str, licence_id, seat_policy)
    return hashlib.sha256(token + b"yashigani-kdf-gate-v1").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compute EXPECTED_TOKEN_HMAC for embedding in _integrity.py. "
            "Outputs a 64-char hex string."
        )
    )
    parser.add_argument(
        "--bundle-str",
        required=True,
        metavar="STRING_OR_DASH",
        help=(
            "Canonical hash-bundle string (sorted KEY=hex\\n... pairs, no trailing newline). "
            "Pass '-' to read from stdin."
        ),
    )
    parser.add_argument(
        "--licence-id",
        default="",
        help="Licence ID (default: empty string for Community).",
    )
    parser.add_argument(
        "--seat-policy",
        default="20,5,2",
        help="Seat policy string (default: '20,5,2' for Community — DG-03).",
    )
    args = parser.parse_args()

    if args.bundle_str == "-":
        bundle_str = sys.stdin.read()
    else:
        bundle_str = args.bundle_str

    # Strip only a trailing newline that a shell heredoc / echo would add —
    # the canonical bundle string itself must have no trailing newline per spec.
    bundle_str = bundle_str.rstrip("\n")

    if not bundle_str:
        print("ERROR: empty bundle string", file=sys.stderr)
        sys.exit(1)

    result = compute_expected_token_hmac(
        bundle_str,
        licence_id=args.licence_id,
        seat_policy=args.seat_policy,
    )
    print(result)


if __name__ == "__main__":
    main()
