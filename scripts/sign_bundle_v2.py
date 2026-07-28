#!/usr/bin/env python3
"""
sign_bundle_v2.py — Build-pipeline helper: sign the canonical hash-bundle
with a CODE-role leaf (root->leaf chain), superseding v1's sign_bundle.py
(counter key, P-256/SHA-256, no chain-of-trust).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §3.3 (Build hash-bundle): bundle_sig = Signer(code leaf).sign(digest),
     digest = SHA384("YSG-BUNDLE-v2" || six_file_hashes).

Usage:
    python scripts/sign_bundle_v2.py \\
        --key   /run/secrets/code_leaf_private_key \\
        --bundle-str "AGENTS_REGISTRY_HASH=<hex>\\n..."

    Or pass --bundle-str via stdin with "-".

Output:
    Standard base64 DER ECDSA P-384 signature on stdout — the BUNDLE_SIG
    constant to embed in _integrity.py (matches verifier._check_build_
    integrity_chain()'s dispatch: verify_signature(code_leaf_cert.alg, ...)).

Passphrase for the (MC-01 encrypted) code-leaf private key, in order:
    1. CODE_LEAF_KEY_PASSPHRASE   — dedicated var (recommended for CI/BuildKit)
    2. YASHIGANI_KEY_PASSPHRASE   — shared fallback (also used by keygen.py)
    3. "" (explicit, either var set to empty string) — unencrypted key,
       dev/test convenience only.
Exits with an error if neither var is present — never silently falls back
to password=None (masks a misconfigured passphrase delivery).

Security notes (mirrors v1 sign_bundle.py's MC-01/S1 discipline):
    - Private key path is read from the argument; key material never printed.
    - Key file must be chmod 0400 or 0600 — abort if world/group readable
      (CWE-732).
    - Self-verifies the produced signature against the derived public key
      before printing — never emits an unverified signature.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    src = Path(__file__).resolve().parent.parent / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


_ensure_src_on_path()


def _resolve_code_leaf_passphrase() -> bytes | None:
    for var in ("CODE_LEAF_KEY_PASSPHRASE", "YASHIGANI_KEY_PASSPHRASE"):
        val = os.environ.get(var)
        if val is not None:
            if val == "":
                return None
            return val.rstrip("\n").encode("utf-8")
    print(
        "ERROR: neither CODE_LEAF_KEY_PASSPHRASE nor YASHIGANI_KEY_PASSPHRASE is set.\n"
        "  For encrypted keys (MC-01): set CODE_LEAF_KEY_PASSPHRASE.\n"
        "  For unencrypted / dev keys: set CODE_LEAF_KEY_PASSPHRASE='' explicitly.",
        file=sys.stderr,
    )
    sys.exit(1)


def _check_key_permissions(key_path: str) -> None:
    mode = os.stat(key_path).st_mode
    if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
        print(
            f"ERROR: private key {key_path!r} has group/world read or write bits set "
            f"(mode={oct(mode)}) — refusing to use (CWE-732).",
            file=sys.stderr,
        )
        sys.exit(1)


def sign_bundle_v2(private_key_path: str, bundle_str: str) -> str:
    """Sign the canonical bundle string with a P-384 code-leaf key via the
    chain-of-trust digest formula (§3.3). Self-verifies before returning."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from yashigani.licensing.chain.algorithms import Alg, sign_message, verify_signature
    from yashigani.licensing.chain.canonical import bundle_signing_digest

    _check_key_permissions(private_key_path)
    passphrase = _resolve_code_leaf_passphrase()

    try:
        key_pem = Path(private_key_path).read_bytes()
    except OSError as exc:
        print(f"ERROR: cannot read private key {private_key_path!r}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        private_key = load_pem_private_key(key_pem, password=passphrase)
    except Exception as exc:
        print(f"ERROR: cannot parse private key: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(private_key, EllipticCurvePrivateKey):
        print(f"ERROR: expected ECDSA private key, got {type(private_key).__name__}", file=sys.stderr)
        sys.exit(1)

    digest = bundle_signing_digest(bundle_str)

    try:
        sig_bytes = sign_message(Alg.ECDSA_P384_SHA384, private_key, digest)
    except Exception as exc:
        print(f"ERROR: signing failed: {exc}", file=sys.stderr)
        sys.exit(1)

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    try:
        if not verify_signature(Alg.ECDSA_P384_SHA384, pub_pem, digest, sig_bytes):
            raise InvalidSignature()
    except InvalidSignature:
        print("ERROR: self-verification of produced signature FAILED — aborting", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: self-verification raised unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)

    import base64

    return base64.b64encode(sig_bytes).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Sign the canonical hash-bundle with a CODE-role leaf key (P-384/SHA-384, "
            "chain-of-trust §3.3). Outputs a standard-base64 DER ECDSA signature."
        )
    )
    parser.add_argument("--key", required=True, metavar="PRIVATE_KEY_PEM", help="Path to the code leaf's private key PEM.")
    parser.add_argument(
        "--bundle-str",
        required=True,
        metavar="STRING_OR_DASH",
        help="Canonical hash-bundle string (sorted KEY=hex\\n... pairs, no trailing newline). '-' reads stdin.",
    )
    args = parser.parse_args()

    bundle_str = sys.stdin.read() if args.bundle_str == "-" else args.bundle_str
    bundle_str = bundle_str.rstrip("\n")
    if not bundle_str:
        print("ERROR: empty bundle string", file=sys.stderr)
        sys.exit(1)

    print(sign_bundle_v2(args.key, bundle_str))


if __name__ == "__main__":
    main()
