#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — Key Generation
=========================================================
YASHIGANI-INTERNAL ONLY — never commit the private key output.

Generates two ECDSA P-256 keypairs:
  1. Primary license-signing keypair  (replaces _PUBLIC_KEY_PEM in verifier.py)
  2. Counter-signing keypair          (replaces COUNTER_PUBLIC_KEY_PEM in _integrity.py)

Will migrate to ML-DSA-65 (FIPS 204) when cryptography library ships support.

MC-01 (Laura / 2026-06-15): Private key PEM files are encrypted at rest using
AES-256-CBC (BestAvailableEncryption) with a passphrase supplied out-of-band.
The passphrase must NEVER be written alongside the key file.

Passphrase source (in order of precedence):
  1. Env var YASHIGANI_KEY_PASSPHRASE   — primary env var (recommended for CI)
  2. Env var YASHIGANI_KEY_PASSPHRASE_FILE — path to a 0400 file containing the passphrase
  3. Interactive prompt (if stdin is a tty and neither env var is set)

Usage:
    YASHIGANI_KEY_PASSPHRASE="$(openssl rand -base64 32)" \\
        python scripts/keygen.py --out-dir keys/

Output:
    keys/yashigani_license_private.pem   — AES-256 encrypted PEM, KEEP SECRET, never commit
    keys/yashigani_license_public.pem    — embed in verifier.py (_PUBLIC_KEY_PEM)
    keys/yashigani_counter_private.pem   — AES-256 encrypted PEM, KEEP SECRET, never commit
    keys/yashigani_counter_public.pem    — embed in _integrity.py (COUNTER_PUBLIC_KEY_PEM)

Next steps after keygen:
  1. Embed yashigani_license_public.pem  → src/yashigani/licensing/verifier.py  (_PUBLIC_KEY_PEM)
  2. Embed yashigani_counter_public.pem  → src/yashigani/licensing/_integrity.py (COUNTER_PUBLIC_KEY_PEM)
  3. The VERIFIER_HASH in _integrity.py must be set by the build pipeline AFTER all
     source edits are finalised:
       sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1
  4. Add keys/ to .gitignore immediately.
  5. Store the passphrase in the HSM / password manager — SEPARATELY from the key file.

Requirements:
    cryptography>=42
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path


def _resolve_passphrase() -> bytes:
    """
    Resolve the key-encryption passphrase from env, file, or interactive prompt.

    Order of precedence:
      1. YASHIGANI_KEY_PASSPHRASE env var (raw string, stripped of trailing newline)
      2. YASHIGANI_KEY_PASSPHRASE_FILE env var (path to 0400 file)
      3. Interactive prompt (only when stdin is a tty)

    Exits with an error if no passphrase can be obtained.
    """
    passphrase_str = os.environ.get("YASHIGANI_KEY_PASSPHRASE")
    if passphrase_str is not None:
        passphrase_str = passphrase_str.rstrip("\n")
        if not passphrase_str:
            print(
                "ERROR: YASHIGANI_KEY_PASSPHRASE is set but empty — refusing to use an empty passphrase.",
                file=sys.stderr,
            )
            sys.exit(1)
        return passphrase_str.encode("utf-8")

    passphrase_file = os.environ.get("YASHIGANI_KEY_PASSPHRASE_FILE")
    if passphrase_file is not None:
        p = Path(passphrase_file)
        if not p.exists():
            print(f"ERROR: YASHIGANI_KEY_PASSPHRASE_FILE={passphrase_file!r} does not exist.", file=sys.stderr)
            sys.exit(1)
        # Ensure the passphrase file is not world- or group-readable (CWE-732).
        mode = p.stat().st_mode & 0o777
        if mode & 0o077:
            print(
                f"ERROR: passphrase file {passphrase_file!r} has mode {oct(mode)} — "
                "must not be group/world readable (CWE-732). Run: chmod 400 <file>",
                file=sys.stderr,
            )
            sys.exit(1)
        raw = p.read_bytes().rstrip(b"\n")
        if not raw:
            print(f"ERROR: passphrase file {passphrase_file!r} is empty.", file=sys.stderr)
            sys.exit(1)
        return raw

    if sys.stdin.isatty():
        try:
            passphrase_str = getpass.getpass("Enter key encryption passphrase: ")
            if not passphrase_str:
                print("ERROR: empty passphrase — refusing to continue.", file=sys.stderr)
                sys.exit(1)
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase_str != confirm:
                print("ERROR: passphrases do not match.", file=sys.stderr)
                sys.exit(1)
            return passphrase_str.encode("utf-8")
        except (EOFError, KeyboardInterrupt):
            print("\nERROR: passphrase entry cancelled.", file=sys.stderr)
            sys.exit(1)

    print(
        "ERROR: no passphrase available.\n"
        "  Set YASHIGANI_KEY_PASSPHRASE or YASHIGANI_KEY_PASSPHRASE_FILE,\n"
        "  or run interactively (stdin must be a tty).",
        file=sys.stderr,
    )
    sys.exit(1)


def _generate_keypair(
    out_dir: Path,
    name_prefix: str,
    force: bool,
    passphrase: bytes,
) -> tuple[Path, Path]:
    """
    Generate one ECDSA P-256 keypair and write PEM files.

    The private key PEM is encrypted with AES-256-CBC using ``passphrase``
    (BestAvailableEncryption — MC-01 fix). The public key PEM is unencrypted.

    Returns (private_key_path, public_key_path).
    Exits with error if files exist and --force not set.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key,
        SECP256R1,
    )
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        PublicFormat,
    )

    priv_path = out_dir / f"{name_prefix}_private.pem"
    pub_path = out_dir / f"{name_prefix}_public.pem"

    if priv_path.exists() and not force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    private_key = generate_private_key(SECP256R1())

    # MC-01: encrypt private key at rest — passphrase supplied out-of-band,
    # never written alongside the key file. BestAvailableEncryption selects
    # AES-256-CBC (the strongest serialization encryption the cryptography
    # library supports for PKCS8 PEM output).
    priv_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key with restricted permissions (0400 — owner read-only).
    # Use os.open for an atomic create-with-mode to avoid a race between
    # write and chmod (TOCTOU-hardened).
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    try:
        os.write(fd, priv_pem)
    finally:
        os.close(fd)

    pub_path.write_bytes(pub_pem)
    os.chmod(pub_path, 0o644)

    return priv_path, pub_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate Yashigani ECDSA P-256 license signing keypairs (primary + counter). "
            "Private keys are encrypted at rest (MC-01). "
            "Passphrase via YASHIGANI_KEY_PASSPHRASE env var, "
            "YASHIGANI_KEY_PASSPHRASE_FILE, or interactive prompt."
        )
    )
    parser.add_argument(
        "--out-dir",
        default="keys",
        help="Output directory for keypairs (default: keys/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys",
    )
    args = parser.parse_args()

    # Resolve passphrase before creating any files.
    passphrase = _resolve_passphrase()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Primary keypair ---
    primary_priv, primary_pub = _generate_keypair(
        out_dir, "yashigani_license", args.force, passphrase
    )
    primary_pub_pem = primary_pub.read_text(encoding="utf-8")

    # --- Counter-signing keypair ---
    counter_priv, counter_pub = _generate_keypair(
        out_dir, "yashigani_counter", args.force, passphrase
    )
    counter_pub_pem = counter_pub.read_text(encoding="utf-8")

    print("=" * 70)
    print("PRIMARY LICENSE KEYPAIR")
    print("=" * 70)
    print(f"  Private key : {primary_priv}  (AES-256 encrypted, chmod 400 — NEVER COMMIT)")
    print(f"  Public key  : {primary_pub}")
    print()
    print("Embed in src/yashigani/licensing/verifier.py:")
    print("  Replace _PUBLIC_KEY_PEM with:\n")
    print(primary_pub_pem)

    print("=" * 70)
    print("COUNTER-SIGNING KEYPAIR")
    print("=" * 70)
    print(f"  Private key : {counter_priv}  (AES-256 encrypted, chmod 400 — NEVER COMMIT)")
    print(f"  Public key  : {counter_pub}")
    print()
    print("Embed in src/yashigani/licensing/_integrity.py:")
    print("  Replace COUNTER_PUBLIC_KEY_PEM with:\n")
    print(counter_pub_pem)

    print("=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("1. Embed primary public key in verifier.py (_PUBLIC_KEY_PEM).")
    print("2. Embed counter public key in _integrity.py (COUNTER_PUBLIC_KEY_PEM).")
    print("3. After all source edits, compute VERIFIER_HASH:")
    print("     sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1")
    print("   Embed the result in _integrity.py (VERIFIER_HASH).")
    print("4. Add keys/ to .gitignore immediately.")
    print("5. Store the passphrase in the HSM / password manager — NOT alongside the key.")
    print()
    print("WARNING: Private keys are AES-256 encrypted at rest (MC-01).")
    print("  Consumers (sign_bundle.py, sign_license.py) must supply the passphrase")
    print("  via COUNTER_KEY_PASSPHRASE / PRIMARY_KEY_PASSPHRASE env vars.")
    print()
    print("WARNING: Add keys/ to .gitignore immediately.")


if __name__ == "__main__":
    main()
