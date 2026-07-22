#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""
Yashigani Model-Manifest Signing Key — Key Generation
======================================================
YASHIGANI SIGNING INFRA ONLY — never commit the private key output, never
run this against a real production keypair on a laptop or CI runner.

**Dedicated purpose key (Nico's provenance red-team, 2026-07-22, finding
#1 — CRITICAL):** this is a SEPARATE keypair from the licence-hardening
counter-signing key (`scripts/keygen.py` in the main `yashigani` repo,
`yashigani_license_*` / `yashigani_counter_*`). Model-manifest signing is a
different purpose with a different operational cadence (minted whenever a
new model/revision is vetted — plausibly weekly/daily, far more often than
a release cut) and a different set of hands (a model-catalog/curation
workflow, not release engineering). Reusing the licence counter-signing key
here would mean a model-signing-workflow compromise also forges licence
integrity attestations — the exact "correlated-failure class" the licence-
crypto-architecture's Tier-4 purpose-key design was built to eliminate
(`licence-crypto-architecture-20260615.md` §3, LCA-H-02). This script
generates ONLY the model-manifest purpose key; it must never be used to
(re)generate the licence-signing or counter-signing keypairs, and vice
versa.

**MC-01 lesson applied at generation time, not patched in later** (per
`key-management-threat-model-20260615.md` MC-01 / T1 / T19): the private
key PEM is written `BestAvailableEncryption`-protected under a passphrase
supplied via environment variable — never `NoEncryption()`. There is no
"skip the passphrase for convenience" flag; if the passphrase is missing,
too short, or generation is invoked with `--allow-test-key` unset while a
`.venv`/test marker is absent, this script refuses to write anything.

Algorithm: ECDSA P-256 (matches the licence-hardening precedent's pattern —
FIPS 186-5 approved, `cryptography` OpenSSL backend). Migration to
ML-DSA-65 (FIPS 204) tracked the same way as the licence key, when library
support ships.

Usage (TEST key, offline unit tests / local dev only):
    YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE='a-test-passphrase-16-chars-min' \\
        python scripts/keygen_manifest.py --out-dir keys/model-manifest --test-key --force

Usage (REAL production key — Yashigani signing infra ONLY, see the
"Real-key provisioning" section below before running this for real):
    YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE="$(read the real passphrase from the signing-infra secrets store)" \\
        python scripts/keygen_manifest.py --out-dir /secure/signing-machine/keys/model-manifest/

Output:
    <out-dir>/model_manifest_private.pem   — KEEP SECRET, encrypted PEM, chmod 600, never commit
    <out-dir>/model_manifest_public.pem    — embed in the engine build (catalog.py's
                                              MODEL_MANIFEST_PUBLIC_KEY_PEM constant), chmod 644

------------------------------------------------------------------------------
Real-key provisioning note (for Tiago / signing infra) — NOT executed by this
script, a procedural note for whoever mints the first real key:
------------------------------------------------------------------------------
  1. Custody: the private key lives ONLY on Yashigani signing infra (the
     same class of machine as the licence counter-signing key — see
     `key-management-threat-model-20260615.md` T8/T18), never on a
     developer laptop, never on customer/operator infrastructure, and
     never inside the running gateway or `infer` process (finding #9).
  2. Rotation cadence: model-manifest signing is expected to be invoked far
     more often than a release cut (weekly/daily curation, per finding #1)
     — but the KEY itself should still rotate on a fixed schedule (proposed:
     annual, or immediately on any suspected compromise of the
     signing/curation workflow) independent of how often it is USED to
     mint manifests. Rotation of this key must NEVER require rotating the
     licence-signing or counter-signing keys, and vice versa (purpose-key
     isolation is the whole point of Finding #1).
  3. Passphrase: generate and store the passphrase in the signing-infra
     secrets manager / HSM-adjacent vault, never alongside the encrypted
     PEM file itself, mirroring MC-01's remediation for the licence key.
  4. The public key (`model_manifest_public.pem`) is embedded at BUILD time
     into the shipped engine (a `MODEL_MANIFEST_PUBLIC_KEY_PEM`-shaped
     constant, same shape as `_integrity.py`'s `COUNTER_PUBLIC_KEY_PEM` in
     the licence engine) — never fetched at runtime, never configurable by
     an operator.
  5. `keys/` (or wherever `--out-dir` points) MUST be added to
     `.gitignore` immediately — this script does not do that for you.
  6. No override flag exists, and none should be added, for "sign without
     a valid encrypted key file" or "verify without checking the
     signature" (SOP: no dishonest-mode flags, per the red-team's finding
     #8 and the standing cross-product rule).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_MIN_PASSPHRASE_LENGTH = 16
_PASSPHRASE_ENV_VAR = "YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE"


class KeygenRefusedError(RuntimeError):
    """Raised when key generation is refused (missing/weak passphrase, existing
    file without --force, etc) — always a hard refusal, never a silent fallback."""


def _read_passphrase() -> bytes:
    passphrase = os.environ.get(_PASSPHRASE_ENV_VAR)
    if not passphrase:
        raise KeygenRefusedError(
            f"{_PASSPHRASE_ENV_VAR} is not set — refusing to generate a model-manifest signing key. "
            "There is no default passphrase and no unencrypted-key fallback (MC-01)."
        )
    if len(passphrase) < _MIN_PASSPHRASE_LENGTH:
        raise KeygenRefusedError(
            f"{_PASSPHRASE_ENV_VAR} is shorter than the required minimum of "
            f"{_MIN_PASSPHRASE_LENGTH} characters — refusing to generate a weakly-protected key."
        )
    return passphrase.encode("utf-8")


def generate_encrypted_keypair(passphrase: bytes) -> tuple[bytes, bytes]:
    """Generate one ECDSA P-256 keypair. Returns (encrypted_private_pem, public_pem).

    Pure function — no filesystem I/O — so unit tests can exercise key
    generation without touching disk or environment variables. The CLI
    entrypoint (`main`) is the only caller that reads `--out-dir`/env vars
    and writes files.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        PublicFormat,
    )

    private_key = generate_private_key(SECP256R1())
    priv_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _write_keypair(out_dir: Path, priv_pem: bytes, pub_pem: bytes, *, force: bool) -> tuple[Path, Path]:
    priv_path = out_dir / "model_manifest_private.pem"
    pub_path = out_dir / "model_manifest_public.pem"

    if priv_path.exists() and not force:
        raise KeygenRefusedError(f"{priv_path} already exists. Use --force to overwrite.")

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)  # CWE-732: never world/group readable
    pub_path.write_bytes(pub_pem)
    os.chmod(pub_path, 0o644)
    return priv_path, pub_path


def _self_check_round_trip(priv_pem: bytes, pub_pem: bytes, passphrase: bytes) -> None:
    """Defensive integrity check (mirrors the licence-hardening precedent's
    self-verify-before-emit pattern, `sign_bundle.py`'s C6 control): reload
    the just-written PEM with the passphrase and confirm the public key
    matches, before telling the operator generation succeeded."""
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

    reloaded_private = load_pem_private_key(priv_pem, password=passphrase)
    reloaded_public = load_pem_public_key(pub_pem)
    if not isinstance(reloaded_private, EllipticCurvePrivateKey):
        raise KeygenRefusedError(
            f"self-check failed: expected an EC private key, got {type(reloaded_private).__name__}"
        )
    if not isinstance(reloaded_public, EllipticCurvePublicKey):
        raise KeygenRefusedError(f"self-check failed: expected an EC public key, got {type(reloaded_public).__name__}")
    reloaded_public_numbers = reloaded_private.public_key().public_numbers()
    expected_public_numbers = reloaded_public.public_numbers()
    if reloaded_public_numbers != expected_public_numbers:
        raise KeygenRefusedError(
            "self-check failed: the generated public key does not match the private key's own "
            "derived public key — refusing to trust this keypair"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the dedicated Yashigani model-manifest signing keypair "
            "(ECDSA P-256, encrypted-at-rest) — a SEPARATE purpose key from the "
            "licence-hardening counter-signing key."
        )
    )
    parser.add_argument("--out-dir", default="keys/model-manifest", help="Output directory for the keypair")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing keypair")
    parser.add_argument(
        "--test-key",
        action="store_true",
        help=(
            "Acknowledge this is a TEST key (offline unit tests / local dev), not a production "
            "signing key. Purely a labelling/acknowledgement flag for the operator's own audit "
            "trail — it changes no cryptographic behaviour and grants no override."
        ),
    )
    args = parser.parse_args(argv)

    try:
        passphrase = _read_passphrase()
        priv_pem, pub_pem = generate_encrypted_keypair(passphrase)
        _self_check_round_trip(priv_pem, pub_pem, passphrase)
        priv_path, pub_path = _write_keypair(Path(args.out_dir), priv_pem, pub_pem, force=args.force)
    except KeygenRefusedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    label = "TEST KEY (offline / dev only)" if args.test_key else "KEYPAIR"
    print("=" * 70)
    print(f"MODEL-MANIFEST SIGNING {label}")
    print("=" * 70)
    print(f"  Private key : {priv_path}  (chmod 600, passphrase-encrypted — NEVER COMMIT)")
    print(f"  Public key  : {pub_path}")
    print()
    print("Next steps:")
    print("  1. Embed the public key PEM into the engine build as MODEL_MANIFEST_PUBLIC_KEY_PEM.")
    print("  2. Add the out-dir to .gitignore immediately.")
    print("  3. Production keys: signing infra custody only — see the module docstring's")
    print("     'Real-key provisioning note' before minting a real (non-test) key.")
    if not args.test_key:
        print()
        print(
            "WARNING: --test-key was not passed. If this is a real production key, confirm it was "
            "generated ON Yashigani signing infra, not on a developer laptop or CI runner."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
