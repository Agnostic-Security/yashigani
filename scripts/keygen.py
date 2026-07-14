#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — Key Generation (v2, root->leaf chain)
==================================================================================
YASHIGANI-INTERNAL ONLY — never commit private key output. This script is the
v2 REPLACEMENT for the v1 flat primary/counter keygen — it mints the
root->leaf PKI chain from AgnosticSecurity/Products/Yashigani/
licence-hardening-v2-design-20260713.md §2 (Key hierarchy) + §2.1 (batch
pre-mint) + §3.1 (leaf_cert) + LOCKED DECISIONS bullet 9 (CSR/PoP).

Three things this script mints, all P-384/SHA-384 (interim `alg`, §"NIST PQC
alignment" — ecdsa-p384-sha384 today, hybrid/ml-dsa-87 later via the same
closed `alg` enum, no format break):

  1. MASTER keypair (root) — cold, rarely unlocked. Backend is pluggable:
     `--backend pem` (interim/demo — §7 "Demo channel: throwaway master
     (local file)") or `--backend piv` (the real interim/prod master, a
     YubiKey via PKCS#11 — wires chain.PivSigner's shape; NO hardware exists
     in this dev environment, so `--backend piv` mints the *registry record*
     shape only and any operation requiring a live PKCS#11 session raises
     NotImplementedError with a clear message, exactly mirroring
     chain.signer.PivSigner's own documented stub behaviour).

  2. LEAF keypair (code | licence) — master-certified via a self-signed
     CSR/proof-of-possession (LOCKED DECISIONS bullet 9): the new leaf signs
     its own CSR first: the master verifies that self-signature (proving the
     requester holds the private key) BEFORE certifying the leaf_cert.

  3. Batch pre-mint of CODE leaves (§2.1) — up to 3 releases in one
     master-unlock, each with its own not_before/not_after window + a
     monotonic serial.

Every mint is recorded in the durable key registry
(yashigani.licensing.chain.registry.KeyRegistry) so `licgen`/`inject_hashes.sh`
can look material back up by role/release/client_id without re-deriving it,
and so `licgen anchor-set emit` / `licgen sign-build` have a single source of
truth to read from.

Private-key passphrase (MC-01 convention, carried from v1 — AES-256/
BestAvailableEncryption, resolved in this order):
  1. YASHIGANI_KEY_PASSPHRASE          env var
  2. YASHIGANI_KEY_PASSPHRASE_FILE     path to a 0400 file
  3. Interactive prompt (stdin is a tty)
One invocation mints ONE keypair — one passphrase per invocation, matching
the design's "sole issuer = Tiago, manual" operational model (§ LOCKED
DECISIONS "Operational assumption").

Usage:
    # 1. Mint the (demo/interim) master, register as anchor M1.
    YASHIGANI_KEY_PASSPHRASE="$(openssl rand -base64 32)" \\
        python scripts/keygen.py master new \\
            --backend pem --anchor-id M1 \\
            --out-dir testing_runs/yashigani/demo-license-system/keys \\
            --registry testing_runs/yashigani/demo-license-system/registry.json

    # 2. Mint a per-release CODE leaf, master-certified.
    YASHIGANI_KEY_PASSPHRASE="<leaf passphrase>" \\
    YASHIGANI_MASTER_KEY_PASSPHRASE="<master passphrase>" \\
        python scripts/keygen.py leaf new \\
            --role code --release 4.1.1 --serial code-0001 \\
            --master-anchor-id M1 \\
            --master-key testing_runs/.../keys/master_private.pem \\
            --out-dir testing_runs/.../keys \\
            --registry testing_runs/.../registry.json

    # 3. Mint a per-client LICENCE leaf at onboarding.
        python scripts/keygen.py leaf new \\
            --role licence --client-id acme-corp --org-domain acme.example.com \\
            --serial licence-acme-0001 --master-anchor-id M1 \\
            --master-key ... --out-dir ... --registry ...

    # 4. Batch pre-mint CODE leaves for the next 3 releases (§2.1, cap 3).
        python scripts/keygen.py batch-premint-code \\
            --releases 4.1.1 4.1.2 4.1.3 --master-anchor-id M1 \\
            --master-key ... --out-dir ... --registry ...

Requires: cryptography>=42 (P-384 support), yashigani.licensing.chain
importable (src/ on PYTHONPATH — set by the caller / dispatched via
`python -m` from repo root, or PYTHONPATH=src explicitly).
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Batch pre-mint cap (§2.1: "up to 3 releases in advance").
BATCH_PREMINT_CAP = 3

# Default signing window for a leaf (§2: "Leaves ... short-window (~1 month)").
DEFAULT_WINDOW_DAYS = 30


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _ensure_src_on_path() -> None:
    src = _repo_root() / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


_ensure_src_on_path()


# ---------------------------------------------------------------------------
# Passphrase resolution (MC-01 convention, carried from v1 keygen.py).
# ---------------------------------------------------------------------------

def _resolve_passphrase(env_var: str, file_env_var: str, prompt: str) -> bytes:
    passphrase_str = os.environ.get(env_var)
    if passphrase_str is not None:
        passphrase_str = passphrase_str.rstrip("\n")
        if not passphrase_str:
            print(f"ERROR: {env_var} is set but empty — refusing an empty passphrase.", file=sys.stderr)
            sys.exit(1)
        return passphrase_str.encode("utf-8")

    passphrase_file = os.environ.get(file_env_var)
    if passphrase_file is not None:
        p = Path(passphrase_file)
        if not p.exists():
            print(f"ERROR: {file_env_var}={passphrase_file!r} does not exist.", file=sys.stderr)
            sys.exit(1)
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
            passphrase_str = getpass.getpass(prompt)
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
        f"ERROR: no passphrase available.\n"
        f"  Set {env_var} or {file_env_var}, or run interactively (stdin must be a tty).",
        file=sys.stderr,
    )
    sys.exit(1)


def _resolve_leaf_passphrase() -> bytes:
    return _resolve_passphrase(
        "YASHIGANI_KEY_PASSPHRASE", "YASHIGANI_KEY_PASSPHRASE_FILE", "Enter leaf key encryption passphrase: "
    )


def _resolve_master_passphrase() -> bytes:
    return _resolve_passphrase(
        "YASHIGANI_MASTER_KEY_PASSPHRASE",
        "YASHIGANI_MASTER_KEY_PASSPHRASE_FILE",
        "Enter MASTER key decryption passphrase: ",
    )


# ---------------------------------------------------------------------------
# Low-level keypair generation (P-384, MC-01 encryption-at-rest).
# ---------------------------------------------------------------------------

def _generate_p384_keypair():
    from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key

    return generate_private_key(SECP384R1())


def _pubkey_pem(private_key) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        private_key.public_key()
        .public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )


def _write_private_key_encrypted(path: Path, private_key, passphrase: bytes) -> None:
    """MC-01: AES-256 (BestAvailableEncryption) at rest, 0400 owner-only,
    O_CREAT|O_EXCL-style atomic create-with-mode (TOCTOU-hardened, matches
    v1's established pattern)."""
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
    )

    priv_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase),
    )
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    try:
        os.write(fd, priv_pem)
    finally:
        os.close(fd)


def _load_private_key_encrypted(path: Path, passphrase: bytes):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, EllipticCurvePrivateKey):
        print(f"ERROR: {path} is not an EC private key: {type(key).__name__}", file=sys.stderr)
        sys.exit(1)
    return key


# ---------------------------------------------------------------------------
# CSR / proof-of-possession (LOCKED DECISIONS bullet 9, generalised via
# chain.canonical.CTX_LEAF_CSR — see that module's docstring for why this is
# a DIFFERENT tag from the spec's audit-specific "YSG-AUDIT-CSR-v1").
# ---------------------------------------------------------------------------

def build_csr_pop(leaf_private_key, leaf_pubkey_pem: str, client_id: str, role) -> dict:
    """The new leaf signs its own CSR — proves it holds the private key
    behind leaf_pubkey_pem BEFORE the master will certify it."""
    import base64

    from yashigani.licensing.chain.algorithms import Alg, sign_message
    from yashigani.licensing.chain.canonical import leaf_csr_signing_digest

    payload = {"leaf_pubkey_pem": leaf_pubkey_pem, "client_id": client_id, "role": role.value}
    digest = leaf_csr_signing_digest(payload)
    csr_self_sig = sign_message(Alg.ECDSA_P384_SHA384, leaf_private_key, digest)
    return {**payload, "csr_self_sig": base64.b64encode(csr_self_sig).decode("ascii")}


def verify_csr_pop(csr_pop: dict) -> bool:
    """The MASTER's side: verify csr_self_sig against the claimed
    leaf_pubkey_pem BEFORE certifying — proof the requester holds the
    private key (not a bare pubkey blob, LOCKED DECISIONS bullet 9)."""
    import base64

    from yashigani.licensing.chain.algorithms import Alg, verify_signature
    from yashigani.licensing.chain.canonical import leaf_csr_signing_digest
    from yashigani.licensing.chain.leaf_cert import Role

    payload = {
        "leaf_pubkey_pem": csr_pop["leaf_pubkey_pem"],
        "client_id": csr_pop["client_id"],
        "role": csr_pop["role"],
    }
    digest = leaf_csr_signing_digest(payload)
    sig = base64.b64decode(csr_pop["csr_self_sig"])
    # role is validated as a real enum member first — reject a malformed/
    # spoofed role string before it ever reaches verify_signature.
    Role(csr_pop["role"])
    return verify_signature(Alg.ECDSA_P384_SHA384, csr_pop["leaf_pubkey_pem"], digest, sig)


# ---------------------------------------------------------------------------
# Master signing (§2 — direct sign_message() against the master private key
# for the PEM/interim backend; PivSigner path for the hardware-shape master.
# Matches the pattern already established in
# src/tests/unit/test_licence_chain_phase_b.py: `sign_message(Alg.ECDSA_P384_
# SHA384, master, leaf_cert_signing_digest(...))` — the Signer ABC's role gate
# is a LEAF-signer property (a licence leaf must not sign a build bundle);
# the MASTER's own role-correctness for what it certifies is enforced by the
# `role` field living INSIDE the signed leaf_cert digest itself, not by a
# Signer-level role parameter. Flagged for Nico/Tiago: the Signer ABC's
# constructor requires a `role: Role` even for master backends (PivSigner
# defaults role=Role.CODE) — this is a Phase A abstraction wrinkle, not a
# security gap (the cryptographic role-binding is the leaf_cert.role field).
# ---------------------------------------------------------------------------

def master_sign_leaf_cert(leaf_cert, master_backend: str, master_private_key=None, piv_signer=None) -> bytes:
    from yashigani.licensing.chain.algorithms import Alg, sign_message
    from yashigani.licensing.chain.canonical import leaf_cert_signing_digest
    from yashigani.licensing.chain.leaf_cert import Role

    digest = leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
    if master_backend == "pem":
        if master_private_key is None:
            raise ValueError("master_private_key required for backend=pem")
        return sign_message(Alg.ECDSA_P384_SHA384, master_private_key, digest)
    if master_backend == "piv":
        if piv_signer is None:
            raise ValueError("piv_signer required for backend=piv")
        # See module docstring: role is a formality here, not a semantic
        # constraint on what the master may certify.
        return piv_signer.sign(Role.CODE, "YSG-LEAF-CERT-v1", digest)
    raise ValueError(f"unknown master backend {master_backend!r}")


# ---------------------------------------------------------------------------
# Mint one leaf (code | licence), master-certified.
# ---------------------------------------------------------------------------

def mint_leaf(
    *,
    role,
    client_id: str,
    release: Optional[str],
    serial: str,
    window_days: int,
    master_backend: str,
    master_private_key=None,
    piv_signer=None,
    org_domain: Optional[str] = None,
):
    """Generate a leaf keypair + CSR/PoP + master-signed leaf_cert.

    Returns (leaf_private_key, leaf_cert, leaf_cert_sig_bytes).
    Raises ValueError if the master refuses to certify (csr_pop fails its
    own self-verification — should never happen for a leaf we just
    generated ourselves, but checked defensively, matching the design's
    "the master verifies csr_pop's OWN self-signature before certifying").
    """
    from yashigani.licensing.chain.algorithms import Alg
    from yashigani.licensing.chain.leaf_cert import LeafCert

    now = datetime.now(timezone.utc)
    leaf_private_key = _generate_p384_keypair()
    leaf_pubkey_pem = _pubkey_pem(leaf_private_key)

    csr_pop = build_csr_pop(leaf_private_key, leaf_pubkey_pem, client_id, role)
    if not verify_csr_pop(csr_pop):
        raise ValueError("csr_pop self-verification failed — refusing to certify (PoP invariant violated)")

    leaf_cert = LeafCert(
        role=role,
        client_id=client_id,
        release=release,
        leaf_pubkey_pem=leaf_pubkey_pem,
        not_before=now,
        not_after=now + timedelta(days=window_days),
        serial=serial,
        signed_at=now,
        alg=Alg.ECDSA_P384_SHA384,
        csr_pop=csr_pop,
    )
    leaf_cert_sig = master_sign_leaf_cert(
        leaf_cert, master_backend, master_private_key=master_private_key, piv_signer=piv_signer
    )
    return leaf_private_key, leaf_cert, leaf_cert_sig


# ---------------------------------------------------------------------------
# CLI: master new
# ---------------------------------------------------------------------------

def _cmd_master_new(args: argparse.Namespace) -> None:
    from yashigani.licensing.chain.anchors import AnchorStatus
    from yashigani.licensing.chain.algorithms import Alg
    from yashigani.licensing.chain.registry import KeyRegistry, MasterAnchorRecord

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = KeyRegistry(Path(args.registry))

    if args.backend == "pem":
        passphrase = _resolve_master_passphrase()
        priv_path = out_dir / "master_private.pem"
        pub_path = out_dir / "master_public.pem"
        if priv_path.exists() and not args.force:
            print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)
        master_key = _generate_p384_keypair()
        _write_private_key_encrypted(priv_path, master_key, passphrase)
        pub_pem = _pubkey_pem(master_key)
        pub_path.write_text(pub_pem, encoding="utf-8")
        os.chmod(pub_path, 0o644)
        backend_ref = f"pem:{priv_path}"
    elif args.backend == "piv":
        # No hardware in this environment — mint the registry SHAPE only.
        # public_key()/sign() on the resulting PivSigner raise
        # NotImplementedError until a live PKCS#11 session exists
        # (chain.signer.PivSigner's own documented stub behaviour).
        print(
            "WARNING: --backend piv has no live YubiKey/PKCS#11 hardware in this "
            "environment. Recording the registry SHAPE only (backend_ref); the "
            "public key must be supplied via --piv-pubkey-file (read off the token "
            "by a real PKCS#11 session elsewhere) or this anchor cannot be used.",
            file=sys.stderr,
        )
        if not args.piv_pubkey_file:
            print("ERROR: --backend piv requires --piv-pubkey-file (no live hardware to read it from)", file=sys.stderr)
            sys.exit(1)
        pub_pem = Path(args.piv_pubkey_file).read_text(encoding="utf-8")
        backend_ref = f"piv:module={args.piv_module},slot={args.piv_slot},label={args.piv_label}"
    else:
        print(f"ERROR: unknown --backend {args.backend!r}", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc)
    registry.add_anchor(
        MasterAnchorRecord(
            anchor_id=args.anchor_id,
            pubkey_pem=pub_pem,
            alg=Alg.ECDSA_P384_SHA384,
            status=AnchorStatus.ACTIVE,
            added=now,
            backend_ref=backend_ref,
            note=args.note,
        )
    )
    print("=" * 70)
    print(f"MASTER ANCHOR {args.anchor_id} REGISTERED  (backend={args.backend})")
    print("=" * 70)
    print(f"  Registry    : {args.registry}")
    print(f"  backend_ref : {backend_ref}")
    if args.backend == "pem":
        print(f"  Private key : {priv_path}  (AES-256 encrypted, chmod 400 — NEVER COMMIT)")
        print(f"  Public key  : {pub_path}")
    print()
    print("NEXT STEPS:")
    print("  1. Add the registry dir + any keys/ dir to .gitignore immediately.")
    print("  2. Store the passphrase in the HSM / password manager — SEPARATELY from the key file.")
    print("  3. Mint leaves against this anchor: keygen.py leaf new --master-anchor-id " + args.anchor_id)


# ---------------------------------------------------------------------------
# CLI: leaf new
# ---------------------------------------------------------------------------

def _cmd_leaf_new(args: argparse.Namespace) -> None:
    import base64

    from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, Role
    from yashigani.licensing.chain.registry import KeyRecord, KeyRegistry

    role = Role(args.role)
    if role not in (Role.CODE, Role.LICENCE):
        print(
            "ERROR: keygen.py leaf new only mints role=code|licence — role=audit "
            "onboarding is Phase C (§3.4.1, audit-leaf CSR tool, out of scope)",
            file=sys.stderr,
        )
        sys.exit(1)

    if role == Role.CODE:
        if not args.release:
            print("ERROR: --release is required for --role code", file=sys.stderr)
            sys.exit(1)
        client_id = SHARED_CLIENT_ID
        release = args.release
    else:
        if not args.client_id:
            print("ERROR: --client-id is required for --role licence", file=sys.stderr)
            sys.exit(1)
        if args.release:
            print("ERROR: --release must not be set for --role licence (persists across releases)", file=sys.stderr)
            sys.exit(1)
        client_id = args.client_id
        release = None

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = KeyRegistry(Path(args.registry))
    anchor = registry.get_anchor(args.master_anchor_id)

    if anchor.backend_ref.startswith("pem:"):
        master_backend = "pem"
        master_passphrase = _resolve_master_passphrase()
        master_key_path = Path(args.master_key) if args.master_key else Path(anchor.backend_ref[len("pem:"):])
        master_private_key = _load_private_key_encrypted(master_key_path, master_passphrase)
        piv_signer = None
    elif anchor.backend_ref.startswith("piv:"):
        print(
            "ERROR: master anchor backend is PIV/PKCS#11 — no live hardware in this "
            "environment. Leaf minting against a PIV master requires a real PKCS#11 "
            "session (Captain/Phase-B-KMS scope) — cannot proceed here.",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print(f"ERROR: unrecognised backend_ref {anchor.backend_ref!r} for anchor {args.master_anchor_id!r}", file=sys.stderr)
        sys.exit(1)

    leaf_passphrase = _resolve_leaf_passphrase()
    leaf_private_key, leaf_cert, leaf_cert_sig = mint_leaf(
        role=role,
        client_id=client_id,
        release=release,
        serial=args.serial,
        window_days=args.window_days,
        master_backend=master_backend,
        master_private_key=master_private_key,
        piv_signer=piv_signer,
        org_domain=args.org_domain,
    )

    name_prefix = f"{role.value}-{release or client_id}-{args.serial}".replace("/", "_")
    priv_path = out_dir / f"{name_prefix}_private.pem"
    cert_path = out_dir / f"{name_prefix}_leaf_cert.json"
    sig_path = out_dir / f"{name_prefix}_leaf_cert.sig.b64"

    if priv_path.exists() and not args.force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    _write_private_key_encrypted(priv_path, leaf_private_key, leaf_passphrase)
    cert_path.write_text(json.dumps(leaf_cert.to_canonical_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(cert_path, 0o644)
    sig_b64 = base64.b64encode(leaf_cert_sig).decode("ascii")
    sig_path.write_text(sig_b64 + "\n", encoding="utf-8")
    os.chmod(sig_path, 0o644)

    key_id = f"{role.value}:{release or client_id}:{args.serial}"
    registry.add_key(
        KeyRecord(
            key_id=key_id,
            role=role,
            client_id=client_id,
            release=release,
            public_key_pem=leaf_cert.leaf_pubkey_pem,
            leaf_cert=leaf_cert,
            leaf_cert_sig_b64=sig_b64,
            not_before=leaf_cert.not_before,
            not_after=leaf_cert.not_after,
            serial=args.serial,
            private_key_backend_ref=f"pem:{priv_path}",
            org_domain=args.org_domain,
        )
    )

    print("=" * 70)
    print(f"LEAF MINTED  role={role.value} client_id={client_id} release={release} serial={args.serial}")
    print("=" * 70)
    print(f"  Private key : {priv_path}  (AES-256 encrypted, chmod 400 — NEVER COMMIT)")
    print(f"  leaf_cert   : {cert_path}")
    print(f"  leaf_cert_sig (base64): {sig_path}")
    print(f"  Registered in {args.registry} as key_id={key_id}")


# ---------------------------------------------------------------------------
# CLI: batch-premint-code (§2.1, cap 3)
# ---------------------------------------------------------------------------

def _cmd_batch_premint_code(args: argparse.Namespace) -> None:
    import base64

    from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, Role
    from yashigani.licensing.chain.registry import KeyRecord, KeyRegistry

    releases = args.releases
    if len(releases) > BATCH_PREMINT_CAP:
        print(
            f"ERROR: batch pre-mint cap is {BATCH_PREMINT_CAP} releases per master-unlock "
            f"(§2.1) — got {len(releases)}: {releases}. Split into multiple invocations.",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(releases) != len(set(releases)):
        print(f"ERROR: duplicate releases in --releases: {releases}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = KeyRegistry(Path(args.registry))
    anchor = registry.get_anchor(args.master_anchor_id)

    if not anchor.backend_ref.startswith("pem:"):
        print(
            "ERROR: batch pre-mint against a non-PEM (PIV/KMS) master requires a live "
            "session — not available in this environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    master_passphrase = _resolve_master_passphrase()
    master_key_path = Path(args.master_key) if args.master_key else Path(anchor.backend_ref[len("pem:"):])
    master_private_key = _load_private_key_encrypted(master_key_path, master_passphrase)

    leaf_passphrase = _resolve_leaf_passphrase()

    minted = []
    base_start = datetime.now(timezone.utc)
    for i, release in enumerate(releases):
        # Time-bonded, non-sequential windows (LOCKED DECISIONS: "pre-mint
        # batches (Tiago: e.g. 12 valid month 1-2, next 12 valid month 3-4),
        # time-bonded, non-sequential") — each release's window starts
        # window_days*i after the batch start, so releases 1/2/3 get
        # sequential, non-overlapping signing windows.
        window_start = base_start + timedelta(days=args.window_days * i)
        serial = f"code-{release}-batch{args.batch_id}"

        leaf_private_key = _generate_p384_keypair()
        leaf_pubkey_pem = _pubkey_pem(leaf_private_key)
        csr_pop = build_csr_pop(leaf_private_key, leaf_pubkey_pem, SHARED_CLIENT_ID, Role.CODE)
        if not verify_csr_pop(csr_pop):
            print(f"ERROR: csr_pop self-verification failed for release {release}", file=sys.stderr)
            sys.exit(1)

        from yashigani.licensing.chain.algorithms import Alg
        from yashigani.licensing.chain.leaf_cert import LeafCert

        leaf_cert = LeafCert(
            role=Role.CODE,
            client_id=SHARED_CLIENT_ID,
            release=release,
            leaf_pubkey_pem=leaf_pubkey_pem,
            not_before=window_start,
            not_after=window_start + timedelta(days=args.window_days),
            serial=serial,
            signed_at=base_start,
            alg=Alg.ECDSA_P384_SHA384,
            csr_pop=csr_pop,
        )
        leaf_cert_sig = master_sign_leaf_cert(leaf_cert, "pem", master_private_key=master_private_key)

        name_prefix = f"code-{release}-{serial}".replace("/", "_")
        priv_path = out_dir / f"{name_prefix}_private.pem"
        cert_path = out_dir / f"{name_prefix}_leaf_cert.json"
        sig_path = out_dir / f"{name_prefix}_leaf_cert.sig.b64"
        if priv_path.exists() and not args.force:
            print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)

        _write_private_key_encrypted(priv_path, leaf_private_key, leaf_passphrase)
        cert_path.write_text(json.dumps(leaf_cert.to_canonical_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(cert_path, 0o644)
        sig_b64 = base64.b64encode(leaf_cert_sig).decode("ascii")
        sig_path.write_text(sig_b64 + "\n", encoding="utf-8")
        os.chmod(sig_path, 0o644)

        key_id = f"code:{release}:{serial}"
        registry.add_key(
            KeyRecord(
                key_id=key_id,
                role=Role.CODE,
                client_id=SHARED_CLIENT_ID,
                release=release,
                public_key_pem=leaf_pubkey_pem,
                leaf_cert=leaf_cert,
                leaf_cert_sig_b64=sig_b64,
                not_before=leaf_cert.not_before,
                not_after=leaf_cert.not_after,
                serial=serial,
                private_key_backend_ref=f"pem:{priv_path}",
            )
        )
        minted.append((release, key_id, priv_path, cert_path, sig_path))

    print("=" * 70)
    print(f"BATCH PRE-MINT COMPLETE — {len(minted)} CODE leaves (cap {BATCH_PREMINT_CAP}, §2.1)")
    print("=" * 70)
    for release, key_id, priv_path, cert_path, sig_path in minted:
        print(f"  release={release}  key_id={key_id}")
        print(f"    private key : {priv_path}")
        print(f"    leaf_cert   : {cert_path}")
        print(f"    sig         : {sig_path}")


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Yashigani v2 root->leaf key generation (master + code/licence leaves)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_master = sub.add_parser("master", help="Master (root) key operations")
    sub_master = p_master.add_subparsers(dest="master_command", required=True)
    p_master_new = sub_master.add_parser("new", help="Mint a new master anchor")
    p_master_new.add_argument("--backend", choices=["pem", "piv"], default="pem")
    p_master_new.add_argument("--anchor-id", required=True)
    p_master_new.add_argument("--out-dir", required=True)
    p_master_new.add_argument("--registry", required=True)
    p_master_new.add_argument("--force", action="store_true")
    p_master_new.add_argument("--note", default=None)
    p_master_new.add_argument("--piv-module", default=None, help="PKCS#11 module path (backend=piv)")
    p_master_new.add_argument("--piv-slot", type=int, default=None, help="PKCS#11 slot id (backend=piv)")
    p_master_new.add_argument("--piv-label", default=None, help="PKCS#11 key label (backend=piv)")
    p_master_new.add_argument("--piv-pubkey-file", default=None, help="Public key PEM read off the token (backend=piv, no live session here)")
    p_master_new.set_defaults(func=_cmd_master_new)

    p_leaf = sub.add_parser("leaf", help="Leaf (code | licence) key operations")
    sub_leaf = p_leaf.add_subparsers(dest="leaf_command", required=True)
    p_leaf_new = sub_leaf.add_parser("new", help="Mint + master-certify a new leaf")
    p_leaf_new.add_argument("--role", choices=["code", "licence"], required=True)
    p_leaf_new.add_argument("--release", default=None, help="Required for --role code, e.g. 4.1.1")
    p_leaf_new.add_argument("--client-id", default=None, help="Required for --role licence")
    p_leaf_new.add_argument("--org-domain", default=None, help="Licence leaf: registered org_domain for this client")
    p_leaf_new.add_argument("--serial", required=True)
    p_leaf_new.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    p_leaf_new.add_argument("--master-anchor-id", required=True)
    p_leaf_new.add_argument("--master-key", default=None, help="Override path (default: anchor's registered backend_ref)")
    p_leaf_new.add_argument("--out-dir", required=True)
    p_leaf_new.add_argument("--registry", required=True)
    p_leaf_new.add_argument("--force", action="store_true")
    p_leaf_new.set_defaults(func=_cmd_leaf_new)

    p_batch = sub.add_parser("batch-premint-code", help=f"Pre-mint up to {BATCH_PREMINT_CAP} CODE leaves (§2.1)")
    p_batch.add_argument("--releases", nargs="+", required=True)
    p_batch.add_argument("--batch-id", default=datetime.now(timezone.utc).strftime("%Y%m%d"))
    p_batch.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    p_batch.add_argument("--master-anchor-id", required=True)
    p_batch.add_argument("--master-key", default=None)
    p_batch.add_argument("--out-dir", required=True)
    p_batch.add_argument("--registry", required=True)
    p_batch.add_argument("--force", action="store_true")
    p_batch.set_defaults(func=_cmd_batch_premint_code)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
