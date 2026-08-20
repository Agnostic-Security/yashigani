#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""
Yashigani Model-Manifest Signing Tool — MINT SIDE
==================================================
YASHIGANI SIGNING INFRA ONLY. This module holds the private-key half of the
model-manifest signature scheme (`catalog.SignedCatalogEntry`,
`convert_provenance.ConvertedManifestEntry`). It must never be imported by
`src/kuroshio/` runtime/serving code (`app.py`, `supervisor/`,
`shim/`) — the engine ships only the PUBLIC key (see
`keygen_manifest.py`'s "Real-key provisioning note" and Nico's provenance
red-team finding #9). Living in `scripts/`, not `src/kuroshio/`,
mirrors the licence-hardening precedent's own separation
(`scripts/sign_bundle.py` mint-side vs `src/yashigani/licensing/verifier.py`
verify-side) — physically keeping signing capability out of every
installed wheel, not just out of the running import path.

Both signer classes below **self-verify before returning** (the licence-
hardening precedent's C6 control, `sign_bundle.py:110-119`): a signer never
hands back a `SignedCatalogEntry`/`ConvertedManifestEntry` whose signature
does not independently verify against its own public key.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kuroshio.catalog import CatalogVerifier, SignedCatalogEntry
from kuroshio.convert_provenance import (
    ConversionMeasurement,
    ConvertedManifestEntry,
    ConvertedManifestVerifier,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_signing_key(pem_bytes: bytes, passphrase: bytes | None) -> ec.EllipticCurvePrivateKey:
    """Load a PEM-encoded ECDSA private key (encrypted, per keygen_manifest.py).

    Refuses (raises) anything that is not an EC private key — a caller who
    accidentally points this at an RSA key or a public key gets a clear
    error, not a confusing downstream signature failure.
    """
    key = load_pem_private_key(pem_bytes, password=passphrase)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"expected an EC private key for model-manifest signing, got {type(key).__name__}")
    return key


class ManifestSigner:
    """Mint-side signer for `catalog.SignedCatalogEntry` (network-pull admission manifests)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        self._verifier = CatalogVerifier(private_key.public_key())

    def mint(
        self,
        *,
        repo_id: str,
        revision: str,
        filename: str,
        quant: str,
        sha256: str,
        lfs_object_id: str,
        provenance_tier: str,
        signer_key_id: str,
        max_trust_age_seconds: int,
        issued_at: str | None = None,
    ) -> SignedCatalogEntry:
        """Sign a new admission manifest entry.

        `sha256` and `lfs_object_id` must be the values Yashigani's OWN
        ingestion measured from the actual bytes at mint time (Nico finding
        #3) — this method does not fetch or re-derive either value itself;
        it signs whatever the caller (the ingestion/curation pipeline)
        asserts. Getting that measurement right is the ingestion
        pipeline's job, not this signer's — this class's only
        responsibility is: sign the given tuple as one unit, and never
        hand back a signature that doesn't verify against its own key.
        """
        resolved_issued_at = issued_at or _utc_now_iso()
        unsigned = SignedCatalogEntry(
            repo_id=repo_id,
            revision=revision,
            filename=filename,
            quant=quant,
            sha256=sha256,
            lfs_object_id=lfs_object_id,
            provenance_tier=provenance_tier,
            issued_at=resolved_issued_at,
            max_trust_age_seconds=max_trust_age_seconds,
            signer_key_id=signer_key_id,
            signature=b"",
        )
        signature = self._private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
        entry = SignedCatalogEntry(
            repo_id=repo_id,
            revision=revision,
            filename=filename,
            quant=quant,
            sha256=sha256,
            lfs_object_id=lfs_object_id,
            provenance_tier=provenance_tier,
            issued_at=resolved_issued_at,
            max_trust_age_seconds=max_trust_age_seconds,
            signer_key_id=signer_key_id,
            signature=signature,
        )
        self._verifier.verify(entry)  # self-verify before emit (C6 pattern) — never hand back a bad signature
        return entry


class ConvertedManifestSigner:
    """Mint-side signer for `convert_provenance.ConvertedManifestEntry`
    (converted-GGUF provenance manifests)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        self._verifier = ConvertedManifestVerifier(private_key.public_key())

    def mint(
        self,
        measurement: ConversionMeasurement,
        *,
        provenance_tier: str,
        signer_key_id: str,
        max_trust_age_seconds: int,
        issued_at: str | None = None,
    ) -> ConvertedManifestEntry:
        """Sign a `ConversionMeasurement` (produced by
        `convert_provenance.measure_conversion_tuple`, which measured both
        digests from actual bytes inside the ephemeral convert job) as one
        unit. This method never measures anything itself — it only signs
        what it is handed, so the measurement step (the part the red-team
        finding #4 cares about) stays owned by the convert pipeline, not by
        this signing tool.
        """
        resolved_issued_at = issued_at or _utc_now_iso()
        unsigned = ConvertedManifestEntry(
            source_sha256=measurement.source_sha256,
            convert_tool_commit=measurement.convert_tool_commit,
            quant=measurement.quant,
            output_sha256=measurement.output_sha256,
            provenance_tier=provenance_tier,
            issued_at=resolved_issued_at,
            max_trust_age_seconds=max_trust_age_seconds,
            signer_key_id=signer_key_id,
            signature=b"",
        )
        signature = self._private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
        entry = ConvertedManifestEntry(
            source_sha256=measurement.source_sha256,
            convert_tool_commit=measurement.convert_tool_commit,
            quant=measurement.quant,
            output_sha256=measurement.output_sha256,
            provenance_tier=provenance_tier,
            issued_at=resolved_issued_at,
            max_trust_age_seconds=max_trust_age_seconds,
            signer_key_id=signer_key_id,
            signature=signature,
        )
        self._verifier.verify(entry)  # self-verify before emit
        return entry


def _cli_mint_pull_manifest(args: argparse.Namespace) -> int:
    passphrase = args.passphrase.encode("utf-8") if args.passphrase else None
    private_key = load_signing_key(Path(args.private_key).read_bytes(), passphrase)
    signer = ManifestSigner(private_key)
    entry = signer.mint(
        repo_id=args.repo_id,
        revision=args.revision,
        filename=args.filename,
        quant=args.quant,
        sha256=args.sha256,
        lfs_object_id=args.lfs_object_id,
        provenance_tier=args.provenance_tier,
        signer_key_id=args.signer_key_id,
        max_trust_age_seconds=args.max_trust_age_seconds,
    )
    out_path = Path(args.out)
    out_path.write_text(json.dumps(entry.to_json_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"minted and self-verified: {out_path}", file=sys.stderr)
    return 0


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mint a counter-signed model-pull admission manifest (Yashigani signing infra only)."
    )
    parser.add_argument("--private-key", required=True, help="Path to the encrypted model-manifest private key PEM")
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Private-key passphrase (prefer piping via env/secret store over a shell arg in real use)",
    )
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--revision", required=True, help="Pinned commit hash (never a branch/tag)")
    parser.add_argument("--filename", required=True)
    parser.add_argument("--quant", required=True)
    parser.add_argument("--sha256", required=True, help="Digest MEASURED by Yashigani ingestion, not from HF")
    parser.add_argument("--lfs-object-id", required=True, help="Git-LFS pointer oid, hex, no 'sha256:' prefix")
    parser.add_argument("--provenance-tier", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument("--max-trust-age-seconds", type=int, required=True)
    parser.add_argument("--out", required=True, help="Output manifest JSON path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    return _cli_mint_pull_manifest(args)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ManifestSigner",
    "ConvertedManifestSigner",
    "load_signing_key",
]
