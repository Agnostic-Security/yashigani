# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for `provenance_reverify.py` (Red-Council H1/H2, 2026-07-29).

No real production key, no network, no live llama-server — every keypair
here is an ephemeral P-256 keypair minted in-memory for this test run only,
same convention as `test_catalog.py`/`test_manifest_signing.py`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from kuroshio.catalog import CatalogVerifier, SignedCatalogEntry, StaticRevocationSource
from kuroshio.convert_provenance import (
    ConvertedManifestVerifier,
    measure_conversion_tuple,
)
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.provenance_reverify import ServeTimeProvenanceVerifier, ServeTimeVerificationError

REVISION = "b" * 40
GOOD_SHA256 = "c" * 64
GOOD_LFS_OBJECT_ID = "f" * 64
ISSUED_AT = "2026-07-22T00:00:00Z"


def _make_signed_entry(private_key, **overrides) -> SignedCatalogEntry:
    fields: dict[str, Any] = {
        "repo_id": "acme/tiny-model",
        "revision": REVISION,
        "filename": "tiny-model.Q4_K_M.gguf",
        "quant": "Q4_K_M",
        "sha256": GOOD_SHA256,
        "lfs_object_id": GOOD_LFS_OBJECT_ID,
        "provenance_tier": "vetted",
        "issued_at": ISSUED_AT,
        "max_trust_age_seconds": 90 * 24 * 3600,
        "signer_key_id": "key-2026-07",
    }
    fields.update(overrides)
    unsigned = SignedCatalogEntry(**fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    return SignedCatalogEntry(**fields, signature=signature)


def _resolved_hf_model(
    entry: SignedCatalogEntry, *, sha256: str | None = None, tier: str | None = None
) -> ResolvedModel:
    digest = sha256 or entry.sha256
    provenance = Provenance(
        kind=ProvenanceKind.HUGGINGFACE,
        origin=entry.repo_id,
        revision=entry.revision,
        sha256=digest,
        operator_supplied=False,
        extra={
            "provenance_tier": tier if tier is not None else entry.provenance_tier,
            "signed_manifest": entry.to_json_dict(),
        },
    )
    return ResolvedModel(sha256=digest, blob_path=Path(f"/blobs/{digest}.gguf"), metadata={}, provenance=provenance)


@pytest.fixture()
def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# --- pass-through: nothing signed to re-check ---


def test_verify_passes_through_a_local_file_model_with_no_signed_manifest() -> None:
    model = ResolvedModel(
        sha256="a" * 64,
        blob_path=Path("/blobs/a.gguf"),
        metadata={},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="/x", sha256="a" * 64, operator_supplied=True),
    )
    ServeTimeProvenanceVerifier().verify(model)  # must not raise


def test_verify_passes_through_dev_mode_huggingface_model_with_no_signed_manifest() -> None:
    """The documented 'unverified-dev-mode' fallback (no catalog wired at
    pull time) has nothing signed to persist or re-check — unchanged."""
    model = ResolvedModel(
        sha256="a" * 64,
        blob_path=Path("/blobs/a.gguf"),
        metadata={},
        provenance=Provenance(
            kind=ProvenanceKind.HUGGINGFACE,
            origin="acme/x",
            sha256="a" * 64,
            operator_supplied=False,
            extra={"provenance_tier": "unverified-dev-mode"},
        ),
    )
    ServeTimeProvenanceVerifier().verify(model)  # must not raise


# --- Hugging Face / SignedCatalogEntry path ---


def test_verify_accepts_a_valid_still_current_non_revoked_manifest(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    model = _resolved_hf_model(entry)
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key))
    verifier.verify(model)  # must not raise


def test_verify_fails_closed_when_no_catalog_verifier_configured(keypair) -> None:
    private_key, _public_key = keypair
    entry = _make_signed_entry(private_key)
    model = _resolved_hf_model(entry)
    with pytest.raises(ServeTimeVerificationError, match="no CatalogVerifier|no known|not configured"):
        ServeTimeProvenanceVerifier().verify(model)


def test_verify_rejects_a_tampered_stored_signature(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    manifest = entry.to_json_dict()
    manifest["sha256"] = "e" * 64  # tampered after signing, without a fresh signature
    model = ResolvedModel(
        sha256="e" * 64,
        blob_path=Path("/blobs/e.gguf"),
        metadata={},
        provenance=Provenance(
            kind=ProvenanceKind.HUGGINGFACE,
            origin=entry.repo_id,
            revision=entry.revision,
            sha256="e" * 64,
            operator_supplied=False,
            extra={"provenance_tier": entry.provenance_tier, "signed_manifest": manifest},
        ),
    )
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key))
    with pytest.raises(ServeTimeVerificationError, match="failed re-verification"):
        verifier.verify(model)


def test_verify_rejects_digest_mismatch_between_manifest_and_resident_blob(keypair) -> None:
    """The stored manifest's own signature verifies fine, but it was minted
    for a DIFFERENT digest than the blob actually resident under this sha256
    — a tier/manifest binding failure, must fail closed."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)  # signed for GOOD_SHA256
    model = _resolved_hf_model(entry, sha256="d" * 64, tier=entry.provenance_tier)  # resident under a different digest
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key))
    with pytest.raises(ServeTimeVerificationError, match="binding failure"):
        verifier.verify(model)


def test_verify_rejects_relabelled_sidecar_tier(keypair) -> None:
    """H2: the sidecar provenance_tier field was edited independently of the
    signature (e.g. a local write flipped 'community' -> 'vetted') — the
    signed manifest still says the original tier, so this must fail closed."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, provenance_tier="community")
    model = _resolved_hf_model(entry, tier="vetted")  # sidecar relabelled, signature still says "community"
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key))
    with pytest.raises(ServeTimeVerificationError, match="relabelled"):
        verifier.verify(model)


def test_verify_rejects_expired_manifest(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, max_trust_age_seconds=60)
    model = _resolved_hf_model(entry)
    issued = datetime(2026, 7, 22, 0, 0, 0, tzinfo=UTC)
    long_after = issued + timedelta(days=1)
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key), clock=lambda: long_after)
    with pytest.raises(ServeTimeVerificationError, match="max trust age"):
        verifier.verify(model)


def test_verify_rejects_revoked_manifest(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    model = _resolved_hf_model(entry)
    revocation = StaticRevocationSource(denied=[(entry.repo_id, entry.revision, entry.filename)])
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key), revocation_source=revocation)
    with pytest.raises(ServeTimeVerificationError, match="deny-list"):
        verifier.verify(model)


def test_verify_accepts_when_not_on_deny_list(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    model = _resolved_hf_model(entry)
    revocation = StaticRevocationSource(denied=[("acme/some-other-model", REVISION, "other.gguf")])
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key), revocation_source=revocation)
    verifier.verify(model)  # must not raise


def test_verify_fails_closed_on_malformed_stored_manifest(keypair) -> None:
    _private_key, public_key = keypair
    model = ResolvedModel(
        sha256="a" * 64,
        blob_path=Path("/blobs/a.gguf"),
        metadata={},
        provenance=Provenance(
            kind=ProvenanceKind.HUGGINGFACE,
            origin="acme/x",
            sha256="a" * 64,
            operator_supplied=False,
            extra={"provenance_tier": "vetted", "signed_manifest": {"not": "a valid manifest shape"}},
        ),
    )
    verifier = ServeTimeProvenanceVerifier(catalog_verifier=CatalogVerifier(public_key))
    with pytest.raises(ServeTimeVerificationError, match="malformed"):
        verifier.verify(model)


# --- Converted-GGUF / ConvertedManifestEntry path ---


def test_verify_accepts_a_valid_converted_manifest(keypair, tmp_path: Path) -> None:
    from kuroshio.convert_provenance import ConvertedManifestVerifier as _CMV  # noqa: F401

    private_key, public_key = keypair
    output_path = tmp_path / "output.gguf"
    output_path.write_bytes(b"converted gguf bytes")
    source_path = tmp_path / "source.safetensors"
    source_path.write_bytes(b"source bytes")

    measurement = measure_conversion_tuple(source_path, output_path, convert_tool_commit="a" * 40, quant="Q4_K_M")
    unsigned_payload_fields = {
        "source_sha256": measurement.source_sha256,
        "convert_tool_commit": measurement.convert_tool_commit,
        "quant": measurement.quant,
        "output_sha256": measurement.output_sha256,
        "provenance_tier": "converted-derived",
        "issued_at": ISSUED_AT,
        # Large enough that this test (real wall-clock time, no explicit
        # `now=`) never spuriously expires relative to the fixed ISSUED_AT.
        "max_trust_age_seconds": 90 * 24 * 3600,
        "signer_key_id": "k1",
    }
    from kuroshio.convert_provenance import ConvertedManifestEntry

    unsigned = ConvertedManifestEntry(**unsigned_payload_fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    entry = ConvertedManifestEntry(**unsigned_payload_fields, signature=signature)

    provenance = Provenance(
        kind=ProvenanceKind.CONVERTED,
        origin="local-convert-job",
        sha256=measurement.output_sha256,
        operator_supplied=False,
        extra={"provenance_tier": "converted-derived", "signed_manifest": entry.to_json_dict()},
    )
    model = ResolvedModel(sha256=measurement.output_sha256, blob_path=output_path, metadata={}, provenance=provenance)

    verifier = ServeTimeProvenanceVerifier(converted_verifier=ConvertedManifestVerifier(public_key))
    verifier.verify(model)  # must not raise


def test_verify_rejects_converted_manifest_when_output_bytes_were_substituted(keypair, tmp_path: Path) -> None:
    """TOCTOU close, re-exercised at SERVE time: if the bytes at blob_path
    changed after minting, serve-time re-verification must catch it too —
    not just the original pull-time verify."""
    private_key, public_key = keypair
    output_path = tmp_path / "output.gguf"
    output_path.write_bytes(b"original converter output")
    source_path = tmp_path / "source.safetensors"
    source_path.write_bytes(b"source bytes")

    measurement = measure_conversion_tuple(source_path, output_path, convert_tool_commit="a" * 40, quant="Q4_K_M")
    from kuroshio.convert_provenance import ConvertedManifestEntry

    fields = {
        "source_sha256": measurement.source_sha256,
        "convert_tool_commit": measurement.convert_tool_commit,
        "quant": measurement.quant,
        "output_sha256": measurement.output_sha256,
        "provenance_tier": "converted-derived",
        "issued_at": ISSUED_AT,
        "max_trust_age_seconds": 3600,
        "signer_key_id": "k1",
    }
    unsigned = ConvertedManifestEntry(**fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    entry = ConvertedManifestEntry(**fields, signature=signature)

    provenance = Provenance(
        kind=ProvenanceKind.CONVERTED,
        origin="local-convert-job",
        sha256=measurement.output_sha256,
        operator_supplied=False,
        extra={"provenance_tier": "converted-derived", "signed_manifest": entry.to_json_dict()},
    )
    model = ResolvedModel(sha256=measurement.output_sha256, blob_path=output_path, metadata={}, provenance=provenance)

    output_path.write_bytes(b"SUBSTITUTED bytes after the model was already resident")

    verifier = ServeTimeProvenanceVerifier(converted_verifier=ConvertedManifestVerifier(public_key))
    with pytest.raises(ServeTimeVerificationError, match="failed re-verification"):
        verifier.verify(model)


def test_verify_fails_closed_when_no_converted_verifier_configured(keypair, tmp_path: Path) -> None:
    private_key, _public_key = keypair
    output_path = tmp_path / "output.gguf"
    output_path.write_bytes(b"bytes")
    source_path = tmp_path / "source.safetensors"
    source_path.write_bytes(b"src")
    measurement = measure_conversion_tuple(source_path, output_path, convert_tool_commit="a" * 40, quant="Q4_K_M")
    from kuroshio.convert_provenance import ConvertedManifestEntry

    fields = {
        "source_sha256": measurement.source_sha256,
        "convert_tool_commit": measurement.convert_tool_commit,
        "quant": measurement.quant,
        "output_sha256": measurement.output_sha256,
        "provenance_tier": "converted-derived",
        "issued_at": ISSUED_AT,
        "max_trust_age_seconds": 3600,
        "signer_key_id": "k1",
    }
    unsigned = ConvertedManifestEntry(**fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    entry = ConvertedManifestEntry(**fields, signature=signature)
    provenance = Provenance(
        kind=ProvenanceKind.CONVERTED,
        origin="local-convert-job",
        sha256=measurement.output_sha256,
        operator_supplied=False,
        extra={"provenance_tier": "converted-derived", "signed_manifest": entry.to_json_dict()},
    )
    model = ResolvedModel(sha256=measurement.output_sha256, blob_path=output_path, metadata={}, provenance=provenance)

    with pytest.raises(ServeTimeVerificationError, match="no ConvertedManifestVerifier"):
        ServeTimeProvenanceVerifier().verify(model)
