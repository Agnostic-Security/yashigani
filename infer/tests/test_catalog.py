# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the signed-catalog verify-side (ECDSA). No network, no key-mgmt infra —
this test mints an ephemeral P-256 keypair locally purely to exercise the verify path;
production signing/key distribution is a separate component (Nico), not exercised here."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani_infer.catalog import (
    CatalogVerificationError,
    CatalogVerifier,
    SignedCatalog,
    SignedCatalogEntry,
)

REVISION = "b" * 40
GOOD_SHA256 = "c" * 64


def _make_signed_entry(private_key, **overrides) -> SignedCatalogEntry:
    fields = {
        "repo_id": "acme/tiny-model",
        "revision": REVISION,
        "filename": "tiny-model.Q4_K_M.gguf",
        "sha256": GOOD_SHA256,
        "provenance_tier": "vetted",
        "signer_key_id": "key-2026-07",
    }
    fields.update(overrides)
    unsigned = SignedCatalogEntry(**fields, signature=b"")
    signature = private_key.sign(unsigned.signed_payload(), ec.ECDSA(hashes.SHA256()))
    return SignedCatalogEntry(**fields, signature=signature)


@pytest.fixture()
def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def test_verifier_accepts_a_correctly_signed_entry(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    CatalogVerifier(public_key).verify(entry)  # must not raise


def test_verifier_rejects_tampered_payload(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    tampered = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        sha256="d" * 64,  # digest swapped after signing
        provenance_tier=entry.provenance_tier,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
    )
    with pytest.raises(CatalogVerificationError):
        CatalogVerifier(public_key).verify(tampered)


def test_verifier_rejects_signature_from_a_different_key(keypair) -> None:
    private_key, _public_key = keypair
    entry = _make_signed_entry(private_key)
    other_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(CatalogVerificationError):
        CatalogVerifier(other_public_key).verify(entry)


def test_entry_rejects_malformed_sha256() -> None:
    with pytest.raises(ValueError, match="sha256"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            sha256="not-a-hex-digest",
            provenance_tier="vetted",
            signature=b"",
            signer_key_id="key-1",
        )


def test_signed_catalog_load_and_require_roundtrip(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])

    fetched = catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")
    assert fetched.sha256 == GOOD_SHA256
    assert fetched.provenance_tier == "vetted"


def test_signed_catalog_refuses_to_load_a_badly_signed_entry(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    bad_entry = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        sha256="e" * 64,
        provenance_tier=entry.provenance_tier,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
    )
    catalog = SignedCatalog(CatalogVerifier(public_key))
    with pytest.raises(CatalogVerificationError):
        catalog.load_entries([bad_entry])
    # fail closed: the bad entry must not be reachable afterwards, and
    # the whole batch is refused rather than partially admitted.
    with pytest.raises(CatalogVerificationError):
        catalog.require(entry.repo_id, entry.revision, entry.filename)


def test_signed_catalog_require_raises_when_absent_no_override(keypair) -> None:
    _private_key, public_key = keypair
    catalog = SignedCatalog(CatalogVerifier(public_key))
    with pytest.raises(CatalogVerificationError, match="no override"):
        catalog.require("acme/unlisted-model", REVISION, "model.gguf")
