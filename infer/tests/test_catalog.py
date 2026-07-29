# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the signed-catalog verify-side (ECDSA). No network, no key-mgmt infra —
this test mints an ephemeral P-256 keypair locally purely to exercise the verify path;
production signing/key distribution is a separate component (`scripts/manifest_signer.py`,
Yashigani signing infra only), not exercised here."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from kuroshio.catalog import (
    ECDSA_P256_SHA256,
    CatalogVerificationError,
    CatalogVerifier,
    SignedCatalog,
    SignedCatalogEntry,
    StaticRevocationSource,
)

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
        # Large enough that tests calling require() without an explicit `now=`
        # (i.e. real wall-clock time) never spuriously expire relative to the
        # fixed ISSUED_AT constant above, while still comfortably under the
        # no-eternal-trust ceiling enforced by SignedCatalogEntry.
        "max_trust_age_seconds": 90 * 24 * 3600,
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
        quant=entry.quant,
        sha256="d" * 64,  # digest swapped after signing
        lfs_object_id=entry.lfs_object_id,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
    )
    with pytest.raises(CatalogVerificationError):
        CatalogVerifier(public_key).verify(tampered)


def test_verifier_rejects_tampered_provenance_tier(keypair) -> None:
    """Finding #5: provenance_tier is inside the signature — editing it independently
    of the signature (e.g. laundering 'community' -> 'vetted') must invalidate the sig."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, provenance_tier="community")
    tampered = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        quant=entry.quant,
        sha256=entry.sha256,
        lfs_object_id=entry.lfs_object_id,
        provenance_tier="vetted",  # promoted after signing, without a new signature
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
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
            quant="Q4_K_M",
            sha256="not-a-hex-digest",
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=3600,
            signature=b"",
            signer_key_id="key-1",
        )


def test_entry_rejects_malformed_lfs_object_id() -> None:
    with pytest.raises(ValueError, match="lfs_object_id"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id="sha256:not-stripped",
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=3600,
            signature=b"",
            signer_key_id="key-1",
        )


def test_entry_rejects_floating_revision() -> None:
    """A manifest signed against a floating branch (e.g. 'main') is refused at the
    dataclass level, not only by the adapter's own allowlist (finding #3)."""
    with pytest.raises(ValueError, match="revision"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision="main",
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=3600,
            signature=b"",
            signer_key_id="key-1",
        )


def test_entry_rejects_naive_issued_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at="2026-07-22T00:00:00",  # no tz
            max_trust_age_seconds=3600,
            signature=b"",
            signer_key_id="key-1",
        )


@pytest.mark.parametrize("bad_ttl", [0, -1])
def test_entry_rejects_non_positive_max_trust_age(bad_ttl: int) -> None:
    with pytest.raises(ValueError, match="max_trust_age_seconds"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=bad_ttl,
            signature=b"",
            signer_key_id="key-1",
        )


def test_entry_rejects_eternal_trust_window() -> None:
    with pytest.raises(ValueError, match="ceiling"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=999_999_999,
            signature=b"",
            signer_key_id="key-1",
        )


# --- Nico crypto-agility rec (2026-07-29 design-review): sig_alg dispatch ---


def test_entry_defaults_sig_alg_to_ecdsa_p256_sha256(keypair) -> None:
    private_key, _public_key = keypair
    entry = _make_signed_entry(private_key)
    assert entry.sig_alg == ECDSA_P256_SHA256 == "ecdsa-p256-sha256"


def test_entry_rejects_blank_sig_alg() -> None:
    with pytest.raises(ValueError, match="sig_alg"):
        SignedCatalogEntry(
            repo_id="acme/tiny-model",
            revision=REVISION,
            filename="tiny-model.gguf",
            quant="Q4_K_M",
            sha256=GOOD_SHA256,
            lfs_object_id=GOOD_LFS_OBJECT_ID,
            provenance_tier="vetted",
            issued_at=ISSUED_AT,
            max_trust_age_seconds=3600,
            signature=b"",
            signer_key_id="key-1",
            sig_alg="   ",
        )


def test_verifier_accepts_explicit_ecdsa_sig_alg(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, sig_alg=ECDSA_P256_SHA256)
    CatalogVerifier(public_key).verify(entry)  # must not raise


def test_verifier_fails_closed_on_an_unrecognised_sig_alg(keypair) -> None:
    """Crypto-agility means new algorithms are ADDABLE later without a
    breaking fleet re-mint -- but until this build actually implements one,
    an entry claiming it must be refused, never silently verified as if it
    were ECDSA."""
    private_key, public_key = keypair
    # Sign it correctly (a real future ML-DSA entry would be signed with the
    # NEW algorithm's key, not ECDSA — this test only needs to prove the
    # verifier refuses based on the CLAIMED alg, never reaching the
    # signature-bytes check at all for an unrecognised one).
    entry = _make_signed_entry(private_key, sig_alg="ml-dsa-65")
    with pytest.raises(CatalogVerificationError, match="does not implement"):
        CatalogVerifier(public_key).verify(entry)


def test_sig_alg_is_bound_into_the_signature_tampering_fails(keypair) -> None:
    """sig_alg is part of signed_payload() -- editing it independently of
    the signature (e.g. claiming a stronger algorithm than what was
    actually used) must invalidate the signature, same discipline as
    provenance_tier (finding #5)."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)  # signed with the default sig_alg
    tampered = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        quant=entry.quant,
        sha256=entry.sha256,
        lfs_object_id=entry.lfs_object_id,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
        sig_alg=ECDSA_P256_SHA256,  # same value, but re-asserted independently of the signature
    )
    # sanity: identical value round-trips fine (not a false-positive test)
    CatalogVerifier(public_key).verify(tampered)

    relabelled = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        quant=entry.quant,
        sha256=entry.sha256,
        lfs_object_id=entry.lfs_object_id,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
        signature=entry.signature,  # still the OLD signature
        signer_key_id=entry.signer_key_id,
        sig_alg="some-other-alg",  # relabelled without a fresh signature
    )
    with pytest.raises(CatalogVerificationError):
        CatalogVerifier(public_key).verify(relabelled)


def test_signed_catalog_load_and_require_roundtrip(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])

    fetched = catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")
    assert fetched.sha256 == GOOD_SHA256
    assert fetched.provenance_tier == "vetted"
    assert fetched.quant == "Q4_K_M"
    assert fetched.lfs_object_id == GOOD_LFS_OBJECT_ID


def test_signed_catalog_refuses_to_load_a_badly_signed_entry(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    bad_entry = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        quant=entry.quant,
        sha256="e" * 64,
        lfs_object_id=entry.lfs_object_id,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
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


# --- Nico provenance red-team 2026-07-22: TTL + revocation (findings #2/#6) ---


def test_require_rejects_expired_manifest_no_override(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, max_trust_age_seconds=60)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])

    issued = datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc)
    past_ttl = issued + timedelta(seconds=61)
    with pytest.raises(CatalogVerificationError, match="max trust age"):
        catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf", now=past_ttl)


def test_require_accepts_manifest_still_within_ttl(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, max_trust_age_seconds=60)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])

    issued = datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc)
    within_ttl = issued + timedelta(seconds=59)
    fetched = catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf", now=within_ttl)
    assert fetched.sha256 == GOOD_SHA256


def test_require_rejects_manifest_that_was_admitted_before_it_expired(keypair) -> None:
    """finding #2: TTL must be re-checked at USE time, not only at load time — an
    entry that verified fine at load_entries() can still be too old by the time a
    later pull actually calls require()."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key, max_trust_age_seconds=60)
    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])  # admitted fine — signature is valid regardless of age

    issued = datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc)
    long_after = issued + timedelta(days=30)
    with pytest.raises(CatalogVerificationError, match="max trust age"):
        catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf", now=long_after)


def test_require_rejects_revoked_manifest_no_override(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    revocation = StaticRevocationSource(denied=[("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")])
    catalog = SignedCatalog(CatalogVerifier(public_key), revocation_source=revocation)
    catalog.load_entries([entry])  # a valid signature does not bypass the deny-list

    with pytest.raises(CatalogVerificationError, match="deny-list"):
        catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")


def test_require_accepts_when_not_on_deny_list(keypair) -> None:
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    revocation = StaticRevocationSource(denied=[("acme/some-other-model", REVISION, "other.gguf")])
    catalog = SignedCatalog(CatalogVerifier(public_key), revocation_source=revocation)
    catalog.load_entries([entry])

    fetched = catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")
    assert fetched.sha256 == GOOD_SHA256


def test_default_revocation_source_denies_nothing(keypair) -> None:
    """The offline/air-gapped default: no revocation source wired means no deny-list,
    NOT a fail-closed 'nothing is ever admitted' state (documented explicitly in
    StaticRevocationSource's own docstring)."""
    private_key, public_key = keypair
    entry = _make_signed_entry(private_key)
    catalog = SignedCatalog(CatalogVerifier(public_key))  # no revocation_source passed
    catalog.load_entries([entry])
    fetched = catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")
    assert fetched.sha256 == GOOD_SHA256
