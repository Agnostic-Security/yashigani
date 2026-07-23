# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Round-trip tests for the mint-side signing tool (`scripts/manifest_signer.py`,
`scripts/keygen_manifest.py`) against the verify-side (`catalog.py`,
`convert_provenance.py`). Fully offline — every keypair here is an ephemeral
TEST key generated in-memory for this test run only; no real production key
is minted, read, or referenced anywhere in this suite."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from keygen_manifest import (
    KeygenRefusedError,
    _read_passphrase,
    generate_encrypted_keypair,
)
from manifest_signer import ConvertedManifestSigner, ManifestSigner, load_signing_key

from yashigani_infer.catalog import (
    CatalogVerificationError,
    CatalogVerifier,
    SignedCatalog,
    SignedCatalogEntry,
    StaticRevocationSource,
)
from yashigani_infer.convert_provenance import (
    ConvertedManifestVerificationError,
    ConvertedManifestVerifier,
    measure_conversion_tuple,
    verify_converted_manifest,
)

TEST_PASSPHRASE = b"a-test-passphrase-16-plus-chars"
REVISION = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
CONVERT_TOOL_COMMIT = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"


@pytest.fixture()
def signing_keypair():
    priv_pem, pub_pem = generate_encrypted_keypair(TEST_PASSPHRASE)
    private_key = load_signing_key(priv_pem, TEST_PASSPHRASE)
    return private_key, private_key.public_key()


# --- keygen_manifest.py ---


def test_generate_encrypted_keypair_round_trips_with_passphrase() -> None:
    priv_pem, pub_pem = generate_encrypted_keypair(TEST_PASSPHRASE)
    private_key = load_signing_key(priv_pem, TEST_PASSPHRASE)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    # confirm it really is encrypted at rest, not NoEncryption() (MC-01 lesson)
    assert b"ENCRYPTED" in priv_pem


def test_generate_encrypted_keypair_refuses_wrong_passphrase() -> None:
    priv_pem, _pub_pem = generate_encrypted_keypair(TEST_PASSPHRASE)
    with pytest.raises(Exception):
        load_signing_key(priv_pem, b"the-wrong-passphrase-entirely")


def test_read_passphrase_refuses_when_env_var_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE", raising=False)
    with pytest.raises(KeygenRefusedError, match="not set"):
        _read_passphrase()


def test_read_passphrase_refuses_when_too_short(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE", "short")
    with pytest.raises(KeygenRefusedError, match="minimum"):
        _read_passphrase()


def test_keygen_cli_writes_encrypted_key_with_restricted_perms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import stat

    import keygen_manifest

    monkeypatch.setenv("YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE", TEST_PASSPHRASE.decode())
    out_dir = tmp_path / "keys"
    rc = keygen_manifest.main(["--out-dir", str(out_dir), "--test-key"])
    assert rc == 0

    priv_path = out_dir / "model_manifest_private.pem"
    pub_path = out_dir / "model_manifest_public.pem"
    assert priv_path.is_file()
    assert pub_path.is_file()
    assert stat.S_IMODE(priv_path.stat().st_mode) == 0o600
    assert b"ENCRYPTED" in priv_path.read_bytes()

    # the generated key must actually work end-to-end with the signer
    private_key = load_signing_key(priv_path.read_bytes(), TEST_PASSPHRASE)
    ManifestSigner(private_key)  # constructs without error


def test_keygen_cli_refuses_to_overwrite_without_force(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import keygen_manifest

    monkeypatch.setenv("YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE", TEST_PASSPHRASE.decode())
    out_dir = tmp_path / "keys"
    assert keygen_manifest.main(["--out-dir", str(out_dir), "--test-key"]) == 0
    assert keygen_manifest.main(["--out-dir", str(out_dir), "--test-key"]) == 1  # no --force


# --- manifest_signer.py: pull-manifest (SignedCatalogEntry) round-trip ---


def _mint_pull_entry(
    signer: ManifestSigner,
    *,
    repo_id: str = "acme/tiny-model",
    revision: str = REVISION,
    filename: str = "tiny-model.Q4_K_M.gguf",
    quant: str = "Q4_K_M",
    sha256: str = "c" * 64,
    lfs_object_id: str = "d" * 64,
    provenance_tier: str = "counter-signed",
    signer_key_id: str = "test-signing-key-2026-07",
    # Large enough that tests calling require() without an explicit `now=`
    # (real wall-clock time) never spuriously expire relative to the fixed
    # issued_at below.
    max_trust_age_seconds: int = 90 * 24 * 3600,
    issued_at: str = "2026-07-22T00:00:00Z",
) -> SignedCatalogEntry:
    # Explicit typed kwargs (not a **dict-unpack) mirroring ManifestSigner.mint's
    # own signature — mypy cannot verify a `dict[str, object]` unpack against
    # typed keyword parameters (was the standing arg-type error at this call
    # site); named parameters give it exact per-field types instead.
    return signer.mint(
        repo_id=repo_id,
        revision=revision,
        filename=filename,
        quant=quant,
        sha256=sha256,
        lfs_object_id=lfs_object_id,
        provenance_tier=provenance_tier,
        signer_key_id=signer_key_id,
        max_trust_age_seconds=max_trust_age_seconds,
        issued_at=issued_at,
    )


def test_sign_then_verify_round_trip(signing_keypair) -> None:
    private_key, public_key = signing_keypair
    signer = ManifestSigner(private_key)
    entry = _mint_pull_entry(signer)

    CatalogVerifier(public_key).verify(entry)  # must not raise


def test_sign_then_verify_via_json_round_trip(signing_keypair) -> None:
    """The mint-side writes to_json_dict(); the verify-side reads it back with
    from_json_dict() — this is the on-disk manifest FORMAT round trip."""
    private_key, public_key = signing_keypair
    signer = ManifestSigner(private_key)
    entry = _mint_pull_entry(signer)

    wire_bytes = json.dumps(entry.to_json_dict()).encode("utf-8")
    reloaded = SignedCatalogEntry.from_json_dict(json.loads(wire_bytes))

    CatalogVerifier(public_key).verify(reloaded)  # must not raise
    assert reloaded.sha256 == entry.sha256
    assert reloaded.signature == entry.signature


def test_tampered_manifest_fails_verification(signing_keypair) -> None:
    private_key, public_key = signing_keypair
    signer = ManifestSigner(private_key)
    entry = _mint_pull_entry(signer)

    tampered = SignedCatalogEntry(
        repo_id=entry.repo_id,
        revision=entry.revision,
        filename=entry.filename,
        quant=entry.quant,
        sha256="f" * 64,  # tampered after signing
        lfs_object_id=entry.lfs_object_id,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
    )
    with pytest.raises(CatalogVerificationError):
        CatalogVerifier(public_key).verify(tampered)


def test_expired_manifest_rejected_at_require_time(signing_keypair) -> None:
    private_key, public_key = signing_keypair
    signer = ManifestSigner(private_key)
    entry = _mint_pull_entry(signer, max_trust_age_seconds=60)

    catalog = SignedCatalog(CatalogVerifier(public_key))
    catalog.load_entries([entry])

    long_after = datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc) + timedelta(days=1)
    with pytest.raises(CatalogVerificationError, match="max trust age"):
        catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf", now=long_after)


def test_revoked_manifest_rejected_at_require_time(signing_keypair) -> None:
    private_key, public_key = signing_keypair
    signer = ManifestSigner(private_key)
    entry = _mint_pull_entry(signer)

    revocation = StaticRevocationSource(denied=[("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")])
    catalog = SignedCatalog(CatalogVerifier(public_key), revocation_source=revocation)
    catalog.load_entries([entry])  # signature is valid — load succeeds

    with pytest.raises(CatalogVerificationError, match="deny-list"):
        catalog.require("acme/tiny-model", REVISION, "tiny-model.Q4_K_M.gguf")


def test_signer_self_verifies_and_never_hands_back_a_bad_signature(signing_keypair, monkeypatch) -> None:
    """C6 pattern: if the private key somehow produced a signature that does not
    verify against its own public key, the signer must raise, not return it."""
    private_key, _public_key = signing_keypair
    signer = ManifestSigner(private_key)

    def _broken_verify(self, entry):  # noqa: ANN001
        raise CatalogVerificationError("forced failure for self-check test")

    monkeypatch.setattr(CatalogVerifier, "verify", _broken_verify)
    with pytest.raises(CatalogVerificationError, match="forced failure"):
        _mint_pull_entry(signer)


# --- manifest_signer.py: converted-GGUF manifest round-trip ---


def test_convert_manifest_sign_then_verify_round_trip(signing_keypair, tmp_path: Path) -> None:
    private_key, public_key = signing_keypair
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"fake safetensors bytes for the test fixture")
    output_path.write_bytes(b"fake gguf bytes produced by the (stubbed) converter")

    measurement = measure_conversion_tuple(
        source_path, output_path, convert_tool_commit=CONVERT_TOOL_COMMIT, quant="Q4_K_M"
    )
    signer = ConvertedManifestSigner(private_key)
    entry = signer.mint(
        measurement,
        provenance_tier="converted-derived",
        signer_key_id="test-signing-key-2026-07",
        max_trust_age_seconds=3600,
    )

    verifier = ConvertedManifestVerifier(public_key)
    verify_converted_manifest(entry, output_path=output_path, verifier=verifier)  # must not raise


def test_convert_manifest_rejects_substituted_output_bytes(signing_keypair, tmp_path: Path) -> None:
    """finding #4 TOCTOU: if the bytes at output_path change after minting (a
    substitution between conversion and load), verification must fail — the
    verify hook re-measures from disk, it does not trust a cached digest."""
    private_key, public_key = signing_keypair
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"original source bytes")
    output_path.write_bytes(b"original converter output bytes")

    measurement = measure_conversion_tuple(
        source_path, output_path, convert_tool_commit=CONVERT_TOOL_COMMIT, quant="Q4_K_M"
    )
    signer = ConvertedManifestSigner(private_key)
    entry = signer.mint(
        measurement, provenance_tier="converted-derived", signer_key_id="k1", max_trust_age_seconds=3600
    )

    output_path.write_bytes(b"SUBSTITUTED bytes after minting, before load")  # attacker swap

    verifier = ConvertedManifestVerifier(public_key)
    with pytest.raises(ConvertedManifestVerificationError, match="does not match"):
        verify_converted_manifest(entry, output_path=output_path, verifier=verifier)


def test_convert_manifest_rejects_tampered_source_digest(signing_keypair, tmp_path: Path) -> None:
    """finding #4: the whole tuple is signed as one unit — an attacker editing
    just source_sha256 in the manifest (without a fresh signature) must fail."""
    private_key, public_key = signing_keypair
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"source bytes")
    output_path.write_bytes(b"output bytes")

    measurement = measure_conversion_tuple(
        source_path, output_path, convert_tool_commit=CONVERT_TOOL_COMMIT, quant="Q4_K_M"
    )
    signer = ConvertedManifestSigner(private_key)
    entry = signer.mint(
        measurement, provenance_tier="converted-derived", signer_key_id="k1", max_trust_age_seconds=3600
    )

    from yashigani_infer.convert_provenance import ConvertedManifestEntry

    tampered = ConvertedManifestEntry(
        source_sha256="0" * 64,  # laundered source digest, unsigned edit
        convert_tool_commit=entry.convert_tool_commit,
        quant=entry.quant,
        output_sha256=entry.output_sha256,
        provenance_tier=entry.provenance_tier,
        issued_at=entry.issued_at,
        max_trust_age_seconds=entry.max_trust_age_seconds,
        signature=entry.signature,
        signer_key_id=entry.signer_key_id,
    )
    verifier = ConvertedManifestVerifier(public_key)
    with pytest.raises(ConvertedManifestVerificationError):
        verify_converted_manifest(tampered, output_path=output_path, verifier=verifier)


def test_convert_manifest_rejects_expired(signing_keypair, tmp_path: Path) -> None:
    private_key, public_key = signing_keypair
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"source bytes")
    output_path.write_bytes(b"output bytes")

    measurement = measure_conversion_tuple(
        source_path, output_path, convert_tool_commit=CONVERT_TOOL_COMMIT, quant="Q4_K_M"
    )
    signer = ConvertedManifestSigner(private_key)
    entry = signer.mint(
        measurement,
        provenance_tier="converted-derived",
        signer_key_id="k1",
        max_trust_age_seconds=60,
        issued_at="2026-07-22T00:00:00Z",
    )

    verifier = ConvertedManifestVerifier(public_key)
    long_after = datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc) + timedelta(days=1)
    with pytest.raises(ConvertedManifestVerificationError, match="max trust age"):
        verify_converted_manifest(entry, output_path=output_path, verifier=verifier, now=long_after)


def test_convert_manifest_rejects_revoked(signing_keypair, tmp_path: Path) -> None:
    private_key, public_key = signing_keypair
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"source bytes")
    output_path.write_bytes(b"output bytes")

    measurement = measure_conversion_tuple(
        source_path, output_path, convert_tool_commit=CONVERT_TOOL_COMMIT, quant="Q4_K_M"
    )
    signer = ConvertedManifestSigner(private_key)
    entry = signer.mint(
        measurement, provenance_tier="converted-derived", signer_key_id="k1", max_trust_age_seconds=3600
    )

    revocation = StaticRevocationSource(denied=[(entry.convert_tool_commit, entry.source_sha256, entry.output_sha256)])
    verifier = ConvertedManifestVerifier(public_key)
    with pytest.raises(ConvertedManifestVerificationError, match="deny-list"):
        verify_converted_manifest(entry, output_path=output_path, verifier=verifier, revocation_source=revocation)


def test_measure_conversion_tuple_refuses_floating_tool_ref(tmp_path: Path) -> None:
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"x")
    output_path.write_bytes(b"y")
    with pytest.raises(ValueError, match="convert_tool_commit"):
        measure_conversion_tuple(source_path, output_path, convert_tool_commit="main", quant="Q4_K_M")


def test_manifest_signer_cli_mints_a_manifest_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import keygen_manifest
    import manifest_signer

    monkeypatch.setenv("YASHIGANI_MODEL_MANIFEST_KEY_PASSPHRASE", TEST_PASSPHRASE.decode())
    key_dir = tmp_path / "keys"
    assert keygen_manifest.main(["--out-dir", str(key_dir), "--test-key"]) == 0

    out_manifest = tmp_path / "manifest.json"
    rc = manifest_signer.main(
        [
            "--private-key",
            str(key_dir / "model_manifest_private.pem"),
            "--passphrase",
            TEST_PASSPHRASE.decode(),
            "--repo-id",
            "acme/tiny-model",
            "--revision",
            REVISION,
            "--filename",
            "tiny-model.Q4_K_M.gguf",
            "--quant",
            "Q4_K_M",
            "--sha256",
            "c" * 64,
            "--lfs-object-id",
            "d" * 64,
            "--provenance-tier",
            "counter-signed",
            "--signer-key-id",
            "test-key-1",
            "--max-trust-age-seconds",
            "3600",
            "--out",
            str(out_manifest),
        ]
    )
    assert rc == 0
    assert out_manifest.is_file()

    data = json.loads(out_manifest.read_text())
    entry = SignedCatalogEntry.from_json_dict(data)
    public_key = load_signing_key((key_dir / "model_manifest_private.pem").read_bytes(), TEST_PASSPHRASE).public_key()
    CatalogVerifier(public_key).verify(entry)  # must not raise
    assert base64.b64decode(data["signature"]) == entry.signature
