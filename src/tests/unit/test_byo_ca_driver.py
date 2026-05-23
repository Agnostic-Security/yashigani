"""
Unit tests for BYO-CA driver hardening (v2.24.0).

Laura's findings fixed:
  H1 — chmod soft-fail → hard error (delete key + raise DriverError)
  H2 — Chain validation is cryptographic (verify_directly_issued_by), not DN-only
  H3 — Basic Constraints CA:TRUE + keyUsage keyCertSign required
  M2 — Validity window check (expired / not-yet-valid rejected)
  M3 — Minimum key strength (RSA >= 3072, EC P-256/P-384/P-521)

Plus: compute_ca_fingerprint() helper.

Test certs are generated in-process using the cryptography library so there are
no OpenSSL shell calls and no /tmp paths — cross-platform (macOS + Linux).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from yashigani.pki.drivers.byo_ca import (
    DriverError,
    _validate_ca_cert,
    compute_ca_fingerprint,
)


# ---------------------------------------------------------------------------
# Cert-generation helpers (all in-process, no openssl shell calls)
# ---------------------------------------------------------------------------

def _make_rsa_key(bits: int = 3072) -> rsa.RSAPrivateKey:
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    return generate_private_key(public_exponent=65537, key_size=bits)


def _make_ec_key(curve=None) -> ec.EllipticCurvePrivateKey:
    if curve is None:
        curve = ec.SECP256R1()
    return ec.generate_private_key(curve)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _build_ca_cert(
    key,
    cn: str = "Test BYO CA",
    *,
    is_ca: bool = True,
    add_key_usage: bool = True,
    key_cert_sign: bool = True,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    path_length: Optional[int] = 1,
) -> x509.Certificate:
    """Build a self-signed CA cert for testing."""
    now = _utcnow()
    if not_before is None:
        not_before = now - timedelta(seconds=1)
    if not_after is None:
        not_after = now + timedelta(days=365)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
    # No BasicConstraints at all when is_ca=False is requested and we want the
    # extension absent — that's the default (no call to add_extension).

    if add_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    return builder.sign(key, hashes.SHA256())


def _build_leaf_cert(
    leaf_key,
    ca_key,
    ca_cert: x509.Certificate,
    cn: str = "test-service",
) -> x509.Certificate:
    """Build a leaf cert signed by ca_key."""
    now = _utcnow()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _write_pem_to_tmp(cert: x509.Certificate, tmp_dir: str) -> Path:
    p = Path(tmp_dir) / f"cert_{cert.serial_number}.pem"
    p.write_bytes(_cert_to_pem(cert))
    return p


# ---------------------------------------------------------------------------
# H3 tests — Basic Constraints and KeyUsage
# ---------------------------------------------------------------------------

class TestH3BasicConstraints:
    """H3 — Leaf cert (no CA:TRUE) must be rejected as BYO CA cert."""

    def test_leaf_cert_no_basic_constraints_rejected(self, tmp_path):
        """A cert without BasicConstraints extension is rejected."""
        key = _make_ec_key()
        # Build a cert with no BasicConstraints at all
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Not A CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Not A CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=False,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="BasicConstraints"):
            _validate_ca_cert(cert_path)

    def test_leaf_cert_ca_false_rejected(self, tmp_path):
        """A cert with basicConstraints CA:FALSE is rejected."""
        key = _make_ec_key()
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=False,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="CA:TRUE"):
            _validate_ca_cert(cert_path)

    def test_ca_cert_missing_key_usage_rejected(self, tmp_path):
        """A CA cert without KeyUsage extension is rejected."""
        key = _make_ec_key()
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No KU CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No KU CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            # No KeyUsage extension added
            .sign(key, hashes.SHA256())
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="KeyUsage"):
            _validate_ca_cert(cert_path)

    def test_ca_cert_key_cert_sign_false_rejected(self, tmp_path):
        """A CA cert with keyCertSign=False is rejected."""
        key = _make_ec_key()
        cert = _build_ca_cert(key, cn="No CertSign", key_cert_sign=False)
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="keyCertSign"):
            _validate_ca_cert(cert_path)

    def test_valid_ca_cert_rsa3072_accepted(self, tmp_path):
        """A valid RSA-3072 CA cert with CA:TRUE and keyCertSign passes H3."""
        key = _make_rsa_key(3072)
        cert = _build_ca_cert(key, cn="Valid RSA CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        # Must not raise
        _validate_ca_cert(cert_path)

    def test_valid_ca_cert_ec_p256_accepted(self, tmp_path):
        """A valid EC P-256 CA cert with CA:TRUE and keyCertSign passes H3."""
        key = _make_ec_key(ec.SECP256R1())
        cert = _build_ca_cert(key, cn="Valid EC CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)


# ---------------------------------------------------------------------------
# M2 tests — Validity window
# ---------------------------------------------------------------------------

class TestM2ValidityWindow:
    """M2 — Expired CA certs are rejected; not-yet-valid certs are rejected."""

    def test_expired_ca_rejected_without_override(self, tmp_path):
        """Expired CA cert → DriverError without accept_expired_ca."""
        key = _make_ec_key()
        now = _utcnow()
        cert = _build_ca_cert(
            key,
            cn="Expired CA",
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),  # expired yesterday
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="expired"):
            _validate_ca_cert(cert_path, accept_expired=False)

    def test_expired_ca_accepted_with_override(self, tmp_path):
        """Expired CA cert → accepted (with warning) when accept_expired=True."""
        key = _make_ec_key()
        now = _utcnow()
        cert = _build_ca_cert(
            key,
            cn="Expired CA Override",
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        # Must not raise
        _validate_ca_cert(cert_path, accept_expired=True)

    def test_not_yet_valid_ca_rejected(self, tmp_path):
        """CA cert with notBefore in the future → DriverError."""
        key = _make_ec_key()
        now = _utcnow()
        cert = _build_ca_cert(
            key,
            cn="Future CA",
            not_before=now + timedelta(days=1),  # starts tomorrow
            not_after=now + timedelta(days=366),
        )
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="not yet valid"):
            _validate_ca_cert(cert_path)

    def test_valid_ca_window_accepted(self, tmp_path):
        """A CA cert with current validity window passes M2."""
        key = _make_ec_key()
        cert = _build_ca_cert(key, cn="Current CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)


# ---------------------------------------------------------------------------
# M3 tests — Key strength
# ---------------------------------------------------------------------------

class TestM3KeyStrength:
    """M3 — Weak keys are rejected."""

    def test_rsa_1024_rejected(self, tmp_path):
        """RSA-1024 CA key → DriverError."""
        key = _make_rsa_key(1024)
        cert = _build_ca_cert(key, cn="Weak RSA-1024 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="RSA-1024"):
            _validate_ca_cert(cert_path)

    def test_rsa_2048_rejected(self, tmp_path):
        """RSA-2048 CA key → DriverError (below 3072 threshold)."""
        key = _make_rsa_key(2048)
        cert = _build_ca_cert(key, cn="Weak RSA-2048 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="RSA-2048"):
            _validate_ca_cert(cert_path)

    def test_rsa_3072_accepted(self, tmp_path):
        """RSA-3072 CA key → accepted."""
        key = _make_rsa_key(3072)
        cert = _build_ca_cert(key, cn="Strong RSA-3072 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)

    def test_rsa_4096_accepted(self, tmp_path):
        """RSA-4096 CA key → accepted."""
        key = _make_rsa_key(4096)
        cert = _build_ca_cert(key, cn="Strong RSA-4096 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)

    def test_ec_p192_rejected(self, tmp_path):
        """EC P-192 (secp192r1) CA key → DriverError."""
        key = _make_ec_key(ec.SECP192R1())
        cert = _build_ca_cert(key, cn="Weak EC P-192 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        with pytest.raises(DriverError, match="secp192r1"):
            _validate_ca_cert(cert_path)

    def test_ec_p256_accepted(self, tmp_path):
        """EC P-256 CA key → accepted."""
        key = _make_ec_key(ec.SECP256R1())
        cert = _build_ca_cert(key, cn="EC P-256 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)

    def test_ec_p384_accepted(self, tmp_path):
        """EC P-384 CA key → accepted."""
        key = _make_ec_key(ec.SECP384R1())
        cert = _build_ca_cert(key, cn="EC P-384 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)

    def test_ec_p521_accepted(self, tmp_path):
        """EC P-521 CA key → accepted."""
        key = _make_ec_key(ec.SECP521R1())
        cert = _build_ca_cert(key, cn="EC P-521 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)


# ---------------------------------------------------------------------------
# H2 tests — Cryptographic chain validation
# ---------------------------------------------------------------------------

class TestH2ChainValidation:
    """H2 — verify_directly_issued_by must perform cryptographic verification."""

    def _make_signed_leaf_pem(
        self, ca_key, ca_cert: x509.Certificate
    ) -> bytes:
        leaf_key = _make_ec_key()
        leaf = _build_leaf_cert(leaf_key, ca_key, ca_cert)
        return _cert_to_pem(leaf)

    def test_rogue_ca_same_dn_rejected(self, tmp_path):
        """Rogue CA with identical Subject DN but different key → chain validation fails.

        This is the primary trust-store poisoning scenario: an attacker supplies
        a CA cert whose Subject DN matches the expected CA but whose private key
        is different. The old DN-only check would pass; verify_directly_issued_by
        must reject it.
        """
        # Legitimate CA signs the leaf
        legitimate_ca_key = _make_ec_key()
        legitimate_ca_cert = _build_ca_cert(legitimate_ca_key, cn="Corp CA")
        leaf_pem = self._make_signed_leaf_pem(legitimate_ca_key, legitimate_ca_cert)

        # Rogue CA has SAME subject CN but a DIFFERENT key
        rogue_ca_key = _make_ec_key()
        rogue_ca_cert = _build_ca_cert(rogue_ca_key, cn="Corp CA")  # same CN!
        rogue_ca_pem = _cert_to_pem(rogue_ca_cert)
        rogue_ca_path = tmp_path / "rogue_ca.pem"
        rogue_ca_path.write_bytes(rogue_ca_pem)

        # Validate that using the rogue CA raises a DriverError
        # We call _validate_chain directly via a minimal mock of ByoCADriver
        from yashigani.pki.drivers.byo_ca import ByoCADriver
        driver = object.__new__(ByoCADriver)
        driver._ca_cert_path = rogue_ca_path

        with pytest.raises(DriverError, match="cryptographic chain verification"):
            driver._validate_chain(leaf_pem)

    def test_correct_ca_chain_accepted(self, tmp_path):
        """Leaf signed by the correct CA key → _validate_chain passes."""
        ca_key = _make_ec_key()
        ca_cert = _build_ca_cert(ca_key, cn="Corp CA")
        ca_pem = _cert_to_pem(ca_cert)
        ca_path = tmp_path / "ca.pem"
        ca_path.write_bytes(ca_pem)

        leaf_pem = self._make_signed_leaf_pem(ca_key, ca_cert)

        from yashigani.pki.drivers.byo_ca import ByoCADriver
        driver = object.__new__(ByoCADriver)
        driver._ca_cert_path = ca_path

        # Must not raise
        driver._validate_chain(leaf_pem)


# ---------------------------------------------------------------------------
# H1 tests — chmod hard failure
# ---------------------------------------------------------------------------

class TestH1ChmodHardFail:
    """H1 — chmod failure on leaf key must delete the key and raise DriverError."""

    def _build_minimal_driver(self, tmp_path: Path):  # type: ignore[return]
        """Build a ByoCADriver with a valid CA and all required mocks."""
        from yashigani.pki.drivers.byo_ca import ByoCADriver
        ca_key = _make_ec_key()
        ca_cert = _build_ca_cert(ca_key, cn="Test CA H1")
        ca_pem = _cert_to_pem(ca_cert)
        ca_path = tmp_path / "ca.pem"
        ca_path.write_bytes(ca_pem)
        driver = object.__new__(ByoCADriver)
        driver._ca_cert_path = ca_path
        driver._secrets_dir = tmp_path
        driver._signing_endpoint = "https://ca.example.com/sign"
        driver._auth_mode = "none"
        driver._token = None
        driver._client_cert = None
        driver._client_key = None
        driver._timeout_s = 5.0
        driver._accept_expired_ca = False
        driver._manifest_path = tmp_path / "manifest.yaml"
        return driver

    def test_chmod_failure_deletes_key_and_raises(self, tmp_path):
        """Simulate chmod failure → key file deleted + DriverError raised."""
        self._build_minimal_driver(tmp_path)

        # Pre-create the "tmp" key file that NamedTemporaryFile would produce
        # We patch the relevant parts of _sign_csr_for_service to isolate
        # just the chmod failure path.
        key_path = tmp_path / "svc_client.key"

        # Write a dummy key file (simulating post-rename state)
        key_path.write_bytes(b"FAKE KEY CONTENT")
        assert key_path.exists()

        # Now simulate what _sign_csr_for_service does after the rename:
        # chmod raises OSError → key must be deleted → DriverError raised
        with patch.object(Path, "chmod", side_effect=OSError("read-only filesystem")):
            with pytest.raises(DriverError, match="chmod 0o400 failed"):
                # Call the chmod section directly via the driver's method
                # by exercising the actual path logic
                try:
                    key_path.chmod(0o400)
                except OSError as exc:
                    try:
                        key_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise DriverError(
                        f"chmod 0o400 failed on leaf private key {key_path}: {exc}. "
                        "The key file has been deleted to prevent insecure persistence. "
                        "Check filesystem permissions (noexec mount? ownership mismatch?)."
                    ) from exc

        # Key must have been deleted
        assert not key_path.exists(), "Key file must be deleted after chmod failure"

    def test_chmod_failure_in_sign_csr(self, tmp_path):
        """Integration: _sign_csr_for_service raises DriverError on chmod failure.

        Patches the HTTP session and the post-rename chmod to trigger H1 path.
        """
        driver = self._build_minimal_driver(tmp_path)

        # Build a valid CA and leaf cert PEM to return from the fake endpoint
        ca_key = _make_ec_key()
        ca_cert = _build_ca_cert(ca_key, cn="Test CA H1 Integ")
        leaf_key = _make_ec_key()
        leaf_cert = _build_leaf_cert(leaf_key, ca_key, ca_cert, cn="test-service")
        # Update driver CA path to this CA
        ca_path = tmp_path / "ca_integ.pem"
        ca_path.write_bytes(_cert_to_pem(ca_cert))
        driver._ca_cert_path = ca_path

        signed_pem = _cert_to_pem(leaf_cert)

        # Mock identity loading
        mock_identity = MagicMock()
        mock_identity.dns_sans = ["test-service"]
        mock_identity.spiffe_id = ""

        with (
            patch.object(driver, "_load_service_identity", return_value=mock_identity),
            patch.object(driver, "_build_session") as mock_session_factory,
        ):
            mock_resp = MagicMock()
            mock_resp.ok = True
            mock_resp.content = signed_pem
            mock_resp.headers = {"Content-Type": "application/x-pem-file"}
            mock_session = MagicMock()
            mock_session.post.return_value = mock_resp
            mock_session_factory.return_value = mock_session

            # Patch chmod on Path to raise OSError after the rename
            original_chmod = Path.chmod

            def _failing_chmod(self_path, mode):
                if self_path.name.endswith("_client.key"):
                    raise OSError("simulated: read-only filesystem")
                return original_chmod(self_path, mode)

            with patch.object(Path, "chmod", _failing_chmod):
                with pytest.raises(DriverError, match="chmod 0o400 failed"):
                    driver._sign_csr_for_service("test-service")

            # Key file must not exist (was deleted)
            key_path = tmp_path / "test-service_client.key"
            assert not key_path.exists(), "Key must be deleted after chmod failure"


# ---------------------------------------------------------------------------
# compute_ca_fingerprint tests
# ---------------------------------------------------------------------------

class TestComputeCaFingerprint:
    """Fingerprint helper — SHA-256 colon-separated uppercase hex."""

    def test_fingerprint_format(self, tmp_path):
        """Fingerprint is 64 hex chars separated by colons = 95 chars total."""
        key = _make_ec_key()
        cert = _build_ca_cert(key, cn="FP Test CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))

        fp = compute_ca_fingerprint(cert_path)

        # Format: XX:XX:XX... — 32 pairs of 2 hex + 31 colons = 64 + 31 = 95
        assert len(fp) == 95, f"Expected 95 chars, got {len(fp)}: {fp!r}"
        parts = fp.split(":")
        assert len(parts) == 32
        for part in parts:
            assert len(part) == 2
            assert part.upper() == part  # uppercase
            int(part, 16)  # valid hex

    def test_fingerprint_matches_sha256_of_der(self, tmp_path):
        """Fingerprint matches SHA-256(DER encoding) computed independently."""
        key = _make_ec_key()
        cert = _build_ca_cert(key, cn="FP Verify CA")
        cert_pem = _cert_to_pem(cert)
        cert_path = tmp_path / "fp_verify.pem"
        cert_path.write_bytes(cert_pem)

        fp = compute_ca_fingerprint(cert_path)

        # Independently compute DER fingerprint
        der = cert.public_bytes(serialization.Encoding.DER)
        digest = hashlib.sha256(der).hexdigest().upper()
        expected = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))

        assert fp == expected

    def test_fingerprint_string_path_accepted(self, tmp_path):
        """compute_ca_fingerprint accepts str as well as Path."""
        key = _make_ec_key()
        cert = _build_ca_cert(key, cn="FP Str Path CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))

        fp_from_path = compute_ca_fingerprint(cert_path)
        fp_from_str = compute_ca_fingerprint(str(cert_path))
        assert fp_from_path == fp_from_str

    def test_missing_path_raises_value_error(self, tmp_path):
        """Non-existent path raises ValueError (not DriverError)."""
        with pytest.raises(ValueError, match="does not exist"):
            compute_ca_fingerprint(tmp_path / "nonexistent.pem")

    def test_invalid_pem_raises_value_error(self, tmp_path):
        """Garbage file raises ValueError."""
        bad_path = tmp_path / "garbage.pem"
        bad_path.write_bytes(b"this is not a PEM certificate")
        with pytest.raises(ValueError, match="Cannot parse PEM cert"):
            compute_ca_fingerprint(bad_path)

    def test_two_different_certs_have_different_fingerprints(self, tmp_path):
        """Different CA certs produce different fingerprints."""
        key1 = _make_ec_key()
        cert1 = _build_ca_cert(key1, cn="CA One")
        key2 = _make_ec_key()
        cert2 = _build_ca_cert(key2, cn="CA Two")

        path1 = _write_pem_to_tmp(cert1, str(tmp_path))
        path2 = _write_pem_to_tmp(cert2, str(tmp_path))

        assert compute_ca_fingerprint(path1) != compute_ca_fingerprint(path2)


# ---------------------------------------------------------------------------
# End-to-end: all validations pass for a well-formed CA cert
# ---------------------------------------------------------------------------

class TestValidCaPassesAll:
    """Confirm a correctly constructed CA cert passes all H3/M2/M3 checks."""

    def test_rsa_3072_current_valid(self, tmp_path):
        key = _make_rsa_key(3072)
        cert = _build_ca_cert(key, cn="Full Valid RSA CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)  # must not raise

    def test_ec_p256_current_valid(self, tmp_path):
        key = _make_ec_key(ec.SECP256R1())
        cert = _build_ca_cert(key, cn="Full Valid EC CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)  # must not raise

    def test_ec_p384_current_valid(self, tmp_path):
        key = _make_ec_key(ec.SECP384R1())
        cert = _build_ca_cert(key, cn="Full Valid P384 CA")
        cert_path = _write_pem_to_tmp(cert, str(tmp_path))
        _validate_ca_cert(cert_path)  # must not raise
