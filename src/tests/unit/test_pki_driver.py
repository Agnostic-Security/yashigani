"""
Unit tests — PKI CA driver abstraction (Issue #51 + #53, v2.23.3).

Coverage:
  PKI-D-01  InternalCADriver.get_chain_info returns correct metadata from PEM cert
  PKI-D-02  InternalCADriver.get_pem_bundle returns PEM without PRIVATE KEY
  PKI-D-03  InternalCADriver raises DriverError when cert file missing
  PKI-D-04  ByoCADriver rejects non-HTTPS signing endpoints at construction
  PKI-D-05  ByoCADriver rejects missing env vars at construction
  PKI-D-06  ByoCADriver rejects non-existent BYO CA cert path at construction
  PKI-D-07  driver_factory returns InternalCADriver for mode=internal
  PKI-D-08  driver_factory raises RuntimeError for unknown mode
  PKI-D-09  CertChainInfo is fully serialisable (no private key fields)
  PKI-D-10  _extract_first_pem returns only first block from multi-cert bundle
  PKI-D-11  ByoCADriver rejects invalid auth_mode at construction
  PKI-D-12  InternalCADriver rotate returns RotateResult(success=False) for unknown service

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from yashigani.pki.drivers.base import CertChainInfo, DriverError, RotateResult
from yashigani.pki.drivers.internal_ca import (
    InternalCADriver,
    _extract_first_pem,
)


# ---------------------------------------------------------------------------
# Helpers — generate a real cert for testing
# ---------------------------------------------------------------------------

def _make_self_signed_pem() -> tuple[bytes, bytes]:
    """Generate a minimal self-signed P-256 cert + key PEM pair."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test-service"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("test-service"),
                x509.DNSName("localhost"),
                x509.UniformResourceIdentifier("spiffe://yashigani.internal/test-service"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# PKI-D-01: get_chain_info returns correct metadata
# ---------------------------------------------------------------------------

def test_internal_driver_get_chain_info(tmp_path: Path) -> None:
    cert_pem, _key_pem = _make_self_signed_pem()
    service = "test-service"
    # Bundle: leaf + (fake) intermediate
    bundle = cert_pem + cert_pem  # use same cert as intermediate placeholder
    cert_path = tmp_path / f"{service}_client.crt"
    cert_path.write_bytes(bundle)

    driver = InternalCADriver(secrets_dir=str(tmp_path), manifest_path=str(tmp_path / "manifest.yaml"))
    info = driver.get_chain_info(service)

    assert info.subject_cn == "test-service"
    assert info.issuer_cn == "Test Intermediate CA"
    assert isinstance(info.serial_hex, str) and len(info.serial_hex) > 0
    assert "localhost" in info.dns_sans
    assert any("spiffe://" in u for u in info.uri_sans)
    assert isinstance(info.fingerprint_sha256, str) and len(info.fingerprint_sha256) == 64
    assert info.ca_mode == "internal"
    assert info.needs_renewal is False  # 90-day cert, just issued


# ---------------------------------------------------------------------------
# PKI-D-02: get_pem_bundle never includes PRIVATE KEY
# ---------------------------------------------------------------------------

def test_internal_driver_get_pem_bundle_no_private_key(tmp_path: Path) -> None:
    cert_pem, key_pem = _make_self_signed_pem()
    service = "test-service"
    bundle = cert_pem + cert_pem
    cert_path = tmp_path / f"{service}_client.crt"
    cert_path.write_bytes(bundle)

    driver = InternalCADriver(secrets_dir=str(tmp_path), manifest_path=str(tmp_path / "manifest.yaml"))
    result = driver.get_pem_bundle(service)

    assert b"PRIVATE KEY" not in result
    assert b"BEGIN CERTIFICATE" in result


# ---------------------------------------------------------------------------
# PKI-D-03: DriverError when cert file missing
# ---------------------------------------------------------------------------

def test_internal_driver_missing_cert_raises(tmp_path: Path) -> None:
    driver = InternalCADriver(secrets_dir=str(tmp_path), manifest_path=str(tmp_path / "manifest.yaml"))
    with pytest.raises(DriverError, match="not found"):
        driver.get_chain_info("nonexistent-service")


# ---------------------------------------------------------------------------
# PKI-D-04: ByoCADriver rejects non-HTTPS endpoints
# ---------------------------------------------------------------------------

def test_byo_driver_rejects_http_endpoint(tmp_path: Path) -> None:
    ca_cert = tmp_path / "ca.crt"
    cert_pem, _ = _make_self_signed_pem()
    ca_cert.write_bytes(cert_pem)

    from yashigani.pki.drivers.byo_ca import ByoCADriver

    with pytest.raises(DriverError, match="HTTPS"):
        ByoCADriver(
            ca_cert_path=str(ca_cert),
            signing_endpoint="http://ca.corp.example/v1/sign/tls",
            auth_mode="token",
            signing_token="test-token-12345678",
            secrets_dir=str(tmp_path),
            manifest_path=str(tmp_path / "manifest.yaml"),
        )


# ---------------------------------------------------------------------------
# PKI-D-05: ByoCADriver rejects missing CA cert path env var
# ---------------------------------------------------------------------------

def test_byo_driver_rejects_missing_ca_cert_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("YASHIGANI_BYO_CA_CERT_PATH", raising=False)
    monkeypatch.delenv("YASHIGANI_BYO_SIGNING_ENDPOINT", raising=False)
    monkeypatch.delenv("YASHIGANI_BYO_SIGNING_TOKEN", raising=False)

    from yashigani.pki.drivers.byo_ca import ByoCADriver

    with pytest.raises(DriverError, match="YASHIGANI_BYO_CA_CERT_PATH"):
        ByoCADriver(secrets_dir=str(tmp_path), manifest_path=str(tmp_path / "manifest.yaml"))


# ---------------------------------------------------------------------------
# PKI-D-06: ByoCADriver rejects non-existent CA cert path
# ---------------------------------------------------------------------------

def test_byo_driver_rejects_missing_ca_cert_file(tmp_path: Path) -> None:
    from yashigani.pki.drivers.byo_ca import ByoCADriver

    with pytest.raises(DriverError, match="not found"):
        ByoCADriver(
            ca_cert_path=str(tmp_path / "nonexistent_ca.crt"),
            signing_endpoint="https://ca.corp.example/v1/sign/tls",
            auth_mode="none",
            secrets_dir=str(tmp_path),
            manifest_path=str(tmp_path / "manifest.yaml"),
        )


# ---------------------------------------------------------------------------
# PKI-D-07: driver_factory returns InternalCADriver for mode=internal
# ---------------------------------------------------------------------------

def test_driver_factory_internal(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("YASHIGANI_PKI_CA_MODE", "internal")
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "manifest.yaml"))

    from yashigani.pki.driver_factory import get_ca_driver

    driver = get_ca_driver()
    assert isinstance(driver, InternalCADriver)


# ---------------------------------------------------------------------------
# PKI-D-08: driver_factory raises RuntimeError for unknown mode
# ---------------------------------------------------------------------------

def test_driver_factory_unknown_mode(monkeypatch) -> None:
    monkeypatch.setenv("YASHIGANI_PKI_CA_MODE", "acme-magic")

    from yashigani.pki.driver_factory import get_ca_driver

    with pytest.raises(RuntimeError, match="acme-magic"):
        get_ca_driver()


# ---------------------------------------------------------------------------
# PKI-D-09: CertChainInfo has no private key fields
# ---------------------------------------------------------------------------

def test_cert_chain_info_no_private_key_fields() -> None:
    info = CertChainInfo(
        subject_cn="svc",
        issuer_cn="Intermediate CA",
        serial_hex="deadbeef",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2026-04-01T00:00:00+00:00",
        fingerprint_sha256="a" * 64,
    )
    fields = set(vars(info).keys())
    # Ensure no private key field sneaks in
    for bad in ("private_key", "key", "pem_key", "key_pem", "key_path"):
        assert bad not in fields, f"CertChainInfo must not expose {bad!r}"


# ---------------------------------------------------------------------------
# PKI-D-10: _extract_first_pem returns only first block from multi-cert bundle
# ---------------------------------------------------------------------------

def test_extract_first_pem_from_bundle() -> None:
    cert1_pem, _ = _make_self_signed_pem()
    cert2_pem, _ = _make_self_signed_pem()
    bundle = cert1_pem + cert2_pem

    result = _extract_first_pem(bundle)
    # Should only contain one certificate block
    assert result.count(b"BEGIN CERTIFICATE") == 1
    assert result.count(b"END CERTIFICATE") == 1
    # Should match the first cert
    assert result == cert1_pem


# ---------------------------------------------------------------------------
# PKI-D-11: ByoCADriver rejects invalid auth_mode
# ---------------------------------------------------------------------------

def test_byo_driver_rejects_invalid_auth_mode(tmp_path: Path) -> None:
    from yashigani.pki.drivers.byo_ca import ByoCADriver

    cert_pem, _ = _make_self_signed_pem()
    ca_cert = tmp_path / "ca.crt"
    ca_cert.write_bytes(cert_pem)

    with pytest.raises(DriverError, match="auth_mode"):
        ByoCADriver(
            ca_cert_path=str(ca_cert),
            signing_endpoint="https://ca.corp.example/v1/sign/tls",
            auth_mode="kerberos",  # invalid
            secrets_dir=str(tmp_path),
            manifest_path=str(tmp_path / "manifest.yaml"),
        )


# ---------------------------------------------------------------------------
# PKI-D-12: InternalCADriver.rotate returns RotateResult(success=False) for unknown service
# ---------------------------------------------------------------------------

def test_internal_driver_rotate_unknown_service(tmp_path: Path) -> None:
    """rotate() for a service not in the manifest returns success=False, does not raise."""
    # Create a minimal manifest with no services matching "ghost-service"
    manifest_yaml = tmp_path / "manifest.yaml"
    manifest_yaml.write_text(
        "schema_version: 1\n"
        "services:\n"
        "  - name: real-service\n"
        "    dns_sans: [real-service]\n"
        "    purpose: test\n"
        "    mtls_capable: true\n"
        "    bootstrap_token_sha256: ''\n"
        "    revoked: false\n"
        "cert_policy:\n"
        "  root_lifetime_years_min: 5\n"
        "  root_lifetime_years_max: 20\n"
        "  root_lifetime_years_default: 10\n"
        "  root_rotation_requires_manual_confirmation: true\n"
        "  intermediate_lifetime_days_min: 90\n"
        "  intermediate_lifetime_days_max: 365\n"
        "  intermediate_lifetime_days_default: 180\n"
        "  leaf_lifetime_days_min: 30\n"
        "  leaf_lifetime_days_max: 90\n"
        "  leaf_lifetime_days_default: 90\n"
        "  renewal_threshold: 0.33\n"
        "ca_source:\n"
        "  mode: yashigani_generated\n"
    )
    # Create a fake intermediate cert + key so IssuerPaths.rotate_leaves can run
    cert_pem, key_pem = _make_self_signed_pem()
    (tmp_path / "ca_intermediate.crt").write_bytes(cert_pem)
    (tmp_path / "ca_intermediate.key").write_bytes(key_pem)

    driver = InternalCADriver(secrets_dir=str(tmp_path), manifest_path=str(manifest_yaml))
    result = driver.rotate("ghost-service")

    assert isinstance(result, RotateResult)
    assert result.success is False
    assert result.error is not None
