"""
Unit tests for YSG-RISK-044 mitigation — RSA SP key enforcement at SAMLProvider init.

CVE-2026-41989: libgcrypt ECDH heap-buffer-overflow.  The vulnerable code path
(gcry_pk_decrypt on ECDH-ES key transport) is only reachable when the SP private
key is EC-type.  RSA SP keys route to a different xmlsec1/libgcrypt path and do
not reach the vulnerable C call.

Enforcement point:
  src/yashigani/sso/saml.py  — _assert_rsa_sp_key(), called from SAMLProvider.__init__

Test matrix:
  T1 — RSA key (PKCS#8 PEM body) is accepted; SAMLProvider initialises without error.
  T2 — EC key (P-256, PKCS#8 PEM body) raises ValueError with clear message.
  T3 — DSA key (PKCS#8 PEM body) raises ValueError with clear message.
  T4 — Exception message from EC rejection contains "YSG-RISK-044".
  T5 — Exception message from EC rejection contains the openssl genrsa remediation command.
  T6 — Full PEM (with headers) is also accepted for RSA keys.
  T7 — Full PEM (with headers) is rejected for EC keys.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from yashigani.sso.saml import SAMLConfig, SAMLProvider, _assert_rsa_sp_key


# ---------------------------------------------------------------------------
# Key-generation helpers (used by fixtures + direct tests)
# ---------------------------------------------------------------------------

def _rsa_pem_body() -> str:
    """Generate a minimal 2048-bit RSA key; return the PKCS#8 PEM body (no headers)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")
    # Strip -----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY----- headers
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _ec_pem_body() -> str:
    """Generate a P-256 EC key; return the PKCS#8 PEM body (no headers)."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _dsa_pem_body() -> str:
    """Generate a DSA key; return the PKCS#8 PEM body (no headers)."""
    key = dsa.generate_private_key(key_size=1024)
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _rsa_full_pem() -> str:
    """Generate a 2048-bit RSA key; return the full PKCS#8 PEM (with headers)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")


def _ec_full_pem() -> str:
    """Generate a P-256 EC key; return the full PKCS#8 PEM (with headers)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")


def _minimal_saml_config(sp_private_key: str) -> SAMLConfig:
    """Build a SAMLConfig that will only be used to reach the key-type check."""
    return SAMLConfig(
        sp_entity_id="https://sp.example.com/saml",
        sp_acs_url="https://sp.example.com/saml/acs",
        sp_sls_url="https://sp.example.com/saml/sls",
        idp_entity_id="https://idp.example.com/saml",
        idp_sso_url="https://idp.example.com/saml/sso",
        idp_sls_url="https://idp.example.com/saml/sls",
        idp_x509_cert="dummycert",
        sp_private_key=sp_private_key,
        sp_certificate="dummycert",
    )


# ---------------------------------------------------------------------------
# T1 — RSA key (no headers) is accepted
# ---------------------------------------------------------------------------

def test_rsa_key_accepted() -> None:
    """
    T1: An RSA PKCS#8 PEM body (no headers) must not raise.
    SAMLProvider.__init__ must complete without error.
    """
    _assert_rsa_sp_key(_rsa_pem_body())  # must not raise


# ---------------------------------------------------------------------------
# T2 — EC key (P-256, no headers) is rejected
# ---------------------------------------------------------------------------

def test_ec_key_rejected() -> None:
    """
    T2: A P-256 EC PKCS#8 PEM body must raise ValueError.
    """
    with pytest.raises(ValueError):
        _assert_rsa_sp_key(_ec_pem_body())


# ---------------------------------------------------------------------------
# T3 — DSA key (no headers) is rejected
# ---------------------------------------------------------------------------

def test_dsa_key_rejected() -> None:
    """
    T3: A DSA PKCS#8 PEM body must raise ValueError.
    """
    with pytest.raises(ValueError):
        _assert_rsa_sp_key(_dsa_pem_body())


# ---------------------------------------------------------------------------
# T4 — Error message cites YSG-RISK-044
# ---------------------------------------------------------------------------

def test_error_message_cites_acs_risk_044() -> None:
    """
    T4: The ValueError raised for an EC key must mention YSG-RISK-044.
    """
    with pytest.raises(ValueError, match="YSG-RISK-044"):
        _assert_rsa_sp_key(_ec_pem_body())


# ---------------------------------------------------------------------------
# T5 — Error message cites the remediation command
# ---------------------------------------------------------------------------

def test_error_message_cites_remediation() -> None:
    """
    T5: The ValueError raised for an EC key must include the openssl genrsa command.
    """
    with pytest.raises(ValueError, match="openssl genrsa"):
        _assert_rsa_sp_key(_ec_pem_body())


# ---------------------------------------------------------------------------
# T6 — Full RSA PEM (with headers) is also accepted
# ---------------------------------------------------------------------------

def test_rsa_full_pem_accepted() -> None:
    """
    T6: A full PKCS#8 RSA PEM (with headers) must also be accepted.
    Callers that pass full PEM rather than the stripped body are not rejected.
    """
    _assert_rsa_sp_key(_rsa_full_pem())  # must not raise


# ---------------------------------------------------------------------------
# T7 — Full EC PEM (with headers) is rejected
# ---------------------------------------------------------------------------

def test_ec_full_pem_rejected() -> None:
    """
    T7: A full PKCS#8 EC PEM (with headers) is still rejected with clear message.
    """
    with pytest.raises(ValueError, match="YSG-RISK-044"):
        _assert_rsa_sp_key(_ec_full_pem())


# ---------------------------------------------------------------------------
# Integration: SAMLProvider.__init__ surface
# ---------------------------------------------------------------------------

def test_saml_provider_init_rsa_succeeds() -> None:
    """
    SAMLProvider.__init__ must complete without error for an RSA key.
    (The provider is not usable without python3-saml but the init guard fires first.)
    """
    cfg = _minimal_saml_config(_rsa_pem_body())
    # Must not raise at __init__ time.
    SAMLProvider(cfg)


def test_saml_provider_init_ec_raises() -> None:
    """
    SAMLProvider.__init__ must raise ValueError for an EC SP key,
    before any SAML library interaction occurs.
    """
    cfg = _minimal_saml_config(_ec_pem_body())
    with pytest.raises(ValueError, match="YSG-RISK-044"):
        SAMLProvider(cfg)


def test_saml_provider_init_dsa_raises() -> None:
    """
    SAMLProvider.__init__ must raise ValueError for a DSA SP key.
    """
    cfg = _minimal_saml_config(_dsa_pem_body())
    with pytest.raises(ValueError, match="YSG-RISK-044"):
        SAMLProvider(cfg)
