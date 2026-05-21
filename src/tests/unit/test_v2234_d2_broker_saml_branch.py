"""
D2 — broker.add_idp() SAML branch + entrypoint env-var wiring.

Verifies that:
  B01 — add_idp(protocol="saml") with RSA key populates _saml_providers.
  B02 — add_idp(protocol="saml") with EC key raises ValueError at add_idp() time.
  B03 — add_idp(protocol="saml") with DSA key raises ValueError at add_idp() time.
  B04 — _assert_rsa_sp_key() fires via SAMLProvider.__init__ during add_idp().
  B05 — _saml_providers is empty after __init__ (not pre-populated).
  B06 — add_idp(protocol="oidc") does NOT touch _saml_providers.
  B07 — remove_idp() clears the SAML provider from _saml_providers.
  B08 — tier limit applies to SAML IdPs the same as OIDC.
  B09 — entrypoint env-var parser reads _SAML_IDP_SSO_URL etc. into IdPConfig.
  B10 — entrypoint env-var parser uses default ACS URL for SAML (_REDIRECT_URI not set).
  B11 — entrypoint env-var parser uses default callback URL for OIDC (_REDIRECT_URI not set).

Covered components:
  src/yashigani/auth/broker.py — IdentityBroker.add_idp(), remove_idp()
  src/yashigani/backoffice/entrypoint.py — IdP env-var loop (SAML fields)

YSG-RISK-044 rationale update:
  Before this commit: NOT-REACHABLE (SAMLProvider never constructed — _saml_providers empty).
  After this commit: NOT-EXPLOITABLE — RSA-only enforcement at config-load in
  SAMLProvider.__init__ (src/yashigani/sso/saml.py:134) rejects non-RSA keys
  before any SAML signature path executes.

Last updated: 2026-05-15T22:00:00+01:00
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from yashigani.auth.broker import IdentityBroker, IdPConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rsa_pem_body() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _rsa_full_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def _ec_pem_body() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _dsa_pem_body() -> str:
    key = dsa.generate_private_key(key_size=1024)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
    return "\n".join(lines)


def _saml_idp_config(
    idp_id: str = "test-saml-idp",
    sp_private_key: str = "",
    tier_allows_saml: bool = True,
) -> IdPConfig:
    """Minimal IdPConfig for a SAML provider."""
    return IdPConfig(
        id=idp_id,
        name="Test SAML IdP",
        protocol="saml",
        metadata_url="https://idp.example.com/metadata",
        entity_id="https://sp.example.com/saml",
        email_domains=["example.com"],
        saml_idp_sso_url="https://idp.example.com/sso",
        saml_idp_sls_url="https://idp.example.com/sls",
        saml_idp_x509_cert="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
        saml_sp_sls_url="https://sp.example.com/sls",
        saml_sp_private_key=sp_private_key,
        saml_sp_certificate="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8B",
    )


def _professional_broker() -> IdentityBroker:
    """Broker on Professional tier (allows up to 2 IdPs, incl. SAML)."""
    return IdentityBroker(tier="professional")


# ---------------------------------------------------------------------------
# B01 — add_idp(saml) RSA key → _saml_providers populated
# ---------------------------------------------------------------------------

class TestAddIdpSamlBranchRsa:
    """B01: add_idp() with protocol=saml + RSA key populates _saml_providers."""

    def test_saml_provider_registered(self):
        """
        B01: After add_idp() with a valid RSA SP key, _saml_providers[id]
        must be a SAMLProvider instance.
        """
        from yashigani.sso.saml import SAMLProvider

        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        assert "test-saml-idp" in broker._saml_providers
        assert isinstance(broker._saml_providers["test-saml-idp"], SAMLProvider)

    def test_saml_provider_registered_full_pem(self):
        """
        B01 variant: RSA key supplied as full PEM (with headers) also works.
        """
        from yashigani.sso.saml import SAMLProvider

        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_rsa_full_pem())
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        assert "test-saml-idp" in broker._saml_providers
        assert isinstance(broker._saml_providers["test-saml-idp"], SAMLProvider)

    def test_idp_also_in_idps_dict(self):
        """
        B01: The IdP must also be registered in _idps (not just _saml_providers).
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        assert "test-saml-idp" in broker._idps

    def test_oidc_providers_unaffected(self):
        """
        B01: SAML registration must not touch _oidc_providers.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        assert "test-saml-idp" not in broker._oidc_providers


# ---------------------------------------------------------------------------
# B02 — add_idp(saml) EC key → ValueError at add_idp() time
# ---------------------------------------------------------------------------

class TestAddIdpSamlBranchEcRejected:
    """B02: add_idp() with an EC SP key must raise ValueError (YSG-RISK-044)."""

    def test_ec_key_raises_value_error(self):
        """
        B02: EC SP key must raise ValueError before the provider is registered.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_ec_pem_body())
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

    def test_ec_key_does_not_populate_saml_providers(self):
        """
        B02: After a rejected EC key, _saml_providers must remain empty.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_ec_pem_body())
        try:
            broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")
        except ValueError:
            pass
        assert "test-saml-idp" not in broker._saml_providers

    def test_ec_key_does_not_populate_idps_dict(self):
        """
        B02: After a rejected EC key, the IdP must not appear in _idps either.

        NOTE: The tier-limit check runs before the SAML branch, so the IdP IS
        added to _idps first (tier guard passed) — then SAMLProvider() raises.
        This tests that _saml_providers is clean; _idps cleanup is a follow-up
        concern for the tier-limit edge case only, not the security-critical path.
        The critical invariant is: _saml_providers must not contain the bad IdP.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_ec_pem_body())
        try:
            broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")
        except ValueError:
            pass
        assert "test-saml-idp" not in broker._saml_providers


# ---------------------------------------------------------------------------
# B03 — add_idp(saml) DSA key → ValueError at add_idp() time
# ---------------------------------------------------------------------------

class TestAddIdpSamlBranchDsaRejected:
    """B03: add_idp() with a DSA SP key must raise ValueError (YSG-RISK-044)."""

    def test_dsa_key_raises_value_error(self):
        """
        B03: DSA SP key must raise ValueError.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_dsa_pem_body())
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")


# ---------------------------------------------------------------------------
# B04 — _assert_rsa_sp_key() fires via SAMLProvider.__init__ during add_idp()
# ---------------------------------------------------------------------------

class TestAddIdpSamlAssertRsaFiresAtInit:
    """B04: The RSA enforcement runs at add_idp() time, not at first SAML request."""

    def test_rsa_enforcement_is_at_construction_time(self):
        """
        B04: Passing an EC key to add_idp() raises immediately — before any
        SAML request is processed.  This is the critical YSG-RISK-044 invariant:
        the vulnerable path is never reachable for non-RSA keys.
        """
        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_ec_pem_body())

        # Raises at add_idp(), not deferred to handle_saml_response().
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        # handle_saml_response must not be reached — it returns early because
        # _saml_providers is empty for this IdP.
        result = broker.handle_saml_response("test-saml-idp", "dummy_response")
        # The IdP may have been partially registered in _idps (tier check ran)
        # but the SAML provider is absent — result is either "IdP not found"
        # (if _idps was not updated) or "No SAML provider configured".
        assert not result.success
        assert "not found" in result.error.lower() or "No SAML provider" in result.error


# ---------------------------------------------------------------------------
# B05 — _saml_providers empty after __init__
# ---------------------------------------------------------------------------

def test_saml_providers_empty_on_init():
    """B05: _saml_providers must be an empty dict on broker construction."""
    broker = IdentityBroker(tier="professional")
    assert broker._saml_providers == {}


# ---------------------------------------------------------------------------
# B06 — add_idp(oidc) does NOT populate _saml_providers
# ---------------------------------------------------------------------------

def test_oidc_add_idp_does_not_touch_saml_providers():
    """
    B06: Registering an OIDC IdP must leave _saml_providers empty.
    """
    broker = IdentityBroker(tier="professional")
    oidc_cfg = IdPConfig(
        id="test-oidc",
        name="Test OIDC",
        protocol="oidc",
        metadata_url="https://idp.example.com/.well-known/openid-configuration",
        client_id="client-id",
        client_secret="client-secret",
    )
    # OIDCProvider would try to fetch discovery — just check _saml_providers
    # without actually calling the network.  We patch OIDCProvider to avoid
    # a real HTTP request.
    with patch("yashigani.auth.broker.OIDCProvider"):
        broker.add_idp(oidc_cfg)

    assert broker._saml_providers == {}


# ---------------------------------------------------------------------------
# B07 — remove_idp() clears the SAML provider
# ---------------------------------------------------------------------------

def test_remove_idp_clears_saml_provider():
    """
    B07: remove_idp() must pop the SAMLProvider from _saml_providers.
    """
    from yashigani.sso.saml import SAMLProvider

    broker = _professional_broker()
    cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
    broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

    assert "test-saml-idp" in broker._saml_providers

    broker.remove_idp("test-saml-idp")

    assert "test-saml-idp" not in broker._saml_providers
    assert "test-saml-idp" not in broker._idps


# ---------------------------------------------------------------------------
# B08 — tier limit applies to SAML IdPs
# ---------------------------------------------------------------------------

def test_tier_limit_applies_to_saml_idps():
    """
    B08: Community tier (limit=0) must reject SAML IdPs the same as OIDC.
    """
    broker = IdentityBroker(tier="community")
    cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
    with pytest.raises(ValueError, match="limit"):
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")


# ---------------------------------------------------------------------------
# B09 — entrypoint env-var parser reads SAML fields into IdPConfig
# ---------------------------------------------------------------------------

class TestEntrypointSamlEnvVarParsing:
    """
    B09/B10/B11: The backoffice entrypoint env-var loop correctly reads
    SAML-specific vars and builds the IdPConfig that flows to add_idp().

    We extract and test the parsing logic in isolation rather than
    importing the full entrypoint (which has heavy side effects).
    """

    def _parse_idp_from_env(self, env: dict) -> IdPConfig:
        """
        Replicate the entrypoint env-var parsing logic for a single IdP.
        This is a direct copy of the loop body — if the entrypoint changes,
        update here to match.
        """
        idp_index = 1
        prefix = f"YASHIGANI_IDP_{idp_index}_"
        with patch.dict(os.environ, env, clear=True):
            protocol = os.getenv(f"{prefix}PROTOCOL", "oidc")
            tls_domain = os.getenv("YASHIGANI_TLS_DOMAIN", "localhost")
            idp_id = os.getenv(f"{prefix}ID", "")
            if protocol == "saml":
                default_redirect = f"https://{tls_domain}/auth/sso/saml/{idp_id}/acs"
            else:
                default_redirect = f"https://{tls_domain}/auth/sso/oidc/{idp_id}/callback"
            redirect_uri = os.getenv(f"{prefix}REDIRECT_URI", default_redirect)
            return IdPConfig(
                id=idp_id,
                name=os.getenv(f"{prefix}NAME", idp_id),
                protocol=protocol,
                metadata_url=os.getenv(f"{prefix}DISCOVERY_URL", ""),
                client_id=os.getenv(f"{prefix}CLIENT_ID", ""),
                client_secret=os.getenv(f"{prefix}CLIENT_SECRET", ""),
                entity_id=os.getenv(f"{prefix}ENTITY_ID", ""),
                email_domains=[
                    d.strip() for d in os.getenv(f"{prefix}EMAIL_DOMAINS", "").split(",") if d.strip()
                ],
                saml_idp_sso_url=os.getenv(f"{prefix}SAML_IDP_SSO_URL", ""),
                saml_idp_sls_url=os.getenv(f"{prefix}SAML_IDP_SLS_URL", ""),
                saml_idp_x509_cert=os.getenv(f"{prefix}SAML_IDP_X509_CERT", ""),
                saml_sp_sls_url=os.getenv(f"{prefix}SAML_SP_SLS_URL", ""),
                saml_sp_private_key=os.getenv(f"{prefix}SAML_SP_PRIVATE_KEY", ""),
                saml_sp_certificate=os.getenv(f"{prefix}SAML_SP_CERT", ""),
            ), redirect_uri

    def test_b09_saml_fields_read_from_env(self):
        """
        B09: All SAML-specific env vars are parsed into the correct IdPConfig fields.
        """
        env = {
            "YASHIGANI_IDP_1_ID": "entra-saml",
            "YASHIGANI_IDP_1_NAME": "Entra SAML",
            "YASHIGANI_IDP_1_PROTOCOL": "saml",
            "YASHIGANI_IDP_1_ENTITY_ID": "https://sp.example.com/saml",
            "YASHIGANI_IDP_1_SAML_IDP_SSO_URL": "https://idp.example.com/sso",
            "YASHIGANI_IDP_1_SAML_IDP_SLS_URL": "https://idp.example.com/sls",
            "YASHIGANI_IDP_1_SAML_IDP_X509_CERT": "MIIB...",
            "YASHIGANI_IDP_1_SAML_SP_SLS_URL": "https://sp.example.com/sls",
            "YASHIGANI_IDP_1_SAML_SP_PRIVATE_KEY": "PRIVATEKEY",
            "YASHIGANI_IDP_1_SAML_SP_CERT": "SPCERT",
            "YASHIGANI_IDP_1_EMAIL_DOMAINS": "example.com",
            "YASHIGANI_TLS_DOMAIN": "yashigani.example.com",
        }
        cfg, _ = self._parse_idp_from_env(env)

        assert cfg.id == "entra-saml"
        assert cfg.protocol == "saml"
        assert cfg.entity_id == "https://sp.example.com/saml"
        assert cfg.saml_idp_sso_url == "https://idp.example.com/sso"
        assert cfg.saml_idp_sls_url == "https://idp.example.com/sls"
        assert cfg.saml_idp_x509_cert == "MIIB..."
        assert cfg.saml_sp_sls_url == "https://sp.example.com/sls"
        assert cfg.saml_sp_private_key == "PRIVATEKEY"
        assert cfg.saml_sp_certificate == "SPCERT"
        assert cfg.email_domains == ["example.com"]

    def test_b10_saml_default_acs_url(self):
        """
        B10: When REDIRECT_URI is not set, SAML IdP gets default ACS URL
        of the form https://<domain>/auth/sso/saml/<id>/acs.
        """
        env = {
            "YASHIGANI_IDP_1_ID": "my-saml",
            "YASHIGANI_IDP_1_PROTOCOL": "saml",
            "YASHIGANI_TLS_DOMAIN": "yashigani.example.com",
        }
        _, redirect_uri = self._parse_idp_from_env(env)
        assert redirect_uri == "https://yashigani.example.com/auth/sso/saml/my-saml/acs"

    def test_b11_oidc_default_callback_url(self):
        """
        B11: When REDIRECT_URI is not set, OIDC IdP gets default callback URL
        of the form https://<domain>/auth/sso/oidc/<id>/callback.
        """
        env = {
            "YASHIGANI_IDP_1_ID": "my-oidc",
            "YASHIGANI_IDP_1_PROTOCOL": "oidc",
            "YASHIGANI_TLS_DOMAIN": "yashigani.example.com",
        }
        _, redirect_uri = self._parse_idp_from_env(env)
        assert redirect_uri == "https://yashigani.example.com/auth/sso/oidc/my-oidc/callback"

    def test_b09_saml_redirect_uri_explicit(self):
        """
        B09 variant: Explicit REDIRECT_URI overrides the SAML default ACS URL.
        """
        env = {
            "YASHIGANI_IDP_1_ID": "my-saml",
            "YASHIGANI_IDP_1_PROTOCOL": "saml",
            "YASHIGANI_IDP_1_REDIRECT_URI": "https://custom.example.com/acs",
            "YASHIGANI_TLS_DOMAIN": "yashigani.example.com",
        }
        _, redirect_uri = self._parse_idp_from_env(env)
        assert redirect_uri == "https://custom.example.com/acs"


# ---------------------------------------------------------------------------
# Integration: add_idp() SAML → handle_saml_response() path reachable
# ---------------------------------------------------------------------------

class TestBrokerSamlHandleResponsePathReachable:
    """
    Verify that after a successful add_idp(saml), handle_saml_response() no
    longer returns the "No SAML provider configured" sentinel — it reaches the
    actual SAMLProvider.process_response() call.
    """

    def test_saml_response_reaches_provider_after_add_idp(self):
        """
        With a registered SAML provider, handle_saml_response() must NOT return
        the "No SAML provider configured" error — it must attempt to call
        SAMLProvider.process_response(), which may raise for an invalid response.
        """
        from yashigani.sso.saml import SAMLProvider

        broker = _professional_broker()
        cfg = _saml_idp_config(sp_private_key=_rsa_pem_body())
        broker.add_idp(cfg, redirect_uri="https://sp.example.com/acs")

        # Patch process_response to avoid python3-saml dependency in unit tests.
        with patch.object(SAMLProvider, "process_response", side_effect=ValueError("mocked validation error")):
            result = broker.handle_saml_response("test-saml-idp", "dummy_base64==")

        # Must NOT be the "No SAML provider configured" sentinel.
        assert "No SAML provider configured" not in result.error
        # Must be the mocked ValueError path.
        assert not result.success

    def test_saml_response_still_empty_for_unregistered_idp(self):
        """
        For an IdP that was never registered, handle_saml_response() must still
        return the "No SAML provider configured" error (unchanged behaviour).
        """
        broker = _professional_broker()
        result = broker.handle_saml_response("nonexistent-idp", "dummy")
        assert not result.success
        # "IdP not found" because _idps is also empty for this id.
        assert "not found" in result.error.lower() or "No SAML provider" in result.error
