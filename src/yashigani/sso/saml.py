"""
Yashigani SSO — SAMLv2 Service Provider.
Validates assertions from the IdP and resolves user identity.

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from yashigani.licensing.enforcer import require_feature

logger = logging.getLogger(__name__)


def _assert_rsa_sp_key(sp_private_key: str) -> None:
    """
    Enforce that the SAML SP private key is RSA.

    YSG-RISK-044 (CVE-2026-41989): libgcrypt ECDH heap-buffer-overflow is
    only reachable when the SP key is EC-type (ECDH-ES key-transport path).
    RSA SP keys route to a different decryption path and do not reach the
    vulnerable C code in gcry_pk_decrypt.

    This check is performed once at SAMLProvider init time — not on every
    SAML request.  Fail-closed: any non-RSA key type disables SAML entirely.

    python3-saml stores the private key as a PEM body without headers, so
    we reconstruct the full PEM before parsing.
    """
    # Reconstruct the full PEM block from the stripped body that python3-saml
    # uses internally.  The key may already carry headers if the caller passes
    # a full PEM — strip and reformat to be safe.
    stripped = sp_private_key.strip()
    if "BEGIN" in stripped:
        # Full PEM already — pass through as-is.
        pem_bytes = stripped.encode("ascii")
    else:
        # python3-saml format: base64 body, no headers.
        # Wrap as PRIVATE KEY (PKCS#8) first; if that fails, try RSA PRIVATE KEY.
        pem_bytes = (
            "-----BEGIN PRIVATE KEY-----\n"
            + stripped
            + "\n-----END PRIVATE KEY-----\n"
        ).encode("ascii")

    try:
        key = load_pem_private_key(pem_bytes, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # The PKCS#8 wrapper failed — try legacy RSA PEM header.
        pem_bytes_rsa = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + stripped
            + "\n-----END RSA PRIVATE KEY-----\n"
        ).encode("ascii")
        try:
            key = load_pem_private_key(pem_bytes_rsa, password=None)
        except Exception as exc:
            raise ValueError(
                f"SAML SP key could not be parsed as a PEM private key "
                f"(YSG-RISK-044). "
                f"Regenerate with: openssl genrsa -out sp_key.pem 4096"
            ) from exc
    except Exception as exc:
        raise ValueError(
            f"SAML SP key could not be loaded: {exc!r} "
            f"(YSG-RISK-044). "
            f"Regenerate with: openssl genrsa -out sp_key.pem 4096"
        ) from exc

    if not isinstance(key, RSAPrivateKey):
        raise ValueError(
            f"SAML SP key must be RSA (mitigates YSG-RISK-044 / CVE-2026-41989). "
            f"Got: {type(key).__name__}. "
            f"EC/EdDSA/DSA SP keys are not permitted — PQR support is deferred. "
            f"Regenerate with: openssl genrsa -out sp_key.pem 4096"
        )


def _import_saml():
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        return OneLogin_Saml2_Auth, OneLogin_Saml2_Settings
    except ImportError as exc:
        raise ImportError(
            "python3-saml is required for SAMLv2. "
            "Install with: pip install python3-saml"
        ) from exc


@dataclass
class SAMLConfig:
    sp_entity_id: str
    sp_acs_url: str             # Assertion Consumer Service URL
    sp_sls_url: str             # Single Logout Service URL
    idp_entity_id: str
    idp_sso_url: str
    idp_sls_url: str
    idp_x509_cert: str          # IdP signing certificate (PEM, no headers)
    sp_private_key: str         # SP private key (PEM, no headers)
    sp_certificate: str         # SP certificate (PEM, no headers)
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


@dataclass
class SAMLUserInfo:
    subject: str                # NameID value
    email: Optional[str]
    attributes: dict            # all assertion attributes
    session_index: Optional[str]
    # V6.8.4 — AuthnContextClassRef from the SAML assertion.
    # Extracted via python3-saml's get_last_authn_contexts() if available,
    # or from the raw XML as a fallback.  Empty string when not present.
    authn_context_class_ref: str = ""
    # AuthnInstant from the AuthnStatement (ISO 8601 string or empty).
    authn_instant: str = ""


class SAMLProvider:
    """
    SAMLv2 Service Provider using python3-saml (OneLogin).
    """

    def __init__(self, config: SAMLConfig) -> None:
        # YSG-RISK-044 (CVE-2026-41989): enforce RSA SP key at init time.
        # Raises ValueError immediately if the key is non-RSA.
        _assert_rsa_sp_key(config.sp_private_key)
        self._config = config

    def get_login_url(self, request_data: dict) -> str:
        """Build the IdP redirect URL for SP-initiated SSO."""
        require_feature("saml")
        auth = self._build_auth(request_data)
        return auth.login()

    def process_response(self, request_data: dict) -> SAMLUserInfo:
        """
        Process the IdP SAMLResponse (POST binding).
        Validates signature and returns SAMLUserInfo on success.
        """
        require_feature("saml")
        auth = self._build_auth(request_data)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise ValueError(
                f"SAML response errors: {errors}. "
                f"Reason: {auth.get_last_error_reason()}"
            )
        if not auth.is_authenticated():
            raise ValueError("SAML authentication failed — not authenticated after response")

        attrs = auth.get_attributes()
        name_id = auth.get_nameid()
        email = None
        if "email" in attrs:
            email = attrs["email"][0]
        elif "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" in attrs:
            email = attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"][0]

        # V6.8.4 — extract AuthnContextClassRef from the assertion.
        # python3-saml (onelogin) >= 2.8.0 exposes get_last_authn_contexts().
        # Older versions don't have it; fall back to empty string gracefully.
        authn_context_class_ref = ""
        authn_instant = ""
        try:
            # get_last_authn_contexts() returns a list of dicts, each with
            # keys 'authnContextClassRef' and 'authnContextDeclRef'.
            contexts = auth.get_last_authn_contexts()
            if contexts:
                authn_context_class_ref = contexts[0].get("authnContextClassRef", "") or ""
        except AttributeError:
            # Method not available in older python3-saml versions; safe to ignore.
            pass

        return SAMLUserInfo(
            subject=name_id,
            email=email,
            attributes={k: v[0] if len(v) == 1 else v for k, v in attrs.items()},
            session_index=auth.get_session_index(),
            authn_context_class_ref=authn_context_class_ref,
            authn_instant=authn_instant,
        )

    # -- Internal ------------------------------------------------------------

    def _build_auth(self, request_data: dict):
        OneLogin_Saml2_Auth, _ = _import_saml()
        settings = self._build_settings()
        return OneLogin_Saml2_Auth(request_data, custom_base_path=None, settings=settings)

    def _build_settings(self) -> dict:
        c = self._config
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": c.sp_entity_id,
                "assertionConsumerService": {
                    "url": c.sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url": c.sp_sls_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "NameIDFormat": c.name_id_format,
                "x509cert": c.sp_certificate,
                "privateKey": c.sp_private_key,
            },
            "idp": {
                "entityId": c.idp_entity_id,
                "singleSignOnService": {
                    "url": c.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "singleLogoutService": {
                    "url": c.idp_sls_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": c.idp_x509_cert,
            },
            "security": {
                "nameIdEncrypted": False,
                "authnRequestsSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
                "signMetadata": True,
                "wantMessagesSigned": True,
                "wantAssertionsSigned": True,
                "wantNameIdEncrypted": False,
                "requestedAuthnContext": True,
                "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            },
        }
