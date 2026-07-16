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

from yashigani.licensing.enforcer import LicenseFeatureGated, LicenseTier

logger = logging.getLogger(__name__)


def _licence_hard_gate(feature: str) -> None:
    """
    Point-of-use licence gate (LAURA-V2-001 follow-up, 2026-07-16).

    Mirrors sso/oidc.py's `_licence_hard_gate()` — see that function's
    docstring for the full rationale (deliberately a SEPARATE local copy,
    not a shared import, so patching enforcer.require_feature() — or this
    same function as defined in oidc.py/routes/sso.py/routes/scim.py — has
    no effect on this file's own gate). Reads verifier.get_integrity_status()
    (signed, live re-derived) and enforcer.get_enforcer_integrity_status()
    directly; never calls enforcer.require_feature(). Hard-refuses (raises)
    on any integrity violation or missing feature — never silently passes on
    error (IMPL-03).

    One of THREE independent layers for SAML (this provider-level gate,
    backoffice/routes/sso.py's route-level gate, licensing/gate_middleware.py's
    ASGI-level gate) — see gate_middleware.py's module docstring.

    HONEST CEILING (Phase C, 2026-07-16 — mesh-topology note): unlike
    verifier.py/enforcer.py/gate_middleware.py/sso/oidc.py/
    backoffice/routes/sso.py/backoffice/routes/scim.py, this file is NOT one
    of this release's 6 mesh ring members (5 rotation candidates existed —
    gate_middleware.py, oidc.py, saml.py, routes/sso.py, routes/scim.py —
    only 4 were selected; saml.py is the one held out this release, and is
    a candidate for a future release's rotation). It remains protected the
    Phase B way: verifier.py's central live-hash re-derivation (still
    covers SAML_MODULE_HASH) plus this file's own verifier/enforcer-flag
    read below. It does NOT get the additional independent ring-neighbour
    check the other 5 files have this release — a coordinated edit confined
    to verifier.py+enforcer.py+saml.py (3 files, all outside the ring) is
    therefore not covered by the NEW mesh guarantee, only by the pre-existing
    T1-T4+POU mechanism (see verifier.py's module docstring for what that
    mechanism alone can and cannot detect). See gate_middleware.py's module
    docstring for the full honest-ceiling statement covering the ring
    members.
    """
    try:
        from yashigani.licensing import verifier as _verifier
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "SAML provider: could not import verifier/enforcer for integrity "
            "check — treating as violation and refusing (IMPL-03): %s", exc,
        )
        _emit_saml_tamper_event("integrity_module_unavailable", "n/a", "import_failed")
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY) from exc

    try:
        if _verifier.get_integrity_status() or _enforcer.get_enforcer_integrity_status():
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: SAML provider hard-refusing "
                "feature=%s — build integrity violated", feature,
            )
            _emit_saml_tamper_event("build_integrity_violated", "clean", "tampered")
            raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY)
    except LicenseFeatureGated:
        raise
    except Exception as exc:
        logger.critical(
            "SAML provider: integrity check raised — treating as violation "
            "and refusing: %s", exc,
        )
        _emit_saml_tamper_event("integrity_check_raised", "n/a", "raised")
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY) from exc

    try:
        lic = _enforcer.get_license()
    except Exception as exc:
        logger.critical(
            "SAML provider: enforcer.get_license() raised — treating as "
            "violation and refusing: %s", exc,
        )
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY) from exc

    if not lic.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=lic.tier)


def _emit_saml_tamper_event(check_type: str, expected_hash: str, actual_hash: str) -> None:
    """Emit a tamper-evidence audit event at gate-invocation time — own
    inline copy, see gate_middleware.py's twin function for the full
    rationale (LAURA-V2-003: no shared chokepoint). saml.py is not a mesh
    ring member this release (see _licence_hard_gate()'s honest-ceiling
    note above) but still emits on the verifier/enforcer-flag path so
    "any INCOMPLETE tamper is logged" holds uniformly across all 5
    point-of-use gates, not just the 4 ring members."""
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        writer.write(LicenceIntegrityViolationEvent(
            module="sso.saml",
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        ))
    except Exception:
        pass


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
        _licence_hard_gate("saml")
        auth = self._build_auth(request_data)
        return auth.login()

    def process_response(self, request_data: dict) -> SAMLUserInfo:
        """
        Process the IdP SAMLResponse (POST binding).
        Validates signature and returns SAMLUserInfo on success.
        """
        _licence_hard_gate("saml")
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
