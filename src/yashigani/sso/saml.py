"""
Yashigani SSO — SAMLv2 Service Provider.
Validates assertions from the IdP and resolves user identity.

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from yashigani.licensing import _integrity
from yashigani.licensing.enforcer import LicenseFeatureGated, LicenseTier

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mesh FULL-graph check (licence-hardening-v2 Phase D, 2026-07-17 —
# LAURA-V2-003 RE-VERIFY hardening). See licensing/verifier.py's
# module-level comment block above _check_mesh_full() for the full
# rationale. saml.py is a full mesh member for the FIRST time as of Phase D
# — Phase C held it out of the 6-file ring entirely, leaving it with zero
# independent peer-check of its own (only the shared verifier/enforcer-flag
# fallback, which Laura's 4-file re-verify attack exploited alongside
# gate_middleware.py + routes/sso.py to fully, silently defeat all three of
# SAML's real enforcement layers). This is saml.py's OWN
# independently-authored copy — deliberately a DIFFERENT code shape
# (functional map()/all() pass over the peer list) from verifier.py's
# for-loop, enforcer.py's list-comprehension, gate_middleware.py's class,
# sso/oidc.py's while-loop, routes/sso.py's dict-comprehension+any(), and
# routes/scim.py's recursion, so a single AST/regex strip-script cannot
# pattern-match and remove all seven at once.
# ---------------------------------------------------------------------------

_MESH_ROLE = "SAML"
_mesh_integrity_violated = False


def _mesh_targets() -> dict:
    sso_dir = Path(__file__).parent
    pkg_dir = sso_dir.parent
    licensing_dir = pkg_dir / "licensing"
    return {
        "VERIFIER": ("VERIFIER_HASH", licensing_dir / "verifier.py"),
        "ENFORCER": ("ENFORCER_HASH", licensing_dir / "enforcer.py"),
        "GATE_MIDDLEWARE": ("GATE_MIDDLEWARE_HASH", licensing_dir / "gate_middleware.py"),
        "OIDC": ("OIDC_MODULE_HASH", sso_dir / "oidc.py"),
        "SAML": ("SAML_MODULE_HASH", sso_dir / "saml.py"),
        "SSO_ROUTES": ("SSO_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "sso.py"),
        "SCIM_ROUTES": ("SCIM_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "scim.py"),
    }


def _peer_ok(role: str, targets: dict) -> bool:
    """Return True iff `role`'s live hash matches its signed value. Base
    predicate for the functional map()/all() pass below."""
    const_name, path = targets[role]
    expected = getattr(_integrity, const_name, "")
    try:
        live = hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception as exc:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (sso/saml.py) — "
            "could not read mesh peer role=%s (%s): %s", role, path, exc,
        )
        return False
    if live != expected:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (sso/saml.py) — "
            "mesh peer role=%s (%s) live hash mismatch (expected=%s, "
            "actual=%s) — independent detection (LAURA-V2-003 Phase D "
            "hardening)",
            role, const_name, expected[:16], live[:16],
        )
        return False
    return True


def _check_mesh_full() -> None:
    """Style: functional map()/all() pass over the full peer list — the
    result is computed eagerly (a list, not a lazy generator) so every peer
    is checked and every mismatch is logged, not short-circuited on the
    first failure."""
    global _mesh_integrity_violated
    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"
    targets = _mesh_targets()

    if _integrity.is_any_hash_placeholder() or _integrity.is_mesh_topology_placeholder():
        if not is_dev:
            _mesh_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh full-check (sso/saml.py) "
                "— hash or topology constants still placeholders in a "
                "non-dev environment; hard-refusing"
            )
        return

    try:
        member_order = json.loads(_integrity.MESH_TOPOLOGY_JSON)["member_order"]
        if not isinstance(member_order, list) or sorted(member_order) != sorted(targets):
            raise ValueError("member_order is not a permutation of the 7 mesh roles")
        if member_order.count(_MESH_ROLE) != 1:
            raise ValueError("member_order missing this file's role")
    except Exception as exc:
        _mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (sso/saml.py) — "
            "MESH_TOPOLOGY_JSON malformed or missing this file's role: %s", exc,
        )
        return

    peers = [role for role in member_order if role != _MESH_ROLE]
    results = list(map(lambda role: _peer_ok(role, targets), peers))
    if not all(results):
        _mesh_integrity_violated = True


def get_mesh_integrity_status() -> bool:
    """Return True if this file's independent full-mesh check has detected
    a tampered peer (LAURA-V2-003 Phase D hardening)."""
    return _mesh_integrity_violated


def _emit_saml_tamper_event(check_type: str, expected_hash: str, actual_hash: str) -> None:
    """Emit a tamper-evidence audit event at gate-invocation time — own
    inline copy, see gate_middleware.py's twin function for the full
    rationale (LAURA-V2-003: no shared chokepoint)."""
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


# ---------------------------------------------------------------------------
# Root-of-trust pin (LAURA-V2-005, 2026-07-17) — this file's OWN copy of the
# _integrity.py root-of-trust pin. See licensing/verifier.py's module-level
# comment block above _check_integrity_root_pin() for the full rationale
# (self-reference solved by hardcoding the expected hash HERE, injected at
# build time before this file's own SAML_MODULE_HASH is computed — no
# circularity) and the named residual (covers only the 5 root-of-trust
# fields; the rest of _integrity.py stays covered by BUNDLE_SIG/
# INTEGRITY_HASH). Style: ternary-assembled verdict, mirroring this file's
# existing map()/all() functional flavour above.
# ---------------------------------------------------------------------------

_EXPECTED_INTEGRITY_ROOT_HASH: str = "a76fbc6aff00e77042ab977b73911a7318684232d3c24f4cb05750e866962573"


def _live_integrity_root_hash() -> str:
    canonical = "\n".join([
        f"MASTER_ANCHOR_SET_JSON={_integrity.MASTER_ANCHOR_SET_JSON}",
        f"CODE_LEAF_CERT_JSON={_integrity.CODE_LEAF_CERT_JSON}",
        f"CODE_LEAF_CERT_SIG={_integrity.CODE_LEAF_CERT_SIG}",
        f"KILL_LIST_JSON={_integrity.KILL_LIST_JSON}",
        f"CLIENT_DOMAIN_REGISTRY_JSON={_integrity.CLIENT_DOMAIN_REGISTRY_JSON}",
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_integrity_root_pin() -> None:
    global _mesh_integrity_violated
    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"
    is_placeholder = "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH" in _EXPECTED_INTEGRITY_ROOT_HASH
    mismatch = (not is_placeholder) and (_live_integrity_root_hash() != _EXPECTED_INTEGRITY_ROOT_HASH)

    violated = mismatch or (is_placeholder and not is_dev)
    if violated:
        _mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: root-of-trust pin (sso/saml.py) — "
            "%s (LAURA-V2-005)",
            "_EXPECTED_INTEGRITY_ROOT_HASH is still a placeholder in a "
            "non-dev environment" if is_placeholder else
            "_integrity.py's root-of-trust fields do not match this file's "
            "hardcoded pin — _integrity.py has been modified since this "
            "build was signed",
        )


_check_mesh_full()
_check_integrity_root_pin()


def _licence_hard_gate(feature: str) -> None:
    """
    Point-of-use licence gate (LAURA-V2-001 follow-up, 2026-07-16; Phase D
    full-mesh hardening, 2026-07-17 — saml.py is a full mesh member for the
    FIRST time this phase).

    Mirrors sso/oidc.py's `_licence_hard_gate()` — see that function's
    docstring for the full rationale (deliberately a SEPARATE local copy,
    not a shared import, so patching enforcer.require_feature() — or this
    same function as defined in oidc.py/routes/sso.py/routes/scim.py — has
    no effect on this file's own gate). Never calls
    enforcer.require_feature(). Hard-refuses (raises) on any integrity
    violation or missing feature — never silently passes on error (IMPL-03).

    One of THREE independent layers for SAML (this provider-level gate,
    backoffice/routes/sso.py's route-level gate, licensing/gate_middleware.py's
    ASGI-level gate) — see gate_middleware.py's module docstring.

    HONEST CEILING (Phase D, 2026-07-17 — mesh-topology note, supersedes
    Phase C which held this file OUT of the ring entirely): saml.py is now
    a full mesh member — its integrity decision comes SOLELY from
    `_mesh_integrity_violated` (this file's own inline full-mesh check of
    every OTHER mesh member's bytes, _check_mesh_full() above), exactly
    like the other 6 mesh files. No fallback to
    verifier.get_integrity_status()/enforcer.get_enforcer_integrity_status()
    is consulted. Phase C's gap here (zero independent peer-check of its
    own, only the shared verifier/enforcer-getter fallback) was exactly
    what Laura's 4-file re-verify attack ({verifier.py, enforcer.py,
    gate_middleware.py, routes/sso.py}) exploited to fully, silently defeat
    all three of SAML's real enforcement layers at once — closed by this
    fix. See gate_middleware.py's module docstring for the full
    honest-ceiling statement covering all 7 mesh members.
    """
    if _mesh_integrity_violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: SAML provider hard-refusing "
            "feature=%s — this file's own full-mesh check detected a "
            "tampered peer (LAURA-V2-003 Phase D hardening, no fallback to "
            "verifier.py/enforcer.py getters)",
            feature,
        )
        _emit_saml_tamper_event("mesh_full_check_mismatch", "clean", "tampered")
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY)

    try:
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "SAML provider: could not import enforcer for license state — "
            "treating as violation and refusing (IMPL-03): %s", exc,
        )
        _emit_saml_tamper_event("integrity_module_unavailable", "n/a", "import_failed")
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
