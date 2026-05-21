"""
Yashigani Auth — Multi-IdP Identity Broker.

Last updated: 2026-05-15T22:00:00+01:00

Yashigani IS the identity broker (Decision 11). Supports OIDC and SAML v2
with multiple IdPs per deployment. Caddy delegates auth to the backoffice,
which resolves identity and sets session cookies.

Tier gating:
  Community:         Local auth + API keys only
  Starter:           1 OIDC
  Professional:      1 OIDC + 1 SAML
  Professional Plus: 5 IdPs (any mix)
  Enterprise:        Unlimited
  Academic:          1 OIDC

Login flow:
  1. User hits /chat/* -> Caddy redirects unauthenticated to /auth/sso/select
  2. User selects IdP (or auto-detected by email domain)
  3. Redirect to IdP (OIDC authorization endpoint or SAML SSO URL)
  4. IdP callback -> backoffice validates token/assertion
  5. Backoffice resolves/creates Yashigani identity
  6. Sets session cookie
  7. Caddy reads session -> injects X-Forwarded-* headers
  8. Open WebUI/Gateway receive pre-authenticated identity
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from yashigani.sso.oidc import OIDCConfig, OIDCProvider, OIDCUserInfo
from yashigani.sso.saml import SAMLConfig, SAMLProvider, SAMLUserInfo

logger = logging.getLogger(__name__)


@dataclass
class IdPConfig:
    """Configuration for an identity provider."""
    id: str
    name: str                      # Display name ("Entra ID Germany")
    protocol: str                  # "oidc" or "saml"
    metadata_url: str = ""         # OIDC discovery or SAML metadata URL
    client_id: str = ""            # OIDC client ID or SAML entity ID
    client_secret: str = ""        # Stored encrypted in KMS
    entity_id: str = ""            # SAML entity ID
    group_mapping: dict = field(default_factory=dict)  # IdP group -> Yashigani group
    org_id: str = ""               # Which org this IdP serves
    default_sensitivity: str = "INTERNAL"
    email_domains: list[str] = field(default_factory=list)  # For auto-detection
    enabled: bool = True
    # YSG-RISK-003 #3at: optional override for OIDC endpoint host validation.
    # None (default) = the endpoint hostname must match the discovery_url hostname.
    # A non-None value must be a fully-qualified hostname or a *.example.com-style
    # suffix glob (matched via fnmatch, case-insensitive).
    allowed_auth_endpoint_pattern: Optional[str] = None

    # SAML SP / IdP credentials (ignored for protocol="oidc").
    # sp_private_key: RSA private key PEM body (no headers) or full PEM.
    #   Enforcement: _assert_rsa_sp_key() fires at add_idp() time — non-RSA keys
    #   reject startup (YSG-RISK-044 / CVE-2026-41989 mitigation).
    # idp_sso_url / idp_sls_url: SAML SSO and SLS endpoints from IdP metadata.
    # idp_x509_cert / sp_certificate: X.509 PEM bodies (no headers).
    # sp_sls_url: SP Single Logout Service URL.
    saml_idp_sso_url: str = ""
    saml_idp_sls_url: str = ""
    saml_idp_x509_cert: str = ""
    saml_sp_sls_url: str = ""
    saml_sp_private_key: str = ""
    saml_sp_certificate: str = ""

    # V6.8.4 — acr/amr allowlist validation (ASVS V6.3.3).
    # Both fields are Optional[List[str]] with None meaning "no enforcement".
    # Purpose: catch HONEST IdP misconfiguration loudly at deploy time.
    # NOT a security boundary — a compromised IdP can lie about these claims.
    #
    # required_acr_values: the ID token `acr` claim (or SAML
    #   AuthnContextClassRef) must be IN this list. If None, no check.
    #   e.g. ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold"]
    #
    # required_amr_values: every element of this list must be present in the
    #   ID token `amr` claim (set-subset semantics). If None, no check.
    #   e.g. ["mfa"]  — require at least one multi-factor method
    #
    # For SAML, AuthnContextClassRef maps to required_acr_values.
    # SAML has no direct amr equivalent; the ClassRef allowlist is sufficient.
    required_acr_values: Optional[List[str]] = None
    required_amr_values: Optional[List[str]] = None


@dataclass
class SSOResult:
    """Result of SSO authentication."""
    success: bool
    identity_id: str = ""
    email: str = ""
    name: str = ""
    groups: list[str] = field(default_factory=list)
    idp_name: str = ""
    error: str = ""
    raw_claims: dict = field(default_factory=dict)  # ID token claims (acr, amr, etc.)


# Tier limits for IdP count
_TIER_IDP_LIMITS = {
    "community": 0,
    "starter": 1,
    "professional": 2,
    "professional_plus": 5,
    "enterprise": 999,
    "academic": 1,
}


class IdentityBroker:
    """
    Multi-IdP identity broker.

    Manages IdP configurations and handles SSO authentication flows.
    """

    def __init__(self, tier: str = "community") -> None:
        self._idps: dict[str, IdPConfig] = {}
        self._oidc_providers: dict[str, OIDCProvider] = {}
        self._saml_providers: dict[str, SAMLProvider] = {}
        self._tier = tier
        self._limit = _TIER_IDP_LIMITS.get(tier, 0)
        logger.info("IdentityBroker: tier=%s, idp_limit=%d", tier, self._limit)

    def add_idp(self, config: IdPConfig, redirect_uri: str = "") -> None:
        """
        Register an IdP. Raises if tier limit exceeded.

        For OIDC IdPs, an OIDCProvider is created immediately so that
        get_oidc_auth_url() and handle_oidc_callback() can delegate to it.
        ``redirect_uri`` is required for OIDC; if omitted the provider is
        constructed without one (callers must pass it at exchange time).
        """
        if len(self._idps) >= self._limit:
            raise ValueError(
                f"IdP limit reached for tier '{self._tier}' "
                f"({self._limit} max, {len(self._idps)} configured)"
            )
        self._idps[config.id] = config

        if config.protocol == "oidc":
            oidc_cfg = OIDCConfig(
                client_id=config.client_id,
                client_secret=config.client_secret,
                discovery_url=config.metadata_url,
                redirect_uri=redirect_uri,
                scopes=["openid", "email", "profile", "groups"],
                # YSG-RISK-003 #3at: thread the endpoint pattern through
                # so OIDCProvider can validate discovery endpoints.
                allowed_auth_endpoint_pattern=config.allowed_auth_endpoint_pattern,
            )
            self._oidc_providers[config.id] = OIDCProvider(oidc_cfg)

        elif config.protocol == "saml":
            # Build SAMLConfig from the IdPConfig SAML fields and register the
            # provider.  SAMLProvider.__init__ calls _assert_rsa_sp_key() —
            # non-RSA SP keys raise ValueError here, fail-closing at config-load
            # (YSG-RISK-044 / CVE-2026-41989 mitigation).
            #
            # entity_id on IdPConfig serves as the SAML SP entity ID (the SP's
            # own public identifier).  sp_acs_url defaults to metadata_url when
            # the caller does not supply a separate ACS URL via redirect_uri.
            sp_entity_id = config.entity_id or config.client_id or config.id
            sp_acs_url = redirect_uri or config.metadata_url
            saml_cfg = SAMLConfig(
                sp_entity_id=sp_entity_id,
                sp_acs_url=sp_acs_url,
                sp_sls_url=config.saml_sp_sls_url or sp_acs_url.replace("/acs", "/sls"),
                idp_entity_id=config.saml_idp_sso_url or config.metadata_url,
                idp_sso_url=config.saml_idp_sso_url or config.metadata_url,
                idp_sls_url=config.saml_idp_sls_url,
                idp_x509_cert=config.saml_idp_x509_cert,
                sp_private_key=config.saml_sp_private_key,
                sp_certificate=config.saml_sp_certificate,
            )
            # Raises ValueError for non-RSA keys — propagate to fail the
            # container at startup (SOP 1: lifespan fail-closed discipline).
            self._saml_providers[config.id] = SAMLProvider(saml_cfg)
            logger.info(
                "IdentityBroker: SAML SP registered for IdP %s — RSA key enforced",
                config.id,
            )

        logger.info("IdentityBroker: added IdP %s (%s, %s)", config.id, config.name, config.protocol)

    def remove_idp(self, idp_id: str) -> None:
        """Remove an IdP configuration."""
        self._idps.pop(idp_id, None)
        self._oidc_providers.pop(idp_id, None)
        self._saml_providers.pop(idp_id, None)

    def list_idps(self) -> list[IdPConfig]:
        """List all configured IdPs."""
        return [idp for idp in self._idps.values() if idp.enabled]

    def get_idp(self, idp_id: str) -> Optional[IdPConfig]:
        """Get a specific IdP configuration."""
        return self._idps.get(idp_id)

    def detect_idp_by_email(self, email: str) -> Optional[IdPConfig]:
        """Auto-detect IdP from email domain."""
        domain = email.split("@")[-1].lower() if "@" in email else ""
        for idp in self._idps.values():
            if idp.enabled and domain in idp.email_domains:
                return idp
        return None

    def get_oidc_auth_url(
        self, idp_id: str, redirect_uri: str, state: str, nonce: str = "",
    ) -> tuple[Optional[str], str]:
        """
        Generate OIDC authorization URL for a specific IdP.

        Delegates to OIDCProvider.get_authorization_url() which performs a
        real OIDC discovery fetch and uses authlib to build the URL.
        Returns (redirect_url, code_verifier) or (None, "") if IdP not found.
        The caller MUST persist code_verifier in session state for the token
        exchange (PKCE — ASVS 10.4.6).
        """
        idp = self._idps.get(idp_id)
        if not idp or idp.protocol != "oidc" or not idp.enabled:
            return None, ""

        provider = self._oidc_providers.get(idp_id)
        if provider is None:
            # Lazily create provider if it was somehow missing (e.g., added
            # before redirect_uri was known).  The caller must supply it here.
            oidc_cfg = OIDCConfig(
                client_id=idp.client_id,
                client_secret=idp.client_secret,
                discovery_url=idp.metadata_url,
                redirect_uri=redirect_uri,
                scopes=["openid", "email", "profile", "groups"],
                # YSG-RISK-003 #3at: thread the endpoint pattern through.
                allowed_auth_endpoint_pattern=idp.allowed_auth_endpoint_pattern,
            )
            provider = OIDCProvider(oidc_cfg)
            self._oidc_providers[idp_id] = provider
        else:
            # Stamp the redirect_uri onto the provider config — it may differ
            # per-request when the host/scheme changes across environments.
            provider._config.redirect_uri = redirect_uri

        url, code_verifier = provider.get_authorization_url(state=state, nonce=nonce or state)
        return url, code_verifier

    def handle_oidc_callback(
        self,
        idp_id: str,
        code: str,
        redirect_uri: str,
        state: str = "",
        code_verifier: str = "",
    ) -> SSOResult:
        """
        Handle OIDC authorization code callback.

        Delegates to OIDCProvider.exchange_code(), validates the ID token,
        maps IdP groups, and returns a populated SSOResult.
        code_verifier is forwarded to the token endpoint for PKCE (ASVS 10.4.6).
        """
        idp = self._idps.get(idp_id)
        if not idp:
            return SSOResult(success=False, error="IdP not found")

        provider = self._oidc_providers.get(idp_id)
        if provider is None:
            return SSOResult(success=False, error=f"No OIDC provider configured for IdP '{idp_id}'")

        # Keep redirect_uri in sync — same value used during authorization.
        provider._config.redirect_uri = redirect_uri

        try:
            user_info: OIDCUserInfo = provider.exchange_code(
                code=code, state=state, code_verifier=code_verifier,
            )
        except ValueError as exc:
            logger.warning("OIDC code exchange failed for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error=type(exc).__name__)
        except Exception as exc:
            logger.error("OIDC provider error for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error="OIDC token exchange failed")

        # Extract raw groups claim from ID token (Entra: groups, Okta: groups, etc.)
        raw_groups: list[str] = []
        for claim_name in ("groups", "roles", "cognito:groups"):
            val = user_info.raw_claims.get(claim_name)
            if isinstance(val, list):
                raw_groups = [str(g) for g in val]
                break

        mapped_groups = self.map_groups(idp_id, raw_groups)

        logger.info(
            "OIDC callback success: idp=%s sub=%s email=%s groups=%s",
            idp.name, user_info.subject, user_info.email, mapped_groups,
        )
        return SSOResult(
            success=True,
            identity_id=user_info.subject,
            email=user_info.email or "",
            name=user_info.name or "",
            groups=mapped_groups,
            idp_name=idp.name,
            raw_claims=user_info.raw_claims,
        )

    def handle_saml_response(
        self,
        idp_id: str,
        saml_response: str,
        request_data: dict | None = None,
    ) -> SSOResult:
        """
        Handle SAML v2 assertion response.

        Delegates to SAMLProvider.process_response() to validate the
        assertion and extract user attributes. Maps groups and returns
        a populated SSOResult.
        """
        idp = self._idps.get(idp_id)
        if not idp:
            return SSOResult(success=False, error="IdP not found")

        provider = self._saml_providers.get(idp_id)
        if provider is None:
            return SSOResult(
                success=False,
                error=f"No SAML provider configured for IdP '{idp_id}'. "
                      "Configure SAML SP certificate and IdP metadata.",
            )

        if request_data is None:
            request_data = {"post_data": {"SAMLResponse": saml_response}}

        try:
            user_info: SAMLUserInfo = provider.process_response(request_data)
        except ValueError as exc:
            logger.warning("SAML assertion failed for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error=type(exc).__name__)
        except Exception as exc:
            logger.error("SAML provider error for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error="SAML assertion validation failed")

        # Extract groups from attributes
        raw_groups: list[str] = []
        attrs = user_info.attributes
        for attr_name in ("groups", "memberOf", "http://schemas.xmlsoap.org/claims/Group"):
            val = attrs.get(attr_name)
            if isinstance(val, list):
                raw_groups = [str(g) for g in val]
                break
            elif isinstance(val, str):
                raw_groups = [val]
                break

        mapped_groups = self.map_groups(idp_id, raw_groups)

        logger.info(
            "SAML callback success: idp=%s subject=%s email=%s groups=%s acr=%r",
            idp.name, user_info.subject, user_info.email, mapped_groups,
            user_info.authn_context_class_ref,
        )
        # V6.8.4 — populate raw_claims with SAML auth-context fields so the
        # ACS route can extract them for acr validation and audit logging,
        # mirroring how OIDC raw_claims carries acr/amr/auth_time/iss.
        saml_raw_claims = {
            "authn_context_class_ref": user_info.authn_context_class_ref,
            "authn_instant": user_info.authn_instant,
            "iss": idp.entity_id,  # SAML issuer = IdP entity ID
        }
        return SSOResult(
            success=True,
            identity_id=user_info.subject,
            email=user_info.email or user_info.subject,
            name=attrs.get("firstName", attrs.get("displayName", "")),
            groups=mapped_groups,
            idp_name=idp.name,
            raw_claims=saml_raw_claims,
        )

    def map_groups(self, idp_id: str, idp_groups: list[str]) -> list[str]:
        """Map IdP group names to Yashigani group slugs."""
        idp = self._idps.get(idp_id)
        if not idp:
            return []
        return [
            idp.group_mapping.get(g, g)  # Pass through if no mapping
            for g in idp_groups
        ]
