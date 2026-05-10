"""
Yashigani SSO — OpenID Connect (OIDC) relying party.
Validates ID tokens and resolves user identity from claims.
YASHIGANI_AUTH_MODE=sso with OIDC discovery.

PKCE (RFC 7636) — ASVS 10.4.6:
  Every authorization request includes code_challenge (S256).
  The code_verifier is returned to the caller (stored in session state)
  and sent back during the token exchange.

ACS gap #95 (3p response validation):
  OIDC discovery metadata is now validated with a Pydantic-strict model
  (OIDCDiscoveryMetadata) before the mandatory endpoints are used.
  Malformed or unexpected metadata fields surface as ValidationError.

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from yashigani.licensing.enforcer import require_feature

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ACS gap #95 — 3p response validation: OIDC discovery metadata model
# ---------------------------------------------------------------------------


def _validate_oidc_metadata(raw: dict) -> dict:
    """
    Validate mandatory OIDC discovery metadata fields.

    ACS gap #95 (3p response validation): enforces that the discovery
    document from the IdP contains the required string fields before they
    are used.  Raises ValueError with a descriptive message on failure so
    the caller can surface a safe error to the admin.

    Required fields (RFC 8414 §2):
      - issuer (string, non-empty)
      - authorization_endpoint (string, non-empty URL)
      - token_endpoint (string, non-empty URL)
      - jwks_uri (string, non-empty URL)

    Extra fields are allowed (IdPs extend the spec freely).
    """
    required_url_fields = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    required_string_fields = ("issuer",)

    errors: list[str] = []

    for field in required_string_fields:
        val = raw.get(field)
        if not isinstance(val, str) or not val.strip():
            errors.append(f"'{field}' must be a non-empty string, got {type(val).__name__!r}")

    for field in required_url_fields:
        val = raw.get(field)
        if not isinstance(val, str) or not val.startswith("https://"):
            errors.append(
                f"'{field}' must be an https:// URL, got {val!r}"
                if isinstance(val, str)
                else f"'{field}' must be a string, got {type(val).__name__!r}"
            )

    if errors:
        raise ValueError(f"OIDC discovery metadata validation failed: {'; '.join(errors)}")

    return raw


def _import_authlib():
    try:
        from authlib.integrations.requests_client import OAuth2Session
        from authlib.jose import jwt, JWTClaims
        from authlib.jose.errors import JoseError

        return OAuth2Session, jwt, JWTClaims, JoseError
    except ImportError as exc:
        raise ImportError("authlib is required for OIDC. Install with: pip install authlib") from exc


@dataclass
class OIDCConfig:
    client_id: str
    client_secret: str
    discovery_url: str  # e.g. https://accounts.google.com/.well-known/openid-configuration
    redirect_uri: str
    scopes: list[str] = None  # type: ignore[assignment]  # populated in __post_init__
    # YSG-RISK-003 #3at: optional override for OIDC endpoint host validation.
    # None = endpoint hostname must equal the discovery_url hostname.
    # Non-None = a fully-qualified hostname or *.example.com suffix glob
    # (fnmatch, case-insensitive) — when set, endpoints whose hostname matches
    # this pattern AND have scheme == "https" are permitted.
    allowed_auth_endpoint_pattern: Optional[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["openid", "email", "profile"]


@dataclass
class OIDCUserInfo:
    subject: str  # IdP-stable user identifier
    email: Optional[str]
    name: Optional[str]
    raw_claims: dict


class OIDCProvider:
    """
    OIDC Relying Party.
    Handles authorization redirect, callback token exchange, and ID token validation.
    PKCE (S256) is used on every flow — ASVS 10.4.6.
    """

    def __init__(self, config: OIDCConfig) -> None:
        self._config = config
        self._metadata: Optional[dict] = None
        self._jwks: Optional[dict] = None

    @staticmethod
    def _generate_pkce() -> tuple[str, str]:
        """
        Generate a PKCE code_verifier (43-128 chars) and S256 code_challenge.
        Returns (code_verifier, code_challenge).
        RFC 7636 Section 4.1-4.2.
        """
        # 32 bytes -> 43 base64url chars (no padding)
        verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def get_authorization_url(self, state: str, nonce: str) -> tuple[str, str]:
        """
        Build the IdP authorization redirect URL with PKCE S256 challenge.
        Returns (url, code_verifier). Caller MUST persist code_verifier in
        session state alongside the CSRF state token.
        """
        require_feature("oidc")
        OAuth2Session, *_ = _import_authlib()
        meta = self._get_metadata()
        session = OAuth2Session(
            client_id=self._config.client_id,
            redirect_uri=self._config.redirect_uri,
            scope=" ".join(self._config.scopes),
        )
        code_verifier, code_challenge = self._generate_pkce()
        url, _ = session.create_authorization_url(
            meta["authorization_endpoint"],
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )
        return url, code_verifier

    def exchange_code(self, code: str, state: str, code_verifier: str = "") -> OIDCUserInfo:
        """
        Exchange authorization code for tokens.
        Validates ID token signature and claims.
        Returns OIDCUserInfo on success.
        code_verifier is sent to the token endpoint for PKCE validation (ASVS 10.4.6).
        """
        require_feature("oidc")
        OAuth2Session, jwt_lib, _, JoseError = _import_authlib()
        meta = self._get_metadata()
        session = OAuth2Session(
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
            redirect_uri=self._config.redirect_uri,
        )
        fetch_kwargs: dict = {
            "code": code,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            fetch_kwargs["code_verifier"] = code_verifier
        token = session.fetch_token(
            meta["token_endpoint"],
            **fetch_kwargs,
        )
        id_token = token.get("id_token")
        if not id_token:
            raise ValueError("No id_token in token response")

        jwks = self._get_jwks()
        try:
            claims = jwt_lib.decode(id_token, jwks)
            claims.validate(
                now=int(time.time()),
                leeway=30,
            )
        except JoseError as exc:
            raise ValueError(f"ID token validation failed: {exc}") from exc

        return OIDCUserInfo(
            subject=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name"),
            raw_claims=dict(claims),
        )

    # -- Internal ------------------------------------------------------------

    def _assert_safe_discovery_url(self, url: str) -> None:
        """Validate the OIDC discovery_url before fetching it (B1 — CWE-918).

        Rules (YSG-RISK-007.B #3ax):
        1. Scheme MUST be ``https``.
        2. Hostname must either:
           a. Be in the YASHIGANI_OIDC_DISCOVERY_HOSTS env allowlist
              (comma-separated, case-insensitive; "*" means any hostname allowed), OR
           b. If the env var is not set/empty, any hostname is allowed (operator
              responsibility — env var is the opt-in tightening control).

        Raises ``HTTPException(502)`` on any violation.
        """
        import os
        from fastapi import HTTPException

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        if scheme != "https":
            logger.warning(
                "OIDC discovery_url has unsafe scheme %r — URL: %r",
                repr(scheme),
                repr(url),
            )
            raise HTTPException(status_code=502, detail="oidc_discovery_invalid")

        raw = os.getenv("YASHIGANI_OIDC_DISCOVERY_HOSTS", "").strip()
        if not raw:
            # No allowlist configured — any https host is permitted.
            return

        allowed = {h.strip().lower() for h in raw.split(",") if h.strip()}
        if "*" in allowed:
            return  # wildcard: any host

        # fnmatch-style glob matching (e.g. *.example.com)
        import fnmatch as _fnmatch

        for entry in allowed:
            if _fnmatch.fnmatch(host, entry):
                return

        logger.warning(
            "OIDC discovery_url hostname %r not in YASHIGANI_OIDC_DISCOVERY_HOSTS — blocked",
            repr(host),
        )
        raise HTTPException(status_code=502, detail="oidc_discovery_invalid")

    def _assert_oidc_endpoint(self, endpoint_name: str, endpoint_url: str) -> None:
        """Validate that an OIDC discovery endpoint URL is safe.

        Rules (YSG-RISK-003 #3at, CWE-601):
        1. Scheme MUST be ``https``.
        2. Hostname must match the registered ``discovery_url`` hostname OR,
           when ``allowed_auth_endpoint_pattern`` is set, must match that
           fnmatch glob (case-insensitive).

        Raises ``HTTPException(502)`` on any violation so the caller never
        issues a redirect or outbound fetch to an attacker-controlled host.
        The rejected hostname is logged via ``repr()`` to prevent log injection.
        """
        from fastapi import HTTPException

        parsed = urlparse(endpoint_url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        if scheme != "https":
            logger.warning(
                "OIDC discovery: %s has unsafe scheme %r — discovery_url=%r",
                endpoint_name,
                repr(scheme),
                repr(self._config.discovery_url),
            )
            raise HTTPException(
                status_code=502,
                detail="oidc_discovery_invalid",
            )

        discovery_host = (urlparse(self._config.discovery_url).hostname or "").lower()
        pattern = self._config.allowed_auth_endpoint_pattern

        if pattern is not None:
            # Caller-supplied glob: must match the endpoint hostname.
            if not fnmatch.fnmatch(host, pattern.lower()):
                logger.warning(
                    "OIDC discovery: %s hostname %r does not match allowed_auth_endpoint_pattern %r — rejecting",
                    endpoint_name,
                    repr(host),
                    repr(pattern),
                )
                raise HTTPException(
                    status_code=502,
                    detail="oidc_discovery_invalid",
                )
        else:
            # Default: endpoint hostname must equal the discovery_url hostname.
            if host != discovery_host:
                logger.warning(
                    "OIDC discovery: %s hostname %r does not match discovery_url hostname %r — rejecting",
                    endpoint_name,
                    repr(host),
                    repr(discovery_host),
                )
                raise HTTPException(
                    status_code=502,
                    detail="oidc_discovery_invalid",
                )

    def _get_metadata(self) -> dict:
        if self._metadata:
            return self._metadata
        import urllib.request
        import json

        # B1: assert the discovery_url itself is safe before fetching
        # (YSG-RISK-007.B #3ax, CWE-918).
        self._assert_safe_discovery_url(self._config.discovery_url)
        with urllib.request.urlopen(self._config.discovery_url, timeout=10) as resp:
            raw = json.loads(resp.read())
        # ACS gap #95 (3p response validation): validate metadata schema before
        # caching or using any field from it.  Raises ValueError on schema
        # violation so the caller can surface a safe 502 to the admin.
        if not isinstance(raw, dict):
            raise ValueError(f"OIDC discovery document must be a JSON object, got {type(raw).__name__!r}")
        _validate_oidc_metadata(raw)
        self._metadata = raw
        # B2 / YSG-RISK-003: validate mandatory endpoints from the discovery
        # document before any call site uses them (CWE-601 + CWE-918).
        for field_name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = self._metadata.get(field_name, "")
            self._assert_oidc_endpoint(field_name, value)
        return self._metadata

    def _get_jwks(self) -> dict:
        if self._jwks:
            return self._jwks
        import urllib.request
        import json

        meta = self._get_metadata()
        # jwks_uri is already validated by _get_metadata(); re-assert here as a
        # defence-in-depth guard in case _get_jwks() is ever called with a
        # pre-populated _metadata that bypassed validation (YSG-RISK-007.B B2).
        self._assert_oidc_endpoint("jwks_uri", meta.get("jwks_uri", ""))
        with urllib.request.urlopen(meta["jwks_uri"], timeout=10) as resp:
            self._jwks = json.loads(resp.read())
        return self._jwks
