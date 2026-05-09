"""
Yashigani Backoffice — BOPLA per-property allowlist schemas.

These are the canonical public-view Pydantic models used as response_model
on every backoffice endpoint that touches sensitive object types
(admin accounts, user accounts, SIEM targets, IdP configs, JWT configs).

SECURITY CONTRACT
-----------------
Only fields listed in these models are ever serialised into API responses.
Any field added to an internal model (AccountRecord, etc.) is automatically
excluded from all public endpoints until explicitly added to the matching
public-view model here AND documented in docs/security/bopla-allowlist.md.

Sensitive fields excluded in every public-view model:
  AccountRecord:  password_hash, totp_secret, recovery_codes,
                  failed_attempts, locked_until, totp_failed_attempts,
                  totp_backoff_until
  SiemTarget:     auth_value  (credentials; URL shown, secret never)
  IdPConfig:      client_secret, client_id (opaque at registration),
                  private_key, signing_cert
  JWTConfig:      <all sensitive claim values> — only metadata returned
  JWTTestResult:  raw claims filtered through SAFE_JWT_CLAIMS allowlist

Issue #90 — API3 BOPLA per-property allowlist audit (v2.23.3).
OWASP API3:2023, ASVS V4.2.1, CWE-213.
Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Admin & User Account — public read view
# ---------------------------------------------------------------------------


class AdminAccountPublic(BaseModel):
    """
    Public-safe view of an admin AccountRecord.

    EXCLUDED (never returned):
      - password_hash     — Argon2id hash; exposure enables offline cracking
      - totp_secret       — TOTP seed; exposure allows OTP forgery
      - recovery_codes    — backup codes; exposure allows session takeover
      - failed_attempts   — lockout counter; exposure aids brute-force timing
      - locked_until      — lockout timestamp; same reasoning
      - totp_failed_attempts — same as failed_attempts
      - totp_backoff_until   — same as locked_until
      - last_login_at     — PII-adjacent activity timestamp; not needed for admin list
      - inactive_disabled_at — operational internal field
    """

    username: str
    account_id: str
    email: Optional[str] = None
    disabled: bool
    force_password_change: bool
    force_totp_provision: bool
    created_at: float

    model_config = {"extra": "forbid"}


class UserAccountPublic(BaseModel):
    """
    Public-safe view of a user AccountRecord.

    EXCLUDED (same rationale as AdminAccountPublic plus):
      - email is included — used for user identity display in admin UIs
    """

    username: str
    account_id: str
    email: Optional[str] = None
    disabled: bool
    force_password_change: bool
    force_totp_provision: bool
    created_at: float

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Account creation responses
# ---------------------------------------------------------------------------
# These intentionally include totp_secret / temporary_password because they
# are one-time-delivery paths (admin shares credential out-of-band with the
# new account holder).  The secret is not re-derivable after this response.
# This is the ONLY endpoint permitted to return these fields.
# Documented in bopla-allowlist.md as a deliberate exception.


class AdminCreateResponse(BaseModel):
    """One-time admin-account creation response (includes bootstrap credentials)."""

    status: str
    account_id: str
    username: str
    temporary_password: str
    totp_secret: str
    totp_uri: str

    model_config = {"extra": "forbid"}


class UserCreateResponse(BaseModel):
    """One-time user-account creation response (includes bootstrap credentials)."""

    status: str
    account_id: str
    username: str
    temporary_password: str
    totp_secret: str
    totp_uri: str

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# SIEM target — public view
# ---------------------------------------------------------------------------


class SiemTargetPublic(BaseModel):
    """
    Public-safe view of a SiemTarget.

    EXCLUDED:
      - auth_value  — bearer token / HEC token / API key; never returned
                      after registration (write-only credential)
    """

    name: str
    target_type: str
    url: str
    auth_header: str
    enabled: bool

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# IdP config — public view (SSO list)
# ---------------------------------------------------------------------------


class IdPPublic(BaseModel):
    """
    Public-safe view of an IdP configuration.

    EXCLUDED:
      - client_secret   — OAuth2 client credential
      - client_id       — opaque; returned only to the configuring admin
      - private_key     — SAML private key
      - signing_cert    — SAML IdP cert
      - org_id          — internal tenant identifier
      - default_sensitivity — internal classification default
    """

    id: str
    name: str
    protocol: str
    email_domains: list[str] = []

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# JWT config — public view
# ---------------------------------------------------------------------------


class JWTConfigPublic(BaseModel):
    """
    Public-safe view of a JWT configuration row.

    All fields here are metadata (URL, issuer, audience, flags — no secrets).
    The jwks_url is an endpoint reference, not a key value, and is safe to
    show to admins managing the config.
    """

    tenant_id: str
    jwks_url: str
    issuer: str
    audience: str
    fail_closed: bool
    scope: str

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# JWT test result — claims allowlist
# ---------------------------------------------------------------------------

# SAFE_JWT_CLAIMS: claim names that are safe to return in a JWT test response.
# Any claim not in this set is stripped before the response is serialised.
# Sensitive claims include: sub (may be a persistent identifier), email,
# phone_number, address, birthdate, ssn, etc.
# We return only the structural/integrity claims useful for configuration
# debugging, not identity claims.
SAFE_JWT_CLAIMS: frozenset[str] = frozenset(
    {
        "iss",
        "aud",
        "iat",
        "exp",
        "nbf",
        "jti",
        "azp",
        "scope",
        "roles",
        "groups",
        "acr",
        "amr",
        "auth_time",
    }
)


class JWTTestResultPublic(BaseModel):
    """
    Public-safe JWT test result.

    - valid / tenant_id / error are safe structural fields.
    - sub is included for debugging JWT identity resolution — not a secret
      but is a persistent identifier; admins using this endpoint are already
      authed and need it to verify token routing.
    - claims is filtered through SAFE_JWT_CLAIMS allowlist; sensitive identity
      claims (email, phone, address, etc.) are stripped.
    """

    valid: bool
    sub: Optional[str] = None
    tenant_id: Optional[str] = None
    error: Optional[str] = None
    claims: dict[str, Any] = {}

    model_config = {"extra": "forbid"}
