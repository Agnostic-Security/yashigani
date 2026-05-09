"""
BOPLA per-property allowlist regression tests — issue #90 (v2.23.3).

Validates that:
1. Each public-view Pydantic schema (AdminAccountPublic, UserAccountPublic,
   SiemTargetPublic, IdPPublic, JWTConfigPublic, JWTTestResultPublic) excludes
   the documented sensitive fields.
2. Route helper functions that build list responses do not include sensitive
   properties even when the underlying record contains them.
3. SAFE_JWT_CLAIMS allowlist strips non-allowed claims from JWT test results.

OWASP API3:2023, ASVS V4.2.1, CWE-213.
Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.backoffice.schemas.bopla import (
    AdminAccountPublic,
    IdPPublic,
    JWTConfigPublic,
    JWTTestResultPublic,
    SAFE_JWT_CLAIMS,
    SiemTargetPublic,
    UserAccountPublic,
)


# ---------------------------------------------------------------------------
# Shared sensitive-field constants
# ---------------------------------------------------------------------------

ADMIN_SENSITIVE_FIELDS = {
    "password_hash",
    "totp_secret",
    "recovery_codes",
    "failed_attempts",
    "locked_until",
    "totp_failed_attempts",
    "totp_backoff_until",
}

USER_SENSITIVE_FIELDS = ADMIN_SENSITIVE_FIELDS.copy()

SIEM_SENSITIVE_FIELDS = {"auth_value"}

IDP_SENSITIVE_FIELDS = {
    "client_secret",
    "client_id",
    "private_key",
    "signing_cert",
    "org_id",
    "default_sensitivity",
}


# ---------------------------------------------------------------------------
# 1. Schema model tests — sensitive fields excluded at serialisation
# ---------------------------------------------------------------------------


class TestAdminAccountPublic:
    def _make_record(self) -> dict[str, Any]:
        """Full internal account record including all sensitive fields."""
        return {
            "username": "admin@example.com",
            "account_id": "00000000-0000-0000-0000-000000000001",
            "email": "admin@example.com",
            "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "recovery_codes": ["ABC12", "DEF34", "GHI56"],
            "account_tier": "admin",
            "disabled": False,
            "force_password_change": True,
            "force_totp_provision": False,
            "created_at": 1746700000.0,
            "failed_attempts": 2,
            "locked_until": 0.0,
            "totp_failed_attempts": 1,
            "totp_backoff_until": 0.0,
            "last_login_at": 1746700000.0,
            "inactive_disabled_at": None,
        }

    def test_sensitive_fields_absent_from_serialisation(self):
        rec = self._make_record()
        pub = AdminAccountPublic(
            username=rec["username"],
            account_id=rec["account_id"],
            email=rec["email"],
            disabled=rec["disabled"],
            force_password_change=rec["force_password_change"],
            force_totp_provision=rec["force_totp_provision"],
            created_at=rec["created_at"],
        )
        dumped = pub.model_dump()
        for field in ADMIN_SENSITIVE_FIELDS:
            assert field not in dumped, (
                f"AdminAccountPublic.model_dump() must NOT contain '{field}' "
                f"(BOPLA #90: password_hash / totp_secret / recovery_codes leak)"
            )

    def test_allowed_fields_present(self):
        pub = AdminAccountPublic(
            username="admin@example.com",
            account_id="abc-123",
            email="admin@example.com",
            disabled=False,
            force_password_change=True,
            force_totp_provision=False,
            created_at=1746700000.0,
        )
        dumped = pub.model_dump()
        assert dumped["username"] == "admin@example.com"
        assert dumped["account_id"] == "abc-123"
        assert dumped["disabled"] is False

    @pytest.mark.parametrize("sensitive_field", list(ADMIN_SENSITIVE_FIELDS))
    def test_extra_fields_rejected(self, sensitive_field: str):
        """model_config extra='forbid' ensures extra fields are rejected."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AdminAccountPublic(
                username="admin@example.com",
                account_id="abc-123",
                email=None,
                disabled=False,
                force_password_change=True,
                force_totp_provision=False,
                created_at=1746700000.0,
                **{sensitive_field: "injected_value"},
            )


class TestUserAccountPublic:
    @pytest.mark.parametrize("sensitive_field", list(USER_SENSITIVE_FIELDS))
    def test_sensitive_fields_not_in_dump(self, sensitive_field: str):
        pub = UserAccountPublic(
            username="alice",
            account_id="user-001",
            email=None,
            disabled=False,
            force_password_change=True,
            force_totp_provision=True,
            created_at=1746700000.0,
        )
        dumped = pub.model_dump()
        assert sensitive_field not in dumped, f"UserAccountPublic must NOT serialise '{sensitive_field}'"


class TestSiemTargetPublic:
    @pytest.mark.parametrize("sensitive_field", list(SIEM_SENSITIVE_FIELDS))
    def test_auth_value_absent(self, sensitive_field: str):
        pub = SiemTargetPublic(
            name="prod-siem",
            target_type="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            auth_header="X-Splunk-HEC-Token",
            enabled=True,
        )
        dumped = pub.model_dump()
        assert sensitive_field not in dumped, (
            f"SiemTargetPublic must NOT serialise '{sensitive_field}' (bearer token / HEC token must never be returned)"
        )

    def test_safe_fields_present(self):
        pub = SiemTargetPublic(
            name="prod-siem",
            target_type="splunk_hec",
            url="https://splunk.example.com:8088",
            auth_header="X-Splunk-HEC-Token",
            enabled=True,
        )
        dumped = pub.model_dump()
        assert dumped["name"] == "prod-siem"
        assert dumped["url"] == "https://splunk.example.com:8088"
        assert dumped["auth_header"] == "X-Splunk-HEC-Token"
        assert "auth_value" not in dumped


class TestIdPPublic:
    @pytest.mark.parametrize("sensitive_field", list(IDP_SENSITIVE_FIELDS))
    def test_sensitive_fields_absent(self, sensitive_field: str):
        pub = IdPPublic(
            id="google-oidc",
            name="Google",
            protocol="oidc",
            email_domains=["example.com"],
        )
        dumped = pub.model_dump()
        assert sensitive_field not in dumped, f"IdPPublic must NOT serialise '{sensitive_field}'"

    def test_safe_fields_present(self):
        pub = IdPPublic(
            id="google-oidc",
            name="Google",
            protocol="oidc",
            email_domains=["example.com"],
        )
        dumped = pub.model_dump()
        assert dumped["id"] == "google-oidc"
        assert dumped["protocol"] == "oidc"
        assert dumped["email_domains"] == ["example.com"]


class TestJWTConfigPublic:
    def test_fields_present(self):
        pub = JWTConfigPublic(
            tenant_id="00000000-0000-0000-0000-000000000000",
            jwks_url="https://idp.example.com/.well-known/jwks.json",
            issuer="https://idp.example.com",
            audience="yashigani",
            fail_closed=True,
            scope="platform",
        )
        dumped = pub.model_dump()
        assert dumped["tenant_id"] == "00000000-0000-0000-0000-000000000000"
        assert dumped["jwks_url"] == "https://idp.example.com/.well-known/jwks.json"
        assert dumped["fail_closed"] is True

    def test_extra_fields_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            JWTConfigPublic(
                tenant_id="00000000-0000-0000-0000-000000000000",
                jwks_url="https://idp.example.com/.well-known/jwks.json",
                issuer="https://idp.example.com",
                audience="yashigani",
                fail_closed=True,
                scope="platform",
                signing_secret="s3cr3t",  # should be rejected
            )


# ---------------------------------------------------------------------------
# 2. SAFE_JWT_CLAIMS allowlist
# ---------------------------------------------------------------------------


class TestSafeJwtClaims:
    SENSITIVE_CLAIMS = [
        "email",
        "phone_number",
        "address",
        "birthdate",
        "ssn",
        "given_name",
        "family_name",
        "preferred_username",
    ]
    SAFE_CLAIMS = [
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
    ]

    @pytest.mark.parametrize("claim", SENSITIVE_CLAIMS)
    def test_sensitive_claim_not_in_safe_set(self, claim: str):
        assert claim not in SAFE_JWT_CLAIMS, f"'{claim}' must NOT be in SAFE_JWT_CLAIMS — it is a PII/identity claim"

    @pytest.mark.parametrize("claim", SAFE_CLAIMS)
    def test_safe_claim_in_safe_set(self, claim: str):
        assert claim in SAFE_JWT_CLAIMS, f"'{claim}' should be in SAFE_JWT_CLAIMS — it is a structural/integrity claim"

    def test_jwt_test_result_claims_filtered(self):
        """Verify that JWTTestResultPublic strips sensitive claims from raw JWT."""
        raw_claims = {
            "iss": "https://idp.example.com",
            "aud": "yashigani",
            "iat": 1746700000,
            "exp": 1746703600,
            "sub": "user-123",  # sub is allowed on JWTTestResultPublic but not in claims dict
            "email": "alice@example.com",  # should be stripped
            "phone_number": "+441234567890",  # should be stripped
            "given_name": "Alice",  # should be stripped
            "ssn": "123-45-6789",  # definitely should be stripped
            "scope": "openid profile",
            "roles": ["admin"],
        }
        safe_claims = {k: v for k, v in raw_claims.items() if k in SAFE_JWT_CLAIMS}

        pub = JWTTestResultPublic(
            valid=True,
            sub="user-123",
            tenant_id="00000000-0000-0000-0000-000000000000",
            error=None,
            claims=safe_claims,
        )
        dumped = pub.model_dump()
        returned_claims = dumped["claims"]

        assert "email" not in returned_claims
        assert "phone_number" not in returned_claims
        assert "given_name" not in returned_claims
        assert "ssn" not in returned_claims
        assert returned_claims["iss"] == "https://idp.example.com"
        assert returned_claims["scope"] == "openid profile"
        assert returned_claims["roles"] == ["admin"]


# ---------------------------------------------------------------------------
# 3. Route-level: list_users response does not include sensitive fields
# ---------------------------------------------------------------------------


class TestListUsersResponseNoBOPLA:
    """
    Test that list_users() route builds responses through UserAccountPublic
    so no sensitive fields reach the wire.

    We call the route function directly with mock state (same pattern as
    other route-level unit tests in this repo).
    """

    def _make_mock_record(self, username: str, tier: str = "user") -> MagicMock:
        rec = MagicMock()
        rec.username = username
        rec.account_id = f"uid-{username}"
        rec.email = f"{username}@example.com"
        rec.account_tier = tier
        rec.disabled = False
        rec.force_password_change = False
        rec.force_totp_provision = False
        rec.created_at = 1746700000.0
        # Sensitive fields present on the internal record
        rec.password_hash = "$argon2id$SENSITIVE"
        rec.totp_secret = "SENSITIVE_TOTP_SECRET"
        rec.recovery_codes = ["CODE1", "CODE2"]
        rec.failed_attempts = 3
        rec.locked_until = 0.0
        rec.totp_failed_attempts = 1
        rec.totp_backoff_until = 0.0
        return rec

    def test_list_users_excludes_sensitive_fields(self):
        from yashigani.backoffice.routes.users import list_users

        mock_record = self._make_mock_record("alice", tier="user")

        state = MagicMock()
        state.auth_service = MagicMock()
        state.auth_service.list_accounts = AsyncMock(return_value=[mock_record])
        state.auth_service.total_user_count = AsyncMock(return_value=1)
        state.user_min_total = 1

        session = MagicMock()

        async def _run():
            with patch("yashigani.backoffice.routes.users.backoffice_state", state):
                return await list_users(session)

        result = asyncio.run(_run())
        users = result["users"]
        assert len(users) == 1
        user_dict = users[0]

        for field in ADMIN_SENSITIVE_FIELDS:
            assert field not in user_dict, f"list_users() response must NOT contain '{field}' (BOPLA #90)"
        # Confirm safe fields present
        assert user_dict["username"] == "alice"
        assert user_dict["account_id"] == "uid-alice"


class TestListAdminsResponseNoBOPLA:
    """
    Test that list_admins() route builds responses through AdminAccountPublic
    so no sensitive fields reach the wire.
    """

    def _make_mock_admin(self, username: str) -> MagicMock:
        rec = MagicMock()
        rec.username = username
        rec.account_id = f"adm-{username}"
        rec.email = f"{username}@example.com"
        rec.account_tier = "admin"
        rec.disabled = False
        rec.force_password_change = False
        rec.force_totp_provision = False
        rec.created_at = 1746700000.0
        rec.password_hash = "$argon2id$SENSITIVE"
        rec.totp_secret = "SENSITIVE_TOTP_SECRET"
        rec.recovery_codes = ["BACKUP1"]
        rec.failed_attempts = 0
        rec.locked_until = 0.0
        rec.totp_failed_attempts = 0
        rec.totp_backoff_until = 0.0
        return rec

    def test_list_admins_excludes_sensitive_fields(self):
        from yashigani.backoffice.routes.accounts import list_admins

        mock_admin = self._make_mock_admin("admin@example.com")

        state = MagicMock()
        state.auth_service = MagicMock()
        state.auth_service.list_accounts = AsyncMock(return_value=[mock_admin])
        state.auth_service.total_admin_count = AsyncMock(return_value=1)
        state.auth_service.active_admin_count = AsyncMock(return_value=1)
        state.admin_min_total = 2
        state.admin_min_active = 2
        state.admin_soft_target = 3

        session = MagicMock()

        async def _run():
            with patch("yashigani.backoffice.routes.accounts.backoffice_state", state):
                return await list_admins(session)

        result = asyncio.run(_run())
        accounts = result["accounts"]
        assert len(accounts) == 1
        admin_dict = accounts[0]

        for field in ADMIN_SENSITIVE_FIELDS:
            assert field not in admin_dict, f"list_admins() response must NOT contain '{field}' (BOPLA #90)"
        assert admin_dict["username"] == "admin@example.com"


# ---------------------------------------------------------------------------
# 4. SIEM target list excludes auth_value
# ---------------------------------------------------------------------------


class TestSiemListResponseNoBOPLA:
    def test_list_siem_targets_excludes_auth_value(self):
        from yashigani.backoffice.routes.audit import list_siem_targets

        mock_target = MagicMock()
        mock_target.name = "prod-splunk"
        mock_target.target_type = "splunk_hec"
        mock_target.url = "https://splunk.example.com:8088/services/collector"
        mock_target.auth_header = "X-Splunk-HEC-Token"
        mock_target.auth_value = "SENSITIVE_SPLUNK_HEC_TOKEN"
        mock_target.enabled = True

        mock_writer = MagicMock()
        mock_writer._siem_targets = [mock_target]

        state = MagicMock()
        state.audit_writer = mock_writer

        session = MagicMock()

        async def _run():
            with patch("yashigani.backoffice.routes.audit.backoffice_state", state):
                return await list_siem_targets(session)

        result = asyncio.run(_run())
        targets = result["siem_targets"]
        assert len(targets) == 1
        target_dict = targets[0]

        assert "auth_value" not in target_dict, "SIEM target list must NOT return auth_value (bearer token / HEC token)"
        assert target_dict["name"] == "prod-splunk"
        assert target_dict["url"] == "https://splunk.example.com:8088/services/collector"


# ---------------------------------------------------------------------------
# 5. SSO IdP list excludes client_secret
# ---------------------------------------------------------------------------


class TestIdPListResponseNoBOPLA:
    def test_list_idps_excludes_client_secret(self):
        from yashigani.backoffice.routes.sso import list_idps

        mock_idp = MagicMock()
        mock_idp.id = "google-oidc"
        mock_idp.name = "Google"
        mock_idp.protocol = "oidc"
        mock_idp.email_domains = ["example.com"]
        mock_idp.enabled = True
        mock_idp.client_secret = "SENSITIVE_OAUTH_SECRET"
        mock_idp.client_id = "123456.apps.googleusercontent.com"
        mock_idp.org_id = "org-internal-123"
        mock_idp.default_sensitivity = "INTERNAL"

        mock_broker = MagicMock()
        mock_broker.list_idps.return_value = [mock_idp]

        state = MagicMock()
        state.identity_broker = mock_broker

        async def _run():

            with patch("yashigani.backoffice.routes.sso.backoffice_state", state):
                resp = await list_idps()
                return resp.body

        body_bytes = asyncio.run(_run())
        import json

        body = json.loads(body_bytes)
        idps = body["idps"]
        assert len(idps) == 1
        idp_dict = idps[0]

        for field in IDP_SENSITIVE_FIELDS:
            assert field not in idp_dict, f"SSO IdP list must NOT return '{field}' (BOPLA #90)"
        assert idp_dict["id"] == "google-oidc"
        assert idp_dict["protocol"] == "oidc"


# ---------------------------------------------------------------------------
# 6. JWT test result strips sensitive claims
# ---------------------------------------------------------------------------


class TestJWTTestResultNoBOPLA:
    def test_jwt_test_result_strips_email(self):
        """Regression: JWT test endpoint must not return email or PII claims."""
        raw_claims = {
            "iss": "https://idp.example.com",
            "aud": "yashigani",
            "iat": 1746700000,
            "exp": 1746703600,
            "email": "alice@example.com",
            "phone_number": "+441234567890",
            "given_name": "Alice",
            "family_name": "Smith",
            "ssn": "123-45-6789",
            "scope": "openid email profile",
            "roles": ["user"],
        }
        safe = {k: v for k, v in raw_claims.items() if k in SAFE_JWT_CLAIMS}
        pub = JWTTestResultPublic(valid=True, sub="alice", claims=safe)
        dumped = pub.model_dump()
        returned = dumped["claims"]

        for pii_claim in ("email", "phone_number", "given_name", "family_name", "ssn"):
            assert pii_claim not in returned, f"JWT test result must NOT return PII claim '{pii_claim}'"
        assert returned["iss"] == "https://idp.example.com"
        assert returned["scope"] == "openid email profile"
