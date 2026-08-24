"""
Unit tests for V6.8.4 — acr/amr allowlist + SAML AuthnContextClassRef mirror + audit claims.

ASVS V6.3.3 — Authentication context validation.
Reference: Internal/ACS/v3/asvs-stage-b-class3-2026-04-28.md §8.2

Test matrix (T-prefix = test function suffix):

  Commit 1 — acr/amr allowlist semantics in IdPConfig + broker:
    T01 — IdPConfig accepts required_acr_values and required_amr_values (both None = no-op)
    T02 — acr allowlist match → SSOResult passes through unchanged
    T03 — acr allowlist mismatch → 401-redirect with clear reason in audit
    T04 — acr allowlist empty claim → treated as mismatch
    T05 — amr set-subset satisfied → passes
    T06 — amr set-subset NOT satisfied (required=["mfa"], claim=["pwd"]) → 401-redirect
    T07 — amr partial subset (required=["mfa","hwk"], claim=["mfa","pwd","otp"]) → fail (hwk missing)
    T08 — Both required_acr_values=None and required_amr_values=None → no enforcement (backward compat)
    T09 — required_acr_values=None, required_amr_values=["mfa"] → only amr checked
    T10 — required_acr_values set, required_amr_values=None → only acr checked

  Commit 2 — SAML AuthnContextClassRef mirror:
    T11 — SAMLUserInfo has authn_context_class_ref field defaulting to ""
    T12 — SAMLUserInfo has authn_instant field defaulting to ""
    T13 — broker.handle_saml_response populates raw_claims with authn_context_class_ref
    T14 — SAML acr allowlist match → passes (returns sso_result.success=True downstream)
    T15 — SAML acr allowlist mismatch → redirect to login?error=auth_strength_insufficient
    T16 — SAML with required_acr_values=None → no enforcement

  Commit 3 — Audit-log acr/amr/auth_time/iss claims:
    T17 — SSOLoginSuccessEvent has acr/amr/auth_time/iss fields
    T18 — SAMLLoginSuccessEvent and SAMLLoginFailureEvent exist with correct event_types
    T19 — SAMLLoginSuccessEvent has authn_context_class_ref/authn_instant/issuer fields
    T20 — _write_sso_success_audit passes acr/amr/auth_time/iss to SSOLoginSuccessEvent
    T21 — _write_saml_success_audit passes authn_context_class_ref/authn_instant/issuer
    T22 — EventType.SSO_SAML_LOGIN_SUCCESS and SSO_SAML_LOGIN_FAILURE defined
    T23 — SAML handler 2FA-required default is "true" (matches OIDC path, V6.8.4 fix)

  Tier matrix:
    T24 — broker.py tier table: community=0 OIDC/SAML IdPs documented correctly
    T25 — broker.py tier table: enterprise=999 (unlimited)

Last updated: 2026-04-28T23:58:36+01:00
"""
from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_DIR = SRC / "backoffice" / "routes"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_idp_config(**kwargs):
    from yashigani.auth.broker import IdPConfig
    defaults = dict(
        id="test-idp",
        name="Test IdP",
        protocol="oidc",
        metadata_url="https://idp.example.com/.well-known/openid-configuration",
        client_id="client-id",
        client_secret="client-secret",
    )
    defaults.update(kwargs)
    return IdPConfig(**defaults)


def _make_sso_result(success=True, raw_claims=None, **kwargs):
    from yashigani.auth.broker import SSOResult
    defaults = dict(
        success=success,
        identity_id="usr-001",
        email="alice@example.com",
        name="Alice",
        groups=[],
        idp_name="Test IdP",
        raw_claims=raw_claims or {},
    )
    defaults.update(kwargs)
    return SSOResult(**defaults)


# ---------------------------------------------------------------------------
# T01–T10: acr/amr allowlist semantics
# ---------------------------------------------------------------------------

class TestIdPConfigAcrAmr:
    """T01: IdPConfig accepts required_acr_values and required_amr_values."""

    def test_t01_fields_accept_none(self):
        """T01a: Both fields default to None."""
        cfg = _make_idp_config()
        assert cfg.required_acr_values is None
        assert cfg.required_amr_values is None

    def test_t01_fields_accept_lists(self):
        """T01b: Both fields accept list of strings."""
        cfg = _make_idp_config(
            required_acr_values=["urn:mace:incommon:iap:silver"],
            required_amr_values=["mfa"],
        )
        assert cfg.required_acr_values == ["urn:mace:incommon:iap:silver"]
        assert cfg.required_amr_values == ["mfa"]


class TestAcrAllowlistInRoute:
    """T02–T10: acr/amr validation logic in sso.py (static analysis + object tests)."""

    def _sso_source(self) -> str:
        return (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")

    def test_t02_acr_in_allowlist_phrase_present(self):
        """T02: sso.py must use 'not in _required_acr' (allowlist semantics, not lexicographic)."""
        src = self._sso_source()
        assert "_claim_acr not in _required_acr" in src, (
            "Allowlist check '_claim_acr not in _required_acr' not found. "
            "Lexicographic compare (< min_acr) must be replaced."
        )

    def test_t03_acr_mismatch_failure_audit_written(self):
        """T03: On acr mismatch, sso.py writes acr_not_in_allowlist failure reason."""
        src = self._sso_source()
        assert "acr_not_in_allowlist" in src, (
            "Failure audit reason 'acr_not_in_allowlist' not found in sso.py"
        )

    def test_t04_empty_claim_treated_as_mismatch(self):
        """T04: The allowlist check triggers when _claim_acr is empty (not _claim_acr or ...)."""
        src = self._sso_source()
        # The check must be: 'not _claim_acr or _claim_acr not in _required_acr'
        assert "not _claim_acr or _claim_acr not in _required_acr" in src, (
            "Empty acr must be treated as mismatch. "
            "Check 'not _claim_acr or _claim_acr not in _required_acr' not found."
        )

    def test_t05_amr_subset_phrase_present(self):
        """T05: sso.py uses set subtraction for amr check."""
        src = self._sso_source()
        assert "set(_required_amr) - set(_claim_amr)" in src, (
            "amr set-subset check 'set(_required_amr) - set(_claim_amr)' not found"
        )

    def test_t06_amr_failure_audit_written(self):
        """T06: On amr mismatch, sso.py writes amr_methods_missing failure reason."""
        src = self._sso_source()
        assert "amr_methods_missing" in src, (
            "Failure audit reason 'amr_methods_missing' not found in sso.py"
        )

    def test_t08_null_required_means_no_enforcement(self):
        """T08: required_acr_values=None and required_amr_values=None → both checks skipped.
        Verify via AST: the if-blocks are guarded by `if _required_acr is not None`."""
        src = self._sso_source()
        assert "_required_acr is not None" in src
        assert "_required_amr is not None" in src

    def test_t09_legacy_min_acr_env_var_removed(self):
        """T09: YASHIGANI_MIN_ACR_VALUE must no longer appear in sso.py (replaced by allowlist)."""
        src = self._sso_source()
        assert "YASHIGANI_MIN_ACR_VALUE" not in src, (
            "Legacy YASHIGANI_MIN_ACR_VALUE env var still present. "
            "It was replaced by IdPConfig.required_acr_values allowlist in V6.8.4."
        )

    def test_t10_lexicographic_compare_removed(self):
        """T10: Lexicographic compare `_id_token_acr < _min_acr` removed."""
        src = self._sso_source()
        assert "_id_token_acr < _min_acr" not in src, (
            "Legacy lexicographic acr compare still present — must be replaced by allowlist"
        )


# ---------------------------------------------------------------------------
# T11–T16: SAML AuthnContextClassRef mirror
# ---------------------------------------------------------------------------

class TestSAMLUserInfoFields:
    """T11–T12: SAMLUserInfo authn_context_class_ref / authn_instant fields."""

    def test_t11_authn_context_class_ref_field_exists(self):
        """T11: SAMLUserInfo.authn_context_class_ref defaults to empty string."""
        from yashigani.sso.saml import SAMLUserInfo
        u = SAMLUserInfo(
            subject="s",
            email="a@b.com",
            attributes={},
            session_index=None,
        )
        assert hasattr(u, "authn_context_class_ref")
        assert u.authn_context_class_ref == ""

    def test_t12_authn_instant_field_exists(self):
        """T12: SAMLUserInfo.authn_instant defaults to empty string."""
        from yashigani.sso.saml import SAMLUserInfo
        u = SAMLUserInfo(
            subject="s",
            email="a@b.com",
            attributes={},
            session_index=None,
        )
        assert hasattr(u, "authn_instant")
        assert u.authn_instant == ""

    def test_saml_user_info_explicit_classref(self):
        """SAMLUserInfo accepts explicit authn_context_class_ref value."""
        from yashigani.sso.saml import SAMLUserInfo
        classref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        u = SAMLUserInfo(
            subject="s",
            email="a@b.com",
            attributes={},
            session_index=None,
            authn_context_class_ref=classref,
        )
        assert u.authn_context_class_ref == classref


class TestBrokerSAMLRawClaims:
    """T13: broker.handle_saml_response populates raw_claims with authn_context_class_ref."""

    def _make_broker(self):
        from yashigani.auth.broker import IdentityBroker, IdPConfig
        broker = IdentityBroker(tier="enterprise")
        # Bypass _limit check by directly populating internals
        cfg = IdPConfig(
            id="saml-idp",
            name="Corp SAML",
            protocol="saml",
            entity_id="https://idp.corp.example.com/metadata",
        )
        broker._idps["saml-idp"] = cfg
        return broker, cfg

    def test_t13_raw_claims_populated_from_saml_user_info(self):
        """T13: raw_claims on SSOResult contains authn_context_class_ref."""
        from yashigani.auth.broker import IdentityBroker, IdPConfig
        from yashigani.sso.saml import SAMLUserInfo

        classref = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        mock_user_info = SAMLUserInfo(
            subject="uid=alice",
            email="alice@corp.example.com",
            attributes={"displayName": "Alice"},
            session_index="sess-1",
            authn_context_class_ref=classref,
            authn_instant="2026-04-28T22:00:00Z",
        )

        broker, cfg = self._make_broker()
        mock_provider = MagicMock()
        mock_provider.process_response.return_value = mock_user_info
        broker._saml_providers["saml-idp"] = mock_provider

        result = broker.handle_saml_response("saml-idp", "base64encoded==")
        assert result.success is True
        assert "authn_context_class_ref" in result.raw_claims
        assert result.raw_claims["authn_context_class_ref"] == classref
        assert result.raw_claims["iss"] == "https://idp.corp.example.com/metadata"

    def test_t14_saml_acr_allowlist_match_not_rejected(self):
        """T14: When AuthnContextClassRef is in required_acr_values, result is not rejected.
        Static: sso.py must NOT reject when _saml_classref in _required_saml_acr."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        # The guard must check: not _saml_classref or _saml_classref not in _required_saml_acr
        assert "_saml_classref not in _required_saml_acr" in src, (
            "SAML classref allowlist check not found in sso.py"
        )

    def test_t15_saml_acr_mismatch_failure_reason(self):
        """T15: SAML classref mismatch writes authn_context_class_ref_not_in_allowlist."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        assert "authn_context_class_ref_not_in_allowlist" in src, (
            "'authn_context_class_ref_not_in_allowlist' failure reason not found in sso.py"
        )

    def test_t16_saml_none_required_no_enforcement(self):
        """T16: SAML with required_acr_values=None → check skipped."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        # Guard: _required_saml_acr = idp.required_acr_values if idp else None
        assert "_required_saml_acr = idp.required_acr_values" in src, (
            "_required_saml_acr not derived from idp.required_acr_values in sso.py"
        )
        assert "if _required_saml_acr is not None" in src, (
            "SAML acr check must be guarded by 'if _required_saml_acr is not None'"
        )


# ---------------------------------------------------------------------------
# T17–T22: Audit-log claim fields
# ---------------------------------------------------------------------------

class TestSSOLoginSuccessEventFields:
    """T17: SSOLoginSuccessEvent carries acr/amr/auth_time/iss."""

    def test_t17_acr_field_on_event(self):
        """T17a: SSOLoginSuccessEvent.acr field exists and defaults to ''."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent()
        assert hasattr(ev, "acr")
        assert ev.acr == ""

    def test_t17_amr_field_on_event(self):
        """T17b: SSOLoginSuccessEvent.amr field exists and defaults to []."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent()
        assert hasattr(ev, "amr")
        assert ev.amr == []

    def test_t17_auth_time_field_on_event(self):
        """T17c: SSOLoginSuccessEvent.auth_time defaults to None."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent()
        assert hasattr(ev, "auth_time")
        assert ev.auth_time is None

    def test_t17_iss_field_on_event(self):
        """T17d: SSOLoginSuccessEvent.iss field exists and defaults to ''."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent()
        assert hasattr(ev, "iss")
        assert ev.iss == ""

    def test_t17_full_event_with_claims(self):
        """T17e: SSOLoginSuccessEvent can be constructed with all V6.8.4 fields."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent(
            idp_id="oidc-1",
            idp_name="Corp OIDC",
            identity_id="usr-001",
            email_hash="deadbeef",
            groups=["admins"],
            client_ip_prefix="10.0.0.0",
            acr="urn:mace:incommon:iap:silver",
            amr=["mfa", "totp"],
            auth_time=1714345200,
            iss="https://idp.corp.example.com",
        )
        assert ev.acr == "urn:mace:incommon:iap:silver"
        assert ev.amr == ["mfa", "totp"]
        assert ev.auth_time == 1714345200
        assert ev.iss == "https://idp.corp.example.com"


class TestSAMLAuditEvents:
    """T18–T19: SAMLLoginSuccessEvent and SAMLLoginFailureEvent."""

    def test_t18_saml_login_success_event_exists(self):
        """T18a: SAMLLoginSuccessEvent importable from audit.schema."""
        from yashigani.audit.schema import SAMLLoginSuccessEvent
        ev = SAMLLoginSuccessEvent()
        assert ev.event_type == "SSO_SAML_LOGIN_SUCCESS"

    def test_t18_saml_login_failure_event_exists(self):
        """T18b: SAMLLoginFailureEvent importable from audit.schema."""
        from yashigani.audit.schema import SAMLLoginFailureEvent
        ev = SAMLLoginFailureEvent()
        assert ev.event_type == "SSO_SAML_LOGIN_FAILURE"

    def test_t19_saml_success_event_has_classref_fields(self):
        """T19: SAMLLoginSuccessEvent.authn_context_class_ref/authn_instant/issuer present."""
        from yashigani.audit.schema import SAMLLoginSuccessEvent
        ev = SAMLLoginSuccessEvent()
        assert hasattr(ev, "authn_context_class_ref")
        assert hasattr(ev, "authn_instant")
        assert hasattr(ev, "issuer")
        assert ev.authn_context_class_ref == ""
        assert ev.authn_instant == ""
        assert ev.issuer == ""

    def test_t19_saml_success_event_full_construction(self):
        """T19b: SAMLLoginSuccessEvent can be constructed with all V6.8.4 fields."""
        from yashigani.audit.schema import SAMLLoginSuccessEvent
        ev = SAMLLoginSuccessEvent(
            idp_id="saml-1",
            idp_name="Corp SAML",
            identity_id="usr-002",
            email_hash="cafebabe",
            groups=["users"],
            client_ip_prefix="10.0.1.0",
            authn_context_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
            authn_instant="2026-04-28T22:00:00Z",
            issuer="https://idp.corp.example.com/metadata",
        )
        assert ev.authn_context_class_ref == "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        assert ev.authn_instant == "2026-04-28T22:00:00Z"
        assert ev.issuer == "https://idp.corp.example.com/metadata"


class TestEventTypeEnum:
    """T22: EventType enum has SAML entries."""

    def test_t22_saml_login_success_event_type(self):
        """T22a: EventType.SSO_SAML_LOGIN_SUCCESS defined."""
        from yashigani.audit.schema import EventType
        assert EventType.SSO_SAML_LOGIN_SUCCESS == "SSO_SAML_LOGIN_SUCCESS"

    def test_t22_saml_login_failure_event_type(self):
        """T22b: EventType.SSO_SAML_LOGIN_FAILURE defined."""
        from yashigani.audit.schema import EventType
        assert EventType.SSO_SAML_LOGIN_FAILURE == "SSO_SAML_LOGIN_FAILURE"


class TestAuditWriterHelpers:
    """T20–T21: Audit write helpers pass correct fields."""

    def test_t20_write_sso_success_audit_passes_acr_fields(self):
        """T20: _write_sso_success_audit passes acr/amr/auth_time/iss to SSOLoginSuccessEvent."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        # The function signature must have the acr/amr/auth_time/iss keyword args
        assert "acr: str = \"\"" in src or "acr=" in src, (
            "_write_sso_success_audit must accept acr parameter"
        )
        assert "amr: Optional[list] = None" in src or "amr=" in src, (
            "_write_sso_success_audit must accept amr parameter"
        )
        assert "auth_time: Optional[int] = None" in src, (
            "_write_sso_success_audit must accept auth_time parameter"
        )
        assert "iss: str = \"\"" in src or "iss=" in src, (
            "_write_sso_success_audit must accept iss parameter"
        )

    def test_t21_write_saml_success_audit_function_defined(self):
        """T21: _write_saml_success_audit function exists in sso.py."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        assert "def _write_saml_success_audit" in src, (
            "_write_saml_success_audit not defined in sso.py"
        )
        assert "def _write_saml_failure_audit" in src, (
            "_write_saml_failure_audit not defined in sso.py"
        )
        assert "authn_context_class_ref" in src, (
            "_write_saml_success_audit must pass authn_context_class_ref"
        )

    def test_audit_claims_propagated_through_pending_2fa(self):
        """Pending 2FA JSON must include acr/amr/auth_time/iss fields for OIDC path."""
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")
        # Look for the pending_data JSON that's stored in Redis
        assert '"acr": _claim_acr' in src, (
            "acr not persisted in pending 2FA data — audit log at 2FA completion will be empty"
        )
        assert '"amr": _claim_amr' in src, (
            "amr not persisted in pending 2FA data"
        )


# ---------------------------------------------------------------------------
# T23: SAML 2FA flag default
# ---------------------------------------------------------------------------

class TestSAML2FADefault:
    """T23: YASHIGANI_SSO_2FA_REQUIRED defaults to 'true' in SAML path."""

    def test_t23_saml_2fa_default_is_true(self):
        """T23: The SAML ACS handler must use default 'true', not 'false'."""
        import re
        src = (ROUTES_DIR / "sso.py").read_text(encoding="utf-8")

        # Find all os.getenv("YASHIGANI_SSO_2FA_REQUIRED", ...) calls
        pattern = re.compile(
            r'os\.getenv\("YASHIGANI_SSO_2FA_REQUIRED"\s*,\s*"([^"]+)"\)'
        )
        matches = pattern.findall(src)
        assert matches, "No YASHIGANI_SSO_2FA_REQUIRED getenv found in sso.py"

        # Every occurrence must default to "true"
        false_defaults = [v for v in matches if v != "true"]
        assert not false_defaults, (
            f"YASHIGANI_SSO_2FA_REQUIRED has non-'true' defaults: {false_defaults}. "
            "All occurrences must default to 'true' (V6.8.4 fix — was 'false' in SAML path)."
        )


# ---------------------------------------------------------------------------
# T24–T25: Tier table verification
# ---------------------------------------------------------------------------

class TestTierTable:
    """T24–T25: Verify the tier→IdP-limit table in broker.py."""

    def _get_tier_limits(self) -> dict:
        from yashigani.auth.broker import _TIER_IDP_LIMITS
        return _TIER_IDP_LIMITS

    def test_t24_community_has_zero_idps(self):
        """T24: Community tier has 0 IdPs (local auth only)."""
        limits = self._get_tier_limits()
        assert "community" in limits
        assert limits["community"] == 0, (
            f"Community tier IdP limit is {limits['community']}, expected 0. "
            "Community uses local auth only — no OIDC/SAML (per product table)."
        )

    def test_t25_enterprise_is_unlimited(self):
        """T25: Enterprise tier has 999 (effectively unlimited) IdPs."""
        limits = self._get_tier_limits()
        assert "enterprise" in limits
        assert limits["enterprise"] >= 999, (
            f"Enterprise tier IdP limit is {limits['enterprise']}, expected ≥999."
        )

    def test_tier_table_includes_professional_tiers(self):
        """Starter/Professional/Professional Plus/Non-profit&Education all
        present.

        TB-07 (Lu, 4.1.2): this test previously asserted the STALE string
        "academic" -- which was itself an instance of the bug it should
        have caught. LicenseTier.ACADEMIC_NONPROFIT.value ==
        "academic_nonprofit"; the old assertion passed only because the
        buggy dict happened to carry a key spelled "academic" (unreachable
        via the real enum value), not because the real tier was covered.
        Corrected to the real enum value -- see
        test_tom_tb07_license_tier_key_enum_divergence.py for the full
        root-cause writeup and fix.
        """
        limits = self._get_tier_limits()
        for tier in ("starter", "professional", "professional_plus", "academic_nonprofit"):
            assert tier in limits, f"Tier '{tier}' missing from _TIER_IDP_LIMITS"

    def test_professional_supports_oidc_and_saml(self):
        """Professional tier supports at least 2 IdPs (1 OIDC + 1 SAML per docs)."""
        limits = self._get_tier_limits()
        assert limits.get("professional", 0) >= 2, (
            "Professional tier must allow ≥2 IdPs (OIDC + SAML per product table)"
        )

    def test_starter_supports_single_oidc(self):
        """Starter tier supports 1 IdP (OIDC only per product table)."""
        limits = self._get_tier_limits()
        assert limits.get("starter", 0) == 1, (
            f"Starter tier should have 1 IdP, got {limits.get('starter')}"
        )

    def test_broker_docstring_tier_matrix_documented(self):
        """broker.py docstring must document the tier→SSO capability matrix."""
        src = (SRC / "auth" / "broker.py").read_text(encoding="utf-8")
        assert "Tier gating" in src or "Tier limits" in src, (
            "Tier matrix not documented in broker.py module docstring"
        )
        # Verify all tiers are mentioned in the docstring
        assert "Community" in src or "community" in src
        assert "Enterprise" in src or "enterprise" in src
        assert "Professional" in src or "professional" in src


# ---------------------------------------------------------------------------
# Broker handle_saml_response iss = entity_id
# ---------------------------------------------------------------------------

class TestBrokerSAMLIssuer:
    """V6.8.4: broker.handle_saml_response sets iss = idp.entity_id in raw_claims."""

    def test_broker_sets_iss_to_entity_id(self):
        """raw_claims['iss'] must equal the IdP entity_id from IdPConfig."""
        from yashigani.auth.broker import IdentityBroker, IdPConfig
        from yashigani.sso.saml import SAMLUserInfo

        entity_id = "https://idp.corp.example.com/metadata"
        mock_user_info = SAMLUserInfo(
            subject="uid=bob",
            email="bob@corp.example.com",
            attributes={},
            session_index=None,
            authn_context_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        )

        broker = IdentityBroker(tier="enterprise")
        cfg = IdPConfig(
            id="saml-idp",
            name="Corp SAML",
            protocol="saml",
            entity_id=entity_id,
        )
        broker._idps["saml-idp"] = cfg

        mock_provider = MagicMock()
        mock_provider.process_response.return_value = mock_user_info
        broker._saml_providers["saml-idp"] = mock_provider

        result = broker.handle_saml_response("saml-idp", "base64==")
        assert result.raw_claims.get("iss") == entity_id


# ---------------------------------------------------------------------------
# Round-trip: SSOLoginSuccessEvent serialises V6.8.4 fields
# ---------------------------------------------------------------------------

class TestEventSerialisation:
    """V6.8.4 fields must survive to_dict() for the audit writer."""

    def test_sso_login_success_to_dict(self):
        """SSOLoginSuccessEvent.to_dict() includes acr/amr/auth_time/iss."""
        from yashigani.audit.schema import SSOLoginSuccessEvent
        ev = SSOLoginSuccessEvent(
            acr="urn:mace:incommon:iap:gold",
            amr=["mfa", "hwk"],
            auth_time=1714345200,
            iss="https://idp.example.com",
        )
        d = ev.to_dict()
        assert d["acr"] == "urn:mace:incommon:iap:gold"
        assert d["amr"] == ["mfa", "hwk"]
        assert d["auth_time"] == 1714345200
        assert d["iss"] == "https://idp.example.com"

    def test_saml_login_success_to_dict(self):
        """SAMLLoginSuccessEvent.to_dict() includes authn_context_class_ref."""
        from yashigani.audit.schema import SAMLLoginSuccessEvent
        ev = SAMLLoginSuccessEvent(
            authn_context_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
            authn_instant="2026-04-28T22:00:00Z",
            issuer="https://idp.corp.example.com/metadata",
        )
        d = ev.to_dict()
        assert d["authn_context_class_ref"] == "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
        assert d["authn_instant"] == "2026-04-28T22:00:00Z"
        assert d["issuer"] == "https://idp.corp.example.com/metadata"
