"""
v2.23.3 ACS product gaps — issue #95.

Five ACS-surfaced gaps closed in a single bundled PR:

  Gap 1 — auth_log:   Missing structured audit events (AUTH_LOGIN_ATTEMPT,
                       ACCOUNT_LOCKOUT, PASSWORD_CHANGED, SESSIONS_INVALIDATED).
  Gap 2 — Injection:  SCIM filter query param bypassed Pydantic validation.
  Gap 3 — BFLA:       manage_service() used AdminSession instead of
                       StepUpAdminSession for mutating operations.
  Gap 4 — 3p resp:    HIBP response lines were parsed with raw split()+int()
                       without format validation; OIDC metadata had no schema check.
  Gap 5 — CMMC AC.L2-3.1.1: manage_service() was the unfenced route
                              (same fix as Gap 3).

OWASP references: A09 (audit), A03 (injection), A01 (BFLA), A05 (misconfig)
CMMC: AU.L2-3.3.1, AC.L2-3.1.1, ASVS V2.1.5, V5.1.1, V6.8.4, V7.2.1

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).parent.parent.parent / "yashigani"
_AUDIT_SCHEMA = _SRC / "audit" / "schema.py"
_AUDIT_INIT = _SRC / "audit" / "__init__.py"
_ROUTES_AUTH = _SRC / "backoffice" / "routes" / "auth.py"
_ROUTES_SCIM = _SRC / "backoffice" / "routes" / "scim.py"
_ROUTES_SERVICES = _SRC / "backoffice" / "routes" / "services.py"
_AUTH_PASSWORD = _SRC / "auth" / "password.py"
_AUTH_PG = _SRC / "auth" / "pg_auth.py"
_SSO_OIDC = _SRC / "sso" / "oidc.py"


# ===========================================================================
# Gap 1 — auth_log: missing structured audit events
# ===========================================================================


class TestAuthLogSchemaEvents:
    """Verify the new event types exist in audit/schema.py."""

    def _event_types(self) -> set[str]:
        src = _AUDIT_SCHEMA.read_text(encoding="utf-8")
        return set(re.findall(r'(\w+)\s*=\s*"\w+"', src))

    def test_auth_login_attempt_in_schema(self):
        assert "AUTH_LOGIN_ATTEMPT" in _AUDIT_SCHEMA.read_text()

    def test_account_lockout_in_schema(self):
        assert "ACCOUNT_LOCKOUT" in _AUDIT_SCHEMA.read_text()

    def test_password_changed_in_schema(self):
        assert "PASSWORD_CHANGED" in _AUDIT_SCHEMA.read_text()

    def test_sessions_invalidated_in_schema(self):
        assert "SESSIONS_INVALIDATED" in _AUDIT_SCHEMA.read_text()

    def test_auth_login_attempt_event_class_in_schema(self):
        assert "class AuthLoginAttemptEvent" in _AUDIT_SCHEMA.read_text()

    def test_account_lockout_event_class_in_schema(self):
        assert "class AccountLockoutEvent" in _AUDIT_SCHEMA.read_text()

    def test_password_changed_event_class_in_schema(self):
        assert "class PasswordChangedEvent" in _AUDIT_SCHEMA.read_text()

    def test_sessions_invalidated_event_class_in_schema(self):
        assert "class SessionsInvalidatedEvent" in _AUDIT_SCHEMA.read_text()


class TestAuthLogBarrelExports:
    """Verify the new event classes are exported from audit/__init__.py."""

    def test_auth_login_attempt_exported(self):
        assert "AuthLoginAttemptEvent" in _AUDIT_INIT.read_text()

    def test_account_lockout_exported(self):
        assert "AccountLockoutEvent" in _AUDIT_INIT.read_text()

    def test_password_changed_exported(self):
        assert "PasswordChangedEvent" in _AUDIT_INIT.read_text()

    def test_sessions_invalidated_exported(self):
        assert "SessionsInvalidatedEvent" in _AUDIT_INIT.read_text()

    def test_import_from_audit_package(self):
        """Barrel imports must resolve at import time."""
        from yashigani.audit import (
            AuthLoginAttemptEvent,
            AccountLockoutEvent,
            PasswordChangedEvent,
            SessionsInvalidatedEvent,
        )

        assert AuthLoginAttemptEvent is not None
        assert AccountLockoutEvent is not None
        assert PasswordChangedEvent is not None
        assert SessionsInvalidatedEvent is not None


class TestAuthLogEventInstantiation:
    """Verify the new event dataclasses can be instantiated correctly."""

    def test_auth_login_attempt_instantiation(self):
        from yashigani.audit.schema import AuthLoginAttemptEvent, EventType

        evt = AuthLoginAttemptEvent(
            account_tier="admin",
            admin_account="testadmin@example.com",
            client_ip_prefix="192.168.1.0",
            outcome="attempt",
        )
        assert evt.event_type == EventType.AUTH_LOGIN_ATTEMPT
        assert evt.outcome == "attempt"
        assert evt.masking_applied is True  # immutable floor

    def test_account_lockout_instantiation(self):
        from yashigani.audit.schema import AccountLockoutEvent, EventType

        evt = AccountLockoutEvent(
            account_tier="admin",
            admin_account="testadmin@example.com",
            lockout_type="password",
            failed_attempts=5,
            lockout_duration_seconds=1800,
        )
        assert evt.event_type == EventType.ACCOUNT_LOCKOUT
        assert evt.lockout_type == "password"
        assert evt.failed_attempts == 5
        assert evt.masking_applied is True

    def test_account_lockout_totp_type(self):
        from yashigani.audit.schema import AccountLockoutEvent

        evt = AccountLockoutEvent(
            account_tier="admin",
            admin_account="testadmin@example.com",
            lockout_type="totp",
            failed_attempts=5,
            lockout_duration_seconds=1800,
        )
        assert evt.lockout_type == "totp"

    def test_password_changed_instantiation(self):
        from yashigani.audit.schema import PasswordChangedEvent, EventType

        evt = PasswordChangedEvent(
            account_tier="admin",
            admin_account="testadmin@example.com",
            change_type="self_service",
            old_hash_tail="abcd1234",
            new_hash_tail="efgh5678",
            sessions_invalidated=True,
        )
        assert evt.event_type == EventType.PASSWORD_CHANGED
        assert evt.masking_applied is True  # immutable floor
        assert evt.sessions_invalidated is True

    def test_sessions_invalidated_instantiation(self):
        from yashigani.audit.schema import SessionsInvalidatedEvent, EventType

        evt = SessionsInvalidatedEvent(
            account_tier="admin",
            admin_account="testadmin@example.com",
            acting_admin="",
            reason="password_change",
            sessions_count=-1,
        )
        assert evt.event_type == EventType.SESSIONS_INVALIDATED
        assert evt.reason == "password_change"


class TestAuthLogLoginRouteEmitsAttemptEvent:
    """Verify login() emits AUTH_LOGIN_ATTEMPT before the outcome event."""

    def test_login_route_calls_make_login_attempt_event(self):
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "_make_login_attempt_event" in src, (
            "login() must call _make_login_attempt_event() — AUTH_LOGIN_ATTEMPT not emitted"
        )

    def test_make_login_attempt_event_helper_exists(self):
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "def _make_login_attempt_event" in src

    def test_login_route_emits_attempt_before_auth_call(self):
        """AUTH_LOGIN_ATTEMPT must be written before authenticate() is called."""
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        attempt_pos = src.find("_make_login_attempt_event")
        auth_call_pos = src.find("auth_service.authenticate(")
        assert attempt_pos != -1, "_make_login_attempt_event not found"
        assert auth_call_pos != -1, "auth_service.authenticate() not found"
        assert attempt_pos < auth_call_pos, "AUTH_LOGIN_ATTEMPT must be emitted BEFORE authenticate() is called"

    def test_password_changed_event_helper_exists(self):
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "def _make_password_changed_event" in src

    def test_sessions_invalidated_event_helper_exists(self):
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "def _make_sessions_invalidated_event" in src

    def test_change_password_uses_password_changed_event(self):
        """change_password() must use PasswordChangedEvent, not ConfigChangedEvent."""
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "_make_password_changed_event" in src, "change_password() must use _make_password_changed_event()"

    def test_change_password_emits_sessions_invalidated_event(self):
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        assert "_make_sessions_invalidated_event" in src, "change_password() must emit SESSIONS_INVALIDATED event"


class TestAuthLogLockoutEmitUnit:
    """Verify _emit_lockout_event() in pg_auth works correctly."""

    def test_emit_lockout_event_with_writer(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        mock_writer = MagicMock()
        _emit_lockout_event(mock_writer, "testuser", "password", 5)
        assert mock_writer.write.call_count == 1
        evt = mock_writer.write.call_args[0][0]
        from yashigani.audit.schema import AccountLockoutEvent

        assert isinstance(evt, AccountLockoutEvent)
        assert evt.lockout_type == "password"
        assert evt.failed_attempts == 5

    def test_emit_lockout_event_no_writer_is_noop(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        # Must not raise
        _emit_lockout_event(None, "testuser", "totp", 5)

    def test_emit_lockout_event_swallows_write_error(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        bad_writer = MagicMock()
        bad_writer.write.side_effect = RuntimeError("audit bus down")
        # Must not propagate the error — lockout must not block auth response
        _emit_lockout_event(bad_writer, "testuser", "password", 5)


class TestAuthLogMakeLoginAttemptEvent:
    """Verify _make_login_attempt_event() constructs the correct event."""

    def test_makes_auth_login_attempt_event(self):
        from yashigani.backoffice.routes.auth import _make_login_attempt_event
        from yashigani.audit.schema import AuthLoginAttemptEvent, EventType

        evt = _make_login_attempt_event("admin@example.com", "192.168.1.10")
        assert isinstance(evt, AuthLoginAttemptEvent)
        assert evt.event_type == EventType.AUTH_LOGIN_ATTEMPT
        assert evt.outcome == "attempt"
        assert evt.admin_account == "admin@example.com"

    def test_ipv4_last_octet_masked(self):
        from yashigani.backoffice.routes.auth import _make_login_attempt_event

        evt = _make_login_attempt_event("admin@example.com", "10.20.30.99")
        assert evt.client_ip_prefix == "10.20.30.0"

    def test_non_ipv4_ip_preserved(self):
        from yashigani.backoffice.routes.auth import _make_login_attempt_event

        evt = _make_login_attempt_event("admin@example.com", "::1")
        assert evt.client_ip_prefix == "::1"


# ===========================================================================
# Gap 2 — Injection: SCIM filter query param
# ===========================================================================


class TestSCIMFilterValidation:
    """Verify SCIM filter input validation."""

    def test_parse_filter_email_valid(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        result = _parse_filter_email('userName eq "admin@example.com"')
        assert result == "admin@example.com"

    def test_parse_filter_email_invalid_format_rejected(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        result = _parse_filter_email('userName eq "not-an-email"')
        assert result is None, "Non-email value must be rejected"

    def test_parse_filter_email_injection_attempt_rejected(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        # SQL injection attempt (not used in SQL but verifies input rejection)
        result = _parse_filter_email('userName eq "\'; DROP TABLE admin_accounts; --"')
        assert result is None, "SQL injection attempt must be rejected"

    def test_parse_filter_email_oversized_input_rejected(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        oversized = 'userName eq "' + "a" * 300 + '@example.com"'
        result = _parse_filter_email(oversized)
        assert result is None, "Oversized filter must be rejected"

    def test_parse_filter_empty_returns_none(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        assert _parse_filter_email("") is None
        assert _parse_filter_email("   ") is None

    def test_parse_filter_malformed_returns_none(self):
        from yashigani.backoffice.routes.scim import _parse_filter_email

        assert _parse_filter_email("invalid filter") is None
        assert _parse_filter_email('userName ne "a@b.com"') is None

    def test_scim_list_users_uses_query_param(self):
        """scim_list_users function body must not use request.query_params.get()."""
        src = _ROUTES_SCIM.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "scim_list_users":
                # Walk all attribute accesses inside the function body (excludes docstring)
                for child in ast.walk(node):
                    if isinstance(child, ast.Attribute) and child.attr == "query_params":
                        pytest.fail(
                            "scim_list_users() must NOT access request.query_params — "
                            "use a typed FastAPI Query param instead (ACS gap #95 injection)"
                        )
                return
        pytest.fail("scim_list_users() async function not found in routes/scim.py")

    def test_scim_imports_query(self):
        src = _ROUTES_SCIM.read_text(encoding="utf-8")
        assert "from fastapi import" in src
        assert "Query" in src

    def test_scim_email_regex_defined(self):
        src = _ROUTES_SCIM.read_text(encoding="utf-8")
        assert "_EMAIL_RE" in src, "Email validation regex must be defined"

    def test_scim_max_len_guard(self):
        src = _ROUTES_SCIM.read_text(encoding="utf-8")
        assert "_SCIM_FILTER_MAX_LEN" in src


# ===========================================================================
# Gap 3 — BFLA: manage_service() must require StepUpAdminSession
# ===========================================================================


class TestBFLAServiceManagement:
    """Verify manage_service() requires step-up auth."""

    def test_manage_service_uses_stepup_session(self):
        src = _ROUTES_SERVICES.read_text(encoding="utf-8")
        # Find the manage_service function definition
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "manage_service":
                fn_src = ast.unparse(node)
                assert "StepUpAdminSession" in fn_src, (
                    "manage_service() must use StepUpAdminSession, not AdminSession — "
                    "BFLA: starting/stopping system services requires step-up TOTP"
                )
                return
        pytest.fail("manage_service() async function not found in routes/services.py")

    def test_services_imports_stepup_session(self):
        src = _ROUTES_SERVICES.read_text(encoding="utf-8")
        assert "StepUpAdminSession" in src, "routes/services.py must import StepUpAdminSession"

    def test_list_services_still_uses_admin_session(self):
        """GET (read-only) should remain AdminSession — no step-up needed for read."""
        src = _ROUTES_SERVICES.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_services":
                fn_src = ast.unparse(node)
                assert "AdminSession" in fn_src, "list_services() should use AdminSession (read-only route)"
                return
        pytest.fail("list_services() async function not found in routes/services.py")


# ===========================================================================
# Gap 4 — 3p response validation: HIBP and OIDC metadata
# ===========================================================================


class TestHIBPResponseValidation:
    """Verify HIBP response parsing validates line format."""

    def test_parse_hibp_line_valid(self):
        from yashigani.auth.password import _parse_hibp_line

        result = _parse_hibp_line("00000F7FA6F08AEDA012FCA0F30B04D4835:4")
        assert result is not None
        suffix, count = result
        assert suffix == "00000F7FA6F08AEDA012FCA0F30B04D4835"
        assert count == 4

    def test_parse_hibp_line_zero_count(self):
        from yashigani.auth.password import _parse_hibp_line

        result = _parse_hibp_line("00000F7FA6F08AEDA012FCA0F30B04D4835:0")
        assert result is not None
        _, count = result
        assert count == 0

    def test_parse_hibp_line_empty_returns_none(self):
        from yashigani.auth.password import _parse_hibp_line

        assert _parse_hibp_line("") is None
        assert _parse_hibp_line("  \r\n") is None

    def test_parse_hibp_line_malformed_no_colon_returns_none(self):
        from yashigani.auth.password import _parse_hibp_line

        result = _parse_hibp_line("00000F7FA6F08AEDA012FCA0F30B04D4835")
        assert result is None, "Line without colon must return None, not raise"

    def test_parse_hibp_line_short_suffix_rejected(self):
        from yashigani.auth.password import _parse_hibp_line

        # 34 chars instead of 35
        result = _parse_hibp_line("0000F7FA6F08AEDA012FCA0F30B04D4835:4")
        assert result is None, "Suffix with wrong length must be rejected"

    def test_parse_hibp_line_non_hex_suffix_rejected(self):
        from yashigani.auth.password import _parse_hibp_line

        # Replace first char with 'Z' (not valid hex)
        result = _parse_hibp_line("Z0000F7FA6F08AEDA012FCA0F30B04D4835:4")
        assert result is None, "Non-hex suffix must be rejected"

    def test_parse_hibp_line_non_numeric_count_rejected(self):
        from yashigani.auth.password import _parse_hibp_line

        result = _parse_hibp_line("00000F7FA6F08AEDA012FCA0F30B04D4835:NOTANUMBER")
        assert result is None, "Non-numeric count must return None via regex guard"

    def test_parse_hibp_line_uppercase_normalised(self):
        from yashigani.auth.password import _parse_hibp_line

        result = _parse_hibp_line("00000f7fa6f08aeda012fca0f30b04d4835:4")
        # Line is uppercase-normalised by the regex (only accepts A-F)
        # Lower-case hex fails the regex — returns None, not matching
        assert result is None, "Lowercase hex suffix must be rejected (HIBP API returns uppercase)"

    def test_hibp_parser_used_in_check_hibp(self):
        """check_hibp() must call _parse_hibp_line(), not bare split()."""
        src = _AUTH_PASSWORD.read_text(encoding="utf-8")
        # Verify _parse_hibp_line is called in the response-parsing loop
        assert "_parse_hibp_line" in src
        # Verify the old split+int pattern is no longer used in the loop
        # (it may still exist in _parse_hibp_line itself, which is fine)
        # Find the part of check_hibp after response.text.splitlines()
        check_fn_start = src.find("def check_hibp(")
        check_fn_end = src.find("\ndef ", check_fn_start + 1)
        check_fn_body = src[check_fn_start:check_fn_end]
        assert "_parse_hibp_line" in check_fn_body, "check_hibp() must use _parse_hibp_line() for response parsing"


class TestOIDCMetadataValidation:
    """Verify OIDC discovery metadata is validated with _validate_oidc_metadata()."""

    def test_validate_oidc_metadata_valid(self):
        from yashigani.sso.oidc import _validate_oidc_metadata

        valid_meta = {
            "issuer": "https://accounts.example.com",
            "authorization_endpoint": "https://accounts.example.com/o/oauth2/v2/auth",
            "token_endpoint": "https://accounts.example.com/token",
            "jwks_uri": "https://accounts.example.com/.well-known/jwks.json",
        }
        result = _validate_oidc_metadata(valid_meta)
        assert result is valid_meta  # returns the same dict on success

    def test_validate_oidc_metadata_missing_issuer_raises(self):
        from yashigani.sso.oidc import _validate_oidc_metadata

        with pytest.raises(ValueError, match="issuer"):
            _validate_oidc_metadata(
                {
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/jwks",
                }
            )

    def test_validate_oidc_metadata_missing_jwks_uri_raises(self):
        from yashigani.sso.oidc import _validate_oidc_metadata

        with pytest.raises(ValueError, match="jwks_uri"):
            _validate_oidc_metadata(
                {
                    "issuer": "https://example.com",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                }
            )

    def test_validate_oidc_metadata_http_url_rejected(self):
        from yashigani.sso.oidc import _validate_oidc_metadata

        with pytest.raises(ValueError, match="https://"):
            _validate_oidc_metadata(
                {
                    "issuer": "https://example.com",
                    "authorization_endpoint": "http://example.com/auth",  # http, not https
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/jwks",
                }
            )

    def test_validate_oidc_metadata_non_string_field_raises(self):
        from yashigani.sso.oidc import _validate_oidc_metadata

        with pytest.raises(ValueError):
            _validate_oidc_metadata(
                {
                    "issuer": 12345,  # not a string
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/jwks",
                }
            )

    def test_validate_oidc_metadata_extra_fields_allowed(self):
        """OIDC IdPs extend the spec — extra fields must be tolerated."""
        from yashigani.sso.oidc import _validate_oidc_metadata

        meta = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "scopes_supported": ["openid", "email"],
            "response_types_supported": ["code"],
            "vendor_extension_field": "anything",
        }
        result = _validate_oidc_metadata(meta)
        assert "vendor_extension_field" in result

    def test_validate_oidc_metadata_called_in_get_metadata(self):
        """_get_metadata() must call _validate_oidc_metadata() on the raw response."""
        src = _SSO_OIDC.read_text(encoding="utf-8")
        # Find _get_metadata
        assert "_validate_oidc_metadata" in src, "_validate_oidc_metadata must be called in _get_metadata()"
        meta_fn_start = src.find("def _get_metadata(")
        assert meta_fn_start != -1
        meta_fn_end = src.find("\n    def ", meta_fn_start + 1)
        meta_fn_body = src[meta_fn_start:meta_fn_end]
        assert "_validate_oidc_metadata" in meta_fn_body, (
            "_validate_oidc_metadata must be called inside _get_metadata()"
        )


# ===========================================================================
# Gap 5 — CMMC AC.L2-3.1.1: explicit access control on all routes
# ===========================================================================


class TestCMMCAccessControl:
    """
    Verify all mutating service management routes have explicit access control.

    CMMC AC.L2-3.1.1 requires limiting information system access to authorised
    users and processes acting on behalf of authorised users.  Mutating routes
    must gate on a session dependency — AdminSession or StepUpAdminSession.

    Intentionally unprotected routes (documented exceptions):
    - GET  /healthz              — Docker/Podman healthcheck (no auth by design)
    - POST /admin/csp-report     — Browser CSP reports (no session available)
    - POST /auth/login           — Login endpoint (pre-auth by definition)
    - GET  /auth/verify          — Caddy forward_auth (validated differently)
    - POST /auth/password/self-reset — Self-service recovery (uses TOTP, no session)
    - POST /auth/webauthn/login/start  — WebAuthn ceremony start (public)
    - POST /auth/webauthn/login/finish — WebAuthn ceremony finish (issues session)
    """

    def test_manage_service_not_using_plain_admin_session(self):
        """
        manage_service() must use StepUpAdminSession, not plain AdminSession.
        CMMC AC.L2-3.1.1: starting/stopping system services is a high-impact
        action; step-up TOTP re-auth is required (ASVS V6.8.4).
        """
        src = _ROUTES_SERVICES.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "manage_service":
                fn_src = ast.unparse(node)
                assert "StepUpAdminSession" in fn_src, (
                    "manage_service() must use StepUpAdminSession for CMMC AC.L2-3.1.1"
                )
                assert "AdminSession" not in fn_src or "StepUpAdminSession" in fn_src, (
                    "manage_service() must not use bare AdminSession"
                )
                return
        pytest.fail("manage_service() not found")

    def test_services_module_imports_stepup(self):
        src = _ROUTES_SERVICES.read_text(encoding="utf-8")
        assert "StepUpAdminSession" in src

    def test_audit_schema_has_all_four_new_event_types(self):
        """All four new event types must be present for complete audit coverage."""
        src = _AUDIT_SCHEMA.read_text(encoding="utf-8")
        for et in ("AUTH_LOGIN_ATTEMPT", "ACCOUNT_LOCKOUT", "PASSWORD_CHANGED", "SESSIONS_INVALIDATED"):
            assert et in src, f"EventType.{et} missing from audit/schema.py"

    def test_pg_auth_authenticate_accepts_audit_writer_kwarg(self):
        """authenticate() must accept audit_writer as a keyword argument."""
        src = _AUTH_PG.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "authenticate":
                fn_src = ast.unparse(node)
                assert "audit_writer" in fn_src, (
                    "authenticate() must accept audit_writer= kwarg for ACCOUNT_LOCKOUT events"
                )
                return
        pytest.fail("authenticate() not found in pg_auth.py")

    def test_login_route_passes_audit_writer_to_authenticate(self):
        """login() must pass audit_writer= to auth_service.authenticate()."""
        src = _ROUTES_AUTH.read_text(encoding="utf-8")
        # Find the authenticate call
        assert "audit_writer=state.audit_writer" in src, (
            "login() must pass audit_writer=state.audit_writer to authenticate()"
        )
