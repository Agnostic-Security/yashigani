"""
v2.23.4 arch-completion — Bundle 1 regression tests.

Covers:
  A1 — Gap 1: email-as-username enforcement in CreateUserRequest
  A2 — F9 / Q3 REVISED: suspended-identity check on login path
       (_register_human_identity_on_login) — Q3 (2026-05-15) REVERTS
       auto-reactivate on login; suspended identity now blocks login (403).
       Full Q3 tests are in test_v2234_gap3_q3_reactivate.py.
  D2 — BYOK SP-key load-time validation spot-check

Source references:
  src/yashigani/backoffice/routes/users.py   — CreateUserRequest (A1)
  src/yashigani/backoffice/routes/auth.py    — _register_human_identity_on_login (A2/Q3)
  src/yashigani/sso/saml.py                 — SAMLProvider.__init__ + _assert_rsa_sp_key (D2)

Last updated: 2026-05-15T00:00:00+01:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from typing import Optional
from dataclasses import dataclass, field


# ===========================================================================
# A1 — Gap 1: email-as-username enforcement in CreateUserRequest
# ===========================================================================

class TestCreateUserRequestEmailRequired:
    """
    A1 regression: CreateUserRequest must REQUIRE `email` for user-tier creation.

    Design intent (Tiago 2026-05-14): "email as the username for normal users".

    If the email requirement is weakened (made Optional again), these tests fail
    before the system regresses to the old behaviour.
    """

    def _validate(self, data: dict):
        from yashigani.backoffice.routes.users import CreateUserRequest
        return CreateUserRequest.model_validate(data)

    def test_email_required_missing_raises_validation_error(self):
        """
        POST /admin/users without `email` must return 422.
        Before A1: email was Optional → could create username-only accounts.
        After A1: email is required → 422 on missing field.
        """
        from pydantic import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            self._validate({"username": "alice"})
        errors = exc_info.value.errors()
        field_names = [e["loc"][0] for e in errors]
        assert "email" in field_names, (
            f"Expected validation error on 'email' field, got: {errors}"
        )

    def test_valid_email_accepted(self):
        """Valid email + no username → model validates; username derived."""
        req = self._validate({"email": "alice@example.com"})
        assert str(req.email) == "alice@example.com"
        # username derived from local part of email
        assert req.username is not None
        assert len(req.username) >= 3

    def test_username_derived_from_email_local_part(self):
        """When username is omitted, it should be derived from email local part."""
        req = self._validate({"email": "bob@example.com"})
        assert "bob" in req.username.lower(), (
            f"Expected 'bob' in derived username, got: {req.username!r}"
        )

    def test_explicit_username_accepted(self):
        """When username is explicitly supplied, it is used as-is."""
        req = self._validate({"email": "carol@example.com", "username": "c_smith"})
        assert req.username == "c_smith"
        assert str(req.email) == "carol@example.com"

    def test_invalid_email_raises_validation_error(self):
        """Malformed email must produce a validation error (EmailStr enforcement)."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._validate({"email": "not-an-email"})

    def test_invalid_email_missing_domain_raises(self):
        """Email without domain raises ValidationError."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._validate({"email": "alice@"})

    def test_email_only_no_username_creates_valid_request(self):
        """email is the only required field — username is derived."""
        req = self._validate({"email": "dave@corp.example.org"})
        assert req.email is not None
        assert req.username is not None
        assert len(req.username) >= 3

    def test_username_with_special_chars_derived_safely(self):
        """
        Email with special chars in local part (dots, plus) produces a safe username.
        username must be 3-64 chars of alphanumeric / underscore / hyphen.
        """
        req = self._validate({"email": "first.last+tag@example.com"})
        # Must be a valid identifier — no dots or plus signs
        assert "." not in req.username
        assert "+" not in req.username
        assert len(req.username) >= 3

    def test_regression_old_username_only_pattern_now_fails(self):
        """
        Pre-A1 pattern: {"username": "alice", "email": null}.
        Post-A1: must fail validation because email is required.

        If this test passes when old pattern succeeds, A1 has regressed.
        """
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._validate({"username": "alice", "email": None})


# ===========================================================================
# A2 — F9: suspended-identity check on login path
# ===========================================================================

@dataclass
class _A2Record:
    """Minimal AccountRecord for A2 tests."""
    username: str
    account_id: str
    account_tier: str = "user"
    email: Optional[str] = "alice@example.com"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False


def _make_a2_registry(existing_identity: dict | None = None):
    """Make a MagicMock registry that returns existing_identity on get_by_slug."""
    registry = MagicMock()
    registry.get_by_slug = MagicMock(return_value=existing_identity)
    registry.register = MagicMock(return_value=("idnt_new", "plaintext-key"))
    registry.reactivate = MagicMock()
    return registry


def _make_a2_state(registry=None):
    state = MagicMock()
    state.identity_registry = registry
    return state


def _call_register(record, registry):
    from yashigani.backoffice.routes.auth import _register_human_identity_on_login
    state = _make_a2_state(registry=registry)
    _register_human_identity_on_login(record, state)
    return state


class TestSuspendedIdentityCheck:
    """
    A2 / Q3 regression: suspended HUMAN identity on login path.

    REVISED 2026-05-15 (Q3 Tiago directive): auto-reactivate on login REVERTED.
    Suspended identity now BLOCKS login (403) and audit-logs the attempt.
    Admin must call POST /admin/users/{username}/reactivate to restore access.

    Full Q3 test coverage is in test_v2234_gap3_q3_reactivate.py.
    These A2 tests are updated to reflect the new Q3 behaviour so they
    don't falsely fail as regressions of a no-longer-intended behaviour.
    """

    def test_suspended_identity_blocks_login(self):
        """
        Q3: suspended identity → _register_human_identity_on_login raises 403.

        Before be75aab: existing identity → return early (no reactivate).
        After be75aab (pre-Q3): suspended identity → auto-reactivate().
        After Q3 revert: suspended identity → HTTPException(403, account_suspended).
        """
        from fastapi import HTTPException
        record = _A2Record(username="alice", account_id="u-001")
        existing = {
            "identity_id": "idnt_suspended",
            "kind": "human",
            "slug": "alice-example-com",
            "status": "suspended",
        }
        registry = _make_a2_registry(existing_identity=existing)

        with pytest.raises(HTTPException) as exc_info:
            _call_register(record, registry)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "account_suspended"
        # Must NOT reactivate — admin-only action.
        registry.reactivate.assert_not_called()
        registry.register.assert_not_called()

    def test_inactive_identity_blocks_login(self):
        """
        Q3 variant: status='inactive' is treated identically to 'suspended' — blocks login.
        """
        from fastapi import HTTPException
        record = _A2Record(username="alice", account_id="u-001")
        existing = {
            "identity_id": "idnt_inactive",
            "kind": "human",
            "slug": "alice-example-com",
            "status": "inactive",
        }
        registry = _make_a2_registry(existing_identity=existing)

        with pytest.raises(HTTPException) as exc_info:
            _call_register(record, registry)

        assert exc_info.value.status_code == 403
        registry.reactivate.assert_not_called()

    def test_active_identity_not_reactivated(self):
        """
        Active identity: reactivate() MUST NOT be called; register() MUST NOT be called.
        (Active idempotency path — existing behaviour preserved.)
        """
        record = _A2Record(username="alice", account_id="u-001")
        existing = {
            "identity_id": "idnt_active",
            "kind": "human",
            "slug": "alice-example-com",
            "status": "active",
        }
        registry = _make_a2_registry(existing_identity=existing)
        _call_register(record, registry)

        registry.reactivate.assert_not_called()
        registry.register.assert_not_called()

    def test_no_existing_identity_registers_new(self):
        """
        No existing identity: register() is called once; reactivate() not called.
        (First-login path — existing behaviour preserved.)
        """
        record = _A2Record(username="alice", account_id="u-001")
        registry = _make_a2_registry(existing_identity=None)
        _call_register(record, registry)

        registry.register.assert_called_once()
        registry.reactivate.assert_not_called()

    def test_existing_identity_without_status_field_treated_as_active(self):
        """
        Edge case: identity dict missing 'status' key.
        Should default to 'active' (safe fallback — don't re-register or crash).
        """
        record = _A2Record(username="alice", account_id="u-001")
        existing = {
            "identity_id": "idnt_nostatus",
            "kind": "human",
            "slug": "alice-example-com",
            # No 'status' key — old format or partial record
        }
        registry = _make_a2_registry(existing_identity=existing)
        _call_register(record, registry)

        # Neither re-register nor reactivate
        registry.register.assert_not_called()
        registry.reactivate.assert_not_called()

    def test_disable_reenable_cycle_requires_admin_reactivate(self):
        """
        Q3 REVISED: disable→re-enable cycle now requires explicit admin reactivation.

        Step 1: user exists with active HUMAN identity.
        Step 2: admin disables user → identity suspended (suspend_owned_by).
        Step 3: admin re-enables user account (identity still suspended).
        Step 4: user attempts login → blocked with 403 account_suspended.
        Step 5: admin calls POST /admin/users/{username}/reactivate (StepUp).
        Step 6: user logs in again → identity is active → /v1/* works.

        This test asserts Step 4: login must NOT succeed while identity is
        suspended, and auto-reactivate must NOT fire. The full admin-reactivate
        endpoint tests (Step 5-6) are in test_v2234_gap3_q3_reactivate.py.
        """
        from fastapi import HTTPException
        record = _A2Record(username="bob", account_id="u-bob-001")

        # Step 3 state: account is re-enabled but identity is still suspended.
        suspended_identity = {
            "identity_id": "idnt_bob_human",
            "kind": "human",
            "slug": "bob-example-com",
            "status": "suspended",  # set by disable → suspend_owned_by
        }

        registry = _make_a2_registry(existing_identity=suspended_identity)

        # Step 4: login attempt is blocked.
        with pytest.raises(HTTPException) as exc_info:
            _call_register(record, registry)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["error"] == "account_suspended"

        # Critical: reactivate NOT called — admin must do it explicitly.
        registry.reactivate.assert_not_called()
        # register NOT called — identity already exists.
        registry.register.assert_not_called()

    def test_admin_tier_suspended_identity_not_reactivated(self):
        """
        Admin accounts MUST NOT have HUMAN identities reactivated (Gap 2 invariant).
        The account_tier guard must fire BEFORE we reach the suspended-identity check.
        """
        record = _A2Record(
            username="admin@example.com",
            account_id="admin-001",
            account_tier="admin",  # admin tier
        )
        existing = {
            "identity_id": "idnt_admin_should_not_exist",
            "kind": "human",
            "slug": "admin-example-com",
            "status": "suspended",
        }
        registry = _make_a2_registry(existing_identity=existing)
        _call_register(record, registry)

        # Neither register nor reactivate — admin guard must fire first.
        registry.register.assert_not_called()
        registry.reactivate.assert_not_called()


# ===========================================================================
# D2 — BYOK SP-key load-time validation spot-check
# ===========================================================================

class TestBYOKSpKeyValidation:
    """
    D2: Spot-check that the RSA SP-key enforcement fires on BYOK key paths.

    Scenario: admin replaces saml_sp.key with an EC key (BYOK — Bring Your Own Key),
    then restarts the container. SAMLProvider.__init__ must fail loudly with
    ValueError referencing YSG-RISK-044.

    Tom's commit 105be23 added _assert_rsa_sp_key() called at SAMLProvider.__init__.
    The existing tests (test_v2234_rsa_sp_key_enforcement.py) cover T1-T7 for the
    _assert_rsa_sp_key function directly and via SAMLProvider.__init__.

    D2 specifically documents the BYOK scenario:
    (a) Install-generated RSA SP key → accepted (Su's 7cdbcf9 post-gen check).
    (b) BYOK EC key from file → SAMLProvider.__init__ raises ValueError.
    (c) Test confirms end-to-end: admin cannot degrade SAML to EC silently.
    """

    def _make_ec_pem_str(self) -> str:
        """Generate a P-256 EC private key as a full PEM string."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat
        )
        key = ec.generate_private_key(ec.SECP256R1())
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        ).decode("ascii")

    def _make_rsa_pem_str(self) -> str:
        """Generate a 2048-bit RSA private key as a full PEM string."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        ).decode("ascii")

    def _make_ec_pem_body(self) -> str:
        """Return EC key without PEM headers (python3-saml storage format)."""
        pem = self._make_ec_pem_str()
        lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
        return "\n".join(lines)

    def _make_rsa_pem_body(self) -> str:
        """Return RSA key without PEM headers."""
        pem = self._make_rsa_pem_str()
        lines = [ln for ln in pem.splitlines() if not ln.startswith("-----")]
        return "\n".join(lines)

    def _saml_config(self, sp_private_key: str):
        from yashigani.sso.saml import SAMLConfig
        return SAMLConfig(
            sp_entity_id="https://sp.example.com/saml",
            sp_acs_url="https://sp.example.com/saml/acs",
            sp_sls_url="https://sp.example.com/saml/sls",
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            idp_sls_url="https://idp.example.com/sls",
            idp_x509_cert="MIIB...",
            sp_private_key=sp_private_key,
            sp_certificate="MIIB...",
        )

    def test_d2_byok_ec_key_full_pem_rejected(self):
        """
        D2(b): Admin supplies BYOK EC key (full PEM with headers).
        SAMLProvider.__init__ must raise ValueError citing YSG-RISK-044.

        If this test fails, an admin can degrade SAML to an EC SP key without
        any startup error, silently enabling the CVE-2026-41989 attack path.
        """
        from yashigani.sso.saml import SAMLProvider
        ec_pem = self._make_ec_pem_str()
        cfg = self._saml_config(ec_pem)
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            SAMLProvider(cfg)

    def test_d2_byok_ec_key_no_headers_rejected(self):
        """
        D2(b) variant: Admin supplies BYOK EC key in python3-saml body format
        (no PEM headers — e.g. extracted from existing config or cert store).
        """
        from yashigani.sso.saml import SAMLProvider
        ec_body = self._make_ec_pem_body()
        cfg = self._saml_config(ec_body)
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            SAMLProvider(cfg)

    def test_d2_byok_rsa_key_accepted(self):
        """
        D2(a/c): Install-generated (or admin-supplied) RSA key is accepted.
        SAMLProvider.__init__ must not raise for a valid RSA key.
        This confirms the enforcement does not block the intended key type.
        """
        from yashigani.sso.saml import SAMLProvider
        rsa_pem = self._make_rsa_pem_str()
        cfg = self._saml_config(rsa_pem)
        # Must not raise.
        SAMLProvider(cfg)

    def test_d2_byok_rsa_body_format_accepted(self):
        """
        D2: RSA key in python3-saml body format (no headers) also accepted.
        Confirms BYOK via config file extraction also works correctly.
        """
        from yashigani.sso.saml import SAMLProvider
        rsa_body = self._make_rsa_pem_body()
        cfg = self._saml_config(rsa_body)
        SAMLProvider(cfg)

    def test_d2_byok_error_message_contains_remediation(self):
        """
        D2(c): Error message from EC key rejection must include the openssl
        remediation command so operators know how to fix the BYOK key.
        """
        from yashigani.sso.saml import SAMLProvider
        ec_pem = self._make_ec_pem_str()
        cfg = self._saml_config(ec_pem)
        with pytest.raises(ValueError) as exc_info:
            SAMLProvider(cfg)
        msg = str(exc_info.value)
        assert "openssl genrsa" in msg, (
            f"Expected remediation command in error message, got: {msg!r}"
        )

    def test_d2_byok_assert_rsa_sp_key_standalone_ec_rejected(self):
        """
        D2: _assert_rsa_sp_key() called directly (as it would be from any
        BYOK config-loading path) rejects EC keys.
        """
        from yashigani.sso.saml import _assert_rsa_sp_key
        ec_pem = self._make_ec_pem_str()
        with pytest.raises(ValueError, match="YSG-RISK-044"):
            _assert_rsa_sp_key(ec_pem)

    def test_d2_byok_assert_rsa_sp_key_standalone_rsa_accepted(self):
        """
        D2: _assert_rsa_sp_key() accepts RSA key (install.sh generated or BYOK).
        """
        from yashigani.sso.saml import _assert_rsa_sp_key
        rsa_pem = self._make_rsa_pem_str()
        # Must not raise.
        _assert_rsa_sp_key(rsa_pem)


# ===========================================================================
# D6 — Migration script unit test
# ===========================================================================

class TestMigrationScript:
    """
    D6: Unit tests for the migration decision table logic in
    v2234_email_as_username.py.

    The migration script backfills email for user-tier records.
    These tests exercise the decision function without a real database.
    """

    def test_email_shape_detection_valid_emails(self):
        """Strings with @ and valid domain should be detected as email-shaped."""
        from yashigani.migrations.v2234_email_as_username import _looks_like_email
        assert _looks_like_email("alice@example.com")
        assert _looks_like_email("admin@yashigani.local")
        assert _looks_like_email("user.name+tag@corp.example.org")

    def test_email_shape_detection_invalid(self):
        """Strings without @ or with bad domain should NOT be detected as email-shaped."""
        from yashigani.migrations.v2234_email_as_username import _looks_like_email
        assert not _looks_like_email("alice")
        assert not _looks_like_email("alice@")
        assert not _looks_like_email("@example.com")
        assert not _looks_like_email("notanemail")
        assert not _looks_like_email("alice@localhost")  # no TLD

    def test_migration_module_importable(self):
        """Migration script is importable without side effects."""
        import yashigani.migrations.v2234_email_as_username as m
        assert hasattr(m, "_looks_like_email")
        assert hasattr(m, "_run")
        assert hasattr(m, "main")
