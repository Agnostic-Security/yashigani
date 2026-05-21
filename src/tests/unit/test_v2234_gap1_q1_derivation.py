"""
v2.23.4 arch-completion — Q1 username derivation algorithm regression tests.

Covers the _derive_username_from_email() function per Tiago verbatim spec
(2026-05-15):

Algorithm:
  Given email <local>@<host>:
  1. Local-part: strip chars outside [a-zA-Z0-9_\-] (strip '+' delimiter,
     KEEP the content after '+' tag — e.g. alice+work → alicework)
  2. First domain label: everything before the first '.' in host; hyphens kept.
  3. Concatenate: <sanitised-local><first-label>, lowercase
  4. Truncate to 64 chars.
  5. DB UNIQUE collision → 409 with remediation message.

Tiago verbatim examples:
  alice@domain.com   → alicedomain
  alice@my-co.com    → alicemy-co
  alice+work@x.com   → aliceworkx  (strip '+', keep "work", concat "x")
  a@x.co.uk          → ax

Source: src/yashigani/backoffice/routes/users.py::_derive_username_from_email

Last updated: 2026-05-15T00:00:00+01:00
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Optional
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _derive(email: str) -> str:
    from yashigani.backoffice.routes.users import _derive_username_from_email
    return _derive_username_from_email(email)


def _validate_request(data: dict):
    from yashigani.backoffice.routes.users import CreateUserRequest
    return CreateUserRequest.model_validate(data)


# ===========================================================================
# 1. _derive_username_from_email unit tests
# ===========================================================================

class TestDeriveUsernameFromEmail:

    def test_derive_simple(self):
        """alice@domain.com → alicedomain  (Tiago verbatim example)."""
        assert _derive("alice@domain.com") == "alicedomain"

    def test_derive_hyphen_domain_kept(self):
        """alice@my-co.com → alicemy-co  (Tiago verbatim: "alicemy-co (keep)")."""
        assert _derive("alice@my-co.com") == "alicemy-co"

    def test_derive_plus_tag_handling(self):
        """
        alice+work@x.com → aliceworkx.

        Tiago verbatim: "aliceworkx (keep)" — the '+' delimiter is stripped;
        the tag content "work" is preserved; then concatenated with first label "x".

        Interpretation documented in Q1 commit body:
          local-part  = "alice+work"
          strip '+'   → "alicework"
          first-label = "x"
          result      = "aliceworkx"
        """
        assert _derive("alice+work@x.com") == "aliceworkx"

    def test_derive_multi_label_tld_first_only(self):
        """a@x.co.uk → ax  (only first label 'x', not 'x.co')."""
        assert _derive("a@x.co.uk") == "ax"

    def test_derive_truncate_at_64(self):
        """Long email → result truncated to exactly 64 chars."""
        long_local = "a" * 40
        long_domain = "b" * 40 + ".com"
        email = f"{long_local}@{long_domain}"
        result = _derive(email)
        assert len(result) == 64, f"Expected 64 chars, got {len(result)}: {result!r}"

    def test_derive_lowercase(self):
        """Alice@Domain.com → alicedomain  (all lowercase)."""
        assert _derive("Alice@Domain.com") == "alicedomain"

    def test_derive_uppercase_local_and_domain(self):
        """BOB@MY-CO.COM → bobmy-co  (lowercase both parts)."""
        assert _derive("BOB@MY-CO.COM") == "bobmy-co"

    def test_derive_single_char_local_and_domain(self):
        """a@x.com → ax  (short but valid)."""
        assert _derive("a@x.com") == "ax"

    def test_derive_underscore_in_local_kept(self):
        """first_last@example.com → first_lastexample  (underscore kept)."""
        assert _derive("first_last@example.com") == "first_lastexample"

    def test_derive_hyphen_in_local_kept(self):
        """first-last@example.com → first-lastexample  (hyphen kept)."""
        assert _derive("first-last@example.com") == "first-lastexample"

    def test_derive_dot_in_local_stripped(self):
        """first.last@example.com → firstlastexample  (dot stripped)."""
        assert _derive("first.last@example.com") == "firstlastexample"

    def test_derive_multiple_plus_tags(self):
        """user+tag1+tag2@corp.example.org → usertag1tag2corp  (both '+' stripped)."""
        assert _derive("user+tag1+tag2@corp.example.org") == "usertag1tag2corp"

    def test_derive_subdomain_only_first_label_used(self):
        """alice@mail.example.com → alicemail  (only 'mail', not 'mail.example')."""
        assert _derive("alice@mail.example.com") == "alicemail"

    def test_derive_result_is_all_lowercase(self):
        """Derived username must always be lowercase regardless of input case."""
        result = _derive("ALICE+WORK@MY-CO.COM")
        assert result == result.lower(), f"Result not lowercase: {result!r}"

    def test_derive_truncate_preserves_prefix(self):
        """Truncation takes the FIRST 64 chars, not the last."""
        email = "averylongusername@averylongdomainname.com"
        result = _derive(email)
        expected_prefix = ("averylongusername" + "averylongdomainname").lower()[:64]
        assert result == expected_prefix

    def test_derive_only_special_chars_in_local(self):
        """
        Email where local part is entirely special chars (e.g. +++@x.com).
        After stripping, local becomes empty string; result is just the domain label.
        """
        result = _derive("+++@x.com")
        # '+' stripped → empty local; first label 'x'; result 'x'
        assert result == "x"

    def test_derive_exact_64_chars_not_truncated(self):
        """A result that is exactly 64 chars is not truncated further."""
        # 32-char local + 32-char first-label = 64
        local = "a" * 32
        domain = "b" * 32 + ".com"
        result = _derive(f"{local}@{domain}")
        assert len(result) == 64

    def test_derive_result_over_64_is_truncated(self):
        """A result over 64 chars is truncated to exactly 64."""
        local = "a" * 35
        domain = "b" * 35 + ".com"
        result = _derive(f"{local}@{domain}")
        assert len(result) == 64


# ===========================================================================
# 2. CreateUserRequest validator — explicit username bypasses derive
# ===========================================================================

class TestCreateUserRequestQ1:

    def test_explicit_username_bypasses_derive(self):
        """
        When admin supplies explicit `username`, _derive_username_from_email
        is NOT invoked — the supplied username is used as-is.

        This confirms the bypass path (test 8 from brief).
        """
        req = _validate_request({"email": "alice@domain.com", "username": "myexplicit"})
        assert req.username == "myexplicit"
        # email still stored
        assert str(req.email) == "alice@domain.com"

    def test_no_username_triggers_derivation(self):
        """When username is absent, derivation fires and returns correct value."""
        req = _validate_request({"email": "alice@domain.com"})
        assert req.username == "alicedomain"

    def test_derive_via_validator_hyphen_domain(self):
        req = _validate_request({"email": "alice@my-co.com"})
        assert req.username == "alicemy-co"

    def test_derive_via_validator_plus_tag(self):
        req = _validate_request({"email": "alice+work@x.com"})
        assert req.username == "aliceworkx"

    def test_derive_via_validator_multi_label_tld(self):
        req = _validate_request({"email": "a@x.co.uk"})
        assert req.username == "ax"

    def test_derive_via_validator_truncate(self):
        long_local = "z" * 40
        long_domain = "y" * 40 + ".com"
        req = _validate_request({"email": f"{long_local}@{long_domain}"})
        assert len(req.username) == 64

    def test_derive_via_validator_lowercase(self):
        req = _validate_request({"email": "Alice@Domain.com"})
        assert req.username == "alicedomain"


# ===========================================================================
# 3. Collision → 409 (via mock DB exception)
# ===========================================================================

@dataclass
class _FakeRecord:
    username: str
    account_id: str = "u-001"
    account_tier: str = "user"
    email: Optional[str] = "alice@domain.com"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False


def _make_state_for_create(existing_account=None, create_raises=None):
    """
    Build a mock backoffice_state sufficient for the create_user route handler.
    """
    auth_service = AsyncMock()
    auth_service.get_account = AsyncMock(return_value=existing_account)
    auth_service.total_user_count = AsyncMock(return_value=0)
    if create_raises is not None:
        auth_service.create_user = AsyncMock(side_effect=create_raises)
    else:
        record = _FakeRecord(username="alicedomain")
        auth_service.create_user = AsyncMock(return_value=record)
        auth_service.set_email = AsyncMock(return_value=None)
        auth_service.set_totp_secret_direct = AsyncMock(return_value=None)

    audit_writer = MagicMock()
    audit_writer.write = MagicMock()

    state = MagicMock()
    state.auth_service = auth_service
    state.audit_writer = audit_writer
    state.user_min_total = 1

    return state


class TestCollision409:

    @pytest.mark.asyncio
    async def test_collision_returns_409(self):
        """
        When create_user raises a UNIQUE constraint violation, the handler
        must return HTTP 409 with error=username_collision and a clear
        remediation message.
        """
        from fastapi import HTTPException as FastAPIHTTPException
        from yashigani.backoffice.routes import users as _users_mod

        unique_error = Exception("asyncpg.UniqueViolationError: duplicate key value violates unique constraint")

        mock_state = _make_state_for_create(create_raises=unique_error)

        # Patch the module-level backoffice_state AND licensing enforcer
        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state), \
             patch("yashigani.licensing.enforcer.check_end_user_limit", return_value=None):

            from yashigani.backoffice.routes.users import create_user, CreateUserRequest
            from yashigani.backoffice.middleware import Session

            body = CreateUserRequest(email="alice@domain.com")
            session = MagicMock(spec=Session)
            session.account_id = "admin-001"

            with pytest.raises(FastAPIHTTPException) as exc_info:
                await create_user(body, session)

        assert exc_info.value.status_code == 409
        detail = exc_info.value.detail
        assert detail["error"] == "username_collision"
        assert "explicit" in detail["message"].lower() or "supply" in detail["message"].lower()
        assert detail["derived_username"] == "alicedomain"

    @pytest.mark.asyncio
    async def test_explicit_username_bypasses_derive_no_collision(self):
        """
        When explicit username is supplied, derive is not invoked.
        The explicit username is used; if it collides, the existing 409
        username_taken path fires (pre-existing check), not the derive-collision path.
        """
        from yashigani.backoffice.routes import users as _users_mod

        # Simulate existing account with the explicit username
        existing = _FakeRecord(username="myexplicit")
        mock_state = _make_state_for_create(existing_account=existing)

        with patch.object(_users_mod, "backoffice_state", mock_state), \
             patch("yashigani.backoffice.routes.users.backoffice_state", mock_state), \
             patch("yashigani.licensing.enforcer.check_end_user_limit", return_value=None):

            from fastapi import HTTPException as FastAPIHTTPException
            from yashigani.backoffice.routes.users import create_user, CreateUserRequest
            from yashigani.backoffice.middleware import Session

            body = CreateUserRequest(email="alice@domain.com", username="myexplicit")
            session = MagicMock(spec=Session)
            session.account_id = "admin-001"

            with pytest.raises(FastAPIHTTPException) as exc_info:
                await create_user(body, session)

        # Should be username_taken (the pre-uniqueness check), not username_collision
        assert exc_info.value.status_code == 409
        assert exc_info.value.detail["error"] == "username_taken"
