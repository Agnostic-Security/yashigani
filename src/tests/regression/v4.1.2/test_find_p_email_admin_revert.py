"""
Regression test -- v4.1.2 FIND-P-EMAIL (LOW, batch-fix 2026-08-04).

Laura's admin-surface pentest: admin2 edited admin1's email (by-design
global admin scope), then tried to revert it back to the non-email seed
value "wolf" (install.sh's random-word bootstrap admin username -- see
install.sh:_gen_admin_usernames) and got 422 -- the endpoint's own
admin-email-shape regex rejected its OWN seed data. A one-way validation
trap: once edited, an admin's original bootstrap email could never be
restored via the API.

Root cause (two parts, both fixed here):
  1. PostgresLocalAuthService.create_admin() / LocalAuthService.create_admin()
     defaulted `email=username` verbatim. install.sh's bootstrap admin
     usernames are bare dictionary words ("wolf", "orchid", "atlas", ...),
     not email-shaped -- so admin_accounts.email (documented as "used as
     the Grafana alert contact") was seeded with a non-email string from
     day one, for every fresh install.
  2. UpdateAdminRequest.email (accounts.py) enforced the admin-email-shape
     pattern + a 5-char minimum directly at the Pydantic field level, with
     NO exception for reverting to the account's own current value --
     making the seed value from (1) permanently unrecoverable once changed.

Fix:
  1. Both create_admin() implementations now default
     email = username if "@" in username else f"{username}@yashigani.local"
     (mirrors the existing auth.py:_register_human_identity_on_login
     synthetic-email convention) -- FRESH bootstraps get a real email-shaped
     value from the start.
  2. update_admin() (accounts.py) now validates the admin-email shape in
     the route handler (not the Pydantic field), with an explicit exception:
     `body.email == record.username` is always accepted verbatim, even when
     not email-shaped -- this covers reverting an ALREADY-DEPLOYED
     (pre-fix) account's seed value, which fix (1) alone cannot retroactively
     repair. Any OTHER non-email garbage is still rejected with 422.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestCreateAdminEmailDefaultingPostgres:
    """PostgresLocalAuthService.create_admin(): email defaulting logic,
    with _insert() mocked out (no real DB required)."""

    @pytest.mark.asyncio
    async def test_bare_word_username_gets_synthetic_email(self):
        from yashigani.auth.pg_auth import PostgresLocalAuthService

        svc = PostgresLocalAuthService(pool=MagicMock())
        with patch.object(svc, "_insert", AsyncMock()):
            record, _plain = await svc.create_admin(
                username="wolf",
                auto_generate=False,
                plaintext_password="x" * 40,
                force_password_change=False,
                force_totp_provision=False,
            )
        assert record.email == "wolf@yashigani.local", (
            "FIND-P-EMAIL: a bare-word bootstrap username must get a "
            "synthetic email-shaped default, not the bare word verbatim"
        )

    @pytest.mark.asyncio
    async def test_email_shaped_username_unchanged(self):
        """API-created admins (CreateAdminRequest.username already requires
        an email pattern) must keep email=username exactly as before —
        no double-suffixing."""
        from yashigani.auth.pg_auth import PostgresLocalAuthService

        svc = PostgresLocalAuthService(pool=MagicMock())
        with patch.object(svc, "_insert", AsyncMock()):
            record, _plain = await svc.create_admin(
                username="admin@example.com",
                auto_generate=False,
                plaintext_password="x" * 40,
                force_password_change=False,
                force_totp_provision=False,
            )
        assert record.email == "admin@example.com"


class TestCreateAdminEmailDefaultingInMemory:
    """LocalAuthService.create_admin(): same defaulting logic, in-memory
    (community-tier fallback path)."""

    def test_bare_word_username_gets_synthetic_email(self):
        from yashigani.auth.local_auth import LocalAuthService

        svc = LocalAuthService()
        record, _plain = svc.create_admin(
            username="orchid", auto_generate=False, plaintext_password="x" * 40,
        )
        assert record.email == "orchid@yashigani.local"

    def test_email_shaped_username_unchanged(self):
        from yashigani.auth.local_auth import LocalAuthService

        svc = LocalAuthService()
        record, _plain = svc.create_admin(
            username="admin@example.com", auto_generate=False, plaintext_password="x" * 40,
        )
        assert record.email == "admin@example.com"


# ---------------------------------------------------------------------------
# Route-level: update_admin() revert-to-seed exception
# ---------------------------------------------------------------------------

def _make_admin_record(username: str, email: str) -> MagicMock:
    rec = MagicMock()
    rec.username = username
    rec.email = email
    rec.account_tier = "admin"
    rec.account_id = f"uuid-{username}"
    rec.disabled = False
    return rec


def _make_session(account_id: str = "admin-uuid") -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    sess.account_tier = "admin"
    return sess


class TestUpdateAdminRequestPydanticShape:
    """Proves the SPECIFIC symptom Laura hit: the Pydantic model itself (not
    just the route handler) must accept "wolf" as a syntactically valid
    request body — pre-fix, `UpdateAdminRequest(email="wolf")` raised a
    pydantic ValidationError before the request even reached update_admin(),
    which is the actual 422 Laura's pentest observed (FastAPI returns 422
    for a body that fails Pydantic validation, before any route code runs)."""

    def test_bare_word_email_is_a_syntactically_valid_request_body(self):
        from yashigani.backoffice.routes.accounts import UpdateAdminRequest

        # Must not raise — pre-fix this raised pydantic.ValidationError
        # because the field itself enforced min_length=5 + the email-shape
        # pattern, rejecting "wolf" (4 chars, no "@") before any handler
        # code (which could apply the revert-to-own-username exception)
        # ever ran.
        req = UpdateAdminRequest(email="wolf")
        assert req.email == "wolf"


class TestUpdateAdminEmailRevertException:
    @pytest.mark.asyncio
    async def test_revert_to_own_bare_word_username_succeeds(self):
        """FIND-P-EMAIL: reverting email back to the account's own username
        ("wolf") must succeed even though it isn't email-shaped."""
        from yashigani.backoffice.routes import accounts as _accounts_mod

        record = _make_admin_record("wolf", "someone-edited-me@example.com")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=record)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.set_email = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        body = MagicMock()
        body.email = "wolf"
        body.disabled = None

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            result = await _accounts_mod.update_admin("wolf", body, _make_session())

        assert result["status"] == "ok"
        mock_state.auth_service.set_email.assert_awaited_once_with("wolf", "wolf")

    @pytest.mark.asyncio
    async def test_other_non_email_garbage_still_rejected(self):
        """The exception is narrowly scoped to the account's OWN username —
        any other non-email string must still 422."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import accounts as _accounts_mod

        record = _make_admin_record("wolf", "someone-edited-me@example.com")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=record)
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        body = MagicMock()
        body.email = "not-an-email-and-not-my-username"
        body.disabled = None

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _accounts_mod.update_admin("wolf", body, _make_session())

        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "invalid_email"

    @pytest.mark.asyncio
    async def test_well_formed_email_still_accepted(self):
        """A genuinely valid new email must still be accepted (no
        regression on the happy path)."""
        from yashigani.backoffice.routes import accounts as _accounts_mod

        record = _make_admin_record("wolf", "wolf@yashigani.local")
        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=record)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=None)
        mock_state.auth_service.set_email = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        body = MagicMock()
        body.email = "real.admin@example.com"
        body.disabled = None

        with patch.object(_accounts_mod, "backoffice_state", mock_state):
            result = await _accounts_mod.update_admin("wolf", body, _make_session())

        assert result["status"] == "ok"
        mock_state.auth_service.set_email.assert_awaited_once_with("wolf", "real.admin@example.com")
