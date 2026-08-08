"""
Regression test -- v4.1.2 FIND-IRIS-SEAT-REENABLE (MEDIUM-HIGH, batch-fix
2026-08-04).

At the 5/5 (Community) seat ceiling, disabling (not deleting) a user then
attempting to re-enable THAT SAME account returned 402
LICENSE_LIMIT_EXCEEDED current=5/maximum=5 -- the account's own existing
identity-registry row was double-counted against itself. Re-enabling
creates zero new occupants (disable never removes a HUMAN identity from
identity:index:kind:human -- see IdentityRegistry.suspend()'s docstring,
"a HOLD, not a release"; only deactivate() frees a seat, per FIND-SEAT-LEAK)
yet was refused as if it would push the deployment over the licensed limit.

Root cause: enable_user() (backoffice/routes/users.py) compared
count_canonical_end_users() against the ceiling BEFORE re-enabling, but that
count already includes the target's own identity (disabled-but-present, not
deleted) -- comparing a population that already contains the row being
toggled against itself is a self-referential double-count.

Fix: resolve the target's own HUMAN identity first (via the account_id link,
IdentityRegistry.get_by_account_id() -- the same mechanism as the sibling
FIND-IRIS-SUSPEND-ORGID fix); if it already exists (i.e. already occupies a
seat, active or suspended), skip the seat-limit check entirely -- re-enabling
never increases the counted population. Only accounts that have never
registered an identity (never logged in) still go through the pre-existing
check.

This test fills a 2-seat licence with two real (fakeredis-backed)
IdentityRegistry HUMAN identities, disables one (suspend(), matching what
disable_user's LF-DISABLE-PARTIAL path now correctly performs post the
FIND-IRIS-SUSPEND-ORGID fix), then calls enable_user() for that SAME account
at the (now apparently full, 2/2) ceiling. Fails on the pre-fix
implementation (402 LICENSE_LIMIT_EXCEEDED); passes on the fix (200 OK).
"""
from __future__ import annotations

import datetime as _dt
import uuid as _uuid
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest

from yashigani.identity.registry import IdentityKind, IdentityRegistry


def _make_account(username: str, account_tier: str, email: str, account_id: str) -> MagicMock:
    acct = MagicMock()
    acct.username = username
    acct.account_tier = account_tier
    acct.email = email
    acct.account_id = account_id
    acct.disabled = True
    return acct


def _make_session(account_id: str) -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    sess.account_tier = "admin"
    return sess


class TestFindIrisSeatReenable:
    @pytest.fixture(autouse=True)
    def _capped_license(self):
        from yashigani.licensing.enforcer import get_license, set_license
        from yashigani.licensing.model import LicenseState, LicenseTier

        original = get_license()
        capped = LicenseState(
            tier=LicenseTier.COMMUNITY,
            org_domain="example.com",
            max_agents=500,
            max_end_users=2,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc),
            expires_at=_dt.datetime(2027, 1, 1, tzinfo=_dt.timezone.utc),
            license_id=str(_uuid.uuid4()),
            valid=True,
            error=None,
        )
        set_license(capped)
        yield
        set_license(original)

    @pytest.mark.asyncio
    async def test_reenable_at_ceiling_does_not_double_count_self(self):
        """FIND-IRIS-SEAT-REENABLE: re-enabling a disabled-but-present
        account at the seat ceiling must succeed — it adds zero new
        occupants."""
        import yashigani.backoffice.state as _state_mod
        from yashigani.backoffice.routes import users as _users_mod

        redis = fakeredis.FakeRedis()
        registry = IdentityRegistry(redis)

        # Fill the 2-seat licence exactly as auth.py's login-time
        # registration does.
        id1, _ = registry.register(kind=IdentityKind.HUMAN, name="alice", slug="alice-example-com")
        registry.link_account_id("uuid-alice", id1)
        id2, _ = registry.register(kind=IdentityKind.HUMAN, name="bob", slug="bob-example-com")
        registry.link_account_id("uuid-bob", id2)

        # alice gets disabled (not deleted) — her identity stays a member of
        # identity:index:kind:human (suspend is a HOLD, not a release).
        registry.suspend(id1)
        assert redis.sismember("identity:index:kind:human", id1), (
            "sanity: suspend must not free the seat"
        )

        record = _make_account("alice", "user", "alice@example.com", "uuid-alice")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=record)
        mock_state.auth_service.enable = AsyncMock(return_value=True)
        mock_state.audit_writer = MagicMock()
        mock_state.identity_registry = registry
        mock_state.rbac_store = None

        session = _make_session("admin-uuid")

        with patch.object(_users_mod, "backoffice_state", mock_state), \
                patch.object(_state_mod, "backoffice_state", mock_state):
            result = await _users_mod.enable_user("alice", session)

        assert result["status"] == "ok", (
            "FIND-IRIS-SEAT-REENABLE: re-enabling a disabled-but-present "
            "account at the seat ceiling must succeed — it never removed "
            "its own seat in the first place"
        )
        mock_state.auth_service.enable.assert_awaited_once_with("alice")

    @pytest.mark.asyncio
    async def test_never_logged_in_account_still_enforces_seat_limit(self):
        """An account with NO identity-registry entry at all (never logged
        in) must still go through the pre-existing seat-limit check — the
        fix must not blanket-skip the check for everyone."""
        import yashigani.backoffice.state as _state_mod
        from yashigani.backoffice.routes import users as _users_mod
        from yashigani.licensing.enforcer import LicenseLimitExceeded
        from fastapi import HTTPException

        redis = fakeredis.FakeRedis()
        registry = IdentityRegistry(redis)
        # Fill both seats with OTHER accounts.
        id1, _ = registry.register(kind=IdentityKind.HUMAN, name="carol", slug="carol-example-com")
        registry.link_account_id("uuid-carol", id1)
        id2, _ = registry.register(kind=IdentityKind.HUMAN, name="dave", slug="dave-example-com")
        registry.link_account_id("uuid-dave", id2)

        # "eve" is disabled but has NEVER logged in — no identity was ever
        # registered for her, so get_by_account_id finds nothing.
        record = _make_account("eve", "user", "eve@example.com", "uuid-eve")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=record)
        mock_state.auth_service.enable = AsyncMock(return_value=True)
        mock_state.audit_writer = MagicMock()
        mock_state.identity_registry = registry
        mock_state.rbac_store = None

        session = _make_session("admin-uuid")

        with patch.object(_users_mod, "backoffice_state", mock_state), \
                patch.object(_state_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _users_mod.enable_user("eve", session)

        assert exc_info.value.status_code == 402
        mock_state.auth_service.enable.assert_not_awaited()
