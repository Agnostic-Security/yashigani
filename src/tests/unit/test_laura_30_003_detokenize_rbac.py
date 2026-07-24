"""
Regression test — LAURA-30-003 + v4.1.2 bug 2 (YCS-20260723-v4.1.2-CONFORMANCE):
detokenize RBAC gate identity resolution.

History:
  - LAURA-30-003 (pre-4.1.2): ``_admin_in_detokenize_role(account_id, role)``
    passed the raw account UUID directly to ``RBACStore.get_user_groups``,
    which keys on email — every lookup returned an empty list and the gate
    always denied. Fixed by resolving UUID -> email via
    ``auth_service.get_account_by_id`` first.
  - v4.1.2 bug 2 (this fix, found by the conformance suite): the LAURA-30-003
    fix became stale after the 4.1 UID migration. ``RBACStore.get_user_groups``
    is now keyed by ``identity_id`` (``idnt_{12hex}``), NOT email (see
    ``rbac/store.py`` ``get_user_groups()`` docstring). Passing email
    silently returns ``[]`` — fail-closed, but denies every legitimate admin,
    making the document correspondence-table control unusable. Fixed by
    resolving email -> identity_id via ``backoffice_state.identity_registry``
    before the RBAC lookup, mirroring ``backoffice/routes/rbac.py``'s
    ``get_user_groups()`` route handler.

IMPORTANT: unlike the original version of this file (which re-implemented
``_admin_in_detokenize_role``'s logic inline as a shadow copy), these tests
import and call the REAL function from
``yashigani.backoffice.routes.documents``. The shadow-copy approach is
exactly how the v4.1.2 regression went undetected by this file for as long
as it did: the inline copy kept testing OLD logic while the real function
was fixed and re-broken underneath it. Testing the genuine call path removes
that drift risk permanently.

Closes: LAURA-30-003, YCS-20260723-v4.1.2-CONFORMANCE bug 2.
Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from yashigani.backoffice.routes.documents import _admin_in_detokenize_role
from yashigani.backoffice.state import backoffice_state

# ---------------------------------------------------------------------------
# Minimal fakes
# ---------------------------------------------------------------------------


class _FakeGroup:
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name


class _FakeAccountRecord:
    def __init__(self, email: str | None, username: str | None):
        self.email = email
        self.username = username


class _FakeIdentityRegistry:
    """Minimal stand-in for yashigani.identity.registry.IdentityRegistry —
    only the get_by_email() surface _admin_in_detokenize_role touches."""

    def __init__(self, email_to_identity_id: dict[str, str]):
        self._map = email_to_identity_id

    def get_by_email(self, email: str) -> dict | None:
        iid = self._map.get(email)
        return {"identity_id": iid} if iid else None


def _wire(monkeypatch, *, account_record, groups_by_identity_id, email_to_identity_id, registry=True):
    auth_service = MagicMock()
    auth_service.get_account_by_id = AsyncMock(return_value=account_record)
    monkeypatch.setattr(backoffice_state, "auth_service", auth_service, raising=False)

    rbac_store = MagicMock()
    rbac_store.get_user_groups = MagicMock(
        side_effect=lambda iid: groups_by_identity_id.get(iid, [])
    )
    monkeypatch.setattr(backoffice_state, "rbac_store", rbac_store, raising=False)

    if registry:
        monkeypatch.setattr(
            backoffice_state,
            "identity_registry",
            _FakeIdentityRegistry(email_to_identity_id),
            raising=False,
        )
    else:
        monkeypatch.setattr(backoffice_state, "identity_registry", None, raising=False)

    return rbac_store


# ---------------------------------------------------------------------------
# Tests — real function, real call path
# ---------------------------------------------------------------------------


class TestDetokenizeRBACGateIdentityIdResolution:
    """v4.1.2 bug 2: gate must resolve email -> identity_id before the RBAC
    lookup, since RBACStore.get_user_groups() is identity_id-keyed post-4.1
    UID migration."""

    def test_member_by_identity_id_is_granted(self, monkeypatch):
        """The real-world case the conformance suite proved broken: a group
        has the admin's IDENTITY_ID as a member (exactly how production RBAC
        group membership is populated — RBACStore.add_member takes
        identity_id, never email). The gate must resolve the caller's email
        to that same identity_id and find the membership."""
        account_record = _FakeAccountRecord(email="admin-stepup@acme.com", username="admin-stepup@acme.com")
        matching_group = _FakeGroup(id="docteam", display_name="Doc Team")

        _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={"idnt_5f9e3aa1b2c3": [matching_group]},
            email_to_identity_id={"admin-stepup@acme.com": "idnt_5f9e3aa1b2c3"},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-stepup", "docteam"))
        assert allowed is True

    def test_lookup_by_raw_email_never_matches_post_migration(self, monkeypatch):
        """Documents the OLD (broken) behaviour would have looked like: if
        the gate (incorrectly) passed the raw email to get_user_groups, it
        would never match a real, identity_id-keyed group. This test proves
        our fixed gate does NOT do that -- it resolves to identity_id first,
        so passing membership keyed by email (which no real deployment would
        ever populate) is irrelevant; membership must be identity_id-keyed
        to be found."""
        account_record = _FakeAccountRecord(email="admin-stepup@acme.com", username="admin-stepup@acme.com")
        matching_group = _FakeGroup(id="docteam", display_name="Doc Team")

        rbac_store = _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={"admin-stepup@acme.com": [matching_group]},  # email-keyed (wrong shape)
            email_to_identity_id={"admin-stepup@acme.com": "idnt_5f9e3aa1b2c3"},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-stepup", "docteam"))
        assert allowed is False
        # Confirm the gate called get_user_groups with the RESOLVED
        # identity_id, not the email -- this is the actual fix under test.
        rbac_store.get_user_groups.assert_called_once_with("idnt_5f9e3aa1b2c3")

    def test_non_member_still_denied(self, monkeypatch):
        """Control still enforces: an admin who resolves to a real
        identity_id, but is NOT in the required group, is denied."""
        account_record = _FakeAccountRecord(email="outsider@acme.com", username="outsider@acme.com")

        _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={"idnt_deadbeef0001": []},
            email_to_identity_id={"outsider@acme.com": "idnt_deadbeef0001"},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-outsider", "docteam"))
        assert allowed is False

    def test_no_identity_registry_fails_closed(self, monkeypatch):
        """If the identity registry is unavailable, the gate must deny --
        never fall through to an email-keyed lookup that could accidentally
        match on some legacy/dual-mode store."""
        account_record = _FakeAccountRecord(email="admin@acme.com", username="admin@acme.com")

        _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={"idnt_x": [_FakeGroup(id="docteam", display_name="Doc Team")]},
            email_to_identity_id={"admin@acme.com": "idnt_x"},
            registry=False,
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-admin", "docteam"))
        assert allowed is False

    def test_email_with_no_registered_identity_fails_closed(self, monkeypatch):
        """Registry is present but has no entry for this email -> deny."""
        account_record = _FakeAccountRecord(email="ghost@acme.com", username="ghost@acme.com")

        _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={},
            email_to_identity_id={},  # no mapping for ghost@acme.com
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-ghost", "docteam"))
        assert allowed is False

    def test_group_match_by_display_name(self, monkeypatch):
        """Membership matched by group.display_name when id differs --
        preserved behaviour from the original LAURA-30-003 fix."""
        account_record = _FakeAccountRecord(email="carol@example.com", username="carol@example.com")
        group = _FakeGroup(id="grp-456", display_name="Detokenize Admins")

        _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={"idnt_carol": [group]},
            email_to_identity_id={"carol@example.com": "idnt_carol"},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-carol", "Detokenize Admins"))
        assert allowed is True

    def test_account_with_no_email_and_no_username_denies(self, monkeypatch):
        """If neither email nor username is available, gate fails closed
        before ever reaching identity_registry resolution."""
        account_record = _FakeAccountRecord(email=None, username=None)

        rbac_store = _wire(
            monkeypatch,
            account_record=account_record,
            groups_by_identity_id={},
            email_to_identity_id={},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("uuid-ghost", "some-role"))
        assert allowed is False
        rbac_store.get_user_groups.assert_not_called()

    def test_account_lookup_none_denies(self, monkeypatch):
        """auth_service returns None for the account_id -> deny."""
        _wire(
            monkeypatch,
            account_record=None,
            groups_by_identity_id={},
            email_to_identity_id={},
        )

        allowed = asyncio.run(_admin_in_detokenize_role("non-existent-uuid", "some-role"))
        assert allowed is False

    def test_rbac_store_none_denies(self, monkeypatch):
        monkeypatch.setattr(backoffice_state, "rbac_store", None, raising=False)
        allowed = asyncio.run(_admin_in_detokenize_role("uuid-x", "some-role"))
        assert allowed is False
