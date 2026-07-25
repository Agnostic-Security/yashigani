"""
Regression test -- v4.1.2 bug 3 (YCS-20260723-v4.1.2-CONFORMANCE):
permissions.py declare->approve maker-checker self-approval gap.

Root cause: `approve_declaration()` (src/yashigani/backoffice/routes/
permissions.py) required only a fresh step-up TOTP (StepUpAdminSession) --
never compared the approving admin's identity against who submitted the
declaration. `declared_by` (DeclarationBody) is a client-supplied free-form
string ("agent:<id>" or an admin account_id per its own docstring) with no
binding to any session -- so even a naive "declared_by == session.account_id"
check would have been trivially bypassable (an admin declaring with
declared_by="agent:foo" and then approving with their own session would
never match declared_by, defeating the check).

Proven live by the conformance suite (feat/v412-conformance-suite @ 2d582105,
tests/conformance/test_agents_onboarding_caps.py::TestPermissionsDeclarations::
test_MAKER_CHECKER_FINDING_same_admin_session_declares_and_approves): the SAME
admin session declared a resource and approved it in the very next call --
200, not 403. Contrast with dp_weaken.py's approve_weaken_request() and
cloud_override.py's cloud_override_approve(), which both enforce a genuine
maker!=checker separation of duties.

FIX:
  - permissions/store.py: declare_pending() now accepts an optional
    `declaring_account_id` -- the SERVER-CAPTURED session.account_id of the
    admin who called POST /declarations (never the free-form declared_by
    field). Added get_pending_declaration() (singular fetch).
  - backoffice/routes/permissions.py:
      create_declaration()  now passes declaring_account_id=session.account_id.
      approve_declaration() now (a) requires a pending declaration to exist
        (404 declaration_not_found if not -- mirrors dp_weaken.py/
        cloud_override.py both requiring an existing propose/request before
        approve is meaningful), and (b) rejects (403 self_approval_forbidden)
        when the approving session.account_id matches the declaration's
        server-captured declaring_account_id.

These tests call the real route functions directly (perm_mod.create_declaration
/ perm_mod.approve_declaration), a fakeredis-backed PermissionStore, and real
Session objects -- no mocking of the identity comparison itself.

Closes: YCS-20260723-v4.1.2-CONFORMANCE bug 3.
Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Fixtures (mirror src/tests/regression/v3.1/test_permissions_api.py)
# ---------------------------------------------------------------------------


def _make_admin_session(account_id: str = "admin@test.local"):
    from yashigani.auth.session import Session

    now = time.time()
    return Session(
        token="test-token",
        account_id=account_id,
        account_tier="admin",
        created_at=now,
        last_active_at=now,
        expires_at=now + 14400,
        ip_prefix="127.0.0",
        last_totp_verified_at=now,  # step-up verified
    )


def _make_state_and_store(org_id: str = "default"):
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.backoffice.state import BackofficeState
    from yashigani.capability_policy.store import CapabilityPolicyStore

    redis = fakeredis.FakeRedis(decode_responses=False)
    cap_store = CapabilityPolicyStore(redis_client=redis, default_org_id=org_id)
    state = BackofficeState()
    state.capability_policy_store = cap_store
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()
    return state, cap_store.perm_store


class _Wired:
    """Context manager swapping backoffice_state in the permissions route
    module for the duration of a test, restoring it afterwards."""

    def __init__(self, state):
        self._state = state
        self._original = None

    def __enter__(self):
        from yashigani.backoffice.routes import permissions as perm_mod

        self._perm_mod = perm_mod
        self._original = perm_mod.backoffice_state
        perm_mod.backoffice_state = self._state
        return perm_mod

    def __exit__(self, *exc):
        self._perm_mod.backoffice_state = self._original


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMakerCheckerSelfApproval:
    @pytest.mark.asyncio
    async def test_same_admin_declares_and_approves_is_rejected(self):
        """The exact conformance-suite scenario: one admin session declares,
        then the SAME session tries to approve -> must 403, not 200."""
        state, _ = _make_state_and_store()
        with _Wired(state) as perm_mod:
            from yashigani.backoffice.routes.permissions import (
                ApproveDeclarationBody,
                DeclarationBody,
            )

            own_session = _make_admin_session("conformance-admin-stepup")

            declare_body = DeclarationBody(
                resource_type="external_api",
                resource_id="api.example.com",
                declared_by="conformance-admin-stepup",
                justification="self-declared by the approver",
            )
            result = await perm_mod.create_declaration(declare_body, own_session)
            assert result["status"] == "pending"

            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.approve_declaration(
                    "external_api",
                    "api.example.com",
                    ApproveDeclarationBody(allow=True),
                    own_session,  # SAME session
                )
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail["error"] == "self_approval_forbidden"

    @pytest.mark.asyncio
    async def test_distinct_admin_can_approve(self):
        """Positive counterpart: a genuinely DIFFERENT admin approves the
        same declaration successfully -- the control still functions."""
        state, perm_store = _make_state_and_store()
        with _Wired(state) as perm_mod:
            from yashigani.backoffice.routes.permissions import (
                ApproveDeclarationBody,
                DeclarationBody,
            )
            from yashigani.permissions.model import ResourceType

            declarer = _make_admin_session("declarer@test.local")
            approver = _make_admin_session("approver@test.local")

            declare_body = DeclarationBody(
                resource_type="mcp_server",
                resource_id="mcp-server-y",
                declared_by="agent:mcp-agent",
                justification="MCP access",
            )
            await perm_mod.create_declaration(declare_body, declarer)

            result = await perm_mod.approve_declaration(
                "mcp_server",
                "mcp-server-y",
                ApproveDeclarationBody(allow=True),
                approver,  # DIFFERENT session
            )
            assert result["approved"] is True
            assert result["actor"] == "approver@test.local"

            stored = perm_store.get_boolean_grant(
                ResourceType.MCP_SERVER, "org", "default", "mcp-server-y"
            )
            assert stored is not None
            assert stored.allow is True

    @pytest.mark.asyncio
    async def test_declared_by_string_cannot_be_used_to_dodge_the_check(self):
        """The declaring admin sets declared_by to an UNRELATED string (e.g.
        an agent label) -- proves the check is based on the SERVER-CAPTURED
        session identity, not the spoofable declared_by field. If the check
        naively compared session.account_id == declared_by, this exact
        self-approval would have sailed through (declared_by != session
        account_id), which is precisely why declared_by must never be
        trusted for this comparison."""
        state, _ = _make_state_and_store()
        with _Wired(state) as perm_mod:
            from yashigani.backoffice.routes.permissions import (
                ApproveDeclarationBody,
                DeclarationBody,
            )

            own_session = _make_admin_session("real-admin@test.local")

            declare_body = DeclarationBody(
                resource_type="external_api",
                resource_id="sneaky.example.com",
                declared_by="agent:totally-not-me",  # spoofed label
                justification="",
            )
            await perm_mod.create_declaration(declare_body, own_session)

            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.approve_declaration(
                    "external_api",
                    "sneaky.example.com",
                    ApproveDeclarationBody(allow=True),
                    own_session,
                )
            assert exc_info.value.status_code == 403
            assert exc_info.value.detail["error"] == "self_approval_forbidden"

    @pytest.mark.asyncio
    async def test_approve_without_prior_declaration_404s(self):
        """approve_declaration must require an existing pending declaration
        -- mirrors dp_weaken.py/cloud_override.py, both of which 404/409 when
        there's no matching propose/request. Without this, an admin could
        skip declaring entirely and grant solo, making the distinct-approver
        check meaningless (nothing to compare against)."""
        state, _ = _make_state_and_store()
        with _Wired(state) as perm_mod:
            from yashigani.backoffice.routes.permissions import ApproveDeclarationBody

            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.approve_declaration(
                    "mcp_server",
                    "never-declared-server",
                    ApproveDeclarationBody(allow=True),
                    _make_admin_session("solo-admin@test.local"),
                )
            assert exc_info.value.status_code == 404
            assert exc_info.value.detail["error"] == "declaration_not_found"

    @pytest.mark.asyncio
    async def test_legacy_declaration_with_no_recorded_identity_does_not_spuriously_block(self):
        """Declarations created by calling store.declare_pending() directly
        (no declaring_account_id -- e.g. pre-4.1.2 call sites / seeders) must
        not spuriously trigger self_approval_forbidden: there is no maker
        identity recorded to compare against, so approval must proceed
        normally for any admin."""
        state, perm_store = _make_state_and_store()
        from yashigani.permissions.model import ResourceType

        perm_store.declare_pending(
            ResourceType.EXTERNAL_API,
            "legacy-declared.example.com",
            declared_by="agent:legacy-seeder",
            justification="",
            declared_at="2026-06-28T00:00:00+00:00",
            # declaring_account_id intentionally omitted (defaults to None)
        )

        with _Wired(state) as perm_mod:
            from yashigani.backoffice.routes.permissions import ApproveDeclarationBody

            result = await perm_mod.approve_declaration(
                "external_api",
                "legacy-declared.example.com",
                ApproveDeclarationBody(allow=True),
                _make_admin_session("any-admin@test.local"),
            )
            assert result["approved"] is True
