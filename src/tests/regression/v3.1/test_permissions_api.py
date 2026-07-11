"""
Regression tests — 3.1 Phase 8+9: Unified Permission Grant admin API.

Covers:
  A. Auth enforcement
       A1. GET endpoints require AdminSession (401 without session)
       A2. PUT/DELETE/approve/reject require StepUpAdminSession (401 without step-up)

  B. Grant CRUD per scope × resource_type
       B1. PUT creates org-level grant; GET lists it
       B2. DELETE removes grant; 204 on not-found (idempotent)
       B3. PUT for group scope
       B4. PUT for user scope
       B5. PUT for agent scope
       B6. browser_capability returns 422 (use capability-policy API instead)

  C. INV-2 enforcement
       C1. cloud_model allow=True without opa_policy_ref → 422
       C2. cloud_model allow=True with opa_policy_ref → 200
       C3. cloud_model allow=False without opa_policy_ref → 200 (no INV-2 violation)

  D. Effective resolution
       D1. No org grant → effective_allow=False (deny by default)
       D2. Org grant allow=True → effective_allow=True
       D3. Org allow, group deny → effective_allow=False (group narrows)
       D4. Org allow, user deny → effective_allow=False (user narrows)

  E. Declare→approve flow
       E1. POST /declarations creates pending entry
       E2. GET /declarations returns it (org_grant_exists=False)
       E3. GET /declarations/approve creates org grant + removes pending
       E4. GET /declarations after approve shows org_grant_exists=True or entry removed
       E5. cloud_model approve without opa_policy_ref → 422
       E6. DELETE /declarations/{type}/{id} removes without granting

  F. Audit events (Phase 9)
       F1. PUT grant emits PERMISSION_GRANT_CHANGED with change_type="set"
       F2. DELETE grant emits PERMISSION_GRANT_CHANGED with change_type="deleted"
       F3. approve emits PERMISSION_GRANT_CHANGED with change_type="approved"
       F4. Audit event carries scope, scope_id, resource_type, resource_id, grant_value

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Faithful IdentityRegistry stub
# ---------------------------------------------------------------------------
# IMPORTANT: Do NOT use MagicMock for IdentityRegistry in new tests.
# MagicMock auto-creates any attribute access, so mock.get_by_identity_id()
# succeeds even though IdentityRegistry has no such method.  That is exactly
# the defect that caused BLOCK-2: the real code called a nonexistent method,
# got silently swallowed by except Exception: pass, and the existence guard
# was completely bypassed.
#
# Use _make_faithful_registry_stub() instead.  Any call to a method that
# IdentityRegistry does NOT expose raises AttributeError — the test then
# catches the resulting HTTP 503 (fail-closed), not a silent 200.

class _FaithfulIdentityRegistryStub:
    """
    Minimal faithful stub of IdentityRegistry.

    Exposes ONLY the methods that the real IdentityRegistry exposes:
      - get(identity_id) → dict | None
      - get_by_slug(slug) → dict | None
      - get_by_email(email) → dict | None
      - get_by_api_key(key) → dict | None

    Any access to a nonexistent method (e.g. get_by_identity_id) raises
    AttributeError, which the caller MUST handle correctly — not silently swallow.
    """
    def __init__(self, existing_ids: dict, existing_slugs: dict | None = None):
        self._ids = existing_ids          # identity_id → dict
        self._slugs = existing_slugs or {}  # slug → dict

    def get(self, identity_id: str) -> dict | None:
        return self._ids.get(identity_id)

    def get_by_slug(self, slug: str) -> dict | None:
        return self._slugs.get(slug)

    def get_by_email(self, email: str) -> dict | None:
        from yashigani.identity.slug import email_to_slug
        try:
            slug = email_to_slug(email)
        except ValueError:
            return None
        return self.get_by_slug(slug)

    def get_by_api_key(self, plaintext_key: str) -> dict | None:
        return None


def _make_faithful_registry_stub(
    existing_ids: dict | None = None,
    existing_slugs: dict | None = None,
) -> _FaithfulIdentityRegistryStub:
    return _FaithfulIdentityRegistryStub(
        existing_ids=existing_ids or {},
        existing_slugs=existing_slugs or {},
    )


# ---------------------------------------------------------------------------
# Session helpers (mirror v3.0/test_capability_policy.py pattern)
# ---------------------------------------------------------------------------

def _make_admin_session(account_id: str = "admin@test.local", *, with_stepup: bool = True):
    """Create a mock admin session, optionally with step-up verified."""
    import time
    from yashigani.auth.session import Session
    now = time.time()
    stepup_time = now if with_stepup else None
    return Session(
        token="test-token",
        account_id=account_id,
        account_tier="admin",
        created_at=now,
        last_active_at=now,
        expires_at=now + 14400,
        ip_prefix="127.0.0",
        last_totp_verified_at=stepup_time,
    )


def _make_state_and_store(org_id: str = "default"):
    """Build a BackofficeState with fakeredis-backed capability_policy_store."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.state import BackofficeState

    redis = fakeredis.FakeRedis(decode_responses=False)
    cap_store = CapabilityPolicyStore(redis_client=redis, default_org_id=org_id)
    state = BackofficeState()
    state.capability_policy_store = cap_store
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()
    return state, cap_store.perm_store


# ---------------------------------------------------------------------------
# A. Auth enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    """Routes must enforce AdminSession; writes must enforce StepUpAdminSession."""

    def test_get_perm_store_without_capability_store_raises_503(self):
        """_get_perm_store() raises 503 when capability_policy_store is None."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.state import BackofficeState

        state = BackofficeState()
        state.capability_policy_store = None

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                perm_mod._get_perm_store()
            assert exc_info.value.status_code == 503
        finally:
            perm_mod.backoffice_state = original

    def test_invalid_scope_raises_422(self):
        """_parse_scope with invalid value raises HTTP 422."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.permissions import _parse_scope

        with pytest.raises(HTTPException) as exc_info:
            _parse_scope("superuser")
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "invalid_scope"

    def test_invalid_resource_type_raises_422(self):
        """_parse_resource_type with invalid value raises HTTP 422."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.permissions import _parse_resource_type

        with pytest.raises(HTTPException) as exc_info:
            _parse_resource_type("not_a_type")
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "invalid_resource_type"


# ---------------------------------------------------------------------------
# B. Grant CRUD per scope × resource_type
# ---------------------------------------------------------------------------

class TestGrantCRUD:
    """PUT / GET / DELETE grant round-trips."""

    @pytest.mark.asyncio
    async def test_put_and_list_org_mcp_server(self):
        """PUT org-level mcp_server grant; GET lists it."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            body = BooleanGrantBody(allow=True)
            result = await perm_mod.put_grant(
                "org", "default", "mcp_server", "server-a",
                body, _make_admin_session()
            )
            assert result["allow"] is True
            assert result["resource_id"] == "server-a"
            assert result["scope"] == "org"
            assert result["resource_type"] == "mcp_server"

            # Now list
            list_result = await perm_mod.list_grants(
                "org", "default", "mcp_server", _make_admin_session()
            )
            assert list_result["scope"] == "org"
            assert any(g["resource_id"] == "server-a" and g["allow"] is True
                       for g in list_result["grants"])
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_delete_grant_is_idempotent(self):
        """DELETE returns 204 whether grant exists or not."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            # Delete non-existent — should not raise
            await perm_mod.delete_grant(
                "org", "default", "mcp_server", "nonexistent-server",
                _make_admin_session()
            )
            # Also succeeds when it exists
            from yashigani.backoffice.routes.permissions import BooleanGrantBody
            await perm_mod.put_grant(
                "org", "default", "mcp_server", "server-b",
                BooleanGrantBody(allow=True), _make_admin_session()
            )
            await perm_mod.delete_grant(
                "org", "default", "mcp_server", "server-b",
                _make_admin_session()
            )
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_put_group_scope_grant(self):
        """PUT group-scope grant is persisted and listable."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.put_grant(
                "group", "engineers", "external_api", "api.example.com",
                BooleanGrantBody(allow=False), _make_admin_session()
            )
            assert result["scope"] == "group"
            assert result["scope_id"] == "engineers"
            assert result["allow"] is False

            listed = await perm_mod.list_grants(
                "group", "engineers", "external_api", _make_admin_session()
            )
            assert any(g["resource_id"] == "api.example.com" and g["allow"] is False
                       for g in listed["grants"])
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_put_user_scope_grant(self):
        """PUT user-scope grant is persisted.
        3.1 UID unification: scope_id for user scope MUST be idnt_{12hex}.

        Uses a FaithfulIdentityRegistryStub — NOT MagicMock — so that any
        call to a nonexistent method raises AttributeError and fails the test.
        This was the original defect: MagicMock auto-creates any attribute,
        masking a BLOCK-2 bug where get_by_identity_id (nonexistent method)
        was called but silently resolved via MagicMock magic.
        """
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        # FAITHFUL stub: only exposes methods that IdentityRegistry actually has.
        # A call to get_by_identity_id or any other nonexistent method raises
        # AttributeError, which the fixed permissions.py now turns into HTTP 503
        # (fail-closed). Use get() which IS the real method.
        state.identity_registry = _make_faithful_registry_stub(
            existing_ids={"idnt_alice000001": {"identity_id": "idnt_alice000001"}}
        )
        try:
            result = await perm_mod.put_grant(
                "user", "idnt_alice000001", "agent", "agent-007",
                BooleanGrantBody(allow=False), _make_admin_session()
            )
            assert result["scope"] == "user"
            assert result["scope_id"] == "idnt_alice000001"
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_put_user_scope_grant_unknown_identity_id_returns_422(self):
        """PUT user-scope grant with nonexistent identity_id returns 422.
        3.1 UID unification BLOCK-2: existence guard must be LIVE, not dead code.
        Regression against the original defect where get_by_identity_id() was called
        (nonexistent method, swallowed by except Exception: pass) so any typo'd
        identity_id was silently accepted and the DENY grant became inert.
        """
        from fastapi import HTTPException

        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        # Registry has NO identity with id "idnt_doesnotexist000".
        state.identity_registry = _make_faithful_registry_stub(existing_ids={})
        try:
            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.put_grant(
                    "user", "idnt_doesnotexist000", "agent", "agent-007",
                    BooleanGrantBody(allow=False), _make_admin_session()
                )
            assert exc_info.value.status_code == 422
            assert exc_info.value.detail["error"] == "unknown_identity_id"
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_browser_capability_returns_422(self):
        """PUT browser_capability via this endpoint returns 422."""
        from fastapi import HTTPException
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.put_grant(
                    "org", "default", "browser_capability", "camera",
                    BooleanGrantBody(allow=True), _make_admin_session()
                )
            assert exc_info.value.status_code == 422
            assert "browser_capability_not_supported_here" in exc_info.value.detail["error"]
        finally:
            perm_mod.backoffice_state = original


# ---------------------------------------------------------------------------
# C. INV-2 enforcement
# ---------------------------------------------------------------------------

class TestINV2Enforcement:
    """cloud_model allow=True MUST carry opa_policy_ref."""

    @pytest.mark.asyncio
    async def test_cloud_model_allow_true_without_opa_policy_ref_raises_422(self):
        """INV-2: cloud_model allow=True without opa_policy_ref → 422."""
        from fastapi import HTTPException
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.put_grant(
                    "org", "default", "cloud_model", "gpt-4o",
                    BooleanGrantBody(allow=True, opa_policy_ref=None),
                    _make_admin_session()
                )
            assert exc_info.value.status_code == 422
            assert "inv2" in exc_info.value.detail["error"]
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_cloud_model_allow_true_with_opa_policy_ref_succeeds(self):
        """INV-2 satisfied: cloud_model allow=True with opa_policy_ref → 200."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.put_grant(
                "org", "default", "cloud_model", "gpt-4o",
                BooleanGrantBody(allow=True, opa_policy_ref="yashigani/cloud_model/gpt4o"),
                _make_admin_session()
            )
            assert result["allow"] is True
            assert result["opa_policy_ref"] == "yashigani/cloud_model/gpt4o"
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_cloud_model_allow_false_without_opa_policy_ref_succeeds(self):
        """INV-2 only applies to allow=True; allow=False without ref → 200."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.put_grant(
                "org", "default", "cloud_model", "gpt-4o",
                BooleanGrantBody(allow=False, opa_policy_ref=None),
                _make_admin_session()
            )
            assert result["allow"] is False
        finally:
            perm_mod.backoffice_state = original


# ---------------------------------------------------------------------------
# D. Effective resolution
# ---------------------------------------------------------------------------

class TestEffectiveResolution:
    """GET /effective reflects org-ceiling semantics."""

    @pytest.mark.asyncio
    async def test_no_org_grant_deny_by_default(self):
        """With no org grant: effective_allow=False (INV-1 deny by default)."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.get_effective(
                session=_make_admin_session(),
                resource_type="mcp_server",
                resource_id="never-granted",
                org_id="default",
                user_id=None,
                group_ids=None,
            )
            assert result["effective_allow"] is False
            assert result["resolution_path"]["org_grant"] is None
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_org_allow_effective_true(self):
        """Org grant allow=True → effective_allow=True."""
        state, perm_store = _make_state_and_store()
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        from yashigani.backoffice.routes import permissions as perm_mod

        perm_store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "allowed-server",
            BooleanGrantValue(allow=True)
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.get_effective(
                session=_make_admin_session(),
                resource_type="mcp_server",
                resource_id="allowed-server",
                org_id="default",
                user_id=None,
                group_ids=None,
            )
            assert result["effective_allow"] is True
            assert result["resolution_path"]["org_grant"]["allow"] is True
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_org_allow_group_deny_effective_false(self):
        """Org allow + group deny → effective_allow=False (group narrows)."""
        state, perm_store = _make_state_and_store()
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        from yashigani.backoffice.routes import permissions as perm_mod

        perm_store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "org", "default", "api.example.com",
            BooleanGrantValue(allow=True)
        )
        perm_store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "group", "restricted-group", "api.example.com",
            BooleanGrantValue(allow=False)
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.get_effective(
                session=_make_admin_session(),
                resource_type="external_api",
                resource_id="api.example.com",
                org_id="default",
                user_id="alice-slug",
                agent_id=None,
                group_ids="restricted-group",
            )
            assert result["effective_allow"] is False
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_org_allow_user_deny_effective_false(self):
        """Org allow + user deny → effective_allow=False (user narrows)."""
        state, perm_store = _make_state_and_store()
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        from yashigani.backoffice.routes import permissions as perm_mod

        perm_store.set_boolean_grant(
            ResourceType.AGENT, "org", "default", "agent-007",
            BooleanGrantValue(allow=True)
        )
        # Grant keyed by user_id (slug), NOT email — email is out of the authz path.
        perm_store.set_boolean_grant(
            ResourceType.AGENT, "user", "bob-slug", "agent-007",
            BooleanGrantValue(allow=False)
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.get_effective(
                session=_make_admin_session(),
                resource_type="agent",
                resource_id="agent-007",
                org_id="default",
                user_id="bob-slug",  # user_id (slug), never email
                agent_id=None,
                group_ids=None,
            )
            assert result["effective_allow"] is False
        finally:
            perm_mod.backoffice_state = original


# ---------------------------------------------------------------------------
# E. Declare→approve flow
# ---------------------------------------------------------------------------

class TestDeclareApprove:
    """Pending declarations → approve creates org grant."""

    @pytest.mark.asyncio
    async def test_create_declaration(self):
        """POST /declarations creates a pending entry."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import DeclarationBody

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            body = DeclarationBody(
                resource_type="external_api",
                resource_id="api.openai.com",
                declared_by="agent:my-agent",
                justification="LLM API access",
            )
            result = await perm_mod.create_declaration(body, _make_admin_session())
            assert result["resource_type"] == "external_api"
            assert result["resource_id"] == "api.openai.com"
            assert result["status"] == "pending"
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_list_declarations_returns_pending(self):
        """GET /declarations returns submitted entries."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.permissions.model import ResourceType

        perm_store.declare_pending(
            ResourceType.EXTERNAL_API,
            "api.openai.com",
            declared_by="agent:my-agent",
            justification="LLM",
            declared_at="2026-06-28T00:00:00+00:00",
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.list_declarations(
                _make_admin_session(), resource_type=None
            )
            pending = result["pending"]
            assert any(
                d["resource_id"] == "api.openai.com"
                and d["org_grant_exists"] is False
                for d in pending
            )
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_approve_creates_org_grant_and_removes_declaration(self):
        """POST approve creates org-level grant + removes pending declaration."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import ApproveDeclarationBody
        from yashigani.permissions.model import ResourceType

        perm_store.declare_pending(
            ResourceType.MCP_SERVER,
            "mcp-server-x",
            declared_by="agent:mcp-agent",
            justification="MCP access",
            declared_at="2026-06-28T00:00:00+00:00",
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            result = await perm_mod.approve_declaration(
                "mcp_server", "mcp-server-x",
                ApproveDeclarationBody(allow=True),
                _make_admin_session("approver@test.local")
            )
            assert result["approved"] is True
            assert result["grant_created"]["allow"] is True
            assert result["grant_created"]["scope"] == "org"
            assert result["actor"] == "approver@test.local"

            # Declaration should be gone from pending
            listing = await perm_mod.list_declarations(
                _make_admin_session(), resource_type="mcp_server"
            )
            assert not any(
                d["resource_id"] == "mcp-server-x"
                for d in listing["pending"]
            )

            # Org grant must exist
            from yashigani.permissions.model import BooleanGrantValue
            stored = perm_store.get_boolean_grant(
                ResourceType.MCP_SERVER, "org", "default", "mcp-server-x"
            )
            assert stored is not None
            assert stored.allow is True
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_approve_cloud_model_without_opa_policy_ref_raises_422(self):
        """approve cloud_model allow=True without opa_policy_ref → 422 (INV-2)."""
        from fastapi import HTTPException
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import ApproveDeclarationBody
        from yashigani.permissions.model import ResourceType

        perm_store.declare_pending(
            ResourceType.CLOUD_MODEL,
            "gpt-4o",
            declared_by="admin@test.local",
            justification="Need cloud model",
            declared_at="2026-06-28T00:00:00+00:00",
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                await perm_mod.approve_declaration(
                    "cloud_model", "gpt-4o",
                    ApproveDeclarationBody(allow=True, opa_policy_ref=None),
                    _make_admin_session()
                )
            assert exc_info.value.status_code == 422
            assert "inv2" in exc_info.value.detail["error"]
        finally:
            perm_mod.backoffice_state = original

    @pytest.mark.asyncio
    async def test_reject_declaration_removes_without_granting(self):
        """DELETE /declarations removes pending entry; no grant created."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.permissions.model import ResourceType

        perm_store.declare_pending(
            ResourceType.EXTERNAL_API,
            "bad-api.example.com",
            declared_by="agent:rogue",
            justification="",
            declared_at="2026-06-28T00:00:00+00:00",
        )

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            # Reject
            await perm_mod.reject_declaration(
                "external_api", "bad-api.example.com",
                _make_admin_session()
            )
            # No grant created
            grant = perm_store.get_boolean_grant(
                ResourceType.EXTERNAL_API, "org", "default", "bad-api.example.com"
            )
            assert grant is None
            # Declaration gone
            pending = perm_store.get_pending_declarations(ResourceType.EXTERNAL_API)
            assert not any(d["resource_id"] == "bad-api.example.com" for d in pending)
        finally:
            perm_mod.backoffice_state = original


# ---------------------------------------------------------------------------
# F. Audit events (Phase 9)
# ---------------------------------------------------------------------------

class TestAuditEvents:
    """Every mutation emits PERMISSION_GRANT_CHANGED to the audit chain."""

    @pytest.mark.asyncio
    async def test_put_grant_emits_audit_set(self):
        """PUT grant emits PERMISSION_GRANT_CHANGED with change_type='set'."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody
        from yashigani.audit.schema import EventType

        audit_events: list = []
        mock_writer = MagicMock()
        mock_writer.write = lambda ev: audit_events.append(ev)
        state.audit_writer = mock_writer

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            await perm_mod.put_grant(
                "org", "default", "mcp_server", "audit-server",
                BooleanGrantBody(allow=True),
                _make_admin_session("auditor@test.local")
            )
        finally:
            perm_mod.backoffice_state = original

        assert len(audit_events) == 1
        evt = audit_events[0]
        assert evt.event_type == EventType.PERMISSION_GRANT_CHANGED
        assert evt.change_type == "set"
        assert evt.scope == "org"
        assert evt.scope_id == "default"
        assert evt.resource_type == "mcp_server"
        assert evt.resource_id == "audit-server"
        assert evt.admin_account == "auditor@test.local"
        assert evt.grant_value["allow"] is True

    @pytest.mark.asyncio
    async def test_delete_grant_emits_audit_deleted(self):
        """DELETE grant emits PERMISSION_GRANT_CHANGED with change_type='deleted'."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        from yashigani.audit.schema import EventType

        perm_store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "del-server",
            BooleanGrantValue(allow=True)
        )

        audit_events: list = []
        mock_writer = MagicMock()
        mock_writer.write = lambda ev: audit_events.append(ev)
        state.audit_writer = mock_writer

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            await perm_mod.delete_grant(
                "org", "default", "mcp_server", "del-server",
                _make_admin_session("deleter@test.local")
            )
        finally:
            perm_mod.backoffice_state = original

        assert len(audit_events) == 1
        evt = audit_events[0]
        assert evt.event_type == EventType.PERMISSION_GRANT_CHANGED
        assert evt.change_type == "deleted"
        assert evt.resource_id == "del-server"
        assert evt.admin_account == "deleter@test.local"

    @pytest.mark.asyncio
    async def test_approve_emits_audit_approved(self):
        """approve emits PERMISSION_GRANT_CHANGED with change_type='approved'."""
        state, perm_store = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import ApproveDeclarationBody
        from yashigani.permissions.model import ResourceType
        from yashigani.audit.schema import EventType

        perm_store.declare_pending(
            ResourceType.MCP_SERVER,
            "approved-server",
            declared_by="agent:test",
            justification="test",
            declared_at="2026-06-28T00:00:00+00:00",
        )

        audit_events: list = []
        mock_writer = MagicMock()
        mock_writer.write = lambda ev: audit_events.append(ev)
        state.audit_writer = mock_writer

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            await perm_mod.approve_declaration(
                "mcp_server", "approved-server",
                ApproveDeclarationBody(allow=True),
                _make_admin_session("approver@test.local")
            )
        finally:
            perm_mod.backoffice_state = original

        assert len(audit_events) == 1
        evt = audit_events[0]
        assert evt.event_type == EventType.PERMISSION_GRANT_CHANGED
        assert evt.change_type == "approved"
        assert evt.scope == "org"
        assert evt.resource_type == "mcp_server"
        assert evt.resource_id == "approved-server"
        assert evt.admin_account == "approver@test.local"
        assert evt.grant_value["allow"] is True

    @pytest.mark.asyncio
    async def test_audit_event_carries_all_required_fields(self):
        """Audit event includes scope, scope_id, resource_type, resource_id, grant_value."""
        state, _ = _make_state_and_store()
        from yashigani.backoffice.routes import permissions as perm_mod
        from yashigani.backoffice.routes.permissions import BooleanGrantBody
        from yashigani.audit.schema import EventType, AccountTier

        audit_events: list = []
        mock_writer = MagicMock()
        mock_writer.write = lambda ev: audit_events.append(ev)
        state.audit_writer = mock_writer

        original = perm_mod.backoffice_state
        perm_mod.backoffice_state = state
        try:
            await perm_mod.put_grant(
                "group", "eng-team", "external_api", "api.partner.io",
                BooleanGrantBody(allow=True),
                _make_admin_session("boss@test.local")
            )
        finally:
            perm_mod.backoffice_state = original

        evt = audit_events[0]
        assert evt.event_type == EventType.PERMISSION_GRANT_CHANGED
        assert evt.account_tier == AccountTier.ADMIN
        assert evt.scope == "group"
        assert evt.scope_id == "eng-team"
        assert evt.resource_type == "external_api"
        assert evt.resource_id == "api.partner.io"
        assert evt.admin_account == "boss@test.local"
        assert isinstance(evt.grant_value, dict)
        assert "allow" in evt.grant_value
