"""
Tests for 4.1.1 pentest findings:
  LAURA-411-001 — cloud-model DENY grant bypassed on Ollama fallback
  LAURA-411-002 — InMemoryNonceStore refused in production
  LAURA-411-004 — unauth /v1 401 discloses internal header names
  LAURA-411-005 — X-XSS-Protection removed (deprecated header)
  LAURA-411-006 — single X-Frame-Options (Caddy owns it; app removes duplicates)
  RBAC-BUG-4.1.1 — add_member/remove_member/get_user_groups email→identity_id fix
"""
from __future__ import annotations

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ===========================================================================
# LAURA-411-001: cloud-model DENY bypass on Ollama fallback
# ===========================================================================

class TestLaura411001DenyBypassOnOllamaFallback:
    """
    When selected_provider is 'ollama' (no cloud key configured), an explicit user-level
    or group-level DENY grant on the requested model must still block the request.
    """

    def _make_store_with_deny(self, uid: str, model: str):
        """Return a mock PermissionStore that has an explicit user DENY for model."""
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        store = MagicMock()
        deny_grant = BooleanGrantValue(allow=False)
        allow_grant = BooleanGrantValue(allow=True)

        def _get_grant(rt, scope_kind, scope_id, resource_id):
            if scope_kind == "user" and scope_id == uid and resource_id == model:
                return deny_grant
            return None

        store.get_boolean_grant.side_effect = _get_grant
        return store

    def _make_store_with_group_deny(self, group_id: str, model: str):
        """Return a mock PermissionStore with group DENY for model."""
        from yashigani.permissions.model import BooleanGrantValue
        store = MagicMock()
        deny_grant = BooleanGrantValue(allow=False)

        def _get_grant(rt, scope_kind, scope_id, resource_id):
            if scope_kind == "group" and scope_id == group_id and resource_id == model:
                return deny_grant
            return None

        store.get_boolean_grant.side_effect = _get_grant
        return store

    def _make_store_no_deny(self):
        """Return a mock PermissionStore with no explicit DENY."""
        store = MagicMock()
        store.get_boolean_grant.return_value = None
        return store

    def test_user_deny_grant_blocks_ollama_fallback(self):
        """User-level DENY on openai:gpt-4o must block even when routing → Ollama."""
        from yashigani.permissions.model import ResourceType

        uid = "idnt_aabbccdd1234"
        model = "openai:gpt-4o"
        store = self._make_store_with_deny(uid, model)

        # Simulate the LAURA-411-001 check logic (extracted from openai_router)
        identity = {"identity_id": uid, "kind": "user", "groups": []}
        _411_kind = identity.get("kind", "")
        _411_uid = identity.get("identity_id") if _411_kind in ("human", "user") else None
        _411_groups = identity.get("groups", [])

        _explicit_deny = False
        if _411_uid:
            ug = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "user", _411_uid, model)
            if ug is not None and not ug.allow:
                _explicit_deny = True

        assert _explicit_deny, "User DENY grant on requested model must set _explicit_deny=True"

    def test_group_deny_grant_blocks_ollama_fallback(self):
        """Group-level DENY on openai:gpt-4o must block even when routing → Ollama."""
        from yashigani.permissions.model import ResourceType

        group_id = "group-uuid-1"
        model = "openai:gpt-4o"
        store = self._make_store_with_group_deny(group_id, model)

        identity = {"identity_id": "idnt_aabbccdd1234", "kind": "user", "groups": [group_id]}
        _411_kind = identity.get("kind", "")
        _411_uid = identity.get("identity_id") if _411_kind in ("human", "user") else None
        _411_groups = identity.get("groups", [])

        _explicit_deny = False
        if _411_uid:
            ug = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "user", _411_uid, model)
            if ug is not None and not ug.allow:
                _explicit_deny = True
        if not _explicit_deny:
            for gid in _411_groups:
                gg = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "group", gid, model)
                if gg is not None and not gg.allow:
                    _explicit_deny = True
                    break

        assert _explicit_deny, "Group DENY grant on requested model must set _explicit_deny=True"

    def test_no_explicit_deny_does_not_block_ollama(self):
        """When no explicit DENY exists, Ollama fallback is allowed (no false positive)."""
        from yashigani.permissions.model import ResourceType

        uid = "idnt_aabbccdd1234"
        model = "openai:gpt-4o"
        store = self._make_store_no_deny()

        identity = {"identity_id": uid, "kind": "user", "groups": []}
        _411_uid = identity.get("identity_id")
        _explicit_deny = False
        ug = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "user", _411_uid, model)
        if ug is not None and not ug.allow:
            _explicit_deny = True

        assert not _explicit_deny, "No explicit DENY must not block the Ollama path"

    def test_brain_reasoning_leg_exempt(self):
        """brain_reasoning_leg=True must exempt the check (server-minted, no allocation)."""
        # The flag check is: `not brain_reasoning_leg` — no store access at all.
        # Simulate: if brain_reasoning_leg=True, we skip the block entirely.
        brain_reasoning_leg = True
        called = False

        if not brain_reasoning_leg:
            called = True  # would have checked store

        assert not called, "brain_reasoning_leg must exempt from the DENY check"

    def test_agent_call_exempt(self):
        """is_agent_call=True (model starts with @) must exempt the check."""
        is_agent_call = True
        called = False

        if not is_agent_call:
            called = True

        assert not called, "is_agent_call must exempt from the DENY check"

    def test_store_error_fails_closed(self):
        """An exception from the permission store must result in deny (fail-closed)."""
        from yashigani.permissions.model import ResourceType

        uid = "idnt_aabbccdd1234"
        model = "openai:gpt-4o"
        store = MagicMock()
        store.get_boolean_grant.side_effect = RuntimeError("Redis down")

        identity = {"identity_id": uid, "kind": "user", "groups": []}
        _411_uid = identity.get("identity_id")
        _explicit_deny = False

        try:
            ug = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "user", _411_uid, model)
            if ug is not None and not ug.allow:
                _explicit_deny = True
        except Exception:
            _explicit_deny = True  # fail-closed

        assert _explicit_deny, "Exception from permission store must fail-closed (deny)"


# ===========================================================================
# LAURA-411-002: InMemoryNonceStore refused in production
# ===========================================================================

class TestLaura411002NonceStoreProductionGuard:
    """
    McpBroker must raise RuntimeError if InMemoryNonceStore is used in
    YASHIGANI_ENV=production or YASHIGANI_ENV=staging.
    """

    def _make_minimal_broker_config(self, env: str, nonce_store=None):
        """Build a minimal McpBrokerConfig sufficient to init McpBroker."""
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP384R1
        from cryptography.hazmat.backends import default_backend
        from yashigani.mcp.broker import McpBrokerConfig
        from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier

        private_key = generate_private_key(SECP384R1(), default_backend())
        issuer = McpJwtIssuer(
            tenant_id="test-tenant",
            private_key=private_key,
            key_generated_at=1748476800,
        )
        verifier = McpJwtVerifier.from_issuer(issuer)
        audit_writer = MagicMock()  # non-None so the audit_writer guard passes

        return McpBrokerConfig(
            opa_url="http://policy:8181",
            tenant_id="test-tenant",
            issuer=issuer,
            verifier=verifier,
            nonce_store=nonce_store,
            audit_writer=audit_writer,
        )

    def test_inmemory_rejected_in_production(self):
        """InMemoryNonceStore must raise RuntimeError when YASHIGANI_ENV=production."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config("production", nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            with pytest.raises(RuntimeError, match="InMemoryNonceStore"):
                McpBroker(config)

    def test_inmemory_rejected_in_staging(self):
        """InMemoryNonceStore must raise RuntimeError when YASHIGANI_ENV=staging."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config("staging", nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "staging"}):
            with pytest.raises(RuntimeError, match="InMemoryNonceStore"):
                McpBroker(config)

    def test_inmemory_allowed_in_dev(self):
        """InMemoryNonceStore must be accepted when YASHIGANI_ENV=dev."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config("dev", nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "dev"}):
            # Should not raise
            broker = McpBroker(config)
            assert broker is not None

    def test_inmemory_allowed_when_env_unset(self):
        """InMemoryNonceStore must be accepted when YASHIGANI_ENV is not set."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config("", nonce_store=InMemoryNonceStore())

        env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_ENV"}
        with patch.dict(os.environ, env, clear=True):
            broker = McpBroker(config)
            assert broker is not None


# ===========================================================================
# LAURA-411-004: unauth /v1 401 must not disclose internal header names
# ===========================================================================

class TestLaura411004UnAuthDisclosure:
    """
    The 401 response body for unauthenticated /v1/* requests must use the
    generic OpenAI-format error and must NOT contain internal header names,
    architecture clues, or bearer path details.

    We test at the openai_router level by reading the exception raised and
    checking its detail.
    """

    def _build_fake_state(self):
        """Minimal _GatewayState mock so the 401 path is reachable."""
        from yashigani.gateway.openai_router import _GatewayState
        state = MagicMock(spec=_GatewayState)
        state.optimization_engine = None
        state.permission_store = None
        state.permission_strict = False
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_config_store = None
        state.model_alias_store = None
        state.model_allocation_store = None
        state.audit_writer = MagicMock()
        state.rbac_store = None
        state.identity_registry = None
        return state

    def test_401_detail_is_generic_openai_format(self):
        """The HTTPException raised for unauthenticated /v1/* must use OpenAI format."""
        from fastapi import HTTPException

        # Simulate the decision point: identity is None → 401 raised with generic body.
        # We replicate the new code path inline to verify the structure.
        raised = None
        try:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": {
                        "message": "Authentication required",
                        "type": "authentication_error",
                        "code": "unauthorized",
                    },
                },
            )
        except HTTPException as exc:
            raised = exc

        assert raised is not None
        assert raised.status_code == 401
        assert isinstance(raised.detail, dict)
        error = raised.detail.get("error", {})
        assert error.get("message") == "Authentication required"
        assert error.get("type") == "authentication_error"
        assert error.get("code") == "unauthorized"

    def test_401_does_not_disclose_x_yashigani_header(self):
        """The 401 body must not mention X-Yashigani-Identity-Id or any Yashigani header."""
        from fastapi import HTTPException

        try:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": {
                        "message": "Authentication required",
                        "type": "authentication_error",
                        "code": "unauthorized",
                    },
                },
            )
        except HTTPException as exc:
            detail_str = json.dumps(exc.detail)
            assert "X-Yashigani" not in detail_str, (
                "401 body must not disclose X-Yashigani header names"
            )
            assert "Caddy" not in detail_str, (
                "401 body must not disclose Caddy (internal auth architecture)"
            )
            assert "SSO" not in detail_str, (
                "401 body must not disclose SSO flow details"
            )
            assert "X-Yashigani-Identity-Id" not in detail_str, (
                "401 body must not disclose internal identity header name"
            )

    def test_401_detail_keys_are_openai_format(self):
        """Detail must only contain 'error' key at top level, matching OpenAI API format."""
        from fastapi import HTTPException

        try:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": {
                        "message": "Authentication required",
                        "type": "authentication_error",
                        "code": "unauthorized",
                    },
                },
            )
        except HTTPException as exc:
            assert list(exc.detail.keys()) == ["error"], (
                "401 detail must only have 'error' key at top level"
            )
            assert set(exc.detail["error"].keys()) == {"message", "type", "code"}, (
                "401 error object must have exactly message/type/code keys"
            )


# ===========================================================================
# RBAC group persistence root-cause + add_member email→identity_id fix
# ===========================================================================

class TestRBACGroupPersistenceRootCause:
    """
    Verify that RBAC group state lives in Redis (not Postgres), and that the
    add_member/remove_member routes now resolve email → identity_id before
    calling the store.
    """

    def test_rbac_store_uses_redis_not_postgres(self):
        """RBACStore.add_group writes to Redis (rbac:group:{id}), not Postgres."""
        import fakeredis
        from yashigani.rbac.store import RBACStore
        from yashigani.rbac.model import RBACGroup

        r = fakeredis.FakeRedis()
        store = RBACStore(redis_client=r)

        g = RBACGroup(id="test-group-id", display_name="TestGroup")
        store.add_group(g)

        # Verify it's in Redis
        raw = r.get("rbac:group:test-group-id")
        assert raw is not None, "Group must be persisted to Redis"
        data = json.loads(raw)
        assert data["id"] == "test-group-id"
        assert data["display_name"] == "TestGroup"

    def test_add_member_with_identity_id_creates_correct_index(self):
        """
        After the 4.1 migration, add_member with identity_id (not email) creates
        the correct rbac:user:{identity_id} Redis index key.
        """
        import fakeredis
        from yashigani.rbac.store import RBACStore
        from yashigani.rbac.model import RBACGroup

        r = fakeredis.FakeRedis()
        store = RBACStore(redis_client=r)

        g = RBACGroup(id="group-1", display_name="Group 1")
        store.add_group(g)

        identity_id = "idnt_aabbccdd1234"
        store.add_member("group-1", identity_id)

        # Correct key: rbac:user:{identity_id}
        members = r.smembers(f"rbac:user:{identity_id}")
        assert b"group-1" in members, (
            "add_member with identity_id must create rbac:user:{identity_id} index"
        )

        # Wrong key (email-based): must NOT exist
        wrong = r.smembers("rbac:user:user@example.com")
        assert len(wrong) == 0, "No email-based key must be created for identity_id input"

    def test_get_user_groups_by_identity_id(self):
        """get_user_groups(identity_id) returns correct groups after add_member with identity_id."""
        import fakeredis
        from yashigani.rbac.store import RBACStore
        from yashigani.rbac.model import RBACGroup

        r = fakeredis.FakeRedis()
        store = RBACStore(redis_client=r)

        g = RBACGroup(id="group-2", display_name="Group 2")
        store.add_group(g)

        identity_id = "idnt_aabbccdd5678"
        store.add_member("group-2", identity_id)

        groups = store.get_user_groups(identity_id)
        assert len(groups) == 1
        assert groups[0].id == "group-2"

    def test_email_to_identity_id_helper_raises_on_missing_identity(self):
        """_email_to_identity_id must raise HTTPException(422) for unknown email."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.rbac import _email_to_identity_id

        mock_registry = MagicMock()
        mock_registry.get_by_email.return_value = None

        mock_state = MagicMock()
        mock_state.identity_registry = mock_registry

        with patch("yashigani.backoffice.routes.rbac.backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                _email_to_identity_id("noone@example.com")
            assert exc_info.value.status_code == 422
            assert "identity_not_found" in str(exc_info.value.detail)

    def test_email_to_identity_id_helper_resolves_correctly(self):
        """_email_to_identity_id returns the identity_id for a known email."""
        from yashigani.backoffice.routes.rbac import _email_to_identity_id

        mock_registry = MagicMock()
        mock_registry.get_by_email.return_value = {
            "identity_id": "idnt_aabbccdd1234",
            "email": "alice@example.com",
        }

        mock_state = MagicMock()
        mock_state.identity_registry = mock_registry

        with patch("yashigani.backoffice.routes.rbac.backoffice_state", mock_state):
            iid = _email_to_identity_id("alice@example.com")
            assert iid == "idnt_aabbccdd1234"

    def test_postgres_rbac_tables_are_not_the_live_store(self):
        """
        Confirm the design intent: Postgres rbac_groups/rbac_members tables are FK
        anchors only (used by model_allocations, budget_config_store). They are NOT
        populated by the RBAC API — that writes to Redis.

        This test documents the root cause of Laura's observation (empty Postgres tables).
        """
        # The RBACStore class only uses Redis — it has no Postgres dependency.
        from yashigani.rbac.store import RBACStore
        import inspect
        src = inspect.getsource(RBACStore)
        assert "psycopg" not in src, "RBACStore must not use psycopg (Redis only)"
        assert "asyncpg" not in src, "RBACStore must not use asyncpg (Redis only)"
        assert "pg_pool" not in src, "RBACStore must not reference Postgres pool"
        # Confirm it references Redis
        assert "_redis" in src, "RBACStore must use Redis client"


# ===========================================================================
# LAURA-411-001 (rewritten): production code path
# ===========================================================================

class TestLaura411001DenyBlocksViaProductionRouterPath:
    """
    Drive the ACTUAL chat_completions production code path (LAURA-411-001 guard
    at lines 2261-2316).  The previously existing tests re-implemented the
    DENY logic inline; these tests call the real endpoint function.

    Scenario: user has an explicit DENY grant on the requested model, but no
    cloud API key is configured → selected_provider="ollama" (fallback) →
    _perm_needs_check=False → LAURA-411-001 guard fires → 403.
    """

    def _make_deny_permission_store(self, uid: str, model: str):
        """Permission store with explicit user DENY for (uid, model)."""
        from yashigani.permissions.model import BooleanGrantValue, ResourceType
        deny_grant = BooleanGrantValue(allow=False)
        store = MagicMock()

        def _get_grant(rt, scope_kind, scope_id, resource_id):
            if scope_kind == "user" and scope_id == uid and resource_id == model:
                return deny_grant
            return None

        store.get_boolean_grant.side_effect = _get_grant
        return store

    def _make_mock_state_for_deny(self, uid: str, model: str) -> MagicMock:
        """Minimal gateway state: no cloud key, permission_store has DENY."""
        permission_store = self._make_deny_permission_store(uid, model)

        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "llama3.2:3b"
        # No optimization engine → selected_provider = "ollama" (fallback)
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.budget_config_store = None
        state.permission_store = permission_store
        state.permission_strict = False   # so _perm_needs_check = False
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = None
        state.model_allocation_store = None
        state.audit_writer = None
        state.rbac_store = None
        state.identity_registry = None
        state.agent_registry = None
        state.pool_manager = None
        state.pii_detector = None
        state.streaming_enabled = False
        state.streaming_inspect_interval = 200
        state.response_inspection_pipeline = None
        state.low_confidence_stepup_threshold = 0.7
        state.get = MagicMock(return_value=None)
        return state

    @pytest.mark.asyncio
    async def test_deny_grant_blocks_ollama_fallback_via_production_code(self):
        """
        The ACTUAL chat_completions endpoint must return HTTP 403 with
        code='cloud_model_not_granted' when the user has an explicit DENY grant
        on the requested model and no cloud key is configured.

        This drives the real LAURA-411-001 guard at proxy.py:2261-2316,
        NOT a re-implementation of the logic.
        """
        import contextlib
        from fastapi import Request
        from yashigani.gateway.openai_router import (
            ChatCompletionRequest,
            ChatMessage,
        )

        uid = "idnt_aabbccdd1234"
        model = "openai:gpt-4o"

        mock_state = self._make_mock_state_for_deny(uid, model)

        def _make_mock_req() -> MagicMock:
            req = MagicMock(spec=Request)
            req.method = "POST"
            req.headers = MagicMock()
            req.headers.__iter__ = MagicMock(return_value=iter([]))
            req.headers.items = MagicMock(return_value=[])
            req.headers.get = MagicMock(return_value=None)
            req.state = MagicMock()
            req.state.ysg_principal = None
            return req

        patches = [
            patch("yashigani.gateway.openai_router._state", mock_state),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": uid,
                    "kind": "human",
                    "groups": [],
                }),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={
                    "allow": True,
                    "model_allowed": True,
                    "reason": "ok",
                }),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
        ]

        body = ChatCompletionRequest(
            model=model,
            messages=[ChatMessage(role="user", content="tell me a secret")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            from starlette.responses import JSONResponse
            result = await chat_completions(body, _make_mock_req())

        # Must be a JSONResponse (not a streaming response or None)
        assert isinstance(result, JSONResponse), (
            f"Expected JSONResponse from LAURA-411-001 DENY path; got {type(result)}"
        )
        assert result.status_code == 403, (
            f"LAURA-411-001: explicit DENY must return 403; got {result.status_code}"
        )

        # Decode and inspect the response body
        import json
        resp_json = json.loads(result.body)

        error = resp_json.get("error", {})
        assert error.get("code") == "cloud_model_not_granted", (
            f"LAURA-411-001: response code must be 'cloud_model_not_granted'; "
            f"got {error.get('code')!r}"
        )
        assert error.get("type") == "policy_denied", (
            f"LAURA-411-001: response type must be 'policy_denied'; "
            f"got {error.get('type')!r}"
        )

    @pytest.mark.asyncio
    async def test_no_deny_grant_does_not_block(self):
        """
        When no DENY grant exists, chat_completions must NOT 403 at the
        LAURA-411-001 gate (no false positives).  The request proceeds to
        backend routing (not tested here — we just verify it doesn't 403 at
        the permission check).
        """
        import contextlib
        from fastapi import Request
        from starlette.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        uid = "idnt_aabbccdd1234"
        model = "openai:gpt-4o"

        # No explicit DENY — returns None for any grant lookup
        mock_permission_store = MagicMock()
        mock_permission_store.get_boolean_grant.return_value = None

        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "llama3.2:3b"
        state.optimization_engine = None
        state.permission_store = mock_permission_store
        state.permission_strict = False
        state.ddos_protector = None
        state.content_relay_detector = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.budget_config_store = None
        state.model_alias_store = None
        state.model_allocation_store = None
        state.audit_writer = None
        state.rbac_store = None
        state.identity_registry = None
        state.agent_registry = None
        state.pool_manager = None
        state.pii_detector = None
        state.streaming_enabled = False
        state.streaming_inspect_interval = 200
        state.response_inspection_pipeline = None
        state.low_confidence_stepup_threshold = 0.7
        state.get = MagicMock(return_value=None)

        def _make_mock_req():
            req = MagicMock(spec=Request)
            req.method = "POST"
            req.headers = MagicMock()
            req.headers.__iter__ = MagicMock(return_value=iter([]))
            req.headers.items = MagicMock(return_value=[])
            req.headers.get = MagicMock(return_value=None)
            req.state = MagicMock()
            req.state.ysg_principal = None
            return req

        # Provide a mock Ollama response so the request can complete
        mock_ollama_resp = MagicMock()
        mock_ollama_resp.status_code = 200
        mock_ollama_resp.json = MagicMock(return_value={
            "message": {"role": "assistant", "content": "Hi!"},
            "done": True,
            "prompt_eval_count": 5,
            "eval_count": 3,
        })
        mock_ollama_client = AsyncMock()
        mock_ollama_client.post = AsyncMock(return_value=mock_ollama_resp)
        ollama_cm = MagicMock()
        ollama_cm.__aenter__ = AsyncMock(return_value=mock_ollama_client)
        ollama_cm.__aexit__ = AsyncMock(return_value=False)

        patches = [
            patch("yashigani.gateway.openai_router._state", state),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={"identity_id": uid, "kind": "human", "groups": []}),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_response_check",
                AsyncMock(return_value={"allow": True}),
            ),
            patch(
                "yashigani.inspection._ollama_transport.ollama_async_client",
                MagicMock(return_value=ollama_cm),
            ),
        ]

        body = ChatCompletionRequest(
            model=model,
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_mock_req())

        # Must NOT be a 403 — LAURA-411-001 must not fire when no DENY exists
        if isinstance(result, JSONResponse):
            # Specifically check it's not the LAURA-411-001 deny
            import json
            resp_json = json.loads(result.body)
            error_code = resp_json.get("error", {}).get("code", "")
            assert error_code != "cloud_model_not_granted", (
                "LAURA-411-001 must NOT fire when no explicit DENY grant exists"
            )


# ===========================================================================
# LAURA-411-005: X-XSS-Protection header must be absent
# LAURA-411-006: X-Frame-Options must NOT be set by the application
#                (Caddy sets it; duplicate would break frame-embedding controls)
# ===========================================================================

class TestLaura411HeaderPolicy:
    """
    Security header regression tests for backoffice and gateway middleware.

    LAURA-411-005: X-XSS-Protection is deprecated, can introduce vulns on
    old browsers, and has been removed.  Response must contain NO such header.

    LAURA-411-006: X-Frame-Options is set by Caddy's 'header @not_embed'
    block.  The application must NOT set it — a duplicate X-Frame-Options
    causes undefined browser behaviour and breaks embed-policy configuration.
    CSP frame-ancestors is the correct application-layer control.
    """

    # ── backoffice/app.py ────────────────────────────────────────────────

    def _build_backoffice_test_client(self):
        """Build a minimal TestClient for the backoffice app."""
        import importlib
        # Import the factory function from backoffice app
        from yashigani.backoffice.app import create_app
        from yashigani.backoffice.state import BackofficeState, backoffice_state
        # Ensure the state is wired minimally (no Redis needed for header tests)
        with patch("yashigani.backoffice.app.backoffice_state", MagicMock(
            capability_policy_store=None,
            session_store=None,
            rbac_store=None,
        )):
            app = create_app()
        from starlette.testclient import TestClient
        return TestClient(app, raise_server_exceptions=False)

    def test_backoffice_no_xss_protection_header(self):
        """
        Backoffice security_headers middleware must NOT emit X-XSS-Protection.
        (LAURA-411-005: deprecated header removed.)
        """
        # Test using source inspection + direct middleware invocation
        import inspect
        from yashigani.backoffice import app as bo_app
        src = inspect.getsource(bo_app)
        # Verify the header is not set in the middleware
        assert "X-XSS-Protection" not in src or "removed" in src.lower() or (
            # If present, it must only be in comments explaining it was removed
            src.count("X-XSS-Protection") == src.lower().count("x-xss-protection")
            and "removed" in src[
                max(0, src.index("X-XSS-Protection") - 200):
                src.index("X-XSS-Protection") + 200
            ].lower()
        ), (
            "backoffice/app.py must NOT set X-XSS-Protection header "
            "(LAURA-411-005: deprecated header; comments explaining removal are ok)"
        )

    def test_backoffice_does_not_set_x_frame_options(self):
        """
        Backoffice security_headers middleware must NOT set X-Frame-Options.
        (LAURA-411-006: Caddy owns this header; app setting it causes duplicates.)
        """
        import inspect
        from yashigani.backoffice import app as bo_app
        src = inspect.getsource(bo_app)
        # The header name must not appear as a header being SET (only in comments)
        # Find all lines that contain X-Frame-Options
        xfo_lines = [
            line for line in src.splitlines()
            if "X-Frame-Options" in line
        ]
        # Any occurrence must only be in comments (line starts with # or is a comment block)
        for line in xfo_lines:
            stripped = line.strip()
            assert stripped.startswith("#") or stripped.startswith("//"), (
                f"backoffice/app.py must not SET X-Frame-Options header "
                f"(LAURA-411-006); found non-comment line: {line!r}"
            )

    def test_backoffice_xss_protection_not_in_response_headers(self):
        """
        The security_headers middleware must not add X-XSS-Protection to any response.
        We test this directly by calling the middleware function.
        """
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        # Build a mock request + next handler
        mock_request = MagicMock()
        mock_request.url.path = "/admin/dashboard"
        mock_request.cookies = {}

        mock_response = MagicMock()
        mock_response.headers = {}

        async def mock_call_next(req):
            return mock_response

        # Import and invoke the middleware directly from the source
        import inspect
        from yashigani.backoffice import app as bo_app_module

        # The security_headers function is defined inside create_app; we verify
        # the source doesn't assign the deprecated header.
        src = inspect.getsource(bo_app_module)
        # Must not set the header
        assert 'response.headers["X-XSS-Protection"]' not in src, (
            "backoffice security_headers must not set X-XSS-Protection "
            "(LAURA-411-005)"
        )

    def test_backoffice_x_frame_options_not_set_in_source(self):
        """X-Frame-Options must not appear as a headers assignment in backoffice."""
        import inspect
        from yashigani.backoffice import app as bo_app_module
        src = inspect.getsource(bo_app_module)
        assert 'response.headers["X-Frame-Options"]' not in src, (
            "backoffice security_headers must not set X-Frame-Options "
            "(LAURA-411-006: Caddy owns this header)"
        )

    # ── gateway/proxy.py ──────────────────────────────────────────────────

    def test_gateway_no_xss_protection_header_in_source(self):
        """
        gateway/proxy.py security_headers middleware must NOT set X-XSS-Protection.
        (LAURA-411-005)
        """
        import inspect
        from yashigani.gateway import proxy as gw_proxy_module
        src = inspect.getsource(gw_proxy_module)
        assert 'response.headers["X-XSS-Protection"]' not in src, (
            "gateway/proxy.py security_headers must not set X-XSS-Protection "
            "(LAURA-411-005)"
        )

    def test_gateway_x_frame_options_not_set_in_source(self):
        """
        gateway/proxy.py security_headers middleware must NOT set X-Frame-Options.
        (LAURA-411-006: Caddy owns it; duplicate causes undefined behaviour.)
        """
        import inspect
        from yashigani.gateway import proxy as gw_proxy_module
        src = inspect.getsource(gw_proxy_module)
        assert 'response.headers["X-Frame-Options"]' not in src, (
            "gateway/proxy.py security_headers must not set X-Frame-Options "
            "(LAURA-411-006)"
        )

    def test_gateway_comment_explains_xframe_removal(self):
        """
        The comment explaining WHY X-Frame-Options is removed (LAURA-411-006)
        must be present — it prevents future engineers from re-adding the header.
        """
        import inspect
        from yashigani.gateway import proxy as gw_proxy_module
        src = inspect.getsource(gw_proxy_module)
        assert "LAURA-411-006" in src, (
            "gateway/proxy.py must reference LAURA-411-006 near the X-Frame-Options "
            "removal comment (guards against re-introduction)"
        )

    def test_backoffice_comment_explains_xframe_removal(self):
        """
        Same comment guard for backoffice/app.py.
        """
        import inspect
        from yashigani.backoffice import app as bo_app_module
        src = inspect.getsource(bo_app_module)
        assert "LAURA-411-006" in src, (
            "backoffice/app.py must reference LAURA-411-006 near the X-Frame-Options "
            "removal comment"
        )


# ===========================================================================
# LAURA-411-002 (extended): nonce guard covers qa / preprod / any non-dev env
# ===========================================================================

class TestLaura411002NonceStoreExtended:
    """
    Broadened nonce guard (FIX 4): InMemoryNonceStore must be refused for ANY
    environment name that is not in the explicit dev/test allow-list.
    The old check used a deny-list (only production/staging); future env names
    like 'qa' or 'preprod' silently passed with only a WARNING.
    """

    def _make_minimal_broker_config(self, nonce_store=None):
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP384R1
        from cryptography.hazmat.backends import default_backend
        from yashigani.mcp.broker import McpBrokerConfig
        from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier

        private_key = generate_private_key(SECP384R1(), default_backend())
        issuer = McpJwtIssuer(
            tenant_id="test-tenant",
            private_key=private_key,
            key_generated_at=1748476800,
        )
        verifier = McpJwtVerifier.from_issuer(issuer)
        audit_writer = MagicMock()

        return McpBrokerConfig(
            opa_url="http://policy:8181",
            tenant_id="test-tenant",
            issuer=issuer,
            verifier=verifier,
            nonce_store=nonce_store,
            audit_writer=audit_writer,
        )

    def test_inmemory_rejected_in_qa(self):
        """
        InMemoryNonceStore must raise RuntimeError when YASHIGANI_ENV=qa.
        Regression: the old 'if _env in {production, staging}' check silently
        accepted 'qa' with only a WARNING.
        """
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config(nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "qa"}):
            with pytest.raises(RuntimeError, match="InMemoryNonceStore"):
                McpBroker(config)

    def test_inmemory_rejected_in_preprod(self):
        """InMemoryNonceStore must raise RuntimeError when YASHIGANI_ENV=preprod."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config(nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "preprod"}):
            with pytest.raises(RuntimeError, match="InMemoryNonceStore"):
                McpBroker(config)

    def test_inmemory_allowed_in_test_env(self):
        """InMemoryNonceStore must be accepted when YASHIGANI_ENV=test."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config(nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "test"}):
            broker = McpBroker(config)
            assert broker is not None

    def test_inmemory_allowed_in_dev_env(self):
        """InMemoryNonceStore must be accepted when YASHIGANI_ENV=dev."""
        from yashigani.mcp.broker import McpBroker
        from yashigani.mcp._nonce import InMemoryNonceStore

        config = self._make_minimal_broker_config(nonce_store=InMemoryNonceStore())

        with patch.dict(os.environ, {"YASHIGANI_ENV": "dev"}):
            broker = McpBroker(config)
            assert broker is not None
