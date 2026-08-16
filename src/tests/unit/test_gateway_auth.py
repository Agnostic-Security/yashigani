"""Unit tests for yashigani.gateway.agent_auth and agent_router."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
from starlette.requests import Request


class TestAgentAuthMiddleware:
    def test_non_agent_path_passes_through(self):
        """Requests to non-/agents/ paths should bypass agent auth."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()

        @app.get("/healthz")
        async def healthz():
            return {"status": "ok"}

        mock_registry = MagicMock()
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/healthz")
        assert response.status_code == 200
        mock_registry.verify_token.assert_not_called()

    def test_agent_path_without_auth_returns_401(self):
        """Requests to /agents/ without Bearer token should return 401."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()

        @app.get("/agents/target-id/tools/list")
        async def agent_route():
            return {"ok": True}

        mock_registry = MagicMock()
        mock_registry.verify_token.return_value = False
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/agents/target-id/tools/list")
        assert response.status_code == 401

    def test_agent_path_with_valid_token_passes(self):
        """Valid bearer token should be accepted and request.state set."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()
        received_state = {}

        @app.get("/agents/target-id/tools/list")
        async def agent_route(request: Request):
            received_state["caller_type"] = getattr(request.state, "caller_type", None)
            return {"ok": True}

        mock_registry = MagicMock()
        mock_registry.verify_token.return_value = True
        # FIND-0813-013 (Nico, 2026-08-13): AgentAuthMiddleware now also
        # requires a caller-status check (registry.get() -> status == "active")
        # before authenticating, fail-closed on an unresolvable caller — so
        # this active-agent test can no longer stub .get() -> None (that now
        # means "unknown caller, reject" per the fix). Return an active agent
        # with no CIDRs configured, which still exercises the "IP allowlist
        # check skipped when allowed_cidrs is empty" path this test targets.
        mock_registry.get.return_value = {"status": "active", "allowed_cidrs": []}
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            "/agents/target-id/tools/list",
            headers={
                "Authorization": "Bearer " + "a" * 64,
                "X-Yashigani-Caller-Agent-Id": "caller-id",
            }
        )
        assert response.status_code == 200


class TestAgentRegistry:
    def test_register_returns_id_and_token(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, token = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=["engineering"],
            allowed_caller_groups=["engineering"],
            allowed_paths=["**"],
        )
        assert len(agent_id) > 0
        assert len(token) >= 64

    def test_verify_token_valid(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, token = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=[],
            allowed_caller_groups=[],
            allowed_paths=["**"],
        )
        assert registry.verify_token(agent_id, token) is True

    def test_verify_token_wrong_token(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, _ = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=[],
            allowed_caller_groups=[],
            allowed_paths=["**"],
        )
        assert registry.verify_token(agent_id, "wrong" * 20) is False

    def test_count_active(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        assert registry.count("active") == 0
        registry.register("A", "http://a:8080", [], [], ["**"])
        assert registry.count("active") == 1

    def test_approve_svid_with_fakeredis(self, mock_redis):
        """approve_svid() must work with the real fakeredis pipeline.

        Re-enabled after BUG-4.0 fix: approve_svid() previously used the old
        positional pipe.hset(key, field, val) form which is incompatible with
        some fakeredis pipeline implementations.  The fix changes it to the
        mapping= form (mapping={b"svid_issued": b"1"}) used everywhere else in
        registry.py.  This test proves the fix against real fakeredis (not the
        custom _FakeRedis stub in test_nhi_approve_gate.py).
        """
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)

        nhi_id, token = registry.register_nhi(
            name="test-svid-fakeredis",
            owner_identity_id="user__test",
            template_id="tmpl_base",
            allowed_tools=["search"],
            allowed_paths=["/v1/chat/completions"],
            allowed_models=["gpt-4o-mini"],
            sensitivity_ceiling="INTERNAL",
            budget_cap={"max_tokens_per_run": 1000, "max_tool_calls_per_run": 5},
        )

        # Before approval: not in token map (fail-closed)
        assert token not in registry.get_nhi_token_map(), (
            "Un-approved NHI token must not appear in the gateway token-role-map."
        )

        # The fix: pipe.hset(reg_key, mapping={b"svid_issued": b"1"}) works with fakeredis
        registry.approve_svid(nhi_id)

        # After approval: in token map + svid_issued=True
        token_map = registry.get_nhi_token_map()
        assert token in token_map, "After approve_svid() NHI token must appear in token-role-map."
        assert token_map[token] == nhi_id

        nhi = registry.get(nhi_id)
        assert nhi is not None
        assert nhi.get("svid_issued") is True
