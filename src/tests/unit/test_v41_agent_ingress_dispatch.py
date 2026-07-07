# Last updated: 2026-07-07T00:00:00+00:00
"""
Unit tests — v4.1 §2.5 agent-ingress dispatch clients present the mesh leaf.

The §2.5 fronts terminate mTLS ``require_and_verify``; a bare
``httpx.AsyncClient`` presents no client leaf and every dispatch fails
closed at the TLS handshake.  Contract under test:

  * ``agent_dispatch_client()`` (gateway/_dispatch_client.py) primary path
    is ``internal_httpx_client()`` — the per-process ServiceIdentity leaf
    (gateway leaf in the gateway container, backoffice leaf in the
    backoffice container) + internal root-CA trust.
  * Fallback to a bare client ONLY when the ServiceIdentity is unavailable
    (dev/test) — still fail-closed against a mesh front.
  * Wiring: the three dispatch paths — gateway ``agent_router`` forward
    leg, ``langflow_client`` (gateway chat + backoffice create_flow) and
    module-level ``letta_chat`` — construct their client via
    ``agent_dispatch_client``, never bare ``httpx.AsyncClient``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helper — an httpx.AsyncClient-shaped mock usable as async context manager
# ---------------------------------------------------------------------------

def _mock_client(response: MagicMock) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.request = AsyncMock(return_value=response)
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=response)
    return client


def _resp(status_code: int = 200, json_body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_body or {})
    resp.content = b"{}"
    resp.text = "{}"
    resp.headers = {"content-type": "application/json"}
    return resp


# ---------------------------------------------------------------------------
# agent_dispatch_client — primary (mesh identity) + fallback paths
# ---------------------------------------------------------------------------

class TestAgentDispatchClient:
    def test_primary_path_uses_internal_httpx_client(self):
        """The mesh ServiceIdentity client IS the returned client."""
        sentinel = MagicMock(name="mesh-client")
        with patch(
            "yashigani.pki.client.internal_httpx_client", return_value=sentinel,
        ) as mock_internal:
            from yashigani.gateway._dispatch_client import agent_dispatch_client
            client = agent_dispatch_client(timeout=42.0)
        assert client is sentinel
        mock_internal.assert_called_once_with(timeout=42.0)

    def test_fallback_when_service_identity_unavailable(self):
        """No ServiceIdentity (dev/test) → bare client fallback; a mesh
        front refuses it at the handshake (fail-closed, not our problem
        here — we only assert the fallback exists and is bare httpx)."""
        import httpx
        with patch(
            "yashigani.pki.client.internal_httpx_client",
            side_effect=RuntimeError("no /run/secrets"),
        ):
            from yashigani.gateway._dispatch_client import agent_dispatch_client
            client = agent_dispatch_client(timeout=5.0)
        try:
            assert isinstance(client, httpx.AsyncClient)
        finally:
            import asyncio
            asyncio.run(client.aclose())


# ---------------------------------------------------------------------------
# Wiring — gateway agent_router forward leg
# ---------------------------------------------------------------------------

def _router_state() -> dict:
    config = MagicMock()
    config.opa_url = "https://policy:8181"
    registry = {
        "target-b": {
            "status": "active",
            "upstream_url": "https://caddy:9775/agents/default/letta",
            "groups": [],
            "allowed_caller_groups": ["any"],
            "allowed_paths": ["**"],
            "sensitivity_ceiling": "RESTRICTED",
        }
    }
    return {
        "agent_registry": registry,
        "audit_writer": None,
        "config": config,
        "principal_verifier": None,
        "principal_signer": None,
        "principal_tenant_id": "default",
        "response_inspection_pipeline": None,
    }


def _router_request() -> MagicMock:
    req = MagicMock()
    req.method = "POST"
    req.headers = {}
    req.state = MagicMock()
    req.state.agent_id = "caller-a"
    req.state.request_id = "req-test-001"

    async def _body():
        return b'{"prompt": "hello"}'

    req.body = _body
    return req


class TestAgentRouterDispatchWiring:
    @pytest.mark.asyncio
    async def test_forward_leg_uses_agent_dispatch_client(self):
        """route_agent_call dials the ingress front via
        agent_dispatch_client (mesh leaf), not a bare httpx client."""
        from yashigani.gateway.agent_router import route_agent_call

        upstream = _resp(200)
        client = _mock_client(upstream)

        async def _opa_allow(*a, **k):
            return True, ""

        async def _cp_allow(*a, **k):
            return {"allow": True, "deny": []}

        with (
            patch("yashigani.gateway.agent_router._opa_agent_check",
                  side_effect=_opa_allow),
            patch("yashigani.gateway.agent_router._opa_agent_response_check",
                  side_effect=_opa_allow),
            patch("yashigani.gateway.agent_router.evaluate_client_policies",
                  side_effect=_cp_allow),
            patch("yashigani.gateway.agent_router.agent_dispatch_client",
                  return_value=client) as mock_dispatch,
        ):
            resp = await route_agent_call(
                _router_request(), "/agents/target-b/v1/query", _router_state(),
            )

        assert resp.status_code == 200
        mock_dispatch.assert_called_once_with(timeout=30.0)
        client.request.assert_awaited_once()
        url = client.request.await_args.kwargs["url"]
        assert url == "https://caddy:9775/agents/default/letta/v1/query"


# ---------------------------------------------------------------------------
# Wiring — langflow_client (gateway chat + backoffice create_flow)
# ---------------------------------------------------------------------------

class TestLangflowDispatchWiring:
    @pytest.mark.asyncio
    async def test_langflow_chat_uses_agent_dispatch_client(self):
        from yashigani.gateway import langflow_client as lf

        run_resp = _resp(200, {
            "outputs": [{"outputs": [{"results": {"message": {"text": "hi"}}}]}],
        })
        client = _mock_client(run_resp)

        with (
            patch.object(lf, "agent_dispatch_client",
                         return_value=client) as mock_dispatch,
            patch.object(lf, "_ensure_initialized",
                         new=AsyncMock(return_value=("key", "flow-1"))),
        ):
            out = await lf.langflow_chat(
                "https://caddy:9705/agents/default/langflow",
                [{"role": "user", "content": "hello"}],
                timeout=99.0,
            )

        mock_dispatch.assert_called_once_with(timeout=99.0)
        assert out["choices"][0]["message"]["content"] == "hi"

    @pytest.mark.asyncio
    async def test_create_flow_uses_agent_dispatch_client(self):
        """Backoffice draft-flow creation dials the front with the
        process's mesh leaf (backoffice leaf in the backoffice container)."""
        from yashigani.gateway import langflow_client as lf

        client = _mock_client(_resp(201, {"id": "flow-xyz"}))

        with (
            patch.object(lf, "agent_dispatch_client",
                         return_value=client) as mock_dispatch,
            patch.object(lf, "_ensure_initialized",
                         new=AsyncMock(return_value=("key", "flow-1"))),
        ):
            flow_id = await lf.create_flow(
                "https://caddy:9705/agents/default/langflow",
                {"nodes": [], "edges": []},
                "draft-abc",
            )

        mock_dispatch.assert_called_once_with(timeout=60.0)
        assert flow_id == "flow-xyz"


# ---------------------------------------------------------------------------
# Wiring — module-level letta_chat (registered-upstream dispatch)
# ---------------------------------------------------------------------------

class TestLettaDispatchWiring:
    @pytest.mark.asyncio
    async def test_letta_chat_uses_agent_dispatch_client(self):
        from yashigani.gateway import letta_client as lc

        msg_resp = _resp(200, {
            "messages": [
                {"message_type": "assistant_message", "content": "pong"},
            ],
        })
        client = _mock_client(msg_resp)

        with (
            patch.object(lc, "agent_dispatch_client",
                         return_value=client) as mock_dispatch,
            patch.object(lc, "_ensure_agent",
                         new=AsyncMock(return_value="agent-1")),
        ):
            out = await lc.letta_chat(
                "https://caddy:9775/agents/default/letta",
                [{"role": "user", "content": "ping"}],
                timeout=77.0,
            )

        mock_dispatch.assert_called_once_with(timeout=77.0)
        assert out["choices"][0]["message"]["content"] == "pong"
